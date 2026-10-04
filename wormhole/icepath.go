package wormhole

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/quic-go/quic-go"
)

// iceHint is carried in the transit message (json field "bsf-ice") and
// holds a complete non-trickle ICE description: local credentials plus
// every candidate gathered before the transit message was sent. Both
// peers publish one, and a punch is attempted only when both transit
// messages carry the field — the same negotiation shape as bsf-parallel.
// Python clients ignore the unknown field and keep using TCP.
type iceHint struct {
	Ufrag      string   `json:"ufrag"`
	Pwd        string   `json:"pwd"`
	Stun       string   `json:"stun,omitempty"` // "stun:host:port" the sender gathered with; the receiver may reuse it
	Candidates []string `json:"candidates"`     // pion SDP candidate lines
}

// iceNextProto is the QUIC ALPN identifier for the punched path. All
// confidentiality and integrity come from the transit record encryption
// layered on top; the QUIC handshake itself runs with an ephemeral
// self-signed certificate and skipped verification.
const iceNextProto = "bsf-quic"

var (
	// iceGatherTimeout bounds the STUN round trip while gathering
	// server-reflexive candidates (host-only gathering returns at once).
	iceGatherTimeout = 2 * time.Second
	// iceConnectTimeout bounds Dial/Accept, i.e. the whole punch attempt
	// before the transfer falls back to a relay.
	iceConnectTimeout = 8 * time.Second
	// iceHandshakeTimeout bounds the transit handshake over the punched
	// path once the QUIC stream is open.
	iceHandshakeTimeout = 8 * time.Second

	// icePathCloseDelay lets the FIN and any queued stream data reach the
	// peer before the session (and with it the agent) is torn down.
	icePathCloseDelay = 3 * time.Second

	iceQUICIdleTimeout   = 60 * time.Second
	iceQUICHandshakeIdle = 10 * time.Second
	iceQUICKeepAlive     = 15 * time.Second

	// publicSTUNServers seed server-reflexive gathering when neither the
	// user nor the peer advertised an endpoint. Several servers are
	// gathered in parallel: domestic ones answer with a low RTT (and a
	// usable ipv4 mapping), and every extra server adds another srflx
	// candidate, which gives symmetric NATs more pairs to try.
	publicSTUNServers = []string{
		"stun:stun.chat.bilibili.com:3478",
		"stun:stun.cloudflare.com:3478",
		"stun:stun.l.google.com:19302",
	}
)

// testICEIncludeLoopback adds loopback candidates so tests can punch over
// 127.0.0.1 (mirrors testDisableLocalListener).
var testICEIncludeLoopback bool

// icePath owns the live punch state of a transport. One ICE agent yields
// one *ice.Conn; the QUIC session (and its streams) ride on top. Closing
// the path tears down the agent and its sockets — and conversely, the
// agent must be kept alive for as long as the path is in use.
type icePath struct {
	agent  *ice.Agent
	conn   *ice.Conn
	remote net.Addr
	pc     net.PacketConn
	// tr demultiplexes every QUIC session on the punched connection, so
	// resumes can dial again over the same path without two sessions
	// stealing each other's packets
	tr     *quic.Transport
	ln     *quic.Listener
	qconn  *quic.Conn
	closed bool
	// autoClose tears the whole path down shortly after a stream closes
	// (single-stream transfers); parallel transfers clear it because the
	// path must survive stream drops until the resume finishes
	autoClose bool
}

func (p *icePath) close() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	if p.ln != nil {
		p.ln.Close()
	}
	if p.qconn != nil {
		p.qconn.CloseWithError(0, "ice path closed")
	}
	if p.conn != nil {
		p.conn.Close() // closes the agent too
	} else if p.agent != nil {
		p.agent.Close()
	}
}

// closeSoon tears the path down after the FIN and queued stream data
// have had time to reach the peer.
func (p *icePath) closeSoon() {
	if p == nil || p.closed {
		return
	}
	time.AfterFunc(icePathCloseDelay, p.close)
}

// stunServersFor resolves which STUN endpoints to gather with: explicit
// user config first, then the endpoint the sender advertised in its ice
// hint (a self-hosted rendezvous doubling as STUN), then public
// defaults when relays are allowed at all, and none in LAN-only mode.
func stunServersFor(c *Client, senderStun string) []string {
	if len(c.STUNServers) > 0 {
		return c.STUNServers
	}
	if senderStun != "" {
		return []string{senderStun}
	}
	if c.DisableTransitRelay {
		return nil
	}
	return publicSTUNServers
}

// prepareICE gathers host (and, when a STUN server is known,
// server-reflexive) candidates so they can travel inside the transit
// message. Must run before makeTransitMsg.
func (t *fileTransport) prepareICE() error {
	if !t.iceEnabled {
		return nil
	}

	var urls []*stun.URI
	for _, s := range t.stunServers {
		u, err := stun.ParseURI(s)
		if err != nil {
			return fmt.Errorf("bad stun server %q: %w", s, err)
		}
		urls = append(urls, u)
	}

	gatherTimeout := iceGatherTimeout
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:              urls,
		CandidateTypes:    []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		NetworkTypes:      []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		STUNGatherTimeout: &gatherTimeout,
		IncludeLoopback:   testICEIncludeLoopback,
	})
	if err != nil {
		return fmt.Errorf("ice agent: %w", err)
	}

	// pion v4 gathers asynchronously (trickle): the hook is invoked per
	// candidate and with nil once gathering completes. The transit
	// message needs the full set, so wait for that nil — bounded, then
	// ship whatever was gathered.
	gatherDone := make(chan struct{})
	if err := agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			select {
			case <-gatherDone:
			default:
				close(gatherDone)
			}
		}
	}); err != nil {
		agent.Close()
		return fmt.Errorf("ice on-candidate: %w", err)
	}

	if err := agent.GatherCandidates(); err != nil {
		agent.Close()
		return fmt.Errorf("ice gather: %w", err)
	}

	select {
	case <-gatherDone:
	case <-time.After(iceGatherTimeout + 3*time.Second):
		// slow STUN: proceed with the candidates gathered so far
	}

	t.ice = &icePath{agent: agent, autoClose: true}
	return nil
}

// closeICE tears the punch machinery down when the path lost the
// connection race, failed, or the transfer finished.
func (t *fileTransport) closeICE() {
	t.ice.close()
}

// closeICESoon is closeICE with a grace period for queued stream data.
func (t *fileTransport) closeICESoon() {
	t.ice.closeSoon()
}

// holdICEForParallel keeps the path alive across stream drops so a
// resume can redial over the same agent; the caller tears it down
// explicitly when the transfer ends.
func (t *fileTransport) holdICEForParallel() {
	if t.ice != nil {
		t.ice.autoClose = false
	}
}

// iceReady reports whether gathering produced a hint worth publishing.
func (t *fileTransport) iceReady() bool {
	return t.iceHintForTransit() != nil
}

func (t *fileTransport) iceHintForTransit() *iceHint {
	if t.ice == nil || t.ice.closed {
		return nil
	}

	cands, err := t.ice.agent.GetLocalCandidates()
	if err != nil || len(cands) == 0 {
		return nil
	}

	ufrag, pwd, err := t.ice.agent.GetLocalUserCredentials()
	if err != nil {
		return nil
	}

	h := &iceHint{
		Ufrag:      ufrag,
		Pwd:        pwd,
		Candidates: make([]string, 0, len(cands)),
	}
	for _, c := range cands {
		h.Candidates = append(h.Candidates, c.Marshal())
	}
	if len(t.stunServers) > 0 {
		h.Stun = t.stunServers[0]
	}

	return h
}

// punchICE runs the connectivity checks against the peer's candidates.
// The controlling side (sender) nominates the pair via Dial; the
// controlled side (receiver) waits in Accept. Both return once a pair is
// selected, or fail by iceConnectTimeout.
func (t *fileTransport) punchICE(ctx context.Context, peer *iceHint, controlling bool) error {
	if t.ice == nil || t.ice.closed {
		return errors.New("ice not prepared")
	}
	if peer == nil {
		return errors.New("no peer ice hint")
	}

	for _, raw := range peer.Candidates {
		cand, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			continue
		}
		if err := t.ice.agent.AddRemoteCandidate(cand); err != nil {
			return fmt.Errorf("add remote candidate: %w", err)
		}
	}

	pctx, cancel := context.WithTimeout(ctx, iceConnectTimeout)
	defer cancel()

	var conn *ice.Conn
	var err error
	if controlling {
		conn, err = t.ice.agent.Dial(pctx, peer.Ufrag, peer.Pwd)
	} else {
		conn, err = t.ice.agent.Accept(pctx, peer.Ufrag, peer.Pwd)
	}
	if err != nil {
		return fmt.Errorf("ice punch: %w", err)
	}

	t.ice.conn = conn
	t.ice.remote = conn.RemoteAddr()
	t.ice.pc = &icePacketConn{conn: conn, remote: t.ice.remote, local: conn.LocalAddr()}
	t.ice.tr = &quic.Transport{Conn: t.ice.pc}
	return nil
}

// listenQUIC starts the QUIC server side of the punched path (sender).
func (t *fileTransport) listenQUIC() error {
	if t.ice == nil || t.ice.pc == nil {
		return errors.New("ice path not connected")
	}

	cert, err := newSelfSignedCert()
	if err != nil {
		return err
	}

	ln, err := t.ice.tr.Listen(&tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{iceNextProto},
	}, &quic.Config{
		MaxIdleTimeout:          iceQUICIdleTimeout,
		HandshakeIdleTimeout:    iceQUICHandshakeIdle,
		DisablePathMTUDiscovery: true,
	})
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}

	t.ice.ln = ln
	return nil
}

// dialQUIC starts the QUIC client side of the punched path (receiver).
func (t *fileTransport) dialQUIC(ctx context.Context) error {
	if t.ice == nil || t.ice.pc == nil || t.ice.remote == nil {
		return errors.New("ice path not connected")
	}

	sess, err := t.ice.tr.Dial(ctx, t.ice.remote, &tls.Config{
		InsecureSkipVerify: true, // the record layer provides the real authentication
		NextProtos:         []string{iceNextProto},
	}, &quic.Config{
		MaxIdleTimeout:          iceQUICIdleTimeout,
		HandshakeIdleTimeout:    iceQUICHandshakeIdle,
		KeepAlivePeriod:         iceQUICKeepAlive,
		DisablePathMTUDiscovery: true,
	})
	if err != nil {
		return fmt.Errorf("quic dial: %w", err)
	}

	t.ice.qconn = sess
	return nil
}

// senderICEStreams takes the receiver's QUIC session and opens n streams
// as net.Conns.
//
// The sender (not the receiver) opens the streams: QUIC stream creation
// is lazy — an opened stream emits no frame until its first write — and
// in the transit handshake the sender writes first (the "transit sender
// ready" header, streamHello in parallel mode). Opening from the writing
// side materializes every stream immediately on the receiver.
func (t *fileTransport) senderICEStreams(ctx context.Context, n int) ([]net.Conn, error) {
	if t.ice == nil || t.ice.ln == nil {
		return nil, errors.New("quic listener not started")
	}

	qconn, err := t.ice.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	t.ice.qconn = qconn

	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		s, err := qconn.OpenStreamSync(ctx)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			t.closeICE()
			return nil, err
		}
		conns = append(conns, iceStreamConn{stream: s, path: t.ice})
	}

	return conns, nil
}

// receiverICEStreams accepts the sender-opened streams as net.Conns
// (receiver side). They arrive carrying the sender's handshake bytes.
func (t *fileTransport) receiverICEStreams(ctx context.Context, n int) ([]net.Conn, error) {
	if t.ice == nil || t.ice.qconn == nil {
		return nil, errors.New("quic session not started")
	}

	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		s, err := t.ice.qconn.AcceptStream(ctx)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			t.closeICE()
			return nil, err
		}
		conns = append(conns, iceStreamConn{stream: s, path: t.ice})
	}

	return conns, nil
}

// connectICEStream punches, dials QUIC, opens one stream and runs the
// standard transit dialer handshake over it (receiver side). Returns nil
// — with the path cleaned up — when any step fails, so the caller falls
// back to a relay.
func (t *fileTransport) connectICEStream(ctx context.Context, peer *iceHint) net.Conn {
	if err := t.punchICE(ctx, peer, false); err != nil {
		t.closeICE()
		return nil
	}
	if err := t.dialQUIC(ctx); err != nil {
		t.closeICE()
		return nil
	}
	conns, err := t.receiverICEStreams(ctx, 1)
	if err != nil || len(conns) == 0 {
		t.closeICE()
		return nil
	}

	successChan := make(chan net.Conn, 1)
	failChan := make(chan string, 1)
	go t.directRecvHandshake(ctx, "ice", conns[0], successChan, failChan)

	select {
	case conn := <-successChan:
		return conn
	case <-failChan:
		t.closeICE() // directRecvHandshake already closed the conn
		return nil
	case <-time.After(iceHandshakeTimeout):
		conns[0].Close()
		return nil
	}
}

// senderICEConns establishes the parallel streams for the sender side of
// the punched path: the QUIC session the receiver dialed is accepted, n
// streams are opened from here — the sender writes first in the transit
// handshake and QUIC only materializes a stream on its first write — and
// each runs the accept side of the transit handshake. first marks the
// initial connection; retries reuse the live agent and listener across
// resumes.
func (t *fileTransport) senderICEConns(ctx context.Context, n int, peer *iceHint, first bool) ([]net.Conn, error) {
	if first {
		if err := t.punchICE(ctx, peer, true); err != nil {
			return nil, err
		}
		if err := t.listenQUIC(); err != nil {
			return nil, err
		}
	}
	if t.ice == nil || t.ice.closed || t.ice.ln == nil {
		return nil, errors.New("ice listener not ready")
	}

	qconn, err := t.ice.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	t.ice.qconn = qconn

	streams := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		s, err := qconn.OpenStreamSync(ctx)
		if err != nil {
			for _, c := range streams {
				c.Close()
			}
			return nil, err
		}
		streams = append(streams, iceStreamConn{stream: s, path: t.ice})
	}

	readyCh := make(chan net.Conn, n)
	cancelCh := make(chan struct{})
	for _, s := range streams {
		go t.handleIncomingConnection(s, readyCh, cancelCh)
	}

	conns := make([]net.Conn, 0, n)
	deadline := time.After(parallelFirstWait + parallelAcceptWait)
	for len(conns) < n {
		select {
		case conn := <-readyCh:
			if _, err := conn.Write([]byte("go\n")); err != nil {
				conn.Close()
				continue
			}
			conns = append(conns, conn)
		case <-deadline:
			for _, c := range conns {
				c.Close()
			}
			close(cancelCh)
			return nil, errors.New("ice streams did not complete the transit handshake")
		case <-ctx.Done():
			for _, c := range conns {
				c.Close()
			}
			close(cancelCh)
			return nil, ctx.Err()
		}
	}

	return conns, nil
}

// receiverICEConns connects the parallel streams for the receiver side:
// dial the QUIC session, accept the sender-opened streams, and run the
// dialer side of the transit handshake on each. Retries reuse the live
// agent and the shared transport.
func (t *fileTransport) receiverICEConns(ctx context.Context, n int, peer *iceHint, first bool) ([]net.Conn, error) {
	if first {
		if err := t.punchICE(ctx, peer, false); err != nil {
			return nil, err
		}
	} else if t.ice != nil && t.ice.qconn != nil {
		// the previous session is dead; free it before redialing
		t.ice.qconn.CloseWithError(0, "redial")
		t.ice.qconn = nil
	}

	if err := t.dialQUIC(ctx); err != nil {
		return nil, err
	}

	conns, err := t.receiverICEStreams(ctx, n)
	if err != nil {
		return nil, err
	}

	for _, conn := range conns {
		success := make(chan net.Conn, 1)
		fail := make(chan string, 1)
		go t.directRecvHandshake(ctx, "ice", conn, success, fail)
		select {
		case <-success:
		case reason := <-fail:
			for _, c := range conns {
				c.Close()
			}
			return nil, errors.New("transit handshake failed: " + reason)
		case <-ctx.Done():
			conn.Close()
			return nil, ctx.Err()
		}
	}

	return conns, nil
}

// icePacketConn adapts the connected *ice.Conn into the net.PacketConn
// that quic.Listen/quic.Dial expect. ICE hands quic-go exactly one peer,
// so the remote address is fixed once the pair is selected.
type icePacketConn struct {
	conn   net.Conn
	remote net.Addr
	local  net.Addr
}

func (c *icePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(p)
	return n, c.remote, err
}

func (c *icePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.conn.Write(p)
}

func (c *icePacketConn) Close() error                        { return c.conn.Close() }
func (c *icePacketConn) LocalAddr() net.Addr                 { return c.local }
func (c *icePacketConn) SetDeadline(tm time.Time) error      { return c.conn.SetDeadline(tm) }
func (c *icePacketConn) SetReadDeadline(tm time.Time) error  { return c.conn.SetReadDeadline(tm) }
func (c *icePacketConn) SetWriteDeadline(tm time.Time) error { return c.conn.SetWriteDeadline(tm) }

// SetReadBuffer and SetWriteBuffer satisfy quic-go's socket buffer
// sizing probe (without them it warns, once per process, that the conn
// is "not a *net.UDPConn" — alarming and unactionable for users). The
// UDP socket is owned by the pion ICE agent and has no API to resize
// it, so both are accepted and ignored; a larger buffer can still be
// arranged system-wide via net.core.rmem_default.
func (c *icePacketConn) SetReadBuffer(int) error  { return nil }
func (c *icePacketConn) SetWriteBuffer(int) error { return nil }

// iceStreamConn adapts a *quic.Stream (which has no address methods)
// into a net.Conn. Closing a stream only sends its FIN: tearing the
// whole path down right away would discard undelivered stream data (the
// final ack of the transit protocol rides in exactly that window), so
// the path teardown happens on a short delay instead. (Parallel streams
// over one path will need a reference count here.)
type iceStreamConn struct {
	stream *quic.Stream
	path   *icePath
}

func (s iceStreamConn) Read(p []byte) (int, error)  { return s.stream.Read(p) }
func (s iceStreamConn) Write(p []byte) (int, error) { return s.stream.Write(p) }
func (s iceStreamConn) Close() error {
	err := s.stream.Close()
	if s.path.autoClose {
		s.path.closeSoon()
	}
	return err
}

// cancel aborts both directions of the stream immediately (RESET_STREAM
// + STOP_SENDING). Close keeps FIN semantics so queued data still
// reaches the peer; cancel is for error paths, where a stalled stream
// must not hold the session's shared flow-control window hostage.
func (s iceStreamConn) cancel() {
	s.stream.CancelWrite(0)
	s.stream.CancelRead(0)
}

// abortConn unblocks a connection stuck in Read or Write on an error
// path; plain TCP conns have nothing to abort beyond Close.
func abortConn(c net.Conn) {
	if ic, ok := c.(interface{ cancel() }); ok {
		ic.cancel()
	}
	c.Close()
}
func (s iceStreamConn) LocalAddr() net.Addr                { return s.path.pc.LocalAddr() }
func (s iceStreamConn) RemoteAddr() net.Addr               { return s.path.remote }
func (s iceStreamConn) SetDeadline(tm time.Time) error     { return s.stream.SetDeadline(tm) }
func (s iceStreamConn) SetReadDeadline(tm time.Time) error { return s.stream.SetReadDeadline(tm) }
func (s iceStreamConn) SetWriteDeadline(tm time.Time) error {
	return s.stream.SetWriteDeadline(tm)
}

// newSelfSignedCert makes a throwaway certificate for the QUIC handshake.
// Nothing trusts it — the peer skips verification because authenticity
// comes from the PAKE-derived transit record keys.
func newSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "bsf-transit"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
