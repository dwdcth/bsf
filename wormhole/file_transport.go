package wormhole

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dwdcth/bsf/internal/crypto"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"nhooyr.io/websocket"
)

type fileTransportAck struct {
	Ack    string `json:"ack"`
	SHA256 string `json:"sha256"`
}

type TransferType int

const (
	TransferFile TransferType = iota + 1
	TransferDirectory
	TransferText
)

func (tt TransferType) String() string {
	switch tt {
	case TransferFile:
		return "TransferFile"
	case TransferDirectory:
		return "TransferDirectory"
	case TransferText:
		return "TransferText"
	default:
		return fmt.Sprintf("TransferTypeUnknown<%d>", tt)
	}
}

type transportCryptor struct {
	conn           net.Conn
	reader         *bufio.Reader
	prefixBuf      []byte
	nextReadNonce  *big.Int
	nextWriteNonce uint64
	writeBuf       []byte
	err            error
	readKey        [32]byte
	writeKey       [32]byte
}

func newTransportCryptor(c net.Conn, transitKey []byte, readPurpose, writePurpose string) *transportCryptor {
	return newTransportCryptorWithReader(c, nil, transitKey, readPurpose, writePurpose)
}

// newTransportCryptorWithReader builds a cryptor that keeps reading from
// an existing bufio.Reader. Records that arrived in the same tcp segment
// as earlier ones sit in that reader's buffer; a fresh reader would
// never see them, so a handoff must pass the buffer along.
func newTransportCryptorWithReader(c net.Conn, reader *bufio.Reader, transitKey []byte, readPurpose, writePurpose string) *transportCryptor {
	r := hkdf.New(sha256.New, transitKey, nil, []byte(readPurpose))
	var readKey [32]byte
	_, err := io.ReadFull(r, readKey[:])
	if err != nil {
		panic(err)
	}

	r = hkdf.New(sha256.New, transitKey, nil, []byte(writePurpose))
	var writeKey [32]byte
	_, err = io.ReadFull(r, writeKey[:])
	if err != nil {
		panic(err)
	}

	if reader == nil {
		reader = bufio.NewReaderSize(c, 1<<17)
	}

	return &transportCryptor{
		conn:          c,
		reader:        reader,
		prefixBuf:     make([]byte, 4+crypto.NonceSize),
		nextReadNonce: big.NewInt(0),
		readKey:       readKey,
		writeKey:      writeKey,
	}
}
func (d *transportCryptor) Close() error {
	return d.conn.Close()
}

func (d *transportCryptor) readRecord() ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	_, err := io.ReadFull(d.reader, d.prefixBuf)
	if err != nil {
		d.err = err
		return nil, d.err
	}

	l := binary.BigEndian.Uint32(d.prefixBuf[:4])
	var nonce [24]byte
	copy(nonce[:], d.prefixBuf[4:])

	var bigNonce big.Int
	bigNonce.SetBytes(nonce[:])

	if bigNonce.Cmp(d.nextReadNonce) != 0 {
		d.err = errors.New("received out-of-order record")
		return nil, d.err
	}

	d.nextReadNonce.Add(d.nextReadNonce, big.NewInt(1))

	sealedMsg := make([]byte, l-crypto.NonceSize)
	_, err = io.ReadFull(d.reader, sealedMsg)
	if err != nil {
		d.err = err
		return nil, d.err
	}

	out, ok := secretbox.Open(nil, sealedMsg, &nonce, &d.readKey)
	if !ok {
		d.err = errDecryptFailed
		return nil, d.err
	}

	return out, nil
}

func (d *transportCryptor) writeRecord(msg []byte) error {
	var nonce [crypto.NonceSize]byte

	if d.nextWriteNonce == math.MaxUint64 {
		panic("Nonce exhaustion")
	}

	binary.BigEndian.PutUint64(nonce[crypto.NonceSize-8:], d.nextWriteNonce)
	d.nextWriteNonce++

	// one reusable buffer per cryptor instead of three allocations
	// per record
	needed := 4 + crypto.NonceSize + len(msg) + secretbox.Overhead
	if int64(needed) >= math.MaxUint32 {
		panic(fmt.Sprintf("writeRecord too large: %d", len(msg)))
	}
	if cap(d.writeBuf) < needed {
		d.writeBuf = make([]byte, needed)
	}
	buf := d.writeBuf[:needed]

	binary.BigEndian.PutUint32(buf[:4], uint32(crypto.NonceSize+len(msg)+secretbox.Overhead))
	copy(buf[4:], nonce[:])
	secretbox.Seal(buf[4+crypto.NonceSize:4+crypto.NonceSize], msg, &nonce, &d.writeKey)

	_, err := d.conn.Write(buf)
	return err
}

func newFileTransport(transitKey []byte, appID string, c *Client) *fileTransport {
	t := &fileTransport{
		transitKey: transitKey,
		appID:      appID,
		relayAddr:  c.relayAddr(),
	}
	if c.EnableICE {
		t.iceEnabled = true
		t.stunServers = stunServersFor(c, "")
	}
	if c.WSRelayURL != "" && !c.DisableTransitRelay {
		t.wsRelayURL = c.WSRelayURL
	}
	return t
}

type fileTransport struct {
	listener        net.Listener
	relayConn       net.Conn
	relayAddr       string
	transitKey      []byte
	appID           string
	parallelOnce    sync.Once
	parallelReadyCh chan net.Conn

	iceEnabled  bool
	stunServers []string
	ice         *icePath
	wsRelayURL  string
	wsRelay     *websocket.Conn
}

// connectViaRelay falls back to a relay when no direct path exists.
// The websocket relay runs first — wss on 443 slips past more firewalls
// and keeps the transfer on relays the sender chose — and the tcp relay
// only runs when no websocket relay connected.
func (t *fileTransport) connectViaRelay(otherTransit *transitMsg) (net.Conn, error) {
	if conn := t.raceRelays(otherTransit, "relay-ws-v1"); conn != nil {
		return conn, nil
	}
	return t.raceRelays(otherTransit, "relay-v1"), nil
}

// raceRelays dials every hint of one relay kind concurrently; the first
// connection to complete the transit handshake wins and the rest are
// cancelled. Returns nil when none succeeds within the window.
func (t *fileTransport) raceRelays(otherTransit *transitMsg, kind string) net.Conn {
	cancelFuncs := make(map[string]func())

	successChan := make(chan net.Conn)
	failChan := make(chan string)

	var count int

	for _, outerHint := range otherTransit.HintsV1 {
		if outerHint.Type != kind {
			continue
		}
		if kind == "relay-ws-v1" {
			if outerHint.URL == "" {
				continue
			}
			count++
			ctx, cancel := context.WithCancel(context.Background())
			cancelFuncs["ws "+outerHint.URL] = cancel

			go t.connectToWSRelay(ctx, outerHint.URL, successChan, failChan)
			continue
		}
		for _, innerHint := range outerHint.Hints {
			if innerHint.Type != "direct-tcp-v1" {
				continue
			}
			count++
			ctx, cancel := context.WithCancel(context.Background())
			addr := net.JoinHostPort(innerHint.Hostname, strconv.Itoa(innerHint.Port))

			cancelFuncs[addr] = cancel

			go t.connectToRelay(ctx, addr, successChan, failChan)
		}
	}

	if count == 0 {
		return nil
	}

	var conn net.Conn

	// wide enough for the bounded handshake plus a pairing round trip
	connectTimeout := time.After(relayHandshakeTimeout + 2*time.Second)

	for i := 0; i < count; i++ {
		select {
		case <-failChan:
		case conn = <-successChan:
			// first relay through the handshake wins; the losers would
			// only overwrite it. The winner keeps transfering: clear
			// the handshake deadline.
			conn.SetDeadline(time.Time{})
			for _, cancel := range cancelFuncs {
				cancel()
			}
			return conn
		case <-connectTimeout:
			for _, cancel := range cancelFuncs {
				cancel()
			}
			return conn
		}
	}

	return conn
}

// relayHandshakeTimeout bounds the transit handshake over a freshly
// paired relay connection; relays add real latency (the websocket relay
// crosses the edge twice per message) but must not hang forever.
var relayHandshakeTimeout = 10 * time.Second

var directConnectTimeout = 5 * time.Second

func (t *fileTransport) connectDirect(otherTransit *transitMsg) (net.Conn, error) {
	cancelFuncs := make(map[string]func())

	successChan := make(chan net.Conn)
	failChan := make(chan string)

	var count int

	for _, hint := range otherTransit.HintsV1 {
		if hint.Type == "direct-tcp-v1" {
			addr := net.JoinHostPort(hint.Hostname, strconv.Itoa(hint.Port))

			if _, exists := cancelFuncs[addr]; exists {
				// if the other peer sends multiple hints for the same address, only attempt
				// one connection
				continue
			}

			count++
			ctx, cancel := context.WithCancel(context.Background())
			cancelFuncs[addr] = cancel

			go t.connectToSingleHost(ctx, addr, successChan, failChan)
		}
	}

	var conn net.Conn

	connectTimeout := time.After(directConnectTimeout)

	for i := 0; i < count; i++ {
		select {
		case <-failChan:
		case conn = <-successChan:
		case <-connectTimeout:
			for _, cancel := range cancelFuncs {
				cancel()
			}
			// increment the count to make sure we consume all pending writes to the fail channel
			count++
		}
	}

	return conn, nil
}

func (t *fileTransport) connectToRelay(ctx context.Context, addr string, successChan chan net.Conn, failChan chan string) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		failChan <- addr
		return
	}

	_, err = conn.Write(t.relayHandshakeHeader())
	if err != nil {
		failChan <- addr
		return
	}
	gotOk := make([]byte, 3)
	_, err = io.ReadFull(conn, gotOk)
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	if !bytes.Equal(gotOk, []byte("ok\n")) {
		conn.Close()
		failChan <- addr
		return
	}

	// bound the handshake itself: a relay that pairs but stalls would
	// otherwise hang an undated read past the race window
	conn.SetDeadline(time.Now().Add(relayHandshakeTimeout))

	t.directRecvHandshake(ctx, addr, conn, successChan, failChan)
}

func (t *fileTransport) connectToSingleHost(ctx context.Context, addr string, successChan chan net.Conn, failChan chan string) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)

	if err != nil {
		failChan <- addr
		return
	}

	t.directRecvHandshake(ctx, addr, conn, successChan, failChan)
}

func (t *fileTransport) directRecvHandshake(ctx context.Context, addr string, conn net.Conn, successChan chan net.Conn, failChan chan string) {
	expectHeader := t.senderHandshakeHeader()

	gotHeader := make([]byte, len(expectHeader))

	_, err := io.ReadFull(conn, gotHeader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[dbg] dialer %s read header err: %s\n", addr, err)
		conn.Close()
		failChan <- addr
		return
	}

	if subtle.ConstantTimeCompare(gotHeader, expectHeader) != 1 {
		conn.Close()
		failChan <- addr
		return
	}

	_, err = conn.Write(t.receiverHandshakeHeader())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[dbg] dialer %s write reply err: %s\n", addr, err)
		conn.Close()
		failChan <- addr
		return
	}

	gotGo := make([]byte, 3)
	_, err = io.ReadFull(conn, gotGo)
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	if !bytes.Equal(gotGo, []byte("go\n")) {
		fmt.Fprintf(os.Stderr, "[dbg] dialer %s got go=%q\n", addr, gotGo)
		conn.Close()
		failChan <- addr
		return
	}

	successChan <- conn
}

func (t *fileTransport) makeTransitMsg() (*transitMsg, error) {
	msg := transitMsg{
		AbilitiesV1: []transitAbility{
			{
				Type: "direct-tcp-v1",
			},
			{
				Type: "relay-v1",
			},
		},
		// make a slice so this jsons to [] and not null
		HintsV1: make([]transitHintsV1, 0),
	}

	if t.listener != nil {
		_, portStr, err := net.SplitHostPort(t.listener.Addr().String())
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("port isn't an integer? %s", portStr)
		}

		addrs := nonLocalhostAddresses()

		for _, addr := range addrs {
			msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
				Type:     "direct-tcp-v1",
				Priority: 0.0,
				Hostname: addr,
				Port:     port,
			})
		}
	}

	if t.relayConn != nil {
		relayHost, portStr, err := net.SplitHostPort(t.relayAddr)
		if err != nil {
			return nil, err
		}

		relayPort, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("port isn't an integer? %s", portStr)
		}

		msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
			Type: "relay-v1",
			Hints: []transitHintsV1Hint{
				{
					Type:     "direct-tcp-v1",
					Priority: 2.0,
					Hostname: relayHost,
					Port:     relayPort,
				},
			},
		})
	}

	if t.wsRelayURL != "" {
		msg.AbilitiesV1 = append(msg.AbilitiesV1, transitAbility{
			Type: "relay-ws-v1",
		})
		msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
			Type:     "relay-ws-v1",
			Priority: 1.0,
			URL:      t.wsRelayURL,
		})
	}

	// the UDP hole-punch path: publish the full candidate set gathered
	// before this message was built (non-trickle ICE); peers that do not
	// understand "direct-udp-ice-v1"/"bsf-ice" ignore both
	if h := t.iceHintForTransit(); h != nil {
		msg.AbilitiesV1 = append(msg.AbilitiesV1, transitAbility{
			Type: "direct-udp-ice-v1",
		})
		msg.ICE = h
	}

	return &msg, nil
}

func (t *fileTransport) senderHandshakeHeader() []byte {
	purpose := "transit_sender"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	return []byte(fmt.Sprintf("transit sender %x ready\n\n", out))
}

func (t *fileTransport) receiverHandshakeHeader() []byte {
	purpose := "transit_receiver"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	return []byte(fmt.Sprintf("transit receiver %x ready\n\n", out))
}

func (t *fileTransport) relayHandshakeHeader() []byte {
	purpose := "transit_relay_token"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	sideID := crypto.RandHex(8)

	return []byte(fmt.Sprintf("please relay %x for side %s\n", out, sideID))
}

// Test option to disable local listeners
var testDisableLocalListener bool

func (t *fileTransport) listen() error {
	if testDisableLocalListener {
		return nil
	}

	// prefer a fixed port so firewalls only need one rule and resume
	// tests can target it; fall back to a random port when several
	// senders share a host
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", defaultTransitPort))
	if err != nil {
		l, err = net.Listen("tcp", ":0")
		if err != nil {
			return err
		}
	}

	t.listener = l
	return nil
}

func (t *fileTransport) listenRelay() error {
	if t.relayAddr == "" {
		return nil
	}
	conn, err := net.Dial("tcp", t.relayAddr)
	if err != nil {
		return err
	}

	_, err = conn.Write(t.relayHandshakeHeader())
	if err != nil {
		conn.Close()
		return err
	}

	t.relayConn = conn
	return nil
}

func (t *fileTransport) waitForRelayPeer(conn net.Conn, cancelCh chan struct{}) error {
	okCh := make(chan struct{})
	go func() {
		select {
		case <-cancelCh:
			conn.Close()
		case <-okCh:
		}
	}()

	defer close(okCh)

	gotOk := make([]byte, 3)
	_, err := io.ReadFull(conn, gotOk)
	if err != nil {
		conn.Close()
		return err
	}

	if !bytes.Equal(gotOk, []byte("ok\n")) {
		conn.Close()
		return errors.New("got non ok status from relay server")
	}

	return nil
}

// acceptConnections accepts up to n handshaked connections: the first
// within parallelFirstWait, the rest within parallelAcceptWait of each
// other. The accept loop is started once per transport and kept alive,
// so resumed transfers can keep using it; the caller closes the
// listener when done.
func (t *fileTransport) acceptConnections(ctx context.Context, n int) ([]net.Conn, error) {
	if t.listener == nil && t.relayConn == nil && t.wsRelay == nil {
		return nil, errors.New("no transit listener or relay")
	}

	t.parallelOnce.Do(func() {
		t.parallelReadyCh = make(chan net.Conn, n)

		if t.relayConn != nil {
			go func() {
				cancelCh := make(chan struct{})
				waitErr := t.waitForRelayPeer(t.relayConn, cancelCh)
				if waitErr != nil {
					return
				}
				t.handleIncomingConnection(t.relayConn, t.parallelReadyCh, cancelCh)
			}()
		}

		if t.wsRelay != nil {
			go func() {
				cancelCh := make(chan struct{})
				conn, waitErr := t.waitForWSRelayPeer(t.wsRelay, cancelCh)
				if waitErr != nil {
					return
				}
				t.handleIncomingConnection(conn, t.parallelReadyCh, cancelCh)
			}()
		}

		if t.listener != nil {
			go func() {
				for {
					conn, err := t.listener.Accept()
					if err == io.EOF {
						return
					} else if err != nil {
						return
					}

					go t.handleIncomingConnection(conn, t.parallelReadyCh, make(chan struct{}))
				}
			}()
		}
	})

	var (
		conns  []net.Conn
		grace  *time.Timer
		graceC <-chan time.Time
	)

	for len(conns) < n {
		var firstC <-chan time.Time
		if len(conns) == 0 {
			firstC = time.After(parallelFirstWait)
		}

		select {
		case <-ctx.Done():
			for _, c := range conns {
				c.Close()
			}
			return nil, ctx.Err()
		case conn := <-t.parallelReadyCh:
			// complete the transit handshake: the dialer is waiting
			// for this go-ahead after sending its handshake header
			if _, err := conn.Write([]byte("go\n")); err != nil {
				conn.Close()
				continue
			}
			conns = append(conns, conn)
			if grace == nil {
				grace = time.NewTimer(parallelAcceptWait)
				graceC = grace.C
			}
		case <-graceC:
			return conns, nil
		case <-firstC:
			return conns, nil
		}
	}

	return conns, nil
}

func (t *fileTransport) acceptConnection(ctx context.Context, peerTransit *transitMsg) (net.Conn, error) {
	readyCh := make(chan net.Conn)
	cancelCh := make(chan struct{})
	acceptErrCh := make(chan error, 1)

	// UDP hole punch: race the punched QUIC stream against the TCP
	// listener and relay connection. Only attempted when the peer's
	// transit message also carries an ice hint.
	if peerTransit != nil && peerTransit.ICE != nil && t.iceReady() {
		go func() {
			iceErr := func() error {
				if err := t.punchICE(ctx, peerTransit.ICE, true); err != nil {
					return err
				}
				if err := t.listenQUIC(); err != nil {
					return err
				}
				conns, err := t.senderICEStreams(ctx, 1)
				if err != nil {
					return err
				}
				if len(conns) == 0 {
					return errors.New("no ice streams")
				}
				t.handleIncomingConnection(conns[0], readyCh, cancelCh)
				return nil
			}()

			// with no listener and no relay there is nothing left to
			// race: surface the failure instead of hanging forever
			if iceErr != nil && t.listener == nil && t.relayConn == nil && t.wsRelay == nil {
				select {
				case acceptErrCh <- iceErr:
				default:
				}
			}
		}()
	}

	if t.relayConn != nil {
		go func() {
			waitErr := t.waitForRelayPeer(t.relayConn, cancelCh)
			if waitErr != nil {
				return
			}
			t.handleIncomingConnection(t.relayConn, readyCh, cancelCh)
		}()
	}

	if t.wsRelay != nil {
		go func() {
			conn, waitErr := t.waitForWSRelayPeer(t.wsRelay, cancelCh)
			if waitErr != nil {
				return
			}
			t.handleIncomingConnection(conn, readyCh, cancelCh)
		}()
	}

	if t.listener != nil {
		defer t.listener.Close()

		go func() {
			for {
				conn, err := t.listener.Accept()
				if err == io.EOF {
					break
				} else if err != nil {
					acceptErrCh <- err
					break
				}

				go t.handleIncomingConnection(conn, readyCh, cancelCh)
			}
		}()
	}

	select {
	case <-ctx.Done():
		close(cancelCh)
		t.closeICE()
		return nil, ctx.Err()
	case acceptErr := <-acceptErrCh:
		close(cancelCh)
		t.closeICE()
		return nil, acceptErr
	case conn := <-readyCh:
		close(cancelCh)
		// the ice path lost the race: stop punching and free its sockets
		// (when it won, the conn's own Close tears the path down later)
		if _, isICE := conn.(iceStreamConn); !isICE {
			t.closeICE()
		}
		_, err := conn.Write([]byte("go\n"))
		if err != nil {
			return nil, err
		}

		return conn, nil
	}
}

func (t *fileTransport) handleIncomingConnection(conn net.Conn, readyCh chan<- net.Conn, cancelCh chan struct{}) {
	okCh := make(chan struct{})

	go func() {
		select {
		case <-cancelCh:
			conn.Close()
		case <-okCh:
		}
	}()

	_, err := conn.Write(t.senderHandshakeHeader())
	if err != nil {
		conn.Close()
		close(okCh)
		return
	}

	expectHeader := t.receiverHandshakeHeader()

	gotHeader := make([]byte, len(expectHeader))

	_, err = io.ReadFull(conn, gotHeader)
	if err != nil {
		conn.Close()
		close(okCh)
		return
	}

	if subtle.ConstantTimeCompare(gotHeader, expectHeader) != 1 {
		conn.Close()
		close(okCh)
		return
	}

	select {
	case okCh <- struct{}{}:
	case <-cancelCh:
	}

	select {
	case <-cancelCh:
		// One of the other connections won, shut this one down
		conn.Write([]byte("nevermind\n"))
		conn.Close()
	case readyCh <- conn:
	}
}

var nonLocalhostAddresses = func() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	dedupAddrs := make(map[string]struct{})

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				dedupAddrs[ipnet.IP.String()] = struct{}{}
			}
		}
	}

	outAddrs := make([]string, 0, len(dedupAddrs))
	for addr := range dedupAddrs {
		outAddrs = append(outAddrs, addr)
	}

	return outAddrs
}
