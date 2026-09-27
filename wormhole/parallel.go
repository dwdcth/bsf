package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dwdcth/bsf/rendezvous"
	"golang.org/x/crypto/nacl/secretbox"
)

// Parallel file transfer between bsf clients.
//
// The sender announces the stream count in its transit message
// ("bsf-parallel": N, ignored by python clients). The receiver splits
// the file into N contiguous chunks and dials N transit connections;
// each stream carries its chunk as length-prefixed encrypted records
// exactly like the single stream protocol, except that record keys are
// derived per stream AND per resume attempt, so record nonces are never
// reused across streams or attempts.
//
// When a connection drops mid transfer the receiver keeps its partial
// data and per-stream hash state, reports how far every stream got
// (mailbox phase "bsf-resume"), and both sides reconnect with the next
// attempt's keys, continuing where they left off. The final ack
// carries the hash of the concatenated per-stream sha256 sums.

// defaultTransitPort is the port the transit listener tries to bind
// first (random fallback when several senders share a host).
const defaultTransitPort = 40010

const (
	parallelResumePhase = "bsf-resume"
	parallelAcceptWait  = 3 * time.Second
	parallelFirstWait   = 30 * time.Second
	parallelResumeWait  = 15 * time.Minute
	parallelRecordSize  = 1 << 18
)

type parallelResumeMsg struct {
	Attempt  int     `json:"attempt"`
	Progress []int64 `json:"progress"`
}

// streamHello is the first record on every parallel connection,
// encrypted with the base transit keys (independent of stream and
// attempt), telling the receiver which stream index this connection
// carries. Connection ordering alone cannot express that: handshakes
// complete in arbitrary order.
type streamHello struct {
	Stream int `json:"stream"`
}

func sendStreamHellos(conns []net.Conn, transitKey []byte) error {
	for i, conn := range conns {
		cryptor := newTransportCryptor(conn, transitKey, "transit_record_receiver_key", "transit_record_sender_key")
		body, err := json.Marshal(streamHello{Stream: i})
		if err != nil {
			return err
		}
		if err := cryptor.writeRecord(body); err != nil {
			return err
		}
	}
	return nil
}

// readStreamHellos returns cryptors for the connections ordered by
// their stream index as announced in each connection's hello record.
// The cryptors keep the bufio buffer the hello was read through: the
// stream's first records often arrive in the same tcp segment as the
// hello and would otherwise be lost with a fresh reader.
func readStreamHellos(conns []net.Conn, transitKey []byte) ([]*transportCryptor, error) {
	ordered := make([]*transportCryptor, len(conns))
	for _, conn := range conns {
		cryptor := newTransportCryptor(conn, transitKey, "transit_record_sender_key", "transit_record_receiver_key")
		rec, err := cryptor.readRecord()
		if err != nil {
			return nil, fmt.Errorf("read stream hello: %s", err)
		}

		var hello streamHello
		if err := json.Unmarshal(rec, &hello); err != nil {
			return nil, fmt.Errorf("decode stream hello: %s", err)
		}
		if hello.Stream < 0 || hello.Stream >= len(conns) || ordered[hello.Stream] != nil {
			return nil, fmt.Errorf("bogus stream hello index %d", hello.Stream)
		}
		ordered[hello.Stream] = cryptor
	}

	for i, cryptor := range ordered {
		if cryptor == nil {
			return nil, fmt.Errorf("no connection announced stream %d", i)
		}
	}

	return ordered, nil
}

// probeDirectAddr sequentially dials the peer's direct hints until one
// handshakes, returning that connection and address. Unlike
// connectDirect it does not race every hint, so it opens exactly one
// connection.
func probeDirectAddr(ctx context.Context, transport *fileTransport, otherTransit *transitMsg) (net.Conn, string, error) {
	for _, hint := range otherTransit.HintsV1 {
		if hint.Type != "direct-tcp-v1" {
			continue
		}

		addr := net.JoinHostPort(hint.Hostname, strconv.Itoa(hint.Port))
		conn, err := dialDirectAddrs(ctx, transport, addr, 1)
		if err != nil || len(conn) != 1 {
			continue
		}

		return conn[0], addr, nil
	}

	return nil, "", errors.New("no direct connection")
}

func streamChunkBounds(total int64, n, i int) (int64, int64) {
	start := total * int64(i) / int64(n)
	end := total * int64(i+1) / int64(n)
	return start, end
}

func streamPurposes(stream, attempt int) (readPurpose, writePurpose string) {
	return fmt.Sprintf("transit_record_receiver_key/bsfp/%d/%d", stream, attempt),
		fmt.Sprintf("transit_record_sender_key/bsfp/%d/%d", stream, attempt)
}

// sendParallelFile streams the file across n already-accepted
// connections, resuming on connection drops until it completes or the
// peer goes away. It takes ownership of the listener (closing it at
// the end) and of the collector (closing it immediately so resume
// messages can be read from the raw phase channel).
func sendParallelFile(ctx context.Context, collector *msgCollector, clientProto *clientProtocol, transport *fileTransport, transitKey []byte, total int64, src io.ReaderAt, conns []net.Conn, progressFn func(sent, total int64)) error {
	if transport.listener != nil {
		defer transport.listener.Close()
	}
	collector.close()

	n := len(conns)

	sent := make([]int64, n)
	hashers := make([]hash.Hash, n)
	for i := range hashers {
		hashers[i] = sha256.New()
	}

	var progress int64
	reportProgress := func() {
		if progressFn != nil {
			progressFn(atomic.LoadInt64(&progress), total)
		}
	}

	attempt := 0

	// the pump loop only touches the atomic progress counter; report
	// on a ticker so the caller sees smooth progress instead of a jump
	// to 100% at the end
	if progressFn != nil {
		done := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					reportProgress()
				}
			}
		}()
	}

	for {
		if err := sendStreamHellos(conns, transitKey); err != nil {
			return err
		}

		// one cryptor per stream per attempt; the stream 0 cryptor is
		// reused for the final ack so no buffered record bytes are lost
		cryptors := make([]*transportCryptor, n)
		for i := range cryptors {
			readPurpose, writePurpose := streamPurposes(i, attempt)
			cryptors[i] = newTransportCryptor(conns[i], transitKey, readPurpose, writePurpose)
		}

		pumpErr := pumpAllStreams(ctx, src, cryptors, transitKey, attempt, total, sent, hashers, &progress)
		if pumpErr == nil {
			// every stream done: read the receiver's ack from stream 0.
			// A transport failure here still means the connection
			// dropped after all data was buffered, so fall through to
			// the resume wait instead of failing the transfer.
			respRec, err := cryptors[0].readRecord()
			if err != nil {
				pumpErr = err
			} else {
				var ack fileTransportAck
				if err := json.Unmarshal(respRec, &ack); err != nil {
					return fmt.Errorf("decode final ack: %s", err)
				}

				if ack.Ack != "ok" {
					return errors.New("got non ok final ack from receiver")
				}

				var want []byte
				for i := range hashers {
					want = append(want, hashers[i].Sum(nil)...)
				}
				wantSum := sha256.Sum256(want)

				if ack.SHA256 != hex.EncodeToString(wantSum[:]) {
					return errors.New("receiver sha256 mismatch")
				}

				reportProgress()
				for _, c := range cryptors {
					c.Close()
				}
				return nil
			}
		}

		// a stream dropped: close the broken connections so the
		// receiver's other readers also fail, then wait for it to say
		// where it is
		for _, c := range cryptors {
			c.Close()
		}

		resume, err := waitParallelResume(ctx, clientProto, n)
		if err != nil {
			return fmt.Errorf("transfer interrupted (%s): %s", pumpErr, err)
		}

		// the receiver is authoritative; rewind to its positions and
		// recompute the per-stream hash prefixes (a hash cannot be
		// rewound)
		for i := 0; i < n; i++ {
			_, end := streamChunkBounds(total, n, i)
			chunkLen := end - total*int64(i)/int64(n)
			if resume.Progress[i] < 0 || resume.Progress[i] > chunkLen {
				return fmt.Errorf("bogus resume progress %d for stream %d", resume.Progress[i], i)
			}

			sent[i] = resume.Progress[i]
			if err := rehashPrefix(src, hashers[i], total*int64(i)/int64(n), sent[i]); err != nil {
				return err
			}
		}

		attempt = resume.Attempt

		conns, err = transport.acceptConnections(ctx, n)
		if err != nil {
			return err
		}
		if len(conns) != n {
			for _, c := range conns {
				c.Close()
			}
			return errors.New("peer did not re-open all streams")
		}
	}
}

// pumpAllStreams sends the remaining bytes of every chunk on its own
// connection, returning the first error if any stream breaks.
func pumpAllStreams(ctx context.Context, src io.ReaderAt, cryptors []*transportCryptor, transitKey []byte, attempt int, total int64, sent []int64, hashers []hash.Hash, progress *int64) error {
	n := len(cryptors)

	type streamErr struct {
		err error
	}

	errCh := make(chan streamErr, n)
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			cryptor := cryptors[i]
			start, end := streamChunkBounds(total, n, i)
			off := start + sent[i]
			remaining := (end - start) - sent[i]

			buf := make([]byte, parallelRecordSize-secretbox.Overhead)
			for remaining > 0 {
				select {
				case <-ctx.Done():
					errCh <- streamErr{ctx.Err()}
					return
				default:
				}

				want := len(buf)
				if int64(want) > remaining {
					want = int(remaining)
				}

				got, err := src.ReadAt(buf[:want], off)
				if got > 0 {
					if err := cryptor.writeRecord(buf[:got]); err != nil {
						errCh <- streamErr{err}
						return
					}
					hashers[i].Write(buf[:got])
					off += int64(got)
					remaining -= int64(got)
					sent[i] += int64(got)
					atomic.AddInt64(progress, int64(got))
				}
				if err == io.EOF && got == 0 {
					errCh <- streamErr{io.ErrUnexpectedEOF}
					return
				} else if err != nil && err != io.EOF {
					errCh <- streamErr{err}
					return
				}
			}

		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case e := <-errCh:
		cancel()
		return e.err
	}
}

// rehashPrefix recomputes a stream's hash over the first length bytes
// of its chunk after a resume rewound the stream position.
func rehashPrefix(src io.ReaderAt, h hash.Hash, start, length int64) error {
	h.Reset()
	buf := make([]byte, 1<<18)
	off := start
	remaining := length
	for remaining > 0 {
		want := len(buf)
		if int64(want) > remaining {
			want = int(remaining)
		}
		got, err := src.ReadAt(buf[:want], off)
		if got > 0 {
			h.Write(buf[:got])
			off += int64(got)
			remaining -= int64(got)
		}
		if err == io.EOF && got == 0 {
			return io.ErrUnexpectedEOF
		} else if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

func waitParallelResume(ctx context.Context, clientProto *clientProtocol, n int) (*parallelResumeMsg, error) {
	deadline := time.After(parallelResumeWait)

	type phaseMsg struct {
		msg rendezvous.MailboxEvent
		ok  bool
		err error
	}

	for {
		ch := make(chan phaseMsg, 1)
		go func() {
			select {
			case gotMsg := <-clientProto.ch:
				if gotMsg.Error != nil {
					ch <- phaseMsg{err: gotMsg.Error}
					return
				}
				ch <- phaseMsg{msg: gotMsg, ok: true}
			case <-ctx.Done():
				ch <- phaseMsg{err: ctx.Err()}
			}
		}()

		select {
		case m := <-ch:
			if m.err != nil {
				return nil, m.err
			}
			if m.msg.Phase != parallelResumePhase {
				continue
			}

			var resume parallelResumeMsg
			if err := openAndUnmarshal(&resume, m.msg, clientProto.sharedKey); err != nil {
				return nil, fmt.Errorf("decode resume msg: %s", err)
			}
			if len(resume.Progress) != n {
				return nil, fmt.Errorf("resume msg has %d streams, want %d", len(resume.Progress), n)
			}
			return &resume, nil
		case <-deadline:
			return nil, errors.New("peer did not resume within " + parallelResumeWait.String())
		}
	}
}

// receiveParallelFile is the receiver half: it writes the chunks into
// dest as they arrive, reconnecting with a resume message whenever a
// stream drops, and finally acknowledges with the concatenated
// per-stream hash.
func receiveParallelFile(ctx context.Context, clientProto *clientProtocol, transport *fileTransport, transitKey []byte, addr string, conns []net.Conn, total int64, n int, dest io.WriterAt, progressFn func(received, total int64)) error {
	received := make([]int64, n)
	hashers := make([]hash.Hash, n)
	for i := range hashers {
		hashers[i] = sha256.New()
	}

	var progress int64
	attempt := 0

	for {
		helloCryptors, err := readStreamHellos(conns, transitKey)
		if err != nil {
			return err
		}
		for i := range conns {
			conns[i] = helloCryptors[i].conn
		}

		// reuse the readers the hellos came through: the first data
		// records may already sit in their buffers
		cryptors := make([]*transportCryptor, n)
		for i := range cryptors {
			readPurpose, writePurpose := streamPurposes(i, attempt)
			cryptors[i] = newTransportCryptorWithReader(helloCryptors[i].conn, helloCryptors[i].reader, transitKey, writePurpose, readPurpose)
		}

		err = recvAllStreams(ctx, cryptors, attempt, total, received, hashers, dest, &progress, progressFn)
		if err == nil {
			var concat []byte
			for i := range hashers {
				concat = append(concat, hashers[i].Sum(nil)...)
			}
			sum := sha256.Sum256(concat)

			ack := fileTransportAck{
				Ack:    "ok",
				SHA256: hex.EncodeToString(sum[:]),
			}
			ackBody, err := json.Marshal(ack)
			if err != nil {
				return err
			}
			if err := cryptors[0].writeRecord(ackBody); err != nil {
				return fmt.Errorf("send final ack: %s", err)
			}

			for _, c := range cryptors {
				c.Close()
			}
			return nil
		}

		// a stream dropped: close all connections so the sender's
		// writers unblock, then tell it where to resume from
		for _, c := range cryptors {
			c.Close()
		}

		attempt++

		resume := parallelResumeMsg{
			Attempt:  attempt,
			Progress: make([]int64, n),
		}
		copy(resume.Progress, received)

		cause := err
		if werr := clientProto.writePhase(ctx, parallelResumePhase, resume); werr != nil {
			return fmt.Errorf("transfer interrupted (%s) and telling the sender failed: %s", cause, werr)
		}

		// the network may still be down when we get here; keep
		// retrying while the sender is still waiting for us
		var newConns []net.Conn
		var rerr error
		retryDeadline := time.Now().Add(parallelResumeWait - time.Minute)
		for {
			newConns, rerr = dialDirectAddrs(ctx, transport, addr, n)
			if rerr == nil {
				break
			}
			if ctx.Err() != nil || time.Now().After(retryDeadline) {
				return fmt.Errorf("transfer interrupted (%s) and reconnect failed: %s", cause, rerr)
			}
			time.Sleep(2 * time.Second)
		}
		conns = newConns
	}
}

// recvAllStreams writes every chunk into dest as records arrive.
func recvAllStreams(ctx context.Context, cryptors []*transportCryptor, attempt int, total int64, received []int64, hashers []hash.Hash, dest io.WriterAt, progress *int64, progressFn func(received, total int64)) error {
	n := len(cryptors)

	errCh := make(chan error, n)
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			cryptor := cryptors[i]
			start, end := streamChunkBounds(total, n, i)
			chunkLen := end - start
			off := start + received[i]

			for (off - start) < chunkLen {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				default:
				}

				out, err := cryptor.readRecord()
				if err != nil {
					errCh <- err
					return
				}

				if _, err := dest.WriteAt(out, off); err != nil {
					errCh <- err
					return
				}
				hashers[i].Write(out)
				off += int64(len(out))
				received[i] += int64(len(out))
				atomic.AddInt64(progress, int64(len(out)))
				if progressFn != nil {
					progressFn(atomic.LoadInt64(progress), total)
				}
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case err := <-errCh:
		cancel()
		<-done
		return err
	}
}

// dialDirectAddrs dials n connections to addr and runs the transit
// handshake on each.
func dialDirectAddrs(ctx context.Context, transport *fileTransport, addr string, n int) ([]net.Conn, error) {
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		// a hint that blackholes must not stall the transfer for
		// minutes on the default tcp timeout
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return nil, err
		}

		success := make(chan net.Conn, 1)
		fail := make(chan string, 1)
		go transport.directRecvHandshake(ctx, addr, conn, success, fail)

		select {
		case c := <-success:
			conns = append(conns, c)
		case reason := <-fail:
			conn.Close()
			for _, c := range conns {
				c.Close()
			}
			return nil, errors.New("transit handshake failed: " + reason)
		case <-ctx.Done():
			conn.Close()
			for _, c := range conns {
				c.Close()
			}
			return nil, ctx.Err()
		}
	}

	return conns, nil
}

// parallelReceive is the receiver-side state of a parallel transfer,
// stashed on the IncomingMessage until the caller drives it with
// ReceiveFileInto.
type parallelReceive struct {
	clientProto *clientProtocol
	transport   *fileTransport
	transitKey  []byte
	peerTransit transitMsg
	streams     int
	total       int64
}

// ParallelStreams returns the number of transit streams the sender
// offered, or 0 for the standard single stream protocol.
func (m *IncomingMessage) ParallelStreams() int {
	if m.parallel == nil {
		return 0
	}
	return m.parallel.streams
}

// ReceiveFileInto receives a parallel file offer into dest, which must
// support writing at arbitrary offsets. If a stream drops the receiver
// reconnects and resumes instead of failing. progressFn, when set,
// receives the running total.
func (m *IncomingMessage) ReceiveFileInto(ctx context.Context, dest io.WriterAt, progressFn func(received, total int64)) error {
	p := m.parallel
	if p == nil {
		return errors.New("not a parallel transfer")
	}

	// initializeTransfer sends the answer and set up our state
	if err := m.initializeTransfer(); err != nil {
		return err
	}

	closeMailbox := func(err error) {
		mood := rendezvous.Errory
		if err == nil {
			mood = rendezvous.Happy
		} else if err == errDecryptFailed {
			mood = rendezvous.Scary
		}

		// bounded: the peer may already be gone and Close would
		// otherwise wait forever on its response
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		p.clientProto.rc.Close(closeCtx, mood)
	}

	conn1, addr, perr := probeDirectAddr(ctx, p.transport, &p.peerTransit)
	if perr != nil {
		// a wifi blip can fail every probe at once; the sender is
		// usually still there, so try once more before deciding there
		// is no direct path
		time.Sleep(time.Second)
		conn1, addr, perr = probeDirectAddr(ctx, p.transport, &p.peerTransit)
	}
	if perr != nil {
		// no direct path (both peers behind hard NAT): fall back to a
		// single relay stream written sequentially
		err := m.receiveViaRelayFallback(ctx, dest, progressFn)
		closeMailbox(err)
		return err
	}

	conns := []net.Conn{conn1}
	more, derr := dialDirectAddrs(ctx, p.transport, addr, p.streams-1)
	if derr != nil {
		conn1.Close()
		closeMailbox(derr)
		return derr
	}
	conns = append(conns, more...)

	rerr := receiveParallelFile(ctx, p.clientProto, p.transport, p.transitKey, addr, conns, p.total, p.streams, dest, progressFn)
	closeMailbox(rerr)
	return rerr
}

// receiveViaRelayFallback streams the file through the transit relay
// on a single connection when no direct connection could be made.
func (m *IncomingMessage) receiveViaRelayFallback(ctx context.Context, dest io.WriterAt, progressFn func(received, total int64)) error {
	p := m.parallel

	conn, err := p.transport.connectViaRelay(&p.peerTransit)
	if err != nil {
		return err
	}
	if conn == nil {
		return errors.New("failed to establish connection")
	}

	cryptor := newTransportCryptor(conn, p.transitKey, "transit_record_sender_key", "transit_record_receiver_key")
	hasher := sha256.New()

	var off int64
	for off < p.total {
		out, err := cryptor.readRecord()
		if err != nil {
			return err
		}
		if _, err := dest.WriteAt(out, off); err != nil {
			return err
		}
		hasher.Write(out)
		off += int64(len(out))
		if progressFn != nil {
			progressFn(off, p.total)
		}
	}

	sum := sha256.Sum256(hasher.Sum(nil))
	ack := fileTransportAck{
		Ack:    "ok",
		SHA256: hex.EncodeToString(sum[:]),
	}
	ackBody, err := json.Marshal(ack)
	if err != nil {
		return err
	}

	// the fallback receiver hashes the whole stream, which matches the
	// sender's single-stream hash only if it also used one stream; the
	// sender falls back automatically when we did not open parallel
	// streams, so the concatenated-hash ack of the parallel protocol
	// does not apply here. The sender treats a 1-conn accept as the
	// legacy protocol and compares against its whole-file hash.
	// For that comparison to work we must send the whole-file hash,
	// which is exactly what we computed above.
	return cryptor.writeRecord(ackBody)
}
