package wormhole

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
)

func rendezvousServertest(t *testing.T) *rendezvousservertest.TestServer {
	t.Helper()

	DefaultTransitRelayAddress = ""

	rs := rendezvousservertest.NewServer()
	t.Cleanup(rs.Close)

	return rs
}

func TestParallelSendRecvFile(t *testing.T) {
	rs := rendezvousServertest(t)
	url := rs.WebSocketURL()

	payload := make([]byte, 3*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var sender Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendFile(context.Background(), "parallel.bin", bytes.NewReader(payload), WithParallel(4))
	if err != nil {
		t.Fatal(err)
	}

	var receiver Client
	receiver.RendezvousURL = url
	receiver.ParallelStreams = 4
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	if msg.Type != TransferFile {
		t.Fatalf("expected file offer, got %s", msg.Type)
	}
	if msg.ParallelStreams() != 4 {
		t.Fatalf("expected 4 parallel streams, got %d", msg.ParallelStreams())
	}

	dest := &bytesBufferAt{}
	if err := msg.ReceiveFileInto(context.Background(), dest, nil); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dest.Bytes(), payload) {
		t.Fatalf("received %d bytes do not match payload (%d bytes)", dest.Len(), len(payload))
	}

	res := <-statusCh
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

// failOnceAt wraps an io.WriterAt and fails the first write that crosses
// the given offset, to simulate a connection drop mid transfer.
type failOnceAt struct {
	mu      sync.Mutex
	dest    io.WriterAt
	failAt  int64
	written int64
	failed  bool
}

func (f *failOnceAt) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	n, err := f.dest.WriteAt(p, off)
	if err == nil {
		f.written = off + int64(n)
	}
	if !f.failed && off+int64(len(p)) > f.failAt {
		f.failed = true
		return n, fmt.Errorf("injected stream failure")
	}
	return n, err
}

func TestParallelResumeAfterDrop(t *testing.T) {
	rs := rendezvousServertest(t)
	url := rs.WebSocketURL()

	payload := make([]byte, 4*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var sender Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendFile(context.Background(), "resume.bin", bytes.NewReader(payload), WithParallel(4))
	if err != nil {
		t.Fatal(err)
	}

	var receiver Client
	receiver.RendezvousURL = url
	receiver.ParallelStreams = 4
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	good := &bytesBufferAt{}
	dest := &failOnceAt{
		dest:   good,
		failAt: 512 * 1024,
	}

	if err := msg.ReceiveFileInto(context.Background(), dest, nil); err != nil {
		t.Fatalf("resumed receive failed: %s", err)
	}
	if !dest.failed {
		t.Fatal("expected the injected failure to happen")
	}

	if !bytes.Equal(good.Bytes(), payload) {
		t.Fatalf("received content does not match after resume")
	}

	res := <-statusCh
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestSingleStreamFallbackStillWorks(t *testing.T) {
	// a non-parallel receiver against a parallel-offering sender must
	// still work through the legacy single stream path
	rs := rendezvousServertest(t)
	url := rs.WebSocketURL()

	payload := make([]byte, 1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var sender Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendFile(context.Background(), "fallback.bin", bytes.NewReader(payload), WithParallel(4))
	if err != nil {
		t.Fatal(err)
	}

	var receiver Client
	receiver.RendezvousURL = url
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	// simulate a receiver that never does parallel: read it as a plain
	// stream like the legacy protocol does
	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("legacy read content mismatch")
	}

	res := <-statusCh
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

// bytesBufferAt is a growable, concurrency-safe io.WriterAt.
type bytesBufferAt struct {
	mu sync.Mutex
	b  []byte
}

func (x *bytesBufferAt) WriteAt(p []byte, off int64) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	end := off + int64(len(p))
	if int64(len(x.b)) < end {
		x.b = append(x.b, make([]byte, end-int64(len(x.b)))...)
	}
	return copy(x.b[off:end], p), nil
}

func (x *bytesBufferAt) Bytes() []byte {
	return x.b
}

func (x *bytesBufferAt) Len() int {
	return len(x.b)
}
