package wormhole

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// blockedConn is a net.Conn whose Write blocks until the conn is closed
// — a writer stuck in a flow-controlled write when its peer aborts.
type blockedConn struct {
	mu       sync.Mutex
	closed   bool
	release  chan struct{}
	returned chan struct{}
	once     sync.Once
}

func (c *blockedConn) Write(p []byte) (int, error) {
	<-c.release
	c.once.Do(func() { close(c.returned) })
	return 0, errors.New("closed")
}

func (c *blockedConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *blockedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.release)
	return nil
}
func (c *blockedConn) LocalAddr() net.Addr                { return nil }
func (c *blockedConn) RemoteAddr() net.Addr               { return nil }
func (c *blockedConn) SetDeadline(t time.Time) error      { return nil }
func (c *blockedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *blockedConn) SetWriteDeadline(t time.Time) error { return nil }

// failConn errors on the first Write, like a stream reset mid-transfer.
type failConn struct{}

func (c *failConn) Write(p []byte) (int, error)        { return 0, errors.New("reset") }
func (c *failConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (c *failConn) Close() error                       { return nil }
func (c *failConn) LocalAddr() net.Addr                { return nil }
func (c *failConn) RemoteAddr() net.Addr               { return nil }
func (c *failConn) SetDeadline(t time.Time) error      { return nil }
func (c *failConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *failConn) SetWriteDeadline(t time.Time) error { return nil }

// TestPumpAllStreamsDrainsWriters pins the resume race: a writer whose
// writeRecord completes just as another stream breaks must not still be
// running when pumpAllStreams returns — its late sent[i]/hashers[i]
// update would land after the caller rewound them for a resume and
// silently shift the next attempt's stream offsets (the receiver then
// waits forever for bytes the sender believes it sent; observed as the
// i386 CI hang of TestWormholeParallelResumeViaICE).
func TestPumpAllStreamsDrainsWriters(t *testing.T) {
	var transitKey [32]byte
	if _, err := rand.Read(transitKey[:]); err != nil {
		t.Fatal(err)
	}

	total := int64(2 * (1 << 18))
	payload := make([]byte, total)
	src := bytes.NewReader(payload)

	blocked := &blockedConn{
		release:  make(chan struct{}),
		returned: make(chan struct{}),
	}
	cryptors := []*transportCryptor{
		newTransportCryptor(blocked, transitKey[:], "r0", "w0"),
		newTransportCryptor(&failConn{}, transitKey[:], "r1", "w1"),
	}

	sent := make([]int64, 2)
	hashers := make([]hash.Hash, 2)
	for i := range hashers {
		hashers[i] = sha256.New()
	}
	progress := new(int64)

	returned := make(chan error, 1)
	go func() {
		returned <- pumpAllStreams(context.Background(), src, cryptors, transitKey[:], 0, total, sent, hashers, progress)
	}()

	// stream 1 breaks at once; stream 0's writer is stuck inside Write.
	// Whenever pumpAllStreams returns, that writer must already be done.
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("expected the stream error to surface")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pumpAllStreams never returned")
	}

	select {
	case <-blocked.returned:
	default:
		t.Fatal("pumpAllStreams returned while a writer was still active")
	}

	for i, s := range sent {
		if s != 0 {
			t.Fatalf("stream %d counted %d bytes; a failed write must not be counted", i, s)
		}
	}
}
