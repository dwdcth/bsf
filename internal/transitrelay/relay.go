// Package transitrelay implements the server side of the standard
// magic-wormhole TCP transit relay: two peers present the same
// HKDF-derived token (with different side ids) and the server pipes
// their bytes. bsf offers it via `bsf server --transit` so a self-hosted
// deployment has a fallback path that never touches the public relay.
package transitrelay

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// unpairedTimeout bounds how long a first connection waits for its peer
// before the server drops it.
var unpairedTimeout = 60 * time.Second

var headerPrefix = []byte("please relay ")
var headerSide = []byte(" for side ")

type waitingConn struct {
	conn   net.Conn
	side   string
	cancel chan struct{}
	once   sync.Once
}

// Server is a TCP transit relay.
type Server struct {
	l    net.Listener
	addr string
	wg   sync.WaitGroup

	mu      sync.Mutex
	waiting map[string]*waitingConn
}

// New starts a relay listening on addr.
func New(addr string) (*Server, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	s := &Server{
		l:       l,
		addr:    l.Addr().String(),
		waiting: make(map[string]*waitingConn),
	}

	go s.run()
	return s, nil
}

// Addr is the listening address ("host:port").
func (s *Server) Addr() string {
	return s.addr
}

// Close stops the listener and waits for the active pipes to drain.
func (s *Server) Close() {
	s.l.Close()
	s.wg.Wait()
}

func (s *Server) run() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn reads the "please relay <token> for side <side>\n"
// handshake and pairs two connections presenting the same token with
// different sides.
func (s *Server) handleConn(c net.Conn) {
	defer s.wg.Done()

	token, side, ok := readHandshake(c)
	if !ok {
		return
	}

	s.mu.Lock()
	first, found := s.waiting[token]
	if found && first.side != side {
		delete(s.waiting, token)
	}
	s.mu.Unlock()

	if !found {
		s.startWaiting(token, side, c)
		return
	}

	if first.side == side {
		// stray redial of the same peer: leave the original waiting
		c.Close()
		return
	}

	// the peer of a paired connection never goes back to the map
	first.once.Do(func() { close(first.cancel) })

	c.Write([]byte("ok\n"))
	first.conn.Write([]byte("ok\n"))

	log.Printf("transit relay: paired token %s", token[:8])

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		io.Copy(c, first.conn)
		c.Close()
		first.conn.Close()
	}()

	io.Copy(first.conn, c)
	c.Close()
	first.conn.Close()
}

// startWaiting registers the first side of a token and arms the
// unpaired-timeout watchdog.
func (s *Server) startWaiting(token, side string, c net.Conn) {
	w := &waitingConn{conn: c, side: side, cancel: make(chan struct{})}

	s.mu.Lock()
	s.waiting[token] = w
	s.mu.Unlock()

	go func() {
		select {
		case <-time.After(unpairedTimeout):
			s.mu.Lock()
			if s.waiting[token] == w {
				delete(s.waiting, token)
			}
			s.mu.Unlock()
			c.Close()
		case <-w.cancel:
		}
	}()
}

// readHandshake parses and validates the relay greeting, closing the
// connection on any mismatch.
func readHandshake(c net.Conn) (token, side string, ok bool) {
	bad := func() {
		c.Write([]byte("bad handshake\n"))
		c.Close()
	}

	buf := make([]byte, 64)

	readExact := func(n int, expect []byte) bool {
		got := buf[:n]
		if _, err := io.ReadFull(c, got); err != nil {
			c.Close()
			return false
		}
		if expect != nil && !bytes.Equal(got, expect) {
			bad()
			return false
		}
		return true
	}

	if !readExact(len(headerPrefix), headerPrefix) {
		return "", "", false
	}

	// 64 hex chars = 32-byte token
	if !readExact(64, nil) {
		return "", "", false
	}
	token = string(buf[:64])
	if _, err := hex.DecodeString(token); err != nil {
		bad()
		return "", "", false
	}

	if !readExact(len(headerSide), headerSide) {
		return "", "", false
	}

	// 16 hex chars = 8-byte side id
	if !readExact(16, nil) {
		return "", "", false
	}
	side = string(buf[:16])
	if _, err := hex.DecodeString(side); err != nil {
		bad()
		return "", "", false
	}

	// trailing newline
	if !readExact(1, nil) {
		return "", "", false
	}
	if buf[0] != '\n' {
		bad()
		return "", "", false
	}

	return token, side, true
}
