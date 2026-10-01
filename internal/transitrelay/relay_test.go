package transitrelay

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayPairsAndPipes(t *testing.T) {
	s, err := New("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	token := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	sideA := "1111111111111111"
	sideB := "2222222222222222"

	connA, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	if _, err := fmt.Fprintf(connA, "please relay %s for side %s\n", token, sideA); err != nil {
		t.Fatal(err)
	}

	connB, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	if _, err := fmt.Fprintf(connB, "please relay %s for side %s\n", token, sideB); err != nil {
		t.Fatal(err)
	}

	gotOk := make([]byte, 3)
	connA.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(connA, gotOk); err != nil {
		t.Fatalf("side A never paired: %v", err)
	}
	if !bytes.Equal(gotOk, []byte("ok\n")) {
		t.Fatalf("side A got %q", gotOk)
	}

	connB.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(connB, gotOk); err != nil {
		t.Fatalf("side B never paired: %v", err)
	}

	go connA.Write([]byte("hello from A"))
	buf := make([]byte, len("hello from A"))
	connB.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(connB, buf); err != nil {
		t.Fatalf("pipe A->B: %v", err)
	}
	if string(buf) != "hello from A" {
		t.Fatalf("got %q", buf)
	}
}

func TestRelayRejectsBadHandshake(t *testing.T) {
	s, err := New("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("totally not a relay handshake\n")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], []byte("bad handshake")) {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestRelaySameSideDoesNotPair(t *testing.T) {
	s, err := New("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	token := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	sideA := "1111111111111111"

	connA, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	fmt.Fprintf(connA, "please relay %s for side %s\n", token, sideA)

	// a duplicate with the same side must be dropped without pairing
	connA2, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer connA2.Close()
	fmt.Fprintf(connA2, "please relay %s for side %s\n", token, sideA)

	buf := make([]byte, 3)
	connA2.SetReadDeadline(time.Now().Add(1 * time.Second))
	if n, err := connA2.Read(buf); err == nil || n > 0 {
		t.Fatalf("same-side duplicate should not pair, got %q (%v)", buf[:n], err)
	}
}
