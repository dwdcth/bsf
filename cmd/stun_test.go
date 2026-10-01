package cmd

import (
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

// probeSTUN checks whether addr answers STUN binding requests within a
// short window; it returns the "stun:host:port" uri on success.
func probeSTUN(addr string) string {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	c, err := stun.NewClient(conn, stun.WithRTO(600*time.Millisecond))
	if err != nil {
		return ""
	}
	defer c.Close()

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var mapped stun.XORMappedAddress
	errCh := make(chan error, 1)
	if err := c.Do(msg, func(ev stun.Event) {
		if ev.Error != nil {
			errCh <- ev.Error
			return
		}
		errCh <- mapped.GetFrom(ev.Message)
	}); err != nil {
		return ""
	}

	select {
	case err := <-errCh:
		if err != nil || mapped.IP == nil {
			return ""
		}
		return "stun:" + addr
	case <-time.After(1200 * time.Millisecond):
		return ""
	}
}

func TestSTUNServerAnswersBindings(t *testing.T) {
	pc, srv, err := startSTUNServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	defer pc.Close()

	addr := pc.LocalAddr().String()
	if uri := probeSTUN(addr); uri != "stun:"+addr {
		t.Fatalf("expected stun:%s, got %q", addr, uri)
	}
}

func TestProbeSTUNUnreachable(t *testing.T) {
	// a closed local port refuses instantly; a probe against it must
	// come back empty, not with a bogus uri
	if uri := probeSTUN("127.0.0.1:1"); uri != "" {
		t.Fatalf("expected empty uri, got %q", uri)
	}
}
