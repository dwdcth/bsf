package cmd

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dwdcth/bsf/wormhole"
)

func TestSendSessionWaitCancelsLosers(t *testing.T) {
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())

	leg1 := make(chan wormhole.SendResult, 1)
	leg2 := make(chan wormhole.SendResult, 1)

	session := &sendSession{
		legs: []sendLeg{
			{cancel: cancel1, status: leg1},
			{cancel: cancel2, status: leg2},
		},
	}

	leg1 <- wormhole.SendResult{OK: true}

	res := session.wait()
	if !res.OK {
		t.Fatalf("expected winning leg result, got %+v", res)
	}

	// the losing leg must have been cancelled
	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Error("losing leg was not cancelled")
	}
	if err := ctx1.Err(); err != nil {
		t.Error("winning leg should not be cancelled")
	}
}

func dualSendSession(t *testing.T, msg string) (*sendSession, func()) {
	t.Helper()

	session, err := startSendSession(func(c *wormhole.Client, ctx context.Context, code string) (string, chan wormhole.SendResult, error) {
		opts := []wormhole.SendOption{}
		if code != "" {
			opts = append(opts, wormhole.WithCode(code))
		}
		return c.SendText(ctx, msg, opts...)
	})
	if err != nil {
		// the embedded/mDNS server is environment dependent; on hosts
		// where it cannot start there is nothing to test here
		t.Skipf("cannot start send session: %s", err)
	}

	return session, func() {
		for _, leg := range session.legs {
			leg.cancel()
		}
		session.shutdown()
	}
}

func TestDualSendReceiverViaLAN(t *testing.T) {
	ts, err := startRendezvousServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	relayURL = ts.WebSocketURL()
	lanMode = false
	t.Cleanup(func() {
		relayURL = ""
		lanMode = false
	})

	session, cleanup := dualSendSession(t, "dual send via lan")
	defer cleanup()

	if len(session.legs) != 2 {
		// no lan leg means this host cannot run the embedded advertised
		// server (e.g. no usable interface or mDNS port)
		t.Skipf("expected 2 legs (relay + lan), got %d", len(session.legs))
	}

	// the lan leg mirrors the relay-minted code
	found := discoverRendezvous(codeNameplate(session.code))
	if found == "" {
		t.Skip("mDNS multicast not available in this environment")
	}

	var receiver wormhole.Client
	receiver.RendezvousURL = found
	msg, err := receiver.Receive(context.Background(), session.code)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "dual send via lan" {
		t.Fatalf("received %q, want %q", body, "dual send via lan")
	}

	if res := session.wait(); !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestDualSendReceiverViaRelay(t *testing.T) {
	ts, err := startRendezvousServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	relayURL = ts.WebSocketURL()
	lanMode = false
	t.Cleanup(func() {
		relayURL = ""
		lanMode = false
	})

	session, cleanup := dualSendSession(t, "dual send via relay")
	defer cleanup()

	if len(session.legs) < 1 {
		t.Fatal("expected at least the relay leg")
	}

	// receiver goes straight to the relay, never touching mDNS
	var receiver wormhole.Client
	receiver.RendezvousURL = ts.WebSocketURL()
	msg, err := receiver.Receive(context.Background(), session.code)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "dual send via relay" {
		t.Fatalf("received %q, want %q", body, "dual send via relay")
	}

	if res := session.wait(); !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestDualSendRelayUnreachableFallsBackToLAN(t *testing.T) {
	// dead relay port fails fast, so the session must fall back to
	// minting the code on the embedded lan server alone
	relayURL = "ws://127.0.0.1:1/ws"
	lanMode = false
	t.Cleanup(func() {
		relayURL = ""
		lanMode = false
	})

	session, cleanup := dualSendSession(t, "fallback to lan")
	defer cleanup()

	if len(session.legs) != 1 {
		t.Skipf("expected 1 lan-only leg after relay failure, got %d", len(session.legs))
	}

	found := discoverRendezvous(codeNameplate(session.code))
	if found == "" {
		t.Skip("mDNS multicast not available in this environment")
	}

	var receiver wormhole.Client
	receiver.RendezvousURL = found
	msg, err := receiver.Receive(context.Background(), session.code)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "fallback to lan") {
		t.Fatalf("received %q", body)
	}

	if res := session.wait(); !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}
