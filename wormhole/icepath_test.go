package wormhole

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
)

func TestIceHintJSONRoundTrip(t *testing.T) {
	msg := transitMsg{
		AbilitiesV1: []transitAbility{
			{Type: "direct-tcp-v1"},
			{Type: "relay-v1"},
			{Type: "direct-udp-ice-v1"},
		},
		HintsV1:  make([]transitHintsV1, 0),
		Parallel: 4,
		ICE: &iceHint{
			Ufrag:      "ufrag",
			Pwd:        "pwd",
			Stun:       "stun:example.com:3478",
			Candidates: []string{"candidate:1 1 UDP 1 127.0.0.1 50000 typ host"},
		},
	}

	out, err := json.Marshal(&msg)
	if err != nil {
		t.Fatal(err)
	}

	var back transitMsg
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}

	if back.ICE == nil {
		t.Fatalf("ice hint lost in round trip: %s", out)
	}
	if back.ICE.Ufrag != "ufrag" || back.ICE.Pwd != "pwd" || back.ICE.Stun != "stun:example.com:3478" {
		t.Fatalf("ice hint fields mismatch: %+v", back.ICE)
	}
	if len(back.ICE.Candidates) != 1 || back.ICE.Candidates[0] != msg.ICE.Candidates[0] {
		t.Fatalf("ice candidates mismatch: %+v", back.ICE.Candidates)
	}
	if back.Parallel != 4 {
		t.Fatalf("parallel mismatch: %d", back.Parallel)
	}
}

func TestTransitMsgPythonCompat(t *testing.T) {
	// a python magic-wormhole transit message carries none of the bsf
	// fields; decoding must succeed with them empty
	raw := `{"abilities-v1": [{"type": "direct-tcp-v1"}, {"type": "relay-v1"}],
	         "hints-v1": [{"type": "direct-tcp-v1", "hostname": "192.168.1.4", "port": 40010, "priority": 0.0}]}`

	var msg transitMsg
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.ICE != nil {
		t.Fatalf("expected nil ice hint, got %+v", msg.ICE)
	}
	if msg.Parallel != 0 {
		t.Fatalf("expected zero parallel, got %d", msg.Parallel)
	}

	// and a bsf transit message must not confuse an old decoder: the
	// url field stays absent unless a ws relay is offered
	hint := transitHintsV1{Type: "direct-tcp-v1", Hostname: "h", Port: 1}
	out, err := json.Marshal(&hint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("url")) {
		t.Fatalf("unexpected url field: %s", out)
	}
}

func TestStunServersFor(t *testing.T) {
	var c Client
	if got := stunServersFor(&c, ""); len(got) == 0 || got[0] != publicSTUNServers[0] {
		t.Fatalf("expected public defaults, got %v", got)
	}

	c.STUNServers = []string{"stun:mine:1"}
	if got := stunServersFor(&c, "stun:theirs:2"); len(got) != 1 || got[0] != "stun:mine:1" {
		t.Fatalf("explicit config must win, got %v", got)
	}

	c.STUNServers = nil
	if got := stunServersFor(&c, "stun:theirs:2"); len(got) != 1 || got[0] != "stun:theirs:2" {
		t.Fatalf("sender hint must come second, got %v", got)
	}

	c.DisableTransitRelay = true
	if got := stunServersFor(&c, ""); got != nil {
		t.Fatalf("lan-only mode must gather host-only, got %v", got)
	}
}

func TestNewSelfSignedCertDiffers(t *testing.T) {
	a, err := newSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Certificate[0], b.Certificate[0]) {
		t.Fatal("two transfers must not share a certificate")
	}
}

// TestWormholeFileTransferViaICE runs a whole transfer over the punched
// path: the TCP listener is disabled and the relay forbidden, so the ICE
// punch is the only possible route — success proves the punch worked.
func TestWormholeFileTransferViaICE(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	testDisableLocalListener = true
	defer func() { testDisableLocalListener = false }()
	testICEIncludeLoopback = true
	defer func() { testICEIncludeLoopback = false }()

	newClient := func() Client {
		var c Client
		c.RendezvousURL = url
		c.DisableTransitRelay = true
		c.EnableICE = true
		return c
	}

	c0 := newClient()
	c1 := newClient()

	fileContent := make([]byte, 1<<18)
	for i := range fileContent {
		fileContent[i] = byte(i)
	}

	code, resultCh, err := c0.SendFile(ctx, "file.txt", bytes.NewReader(fileContent))
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := c1.Receive(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(receiver)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, fileContent) {
		t.Fatalf("File contents mismatch")
	}

	result := <-resultCh
	if !result.OK {
		t.Fatalf("Expected ok result but got: %+v", result)
	}
}

// TestWormholeFileTransferIceNotNegotiated runs with ICE enabled on the
// sender only: a punch requires both transit messages to carry the ice
// hint, so the transfer must complete over the relay like an old client.
func TestWormholeFileTransferIceNotNegotiated(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	testDisableLocalListener = true
	defer func() { testDisableLocalListener = false }()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	var c0 Client
	c0.RendezvousURL = url
	c0.TransitRelayAddress = relayServer.addr
	c0.EnableICE = true
	// keep gathering offline and fast: a closed local port refuses
	// instantly instead of timing out on a public server
	c0.STUNServers = []string{"stun:127.0.0.1:1"}

	var c1 Client
	c1.RendezvousURL = url
	c1.TransitRelayAddress = relayServer.addr

	fileContent := make([]byte, 1<<16)
	for i := range fileContent {
		fileContent[i] = byte(i)
	}

	code, resultCh, err := c0.SendFile(ctx, "file.txt", bytes.NewReader(fileContent))
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := c1.Receive(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(receiver)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, fileContent) {
		t.Fatalf("File contents mismatch")
	}

	result := <-resultCh
	if !result.OK {
		t.Fatalf("Expected ok result but got: %+v", result)
	}
}

// iceTestEnv forces transfers onto the punched path: no TCP listener, no
// relay, loopback candidates.
func iceTestEnv(t *testing.T) {
	testDisableLocalListener = true
	testICEIncludeLoopback = true
	t.Cleanup(func() {
		testDisableLocalListener = false
		testICEIncludeLoopback = false
	})
}

func TestWormholeParallelFileTransferViaICE(t *testing.T) {
	rs := rendezvousServertest(t)
	url := rs.WebSocketURL()
	iceTestEnv(t)

	payload := make([]byte, 4*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var sender Client
	sender.RendezvousURL = url
	sender.DisableTransitRelay = true
	sender.EnableICE = true
	code, statusCh, err := sender.SendFile(context.Background(), "ice-parallel.bin", bytes.NewReader(payload), WithParallel(4))
	if err != nil {
		t.Fatal(err)
	}

	var receiver Client
	receiver.RendezvousURL = url
	receiver.DisableTransitRelay = true
	receiver.EnableICE = true
	receiver.ParallelStreams = 4
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	if msg.ParallelStreams() != 4 {
		t.Fatalf("expected a 4-stream parallel offer, got %d", msg.ParallelStreams())
	}

	dest := &bytesBufferAt{}
	if err := msg.ReceiveFileInto(context.Background(), dest, nil); err != nil {
		t.Fatalf("parallel receive over ice failed: %s", err)
	}
	if !bytes.Equal(dest.Bytes(), payload) {
		t.Fatalf("received content does not match")
	}

	res := <-statusCh
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestWormholeParallelResumeViaICE(t *testing.T) {
	rs := rendezvousServertest(t)
	url := rs.WebSocketURL()
	iceTestEnv(t)

	payload := make([]byte, 4*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var sender Client
	sender.RendezvousURL = url
	sender.DisableTransitRelay = true
	sender.EnableICE = true
	code, statusCh, err := sender.SendFile(context.Background(), "ice-resume.bin", bytes.NewReader(payload), WithParallel(4))
	if err != nil {
		t.Fatal(err)
	}

	var receiver Client
	receiver.RendezvousURL = url
	receiver.DisableTransitRelay = true
	receiver.EnableICE = true
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
		t.Fatalf("resumed ice receive failed: %s", err)
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

// TestWormholeParallelReceiverRelayFallback covers the cross-NAT shape:
// a parallel-planning sender, a parallel-accepting receiver, no direct
// path, no punch — the receiver must finish over the single relay
// stream and ack with the whole-file hash the sender compares against
// (a regression: the fallback used to send a double hash and the sender
// reported "receiver sha256 mismatch" after a correct transfer).
func TestWormholeParallelReceiverRelayFallback(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()
	url := rs.WebSocketURL()

	testDisableLocalListener = true
	defer func() { testDisableLocalListener = false }()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	payload := make([]byte, 2*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var sender Client
	sender.RendezvousURL = url
	sender.TransitRelayAddress = relayServer.addr
	code, statusCh, err := sender.SendFile(context.Background(), "fb.bin", bytes.NewReader(payload), WithParallel(4))
	if err != nil {
		t.Fatal(err)
	}

	var receiver Client
	receiver.RendezvousURL = url
	receiver.TransitRelayAddress = relayServer.addr
	receiver.ParallelStreams = 4
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if msg.ParallelStreams() != 4 {
		t.Fatalf("expected a parallel offer, got %d", msg.ParallelStreams())
	}

	dest := &bytesBufferAt{}
	if err := msg.ReceiveFileInto(context.Background(), dest, nil); err != nil {
		t.Fatalf("relay fallback receive failed: %s", err)
	}
	if !bytes.Equal(dest.Bytes(), payload) {
		t.Fatalf("received content does not match")
	}

	res := <-statusCh
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}
