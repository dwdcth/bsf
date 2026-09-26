package cmd

import (
	"context"
	"io"
	"testing"

	"github.com/psanford/wormhole-william/wormhole"
)

func TestStartRendezvousServer(t *testing.T) {
	ts, err := startRendezvousServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	url := ts.WebSocketURL()
	if url == "" {
		t.Fatal("empty websocket url")
	}

	ctx := context.Background()

	var sender wormhole.Client
	sender.RendezvousURL = url
	code, statusChan, err := sender.SendText(ctx, "lan rendezvous server test")
	if err != nil {
		t.Fatal(err)
	}

	var receiver wormhole.Client
	receiver.RendezvousURL = url
	msg, err := receiver.Receive(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "lan rendezvous server test" {
		t.Fatalf("received %q, want %q", body, "lan rendezvous server test")
	}

	res := <-statusChan
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}
