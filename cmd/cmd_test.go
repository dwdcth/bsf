package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"github.com/dwdcth/bsf/wormhole"
)

func TestLooksLikeRecvCode(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"3-cinnamon-chalk-wizard", true},
		{"42-foo", true},
		{"28-dinosaur-guidance", true},
		{"1-a2-b3", true},

		{"send", false},
		{"3", false},
		{"3-", false},
		{"3-foo-", false},
		{"3-foo--bar", false},
		{"-3-foo", false},
		{"3.5-foo", false},
		{"foo-3-bar", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := looksLikeRecvCode(tt.code); got != tt.want {
			t.Errorf("looksLikeRecvCode(%q) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestRootUnknownCommand(t *testing.T) {
	rootCmd.SetArgs([]string{"badcmd"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected unknown command error, got nil")
	}
	if !strings.Contains(err.Error(), `unknown command "badcmd"`) {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestRootBareCodeReceive(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	var sender wormhole.Client
	sender.RendezvousURL = rs.WebSocketURL()

	code, statusChan, err := sender.SendText(context.Background(), "bare code receive test")
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeRecvCode(code) {
		t.Fatalf("generated code %q does not match receive code pattern", code)
	}

	relayURL = rs.WebSocketURL()
	t.Cleanup(func() {
		relayURL = ""
	})
	rootCmd.SetArgs([]string{code})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("root command execute error: %s", err)
	}

	res := <-statusChan
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

// TestRootBareFileSend covers the send shorthand of the bare form:
// "bsf FILE" (no subcommand) must send the file, honor --code, and
// reach a library receiver intact.
func TestRootBareFileSend(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	payload := []byte("bare file send test")
	src, err := os.CreateTemp(t.TempDir(), "bsf-bare-send")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Write(payload); err != nil {
		t.Fatal(err)
	}
	src.Close()

	relayURL = rs.WebSocketURL()
	codeFlag = "7-bare-file-send"
	disableClipboard = true
	t.Cleanup(func() {
		relayURL = ""
		codeFlag = ""
		disableClipboard = false
	})

	received := make(chan []byte, 1)
	receiverErr := make(chan error, 1)
	go func() {
		var receiver wormhole.Client
		receiver.RendezvousURL = rs.WebSocketURL()
		msg, err := receiver.Receive(context.Background(), codeFlag)
		if err != nil {
			receiverErr <- err
			return
		}
		if msg.Type != wormhole.TransferFile {
			receiverErr <- fmt.Errorf("unexpected message type %v", msg.Type)
			return
		}
		// the 22-byte payload goes single-stream: Read drives the
		// standard transit protocol (parallel offers use
		// ReceiveFileInto instead)
		got, err := io.ReadAll(msg)
		if err != nil {
			receiverErr <- err
			return
		}
		received <- got
	}()

	rootCmd.SetArgs([]string{src.Name()})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("root command execute error: %s", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("received %q, want %q", got, payload)
		}
	case err := <-receiverErr:
		t.Fatalf("receiver error: %s", err)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the receiver")
	}
}
