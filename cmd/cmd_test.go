package cmd

import (
	"context"
	"strings"
	"testing"

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
	rootCmd.SetArgs([]string{code})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("root command execute error: %s", err)
	}

	res := <-statusChan
	if !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}
