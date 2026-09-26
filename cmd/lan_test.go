package cmd

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dwdcth/bsf/wormhole"
	"github.com/spf13/cobra"
)

func TestCodeNameplate(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"3-cinnamon-chalk-wizard", "3"},
		{"42-foo", "42"},
		{"007-test-code", "007"},
		{"28471-random-ish", "28471"},
		{"", ""},
		{"3", "3"},
		{"foo-3-bar", ""},
		{"-3-foo", ""},
	}

	for _, tt := range tests {
		if got := codeNameplate(tt.code); got != tt.want {
			t.Errorf("codeNameplate(%q) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestBroadcastAddresses(t *testing.T) {
	for _, addr := range broadcastAddresses() {
		if strings.HasPrefix(addr.String(), "0.") {
			t.Fatalf("bogus broadcast address %s (16-byte ip indexing bug?)", addr)
		}
	}
}

// retryFor calls f until it returns true or the deadline passes.
func retryFor(d time.Duration, f func() bool) error {
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			return errors.New("condition not met before deadline")
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// discoverWithRetry retries broadcast discovery a few times; udp can
// drop every probe on a busy ci runner.
func discoverWithRetry(t *testing.T, nameplate string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if found := discoverRendezvous(nameplate); found != "" {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatal("broadcast discovery did not find the sender")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestBroadcastDiscovery(t *testing.T) {
	url, shutdown, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdown()

	var sender wormhole.Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendText(context.Background(), "broadcast discovery test")
	if err != nil {
		t.Fatal(err)
	}

	found := discoverWithRetry(t, codeNameplate(code))

	var receiver wormhole.Client
	receiver.RendezvousURL = found
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatalf("receive via discovered server %s: %s", found, err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "broadcast discovery test" {
		t.Fatalf("received %q, want %q", body, "broadcast discovery test")
	}

	if res := <-statusCh; !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestBroadcastDiscoveryMultipleServers(t *testing.T) {
	// two advertised servers; the code only lives on one, discovery
	// must answer with the server that holds that nameplate
	_, shutdownA, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdownA()

	urlB, shutdownB, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdownB()

	var sender wormhole.Client
	sender.RendezvousURL = urlB
	code, statusCh, err := sender.SendText(context.Background(), "multi server discovery test")
	if err != nil {
		t.Fatal(err)
	}

	found := discoverWithRetry(t, codeNameplate(code))

	var receiver wormhole.Client
	receiver.RendezvousURL = found
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatalf("receive via discovered server %s: %s", found, err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "multi server discovery test" {
		t.Fatalf("received %q, want %q", body, "multi server discovery test")
	}

	if res := <-statusCh; !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestActiveNameplatesBroadcast(t *testing.T) {
	url, shutdown, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdown()

	var sender wormhole.Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendText(context.Background(), "broadcast completion test")
	if err != nil {
		t.Fatal(err)
	}

	want := codeNameplate(code)
	nameplates, err := activeNameplates()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, np := range nameplates {
		if np == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("nameplate %s not in %v", want, nameplates)
	}

	var receiver wormhole.Client
	receiver.RendezvousURL = url
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(msg); err != nil {
		t.Fatal(err)
	}
	if res := <-statusCh; !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestRootHasCodeCompletion(t *testing.T) {
	if rootCmd.ValidArgsFunction == nil {
		t.Fatal("root command has no ValidArgsFunction")
	}

	// word completion for a started code must work through the root
	// command too
	candidates, flags := rootCmd.ValidArgsFunction(rootCmd, []string{}, "1-tor")
	if len(candidates) == 0 {
		t.Fatal("expected word candidates for partial code")
	}
	for _, c := range candidates {
		if !strings.HasPrefix(c, "1-tor") {
			t.Fatalf("candidate %q does not extend the partial code", c)
		}
	}
	if flags&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Error("expected NoFileComp directive")
	}
}
