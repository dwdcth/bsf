package cmd

import (
	"context"
	"io"
	"net"
	neturl "net/url"
	"strings"
	"testing"

	"github.com/hashicorp/mdns"
	"github.com/psanford/wormhole-william/wormhole"
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

func TestEntryURLs(t *testing.T) {
	entry := &mdns.ServiceEntry{
		AddrV4: net.ParseIP("192.168.1.5"),
		Port:   40000,
		InfoFields: []string{
			"ip=192.168.1.5",
			"ip=10.0.0.7",
			"ip=127.0.0.1",
		},
	}

	got := entryURLs(entry)
	want := []string{
		"ws://192.168.1.5:40000/ws",
		"ws://10.0.0.7:40000/ws",
	}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("url[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRendezvousHasNameplate(t *testing.T) {
	ts, err := startRendezvousServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	url := ts.WebSocketURL()

	var sender wormhole.Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendText(context.Background(), "nameplate probe test")
	if err != nil {
		t.Fatal(err)
	}

	if !rendezvousHasNameplate(url, codeNameplate(code)) {
		t.Error("expected server to list the active nameplate")
	}

	if rendezvousHasNameplate(url, "32000") {
		t.Error("did not expect nameplate 32000 to exist")
	}

	// finish the transfer so the sender goroutine exits
	var receiver wormhole.Client
	receiver.RendezvousURL = url
	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}

	if res := <-statusCh; !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}

func TestDiscoverRendezvousMultipleServers(t *testing.T) {
	// two advertised rendezvous servers; the code only lives on one of
	// them, so discovery has to ask each server until it finds the one
	// that knows the nameplate (or the working one happens to answer
	// first — either way the returned url must be usable)
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

	found := discoverRendezvous(codeNameplate(code))
	if found == "" {
		t.Skip("mDNS multicast not available in this environment")
	}

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

func TestBrowseRendezvousURLs(t *testing.T) {
	url, shutdown, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdown()

	urls := browseRendezvousURLs()
	if len(urls) == 0 {
		t.Skip("mDNS multicast not available in this environment")
	}

	// the browse result carries the advertised lan address while url is
	// the sender's loopback view of the same server, so match by port
	parsed, err := neturl.Parse(url)
	if err != nil {
		t.Fatal(err)
	}

	suffix := ":" + parsed.Port() + "/ws"
	found := false
	for _, u := range urls {
		if strings.HasSuffix(u, suffix) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no browsed url on port %s in %v", parsed.Port(), urls)
	}
}

func TestActiveNameplatesExplicitRelay(t *testing.T) {
	ts, err := startRendezvousServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	relayURL = ts.WebSocketURL()
	t.Cleanup(func() {
		relayURL = ""
	})

	var sender wormhole.Client
	sender.RendezvousURL = ts.WebSocketURL()
	code, statusCh, err := sender.SendText(context.Background(), "nameplate completion test")
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

	// finish the transfer
	var receiver wormhole.Client
	receiver.RendezvousURL = ts.WebSocketURL()
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

func TestActiveNameplatesMDNS(t *testing.T) {
	url, shutdown, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdown()

	var sender wormhole.Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendText(context.Background(), "mdns completion test")
	if err != nil {
		t.Fatal(err)
	}

	if browseRendezvousURLs() == nil {
		t.Skip("mDNS multicast not available in this environment")
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

func TestDiscoverRendezvous(t *testing.T) {
	url, shutdown, err := lanRendezvous()
	if err != nil {
		t.Skipf("cannot start advertised rendezvous server: %s", err)
	}
	defer shutdown()

	var sender wormhole.Client
	sender.RendezvousURL = url
	code, statusCh, err := sender.SendText(context.Background(), "mdns discovery test")
	if err != nil {
		t.Fatal(err)
	}

	found := discoverRendezvous(codeNameplate(code))
	if found == "" {
		t.Skip("mDNS multicast not available in this environment")
	}

	// receive through the discovered url
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
	if string(body) != "mdns discovery test" {
		t.Fatalf("received %q, want %q", body, "mdns discovery test")
	}

	if res := <-statusCh; !res.OK {
		t.Fatalf("send failed: %s", res.Error)
	}
}
