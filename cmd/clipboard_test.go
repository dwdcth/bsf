package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"github.com/dwdcth/bsf/wormhole"
	"golang.org/x/term"
)

func TestClipboardCommandHeadlessLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	t.Setenv("XDG_SESSION_TYPE", "tty")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	if isExecutableInPath("termux-clipboard-set") {
		t.Skip("termux clipboard installed")
	}

	if cmd := clipboardCommand(); cmd != nil {
		t.Errorf("expected no clipboard command on headless linux, got %v", cmd)
	}
}

func TestClipboardCommandX11ForwardedSession(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	// simulate an ssh -X session: sshd does not set XDG_SESSION_TYPE,
	// but DISPLAY points at the forwarded X socket
	dir := t.TempDir()
	script := filepath.Join(dir, "xclip")
	err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("XDG_SESSION_TYPE", "")
	t.Setenv("DISPLAY", "localhost:10.0")

	cmd := clipboardCommand()
	if cmd == nil {
		t.Fatal("expected xclip command for X11-forwarded ssh session")
	}
	if got := strings.Join(cmd.Args, " "); got != "xclip -selection clipboard" {
		t.Fatalf("got %q, want %q", got, "xclip -selection clipboard")
	}
}

func TestClipboardCommandX11Session(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	if !isExecutableInPath("xclip") && !isExecutableInPath("xsel") {
		t.Skip("no X11 clipboard tool installed")
	}

	t.Setenv("XDG_SESSION_TYPE", "x11")

	if cmd := clipboardCommand(); cmd == nil {
		t.Error("expected clipboard command for x11 session")
	}
}

func TestCopyViaHelperFakeHelper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.txt")
	script := filepath.Join(dir, "xclip")

	err := os.WriteFile(script, []byte("#!/bin/sh\ncat > "+sink+"\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("XDG_SESSION_TYPE", "x11")
	t.Setenv("DISPLAY", ":0")

	if !copyViaHelper("3-cinnamon-chalk-wizard") {
		t.Fatal("copyViaHelper returned false with fake xclip helper")
	}

	got, err := os.ReadFile(sink)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "3-cinnamon-chalk-wizard" {
		t.Fatalf("clipboard got %q, want code", got)
	}
}

func TestCopyViaHelperNoHelper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	t.Setenv("PATH", "")
	t.Setenv("XDG_SESSION_TYPE", "tty")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	if copyViaHelper("3-cinnamon-chalk-wizard") {
		t.Error("expected copyViaHelper to return false with no helper available")
	}
}

func TestWriteOSC52(t *testing.T) {
	var buf bytes.Buffer
	err := writeOSC52(&buf, "3-cinnamon-chalk-wizard")
	if err != nil {
		t.Fatal(err)
	}

	want := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte("3-cinnamon-chalk-wizard")) + "\x07"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

// The test binary runs with piped stdout/stderr, so the TTY gate should
// keep the escape sequence out of the output. (Running the compiled test
// binary directly on a terminal would make this false by design.)
func TestOSC52CopyNotATerminal(t *testing.T) {
	if term.IsTerminal(int(os.Stdout.Fd())) || term.IsTerminal(int(os.Stderr.Fd())) {
		t.Skip("stdout/stderr is a terminal")
	}

	if osc52Copy("3-cinnamon-chalk-wizard") {
		t.Error("expected osc52Copy to return false when output is not a terminal")
	}
}

func TestSendTextCopiesCodeToClipboard(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	dir := t.TempDir()
	sink := filepath.Join(dir, "sink.txt")
	err := os.WriteFile(filepath.Join(dir, "xclip"), []byte("#!/bin/sh\ncat > "+sink+"\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("XDG_SESSION_TYPE", "x11")
	t.Setenv("DISPLAY", ":0")

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	relayURL = rs.WebSocketURL()
	sendTextFlag = "clipboard code test"
	t.Cleanup(func() {
		sendTextFlag = ""
		relayURL = ""
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		sendText()
	}()

	// wait for the fake clipboard helper to receive the code
	var code string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(sink); err == nil {
			code = strings.TrimSpace(string(b))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code == "" {
		t.Fatal("wormhole code was not copied to the clipboard")
	}

	var receiver wormhole.Client
	receiver.RendezvousURL = rs.WebSocketURL()

	msg, err := receiver.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "clipboard code test" {
		t.Fatalf("received %q, want %q", body, "clipboard code test")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendText did not finish")
	}
}
