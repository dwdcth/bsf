package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/term"
)

// clipboardCommand returns a command that reads clipboard text from stdin,
// or nil if no clipboard helper is available. The dispatch follows croc's:
// clip.exe on windows, pbcopy on macOS, and on linux/bsd wl-copy (wayland)
// or xclip/xsel (X11) depending on the display session.
func clipboardCommand() *exec.Cmd {
	switch runtime.GOOS {
	case "windows":
		// clip.exe ships with windows and is always in PATH
		return exec.Command("clip")
	case "darwin":
		return exec.Command("pbcopy")
	case "linux", "android", "freebsd", "netbsd", "openbsd", "dragonfly", "solaris", "illumos":
		session := os.Getenv("XDG_SESSION_TYPE")
		if session == "wayland" || (session == "" && os.Getenv("WAYLAND_DISPLAY") != "") {
			if isExecutableInPath("wl-copy") {
				return exec.Command("wl-copy")
			}
			if isExecutableInPath("waycopy") {
				return exec.Command("waycopy")
			}
			return nil
		}

		if session == "x11" || session == "xorg" || os.Getenv("DISPLAY") != "" {
			if isExecutableInPath("xclip") {
				return exec.Command("xclip", "-selection", "clipboard")
			}
			if isExecutableInPath("xsel") {
				return exec.Command("xsel", "-b")
			}
			return nil
		}

		// no display session, but termux (android) still has a clipboard
		if isExecutableInPath("termux-clipboard-set") {
			return exec.Command("termux-clipboard-set")
		}
		return nil
	default:
		return nil
	}
}

// copyViaHelper copies text to the system clipboard by piping it into a
// platform clipboard helper. It returns false if no helper is available
// or the helper exits with an error, and never otherwise interferes with
// the running command.
func copyViaHelper(text string) bool {
	cmd := clipboardCommand()
	if cmd == nil {
		return false
	}

	cmd.Stdin = bytes.NewReader([]byte(text))
	return cmd.Run() == nil
}

// osc52Copy asks the terminal emulator to copy text into its clipboard by
// writing an OSC 52 escape sequence (supported by kitty, iTerm2, Windows
// Terminal, WezTerm, alacritty, foot, ...). This reaches the local
// clipboard even over plain ssh, where the remote host has no clipboard
// helper of its own. The sequence is only written when the output is a
// terminal so that piped or redirected output stays clean.
func osc52Copy(text string) bool {
	var w io.Writer
	if term.IsTerminal(int(os.Stdout.Fd())) {
		w = os.Stdout
	} else if term.IsTerminal(int(os.Stderr.Fd())) {
		w = os.Stderr
	} else {
		return false
	}

	return writeOSC52(w, text) == nil
}

func writeOSC52(w io.Writer, text string) error {
	b64 := base64.StdEncoding.EncodeToString([]byte(text))
	_, err := fmt.Fprintf(w, "\x1b]52;c;%s\x07", b64)
	return err
}

func isExecutableInPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
