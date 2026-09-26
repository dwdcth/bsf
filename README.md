# wormhole-william

wormhole-william is a Go (golang) implementation of [magic wormhole](https://magic-wormhole.readthedocs.io/en/latest/). It provides secure end-to-end encrypted file transfers between computers. The endpoints are connected using the same "wormhole code".

wormhole-william is compatible with the official [python magic wormhole cli tool](https://github.com/warner/magic-wormhole).

Currently, wormhole-william supports:
- sending and receiving text over the wormhole protocol
- sending and receiving files over the transit protocol
- sending and receiving directories over the transit protocol

## Docs

https://pkg.go.dev/github.com/psanford/wormhole-william/wormhole?tab=doc

## CLI Usage

As a shortcut, a wormhole code can be passed directly to the `bsf` command, which is equivalent to `bsf receive CODE`:

```
$ bsf 3-cinnamon-chalk-wizard
```

When sending, the wormhole code is automatically copied to the system clipboard (using `pbcopy`, `clip`, `wl-copy`, or `xclip`/`xsel` where available), so it can be pasted directly on the other computer. If no clipboard helper is available (for example over a plain ssh session without X forwarding), it falls back to the OSC 52 terminal escape sequence, which asks the terminal emulator itself to copy the code — this works over plain ssh with terminals like kitty, iTerm2, Windows Terminal, WezTerm, alacritty, or foot (inside tmux, `set-clipboard` must be enabled). Use `--disable-clipboard` to turn this off.

```
$ bsf send --help
Send a text message, file, or directory...

Usage:
  bsf send [WHAT] [flags]

Flags:
      --code string         human-generated code phrase
  -c, --code-length int     length of code (in bytes/words)
      --disable-clipboard   do not copy the wormhole code to the system clipboard
  -h, --help                help for send
      --hide-progress       suppress progress-bar display
      --qr                  display code as QR code (experimental)
      --text string         text message to send, instead of a file.
                            Use '-' to read from stdin
  -v, --verify              display verification string (and wait for approval)

Global Flags:
      --relay-url string   rendezvous relay to use


$ bsf receive --help
Receive a text message, file, or directory...

Usage:
  bsf receive [code] [flags]

Aliases:
  receive, recv

Flags:
  -h, --help            help for receive
      --hide-progress   suppress progress-bar display
  -v, --verify          display verification string (and wait for approval)

Global Flags:
      --relay-url string   rendezvous relay to use
```

### CLI tab completion

The wormhole-william CLI supports shell completion, including completing the receive code.
To enable shell completion follow the instructions from `bsf shell-completion -h`.

Code completion works for both `bsf receive <TAB>` and the bare
`bsf <TAB>` form. Nameplate completion uses the `--relay-url` relay when
given, otherwise it queries every rendezvous server discovered on the local network
via mDNS and only falls back to the public relay when no local server is found.

### Running without the public relay (LAN)

The wormhole protocol always needs a rendezvous (mailbox) server for the initial handshake,
but it does not have to be the public one. By default a send runs on **two rendezvous legs
at once**: the relay (`--relay-url` or the public one) mints the code, and an embedded
mDNS-advertised server on the local network mirrors the same code. Whichever receiver
shows up first — a LAN peer discovering the sender via mDNS, or a remote peer going through
the relay — wins, and the other leg is cancelled. If the relay is unreachable (isolated
networks), the send falls back to the embedded server alone:

```
# machine A
$ bsf send file.txt
Wormhole code is: 1-torpedo-newborn

# machine B on the same LAN (auto-discovers the sender via mDNS, never touches the relay)
$ bsf 1-torpedo-newborn

# machine B elsewhere (goes through the relay, as before)
$ bsf 1-torpedo-newborn
```

Receivers browse the local network for `_bsf._tcp` services and ask each one whether it
knows the code's nameplate, trying the next server until one does. If no local server has
it, they fall back to the public relay, so internet transfers keep working unchanged
(adding ~1s of discovery time).

To skip the relay entirely (privacy, or known-LAN-only transfers), pass `--lan`: the code
is then minted locally on the embedded server and never leaves the local network:

```
$ bsf send --lan file.txt
```

For a longer-lived rendezvous server, `bsf server` runs one and also
advertises it via mDNS:

```
$ bsf server
Rendezvous server listening on [::]:40000 (advertised via mDNS as _bsf._tcp)
Use: bsf --relay-url ws://127.0.0.1:40000/ws ...
Use: bsf --relay-url ws://192.168.31.37:40000/ws ...
```

Then both sides pass `--relay-url ws://<lan-ip>:<port>/ws` (or set `WORMHOLE_RELAY_URL`).
File transfers connect directly over the LAN (direct-tcp-v1 hints are exchanged first;
the public transit relay is only a fallback), and text messages only ever touch the
rendezvous server. Note: this server is a lightweight implementation intended for
personal/LAN use — it has no nameplate expiry or rate limiting, so don't expose it to
the internet. mDNS discovery requires multicast to work between the two machines
(same subnet or a multicast-forwarding network).


## Building the CLI tool

wormhole-william uses go modules so it requires a version of the go tool chain >= 1.11. If you are using a version of go that supports modules you can clone the repo outside of your GOPATH and do a `go build` in the top level directory.

To build a stripped release binary named `bsf` run:

```
go build -trimpath -ldflags "-s -w" -o bsf .
```

To just install via the go tool run:

```
go install github.com/psanford/wormhole-william@latest
```

Note: `go install` names the binary after the module (`wormhole-william`); rename or symlink it to `bsf`, or use the release binaries (`bsf-<os>-<arch>`), which are built stripped of debug symbols.

## API Usage

Sending text:

```go
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/psanford/wormhole-william/wormhole"
)

func sendText() {
	var c wormhole.Client

	msg := "Dillinger-entertainer"

	ctx := context.Background()

	code, status, err := c.SendText(ctx, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("On the other computer, please run: wormhole receive")
	fmt.Printf("Wormhole code is: %s\n", code)

	s := <-status

	if s.OK {
		fmt.Println("OK!")
	} else {
		log.Fatalf("Send error: %s", s.Error)
	}
}

func recvText(code string) {
	var c wormhole.Client

	ctx := context.Background()
	msg, err := c.Receive(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	if msg.Type != wormhole.TransferText {
		log.Fatalf("Expected a text message but got type %s", msg.Type)
	}

	msgBody, err := ioutil.ReadAll(msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("got message:")
	fmt.Println(msgBody)
}
```

See the [cli tool](https://github.com/psanford/wormhole-william/tree/master/cmd) and [examples](https://github.com/psanford/wormhole-william/tree/master/examples) directory for working examples of how to use the API to send and receive text, files and directories.

## Third Party Users of Wormhole William

- [rymdport](https://github.com/Jacalz/rymdport): A cross-platform Magic Wormhole graphical user interface
- [riftshare](https://github.com/achhabra2/riftshare): Desktop filesharing app
- [termshark](https://github.com/gcla/termshark): A terminal UI for tshark
- [tmux-wormhole](https://github.com/gcla/tmux-wormhole): tmux wormhole integration
- [wormhole-william-mobile](https://github.com/psanford/wormhole-william-mobile): Android wormhole-william app
