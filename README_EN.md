# bsf

English documentation | [中文文档](README.md)

bsf (本地收发) is a Go (golang) implementation of [magic wormhole](https://magic-wormhole.readthedocs.io/en/latest/), forked from [psanford/wormhole-william](https://github.com/psanford/wormhole-william). It provides secure end-to-end encrypted file transfers between computers. The endpoints are connected using the same "wormhole code".

bsf is compatible with the official [python magic wormhole cli tool](https://github.com/warner/magic-wormhole).

Currently, bsf supports:
- sending and receiving text over the wormhole protocol
- sending and receiving files over the transit protocol
- sending and receiving directories over the transit protocol

## Docs

https://pkg.go.dev/github.com/dwdcth/bsf/wormhole?tab=doc

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
      --ice               attempt UDP hole punching (p2p over QUIC) before falling back to a relay (default true)
      --relay-url string   rendezvous relay to use
      --stun strings      comma-separated STUN endpoints (stun:host:port) for hole punching
      --ws-relay string   wss:// websocket transit relay to use as fallback


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

### UDP hole punching (P2P over QUIC)

When both peers sit behind NATs, bsf first tries to punch a direct UDP
path: ICE candidates are exchanged over the existing encrypted mailbox
(no server changes), a STUN server provides the public mapping, and the
punched path carries QUIC streams — so parallel transfers and automatic
resume work over it exactly like over TCP. If the punch fails (for
example double symmetric NAT), the transfer falls back to a relay.

- enabled by default; turn off with `--ice=false` or `BSF_NO_ICE=1`
- `--stun stun:host:port` (or `BSF_STUN`, comma-separated) overrides the
  STUN endpoints; by default the receiver follows the endpoint the
  sender advertised (a self-hosted `bsf server` doubles as STUN), then
  public servers
- `--ws-relay wss://...` (or `BSF_WS_RELAY`) adds a websocket fallback
  relay on port 443 — see `contrib/cloudflare-relay/` for a Cloudflare
  Worker you can deploy on the free tier (the edge only ever sees
  PAKE-encrypted ciphertext)

Connection priority, each step falling back to the next: **direct TCP →
UDP punch (ICE + QUIC) → relay** (websocket relay when configured, else
the TCP transit relay).

The punched path's UDP receive buffer can't be enlarged at runtime (the
socket belongs to the ICE stack); Linux defaults to about 208 KiB,
which can cap high-throughput transfers through kernel drops and
retransmits. Raise it system-wide — it applies to the next transfer
started, and benefits every other UDP program too:

```
sudo sysctl -w net.core.rmem_default=7340032    # takes effect at once
echo 'net.core.rmem_default=7340032' | sudo tee /etc/sysctl.d/99-bsf.conf
sudo sysctl --system                            # persists across reboots
```

(7 MiB is the receive buffer QUIC recommends; on macOS the equivalent
is `net.inet.udp.recvspace`.)

### CLI tab completion

The bsf CLI supports shell completion, including completing the receive code.
To enable shell completion follow the instructions from `bsf shell-completion -h`.

Code completion works for both `bsf receive <TAB>` and the bare
`bsf <TAB>` form. Nameplate completion uses the `--relay-url` relay when
given, otherwise it queries every rendezvous server discovered on the local network
via udp broadcast and only falls back to the public relay when no local server is found.

### Running without the public relay (LAN)

The wormhole protocol always needs a rendezvous (mailbox) server for the initial handshake,
but it does not have to be the public one. By default a send **stays entirely on the local
network**: the sender embeds a rendezvous server, mints the code locally, and answers
discovery probes from the local network — no relay is contacted and the code never leaves the network:

```
# machine A
$ bsf send file.txt
Send mode: local network
On the other computer on this network, please run: bsf <code>
Wormhole code is: 28471-torpedo-newborn

# machine B on the same LAN (auto-discovers the sender)
$ bsf 28471-torpedo-newborn
Rendezvous: ws://192.168.31.37:40000/ws (local network)
```

Receivers find senders with a subnet broadcast probe (`bsf1 Q <nameplate>` on udp 53534);
the machine holding that nameplate answers unicast with its address. Broadcast was chosen
over mDNS because macOS delivers udp 5353 exclusively to the system responder, which made
cross-machine discovery with a mac silently fail.

To also let receivers **outside** the local network connect, pass `--relay` (or an
explicit `--relay-url`): the send then runs on two rendezvous legs at once — the relay
mints the code and the embedded server mirrors it, whichever receiver shows up first
wins and the other leg is cancelled. If the relay is unreachable the send quietly falls
back to local-network-only:

```
$ bsf send --relay file.txt
Send mode: relay + local network
```

For a longer-lived rendezvous server, `bsf server` runs one and also
advertises it via udp broadcast:

```
$ bsf server
Rendezvous server listening on [::]:40000 (advertised via udp broadcast)
Use: bsf --relay-url ws://127.0.0.1:40000/ws ...
Use: bsf --relay-url ws://192.168.31.37:40000/ws ...
```

Two companion flags make a self-hosted deployment independent of every
public service:

- `--stun <addr>` (default `:3478`, empty disables): an embedded STUN
  server that peers use for UDP hole punching. Discovery advertises it
  next to the rendezvous, and the sender can also pass it explicitly
  via `--stun stun:<lan-ip>:3478`.
- `--transit <addr>` (default off): a standard magic-wormhole TCP transit
  relay, so a failed punch falls back to your own server instead of the
  public one.

```
$ bsf server --addr :40009 --stun :3478 --transit :4001
Rendezvous server listening on [::]:40009 (advertised via udp broadcast)
STUN server listening on :3478 (udp)
Transit relay listening on 127.0.0.1:4001
...
      (fallback transit relay: 127.0.0.1:4001)
      (stun: stun:192.168.31.37:3478)
```

Then both sides pass `--relay-url ws://<lan-ip>:<port>/ws` (or set `WORMHOLE_RELAY_URL`).
File transfers connect directly over the LAN (direct-tcp-v1 hints are exchanged first;
the public transit relay is only a fallback), and text messages only ever touch the
rendezvous server. Note: this server is a lightweight implementation intended for
personal/LAN use — it has no nameplate expiry or rate limiting, so don't expose it to the
internet. Broadcast discovery requires the two machines to share a subnet.
See also `contrib/cloudflare-relay/`: one Cloudflare Worker that serves
as a websocket fallback relay (`--ws-relay`) at zero server cost.

### Two deployment shapes

- **With a VPS (all Go services)**: `bsf server --addr :40009 --stun
  :3478 --transit :4001` provides signaling, STUN and a relay fallback
  in one command, with no dependency on any public service.
- **Without a VPS (all Cloudflare)**: the same worker also implements
  the rendezvous protocol (`/ws`), so with public STUN (bilibili is in
  the defaults) the full chain works with zero servers of your own:

```sh
bsf --relay-url wss://<your-domain>/ws --ws-relay wss://<your-domain>/relay send FILE   # sender
bsf --relay-url wss://<your-domain>/ws --ws-relay wss://<your-domain>/relay CODE        # receiver
```

Both shapes share the same connection priority: direct TCP → UDP punch
(QUIC, parallel streams) → relay.

### Parallel streams and automatic resume

File transfers between two bsf clients use multiple transit streams in parallel
(`--parallel`, default 4, on both `send` and `receive`): the file is split into
contiguous chunks, each stream carries one chunk, and each stream derives its own
record keys (per stream and per resume attempt), so record nonces are never reused.
Python magic-wormhole peers automatically get the standard single stream protocol.

When a transit connection drops mid transfer, both sides keep their state, the
receiver reports how far every stream got, and the transfer resumes from those
positions on fresh connections — no data is re-sent. The final ack verifies the
sha256 of the whole file. If the connection to the rendezvous server itself is
lost, or one side exits, the transfer fails as usual.

Firewall note for senders: the embedded rendezvous server tries to bind tcp port
`40009` and the transit listener tcp port `40010` (both falling back to random
ports when several senders run on one machine); discovery probes use udp `53534`.
On machines running a firewall, allow them:

```
ufw allow 53534/udp && ufw allow 40009:40010/tcp     # or the firewalld equivalent
```

A receiver that falls back to the public relay prints a note explaining what the
discovery step saw, which tells you which side to fix.


## Building the CLI tool

bsf uses go modules so it requires a version of the go tool chain >= 1.11. If you are using a version of go that supports modules you can clone the repo outside of your GOPATH and do a `go build` in the top level directory.

To build a stripped release binary named `bsf` run:

```
go build -trimpath -ldflags "-s -w" -o bsf .
```

To just install via the go tool run:

```
go install github.com/dwdcth/bsf@latest
```

The installed binary is named `bsf`. Release binaries (`bsf-<os>-<arch>`) are built stripped of debug symbols.

## API Usage

Sending text:

```go
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/dwdcth/bsf/wormhole"
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

See the [cli tool](https://github.com/dwdcth/bsf/tree/master/cmd) and [examples](https://github.com/dwdcth/bsf/tree/master/examples) directory for working examples of how to use the API to send and receive text, files and directories.

## Third Party Users of Wormhole William

- [rymdport](https://github.com/Jacalz/rymdport): A cross-platform Magic Wormhole graphical user interface
- [riftshare](https://github.com/achabra2/riftshare): Desktop filesharing app
- [termshark](https://github.com/gcla/termshark): A terminal UI for tshark
- [tmux-wormhole](https://github.com/gcla/tmux-wormhole): tmux wormhole integration
- [wormhole-william-mobile](https://github.com/psanford/wormhole-william-mobile): Android wormhole-william app
