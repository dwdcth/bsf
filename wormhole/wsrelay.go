package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dwdcth/bsf/internal/crypto"
	"golang.org/x/crypto/hkdf"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// The websocket transit relay ("relay-ws-v1") carries the same byte
// stream as the TCP relay over wss://, which lets a Cloudflare Worker
// (or any static host) serve as the fallback relay: the edge only ever
// sees the PAKE-encrypted records. Both peers identify themselves with
// the same token the TCP relay handshake uses — carried in the url
// query so a hibernating edge can pair the connection the moment it
// arrives, before any message needs to be read.

type wsRelayAck struct {
	Ok bool `json:"ok"`
}

var wsRelayDialTimeout = 5 * time.Second

// wsRelayURLFor appends the token and side to a relay base url.
func wsRelayURLFor(base, token, side string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + token + "&side=" + side
}

// relayTokenHex returns the hex token that identifies this transfer to
// a relay (shared by the TCP and WS handshakes).
func (t *fileTransport) relayTokenHex() string {
	r := hkdf.New(sha256.New, t.transitKey, nil, []byte("transit_relay_token"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return hex.EncodeToString(out)
}

// listenRelayWS registers this transfer with a websocket relay server
// (sender side, mirroring listenRelay): it dials with the token in the
// url and keeps the connection open. The pairing ack is read later,
// when the receiver shows up, inside waitForWSRelayPeer — wsjson reads
// must happen before the NetConn wrapping, or they would steal stream
// bytes.
func (t *fileTransport) listenRelayWS(ctx context.Context) error {
	if t.wsRelayURL == "" {
		return nil
	}

	url := wsRelayURLFor(t.wsRelayURL, t.relayTokenHex(), crypto.RandHex(8))

	dialCtx, cancel := context.WithTimeout(ctx, wsRelayDialTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(dialCtx, url, nil)
	if err != nil {
		return err
	}

	t.wsRelay = ws
	return nil
}

// waitForWSRelayPeer waits for the relay's pairing ack and returns the
// byte-stream conn for the transit handshake (sender side).
func (t *fileTransport) waitForWSRelayPeer(ws *websocket.Conn, cancelCh chan struct{}) (net.Conn, error) {
	okCh := make(chan struct{})
	go func() {
		select {
		case <-cancelCh:
			ws.Close(websocket.StatusGoingAway, "cancelled")
		case <-okCh:
		}
	}()
	defer close(okCh)

	var ack wsRelayAck
	if err := wsjson.Read(context.Background(), ws, &ack); err != nil {
		return nil, err
	}
	if !ack.Ok {
		return nil, errors.New("ws relay refused the token")
	}

	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary), nil
}

// connectToWSRelay dials a websocket relay with the token in the url,
// waits for the pairing ack, and runs the standard transit dialer
// handshake over it (receiver side).
func (t *fileTransport) connectToWSRelay(ctx context.Context, base string, successChan chan net.Conn, failChan chan string) {
	dialCtx, cancel := context.WithTimeout(ctx, wsRelayDialTimeout)
	defer cancel()

	url := wsRelayURLFor(base, t.relayTokenHex(), crypto.RandHex(8))
	ws, _, err := websocket.Dial(dialCtx, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[dbg] ws-relay dial %s err: %s\n", base, err)
		failChan <- base
		return
	}

	var ack wsRelayAck
	if err := wsjson.Read(dialCtx, ws, &ack); err != nil || !ack.Ok {
		fmt.Fprintf(os.Stderr, "[dbg] ws-relay %s ack err: %v ok=%v\n", base, err, ack.Ok)
		ws.Close(websocket.StatusInternalError, "no ack")
		failChan <- base
		return
	}

	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	conn.SetDeadline(time.Now().Add(relayHandshakeTimeout))
	t.directRecvHandshake(ctx, "ws-relay "+base, conn, successChan, failChan)
}
