package wormhole

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"nhooyr.io/websocket"
)

// fakeWSRelayServer mimics the Cloudflare Worker relay: two peers
// present the same token with different sides, both get {"ok":true},
// and their binary frames are piped verbatim.
type fakeWSRelayServer struct {
	server   *httptest.Server
	addr     string
	mu       sync.Mutex
	waiting  map[string]*websocket.Conn
	waitSide map[string]string
	paired   int
}

func newFakeWSRelayServer(t *testing.T) *fakeWSRelayServer {
	f := &fakeWSRelayServer{
		waiting:  make(map[string]*websocket.Conn),
		waitSide: make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		hello := struct{ Token, Side string }{
			Token: r.URL.Query().Get("token"),
			Side:  r.URL.Query().Get("side"),
		}
		if hello.Token == "" || hello.Side == "" {
			http.Error(w, "bad token or side", 400)
			return
		}

		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}

		f.mu.Lock()
		other, found := f.waiting[hello.Token]
		otherSide := f.waitSide[hello.Token]
		if found {
			delete(f.waiting, hello.Token)
			delete(f.waitSide, hello.Token)
		} else {
			f.waiting[hello.Token] = ws
			f.waitSide[hello.Token] = hello.Side
		}
		if found && otherSide != hello.Side {
			f.paired++
		}
		f.mu.Unlock()

		if !found {
			return
		}
		if otherSide == hello.Side {
			ws.Close(websocket.StatusPolicyViolation, "duplicate side")
			return
		}

		ack, _ := json.Marshal(wsRelayAck{Ok: true})
		other.Write(r.Context(), websocket.MessageText, ack)
		ws.Write(r.Context(), websocket.MessageText, ack)

		a := websocket.NetConn(context.Background(), other, websocket.MessageBinary)
		b := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
		go io.Copy(a, b)
		io.Copy(b, a)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	// rewrite the http:// url into a ws:// one
	f.addr = "ws" + f.server.URL[len("http"):] + "/relay"
	return f
}

// TestWormholeFileTransferViaWSRelay pushes a whole transfer through a
// websocket relay: the TCP listener is disabled and the (local, dead)
// tcp relay never answers, so relay-ws-v1 is the only working path.
func TestWormholeFileTransferViaWSRelay(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()
	url := rs.WebSocketURL()

	fake := newFakeWSRelayServer(t)

	// a tcp relay that accepts connections but never answers: it keeps
	// the sender's listenRelay happy while guaranteeing it never wins
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	go func() {
		for {
			c, err := blackhole.Accept()
			if err != nil {
				return
			}
			// hold the connection open, read nothing, write nothing
			go io.Copy(io.Discard, c)
		}
	}()

	testDisableLocalListener = true
	defer func() { testDisableLocalListener = false }()

	var c0 Client
	c0.RendezvousURL = url
	c0.TransitRelayAddress = blackhole.Addr().String()
	c0.WSRelayURL = fake.addr

	var c1 Client
	c1.RendezvousURL = url
	c1.TransitRelayAddress = blackhole.Addr().String()

	fileContent := make([]byte, 1<<16)
	for i := range fileContent {
		fileContent[i] = byte(i)
	}

	code, resultCh, err := c0.SendFile(context.Background(), "file.txt", bytes.NewReader(fileContent))
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := c1.Receive(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(receiver)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, fileContent) {
		t.Fatalf("File contents mismatch")
	}

	result := <-resultCh
	if !result.OK {
		t.Fatalf("Expected ok result but got: %+v", result)
	}

	fake.mu.Lock()
	paired := fake.paired
	fake.mu.Unlock()
	if paired == 0 {
		t.Fatal("the ws relay never paired the peers")
	}
}
