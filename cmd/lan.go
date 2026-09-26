package cmd

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dwdcth/bsf/internal/crypto"
	"github.com/dwdcth/bsf/rendezvous"
	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"github.com/dwdcth/bsf/wormhole"
)

// defaultRendezvousPort is the port embedded rendezvous servers try to
// bind first, so a sender behind a firewall only needs a single tcp
// allow rule (a second concurrent sender falls back to a random port).
const defaultRendezvousPort = 40009

// lanRendezvous starts an embedded rendezvous server, advertises it on
// the local network, and returns the loopback ws url for the sender's
// own client plus a shutdown func.
func lanRendezvous() (string, func(), error) {
	ts, err := startEmbeddedRendezvous()
	if err != nil {
		return "", nil, err
	}

	return advertisedRendezvous(ts)
}

// lanRendezvousForCode is like lanRendezvous, but it mirrors a code that
// was already minted on another rendezvous server: the code's nameplate
// is reserved on the embedded server so the same code works against
// either server.
func lanRendezvousForCode(code string) (string, func(), error) {
	nameplate, err := strconv.Atoi(codeNameplate(code))
	if err != nil {
		return "", nil, fmt.Errorf("code %q has no nameplate", code)
	}

	ts, err := startEmbeddedRendezvous()
	if err != nil {
		return "", nil, err
	}

	if err := ts.ReserveNameplate(nameplate); err != nil {
		ts.Close()
		return "", nil, err
	}

	return advertisedRendezvous(ts)
}

// startEmbeddedRendezvous starts the embedded rendezvous server on the
// default port when it is free, and on a random port otherwise.
func startEmbeddedRendezvous() (*rendezvousservertest.TestServer, error) {
	if ts, err := startRendezvousServer(fmt.Sprintf(":%d", defaultRendezvousPort)); err == nil {
		return ts, nil
	}

	return startRendezvousServer(":0")
}

// advertisedRendezvous announces an embedded rendezvous server on the
// local network and returns its loopback url plus a shutdown func.
func advertisedRendezvous(ts *rendezvousservertest.TestServer) (string, func(), error) {
	_, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		ts.Close()
		return "", nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		ts.Close()
		return "", nil, err
	}

	// broadcast answers queries from receivers scanning the local
	// network for the code's nameplate
	stopBroadcast := startBroadcastResponder(ts, port)

	shutdown := func() {
		stopBroadcast()
		ts.Close()
	}

	// the sender talks to its own embedded server over loopback; other
	// machines reach it through the advertised lan addresses
	return fmt.Sprintf("ws://127.0.0.1:%d/ws", port), shutdown, nil
}

// discoverRendezvous looks for a rendezvous server on the local network
// that knows the given nameplate, and returns its url, or "" when none
// does. serversSeen is the number of servers that answered at all, for
// diagnostics.
func discoverRendezvousDetail(nameplate string) (url string, serversSeen int) {
	if nameplate == "" {
		return "", 0
	}

	if url, ok := broadcastQueryRendezvous(nameplate); ok {
		return url, 1
	}

	return "", 0
}

func discoverRendezvous(nameplate string) string {
	url, _ := discoverRendezvousDetail(nameplate)
	return url
}

// listNameplates connects to a rendezvous server and returns its active
// nameplates.
func listNameplates(url string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := rendezvous.NewClient(url, crypto.RandSideID(), wormhole.WormholeCLIAppID)
	defer client.Close(ctx, rendezvous.Happy)

	if _, err := client.Connect(ctx); err != nil {
		return nil, err
	}

	return client.ListNameplates(ctx)
}

// activeNameplates returns the nameplates that receivers can currently
// complete against: from the explicit --relay-url when given, otherwise
// from every rendezvous server discovered on the local network, and
// from the public relay only when no local server was found.
func activeNameplates() ([]string, error) {
	var urls []string
	if relayURL != "" {
		urls = []string{relayURL}
	} else {
		urls = broadcastQueryAllRendezvous("*", true)
		if len(urls) == 0 {
			urls = []string{wormhole.DefaultRendezvousURL}
		}
	}

	seen := make(map[string]struct{})
	var nameplates []string
	for _, url := range urls {
		nps, err := listNameplates(url, 2*time.Second)
		if err != nil {
			continue
		}

		for _, np := range nps {
			if _, dup := seen[np]; dup {
				continue
			}
			seen[np] = struct{}{}
			nameplates = append(nameplates, np)
		}
	}

	if len(nameplates) == 0 {
		return nil, fmt.Errorf("no active nameplates found")
	}

	sort.Slice(nameplates, func(i, j int) bool {
		a, _ := strconv.Atoi(nameplates[i])
		b, _ := strconv.Atoi(nameplates[j])
		return a < b
	})

	return nameplates, nil
}

// codeNameplate returns the numeric nameplate prefix of a wormhole
// code, or "" if the code does not start with digits.
func codeNameplate(code string) string {
	nameplate := strings.SplitN(code, "-", 2)[0]
	if nameplate == "" {
		return ""
	}

	for _, c := range nameplate {
		if c < '0' || c > '9' {
			return ""
		}
	}

	return nameplate
}

// lanIPs returns the non-loopback addresses of the local interfaces.
func lanIPs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var addrs []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		ipAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range ipAddrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			addrs = append(addrs, ip)
		}
	}

	return addrs
}
