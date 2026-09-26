package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dwdcth/bsf/internal/crypto"
	"github.com/dwdcth/bsf/rendezvous"
	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"github.com/dwdcth/bsf/wormhole"
	"github.com/hashicorp/mdns"
)

// mdnsServiceType is the fixed mDNS service name advertised by every
// rendezvous provider on the local network: senders started with --lan
// embed one, and `bsf server` is one. Receivers browse this
// service type and ask each server whether it knows their nameplate.
const mdnsServiceType = "_bsf._tcp"

var mdnsQueryTimeout = 1200 * time.Millisecond

// the library logs routine events to the default logger; discovery
// failures just mean we fall back to the public relay
var mdnsQuietLogger = log.New(io.Discard, "", 0)

// lanRendezvous starts an embedded rendezvous server, advertises it on
// the local network via mDNS, and returns the loopback ws url for the
// sender's own client plus a shutdown func.
func lanRendezvous() (string, func(), error) {
	ts, err := startRendezvousServer(":0")
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

	ts, err := startRendezvousServer(":0")
	if err != nil {
		return "", nil, err
	}

	if err := ts.ReserveNameplate(nameplate); err != nil {
		ts.Close()
		return "", nil, err
	}

	return advertisedRendezvous(ts)
}

// advertisedRendezvous announces an embedded rendezvous server via mDNS
// and returns its loopback url plus a shutdown func.
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

	stopAdvert, err := advertiseRendezvous(port)
	if err != nil {
		ts.Close()
		return "", nil, err
	}

	shutdown := func() {
		stopAdvert()
		ts.Close()
	}

	// the sender talks to its own embedded server over loopback; other
	// machines reach it through the advertised lan addresses
	return fmt.Sprintf("ws://127.0.0.1:%d/ws", port), shutdown, nil
}

// advertiseRendezvous announces a rendezvous server on every local
// network interface. All lan ips are listed in the TXT record so
// receivers with a different view of the network can try them all.
func advertiseRendezvous(port int) (func(), error) {
	ips := lanIPs()
	if len(ips) == 0 {
		return nil, fmt.Errorf("no non-loopback network interface to advertise on")
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "wormhole"
	}
	// a random suffix keeps the dns names of concurrent senders on one
	// host from colliding
	instance := fmt.Sprintf("%s-%s", hostname, crypto.RandHex(2))

	txt := make([]string, 0, len(ips))
	for _, ip := range ips {
		txt = append(txt, "ip="+ip.String())
	}

	svc, err := mdns.NewMDNSService(instance, mdnsServiceType, "", instance+".local.", port, ips, txt)
	if err != nil {
		return nil, err
	}

	srv, err := mdns.NewServer(&mdns.Config{Zone: svc, Logger: mdnsQuietLogger})
	if err != nil {
		return nil, err
	}

	return func() {
		srv.Shutdown()
	}, nil
}

// discoverRendezvous browses the local network for rendezvous servers
// and returns the url of the first one that knows the given nameplate,
// or "" when none does.
func discoverRendezvous(nameplate string) string {
	if nameplate == "" {
		return ""
	}

	for _, url := range browseRendezvousURLs() {
		if rendezvousHasNameplate(url, nameplate) {
			return url
		}
	}

	return ""
}

// browseRendezvousURLs returns the urls of every rendezvous server
// advertised on the local network via mDNS, deduplicated.
func browseRendezvousURLs() []string {
	entries := make(chan *mdns.ServiceEntry, 16)
	params := mdns.DefaultParams(mdnsServiceType)
	params.Timeout = mdnsQueryTimeout
	params.Entries = entries
	params.Logger = mdnsQuietLogger

	if err := mdns.Query(params); err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var urls []string
drain:
	for {
		select {
		case e := <-entries:
			for _, url := range entryURLs(e) {
				if _, dup := seen[url]; dup {
					continue
				}
				seen[url] = struct{}{}
				urls = append(urls, url)
			}
		default:
			break drain
		}
	}

	return urls
}

// entryURLs returns candidate rendezvous urls from an mDNS entry: the
// announced address plus any addresses carried in the TXT record.
func entryURLs(e *mdns.ServiceEntry) []string {
	var hosts []string
	addHost := func(ip net.IP) {
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return
		}

		host := ip.String()
		if ip.To4() == nil {
			host = "[" + host + "]"
		}

		for _, h := range hosts {
			if h == host {
				return
			}
		}
		hosts = append(hosts, host)
	}

	addHost(e.AddrV4)
	addHost(e.AddrV6)
	for _, field := range e.InfoFields {
		if !strings.HasPrefix(field, "ip=") {
			continue
		}
		addHost(net.ParseIP(strings.TrimPrefix(field, "ip=")))
	}

	urls := make([]string, 0, len(hosts))
	for _, host := range hosts {
		urls = append(urls, fmt.Sprintf("ws://%s:%d/ws", host, e.Port))
	}

	return urls
}

// rendezvousHasNameplate asks a rendezvous server whether it currently
// has an active nameplate (i.e. a sender waiting with that code).
func rendezvousHasNameplate(url, nameplate string) bool {
	nameplates, err := listNameplates(url, 2*time.Second)
	if err != nil {
		return false
	}

	for _, np := range nameplates {
		if np == nameplate {
			return true
		}
	}

	return false
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
		urls = browseRendezvousURLs()
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
