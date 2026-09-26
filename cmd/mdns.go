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
	"sync"
	"time"

	"github.com/dwdcth/bsf/internal/crypto"
	"github.com/dwdcth/bsf/rendezvous"
	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"github.com/dwdcth/bsf/wormhole"
	"github.com/hashicorp/mdns"
)

// mdnsServiceType is the fixed mDNS service name advertised by every
// rendezvous provider on the local network: senders embed one, and
// `bsf server` is one. Receivers browse this service type and ask each
// server whether it knows their nameplate.
const mdnsServiceType = "_bsf._tcp"

// defaultRendezvousPort is the port embedded rendezvous servers try to
// bind first, so a sender behind a firewall only needs a single tcp
// allow rule (a second concurrent sender falls back to a random port).
const defaultRendezvousPort = 40009

var mdnsQueryTimeout = 1200 * time.Millisecond

// the library logs routine events to the default logger; discovery
// failures just mean we fall back to the public relay
var mdnsQuietLogger = log.New(io.Discard, "", 0)

// lanRendezvous starts an embedded rendezvous server, advertises it on
// the local network via mDNS, and returns the loopback ws url for the
// sender's own client plus a shutdown func.
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

// advertisedRendezvous announces an embedded rendezvous server via mDNS
// and subnet broadcast, and returns its loopback url plus a shutdown
// func.
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

	// broadcast answers queries mDNS cannot reach, e.g. on macOS where
	// udp 5353 is delivered to the system responder only
	stopBroadcast := startBroadcastResponder(ts, port)

	shutdown := func() {
		stopBroadcast()
		stopAdvert()
		ts.Close()
	}

	// the sender talks to its own embedded server over loopback; other
	// machines reach it through the advertised lan addresses
	return fmt.Sprintf("ws://127.0.0.1:%d/ws", port), shutdown, nil
}

// multicastInterfaces returns every interface mDNS traffic should run
// on: all up multicast-capable interfaces plus loopback. Using all of
// them matters on multi-homed hosts (docker bridges, vpns), where the
// system's default multicast interface is often not the physical
// network the peers are on.
func multicastInterfaces() []*net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []*net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		iface := iface
		out = append(out, &iface)
	}

	return out
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

	// one responder per interface: a single responder would only join
	// the multicast group on the system default interface
	var servers []*mdns.Server
	for _, iface := range multicastInterfaces() {
		svc, err := mdns.NewMDNSService(instance, mdnsServiceType, "", instance+".local.", port, ips, txt)
		if err != nil {
			continue
		}

		srv, err := mdns.NewServer(&mdns.Config{Zone: svc, Iface: iface, Logger: mdnsQuietLogger})
		if err != nil {
			continue
		}
		servers = append(servers, srv)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("failed to start mDNS responder on any interface")
	}

	return func() {
		for _, srv := range servers {
			srv.Shutdown()
		}
	}, nil
}

// discoverRendezvous browses the local network for rendezvous servers
// and returns the url of the first one that knows the given nameplate,
// or "" when none does.
func discoverRendezvous(nameplate string) string {
	url, _ := discoverRendezvousDetail(nameplate)
	return url
}

// discoverRendezvousDetail is discoverRendezvous that also reports how
// many local servers were seen, so callers can tell an empty network
// from servers that none answered for the nameplate. Subnet broadcast
// is tried first: it works where mDNS cannot, notably on macOS where
// udp 5353 is delivered to the system responder only.
func discoverRendezvousDetail(nameplate string) (url string, serversSeen int) {
	if nameplate == "" {
		return "", 0
	}

	if url, ok := broadcastQueryRendezvous(nameplate); ok {
		return url, 1
	}

	urls := browseRendezvousURLs()
	for _, url := range urls {
		if rendezvousHasNameplate(url, nameplate) {
			return url, len(urls)
		}
	}

	return "", len(urls)
}

// browseRendezvousURLs returns the urls of every rendezvous server
// advertised on the local network via mDNS, deduplicated. The query
// runs once per network interface in parallel (broadcast discovery is
// the primary path; this is the fallback).
func browseRendezvousURLs() []string {
	return browseRendezvousURLsOnce()
}

func browseRendezvousURLsOnce() []string {
	var (
		mu   sync.Mutex
		seen = make(map[string]struct{})
		wg   sync.WaitGroup
	)

	for _, iface := range multicastInterfaces() {
		// the library aborts a query when a send fails, so an interface
		// without an address of one family must not query that family
		hasV4, hasV6 := interfaceFamilies(iface)
		if !hasV4 && !hasV6 {
			continue
		}

		wg.Add(1)
		go func(iface *net.Interface, useV4, useV6 bool) {
			defer wg.Done()

			entries := make(chan *mdns.ServiceEntry, 16)
			params := mdns.DefaultParams(mdnsServiceType)
			params.Timeout = mdnsQueryTimeout
			params.Entries = entries
			params.Logger = mdnsQuietLogger
			params.Interface = iface
			params.DisableIPv4 = !useV4
			params.DisableIPv6 = !useV6

			if err := mdns.Query(params); err != nil {
				return
			}

		drain:
			for {
				select {
				case e := <-entries:
					for _, url := range entryURLs(e) {
						mu.Lock()
						seen[url] = struct{}{}
						mu.Unlock()
					}
				default:
					break drain
				}
			}
		}(iface, hasV4, hasV6)
	}

	wg.Wait()

	urls := make([]string, 0, len(seen))
	for url := range seen {
		urls = append(urls, url)
	}
	sort.Strings(urls)

	return urls
}

// interfaceFamilies reports which ip versions an interface has
// non-link-local addresses for.
func interfaceFamilies(iface *net.Interface) (v4, v6 bool) {
	addrs, err := iface.Addrs()
	if err != nil {
		return false, false
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
			continue
		}

		if ip.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}

	return v4, v6
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
		if url, ok := broadcastQueryRendezvous("*"); ok {
			urls = append(urls, url)
		}
		urls = append(urls, browseRendezvousURLs()...)
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
