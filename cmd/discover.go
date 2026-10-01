package cmd

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The broadcast discovery protocol is a fallback for networks where
// mDNS does not work between the peers. Notably macOS delivers udp
// port 5353 exclusively to the system mDNSResponder, so a userspace
// responder never sees queries there; subnet broadcast has no such
// owner.
//
//	query   "bsf1 Q <nameplate | *>"
//	answer  "bsf1 R <nameplate,...> <tcp-port>"   (unicast back)
//	        "bsf2 R <nameplate,...> <tcp-port> <stun-port>"   (only when a
//	        STUN server runs next to the rendezvous; old receivers keep
//	        parsing the bsf1 answer)
const (
	broadcastDiscoveryPort = 53534
	broadcastMarker        = "bsf1"
	broadcastMarkerV2      = "bsf2"
	broadcastQueryTimeout  = 800 * time.Millisecond
)

// broadcastServer is one embedded rendezvous server registered with
// the process-wide broadcast responder.
type broadcastServer struct {
	nameplates func() []string
	port       int
	stunPort   int // 0: no STUN server to advertise
}

var (
	broadcastMu      sync.Mutex
	broadcastConn    *net.UDPConn
	broadcastServers []*broadcastServer
)

// startBroadcastResponder registers an embedded rendezvous server
// listening on tcpPort with the process-wide discovery responder and
// returns an unregister func.
//
// One responder answers for every local server: a single udp socket
// works on every platform (windows has no portable SO_REUSEPORT, so
// per-server listeners would silently lose all but the first), and
// each server still answers the queries for its own nameplates.
func startBroadcastResponder(ts interface {
	Nameplates() []string
}, tcpPort int) func() {
	return startBroadcastResponderWithSTUN(ts, tcpPort, 0)
}

// startBroadcastResponderWithSTUN also advertises the udp port of a STUN
// server running next to the rendezvous (0 = none).
func startBroadcastResponderWithSTUN(ts interface {
	Nameplates() []string
}, tcpPort, stunPort int) func() {
	server := &broadcastServer{
		nameplates: ts.Nameplates,
		port:       tcpPort,
		stunPort:   stunPort,
	}

	broadcastMu.Lock()
	broadcastServers = append(broadcastServers, server)
	startBroadcastListener()
	broadcastMu.Unlock()

	return func() {
		broadcastMu.Lock()
		for i, s := range broadcastServers {
			if s == server {
				broadcastServers = append(broadcastServers[:i], broadcastServers[i+1:]...)
				break
			}
		}
		broadcastMu.Unlock()
	}
}

// startBroadcastListener starts the shared responder goroutine once.
// The listener stays open for the life of the process; with no servers
// registered it answers nothing. The caller holds broadcastMu.
func startBroadcastListener() {
	if broadcastConn != nil {
		return
	}

	conn, err := listenUDPReusePort(broadcastDiscoveryPort)
	if err != nil {
		return
	}
	broadcastConn = conn

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			fields := strings.Fields(string(buf[:n]))
			if len(fields) != 3 || fields[0] != broadcastMarker || fields[1] != "Q" {
				continue
			}

			broadcastMu.Lock()
			for _, server := range broadcastServers {
				nameplates := server.nameplates()
				if len(nameplates) == 0 {
					continue
				}

				asked := fields[2]
				match := asked == "*"
				if !match {
					for _, np := range nameplates {
						if np == asked {
							match = true
							break
						}
					}
				}
				if !match {
					continue
				}

				answer := fmt.Sprintf("%s R %s %d", broadcastMarker, strings.Join(nameplates, ","), server.port)
				_, _ = conn.WriteToUDP([]byte(answer), from)
				if server.stunPort > 0 {
					answer2 := fmt.Sprintf("%s R %s %d %d", broadcastMarkerV2, strings.Join(nameplates, ","), server.port, server.stunPort)
					_, _ = conn.WriteToUDP([]byte(answer2), from)
				}
			}
			broadcastMu.Unlock()
		}
	}()
}

// broadcastQueryRendezvous asks the local network(s) which rendezvous
// server holds the given nameplate, and returns its url. An empty
// nameplate ("*") matches any server.
func broadcastQueryRendezvous(nameplate string) (string, bool) {
	urls := broadcastQueryAllRendezvous(nameplate, false)
	if len(urls) == 0 {
		return "", false
	}
	return urls[0], true
}

// broadcastQueryRendezvousDetail is broadcastQueryRendezvous plus the
// "host:port" of a STUN server advertised beside the rendezvous, when
// one answered with the bsf2 variant.
func broadcastQueryRendezvousDetail(nameplate string) (string, string, bool) {
	if nameplate == "" {
		return "", "", false
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", "", false
	}
	defer conn.Close()

	if err := enableBroadcast(conn); err != nil {
		return "", "", false
	}

	query := fmt.Sprintf("%s Q %s", broadcastMarker, nameplate)
	sendAll := func() {
		for _, addr := range queryDestinations() {
			_, _ = conn.WriteToUDP([]byte(query), addr)
		}
	}

	sendAll()
	time.AfterFunc(250*time.Millisecond, sendAll)
	time.AfterFunc(500*time.Millisecond, sendAll)

	var stunAddr string
	deadline := time.Now().Add(broadcastQueryTimeout)
	buf := make([]byte, 512)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		fields := strings.Fields(string(buf[:n]))
		if len(fields) < 4 || fields[1] != "R" || fields[0] != broadcastMarker && fields[0] != broadcastMarkerV2 {
			continue
		}
		if nameplate != "*" && !containsNameplate(fields[2], nameplate) {
			continue
		}

		port, err := strconv.Atoi(fields[3])
		if err != nil || port <= 0 {
			continue
		}

		host := from.IP.String()
		if from.IP.To4() == nil {
			host = "[" + host + "]"
		}

		if fields[0] == broadcastMarkerV2 && len(fields) >= 5 {
			if stunPort, serr := strconv.Atoi(fields[4]); serr == nil && stunPort > 0 {
				stunAddr = net.JoinHostPort(from.IP.String(), fields[4])
			}
		}

		return fmt.Sprintf("ws://%s:%d/ws", host, port), stunAddr, true
	}

	return "", "", false
}

// broadcastQueryAllRendezvous broadcasts a query and returns the urls
// of every rendezvous server that answered. With collectAll false it
// returns after the first answer.
func broadcastQueryAllRendezvous(nameplate string, collectAll bool) []string {
	if nameplate == "" {
		return nil
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	if err := enableBroadcast(conn); err != nil {
		return nil
	}

	query := fmt.Sprintf("%s Q %s", broadcastMarker, nameplate)
	dests := queryDestinations()
	sendAll := func() {
		for _, addr := range dests {
			_, _ = conn.WriteToUDP([]byte(query), addr)
		}
	}

	// three passes for lossy links, within the same listen window
	sendAll()
	time.AfterFunc(250*time.Millisecond, sendAll)
	time.AfterFunc(500*time.Millisecond, sendAll)

	var urls []string
	seen := make(map[string]struct{})
	deadline := time.Now().Add(broadcastQueryTimeout)
	buf := make([]byte, 512)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return urls
		}

		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return urls
		}

		fields := strings.Fields(string(buf[:n]))
		if len(fields) < 4 || fields[1] != "R" || fields[0] != broadcastMarker && fields[0] != broadcastMarkerV2 {
			continue
		}
		if nameplate != "*" && !containsNameplate(fields[2], nameplate) {
			continue
		}

		port, err := strconv.Atoi(fields[3])
		if err != nil || port <= 0 {
			continue
		}

		host := from.IP.String()
		if from.IP.To4() == nil {
			host = "[" + host + "]"
		}
		url := fmt.Sprintf("ws://%s:%d/ws", host, port)
		if _, dup := seen[url]; dup {
			continue
		}
		seen[url] = struct{}{}
		urls = append(urls, url)

		if !collectAll {
			return urls
		}
	}
}

// queryDestinations returns where discovery queries are sent: the
// subnet broadcast of every interface, the limited broadcast address,
// and loopback so same-host senders answer too.
func queryDestinations() []*net.UDPAddr {
	var dests []*net.UDPAddr
	for _, addr := range broadcastAddresses() {
		dests = append(dests, &net.UDPAddr{IP: addr, Port: broadcastDiscoveryPort})
	}
	dests = append(dests,
		&net.UDPAddr{IP: net.IPv4bcast, Port: broadcastDiscoveryPort},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: broadcastDiscoveryPort},
	)

	return dests
}

func containsNameplate(list, nameplate string) bool {
	for _, np := range strings.Split(list, ",") {
		if np == nameplate {
			return true
		}
	}
	return false
}

// broadcastAddresses returns the subnet broadcast addresses of every
// interface, which reaches all peers sharing a link without any
// multicast infrastructure.
func broadcastAddresses() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var addrs []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		ipAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range ipAddrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
				continue
			}

			// the ip is stored in 16-byte form; index the 4-byte view
			ip := ipNet.IP.To4()
			mask := ipNet.Mask
			if len(mask) == net.IPv6len {
				mask = mask[12:]
			}

			broadcast := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = ip[i] | ^mask[i]
			}
			addrs = append(addrs, broadcast)
		}
	}

	return addrs
}
