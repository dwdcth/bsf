package cmd

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
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
const (
	broadcastDiscoveryPort = 53534
	broadcastMarker        = "bsf1"
	broadcastQueryTimeout  = 800 * time.Millisecond
)

// startBroadcastResponder answers broadcast queries for the
// nameplates of an embedded rendezvous server listening on tcpPort,
// from broadcastDiscoveryPort. A second process on the same host
// simply does not answer (mDNS still covers the same-host case).
func startBroadcastResponder(ts interface {
	Nameplates() []string
}, tcpPort int) func() {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: broadcastDiscoveryPort})
	if err != nil {
		return func() {}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
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

			nameplates := ts.Nameplates()
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

			answer := fmt.Sprintf("%s R %s %d", broadcastMarker, strings.Join(nameplates, ","), tcpPort)
			_, _ = conn.WriteToUDP([]byte(answer), from)
		}
	}()

	return func() {
		conn.Close()
		<-done
	}
}

// broadcastQueryRendezvous asks the local network(s) which rendezvous
// server holds the given nameplate, and returns its url. An empty
// nameplate ("*") returns the first answerer, for nameplate
// completion.
func broadcastQueryRendezvous(nameplate string) (string, bool) {
	if nameplate == "" {
		return "", false
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", false
	}
	defer conn.Close()

	if err := enableBroadcast(conn); err != nil {
		return "", false
	}

	query := fmt.Sprintf("%s Q %s", broadcastMarker, nameplate)
	dests := broadcastAddresses()
	sendAll := func() {
		for _, addr := range dests {
			_, _ = conn.WriteToUDP([]byte(query), &net.UDPAddr{IP: addr, Port: broadcastDiscoveryPort})
		}
	}

	// two passes for lossy links, within the same listen window
	sendAll()
	time.AfterFunc(250*time.Millisecond, sendAll)

	deadline := time.Now().Add(broadcastQueryTimeout)
	buf := make([]byte, 512)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", false
		}

		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", false
		}

		fields := strings.Fields(string(buf[:n]))
		if len(fields) != 4 || fields[0] != broadcastMarker || fields[1] != "R" {
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
		return fmt.Sprintf("ws://%s:%d/ws", host, port), true
	}
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

func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	err = raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if err != nil {
		return err
	}

	return sockErr
}
