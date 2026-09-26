//go:build windows

package cmd

import (
	"net"

	"golang.org/x/sys/windows"
)

// windows has no portable SO_REUSEPORT; a second sender on the same
// host simply does not answer discovery queries.
func listenUDPReusePort(port int) (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
}

func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}

	return sockErr
}
