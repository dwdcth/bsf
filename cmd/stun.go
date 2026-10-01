package cmd

import (
	"net"

	"github.com/pion/turn/v5"
)

// startSTUNServer runs a STUN-only server (pion/turn with no relay
// generator: TURN allocations fail, binding requests are answered
// without authentication) so peers can learn their public mapping from
// a server they already trust instead of a public STUN provider.
func startSTUNServer(addr string) (net.PacketConn, *turn.Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, err
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc}},
	})
	if err != nil {
		pc.Close()
		return nil, nil, err
	}

	return pc, srv, nil
}
