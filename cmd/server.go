package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/dwdcth/bsf/internal/transitrelay"
	"github.com/dwdcth/bsf/rendezvous/rendezvousservertest"
	"github.com/pion/turn/v5"
	"github.com/spf13/cobra"
)

func serverCommand() *cobra.Command {
	var addr, stunAddr, transitAddr string

	cmd := cobra.Command{
		Use:   "server",
		Short: "Run a private rendezvous server",
		Long: `Run a private rendezvous (mailbox) server, for example on a local
network where the public relay is not reachable or not desired.

Senders and receivers can use this server by passing
--relay-url ws://<host>:<port>/ws

--stun adds a STUN server (default :3478, empty disables) that peers use
for UDP hole punching, and --transit runs a TCP transit relay so
transfers that cannot punch fall back to this server instead of the
public one.`,
		Run: func(cmd *cobra.Command, args []string) {
			ts, err := startRendezvousServer(addr)
			if err != nil {
				bail("Failed to start rendezvous server: %s", err)
			}
			defer ts.Close()

			host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
			if err != nil {
				bail("Failed to determine listen address: %s", err)
			}

			portNum, err := strconv.Atoi(port)
			if err != nil {
				bail("Failed to determine listen port: %s", err)
			}

			var stun *turn.Server
			stunPortNum := 0
			if stunAddr != "" {
				pc, srv, serr := startSTUNServer(stunAddr)
				if serr != nil {
					bail("Failed to start STUN server: %s", serr)
				}
				stun = srv
				defer stun.Close()

				if _, port, perr := net.SplitHostPort(pc.LocalAddr().String()); perr == nil {
					stunPortNum, _ = strconv.Atoi(port)
				}
			}

			var relay *transitrelay.Server
			if transitAddr != "" {
				relay, err = transitrelay.New(transitAddr)
				if err != nil {
					bail("Failed to start transit relay: %s", err)
				}
				defer relay.Close()
			}

			stopBroadcast := startBroadcastResponderWithSTUN(ts, portNum, stunPortNum)
			defer stopBroadcast()

			fmt.Printf("Rendezvous server listening on %s (advertised via udp broadcast)\n", ts.Listener.Addr())
			if stun != nil {
				fmt.Printf("STUN server listening on %s (udp)\n", stunAddr)
			}
			if relay != nil {
				fmt.Printf("Transit relay listening on %s\n", relay.Addr())
			}

			// wildcard binds are reachable via loopback and every
			// interface; an explicit bind is only reachable on that host
			var hosts []string
			if host == "" || host == "::" || host == "0.0.0.0" {
				hosts = append(hosts, "127.0.0.1")
				for _, ip := range lanIPs() {
					hosts = append(hosts, ip.String())
				}
			} else {
				hosts = append(hosts, host)
			}

			for _, h := range hosts {
				if strings.Contains(h, ":") {
					h = "[" + h + "]"
				}
				fmt.Printf("Use: bsf --relay-url ws://%s:%s/ws ...\n", h, port)
				if relay != nil {
					fmt.Printf("      (fallback transit relay: %s)\n", relay.Addr())
				}
				if stun != nil {
					fmt.Printf("      (stun: stun:%s:%d)\n", h, stunPortNum)
				}
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			<-ctx.Done()
			fmt.Println("\nrendezvous server stopped")
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":0", "address to listen on")
	cmd.Flags().StringVar(&stunAddr, "stun", ":3478", "address for the STUN server (empty disables)")
	cmd.Flags().StringVar(&transitAddr, "transit", "", "address for a TCP transit relay (empty disables)")

	return &cmd
}

func startRendezvousServer(addr string) (*rendezvousservertest.TestServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return rendezvousservertest.NewServerOn(l), nil
}
