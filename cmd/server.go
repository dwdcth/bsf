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

	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
	"github.com/spf13/cobra"
)

func serverCommand() *cobra.Command {
	var addr string

	cmd := cobra.Command{
		Use:   "server",
		Short: "Run a private rendezvous server",
		Long: `Run a private rendezvous (mailbox) server, for example on a local
network where the public relay is not reachable or not desired.

Senders and receivers can use this server by passing
--relay-url ws://<host>:<port>/ws`,
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

			stopAdvert, err := advertiseRendezvous(portNum)
			if err != nil {
				bail("Failed to advertise via mDNS: %s", err)
			}
			defer stopAdvert()

			fmt.Printf("Rendezvous server listening on %s (advertised via mDNS as %s)\n", ts.Listener.Addr(), mdnsServiceType)

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
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			<-ctx.Done()
			fmt.Println("\nrendezvous server stopped")
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":0", "address to listen on")

	return &cmd
}

func startRendezvousServer(addr string) (*rendezvousservertest.TestServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return rendezvousservertest.NewServerOn(l), nil
}
