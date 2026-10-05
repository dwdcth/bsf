package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/dwdcth/bsf/version"
	"github.com/spf13/cobra"
)

// A wormhole code is a numeric nameplate followed by one or more
// dash-separated words, e.g. "3-cinnamon-chalk-wizard".
var recvCodeRegexp = regexp.MustCompile(`^[0-9]+(-[a-zA-Z0-9]+)+$`)

func looksLikeRecvCode(s string) bool {
	return recvCodeRegexp.MatchString(s)
}

// existingPath reports whether s names an existing file or directory —
// the bare form's shorthand for sending it.
func existingPath(s string) bool {
	_, err := os.Stat(s)
	return err == nil
}

var rootCmd = &cobra.Command{
	Use:     "bsf [CODE|FILE]",
	Short:   "Create a wormhole and transfer files through it.",
	Version: version.AgentVersion,
	Long: `Create a (magic) Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time. Wormholes are secure against anyone who doesn't
  use the same code.

  Passing a CODE directly is shorthand for "receive CODE"; passing an
  existing file or directory path (or --text) is shorthand for "send".`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || looksLikeRecvCode(args[0]) || existingPath(args[0]) {
			return nil
		}
		return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
	},
	ValidArgsFunction: rootValidArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && looksLikeRecvCode(args[0]) {
			recvAction(cmd, args)
			return nil
		}
		if (len(args) > 0 && existingPath(args[0])) || sendTextFlag != "" {
			sendAction(cmd, args)
			return nil
		}
		return cmd.Help()
	},
}

var (
	relayURL         string
	verify           bool
	hideProgressBar  bool
	acceptAll        bool
	outDir           string
	serveMode        bool
	uploadToken      string
	iceEnabled       = true
	stunServers      string
	wsRelayURL       string
	transitRelayAddr string

	versionTemplate = `{{with .Name}}{{printf "%s " .}}{{end}}{{printf "%s" .Version}}
`
)

func Execute() error {
	rootCmd.SetVersionTemplate(versionTemplate)

	rootCmd.PersistentFlags().StringVar(&relayURL, "relay-url", "", "rendezvous relay to use")
	if relayURL == "" {
		relayURL = os.Getenv("WORMHOLE_RELAY_URL")
	}

	// receive flags on the root command so they work with the
	// bare "wormhole-william CODE" form too
	rootCmd.Flags().BoolVarP(&verify, "verify", "v", false, "display verification string (and wait for approval)")
	rootCmd.Flags().BoolVar(&hideProgressBar, "hide-progress", false, "suppress progress-bar display")
	rootCmd.Flags().IntVar(&parallelStreams, "parallel", 4, "number of parallel transit streams to use when the sender offers them")
	rootCmd.Flags().BoolVarP(&acceptAll, "yes", "y", false, "accept the transfer without prompting and overwrite existing files")
	rootCmd.Flags().StringVarP(&outDir, "out", "o", ".", "directory to receive into")
	rootCmd.Flags().BoolVar(&disableClipboard, "disable-clipboard", false, "do not copy received text to the system clipboard")
	// send's own flags, so the bare "bsf FILE" / "bsf --text MSG" forms
	// accept them too (the flags shared with receive — verify,
	// hide-progress, parallel — are already registered above)
	rootCmd.Flags().IntVarP(&codeLen, "code-length", "c", 0, "length of code (in bytes/words)")
	rootCmd.Flags().StringVar(&codeFlag, "code", "", "human-generated code phrase")
	rootCmd.Flags().StringVar(&sendTextFlag, "text", "", "text message to send, instead of a file.\nUse '-' to read from stdin")
	rootCmd.Flags().BoolVar(&showQRCode, "qr", false, "display code as QR code (experimental)")
	rootCmd.Flags().BoolVar(&relayMode, "relay", false, "also register the code on the relay (--relay-url or the public one) so receivers outside the local network can connect")
	// persistent so both the bare "bsf CODE" form and the send/receive
	// subcommands accept them
	rootCmd.PersistentFlags().BoolVar(&iceEnabled, "ice", true, "attempt UDP hole punching (p2p over QUIC) before falling back to a relay")
	rootCmd.PersistentFlags().StringVar(&stunServers, "stun", "", "comma-separated STUN endpoints (stun:host:port) for hole punching")
	rootCmd.PersistentFlags().StringVar(&wsRelayURL, "ws-relay", "", "wss:// websocket transit relay to use as fallback (e.g. a Cloudflare Worker)")
	rootCmd.PersistentFlags().StringVar(&transitRelayAddr, "transit-relay", "", "host:port of a self-hosted TCP transit relay for fallback (default: the public one)")

	if transitRelayAddr == "" {
		transitRelayAddr = os.Getenv("BSF_TRANSIT_RELAY")
	}

	if os.Getenv("BSF_NO_ICE") != "" {
		iceEnabled = false
	}
	if stunServers == "" {
		stunServers = os.Getenv("BSF_STUN")
	}
	if wsRelayURL == "" {
		wsRelayURL = os.Getenv("BSF_WS_RELAY")
	}

	rootCmd.AddCommand(recvCommand())
	rootCmd.AddCommand(sendCommand())
	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(completionCommand())
	return rootCmd.Execute()
}
