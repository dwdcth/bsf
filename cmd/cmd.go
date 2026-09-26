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

var rootCmd = &cobra.Command{
	Use:     "bsf [CODE]",
	Short:   "Create a wormhole and transfer files through it.",
	Version: version.AgentVersion,
	Long: `Create a (magic) Wormhole and communicate through it.

  Wormholes are created by speaking the same magic CODE in two different
  places at the same time. Wormholes are secure against anyone who doesn't
  use the same code.

  Passing a CODE directly is shorthand for "receive CODE".`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || looksLikeRecvCode(args[0]) {
			return nil
		}
		return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
	},
	ValidArgsFunction: recvCodeCompletion,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && looksLikeRecvCode(args[0]) {
			recvAction(cmd, args)
			return nil
		}
		return cmd.Help()
	},
}

var (
	relayURL        string
	verify          bool
	hideProgressBar bool

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

	rootCmd.AddCommand(recvCommand())
	rootCmd.AddCommand(sendCommand())
	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(completionCommand())
	return rootCmd.Execute()
}
