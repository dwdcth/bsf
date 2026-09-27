package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/dwdcth/bsf/wormhole"
	qrterminal "github.com/mdp/qrterminal/v3"
	"github.com/spf13/cobra"
)

var (
	codeLen          int
	codeFlag         string
	sendTextFlag     string
	showQRCode       bool
	disableClipboard bool
	relayMode        bool
	parallelStreams  int
	parallelExplicit bool
)

// smallFileSingleStreamThreshold is the size under which a send uses a
// single stream when --parallel was not set explicitly: n transit
// handshakes cost more than they save on a transfer this short, and one
// stream is kinder to half-duplex wifi too.
const smallFileSingleStreamThreshold = 8 << 20

// effectiveParallel returns the stream count to offer: the user's
// explicit choice wins, otherwise small transfers go single-stream.
func effectiveParallel(totalBytes int64) int {
	if parallelExplicit {
		return parallelStreams
	}
	if totalBytes < smallFileSingleStreamThreshold {
		return 1
	}
	return parallelStreams
}

func sendCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "send [WHAT]",
		Short: "Send a text message, file, or directory...",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				sendText()
				return
			} else if len(args) > 1 {
				bail("Too many arguments")
			}

			stat, err := os.Stat(args[0])
			if err != nil {
				bail("Failed to read %s: %s", args[0], err)
			}

			parallelExplicit = cmd.Flags().Changed("parallel")

			if stat.IsDir() {
				sendDir(args[0])
				return
			} else {
				sendFile(args[0])
				return
			}
		},
	}

	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "display verification string (and wait for approval)")
	cmd.Flags().IntVarP(&codeLen, "code-length", "c", 0, "length of code (in bytes/words)")
	cmd.Flags().StringVar(&codeFlag, "code", "", "human-generated code phrase")
	cmd.Flags().StringVar(&sendTextFlag, "text", "", "text message to send, instead of a file.\nUse '-' to read from stdin")
	cmd.Flags().BoolVar(&hideProgressBar, "hide-progress", false, "suppress progress-bar display")
	cmd.Flags().BoolVar(&showQRCode, "qr", false, "display code as QR code (experimental)")
	cmd.Flags().BoolVar(&disableClipboard, "disable-clipboard", false, "do not copy the wormhole code to the system clipboard")
	cmd.Flags().BoolVar(&relayMode, "relay", false, "also register the code on the relay (--relay-url or the public one) so receivers outside the local network can connect")
	cmd.Flags().IntVar(&parallelStreams, "parallel", 4, "number of parallel transit streams for file transfers (bsf receivers only)")

	return &cmd
}

func newClient() wormhole.Client {
	if showQRCode && codeLen == 0 {
		codeLen = 4
	}

	c := wormhole.Client{
		RendezvousURL:             relayURL,
		PassPhraseComponentLength: codeLen,
		ParallelStreams:           parallelStreams,
	}

	if verify {
		c.VerifierOk = func(code string) bool {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Verifier %s. ok? (yes/no): ", code)

			yn, _ := reader.ReadString('\n')
			yn = strings.TrimSpace(yn)

			return yn == "yes"
		}
	}

	return c
}

// sendLeg is one rendezvous leg of an in-flight send.
type sendLeg struct {
	via    string // "relay" or "local network", shown to the user
	cancel context.CancelFunc
	status chan wormhole.SendResult
}

// sendSession is a single send racing on one or two rendezvous legs
// that all share the same wormhole code.
type sendSession struct {
	code     string
	legs     []sendLeg
	shutdown func()
}

// startSendSession runs a send on an embedded, mDNS-advertised
// rendezvous server on the local network. That is the default and the
// whole transfer stays on the lan. With --relay (or an explicit
// --relay-url) the code is also registered on a relay so receivers
// outside the local network can connect: the relay mints the code, the
// embedded server mirrors it, and whichever receiver shows up first
// wins while the other leg is cancelled. If that relay is unreachable
// the send falls back to the embedded server alone.
func startSendSession(run func(c *wormhole.Client, ctx context.Context, code string) (string, chan wormhole.SendResult, error)) (*sendSession, error) {
	session := &sendSession{shutdown: func() {}}

	var relayErr error
	relayLegURL := relayURL
	if relayLegURL == "" {
		relayLegURL = wormhole.DefaultRendezvousURL
	}
	if (relayMode || relayURL != "") && relayReachable(relayLegURL) {
		ctx, cancel := context.WithCancel(context.Background())
		c := newClient()
		code, status, err := run(&c, ctx, codeFlag)
		if err != nil {
			cancel()
			relayErr = err
		} else {
			session.code = code
			session.legs = append(session.legs, sendLeg{via: "relay", cancel: cancel, status: status})
		}
	}

	if session.code == "" {
		// no relay leg (default lan-only mode, --relay not given, or the
		// relay was unreachable): mint the code on an embedded server
		url, shutdown, err := lanRendezvous()
		if err != nil {
			if relayErr != nil {
				return nil, fmt.Errorf("relay: %s; lan: %s", relayErr, err)
			}
			return nil, err
		}
		session.shutdown = shutdown

		ctx, cancel := context.WithCancel(context.Background())
		c := newClient()
		c.RendezvousURL = url
		c.DisableTransitRelay = true
		code, status, err := run(&c, ctx, codeFlag)
		if err != nil {
			cancel()
			shutdown()
			if relayErr != nil {
				return nil, fmt.Errorf("relay: %s; lan: %s", relayErr, err)
			}
			return nil, err
		}
		session.code = code
		session.legs = append(session.legs, sendLeg{via: "local network", cancel: cancel, status: status})
		session.printMode()

		return session, nil
	}

	// mirror the relay-minted code on an embedded lan server
	url, shutdown, err := lanRendezvousForCode(session.code)
	if err != nil {
		// no usable lan interface or nameplate collision: relay-only send
		session.printMode()
		return session, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := newClient()
	c.RendezvousURL = url
	c.DisableTransitRelay = true
	_, lanStatus, err := run(&c, ctx, session.code)
	if err != nil {
		cancel()
		shutdown()
		session.printMode()
		return session, nil
	}
	session.shutdown = shutdown
	session.legs = append(session.legs, sendLeg{via: "local network", cancel: cancel, status: lanStatus})
	session.printMode()

	return session, nil
}

// printMode tells the user which rendezvous legs this send runs on.
func (s *sendSession) printMode() {
	vias := make([]string, 0, len(s.legs))
	for _, leg := range s.legs {
		vias = append(vias, leg.via)
	}

	fmt.Printf("Send mode: %s\n", strings.Join(vias, " + "))
}

// relayReachable does a bounded tcp dial to a relay url. It lets an
// unreachable relay fail over to lan-only mode in seconds instead of
// hanging on the os-level connect timeout, which can take half a minute
// on networks that blackhole outgoing traffic.
func relayReachable(url string) bool {
	u, err := neturl.Parse(url)
	if err != nil {
		return false
	}

	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		defaultPort := "80"
		if u.Scheme == "wss" || u.Scheme == "https" {
			defaultPort = "443"
		}
		host = net.JoinHostPort(host, defaultPort)
	}

	conn, err := net.DialTimeout("tcp", host, 3*time.Second)
	if err != nil {
		return false
	}

	return conn.Close() == nil
}

// wait returns the result of the first leg to complete and cancels the
// remaining legs.
func (s *sendSession) wait() wormhole.SendResult {
	type legResult struct {
		idx int
		res wormhole.SendResult
	}

	merged := make(chan legResult, len(s.legs))
	for i := range s.legs {
		go func(i int) {
			merged <- legResult{idx: i, res: <-s.legs[i].status}
		}(i)
	}

	done := <-merged
	for i := range s.legs {
		if i != done.idx {
			s.legs[i].cancel()
		}
	}

	fmt.Printf("Receiver connected via %s\n", s.legs[done.idx].via)

	return done.res
}

// onRelay reports whether any leg of this send registered the code on
// a relay, i.e. whether receivers outside the local network can
// connect.
func (s *sendSession) onRelay() bool {
	for _, leg := range s.legs {
		if leg.via == "relay" {
			return true
		}
	}
	return false
}

func printInstructions(code string, onRelay bool) {
	if onRelay {
		mwCmd := "wormhole receive"
		wwCmd := "bsf recv"

		if verify {
			mwCmd = mwCmd + " --verify"
			wwCmd = wwCmd + " --verify"
		}

		fmt.Printf("On the other computer, please run: %s (or %s)\n", mwCmd, wwCmd)
	} else {
		wwCmd := "bsf <code>"
		if verify {
			wwCmd = wwCmd + " --verify"
		}

		fmt.Printf("On the other computer on this network, please run: %s\n", wwCmd)
	}
	fmt.Printf("Wormhole code is: %s\n", code)

	if !disableClipboard {
		if copyViaHelper(code) {
			fmt.Println("Code copied to clipboard")
		} else if osc52Copy(code) {
			fmt.Println("Code copied to clipboard (OSC 52)")
		}
	}

	if showQRCode {
		url := relayURL
		if url == "" {
			url = wormhole.DefaultRendezvousURL
		}
		content := fmt.Sprintf("wormhole:%s?code=%s", url, code)
		qrterminal.Generate(content, qrterminal.L, os.Stdout)
	}
}

func sendFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		bail("Failed to open %s: %s", filename, err)
	}

	var bar *pb.ProgressBar

	args := []wormhole.SendOption{}

	if !hideProgressBar {
		args = append(args, wormhole.WithProgress(func(sentBytes int64, totalBytes int64) {
			if bar == nil {
				bar = pb.Full.Start64(totalBytes)
				bar.Set(pb.Bytes, true)
				bar.Set(pb.SIBytesPrefix, true)
			}
			bar.SetCurrent(sentBytes)

			if sentBytes == totalBytes {
				bar.Finish()
			}
		}))
	}

	size := int64(-1)
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}

	streams := effectiveParallel(size)

	session, err := startSendSession(func(c *wormhole.Client, ctx context.Context, code string) (string, chan wormhole.SendResult, error) {
		opts := args
		if code != "" {
			opts = append(opts, wormhole.WithCode(code))
		}
		if streams > 1 {
			opts = append(opts, wormhole.WithParallel(streams))
		}
		return c.SendFile(ctx, filepath.Base(filename), f, opts...)
	})
	if err != nil {
		bail("Error sending message: %s", err)
	}
	defer session.shutdown()

	printInstructions(session.code, session.onRelay())

	s := session.wait()

	if s.OK {
		fmt.Println("file sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

func sendDir(dirpath string) {
	dirpath = strings.TrimSuffix(dirpath, "/")

	stat, err := os.Stat(dirpath)
	if err != nil {
		log.Fatal(err)
	}

	if !stat.IsDir() {
		log.Fatalf("%s is not a directory", dirpath)
	}

	prefix, dirname := filepath.Split(dirpath)

	var entries []wormhole.DirectoryEntry
	var totalBytes int64

	filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		relPath := strings.TrimPrefix(path, prefix)
		totalBytes += info.Size()

		entries = append(entries, wormhole.DirectoryEntry{
			Path: relPath,
			Mode: info.Mode(),
			Reader: func() (io.ReadCloser, error) {
				return os.Open(path)
			},
		})

		return nil
	})

	var bar *pb.ProgressBar

	args := []wormhole.SendOption{}
	if !hideProgressBar {
		// progress tracks the compressed zip size; the bar starts from
		// the uncompressed total and corrects itself on the first
		// callback once the zip exists
		args = append(args, wormhole.WithProgress(func(sentBytes int64, totalZipBytes int64) {
			if bar == nil {
				bar = pb.Full.Start64(totalZipBytes)
				bar.Set(pb.Bytes, true)
				bar.Set(pb.SIBytesPrefix, true)
			}
			bar.SetCurrent(sentBytes)

			if sentBytes == totalZipBytes {
				bar.Finish()
			}
		}))
	}
	streams := effectiveParallel(totalBytes)

	session, err := startSendSession(func(c *wormhole.Client, ctx context.Context, code string) (string, chan wormhole.SendResult, error) {
		opts := args
		if code != "" {
			opts = append(opts, wormhole.WithCode(code))
		}
		if streams > 1 {
			opts = append(opts, wormhole.WithParallel(streams))
		}
		return c.SendDirectory(ctx, dirname, entries, opts...)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer session.shutdown()

	printInstructions(session.code, session.onRelay())

	s := session.wait()

	if s.OK {
		fmt.Println("directory sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

func sendText() {
	var msg string
	if sendTextFlag == "-" {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			bail("Read stdin err: %s", err)
		}
		msg = string(data)
	} else if sendTextFlag != "" {
		msg = sendTextFlag
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Text to send: ")
		msg, _ = reader.ReadString('\n')
		msg = strings.TrimSpace(msg)
	}

	session, err := startSendSession(func(c *wormhole.Client, ctx context.Context, code string) (string, chan wormhole.SendResult, error) {
		opts := []wormhole.SendOption{}
		if code != "" {
			opts = append(opts, wormhole.WithCode(code))
		}
		return c.SendText(ctx, msg, opts...)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer session.shutdown()

	printInstructions(session.code, session.onRelay())

	s := session.wait()

	if s.Error != nil {
		log.Fatalf("Send error: %s", s.Error)
	} else if s.OK {
		fmt.Println("text message sent")
	} else {
		log.Fatalf("Hmm not ok but also not error")
	}
}
