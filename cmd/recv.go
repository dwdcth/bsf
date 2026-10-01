package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/dwdcth/bsf/wormhole"
	"github.com/klauspost/compress/zip"
	"github.com/spf13/cobra"
)

func recvCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:     "receive [OPTIONS] [CODE]...",
		Aliases: []string{"recv"},
		Short:   "Receive a text message, file, or directory...",
		Run:     recvAction,
	}

	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "display verification string (and wait for approval)")
	cmd.Flags().BoolVar(&hideProgressBar, "hide-progress", false, "suppress progress-bar display")
	cmd.Flags().IntVar(&parallelStreams, "parallel", 4, "number of parallel transit streams to use when the sender offers them")
	cmd.Flags().BoolVarP(&acceptAll, "yes", "y", false, "accept the transfer without prompting and overwrite existing files")
	cmd.Flags().StringVarP(&outDir, "out", "o", ".", "directory to receive into")
	cmd.Flags().BoolVar(&disableClipboard, "disable-clipboard", false, "do not copy received text to the system clipboard")

	cmd.ValidArgsFunction = recvCodeCompletion

	return &cmd
}

func recvAction(cmd *cobra.Command, args []string) {
	var (
		code string
		c    = newClient()
		ctx  = context.Background()
	)

	if len(args) > 0 {
		code = args[0]
	}

	if code == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter receive wormhole code: ")

		line, err := reader.ReadString('\n')
		if err != nil {
			errf("Error reading from stdin: %s\n", err)
		}
		code = strings.TrimSpace(line)
	}

	// no explicit relay: look for a rendezvous server on the local
	// network that knows this code before falling back to the public one
	if relayURL != "" {
		fmt.Printf("Rendezvous: %s (relay)\n", relayURL)
	} else if url, stunAddr, seen := discoverRendezvousDetail(codeNameplate(code)); url != "" {
		c.RendezvousURL = url
		// the local server doubles as STUN when it runs one
		if stunAddr != "" && len(c.STUNServers) == 0 {
			c.STUNServers = []string{"stun:" + stunAddr}
		}
		fmt.Printf("Rendezvous: %s (local network)\n", url)
	} else {
		if seen > 0 {
			fmt.Fprintf(os.Stderr, "note: %d local rendezvous server(s) found via broadcast discovery, but none answered for nameplate %s (sender exited, or its firewall blocks the connection)\n", seen, codeNameplate(code))
		} else {
			fmt.Fprintf(os.Stderr, "note: no rendezvous server found on the local network\n")
		}
		fmt.Printf("Rendezvous: %s (public relay)\n", wormhole.DefaultRendezvousURL)
	}

	if verify {
		c.VerifierOk = func(code string) bool {
			fmt.Printf("Verifier %s.\n", code)
			return true
		}
	}

	msg, err := c.Receive(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	switch msg.Type {
	case wormhole.TransferText:
		body, err := io.ReadAll(msg)
		if err != nil {
			log.Fatal(err)
		}

		os.Stdout.Write(body)
		os.Stdout.WriteString("\n")

		if !disableClipboard && len(body) <= 1<<20 {
			if copyViaHelper(string(body)) {
				fmt.Fprintln(os.Stderr, "Text copied to clipboard")
			} else if osc52Copy(string(body)) {
				fmt.Fprintln(os.Stderr, "Text copied to clipboard (OSC 52)")
			}
		}
	case wormhole.TransferFile:
		var acceptFile bool

		// the offer filename is peer controlled; keep it a single
		// component so a malicious sender cannot plant the payload
		// outside the receive directory (or overwrite dotfiles there)
		name := filepath.Base(msg.Name)
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/`) {
			msg.Reject()
			bail("bad filename in offer: %q", msg.Name)
		}
		destName := filepath.Join(outDir, name)
		_, statErr := os.Stat(destName)
		if statErr != nil && !os.IsNotExist(statErr) && !acceptAll {
			msg.Reject()
			bail("Error stat'ing existing '%s'", destName)
		}

		if acceptAll {
			acceptFile = true
		} else {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Receiving file (%s) into: %s\n", formatBytes(msg.TransferBytes64), destName)
			if statErr == nil {
				fmt.Print("file exists, overwrite? (y/N):")
			} else {
				fmt.Print("ok? (y/N):")
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				errf("Error reading from stdin: %s\n", err)
			}
			line = strings.TrimSpace(line)
			if line == "y" {
				acceptFile = true
			}
		}

		if !acceptFile {
			msg.Reject()
			bail("transfer rejected")
		} else {
			if err := os.MkdirAll(outDir, 0o777); err != nil {
				bail("Failed to create receive directory %s: %s", outDir, err)
			}
			f, err := ioutil.TempFile(outDir, fmt.Sprintf("%s.tmp", name))
			if err != nil {
				bail("Failed to create tempfile: %s", err)
			}

			if msg.ParallelStreams() > 1 {
				// multi-stream transfer with automatic resume:
				// progress comes from a callback instead of the
				// io.Reader proxy
				var bar *pb.ProgressBar
				progressFn := func(received, total int64) {}
				if !hideProgressBar {
					bar = pb.Full.Start64(msg.TransferBytes64)
					bar.Set(pb.Bytes, true)
					bar.Set(pb.SIBytesPrefix, true)
					progressFn = func(received, total int64) {
						bar.SetCurrent(received)
					}
				}

				err = msg.ReceiveFileInto(ctx, f, progressFn)
				if bar != nil {
					bar.Finish()
				}
				if err != nil {
					os.Remove(f.Name())
					bail("Receive file error: %s", err)
				}
			} else {
				proxyReader := pbProxyReader(msg, msg.TransferBytes64)

				_, err = io.Copy(f, proxyReader)
				if err != nil {
					os.Remove(f.Name())
					bail("Receive file error: %s", err)
				}

				proxyReader.Close()
			}

			tmpName := f.Name()
			f.Close()

			err = os.Rename(tmpName, destName)
			if err != nil {
				bail("Rename %s to %s failed: %s", tmpName, destName, err)
			}
		}
	case wormhole.TransferDirectory:
		var acceptDir bool

		if err := os.MkdirAll(outDir, 0o777); err != nil {
			bail("Failed to create receive directory %s: %s", outDir, err)
		}
		wd, err := filepath.Abs(outDir)
		if err != nil {
			bail("Failed to get receive directory: %s", err)
		}

		dirName := msg.Name
		dirName, err = filepath.Abs(filepath.Join(outDir, dirName))
		if err != nil {
			bail("Failed to get abs directory: %s", err)
		}

		if filepath.Dir(dirName) != wd {
			bail("Bad Directory name %s", msg.Name)
		}

		_, statErr := os.Stat(dirName)
		if statErr != nil && !os.IsNotExist(statErr) && !acceptAll {
			msg.Reject()
			bail("Error stat'ing existing '%s'", msg.Name)
		}

		if acceptAll {
			acceptDir = true
			if err := os.MkdirAll(dirName, 0o777); err != nil {
				bail("Mkdir error for %s: %s\n", dirName, err)
			}
		} else {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Receiving directory (%s) into: %s\n", formatBytes(msg.TransferBytes64), msg.Name)
			fmt.Printf("%d files, %s (uncompressed)\n", msg.FileCount, formatBytes(msg.UncompressedBytes64))
			if statErr == nil {
				fmt.Print("directory exists, overwrite? (y/N):")
			} else {
				fmt.Print("ok? (y/N):")
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				errf("Error reading from stdin: %s\n", err)
			}
			line = strings.TrimSpace(line)
			if line == "y" {
				acceptDir = true
			}
		}

		if !acceptDir {
			msg.Reject()
			bail("transfer rejected")
		} else {
			if err := os.Mkdir(dirName, 0o777); err != nil && !os.IsExist(err) {
				bail("Mkdir error for %s: %s\n", dirName, err)
			}

			tmpFile, err := ioutil.TempFile(wd, msg.Name+".zip.tmp")
			if err != nil {
				bail("Failed to create tempfile: %s", err)
			}

			defer tmpFile.Close()
			defer os.Remove(tmpFile.Name())

			var n int64
			if msg.ParallelStreams() > 1 {
				// multi-stream transfer with automatic resume:
				// progress comes from a callback instead of the
				// io.Reader proxy
				var bar *pb.ProgressBar
				progressFn := func(received, total int64) {}
				if !hideProgressBar {
					bar = pb.Full.Start64(msg.TransferBytes64)
					bar.Set(pb.Bytes, true)
					bar.Set(pb.SIBytesPrefix, true)
					progressFn = func(received, total int64) {
						n = received
						bar.SetCurrent(received)
					}
				}

				err = msg.ReceiveFileInto(ctx, tmpFile, progressFn)
				if bar != nil {
					bar.Finish()
				}
				if err != nil {
					os.Remove(tmpFile.Name())
					bail("Receive file error: %s", err)
				}
				if n == 0 {
					n = msg.TransferBytes64
				}
			} else {
				proxyReader := pbProxyReader(msg, msg.TransferBytes64)

				copied, err := io.Copy(tmpFile, proxyReader)
				if err != nil {
					os.Remove(tmpFile.Name())
					bail("Receive file error: %s", err)
				}

				proxyReader.Close()
				n = copied
			}

			zr, err := zip.NewReader(tmpFile, n)
			if err != nil {
				bail("Read zip error: %s", err)
			}

			for _, zf := range zr.File {
				p, err := filepath.Abs(filepath.Join(dirName, zf.Name))
				if err != nil {
					bail("Failes to calculate file path ABS: %s", err)
				}

				if p != dirName && !strings.HasPrefix(p, dirName+string(os.PathSeparator)) {
					bail("Dangerous filename detected: %s", zf.Name)
				}

				rc, err := zf.Open()
				if err != nil {
					bail("Failed to open file in zip: %s %s", zf.Name, err)
				}

				dir := filepath.Dir(p)
				err = os.MkdirAll(dir, 0777)
				if err != nil {
					bail("Failed to mkdirall %s: %s", dir, err)
				}

				// strip setuid/setgid/sticky: the sender has no
				// business choosing those for files it hands over
				f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode()&0o777)
				if err != nil {
					bail("Failed to open %s: %s", p, err)
				}

				_, err = io.Copy(f, rc)
				if err != nil {
					bail("Failed to write to %s: %s", p, err)
				}

				err = f.Close()
				if err != nil {
					bail("Error closing %s: %s", p, err)
				}

				rc.Close()
			}
		}
	}
}

func errf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	if !strings.HasSuffix("\n", msg) {
		fmt.Fprint(os.Stderr, "\n")
	}
}

func bail(msg string, args ...interface{}) {
	errf(msg, args...)
	os.Exit(1)
}

func formatBytes(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

type proxyReadCloser struct {
	*pb.Reader
	bar *pb.ProgressBar
}

func (p *proxyReadCloser) Close() error {
	p.bar.Finish()
	return nil
}

func pbProxyReader(r io.Reader, size int64) io.ReadCloser {
	if hideProgressBar {
		return ioutil.NopCloser(r)
	} else {
		progressBar := pb.Full.Start64(size)
		progressBar.Set(pb.Bytes, true)
		progressBar.Set(pb.SIBytesPrefix, true)
		proxyReader := progressBar.NewProxyReader(r)
		return &proxyReadCloser{
			Reader: proxyReader,
			bar:    progressBar,
		}
	}
}
