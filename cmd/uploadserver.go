package cmd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The HTTP upload server behind "bsf receive -s": no sender install
// needed, any browser on the network can put files on this machine.
// It listens on the first free port from uploadBasePort upwards, saves
// into the -o directory (the current one by default) without asking,
// and renames collisions a.txt → a_1.txt → a_2.txt …

// uploadBasePort is where the search for a free port starts.
const uploadBasePort = 8075

// uploadPortTries bounds that search.
const uploadPortTries = 25

// uploadTokenLen is the length of the token generated when -t is not
// given; the alphabet drops easily-confused characters (0/O, 1/l/I)
// since the token gets typed on phones.
const uploadTokenLen = 8

const uploadTokenAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// randomUploadToken mints a token from crypto/rand.
func randomUploadToken() (string, error) {
	out := make([]byte, uploadTokenLen)
	buf := make([]byte, uploadTokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		out[i] = uploadTokenAlphabet[int(b)%len(uploadTokenAlphabet)]
	}
	return string(out), nil
}

// uploadTokenOK checks a request's token in constant time. The token
// rides the ?t= query parameter (as the printed URLs carry it) or the
// X-Upload-Token header.
func uploadTokenOK(r *http.Request, token string) bool {
	got := r.URL.Query().Get("t")
	if got == "" {
		got = r.Header.Get("X-Upload-Token")
	}
	if len(got) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// startUploadServer serves the upload page and endpoint until the
// listener is closed, trying basePort, basePort+1, … for a free port.
// Every request must carry token (query ?t= or X-Upload-Token header).
// It returns the listener so tests can shut it down.
func startUploadServer(basePort int, dir, token string) (net.Listener, int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, 0, fmt.Errorf("create target directory: %w", err)
	}

	var ln net.Listener
	var port int
	var err error
	for i := 0; i < uploadPortTries; i++ {
		port = basePort + i
		ln, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, 0, fmt.Errorf("no free port in %d-%d: %w", basePort, basePort+uploadPortTries-1, err)
	}

	srv := &http.Server{
		Handler:           uploadHandler(dir, token),
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		// returns when the listener closes; nothing to report
		_ = srv.Serve(ln)
	}()
	return ln, port, nil
}

// serveUploads runs the upload server in the foreground, printing the
// token-protected URLs to open. It only returns on server failure.
func serveUploads(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	if uploadToken == "" {
		if uploadToken, err = randomUploadToken(); err != nil {
			return fmt.Errorf("generate upload token: %w", err)
		}
	}

	ln, port, err := startUploadServer(uploadBasePort, dir, uploadToken)
	if err != nil {
		return err
	}
	defer ln.Close()

	fmt.Printf("Upload server (no install needed on the sender side, just a browser):\n")
	fmt.Printf("  http://localhost:%d/?t=%s\n", port, uploadToken)
	for _, ip := range lanIPs() {
		if v4 := ip.To4(); v4 != nil {
			fmt.Printf("  http://%s:%d/?t=%s\n", v4, port, uploadToken)
		}
	}
	fmt.Printf("Upload token: %s (also accepted as the X-Upload-Token header)\n", uploadToken)
	fmt.Printf("Saving into %s without confirmation; existing names get a _1, _2, … suffix.\n", abs)
	fmt.Printf("Ctrl-C to stop.\n")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("upload server stopped")
	return nil
}

// uploadHandler serves the picker page on / and takes one raw-body
// upload per POST on /upload?name=<relative path>. Raw bodies keep the
// server side streaming (no multipart buffering) and stay curl-able:
//
//	curl --data-binary @file.txt 'http://host:8075/upload?name=file.txt&t=TOKEN'
//
// The page itself is public (it is just UI), but every upload must
// carry the token as ?t= or the X-Upload-Token header.
func uploadHandler(dir, token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, uploadPageHTML)
	})

	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		// the page verifies its ?t= token after a server restart
		// replaced it, so stale links show the token input again
		if !uploadTokenOK(r, token) {
			http.Error(w, "bad or missing upload token\n", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST a file body to /upload?name=<path>\n", http.StatusMethodNotAllowed)
			return
		}
		if !uploadTokenOK(r, token) {
			http.Error(w, "bad or missing upload token\n", http.StatusUnauthorized)
			return
		}

		rel, err := sanitizeUploadPath(r.URL.Query().Get("name"))
		if err != nil {
			http.Error(w, err.Error()+"\n", http.StatusBadRequest)
			return
		}

		saved, size, err := saveUpload(dir, rel, r.Body)
		if err != nil {
			http.Error(w, err.Error()+"\n", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"saved": saved,
			"size":  size,
		})
	})

	return mux
}

// sanitizeUploadPath normalizes a browser- or curl-supplied relative
// path into something safe to join under the target directory,
// rejecting absolute paths and anything trying to escape it.
func sanitizeUploadPath(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "\\", "/")

	if strings.HasPrefix(name, "/") {
		return "", errors.New("bad file name (absolute paths and .. are not allowed)")
	}

	// windows drive letters, as in "C:/evil"
	if len(name) >= 2 && name[1] == ':' {
		return "", errors.New("bad file name (absolute paths and .. are not allowed)")
	}

	clean := path.Clean(name)
	if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("bad file name (absolute paths and .. are not allowed)")
	}
	if len(clean) > 512 {
		return "", errors.New("file name too long")
	}
	return clean, nil
}

// saveUpload streams r into dir/rel (creating subdirectories), picking
// the first free name when the target already exists: a.txt, a_1.txt,
// a_2.txt … The O_EXCL create makes the collision check race-free. It
// returns the path relative to dir that was actually written.
func saveUpload(dir, rel string, r io.Reader) (string, int64, error) {
	target := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", 0, err
	}

	base := filepath.Base(target)
	var f *os.File
	var chosen string
	for i := 0; ; i++ {
		candidate := collisionName(base, i)
		chosen = filepath.Join(filepath.Dir(target), candidate)
		var err error
		f, err = os.OpenFile(chosen, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", 0, err
		}
		// taken, try the next suffix
	}

	size, err := io.Copy(f, r)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(chosen) // don't leave a partial file behind
		return "", 0, err
	}

	saved, err := filepath.Rel(dir, chosen)
	if err != nil {
		saved = chosen
	}
	fmt.Printf("received %s (%s) → %s\n", rel, humanSize(size), saved)
	return saved, size, nil
}

// collisionName inserts _n before the extension for n > 0:
// a.txt → a_1.txt, archive.tar.gz → archive_1.tar.gz, Makefile →
// Makefile_1, .gitignore → .gitignore_1.
func collisionName(base string, n int) string {
	if n == 0 {
		return base
	}
	suffix := fmt.Sprintf("_%d", n)

	ext := filepath.Ext(base)
	// a lone leading dot is part of the name, not an extension
	if ext == base {
		return base + suffix
	}
	stem := strings.TrimSuffix(base, ext)
	// keep compound archive extensions intact: archive.tar.gz →
	// archive_1.tar.gz, not archive.tar_1.gz
	if first := filepath.Ext(stem); first == ".tar" {
		stem = strings.TrimSuffix(stem, first)
		ext = first + ext
	}
	return stem + suffix + ext
}

// humanSize renders a byte count for the console log line.
func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
