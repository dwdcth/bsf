package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func postUploadQuery(t *testing.T, target, rawQuery string, body []byte) (*http.Response, string) {
	t.Helper()
	resp, err := http.Post(target+"/upload?"+rawQuery, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func postUpload(t *testing.T, target, name string, body []byte) (*http.Response, string) {
	t.Helper()
	return postUploadQuery(t, target, "name="+url.QueryEscape(name), body)
}

func TestUploadHandlerSavesAndRenames(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(uploadHandler(dir, ""))
	defer srv.Close()

	// single file
	resp, body := postUpload(t, srv.URL, "a.txt", []byte("one"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got struct {
		Saved string `json:"saved"`
		Size  int64  `json:"size"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Saved != "a.txt" || got.Size != 3 {
		t.Fatalf("unexpected response: %+v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "one" {
		t.Fatalf("a.txt content %q", b)
	}

	// same name again: no overwrite, _1 suffix instead
	resp, body = postUpload(t, srv.URL, "a.txt", []byte("second"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Saved != "a_1.txt" {
		t.Fatalf("collision should save a_1.txt, got %q", got.Saved)
	}

	// and again: _2
	_, body = postUpload(t, srv.URL, "a.txt", []byte("third"))
	json.Unmarshal([]byte(body), &got)
	if got.Saved != "a_2.txt" {
		t.Fatalf("second collision should save a_2.txt, got %q", got.Saved)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "one" {
		t.Fatal("original a.txt was overwritten")
	}

	// multi-file / folder structure: subdirectories are created
	resp, body = postUpload(t, srv.URL, "photos/holiday/beach.jpg", []byte("jpegdata"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "photos", "holiday", "beach.jpg")); string(b) != "jpegdata" {
		t.Fatal("nested file missing or wrong content")
	}
}

func TestUploadHandlerRejectsBadNames(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(uploadHandler(dir, ""))
	defer srv.Close()

	for _, name := range []string{"../evil", "sub/../../evil", "/etc/passwd", "C:/evil", "..", "", " "} {
		resp, _ := postUpload(t, srv.URL, name, []byte("x"))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("name %q should be rejected, got status %d", name, resp.StatusCode)
		}
	}

	// nothing may have escaped the target dir
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("rejected uploads left files behind: %v", entries)
	}
}

func TestUploadHandlerServesPage(t *testing.T) {
	srv := httptest.NewServer(uploadHandler(t.TempDir(), ""))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"upload", "webkitdirectory", "/upload?name="} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("page missing %q", want)
		}
	}
}

func TestStartUploadServerPortFallback(t *testing.T) {
	// find a free port, then occupy it so the server must move on
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	blocker, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", base))
	if err != nil {
		t.Skipf("cannot occupy port %d: %s", base, err)
	}
	defer blocker.Close()

	dir := t.TempDir()
	ln, port, err := startUploadServer(base, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if port != base+1 {
		t.Fatalf("expected fallback to %d, got %d", base+1, port)
	}

	// the server is live on the fallback port and saves into dir
	resp, body := postUpload(t, "http://127.0.0.1:"+strconv.Itoa(port), "hello.txt", []byte("hi"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hello.txt")); string(b) != "hi" {
		t.Fatal("file missing")
	}
}

func TestCollisionName(t *testing.T) {
	tests := []struct {
		base string
		n    int
		want string
	}{
		{"a.txt", 0, "a.txt"},
		{"a.txt", 1, "a_1.txt"},
		{"a.txt", 2, "a_2.txt"},
		{"archive.tar.gz", 1, "archive_1.tar.gz"},
		{"Makefile", 3, "Makefile_3"},
		{".gitignore", 1, ".gitignore_1"},
		{"no_ext", 1, "no_ext_1"},
	}
	for _, tt := range tests {
		if got := collisionName(tt.base, tt.n); got != tt.want {
			t.Errorf("collisionName(%q, %d) = %q, want %q", tt.base, tt.n, got, tt.want)
		}
	}
}

func TestUploadTokenRequired(t *testing.T) {
	dir := t.TempDir()
	const token = "ab3xk9mq"

	// wrong token: page still served, uploads and checks rejected
	srv := httptest.NewServer(uploadHandler(dir, token))
	defer srv.Close()

	if resp, _ := postUpload(t, srv.URL, "a.txt", []byte("x")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("upload without token: status %d", resp.StatusCode)
	}
	resp, _ := postUploadQuery(t, srv.URL, "name=a.txt&t=wrong1", []byte("x"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("upload with wrong token: status %d", resp.StatusCode)
	}
	if resp, err := http.Get(srv.URL + "/check?t=wrong1"); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("check with wrong token: %v %d", err, resp.StatusCode)
	}

	// right token, via query and via header
	if resp, body := postUploadQuery(t, srv.URL, "name=a.txt&t="+token, []byte("ok")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload with token: status %d: %s", resp.StatusCode, body)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/upload?name=b.txt", strings.NewReader("hdr"))
	req.Header.Set("X-Upload-Token", token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil || resp2.StatusCode != http.StatusCreated {
		t.Fatalf("upload with header token: %v %d", err, resp2.StatusCode)
	}
	resp2.Body.Close()

	// nothing saved by the rejected attempts
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("expected exactly a.txt and b.txt, got %v", entries)
	}
}

func TestRandomUploadToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		tok, err := randomUploadToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != uploadTokenLen {
			t.Fatalf("token %q has length %d", tok, len(tok))
		}
		for _, c := range tok {
			if !strings.ContainsRune(uploadTokenAlphabet, c) {
				t.Fatalf("token %q has character %q outside the alphabet", tok, c)
			}
		}
		if seen[tok] {
			t.Fatalf("token %q repeated", tok)
		}
		seen[tok] = true
	}
}
