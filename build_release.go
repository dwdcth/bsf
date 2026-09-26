//go:build ignore
// +build ignore

// This is a tool to assist with building release artifacts.
// It is run automatically from github actions to produce the
// artifacts.
//
// Instructions for cutting a new release:
// - Update version/version.go
// - Make new git tag (e.g. v1.0.x)
// - Push tag to github
// - Github release.yml action will `go run build_release.go` at that tag

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dwdcth/bsf/version"
)

var ignoreTagMismatch = flag.Bool("ignore-tag-mismatch", false, "Don't check if current tag matches in code version")

func main() {
	flag.Parse()
	if !*ignoreTagMismatch {
		checkTagMatchesVersion()
	}
	os.MkdirAll("release", 0777)

	for _, t := range targets {
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", filepath.Join("release", t.binaryName()))
		env := []string{"GOOS=" + t.goos, "GOARCH=" + t.garch, "GO111MODULE=on"}
		if t.goarm != "" {
			env = append(env, "GOARM="+t.goarm)
		}
		cmd.Env = append(os.Environ(), env...)

		fmt.Printf("run: %s %s %s\n", strings.Join(env, " "), cmd.Path, strings.Join(cmd.Args[1:], " "))

		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %s err: %s, out: %s\n", t.goos, t.garch, err, out)
			os.Exit(1)
		}

		packArchive(&t)
	}
}

// packArchive compresses the freshly built binary into a tar.gz archive next
// to it and removes the intermediate raw binary, so that release/ ends up
// containing only tar.gz artifacts.
func packArchive(t *target) {
	bin := filepath.Join("release", t.binaryName())
	archive := filepath.Join("release", t.archiveName())

	cmd := exec.Command("tar", "-czf", archive, "-C", "release", t.binaryName())
	fmt.Printf("run: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tar %s err: %s, out: %s\n", archive, err, out)
		os.Exit(1)
	}

	if err := os.Remove(bin); err != nil {
		log.Fatalf("remove %s failed: %s", bin, err)
	}
}

func checkTagMatchesVersion() {
	codeVersion := version.AgentVersion
	headSha := gitCmd("rev-parse", "HEAD")
	tagSha := gitCmd("rev-parse", codeVersion)
	if headSha != tagSha {
		log.Fatalf("Tag for %s does not match HEAD ref: HEAD:%s TAG:%s", codeVersion, headSha, tagSha)
	}
}

func gitCmd(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		log.Fatalf("git %s failed: %s", args, err)
	}
	return string(bytes.TrimSpace(out))
}

type target struct {
	goos  string
	garch string
	goarm string
}

func (t *target) binaryName() string {
	ext := ""
	if t.goos == "windows" {
		ext = ".exe"
	}

	tmpl := "bsf-%s-%s%s%s"
	return fmt.Sprintf(tmpl, t.goos, t.garch, t.goarm, ext)
}

func (t *target) archiveName() string {
	return strings.TrimSuffix(t.binaryName(), ".exe") + ".tar.gz"
}

var targets = []target{
	{"linux", "amd64", ""},
	{"linux", "arm64", ""},
	{"linux", "arm", "5"},
	{"linux", "arm", "6"},
	{"linux", "arm", "7"},
	{"darwin", "amd64", ""},
	{"darwin", "arm64", ""},
	{"windows", "amd64", ""},
	{"windows", "arm64", ""},
	{"windows", "386", ""},
	{"freebsd", "amd64", ""},
	{"netbsd", "amd64", ""},
}
