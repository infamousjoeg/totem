//go:build darwin

package attest

// Real-process fixtures for macOS. TestMain builds one small Go program and
// re-signs copies of it with the test CA; the tests then spawn those copies
// (directly, through /bin/sh, through two shells, renamed as an interpreter)
// and attest the live connection through the real kernel interfaces. Nothing
// here needs Claude Code or any vendor binary installed.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fixtureSource is the program every fixture is built from.
//
//	fixture client <socket>      connect, send "hi", wait for a reply, exit
//	fixture run <cmd> [args...]  run cmd as a child and wait for it
const fixtureSource = `package main

import (
	"net"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 3 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "client":
		c, err := net.Dial("unix", os.Args[2])
		if err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		c.Write([]byte("hi"))
		buf := make([]byte, 8)
		c.Read(buf)
	case "run":
		cmd := exec.Command(os.Args[2], os.Args[3:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
	}
}
`

// fixtures is populated by TestMain.
var fixtures struct {
	err     error
	dir     string
	adhoc   string // the linker-signed build
	ca      *testCA
	catalog string // glob for the tools directory
	// Signed twins under <dir>/tools.
	good, badIdent, otherTeam, noDevID, wrongRoot, adhocTool string
	helper, interp, shellCopy                                string
}

const (
	fixtureTool   = "tool"
	fixtureIdent  = "com.totem.test.tool"
	fixtureTeam   = "TESTTEAM01"
	fixtureHelper = "totem"
)

func TestMain(m *testing.M) {
	code := func() int {
		if err := buildFixtures(); err != nil {
			fixtures.err = err
		}
		defer func() {
			if fixtures.dir != "" {
				os.RemoveAll(fixtures.dir)
			}
		}()
		return m.Run()
	}()
	os.Exit(code)
}

func buildFixtures() error {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		var lerr error
		if goBin, lerr = exec.LookPath("go"); lerr != nil {
			return fmt.Errorf("no go toolchain to build fixtures: %w", lerr)
		}
	}
	// Short path: unix socket names are limited to 104 bytes on macOS.
	dir, err := os.MkdirTemp("/tmp", "totem-attest-")
	if err != nil {
		return err
	}
	// The kernel reports real paths (/private/tmp), so work in those.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	fixtures.dir = dir
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(fixtureSource), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fixture\n\ngo 1.26\n"), 0o644); err != nil {
		return err
	}
	fixtures.adhoc = filepath.Join(dir, "fixture")
	cmd := exec.Command(goBin, "build", "-trimpath", "-o", fixtures.adhoc, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building fixture: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(fixtures.adhoc)
	if err != nil {
		return err
	}

	fakeT := &fatalT{}
	fixtures.ca = newTestCAWith(fakeT, testCAOptions{team: fixtureTeam})
	otherTeam := newTestCAWith(fakeT, testCAOptions{team: fixtureTeam, leafOU: "OTHERTEAM1", parent: fixtures.ca})
	noDevID := newTestCAWith(fakeT, testCAOptions{team: fixtureTeam, noDevIDMark: true, parent: fixtures.ca})
	wrongRoot := newTestCAWith(fakeT, testCAOptions{team: fixtureTeam})
	if fakeT.err != nil {
		return fakeT.err
	}

	tools := filepath.Join(dir, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		return err
	}
	fixtures.catalog = filepath.Join(tools, "*")
	// The kernel refuses a CodeDirectory team id that amfid cannot confirm
	// from an Apple-trusted chain, so every runnable twin leaves the CD team
	// field empty and carries its Team ID in the leaf certificate OU, which
	// is where the verifier reads it from anyway.
	sign := func(name, ident string, ca *testCA, o signOptions) (string, error) {
		o.noTeam = true
		out, err := resignMachO(raw, ident, ca, o)
		if err != nil {
			return "", fmt.Errorf("signing %s: %w", name, err)
		}
		p := filepath.Join(tools, name)
		return p, os.WriteFile(p, out, 0o755)
	}
	if fixtures.good, err = sign("good", fixtureIdent, fixtures.ca, signOptions{}); err != nil {
		return err
	}
	if fixtures.badIdent, err = sign("badident", "com.totem.test.other", fixtures.ca, signOptions{}); err != nil {
		return err
	}
	if fixtures.otherTeam, err = sign("otherteam", fixtureIdent, otherTeam, signOptions{}); err != nil {
		return err
	}
	if fixtures.noDevID, err = sign("nodevid", fixtureIdent, noDevID, signOptions{}); err != nil {
		return err
	}
	if fixtures.wrongRoot, err = sign("wrongroot", fixtureIdent, wrongRoot, signOptions{}); err != nil {
		return err
	}
	if fixtures.adhocTool, err = sign("adhoc", fixtureIdent, fixtures.ca, signOptions{adhoc: true}); err != nil {
		return err
	}
	// The helper stands in for the totem binary itself: recognised by path
	// and hash, so the linker-signed build is enough.
	helperDir := filepath.Join(dir, "helper")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		return err
	}
	fixtures.helper = filepath.Join(helperDir, fixtureHelper)
	if err := copyFile(fixtures.adhoc, fixtures.helper); err != nil {
		return err
	}
	interpDir := filepath.Join(dir, "interp")
	if err := os.MkdirAll(interpDir, 0o755); err != nil {
		return err
	}
	fixtures.interp = filepath.Join(interpDir, "python3")
	if err := copyFile(fixtures.adhoc, fixtures.interp); err != nil {
		return err
	}
	fixtures.shellCopy = filepath.Join(dir, "zsh")
	if err := copyFile("/bin/zsh", fixtures.shellCopy); err != nil {
		return err
	}
	return nil
}

// fatalT lets test-helper constructors run from TestMain.
type fatalT struct {
	testing.TB
	err error
}

func (f *fatalT) Helper()                   {}
func (f *fatalT) Fatal(args ...any)         { f.err = errors.New(fmt.Sprint(args...)) }
func (f *fatalT) Fatalf(s string, a ...any) { f.err = fmt.Errorf(s, a...) }

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o755)
}

func needFixtures(t *testing.T) {
	t.Helper()
	if fixtures.err != nil {
		t.Skipf("fixtures unavailable (%v); this test spawns a signed fixture process and attests its live unix connection", fixtures.err)
	}
}

// fixtureAttestor is the real macOS attestor with the trust root swapped for
// the test CA and the helper twin registered as the totem binary.
func fixtureAttestor(t *testing.T, sys system, pins map[string]string) *attestor {
	t.Helper()
	if sys == nil {
		sys = darwinSystem{}
	}
	a, err := newAttestor(sys, fixtureCatalog(), pins)
	if err != nil {
		t.Fatal(err)
	}
	// The test root for the fixtures, Apple's for the real shells the walk
	// crosses. Production trusts Apple only.
	a.roots = append(fixtures.ca.roots(), appleRoots()...)
	a.selfPath = fixtures.helper
	h, err := hashFile(fixtures.helper)
	if err != nil {
		t.Fatal(err)
	}
	a.selfHash = h
	return a
}

func fixtureCatalog() []spiffeCatalog {
	return []spiffeCatalog{{
		Name:          fixtureTool,
		TeamID:        fixtureTeam,
		SigningID:     fixtureIdent,
		ExpectedPaths: []string{fixtures.catalog},
	}}
}

// socketArg is a placeholder the harness substitutes with the socket path.
const socketArg = "@SOCK@"

// attestArgv listens on a fresh socket, spawns argv (with socketArg
// substituted; some process in the tree must connect and wait for a reply),
// attests the connection, and returns the result. The child is released
// only after attestation so every process in its chain is alive for the
// walk.
func attestArgv(t *testing.T, a Attestor, argv ...string) (*Identity, error) {
	t.Helper()
	sock := filepath.Join(fixtures.dir, fmt.Sprintf("s%d.sock", time.Now().UnixNano()%1_000_000))
	args := make([]string, len(argv))
	for i, s := range argv {
		args[i] = strings.ReplaceAll(s, socketArg, sock)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer os.Remove(sock)
	l.SetDeadline(time.Now().Add(10 * time.Second))
	cmd := exec.Command(args[0], args[1:]...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := l.AcceptUnix()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("accept: %v (fixture stderr: %s)", err, stderr.String())
	}
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading hello: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, aerr := a.AttestPeer(ctx, conn)
	conn.Write([]byte("ok"))
	if err := cmd.Wait(); err != nil {
		t.Logf("fixture exit: %v (stderr: %s)", err, stderr.String())
	}
	return id, aerr
}
