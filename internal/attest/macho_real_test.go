//go:build darwin

package attest

import (
	"bytes"
	"debug/macho"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// The tests in this file use binaries the OS ships, not fixtures: they are the
// proof that the pure-Go parser and CMS verifier agree with Apple's signer on
// real signatures. /bin/zsh exists on every macOS; the Claude Code binary is
// optional and its test skips with what it would have asserted.

func TestPlatformShellSignatureVerifies(t *testing.T) {
	f, err := os.Open("/bin/zsh")
	if err != nil {
		t.Fatalf("open /bin/zsh: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	sig, err := verifyMachO(f, st.Size(), sliceSelector{}, appleRoots())
	if err != nil {
		t.Fatalf("verifyMachO(/bin/zsh): %v", err)
	}
	if sig.Adhoc {
		t.Fatal("/bin/zsh reported as ad-hoc signed")
	}
	if sig.Identifier != "com.apple.zsh" {
		t.Errorf("identifier = %q, want com.apple.zsh", sig.Identifier)
	}
	if sig.Platform == 0 {
		t.Error("CodeDirectory platform field is zero for a platform binary")
	}
	if sig.TeamID != "" {
		t.Errorf("platform binary has Team ID %q", sig.TeamID)
	}
	if n := len(sig.Chain); n < 2 {
		t.Fatalf("chain has %d certificates, want at least leaf and root", n)
	}
	root := sig.Chain[len(sig.Chain)-1]
	if root.Subject.CommonName != "Apple Root CA" {
		t.Errorf("chain anchored at %q, want Apple Root CA", root.Subject.CommonName)
	}
	if len(sig.CDHash) != cdHashLen {
		t.Errorf("cdhash length %d", len(sig.CDHash))
	}
}

// TestPlatformShellTamperedPageIsRefused copies /bin/zsh, flips one byte in
// the middle of the text, and expects the page hash check to refuse it even
// though the CMS blob and CodeDirectory are untouched.
func TestPlatformShellTamperedPageIsRefused(t *testing.T) {
	data, err := os.ReadFile("/bin/zsh")
	if err != nil {
		t.Fatal(err)
	}
	// /bin/zsh is fat; flip a byte in the middle of the slice the verifier
	// will select for this host, so the damage is inside checked pages.
	off, size := int64(0), int64(len(data))
	if ff, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		for _, a := range ff.Arches {
			if a.Cpu == hostCPU() {
				off, size = int64(a.Offset), int64(a.Size)
			}
		}
	}
	data[off+size/2] ^= 0xff
	p := filepath.Join(t.TempDir(), "zsh")
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	_, err = verifyMachO(f, st.Size(), sliceSelector{}, appleRoots())
	if err == nil {
		t.Fatal("tampered copy of /bin/zsh verified")
	}
	if !strings.Contains(err.Error(), "code page") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	t.Logf("refused as expected: %v", err)
}

// TestPlatformShellWrongRootIsRefused proves the chain is actually verified:
// with a trust store that does not contain Apple's root, a genuine Apple
// signature must fail.
func TestPlatformShellWrongRootIsRefused(t *testing.T) {
	f, err := os.Open("/bin/zsh")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	ca := newTestCA(t)
	_, err = verifyMachO(f, st.Size(), sliceSelector{}, ca.roots())
	if !errors.Is(err, errCMS) {
		t.Fatalf("expected CMS chain failure with a foreign root, got %v", err)
	}
}

// TestRealClaudeBinary checks the shipped catalog row against a real Claude
// Code install when one is present.
func TestRealClaudeBinary(t *testing.T) {
	home, _ := os.UserHomeDir()
	matches, _ := filepath.Glob(filepath.Join(home, ".local/share/claude/versions/*"))
	if len(matches) == 0 {
		t.Skip("no Claude Code native install under ~/.local/share/claude/versions; would assert that the binary's signature chain-verifies to Apple Root CA with Team ID Q6L2SF6YDW, identifier com.anthropic.claude-code, and a Developer ID Application leaf")
	}
	path := matches[len(matches)-1]
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	sig, err := verifyMachO(f, st.Size(), sliceSelector{}, appleRoots())
	if err != nil {
		t.Fatalf("verifyMachO(%s): %v", path, err)
	}
	row := spiffe.Catalog[0]
	if sig.Adhoc {
		t.Fatal("claude reported ad-hoc")
	}
	if sig.TeamID != row.TeamID || sig.Identifier != row.SigningID {
		t.Errorf("team/id = %q/%q, catalog %q/%q", sig.TeamID, sig.Identifier, row.TeamID, row.SigningID)
	}
	leaf := sig.leaf()
	if subjectOU(leaf.Subject) != row.TeamID {
		t.Errorf("leaf OU %q != Team ID %q", subjectOU(leaf.Subject), row.TeamID)
	}
	if !hasExtension(leaf, oidAppleDeveloperIDApplication) {
		t.Error("leaf lacks the Developer ID Application marker")
	}
	if sig.Chain[len(sig.Chain)-1].Subject.CommonName != "Apple Root CA" {
		t.Error("chain does not end at Apple Root CA")
	}
}

// TestKernelCDHashSelectsBeforeVerification proves the order that keeps a
// swapped file from driving work: with a kernel cdhash no slice matches, a
// tampered copy of /bin/zsh is refused as "no slice matches" and its pages
// are never checked; with the right cdhash the page check runs and fails.
func TestKernelCDHashSelectsBeforeVerification(t *testing.T) {
	data, err := os.ReadFile("/bin/zsh")
	if err != nil {
		t.Fatal(err)
	}
	f0 := bytes.NewReader(data)
	good, err := verifyMachO(f0, int64(len(data)), sliceSelector{}, appleRoots())
	if err != nil {
		t.Fatal(err)
	}
	if ff, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		for _, a := range ff.Arches {
			if a.Cpu == hostCPU() {
				data[int64(a.Offset)+int64(a.Size)/2] ^= 0xff
			}
		}
	}
	r := bytes.NewReader(data)
	_, err = verifyMachO(r, int64(len(data)), sliceSelector{kernelCDHash: bytes.Repeat([]byte{0xee}, cdHashLen)}, appleRoots())
	if !errors.Is(err, errSliceNotFound) || strings.Contains(err.Error(), "code page") {
		t.Fatalf("unknown kernel cdhash: %v, want errSliceNotFound with no page check", err)
	}
	_, err = verifyMachO(r, int64(len(data)), sliceSelector{kernelCDHash: good.CDHash}, appleRoots())
	if err == nil || !strings.Contains(err.Error(), "code page") {
		t.Fatalf("matching kernel cdhash on a tampered slice: %v, want page check failure", err)
	}
}
