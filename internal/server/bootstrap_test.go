package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testCode = "MY-FOUNDING-ADMIN-CODE"

// TestBootstrapGoesToAFileWhenStdoutIsNotATerminal is the whole rule in one
// test. `totem-issuer init` inside a container, under systemd, or in a CI job
// has its stdout captured by something that keeps it, and a founding-admin code
// kept in a journal or a build artifact is a code an attacker reads later from
// a place nobody thinks of as secret.
func TestBootstrapGoesToAFileWhenStdoutIsNotATerminal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A regular file stands in for every captured-stdout case: a pipe, a
	// journal, a redirect. None of them is a character device.
	captured, err := os.Create(filepath.Join(dir, "captured-stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer captured.Close()

	expires := time.Now().Add(BootstrapCodeTTL)
	dest, err := EmitBootstrap(captured, dir, "totem enroll https://issuer#sha256:aa --code "+testCode, expires)
	if err != nil {
		t.Fatal(err)
	}
	if dest.Terminal {
		t.Fatal("a regular file was treated as a terminal")
	}

	stdout, err := os.ReadFile(captured.Name())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stdout, []byte(testCode)) {
		t.Fatal("the bootstrap code was written to a non-terminal stdout")
	}

	body, err := os.ReadFile(dest.Path)
	if err != nil {
		t.Fatalf("the code was not written to the file it named: %v", err)
	}
	if !bytes.Contains(body, []byte(testCode)) {
		t.Error("the file does not contain the code")
	}
	info, err := os.Stat(dest.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("bootstrap file mode %o, want 600", perm)
	}
	if !strings.Contains(dest.String(), dest.Path) {
		t.Error("the operator must be told where the code went")
	}
	if strings.Contains(dest.String(), testCode) {
		t.Error("the notice about where the code went must not contain the code")
	}
}

// TestBootstrapFileIsNeverWrittenIntoAPreExistingMode. Truncating an existing
// file keeps whatever mode and owner it already had, which is how a file an
// attacker pre-created world-readable ends up holding the founding-admin code.
func TestBootstrapFileIsNeverWrittenIntoAPreExistingMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, BootstrapCodeFile)
	if err := os.WriteFile(path, []byte("planted"), 0o666); err != nil {
		t.Fatal(err)
	}
	captured, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer captured.Close()

	dest, err := EmitBootstrap(captured, dir, "cmd --code "+testCode, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dest.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("a pre-created world-writable file kept its mode: %o", perm)
	}
}

// TestBootstrapWithNoSinkFails. An issuer that minted a founding-admin code and
// then lost it is an issuer nobody can enroll against, and the honest outcome is
// to say so rather than to print it somewhere it should not be.
func TestBootstrapWithNoSinkFails(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	_ = buf
	if _, err := EmitBootstrap(nil, "", "cmd --code x", time.Now()); err == nil {
		t.Fatal("delivering a code with nowhere safe to put it must fail")
	}
}

// TestRedactBootstrap is the last line of defence for anything that formats a
// message containing an enroll command.
func TestRedactBootstrap(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"totem enroll https://x#sha256:aa --code ABC123", "totem enroll https://x#sha256:aa --code [redacted]"},
		{"totem enroll https://x --code ABC123 extra", "totem enroll https://x --code [redacted] extra"},
		{"nothing to redact", "nothing to redact"},
	} {
		if got := RedactBootstrap(tc.in); got != tc.want {
			t.Errorf("RedactBootstrap(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBootstrapTTLIsTenMinutes, from the spec, stated so a change is deliberate.
func TestBootstrapTTLIsTenMinutes(t *testing.T) {
	t.Parallel()
	if BootstrapCodeTTL != 10*time.Minute {
		t.Fatalf("bootstrap TTL is %s; the spec says ten minutes", BootstrapCodeTTL)
	}
}
