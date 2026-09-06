package summon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startWith builds a Summoner around a fake provider and starts it, or reports
// why it would not start.
func startWith(t *testing.T, dir, provider string, refs map[string]Secret, tune func(*Config)) (*Summoner, error) {
	t.Helper()
	cfg := testConfig(t, dir, provider, refs)
	if tune != nil {
		tune(&cfg)
	}
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		return nil, err
	}
	if err := s.Start(context.Background()); err != nil {
		return nil, err
	}
	t.Cleanup(func() { s.Close() })
	return s, nil
}

// "Clean environment, fixed PATH." The fake provider dumps its environment and
// working directory; nothing of the issuer's process leaks into it.
func TestProviderRunsWithACleanEnvironment(t *testing.T) {
	dir := sandbox(t)
	out := filepath.Join(dir, "env.txt")
	body := fmt.Sprintf("env > %q\npwd >> %q\nprintf 'v'\n", out, out)
	provider := providerScript(t, dir, "provider", body)

	t.Setenv("TOTEM_SECRET_LEAK", "should-not-be-visible")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-not-be-visible")

	if _, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 1 {
		t.Fatalf("the provider recorded nothing")
	}
	cwd := lines[len(lines)-1]
	env := lines[:len(lines)-1]
	// /bin/sh sets PWD, SHLVL and _ for itself no matter what it was exec'd
	// with; everything else in the provider's environment came from the
	// issuer, and the issuer passes exactly one variable.
	shellOwn := map[string]bool{"PWD": true, "SHLVL": true, "_": true}
	sawPATH := false
	for _, line := range env {
		name, value, _ := strings.Cut(line, "=")
		if name == "PATH" {
			sawPATH = true
			if value != FixedPATH {
				t.Fatalf("provider PATH = %q, want the fixed %q", value, FixedPATH)
			}
			continue
		}
		if !shellOwn[name] {
			t.Fatalf("the provider inherited %q from the issuer; the environment must be clean", line)
		}
	}
	if !sawPATH {
		t.Fatalf("provider environment %q has no PATH", env)
	}
	if cwd != "/" {
		t.Fatalf("provider working directory = %q, want /", cwd)
	}
	if strings.Contains(string(b), "should-not-be-visible") {
		t.Fatalf("the issuer's environment leaked into the provider:\n%s", b)
	}
}

// A provider that hangs is killed at the timeout rather than waited on, and
// the children it started go with it: otherwise a child holding stdout open
// would block the resolve past the deadline.
func TestProviderTimeoutKillsTheProcessGroup(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider", "sleep 30 &\nsleep 30\n")
	start := time.Now()
	_, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, func(c *Config) {
		c.Timeout = 300 * time.Millisecond
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a provider that never returns should not have started the issuer")
	}
	if !strings.Contains(err.Error(), "did not return within") {
		t.Fatalf("error = %v, want a timeout that names the deadline", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the resolve took %s: the hung provider's child was still holding the pipe", elapsed)
	}
}

func TestProviderNonZeroExitCarriesStderr(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider", "echo 'conjur: variable not found' >&2\nexit 7\n")
	_, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil)
	if err == nil {
		t.Fatal("a failing provider should not have started the issuer")
	}
	if !strings.Contains(err.Error(), "conjur: variable not found") {
		t.Fatalf("error = %v, want the provider's own diagnostic", err)
	}
	if !strings.Contains(err.Error(), "totem/a") {
		t.Fatalf("error = %v, want the reference that failed", err)
	}
}

// A provider cannot forge log lines or paint the terminal through stderr.
func TestProviderStderrIsSanitizedAndBounded(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider",
		"printf 'bad\\033[31m\\nlevel=ERROR forged\\n' >&2\nhead -c 20000 /dev/zero | tr '\\0' 'x' >&2\nexit 1\n")
	_, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil)
	if err == nil {
		t.Fatal("expected a failure")
	}
	msg := err.Error()
	if strings.Contains(msg, "\x1b") {
		t.Fatalf("escape sequences survived into the error: %q", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Fatalf("newlines survived into the error, so a provider can forge a log line: %q", msg)
	}
	if len(msg) > 1024 {
		t.Fatalf("error is %d bytes; a flooding provider must not grow it", len(msg))
	}
}

func TestProviderOversizedValueRefused(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider",
		fmt.Sprintf("head -c %d /dev/zero | tr '\\0' 'x'\n", MaxValueSize+100))
	_, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil)
	if err == nil {
		t.Fatal("an oversized value should have been refused")
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Fatalf("error = %v, want the size refusal", err)
	}
}

func TestProviderValueAtTheSizeLimitIsAccepted(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider",
		fmt.Sprintf("head -c %d /dev/zero | tr '\\0' 'x'\n", MaxValueSize))
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil)
	if err != nil {
		t.Fatalf("a value exactly at the limit was refused: %v", err)
	}
	v, err := s.Resolve(context.Background(), "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Zero()
	if len(v.Bytes()) != MaxValueSize {
		t.Fatalf("value is %d bytes, want %d", len(v.Bytes()), MaxValueSize)
	}
}

func TestProviderEmptyValueRefused(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider", "exit 0\n")
	_, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil)
	if err == nil {
		t.Fatal("an empty value should have been refused")
	}
	if !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("error = %v, want the empty-value refusal", err)
	}
}

// The provider protocol: the reference is the single argument, verbatim.
func TestProviderReceivesTheReferenceAsItsOnlyArgument(t *testing.T) {
	dir := sandbox(t)
	out := filepath.Join(dir, "argv.txt")
	body := fmt.Sprintf("printf '%%s|%%s\\n' \"$#\" \"$1\" > %q\nprintf 'v'\n", out)
	provider := providerScript(t, dir, "provider", body)
	if _, err := startWith(t, dir, provider, map[string]Secret{"gh": Rotating("totem/github-app")}, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "1|totem/github-app" {
		t.Fatalf("provider argv = %q, want exactly one argument, the reference", got)
	}
}

// A value is returned byte for byte. A provider that emits a trailing newline
// means it; only the built-in file provider, which reads what an editor wrote,
// trims one.
func TestProviderValueIsNotAltered(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider", "printf 'sk-ant-0123 \\n'\n")
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Resolve(context.Background(), "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Zero()
	if got := string(v.Bytes()); got != "sk-ant-0123 \n" {
		t.Fatalf("value = %q, want it verbatim", got)
	}
}
