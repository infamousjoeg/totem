package summon

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// sandbox returns a directory whose entire ancestor chain satisfies the
// hardening rules for the test user, and which is not inside a git worktree or
// a synced folder, so a test exercises the real checks rather than tripping
// over its own scratch space.
//
// The default temp directory is used when it qualifies (it does on macOS,
// where TMPDIR is per-user and mode 0700). On Linux /tmp is mode 1777, which
// these rules refuse by design, so the fallback is a directory under the
// user's home. A scratch directory inside the checkout would not do: the file
// provider refuses anything inside a git worktree, which is the point of it.
func sandbox(t *testing.T) string {
	t.Helper()
	if dir := t.TempDir(); sandboxUsable(dir) == nil {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no temp directory on this machine satisfies the hardening rules and there is no home directory to fall back to: %v", err)
	}
	dir, err := os.MkdirTemp(home, ".totem-summon-test-")
	if err != nil {
		t.Skipf("cannot create a sandbox under %s: %v", home, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := sandboxUsable(dir); err != nil {
		t.Skipf("no directory on this machine can host the hardening tests: %v", err)
	}
	return dir
}

// sandboxUsable applies the package's own rules to a candidate scratch
// directory, so the helper cannot hand back a base that makes the tests pass
// vacuously.
func sandboxUsable(dir string) error {
	if err := checkTree(dir, os.Geteuid()); err != nil {
		return err
	}
	return checkNotPublished(dir)
}

// providerScript writes an executable fake Summon provider.
//
// It is a real executable on a real filesystem, exec'd through the same code
// path production uses, which is what lets it FAIL the hardening checks: a
// test can chmod it, chmod the directory holding it, rewrite it after the hash
// was pinned, or point a symlink at it. An in-process fake could not be caught
// by any of those checks, so it would only prove the package agrees with
// itself.
//
// What it cannot do: it is a /bin/sh script, so it exercises the protocol
// (argv in, value on stdout, diagnostics on stderr, exit status) and the
// environment, timeout, and process-group handling around it, but not a
// provider's internal behaviour. Nothing in this package depends on that.
func providerScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake provider: %v", err)
	}
	return p
}

// echoProvider is the happy-path fake: it returns a fixed value for any
// reference and records every reference it was called with, so a test can
// prove the provider was never reached.
func echoProvider(t *testing.T, dir, value string) (path, calls string) {
	t.Helper()
	calls = filepath.Join(dir, "calls")
	body := fmt.Sprintf("printf '%%s\\n' \"$1\" >> %q\nprintf '%%s' %q\n", calls, value)
	return providerScript(t, dir, "provider", body), calls
}

// callCount reports how many times a recording fake provider ran.
func callCount(t *testing.T, calls string) int {
	t.Helper()
	b, err := os.ReadFile(calls)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("reading call log: %v", err)
	}
	return len(strings.Fields(string(b)))
}

// writeConfigFile writes a stand-in for the issuer config file. Its contents
// do not matter here; its ownership and mode do, because the hardening rules
// cover the config as well as the provider.
func writeConfigFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "totem.yaml")
	if err := os.WriteFile(p, []byte("secrets:\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return p
}

// testConfig wires a Config around a fake provider with the hash pinned, which
// is what `totem issuer init` would have done.
func testConfig(t *testing.T, dir, provider string, refs map[string]Secret) Config {
	t.Helper()
	hash, err := trustProviderForTest(provider, os.Geteuid())
	if err != nil {
		t.Fatalf("pinning the fake provider: %v", err)
	}
	return Config{
		Path:     writeConfigFile(t, dir),
		Provider: Provider{Path: provider, PinnedHash: hash},
		Refs:     refs,
		Logger:   discardLogger(),
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// logBuffer captures log output so the per-resolve record can be asserted.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuffer) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
