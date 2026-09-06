package summon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// A provider swapped after the pin was taken stops the issuer on the next
// resolve, and the error names both hashes so the operator can see what
// changed.
func TestResolveRefusesSwappedProvider(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "original-value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	pinned := cfg.Provider.PinnedHash
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	v, err := s.Resolve(ctx, "totem/anthropic")
	if err != nil {
		t.Fatalf("resolve before the swap = %v", err)
	}
	v.Zero()

	// The attacker's swap: same path, same mode, different binary.
	providerScript(t, dir, "provider", "printf 'attacker-value'\n")

	_, err = s.Resolve(ctx, "totem/anthropic")
	if !errors.Is(err, ErrProviderUntrusted) {
		t.Fatalf("resolve after the provider was swapped = %v, want ErrProviderUntrusted", err)
	}
	if !strings.Contains(err.Error(), pinned) {
		t.Fatalf("the error must name the pin %s, got %q", pinned, err)
	}
	if !strings.Contains(err.Error(), "trust-provider") {
		t.Fatalf("the error must name the deliberate fix, got %q", err)
	}
}

// The pin must never re-pin itself. After a mismatch, every later resolve
// fails the same way, and the configured pin is untouched.
func TestMismatchNeverRepins(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "original-value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	pinned := cfg.Provider.PinnedHash
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	providerScript(t, dir, "provider", "printf 'attacker-value'\n")
	for i := 0; i < 3; i++ {
		if _, err := s.Resolve(ctx, "totem/anthropic"); !errors.Is(err, ErrProviderUntrusted) {
			t.Fatalf("resolve %d after the swap = %v, want ErrProviderUntrusted every time", i, err)
		}
	}
	if s.cfg.Provider.PinnedHash != pinned {
		t.Fatalf("the pin changed from %s to %s without a trust-provider action", pinned, s.cfg.Provider.PinnedHash)
	}
	if err := s.Rotate(ctx); !errors.Is(err, ErrProviderUntrusted) {
		t.Fatalf("rotation after the swap = %v, want ErrProviderUntrusted", err)
	}
}

// An untrusted provider poisons the Summoner: the values it produced are wiped
// and nothing is served afterwards, including from cache.
func TestUntrustedProviderWipesCachedValues(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "original-value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	v, err := s.Resolve(ctx, "totem/anthropic")
	if err != nil {
		t.Fatal(err)
	}
	providerScript(t, dir, "provider", "printf 'attacker-value'\n")
	if _, err := s.Resolve(ctx, "totem/anthropic"); !errors.Is(err, ErrProviderUntrusted) {
		t.Fatal("expected the swap to be caught")
	}
	if got := v.Bytes(); len(got) != 0 && !allZero(got) {
		t.Fatalf("the value resolved by the now-untrusted provider is still readable: %q", got)
	}
	if err := s.Err(); !errors.Is(err, ErrProviderUntrusted) {
		t.Fatalf("Err() = %v, want the fatal ErrProviderUntrusted", err)
	}
	v.Zero()
}

// trust-provider is the only thing that produces a new pin, and it refuses to
// produce one for a path that fails the checks.
func TestTrustProviderRefusesUnsafePath(t *testing.T) {
	dir := sandbox(t)
	p := providerScript(t, dir, "provider", "printf x\n")
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := trustProviderForTest(p, os.Geteuid()); !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("trust-provider on a world-writable binary = %v, want ErrProviderUnsafe", err)
	}
	if _, err := TrustProvider(p); !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("TrustProvider on a world-writable binary = %v, want ErrProviderUnsafe", err)
	}
}

func TestTrustProviderMatchesTheHashResolveChecks(t *testing.T) {
	dir := sandbox(t)
	p := providerScript(t, dir, "provider", "printf x\n")
	h1, err := trustProviderForTest(p, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("trust-provider pinned %s but resolve checks %s", h1, h2)
	}
	providerScript(t, dir, "provider", "printf y\n")
	h3, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if h3 == h1 {
		t.Fatal("a different binary hashed the same")
	}
}

// A config with no pin, or a malformed one, fails at load. There is no mode in
// which an unpinned provider runs.
func TestNewRefusesMissingOrMalformedPin(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	base := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})

	cases := []struct {
		name string
		hash string
	}{
		{"missing", ""},
		{"truncated", base.Provider.PinnedHash[:32]},
		{"not hex", strings.Repeat("z", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Provider.PinnedHash = tc.hash
			if _, err := New(cfg); !errors.Is(err, ErrProviderUntrusted) {
				t.Fatalf("New with a %s pin = %v, want ErrProviderUntrusted", tc.name, err)
			}
		})
	}
}

// The per-resolve log carries the provider hash, which is what makes a swap
// visible in the record rather than only in an error.
func TestResolveLogsTheProviderHash(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	var buf logBuffer
	cfg.Logger = buf.logger()
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		v, err := s.Resolve(ctx, "totem/anthropic")
		if err != nil {
			t.Fatal(err)
		}
		v.Zero()
	}
	out := buf.String()
	if n := strings.Count(out, "provider_sha256="+cfg.Provider.PinnedHash); n < 3 {
		t.Fatalf("the provider hash appears on %d resolve records, want one per resolve\n%s", n, out)
	}
	if strings.Contains(out, "value") && strings.Contains(out, "secret=") {
		t.Fatalf("the log must never carry a value:\n%s", out)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
