package summon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingProvider returns a different value on every call, so a rotation is
// visible in the value itself rather than only in a log line.
func countingProvider(t *testing.T, dir string) string {
	t.Helper()
	counter := filepath.Join(dir, "counter")
	body := fmt.Sprintf(`n=0
if [ -f %[1]q ]; then n=$(cat %[1]q); fi
n=$((n+1))
printf '%%s' "$n" > %[1]q
printf 'value-%%s' "$n"
`, counter)
	return providerScript(t, dir, "provider", body)
}

// Rotation is atomic and the superseded value stays readable for the in-flight
// window: a request that already has the old value finishes against it.
func TestSupersededValueSurvivesTheInFlightWindow(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Reference{"a": "totem/a"}, func(c *Config) {
		c.RetireAfter = 2 * time.Second
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	old, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(old.Bytes()); got != "value-1" {
		t.Fatalf("first value = %q", got)
	}
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	// The in-flight holder still reads the value it was given.
	if got := string(old.Bytes()); got != "value-1" {
		t.Fatalf("in-flight value after rotation = %q, want value-1 until the window passes", got)
	}
	// A new resolve gets the new value: the replacement was atomic, with no
	// window in which the reference had no value at all.
	fresh, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(fresh.Bytes()); got != "value-2" {
		t.Fatalf("value after rotation = %q, want value-2", got)
	}
	fresh.Zero()
	old.Zero()
}

// The other half of the same rule: a caller who cached a Value across a
// rotation is holding a zeroed buffer once the window passes. That is the
// intended loud failure.
func TestCachedValueIsZeroedAfterTheRetireWindow(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Reference{"a": "totem/a"}, func(c *Config) {
		c.RetireAfter = 50 * time.Millisecond
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hoarded, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(hoarded.Bytes()); got != "value-1" {
		t.Fatalf("first value = %q", got)
	}
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b := hoarded.Bytes(); len(b) == 0 || allZero(b) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a value cached across a rotation is still readable as %q", hoarded.Bytes())
		}
		time.Sleep(10 * time.Millisecond)
	}
	hoarded.Zero()
}

// Releasing the last handle on a superseded value zeroes it immediately rather
// than waiting for the window.
func TestReleasedSupersededValueIsZeroedAtOnce(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Reference{"a": "totem/a"}, func(c *Config) {
		c.RetireAfter = time.Hour // long enough that only the release can wipe it
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	v.Zero()
	if b := v.Bytes(); len(b) != 0 && !allZero(b) {
		t.Fatalf("value still readable as %q after the last holder released it", b)
	}
}

func TestZeroIsIdempotent(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	s, err := startWith(t, dir, provider, map[string]Reference{"a": "totem/a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Resolve(context.Background(), "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		v.Zero()
	}
	// The value is still current, so it is still served; Zero on one handle
	// does not take the secret away from the issuer.
	v2, err := s.Resolve(context.Background(), "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	if string(v2.Bytes()) != "value" {
		t.Fatalf("value after another handle was zeroed = %q", v2.Bytes())
	}
	v2.Zero()
}

func TestCloseZeroesEveryValue(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"a": "totem/a"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	v, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if b := v.Bytes(); len(b) != 0 && !allZero(b) {
		t.Fatalf("value still readable as %q after Close", b)
	}
	if _, err := s.Resolve(ctx, "totem/a"); err == nil {
		t.Fatal("Resolve after Close should fail")
	}
	v.Zero()
}

// A value that cannot be locked into memory is a failure, not a warning: an
// unlocked secret can be paged to disk, and this package exists to stop
// controls that look stronger than they are.
func TestMemoryLockFailureIsFatal(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	restore := setSecretAlloc(func(int) ([]byte, error) {
		return nil, fmt.Errorf("%w: mlock refused by the test", ErrMemoryLock)
	})
	defer restore()

	cfg := testConfig(t, dir, provider, map[string]Reference{"a": "totem/a"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if !errors.Is(err, ErrMemoryLock) {
		t.Fatalf("Start with a failing memory lock = %v, want ErrMemoryLock", err)
	}
}

// Every value the issuer holds comes out of the mmap+mlock allocator. Counting
// through the seam is what makes the lock a real code path rather than a
// comment above one.
func TestEveryValueComesFromTheLockingAllocator(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	var mu sync.Mutex
	allocs := 0
	restore := setSecretAlloc(func(n int) ([]byte, error) {
		mu.Lock()
		allocs++
		mu.Unlock()
		return secretAlloc(n)
	})
	defer restore()

	s, err := startWith(t, dir, provider, map[string]Reference{"a": "totem/a", "b": "totem/b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := allocs
	mu.Unlock()
	if got != 4 {
		t.Fatalf("%d values were allocated, want 4 (two references, resolved at start and again on rotation)", got)
	}
}

func TestSecretAllocRoundTrip(t *testing.T) {
	buf, err := secretAlloc(4096)
	if err != nil {
		t.Fatalf("secretAlloc: %v", err)
	}
	copy(buf, "sk-ant-secret")
	if !strings.HasPrefix(string(buf), "sk-ant-secret") {
		t.Fatal("locked memory did not hold what was written to it")
	}
	secretFree(buf)
}

func TestSecretAllocRefusesZeroSize(t *testing.T) {
	if _, err := secretAlloc(0); err == nil {
		t.Fatal("secretAlloc(0) should fail")
	}
}
