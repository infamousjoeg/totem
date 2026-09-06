package summon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// waitForValue polls until the current value matches want, so a rotation is
// observed rather than assumed after a sleep.
func waitForValue(t *testing.T, s *Summoner, ref Reference, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last string
	for time.Now().Before(deadline) {
		v, err := s.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("resolve while waiting for %q: %v", want, err)
		}
		last = string(v.Bytes())
		v.Zero()
		if last == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("value is still %q after %s, want %q", last, within, want)
}

// Rotation is pull-based on an interval: no restart, no push from anywhere.
func TestRotationOnTheInterval(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, func(c *Config) {
		c.RotateEvery = 40 * time.Millisecond
		c.RetireAfter = 10 * time.Millisecond
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForValue(t, s, "totem/a", "value-1", time.Second)
	waitForValue(t, s, "totem/a", "value-2", 5*time.Second)
	waitForValue(t, s, "totem/a", "value-3", 5*time.Second)
}

// And on SIGHUP, without a restart.
func TestRotationOnSIGHUP(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, func(c *Config) {
		c.RotateEvery = time.Hour // only a HUP can rotate this one
		c.RetireAfter = 10 * time.Millisecond
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForValue(t, s, "totem/a", "value-1", time.Second)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("sending SIGHUP: %v", err)
	}
	waitForValue(t, s, "totem/a", "value-2", 5*time.Second)
}

// A provider that fails during rotation must not take the working credential
// away: the issuer keeps serving the old value and says so.
func TestRotationFailureKeepsThePreviousValue(t *testing.T) {
	dir := sandbox(t)
	// The provider binary never changes; it just starts failing, which is what
	// a sealed vault or an unreachable secrets backend looks like. That is a
	// different thing from a provider that no longer matches its pin, and it
	// must be handled differently.
	sealed := filepath.Join(dir, "sealed")
	provider := providerScript(t, dir, "provider", fmt.Sprintf(
		"if [ -f %q ]; then echo 'vault is sealed' >&2; exit 1; fi\nprintf 'good-value'\n", sealed))
	var buf logBuffer
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, func(c *Config) {
		c.Logger = buf.logger()
		c.RotateEvery = time.Hour
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	waitForValue(t, s, "totem/a", "good-value", time.Second)

	if err := os.WriteFile(sealed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx); err == nil {
		t.Fatal("Rotate should report the provider failure")
	}
	// The credential the issuer is running on is untouched: a backend outage
	// must not take it away.
	waitForValue(t, s, "totem/a", "good-value", time.Second)
	if err := s.Err(); err != nil {
		t.Fatalf("a provider outage must not be fatal, Err() = %v", err)
	}
	if !strings.Contains(buf.String(), "kept the previous value") {
		t.Fatalf("the failure should be logged plainly:\n%s", buf.String())
	}
}

// Rotation runs the hardening too, and a failure there is fatal rather than
// something to log and carry on from.
func TestRotationRefusesAnUnsafeProvider(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, func(c *Config) {
		c.RotateEvery = time.Hour
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := os.Chmod(provider, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx); err == nil {
		t.Fatal("rotation with a world-writable provider should fail")
	}
	if _, err := s.Resolve(ctx, "totem/a"); err == nil {
		t.Fatal("the Summoner should refuse to serve after a fatal rotation failure")
	}
}

// The two duration statements of the same rule must not drift: the frozen
// contract states the default interval as a string, and this package uses a
// duration.
func TestDefaultRotationIntervalMatchesTheContract(t *testing.T) {
	d, err := time.ParseDuration(DefaultRotationInterval)
	if err != nil {
		t.Fatalf("DefaultRotationInterval %q does not parse: %v", DefaultRotationInterval, err)
	}
	if d != DefaultRotateEvery {
		t.Fatalf("DefaultRotateEvery is %s but the contract says %s", DefaultRotateEvery, d)
	}
	var c Config
	if got := c.rotateEvery(); got != DefaultRotateEvery {
		t.Fatalf("an unset RotateEvery gives %s, want %s", got, DefaultRotateEvery)
	}
}

// "Replacement is atomic, in-flight requests finish on the old value, no
// restart." A rotation that takes seconds must not stop the issuer serving the
// credential it already has.
func TestResolveIsNotBlockedByASlowRotation(t *testing.T) {
	dir := sandbox(t)
	counter := filepath.Join(dir, "counter")
	provider := providerScript(t, dir, "provider", fmt.Sprintf(`n=0
if [ -f %[1]q ]; then n=$(cat %[1]q); fi
n=$((n+1))
printf '%%s' "$n" > %[1]q
if [ "$n" -gt 1 ]; then sleep 2; fi
printf 'value-%%s' "$n"
`, counter))
	s, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, func(c *Config) {
		c.RotateEvery = time.Hour
		c.Timeout = 10 * time.Second
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() { done <- s.Rotate(ctx) }()
	time.Sleep(200 * time.Millisecond) // the rotation is now inside the provider

	start := time.Now()
	v, err := s.Resolve(ctx, "totem/a")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("resolve during rotation: %v", err)
	}
	got := string(v.Bytes())
	v.Zero()
	if got != "value-1" {
		t.Fatalf("value during rotation = %q, want the old value until the swap", got)
	}
	if elapsed > time.Second {
		t.Fatalf("a resolve took %s while a rotation was running: rotation is holding the issuer's secrets hostage", elapsed)
	}
	if err := <-done; err != nil {
		t.Fatalf("rotation: %v", err)
	}
	waitForValue(t, s, "totem/a", "value-2", 2*time.Second)
}
