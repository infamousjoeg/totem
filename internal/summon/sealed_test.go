package summon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// valueProvider is a fake whose answer for each reference lives in a file
// beside it, so a test can change what the provider RETURNS without changing
// the provider BINARY. That distinction is the whole subject here: a value
// that drifts is not a provider that was swapped, and the pin must stay valid
// while the value underneath it changes.
func valueProvider(t *testing.T, dir string) (provider, values, calls string) {
	t.Helper()
	values = filepath.Join(dir, "values")
	calls = filepath.Join(dir, "calls")
	if err := os.MkdirAll(values, 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`printf '%%s\n' "$1" >> %[2]q
if [ ! -f %[1]q/"$1" ]; then echo 'no such variable' >&2; exit 1; fi
printf '%%s' "$(cat %[1]q/"$1")"
`, values, calls)
	return providerScript(t, dir, "provider", body), values, calls
}

func setValue(t *testing.T, values string, ref Reference, v string) {
	t.Helper()
	p := filepath.Join(values, filepath.FromSlash(string(ref)))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
}

func dropValue(t *testing.T, values string, ref Reference) {
	t.Helper()
	if err := os.Remove(filepath.Join(values, filepath.FromSlash(string(ref)))); err != nil {
		t.Fatal(err)
	}
}

// inUse reports the value the issuer is actually serving.
func inUse(t *testing.T, s *Summoner, ref Reference) string {
	t.Helper()
	v, err := s.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolve %s: %v", ref, err)
	}
	defer v.Zero()
	return string(v.Bytes())
}

// sealedSummoner starts a Summoner with one sealed reference and one ordinary
// one, which is the shape the issuer actually has.
func sealedSummoner(t *testing.T, tune func(*Config)) (*Summoner, string, string, *logBuffer) {
	t.Helper()
	dir := sandbox(t)
	provider, values, calls := valueProvider(t, dir)
	setValue(t, values, "totem/ca-passphrase", "old-passphrase")
	setValue(t, values, "totem/anthropic", "sk-ant-1")

	cfg := testConfig(t, dir, provider, map[string]Secret{
		"ca_passphrase":     Sealing("totem/ca-passphrase"),
		"anthropic_api_key": Rotating("totem/anthropic"),
	})
	buf := &logBuffer{}
	cfg.Logger = buf.logger()
	cfg.RotateEvery = time.Hour // rotations in these tests are explicit
	if tune != nil {
		tune(&cfg)
	}
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, values, calls, buf
}

// The ruling: a value that seals material at rest is never replaced by a
// rotation, however many times the loop runs.
func TestSealedReferenceIsNeverReplacedByRotation(t *testing.T) {
	s, values, _, _ := sealedSummoner(t, nil)
	ctx := context.Background()

	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	setValue(t, values, "totem/anthropic", "sk-ant-2")
	for i := 0; i < 3; i++ {
		if err := s.Rotate(ctx); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("the sealed value is now %q: rotation replaced a value it cannot re-seal, and this issuer will not restart", got)
	}
	// The reference beside it is a credential and does rotate, so the
	// exclusion is per-reference and not a rotation loop that stopped working.
	if got := inUse(t, s, "totem/anthropic"); got != "sk-ant-2" {
		t.Fatalf("the rotating value is %q, want sk-ant-2", got)
	}
}

// Excluded from replacement is not excluded from attention: the cycle still
// asks the provider what the value is now.
func TestSealedReferenceIsStillCheckedOnEveryCycle(t *testing.T) {
	s, _, calls, _ := sealedSummoner(t, nil)
	ctx := context.Background()
	before := callCount(t, calls)
	for i := 0; i < 3; i++ {
		if err := s.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Three cycles, two references, one provider call each: the sealed one is
	// probed exactly as often as the rotating one is replaced.
	if got := callCount(t, calls) - before; got != 6 {
		t.Fatalf("the provider ran %d times over 3 cycles, want 6: a sealed reference that is never checked cannot raise the alarm", got)
	}
}

// The alarm: the provider's value changed, the issuer keeps serving what its
// files are sealed under, and it says so in terms an operator can act on.
func TestSealedDriftIsDetectedAndShouted(t *testing.T) {
	s, values, _, buf := sealedSummoner(t, nil)
	ctx := context.Background()

	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("value in use = %q, want the old one it can still re-seal with", got)
	}
	if got := s.Drifted(); len(got) != 1 || got[0] != "ca_passphrase" {
		t.Fatalf("Drifted() = %v, want [ca_passphrase]", got)
	}
	out := buf.String()
	for _, want := range []string{"SEALED SECRET CHANGED", "WILL NOT RESTART", "ca_passphrase", "totem/ca-passphrase", "reseal-ca"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the alarm must contain %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "level=ERROR") {
		t.Fatalf("the alarm must be logged at ERROR:\n%s", out)
	}
}

// The alarm carries neither value. It is a warning about a secret, not a place
// to read one.
func TestSealedDriftAlarmCarriesNoValue(t *testing.T) {
	s, values, _, buf := sealedSummoner(t, nil)
	ctx := context.Background()
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	inUse(t, s, "totem/ca-passphrase")
	out := buf.String()
	for _, secret := range []string{"old-passphrase", "new-passphrase", "sk-ant-1"} {
		if strings.Contains(out, secret) {
			t.Fatalf("the log contains the value %q:\n%s", secret, out)
		}
	}
}

// "Keep logging that the issuer will not restart until it is re-sealed." Once
// is a line in a log nobody was reading at the time.
func TestSealedDriftKeepsShoutingOnEveryCycleAndEveryResolve(t *testing.T) {
	s, values, _, buf := sealedSummoner(t, nil)
	ctx := context.Background()
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")

	for i := 0; i < 3; i++ {
		if err := s.Rotate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "SEALED SECRET CHANGED"); n != 3 {
		t.Fatalf("the alarm was raised %d times over 3 cycles, want 3", n)
	}

	before := strings.Count(buf.String(), "SEALED SECRET CHANGED")
	for i := 0; i < 4; i++ {
		inUse(t, s, "totem/ca-passphrase")
	}
	if n := strings.Count(buf.String(), "SEALED SECRET CHANGED") - before; n != 4 {
		t.Fatalf("the alarm was raised %d times over 4 resolves, want 4", n)
	}
	// A resolve of an unaffected reference stays quiet: the alarm is about one
	// secret, not a mode the whole issuer is in.
	quiet := strings.Count(buf.String(), "SEALED SECRET CHANGED")
	inUse(t, s, "totem/anthropic")
	if n := strings.Count(buf.String(), "SEALED SECRET CHANGED"); n != quiet {
		t.Fatal("resolving an unrelated reference raised the sealed-secret alarm")
	}
}

// A provider that goes back to the value in use is no longer drift. The alarm
// tracks the state of the world rather than latching on the first surprise.
func TestSealedDriftClearsIfTheValueComesBack(t *testing.T) {
	s, values, _, _ := sealedSummoner(t, nil)
	ctx := context.Background()
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.Drifted()) != 1 {
		t.Fatal("expected drift")
	}
	setValue(t, values, "totem/ca-passphrase", "old-passphrase")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.Drifted(); len(got) != 0 {
		t.Fatalf("Drifted() = %v after the value came back, want none", got)
	}
}

// Not knowing whether the value changed is a different thing from knowing that
// it did: a probe that cannot reach the provider warns, and does not raise the
// alarm, poison the issuer, or touch the value in use.
func TestSealedProbeFailureIsAWarningNotAnAlarm(t *testing.T) {
	s, values, _, buf := sealedSummoner(t, nil)
	ctx := context.Background()
	dropValue(t, values, "totem/ca-passphrase")

	if err := s.Rotate(ctx); err != nil {
		t.Fatalf("a probe failure must not fail the rotation: %v", err)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("a probe failure must not be fatal: %v", err)
	}
	if got := s.Drifted(); len(got) != 0 {
		t.Fatalf("Drifted() = %v, want none: an unreachable provider is not evidence the value changed", got)
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("value in use = %q, want it untouched", got)
	}
	out := buf.String()
	if !strings.Contains(out, "could not check a sealed secret") {
		t.Fatalf("the probe failure must be visible:\n%s", out)
	}
	if strings.Contains(out, "SEALED SECRET CHANGED") {
		t.Fatalf("a probe failure must not raise the alarm:\n%s", out)
	}
}

// SIGHUP is a rotation trigger too, and it must not become the back door that
// replaces a sealed value.
func TestSIGHUPDoesNotReplaceASealedValue(t *testing.T) {
	s, values, _, _ := sealedSummoner(t, nil)
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	setValue(t, values, "totem/anthropic", "sk-ant-2")

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for inUse(t, s, "totem/anthropic") != "sk-ant-2" {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP never rotated the credential")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("SIGHUP replaced the sealed value with %q", got)
	}
	// A cycle walks its references in no particular order, so seeing the
	// credential rotate does not mean the sealed one has been probed yet.
	// Wait for the alarm rather than assuming the order.
	deadline = time.Now().Add(5 * time.Second)
	for len(s.Drifted()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Drifted() is still empty: the HUP cycle never probed the sealed secret")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("SIGHUP replaced the sealed value with %q after the probe", got)
	}
}

// The interval, not only an explicit call, honours the exclusion.
func TestIntervalRotationHonoursTheExclusion(t *testing.T) {
	s, values, _, _ := sealedSummoner(t, func(c *Config) {
		c.RotateEvery = 40 * time.Millisecond
		c.RetireAfter = 10 * time.Millisecond
	})
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	setValue(t, values, "totem/anthropic", "sk-ant-2")

	deadline := time.Now().Add(5 * time.Second)
	for inUse(t, s, "totem/anthropic") != "sk-ant-2" {
		if time.Now().After(deadline) {
			t.Fatal("the interval never rotated the credential")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(120 * time.Millisecond) // several more cycles
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("the interval replaced the sealed value with %q", got)
	}
}

// The second half of rotating a sealed secret: the material has been re-sealed
// out of band, and the issuer is told so.
func TestResealCompletedAdoptsTheNewValueAndClearsTheAlarm(t *testing.T) {
	s, values, _, buf := sealedSummoner(t, nil)
	ctx := context.Background()
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.Drifted()) != 1 {
		t.Fatal("expected the alarm before the reseal")
	}

	if err := s.ResealCompleted(ctx, "ca_passphrase"); err != nil {
		t.Fatalf("ResealCompleted: %v", err)
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "new-passphrase" {
		t.Fatalf("value in use = %q after a confirmed reseal, want the new one", got)
	}
	if got := s.Drifted(); len(got) != 0 {
		t.Fatalf("Drifted() = %v after a confirmed reseal, want none", got)
	}
	if !strings.Contains(buf.String(), "reseal confirmed") {
		t.Fatalf("the adoption must be in the record:\n%s", buf.String())
	}
	// And a later cycle stays quiet, because there is nothing left to shout
	// about.
	before := strings.Count(buf.String(), "SEALED SECRET CHANGED")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "SEALED SECRET CHANGED"); n != before {
		t.Fatal("the alarm came back after the reseal was confirmed")
	}
}

func TestResealCompletedRefusesWhatItIsNotFor(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)
	ctx := context.Background()

	err := s.ResealCompleted(ctx, "anthropic_api_key")
	if err == nil || !strings.Contains(err.Error(), "needs no reseal") {
		t.Fatalf("ResealCompleted on a rotating credential = %v, want a refusal", err)
	}
	if err := s.ResealCompleted(ctx, "not_configured"); !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("ResealCompleted on an unknown name = %v, want ErrNoSuchReference", err)
	}
}

// Nothing adopts a changed sealed value on its own. If it did, the exclusion
// would be theatre: the running process would be fine and the next start
// broken, which is exactly the failure this whole ruling is about.
func TestNothingAdoptsASealedValueWithoutBeingTold(t *testing.T) {
	s, values, _, _ := sealedSummoner(t, func(c *Config) {
		c.RotateEvery = 30 * time.Millisecond
		c.RetireAfter = 10 * time.Millisecond
	})
	setValue(t, values, "totem/ca-passphrase", "new-passphrase")
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Drifted()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no cycle ever noticed the sealed value changed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond) // several more cycles, every one of them a chance to adopt it
	if got := inUse(t, s, "totem/ca-passphrase"); got != "old-passphrase" {
		t.Fatalf("the sealed value became %q on its own", got)
	}
	if got := s.Drifted(); len(got) != 1 {
		t.Fatalf("Drifted() = %v, want the alarm still standing", got)
	}
}

// A secret that does not declare its rotation shape is refused at config load,
// naming the secret and both choices. This is the part that makes the next
// secret with this property a design question rather than an incident.
func TestConfigRefusesAnUndeclaredRotation(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, nil)
	cfg.Refs = map[string]Secret{
		"anthropic_api_key": Rotating("totem/anthropic"),
		"ca_passphrase":     {Ref: "totem/ca-passphrase"}, // forgot to say
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("a secret with no declared rotation shape must be refused at load")
	}
	for _, want := range []string{"ca_passphrase", "does not declare a rotation shape", "summon.Rotating", "summon.Sealing"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "anthropic_api_key") {
		t.Fatalf("the error should name the secret that is wrong, not the one that is right: %v", err)
	}
}

func TestRotationStringNamesEachShape(t *testing.T) {
	cases := map[Rotation]string{
		RotationPull:            "pull",
		RotationSealsDataAtRest: "seals-data-at-rest",
		// The zero value and an unrecognised value are different facts: one is
		// a secret nobody declared a shape for, the other is a shape this
		// build does not know about. An error that renders them identically
		// sends the reader to the wrong place.
		RotationUnset: "undeclared",
		Rotation(3):   "unknown(3)",
		Rotation(99):  "unknown(99)",
		Rotation(-1):  "unknown(-1)",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("Rotation(%d).String() = %q, want %q", r, got, want)
		}
	}
}

// ca's requirement: the exclusion is keyed on the reference's own declaration,
// so no config edit can silently un-seal it. These two tests are the pair that
// pins it, and the second is the load-bearing one.
//
// First: a sealed secret configured under an unfamiliar logical name and an
// unfamiliar reference is still excluded. The declaration travels with the
// entry; there is no position, index, or ordering anywhere in this package
// that could be disturbed by reformatting a config.
func TestSealednessTravelsWithTheDeclarationNotTheName(t *testing.T) {
	dir := sandbox(t)
	provider, values, _ := valueProvider(t, dir)
	setValue(t, values, "vault/some-other-thing", "old-sealing-key")
	cfg := testConfig(t, dir, provider, map[string]Secret{
		"a_name_this_package_has_never_heard_of": Sealing("vault/some-other-thing"),
	})
	buf := &logBuffer{}
	cfg.Logger = buf.logger()
	cfg.RotateEvery = time.Hour
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	setValue(t, values, "vault/some-other-thing", "new-sealing-key")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := inUse(t, s, "vault/some-other-thing"); got != "old-sealing-key" {
		t.Fatalf("value in use = %q: the exclusion did not follow the declaration", got)
	}
	if got := s.Drifted(); len(got) != 1 || got[0] != "a_name_this_package_has_never_heard_of" {
		t.Fatalf("Drifted() = %v, want the alarm under the operator's own name for it", got)
	}
	if !strings.Contains(buf.String(), "SEALED SECRET CHANGED") {
		t.Fatal("no alarm for a sealed secret this package could not possibly have special-cased")
	}
}

// Second, and this is the one that proves there is no hidden special case: a
// secret named exactly "ca_passphrase", pointed at exactly "totem/ca-passphrase",
// but declared Rotating, DOES rotate.
//
// That is the correct behaviour even though it is the dangerous one. If this
// package refused to rotate it because of its name, the declaration would be
// decoration and the real rule would be a string literal buried in here, where
// the next secret with this property gets no protection at all. The protection
// lives in the declaration, and issuerd is what declares it.
func TestNameAloneDoesNotSealAnything(t *testing.T) {
	dir := sandbox(t)
	provider, values, _ := valueProvider(t, dir)
	setValue(t, values, "totem/ca-passphrase", "v1")
	cfg := testConfig(t, dir, provider, map[string]Secret{
		"ca_passphrase": Rotating("totem/ca-passphrase"),
	})
	cfg.RotateEvery = time.Hour
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	setValue(t, values, "totem/ca-passphrase", "v2")
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := inUse(t, s, "totem/ca-passphrase"); got != "v2" {
		t.Fatalf("value in use = %q, want v2: this package must obey the declaration, not the name", got)
	}
	if got := s.Drifted(); len(got) != 0 {
		t.Fatalf("Drifted() = %v: a reference declared Rotating has nothing to drift from", got)
	}
}

// The rule enforced by its victim: a holder can ask, before it opens anything,
// whether the reference it is about to seal with is declared for that.
func TestRotationOfReportsTheDeclaredShape(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)
	cases := []struct {
		ref  Reference
		want Rotation
	}{
		{"totem/ca-passphrase", RotationSealsDataAtRest},
		{"totem/anthropic", RotationPull},
	}
	for _, tc := range cases {
		got, err := s.RotationOf(tc.ref)
		if err != nil {
			t.Fatalf("RotationOf(%q): %v", tc.ref, err)
		}
		if got != tc.want {
			t.Fatalf("RotationOf(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

// The lead's constraint: an unknown reference must be distinguishable from a
// pull-rotated one, and must not read as the safe answer either.
func TestRotationOfDistinguishesUnknownFromRotating(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)

	got, err := s.RotationOf("totem/never-configured")
	if !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("RotationOf of an unknown reference = %v, want ErrNoSuchReference", err)
	}
	if errors.Is(err, ErrNotSealing) {
		t.Fatal("an unknown reference must not report as a declared-but-wrong shape; those want different messages")
	}
	if got == RotationPull {
		t.Fatal("an unknown reference read back as RotationPull, which is a declared shape a caller could act on")
	}
	if got != RotationUnset {
		t.Fatalf("RotationOf of an unknown reference = %v, want RotationUnset", got)
	}
	// And the shape a caller would compare against still refuses, so even a
	// caller that drops the error fails closed.
	if got == RotationSealsDataAtRest {
		t.Fatal("an unknown reference read back as sealed: a dropped error would have opened the CA")
	}
}

func TestRequireSealingAcceptsOnlyASealedDeclaration(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)

	if err := RequireSealing(s, "totem/ca-passphrase"); err != nil {
		t.Fatalf("RequireSealing on the sealed reference = %v, want nil", err)
	}

	err := RequireSealing(s, "totem/anthropic")
	if !errors.Is(err, ErrNotSealing) {
		t.Fatalf("RequireSealing on a pull-rotated reference = %v, want ErrNotSealing", err)
	}
	for _, want := range []string{"totem/anthropic", "pull", "summon.Sealing", "unreadable at the next start"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must contain %q so it says what to change: %v", want, err)
		}
	}

	if err := RequireSealing(s, "totem/never-configured"); !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("RequireSealing on an unknown reference = %v, want ErrNoSuchReference", err)
	}
}

// It reads the declaration, not a value: usable before Start, and the provider
// is never run for it. A gate that had to resolve a secret first would be a
// gate the CA could only pass after doing the thing it is gating.
func TestRequireSealingWorksBeforeStartAndNeverRunsTheProvider(t *testing.T) {
	dir := sandbox(t)
	provider, calls := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Secret{
		"ca_passphrase": Sealing("totem/ca-passphrase"),
		"anthropic":     Rotating("totem/anthropic"),
	})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately not started.
	if err := RequireSealing(s, "totem/ca-passphrase"); err != nil {
		t.Fatalf("RequireSealing before Start = %v, want nil", err)
	}
	if err := RequireSealing(s, "totem/anthropic"); !errors.Is(err, ErrNotSealing) {
		t.Fatalf("RequireSealing before Start on a rotating reference = %v, want ErrNotSealing", err)
	}
	if n := callCount(t, calls); n != 0 {
		t.Fatalf("the provider ran %d times for a question about the config", n)
	}
}

// The defensive branch. New cannot produce an undeclared shape, so this
// reaches past it to prove the answer is a refusal rather than a nil error
// beside a zero value a caller would act on.
func TestRequireSealingRefusesAnUndeclaredShape(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)
	s.byName["ca_passphrase"] = Secret{Ref: "totem/ca-passphrase"} // Rotation left unset

	got, err := s.RotationOf("totem/ca-passphrase")
	if err == nil {
		t.Fatal("an undeclared shape returned a nil error, which a caller would read as an answer")
	}
	// A caller has two error cases, not three: a shape it can act on, or a
	// shape it cannot determine. Configured-but-undeclared is the second.
	if !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("RotationOf on an undeclared shape = %v, want it to join the cannot-determine case (ErrNoSuchReference)", err)
	}
	if got != RotationUnset {
		t.Fatalf("RotationOf = %v, want RotationUnset alongside the error", got)
	}
	if err := RequireSealing(s, "totem/ca-passphrase"); err == nil {
		t.Fatal("RequireSealing accepted an undeclared shape")
	}
}

// One sentinel for the caller, two sentences for the human. The two ways
// RotationOf can fail to give an answer want the same handling in code and
// very different handling by a person: an unconfigured reference is usually a
// typo in a config key, while a configured-but-undeclared one cannot happen
// through New and therefore means something built a resolver around it.
func TestTheTwoCannotDetermineCasesReadDifferently(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)

	_, unknownErr := s.RotationOf("totem/never-configured")
	if !errors.Is(unknownErr, ErrNoSuchReference) {
		t.Fatalf("unknown reference = %v, want ErrNoSuchReference", unknownErr)
	}

	s.byName["ca_passphrase"] = Secret{Ref: "totem/ca-passphrase"} // reached past New
	_, undeclaredErr := s.RotationOf("totem/ca-passphrase")
	if !errors.Is(undeclaredErr, ErrNoSuchReference) {
		t.Fatalf("undeclared shape = %v, want the same sentinel so a caller has two cases, not three", undeclaredErr)
	}

	// Same sentinel, so a caller cannot accidentally treat one as safe.
	// Different text, so a person is sent to the right place.
	if unknownErr.Error() == undeclaredErr.Error() {
		t.Fatal("the two cannot-determine cases produce identical text; a person debugging one would be sent to the wrong place")
	}
	if !strings.Contains(unknownErr.Error(), "is not configured") {
		t.Fatalf("the unconfigured case must say so plainly: %v", unknownErr)
	}
	for _, want := range []string{"has no declared rotation shape", "summon.New refuses that at config load"} {
		if !strings.Contains(undeclaredErr.Error(), want) {
			t.Fatalf("the undeclared case must point at the load path, not the config file: %v", undeclaredErr)
		}
	}
	if strings.Contains(unknownErr.Error(), "summon.New refuses") {
		t.Fatalf("a typo in a config key must not be reported as a load-path violation: %v", unknownErr)
	}
}

// legalRotations is the closed set of declarable rotation shapes. It exists so
// that adding a shape to this package is a decision rather than an accident.
//
// internal/ca made the case for this and it is worth stating where the shapes
// live rather than only where they are consumed: every at-rest consumer gates
// with `rot != RotationSealsDataAtRest`, chosen over `rot == RotationPull`
// because it stays correct when a shape is added. That asymmetry protects the
// consumers, but the shape itself would arrive HERE, with nothing to prompt
// whoever adds it to think about what a CA or a store should do with it.
//
// So: if you are adding a shape and this test is failing, that is the prompt.
// Decide what every holder of material at rest does with the new shape before
// you add it to the list, and check that each of them still refuses by
// default rather than by luck.
//
// Concretely, two gates outside this test have an opinion about which shapes
// may seal material at rest, and both currently open for exactly one:
// summon.RequireSealing here, and internal/ca's own gate on the CA passphrase.
// Both refuse anything that is not RotationSealsDataAtRest, which is correct
// and is what makes a carelessly added shape fail closed.
//
// The case that needs a human is a new shape that SHOULD be allowed to seal.
// Adding it here without updating those gates does not produce a quiet bug, it
// produces every issuer failing to start after a summon upgrade, with an error
// blaming the operator's declaration rather than the upgrade that caused it.
// If the shape you are adding is safe for material at rest, update those gates
// in the same change.
var legalRotations = []Rotation{RotationPull, RotationSealsDataAtRest}

func TestTheSetOfRotationShapesIsClosed(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")

	// SCAN for what config validation actually accepts rather than probing a
	// few values it probably rejects. Picking arbitrary out-of-set numbers
	// tests nothing: a shape added at the next free value sits in the gap
	// between the ones chosen, and the test passes while the guard it claims
	// to be does not exist. Ask the code what it admits, then compare that
	// with the list.
	accepted := map[Rotation]bool{}
	for i := -8; i < 64; i++ {
		rot := Rotation(i)
		cfg := testConfig(t, dir, provider, map[string]Secret{"s": {Ref: "totem/a", Rotation: rot}})
		if _, err := New(cfg); err == nil {
			accepted[rot] = true
		}
	}

	want := map[Rotation]bool{}
	for _, rot := range legalRotations {
		want[rot] = true
		if !accepted[rot] {
			t.Errorf("config validation refuses the legal shape %v", rot)
		}
	}
	for rot := range accepted {
		if !want[rot] {
			t.Errorf("config validation accepts shape %d (%v), which is not in legalRotations. "+
				"If you are adding a shape, decide what every holder of material at rest does with it "+
				"and add it to the list deliberately. If the new shape is SAFE for material at rest, "+
				"summon.RequireSealing and internal/ca's passphrase gate both refuse it today and must be "+
				"updated in the same change, or every issuer fails to start after this upgrade with an "+
				"error blaming the operator's config rather than the upgrade", rot, rot)
		}
	}
	// RotationUnset is deliberately absent from the list: the zero value is
	// not a shape, it is the absence of one.
	if accepted[RotationUnset] {
		t.Error("config validation accepts RotationUnset; the zero value must never be a legal declaration")
	}
}

// The consumer-side half of the same guard, asserted here so it does not rest
// on every consumer remembering it: the gate opens for exactly one shape, and
// anything else this package could ever return refuses. A shape added
// carelessly fails closed at every holder of material at rest rather than
// being admitted by a comparison that was written the other way round.
func TestOnlySealingOpensTheGateWhateverShapeArrives(t *testing.T) {
	s, _, _, _ := sealedSummoner(t, nil)
	for i := -2; i < 12; i++ {
		rot := Rotation(i)
		s.byName["ca_passphrase"] = Secret{Ref: "totem/ca-passphrase", Rotation: rot}
		err := RequireSealing(s, "totem/ca-passphrase")
		if rot == RotationSealsDataAtRest {
			if err != nil {
				t.Fatalf("the gate refused the one shape it must accept (%v): %v", rot, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("the gate opened for shape %d; only RotationSealsDataAtRest may open it", i)
		}
	}
}
