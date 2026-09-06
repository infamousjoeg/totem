package issuer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/infamousjoeg/totem/internal/summon"
)

// These three cover the step-2 gate's item 5, provider ownership refusals,
// from docs/totem-design.md "Secrets": "Hardening: config, provider binary,
// and every directory in its path must be root-owned and not group or world
// writable, checked at start and on every resolve, fatal on failure. Provider
// hash pinned at issuer init, logged on every resolve, re-pinned with
// trust-provider."
//
// internal/summon now has a real, complete implementation (harden.go,
// summoner.go, fileprovider.go, hash.go) -- this is no longer a "does not
// exist yet" gap. What blocks these three from being driven for real FROM
// THIS PACKAGE is architectural, and worth stating precisely rather than
// papered over as "not implemented":
//
// Every exported entry point that would let a test construct a passing
// Summoner -- summon.New, and summon.TrustProvider -- hardcodes the trusted
// owner to root (rootUID in owner_unix.go), with no exported parameter, flag,
// or config key to change it. The ONLY seam that accepts a different trusted
// uid is internal/summon's own unexported newForTest, in its own
// export_test.go, reachable only from that package's own test files. Proven
// empirically, not assumed: constructing a real summon.Summoner from this
// package and calling Start (even for the built-in FILE provider, which
// checks its own directory against the current euid) fails at the very first
// hardening check -- checkTree on Config.Path itself, which always checks
// against the hardcoded root uid regardless of which provider is configured:
//
//	summon: provider path is not root-owned or is group/world writable:
//	/var/.../T/... is owned by uid 501, which is not root
//
// That means test/issuer cannot even isolate one of these three checks from
// the others: the outer Config.Path check refuses first, every time, before
// a non-root-owned provider directory, a world-readable file, or a hash
// mismatch is ever reached. Running this suite as root would let each
// individual check be exercised, but "a test that has to run as root ... is
// a test that never runs" is internal/summon's own stated reason for why
// newForTest exists at all (export_test.go) -- the same argument applies
// here, one level up.
//
// The practical consequence: these three refusals are real and are already
// covered for real, just not by this package -- internal/summon's own test
// suite (harden_test.go, pin_test.go, reference_test.go, fifo_unix_test.go)
// uses newForTest to exercise exactly the accept/refuse pairs named below.
// What remains open is whether an issuer-level integration test for this is
// wanted at all given that constraint, or whether coverage living entirely in
// internal/summon's own suite is accepted -- flagged to the lead rather than
// guessed at.
func TestProviderRefusesNonRootOwnedProviderDirectory(t *testing.T) {
	t.Skip("not drivable from this package: summon.New hardcodes the trusted provider-chain owner to " +
		"root with no exported override (see this file's package comment for the empirical proof and " +
		"the architectural reason). internal/summon's own test suite already covers this pair " +
		"(root-owned accepted, non-root-owned refused) via its unexported newForTest. Flagged to the " +
		"lead: whether this needs a production-safe seam (e.g. an exported WithTrustedUID test option " +
		"gated to build with a test tag) so an issuer-level integration test can exercise it too, or " +
		"whether internal/summon's own coverage is accepted as sufficient.")
}

func TestProviderRefusesAWorldReadableFileProvider(t *testing.T) {
	t.Skip("not drivable from this package: even the built-in file provider's own directory check uses " +
		"the current euid and would accept a directory this test owns, but Start's FIRST hardening " +
		"check (Config.Path, the issuer config file) is hardcoded to require root ownership regardless " +
		"of which provider is configured, so no Summoner built from this package ever gets far enough " +
		"to reach the file-provider-specific permission check. Verified empirically (see this file's " +
		"package comment). internal/summon's own test suite covers the world-readable-file refusal " +
		"directly, unblocked by this outer check because it runs inside the package.")
}

func TestProviderRefusesAHashThatNoLongerMatchesItsPin(t *testing.T) {
	t.Skip("not drivable from this package, for the same reason as the other two in this file: the " +
		"outer Config.Path ownership check refuses before a Summoner ever reaches verifyPinLocked. " +
		"Also worth noting for whoever revisits this: verifyPinLocked is skipped entirely for the " +
		"built-in file provider (it only applies to an external Provider.Path), so even a hypothetical " +
		"root-owned config would still need an external provider binary, also root-owned, to reach this " +
		"check at all. internal/summon's own test suite (pin_test.go) covers the hash-mismatch refusal " +
		"directly.")
}

// probeProviderPathAlwaysRefusedFromHere is not a test; it exists so the claim
// in this file's package comment ("verified empirically, not assumed") has a
// place to be re-verified if internal/summon's hardening ever changes shape,
// without anyone having to reconstruct the probe from scratch. It is not
// registered as a *_test.go entry point on purpose -- go vet would flag an
// unused function, so it is called once, from a real test, as a live
// assertion that the documented constraint still holds.
func probeProviderPathAlwaysRefusedFromHere(t *testing.T, dir string) error {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("provider: file\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	s, err := summon.New(summon.Config{
		Path: cfgPath,
		File: summon.FileProvider{Dir: dir},
		Refs: map[string]summon.Reference{"secret": "secret"},
	})
	if err != nil {
		t.Fatalf("summon.New: %v", err)
	}
	return s.Start(context.Background())
}

// TestProviderHardeningIsUnreachableWithoutRootFromThisPackage pins the claim
// the three skips above make, so it fails loudly (rather than the skips
// silently going stale) if internal/summon ever adds an exported way to run
// with a non-root trusted owner: today, Start must fail with
// ErrProviderUnsafe purely because this test process is not root, before any
// reference is ever resolved.
func TestProviderHardeningIsUnreachableWithoutRootFromThisPackage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test process is running as root, so the constraint this file documents does not " +
			"hold here; the three skips above should be revisited under this environment.")
	}
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("s3cr3t-value"), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	err := probeProviderPathAlwaysRefusedFromHere(t, dir)
	if err == nil {
		t.Fatal("Start succeeded from a non-root test process; the documented constraint no longer " +
			"holds, and the three skips in this file should be turned into real tests")
	}
	if !errors.Is(err, summon.ErrProviderUnsafe) {
		t.Fatalf("Start failed with %v, want it to fail specifically with ErrProviderUnsafe (the outer "+
			"Config.Path ownership check); a different failure mode would mean this file's reasoning "+
			"about WHERE it fails is no longer accurate even if the fact that it fails still holds", err)
	}
	t.Logf("confirmed: %v", err)
}
