package issuer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/infamousjoeg/totem/internal/summon"
)

// TestSealedReferenceSurvivesRotationOnBothIntervalAndSIGHUPPaths would cover
// the control that exists so replacing a value that seals material at rest
// (the CA passphrase, the store's data key) never bricks the issuer at its
// next restart: docs/totem-design-decisions.md's rotation rule, implemented
// as summon.RotationSealsDataAtRest / summon.Sealing. A sealed reference must
// be resolved and COMPARED on every rotation cycle -- interval and SIGHUP
// alike -- and never REPLACED; see checkSealed's doc comment in
// internal/summon/summoner.go.
//
// It cannot be driven from this package, for the identical reason
// TestProviderHardeningIsUnreachableWithoutRootFromThisPackage documents and
// TestProviderRefusesNonRootOwnedProviderDirectory and its two siblings are
// skipped for: both the interval and the SIGHUP rotation paths live entirely
// inside (*Summoner).Rotate, which Rotate itself refuses to run unless
// Start already succeeded ("summon: not running"), and Start's very first
// hardening check -- checkTree on Config.Path, hardcoded to root regardless
// of what is configured -- refuses before a single reference, sealed or not,
// is ever resolved. There is no seam that lets a Summoner built from this
// package reach Start, let alone Rotate or the SIGHUP handler behind it, and
// per the lead's ruling on the identical question for the other three
// refusals, none will be added. TestSealedSecretRotationIsUnreachableWithoutRootFromThisPackage
// pins that this is still true, the same way
// TestProviderHardeningIsUnreachableWithoutRootFromThisPackage does for the
// general case, so this skip fails loudly rather than going stale if that
// ever changes.
//
// Coverage for both paths belongs to internal/summon's own test suite, which
// can reach Start via its unexported newForTest. Flagged to the lead as
// requested: the SIGHUP half was reported failing there at the time of this
// writing, which this package cannot independently re-verify or contribute a
// second observation of, for the reason above.
func TestSealedReferenceSurvivesRotationOnBothIntervalAndSIGHUPPaths(t *testing.T) {
	t.Skip("not drivable from this package, by the same architectural constraint as the three " +
		"provider-ownership refusals in secrets_test.go: (*Summoner).Rotate refuses to run unless " +
		"Start already succeeded, and Start's Config.Path hardening check is hardcoded to require root " +
		"ownership, so no Summoner built from this package can reach either the interval or the SIGHUP " +
		"rotation path at all (see TestSealedSecretRotationIsUnreachableWithoutRootFromThisPackage for " +
		"the empirical proof). Coverage for a sealed reference surviving both rotation paths lives, for " +
		"real, in internal/summon's own test suite via its unexported newForTest -- which is where the " +
		"SIGHUP half was reported failing.")
}

// TestSealedSecretRotationIsUnreachableWithoutRootFromThisPackage extends
// TestProviderHardeningIsUnreachableWithoutRootFromThisPackage's pin to the
// rotation feature specifically: it is not enough that SOME Summoner is
// unreachable from here, the skip above is claiming that the SEALED-SECRET
// ROTATION PATH specifically is unreachable, and this proves that claim on a
// Config that actually declares a sealed reference rather than an arbitrary
// one, so a future change that narrows the Config.Path check without
// touching sealing specifically would still be caught here.
func TestSealedSecretRotationIsUnreachableWithoutRootFromThisPackage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test process is running as root, so the constraint this test pins does not hold " +
			"here; TestSealedReferenceSurvivesRotationOnBothIntervalAndSIGHUPPaths should be revisited " +
			"under this environment.")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("provider: file\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	secretPath := filepath.Join(dir, "ca_passphrase")
	if err := os.WriteFile(secretPath, []byte("a-passphrase-only-summon-knows"), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	s, err := summon.New(summon.Config{
		Path: cfgPath,
		File: summon.FileProvider{Dir: dir},
		Refs: map[string]summon.Secret{"ca_passphrase": summon.Sealing("ca_passphrase")},
	})
	if err != nil {
		t.Fatalf("summon.New: %v", err)
	}

	err = s.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded from a non-root test process; the constraint this test pins no longer " +
			"holds, and TestSealedReferenceSurvivesRotationOnBothIntervalAndSIGHUPPaths should be turned " +
			"into a real test")
	}
	if !errors.Is(err, summon.ErrProviderUnsafe) {
		t.Fatalf("Start failed with %v, want it to fail specifically with ErrProviderUnsafe before ever "+
			"resolving the sealed reference", err)
	}
	t.Logf("confirmed: a Config declaring a sealed reference is refused at the same outer check, before "+
		"rotation logic is ever reached: %v", err)
}

// TestSealedSecretDriftDetectionAndResealCompleted covers the other two
// pieces of the same control: (*Summoner).Drifted, which is how an operator
// sees that a sealed secret's provider value no longer matches what the
// issuer is running on, and ResealCompleted, which adopts a changed sealed
// value after a manual re-seal (`totem issuer reseal-ca`). Both are
// unreachable from this package for the same reason as the rotation paths:
// Drifted only ever reports something because checkSealed populated it
// inside Rotate, which needs Start to have succeeded, and ResealCompleted
// refuses outright unless Start already succeeded ("summon: not running").
//
// A call to Drifted() on a Summoner that never started would return an empty
// slice, but asserting that would be testing "an unstarted Summoner has no
// drift," which is trivially true of anything and not a test of drift
// detection at all -- precisely the "testing something adjacent and calling
// it covered" trap this suite exists to avoid. So this stays a skip rather
// than a hollow assertion.
func TestSealedSecretDriftDetectionAndResealCompleted(t *testing.T) {
	t.Skip("not drivable from this package, for the same reason as the rotation paths in this file: " +
		"Drifted can only ever report something real once checkSealed has populated it inside Rotate, " +
		"and ResealCompleted refuses outright unless Start already succeeded. Both are downstream of " +
		"the same root-ownership gate TestSealedSecretRotationIsUnreachableWithoutRootFromThisPackage " +
		"already pins. Coverage lives in internal/summon's own test suite.")
}
