package ca

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// sealState renders what a failure in these tests actually needs to be
// diagnosed: which sealed files exist and which candidate passphrase opens
// each. It exists because a passphrase failure that only says "got nil, want
// error" tells you the assertion that fired and nothing about the state that
// produced it, and these tests run under a full-tree race run where a single
// unreproducible failure is all the evidence there will ever be.
//
// It uses CanOpen, which is the same question an operator asks when a re-seal
// goes wrong, so a failure here reads the same way an incident does.
func sealState(ctx context.Context, ca *testCA, candidates map[string]string) string {
	op, ok := ca.Authority.(PassphraseOperator)
	if !ok {
		return " (authority is not a PassphraseOperator)"
	}
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(ca.dir, "*"+keySuffix))
	sort.Strings(files)
	fmt.Fprintf(&b, "\n  sealed key files (%d):", len(files))
	for _, f := range files {
		fmt.Fprintf(&b, " %s", filepath.Base(f))
	}
	names := make([]string, 0, len(candidates))
	for n := range candidates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		bad, err := op.CanOpen(ctx, []byte(candidates[n]))
		switch {
		case err != nil:
			fmt.Fprintf(&b, "\n  CanOpen(%s): error: %v", n, err)
		case len(bad) == 0:
			fmt.Fprintf(&b, "\n  CanOpen(%s): opens every file", n)
		default:
			fmt.Fprintf(&b, "\n  CanOpen(%s): does NOT open %v", n, bad)
		}
	}
	fmt.Fprintf(&b, "\n  resolver calls so far: %d", ca.res.callCount())
	return b.String()
}

func (c *testCA) setPassphrase(p string) {
	c.res.mu.Lock()
	defer c.res.mu.Unlock()
	c.res.pass = p
}

// TestPassphraseRotationIsLatentUntilRestart demonstrates the failure this
// whole mechanism exists for, before demonstrating the detection.
//
// Summon rotation is pull-based on an hourly default. When the CA passphrase
// rotates, the running issuer is completely unaffected: its intermediate keys
// are already unsealed in memory, so it keeps minting correct certificates and
// nothing anywhere reports a problem. The brick only lands at the next restart,
// which may be weeks later and will look unrelated. That gap is the point.
func TestPassphraseRotationIsLatentUntilRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	ca.setPassphrase("a completely different passphrase")

	// The running issuer does not notice, and this is not a bug in the issuer.
	if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); err != nil {
		t.Fatalf("a rotated passphrase must not disturb a running issuer: %v", err)
	}
	if _, err := ca.Bundle(ctx); err != nil {
		t.Fatal(err)
	}

	// A restart is where it lands.
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := Open(ctx, Config{
		Dir: ca.dir, Resolver: ca.res, PassphraseRef: "ca_passphrase",
		TrustDomain: testTrustDomain, Now: ca.clk.now,
	})
	if err == nil {
		t.Fatal("the issuer must fail to reopen under a rotated passphrase; if this passes, the seal is not doing anything")
	}
	if !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("reopen failed with %v, want an unseal failure", err)
	}
}

// TestVerifyPassphraseCatchesItWhileTheOldValueIsStillReachable is the
// detection half: it converts a silent brick into a visible alarm at the moment
// of rotation, when the previous value can still be fetched and the fix is
// cheap.
func TestVerifyPassphraseCatchesItWhileTheOldValueIsStillReachable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	op, ok := ca.Authority.(PassphraseOperator)
	if !ok {
		t.Fatal("the authority must implement PassphraseOperator")
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("a freshly initialised CA must verify: %v", err)
	}

	ca.setPassphrase("rotated out from under us")
	err := op.VerifyPassphrase(ctx)
	if !errors.Is(err, ErrPassphraseChanged) {
		t.Fatalf("got %v, want ErrPassphraseChanged", err)
	}
	// The message has to name the files, because a partial re-seal is a real
	// state and "something is wrong" would not tell the operator which.
	for _, want := range []string{rootPrefix, interPrefix} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must name the unopenable files, got %q", err)
		}
	}
}

// TestVerifyPassphraseIgnoresAnOfflineRoot: a root carried off the box is the
// intended posture, not a fault, and there is nothing local to re-seal.
func TestVerifyPassphraseIgnoresAnOfflineRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)

	roots, err := filepath.Glob(filepath.Join(ca.dir, rootPrefix+"*"+keySuffix))
	if err != nil || len(roots) != 1 {
		t.Fatalf("want one root key file, got %v", roots)
	}
	if err := os.Rename(roots[0], filepath.Join(t.TempDir(), "root.key")); err != nil {
		t.Fatal(err)
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("an offline root must not read as a passphrase failure: %v", err)
	}
}

// TestResealRecoversTheCA is the repair half, end to end: rotate the
// passphrase, re-seal with the previous one, and confirm the thing that
// actually matters, which is that a restart now succeeds and the CA still
// works.
func TestResealRecoversTheCA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)
	const oldPass = "a-passphrase-only-summon-knows"

	before, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}

	ca.setPassphrase("the new value the provider now returns")
	if err := op.Reseal(ctx, []byte(oldPass)); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("after re-sealing the CA must verify: %v", err)
	}

	// Idempotent: running it again is not an error and does not need the old
	// value any more.
	if err := op.Reseal(ctx, nil); err != nil {
		t.Fatalf("re-running Reseal must be safe: %v", err)
	}

	// The property that was actually wanted: a restart succeeds.
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, Config{
		Dir: ca.dir, Resolver: ca.res, PassphraseRef: "ca_passphrase",
		TrustDomain: testTrustDomain, Now: ca.clk.now,
	})
	if err != nil {
		t.Fatalf("reopening after a re-seal: %v", err)
	}
	defer reopened.Close()

	bundle, err := reopened.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstBundle(t, before.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("a credential issued before the re-seal stopped verifying: %v", err)
	}
	if _, err := reopened.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); err != nil {
		t.Fatalf("issuing after a re-seal: %v", err)
	}
	// And the root is genuinely re-sealed, not merely skipped: rotation needs
	// the root signer, which has to unseal under the new passphrase.
	sched, err := reopened.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.RotateAfter.Add(time.Hour))
	if _, err := reopened.RotateIntermediate(ctx); err != nil {
		t.Fatalf("rotating after a re-seal must unseal the root under the new passphrase: %v", err)
	}
}

// TestResealWithoutThePreviousPassphraseSaysWhatItCouldNotDo: the intermediates
// can be re-sealed from the keys already in memory, but the root only exists on
// disk. A partial result must be named rather than reported as success.
func TestResealWithoutThePreviousPassphraseSaysWhatItCouldNotDo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)
	const oldPass = "a-passphrase-only-summon-knows"

	ca.setPassphrase("new value")
	err := op.Reseal(ctx, nil)
	if !errors.Is(err, ErrPassphraseChanged) {
		t.Fatalf("got %v, want ErrPassphraseChanged naming the root", err)
	}
	if !strings.Contains(err.Error(), rootPrefix) {
		t.Fatalf("the error must name the root key file, got %q", err)
	}
	// It must fail on the "I could not do this, here is how to finish it" path,
	// not merely on the final confirmation that something is still unopenable.
	// Both are loud, but only one tells the operator what to do next, and a
	// generic "still does not open" at the end of a re-seal reads like the
	// re-seal itself is broken rather than like it needs one more input.
	if !strings.Contains(err.Error(), "re-run reseal with it") {
		t.Fatalf("the error must tell the operator to re-run with the previous passphrase, got %q", err)
	}

	// The intermediates did get re-sealed from memory, so this is a real
	// partial state, and finishing it is just running Reseal again with the
	// previous value.
	if err := op.Reseal(ctx, []byte(oldPass)); err != nil {
		t.Fatalf("completing an interrupted re-seal: %v", err)
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("after completing the re-seal: %v", err)
	}
}

// TestResealRefusesAWrongPreviousPassphrase: it must not report success for a
// file it could not open, because the operator would then believe a restart is
// safe when it is not.
func TestResealRefusesAWrongPreviousPassphrase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)

	ca.setPassphrase("new value")
	err := op.Reseal(ctx, []byte("not the previous passphrase either"))
	if err == nil {
		t.Fatal("re-sealing with a wrong previous passphrase must fail loudly")
	}
	if !strings.Contains(err.Error(), "neither the current nor the previous") {
		t.Fatalf("got %v, want an error naming the file that opens under neither", err)
	}
}

// TestResealRefusesBeforeTheResolverHasAdoptedTheNewValue is the defect issuerd
// found while wiring reseal-ca, and it is the nastiest shape in this mechanism.
//
// summon deliberately keeps SERVING the old value for a Sealing reference while
// it raises a drift alarm. Reseal resolves "the passphrase the resolver returns
// now", so in that window every file opens under what it was just handed, every
// file is skipped, and the previous value the operator typed is never tried at
// all. It returned nil. An operator reading that success would believe a
// restart is safe when nothing whatsoever had been done, which is the same
// class of lie as the silent brick this whole mechanism exists to remove.
//
// Refusing is the only honest answer, because doing nothing and having done the
// work are indistinguishable from outside.
func TestResealRefusesBeforeTheResolverHasAdoptedTheNewValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)
	const oldPass = "a-passphrase-only-summon-knows"

	const newPass = "the value the provider now returns"
	state := func() string {
		return sealState(ctx, ca, map[string]string{"old": oldPass, "new": newPass, "wrong": "a flatly wrong previous passphrase"})
	}

	// The resolver still serves the old value: summon's pre-adoption state.
	if err := op.Reseal(ctx, []byte(oldPass)); !errors.Is(err, ErrPassphraseNotAdopted) {
		t.Fatalf("re-sealing before adoption: got %v, want ErrPassphraseNotAdopted%s", err, state())
	}
	// A flatly wrong previous value must not read as success either, which is
	// what it did before: it was never tried.
	if err := op.Reseal(ctx, []byte("a flatly wrong previous passphrase")); err == nil {
		t.Fatalf("a wrong previous value reported success; it was never checked against anything%s", state())
	}

	// After adoption the ordinary path works.
	ca.setPassphrase(newPass)
	if err := op.Reseal(ctx, []byte(oldPass)); err != nil {
		t.Fatalf("re-sealing after adoption: %v%s", err, state())
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("after re-sealing: %v%s", err, state())
	}
}

// TestCanOpenTestsTheCandidateAgainstTheFiles: the pre-flight issuerd needs
// before reseal-ca writes anything.
func TestCanOpenTestsTheCandidateAgainstTheFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)
	const oldPass = "a-passphrase-only-summon-knows"

	bad, err := op.CanOpen(ctx, []byte(oldPass))
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Fatalf("the correct passphrase must open everything, got %v unopened", bad)
	}

	bad, err = op.CanOpen(ctx, []byte("wrong"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 2 {
		t.Fatalf("a wrong candidate must name both the root and the intermediate, got %v", bad)
	}
	for _, name := range bad {
		if !strings.HasPrefix(name, rootPrefix) && !strings.HasPrefix(name, interPrefix) {
			t.Fatalf("unexpected file name %q", name)
		}
	}

	// It resolves nothing. issuerd calls this BEFORE adoption, so a check that
	// consulted the resolver would be answering about the old value and would
	// say nothing at all about the candidate the operator just typed.
	before := ca.res.callCount()
	if _, err := op.CanOpen(ctx, []byte("wrong again")); err != nil {
		t.Fatal(err)
	}
	if ca.res.callCount() != before {
		t.Fatal("CanOpen resolved through the provider; it must test the candidate against the files alone")
	}
}

// TestCanOpenSeesAPartiallyResealedDirectory is why it returns file names
// rather than a bool. A re-seal interrupted between two files leaves a
// directory that opens today and fails at the next restart, and the operator
// needs to know WHICH half is which to finish it.
func TestCanOpenSeesAPartiallyResealedDirectory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	op := ca.Authority.(PassphraseOperator)
	const oldPass = "a-passphrase-only-summon-knows"
	const newPass = "the value the provider now returns"

	// Re-seal what can be done without the previous value: the intermediates,
	// from the keys already in memory. The root is left under the old value.
	ca.setPassphrase(newPass)
	if err := op.Reseal(ctx, nil); !errors.Is(err, ErrPassphraseChanged) {
		t.Fatalf("got %v, want the partial-result refusal", err)
	}

	underNew, err := op.CanOpen(ctx, []byte(newPass))
	if err != nil {
		t.Fatal(err)
	}
	if len(underNew) != 1 || !strings.HasPrefix(underNew[0], rootPrefix) {
		t.Fatalf("the root should be the only file not yet under the new value, got %v", underNew)
	}
	underOld, err := op.CanOpen(ctx, []byte(oldPass))
	if err != nil {
		t.Fatal(err)
	}
	if len(underOld) != 1 || !strings.HasPrefix(underOld[0], interPrefix) {
		t.Fatalf("the intermediate should be the only file no longer under the old value, got %v", underOld)
	}

	// Finishing it clears both views.
	if err := op.Reseal(ctx, []byte(oldPass)); err != nil {
		t.Fatal(err)
	}
	if bad, err := op.CanOpen(ctx, []byte(newPass)); err != nil || len(bad) != 0 {
		t.Fatalf("after completing the re-seal everything must open under the new value: %v %v", bad, err)
	}
}
