package ca

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

func deviceID(tool string) spiffe.ID {
	return spiffe.ID{TrustDomain: testTrustDomain, DeviceID: "dev-abc123", Tool: tool}
}

// TestOverlapWindow is the load-bearing test for "rotates every 30 days with
// overlap; the bundle endpoint publishes current plus next".
//
// It walks one whole rotation on the clock and asserts the two properties that
// make a rotation not be an outage:
//
//  1. The successor is in the bundle BEFORE it signs anything, so a relying
//     party that fetched during the overlap already trusts it.
//  2. A certificate signed by the outgoing intermediate STILL VERIFIES after
//     the successor takes over, because the outgoing intermediate stays in the
//     bundle for its retirement tail.
//
// Both verifications go through crypto/x509's own chain builder against nothing
// but what the bundle publishes.
func TestOverlapWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sched.Current == nil {
		t.Fatal("a freshly initialised CA must have a signing intermediate")
	}
	if sched.Next != nil {
		t.Fatal("a freshly initialised CA must not have a successor yet")
	}
	first := sched.Current
	if got, want := first.SigningEnd.Sub(first.SigningStart), IntermediateSigningPeriod; got != want {
		t.Fatalf("first intermediate signs for %s, want %s", got, want)
	}
	if got, want := sched.RotateAfter, first.SigningEnd.Add(-IntermediatePublicationOverlap); !got.Equal(want) {
		t.Fatalf("RotateAfter = %s, want SigningEnd minus the publication overlap (%s)", got, want)
	}

	// Before the overlap opens, rotating is refused. Preparing a successor
	// early would leave it published for longer than the overlap and shift
	// every later boundary off the schedule the constants describe.
	ca.clk.set(sched.RotateAfter.Add(-time.Hour))
	if _, err := ca.RotateIntermediate(ctx); !errors.Is(err, ErrRotationTooSoon) {
		t.Fatalf("rotating before the overlap opened: got %v, want ErrRotationTooSoon", err)
	}

	// Inside the overlap, the successor is prepared and published.
	ca.clk.set(sched.RotateAfter.Add(time.Hour))
	sched, err = ca.RotateIntermediate(ctx)
	if err != nil {
		t.Fatalf("RotateIntermediate inside the overlap: %v", err)
	}
	if sched.Next == nil {
		t.Fatal("after rotating inside the overlap there must be a published successor")
	}
	if !sched.Next.SigningStart.Equal(first.SigningEnd) {
		t.Fatalf("successor starts signing at %s, want exactly when the outgoing one stops (%s); a gap or an overlap in SIGNING makes the issuer of a leaf unpredictable from the clock",
			sched.Next.SigningStart, first.SigningEnd)
	}

	// Property 1: the bundle carries current AND next, and the next is trusted
	// before it has signed anything.
	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[IntermediateRole]int{}
	for _, in := range bundle.Intermediates {
		roles[in.Role]++
	}
	if roles[RoleCurrent] != 1 || roles[RoleNext] != 1 {
		t.Fatalf("during the overlap the bundle must publish exactly one current and one next intermediate, got %v", roles)
	}

	// A leaf minted just before the handover, by the OUTGOING intermediate.
	ca.clk.set(first.SigningEnd.Add(-30 * time.Minute))
	key := newSVIDKey(t)
	outgoing, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: key.Public()})
	if err != nil {
		t.Fatalf("issuing before the handover: %v", err)
	}
	if string(outgoing.IssuedBy) != string(first.Certificate.SubjectKeyId) {
		t.Fatal("a certificate minted before the handover must be signed by the outgoing intermediate")
	}

	// Cross the handover. Nothing runs; the clock alone promotes the successor.
	ca.clk.set(first.SigningEnd.Add(10 * time.Minute))
	sched, err = ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sched.Current == nil || string(sched.Current.Certificate.SubjectKeyId) == string(first.Certificate.SubjectKeyId) {
		t.Fatal("crossing SigningEnd must promote the successor without an operator or a cron doing anything")
	}
	if len(sched.Retiring) != 1 || !sched.Retiring[0].Certificate.Equal(first.Certificate) {
		t.Fatalf("the outgoing intermediate must be retiring, got %d retiring", len(sched.Retiring))
	}

	bundle, err = ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Intermediates) != 2 {
		t.Fatalf("during the retirement tail the bundle must still carry the outgoing intermediate, got %d intermediates", len(bundle.Intermediates))
	}

	// Property 2: the leaf the outgoing intermediate signed still verifies,
	// through crypto/x509, against the published bundle, after the handover.
	if err := verifyAgainstBundle(t, outgoing.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("a certificate signed by the outgoing intermediate stopped verifying after the handover; that is the rotation being an outage: %v", err)
	}

	// And the new intermediate mints working certificates immediately.
	incoming, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatalf("issuing after the handover: %v", err)
	}
	if string(incoming.IssuedBy) != string(sched.Current.Certificate.SubjectKeyId) {
		t.Fatal("a certificate minted after the handover must be signed by the incoming intermediate")
	}
	if err := verifyAgainstBundle(t, incoming.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("verifying a certificate from the incoming intermediate: %v", err)
	}

	// Past its NotAfter the outgoing intermediate leaves the bundle. By then
	// every leaf it signed has expired, because the retirement tail is longer
	// than the maximum SVID lifetime.
	ca.clk.set(first.Certificate.NotAfter.Add(time.Minute))
	bundle, err = ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range bundle.Intermediates {
		if in.Certificate.Equal(first.Certificate) {
			t.Fatal("an expired intermediate must leave the bundle")
		}
	}
}

// TestRotateTwiceInsideOneOverlapIsRefused is the guard the brief asks about by
// name.
//
// Replacing a published-but-not-yet-signing intermediate is the exact outage
// the overlap exists to prevent: every relying party that already fetched the
// bundle trusts the successor that was published, and would reject everything
// the replacement signs until it refetched. So the second rotation changes
// nothing, returns ErrRotationPending, and hands back the schedule that
// already exists.
func TestRotateTwiceInsideOneOverlapIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.RotateAfter.Add(time.Hour))

	first, err := ca.RotateIntermediate(ctx)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if first.Next == nil {
		t.Fatal("first rotation must publish a successor")
	}
	published := string(first.Next.Certificate.SubjectKeyId)

	// A day later, still inside the same overlap.
	ca.clk.advance(24 * time.Hour)
	second, err := ca.RotateIntermediate(ctx)
	if !errors.Is(err, ErrRotationPending) {
		t.Fatalf("second rotation inside the overlap: got %v, want ErrRotationPending", err)
	}
	if second == nil || second.Next == nil {
		t.Fatal("a refused rotation must still report the schedule that exists")
	}
	if string(second.Next.Certificate.SubjectKeyId) != published {
		t.Fatal("the published successor was replaced; every relying party holding the earlier bundle would now reject what the CA signs")
	}

	// And the CA did not quietly accumulate a third pending intermediate.
	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Intermediates) != 2 {
		t.Fatalf("bundle has %d intermediates after a refused rotation, want 2", len(bundle.Intermediates))
	}
}

// TestMissedRotationFailsClosedAndRecovers pins the other half of the offline
// root's bargain: if nobody rotates, the CA stops minting rather than signing
// under a key whose signing window closed, and the recovery path does not
// itself require a window that has already passed.
func TestMissedRotationFailsClosedAndRecovers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.Current.SigningEnd.Add(time.Hour))

	if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); !errors.Is(err, ErrNoSigningIntermediate) {
		t.Fatalf("issuing with no intermediate in its signing window: got %v, want ErrNoSigningIntermediate", err)
	}

	recovered, err := ca.RotateIntermediate(ctx)
	if err != nil {
		t.Fatalf("recovery rotation: %v", err)
	}
	if recovered.Current == nil {
		t.Fatal("recovery must produce an intermediate that signs immediately, not one that waits out a publication overlap")
	}
	svid, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatalf("issuing after recovery: %v", err)
	}
	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstBundle(t, svid.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("verifying a certificate minted after recovery: %v", err)
	}
}

// TestRetirementTailCoversMaxSVIDTTL is an invariant, not a behaviour: if the
// tail were ever shortened below the maximum SVID lifetime, a leaf could
// outlive the intermediate that signed it and a relying party would see an
// expired chain under a perfectly valid leaf.
func TestRetirementTailCoversMaxSVIDTTL(t *testing.T) {
	t.Parallel()
	if IntermediateRetirementTail < MaxSVIDTTL {
		t.Fatalf("IntermediateRetirementTail (%s) must be at least MaxSVIDTTL (%s)", IntermediateRetirementTail, MaxSVIDTTL)
	}
	if IntermediateValidity != IntermediatePublicationOverlap+IntermediateSigningPeriod+IntermediateRetirementTail {
		t.Fatal("IntermediateValidity must be the sum of the three windows it names")
	}
}

// TestLeafNeverOutlivesItsIntermediate exercises the clamp directly, by issuing
// in the last minutes of a signing window.
func TestLeafNeverOutlivesItsIntermediate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The retirement tail means this cannot bite in normal operation, so drive
	// the clock to the very end of the certificate instead.
	ca.clk.set(sched.Current.Certificate.NotAfter.Add(-10 * time.Minute))
	// At this point the intermediate is retiring, so issuance must be refused
	// outright rather than clamped.
	if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); !errors.Is(err, ErrNoSigningIntermediate) {
		t.Fatalf("a retiring intermediate must not sign 'just this once': got %v", err)
	}
}
