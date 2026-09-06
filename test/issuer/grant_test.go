package issuer

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
)

// TestGrantNarrowingIsMonotonic drives a real presence.Registry through
// sponsor -> open -> narrow, and proves the two directions monotonic
// narrowing must refuse: a scope that adds a capability (ErrNotNarrower) and
// an expiry that outlives the parent (ErrExpiryWidens). A positive narrow can
// only pass, so per the step-1 lesson these two refusals are the real test;
// the positive case is here mainly to set up state for them.
func TestGrantNarrowingIsMonotonic(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	reg := liveRegistry(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "admin-device-1"

	rootScope := presence.Scope{
		AWSProfiles:  []string{"dev", "staging"},
		GitHubScopes: []string{"repo:read"},
		ClaudeProxy:  true,
		SpendCapUSD:  20,
	}
	root := sponsorRootGrant(t, v, reg, key, deviceID, "agent-1", rootScope, clk.Now().Add(30*24*time.Hour))

	sess, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	narrower := presence.Scope{AWSProfiles: []string{"dev"}, ClaudeProxy: true, SpendCapUSD: 5}
	child, err := reg.Narrow(sess.ID, narrower, time.Time{})
	if err != nil {
		t.Fatalf("Narrow with a genuinely narrower scope: %v", err)
	}
	if !child.Scope.Within(root.Scope) {
		t.Error("narrowed grant's scope is not Within the root's scope")
	}
	if !child.Until.Equal(root.Until) {
		t.Errorf("Narrow with a zero `until` should inherit the parent's: got %s, want %s", child.Until, root.Until)
	}
	if got, want := child.ParentID(), root.ID; got != want {
		t.Errorf("child.ParentID() = %q, want %q", got, want)
	}

	// Negative: a scope that adds a capability the root never had.
	wider := presence.Scope{AWSProfiles: []string{"dev", "staging", "prod"}, ClaudeProxy: true, SpendCapUSD: 5}
	if _, err := reg.Narrow(sess.ID, wider, time.Time{}); !errors.Is(err, presence.ErrNotNarrower) {
		t.Errorf("Narrow adding an AWS profile the parent never granted = %v, want ErrNotNarrower", err)
	}

	// Negative: an expiry later than the parent's, even with an otherwise
	// narrower scope.
	laterUntil := root.Until.Add(time.Hour)
	if _, err := reg.Narrow(sess.ID, narrower, laterUntil); !errors.Is(err, presence.ErrExpiryWidens) {
		t.Errorf("Narrow with expiry after the parent's = %v, want ErrExpiryWidens", err)
	}

	// The session's active grant must be unaffected by either refused
	// attempt: it should still be the one successful child from before.
	active, err := reg.Active(sess.ID)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.ID != child.ID {
		t.Errorf("Active().ID = %q after two refused Narrow calls, want the unaffected child %q", active.ID, child.ID)
	}
}

// TestReWideningRequiresFreshPresenceAfterNarrowing proves the "narrow, do
// the quiet thing, silently restore" laundering path is closed: an
// otherwise-valid, correctly-bound widening assertion that was verified
// BEFORE the narrowing it is meant to undo must be refused, and the identical
// widen succeeds once the presence proof postdates the narrowing (including
// the documented edge case that an EQUAL instant is accepted, not just a
// strictly later one).
func TestReWideningRequiresFreshPresenceAfterNarrowing(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	reg := liveRegistry(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "admin-device-1"

	root := sponsorRootGrant(t, v, reg, key, deviceID, "agent-1", presence.Scope{ClaudeProxy: true, SpendCapUSD: 20}, clk.Now().Add(time.Hour))
	sess, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	widenHash := presence.WidenHash(sess.ID, root.ID)
	staleVerified := touchAlways(t, v, key, deviceID, "totem-widen", "agent-1", widenHash)

	// Advance the clock so the narrowing strictly postdates the touch above.
	clk.Advance(time.Second)
	if _, err := reg.Narrow(sess.ID, presence.Scope{}, time.Time{}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}

	if _, err := reg.Widen(sess.ID, root.ID, staleVerified); !errors.Is(err, presence.ErrRewidenRequiresPresence) {
		t.Fatalf("Widen with a pre-narrowing presence proof = %v, want ErrRewidenRequiresPresence", err)
	}

	// A fresh touch verified at exactly the narrowing instant (equal, not
	// later) must still succeed: session.go's Widen doc says "equal instants
	// pass."
	freshVerified := touchAlways(t, v, key, deviceID, "totem-widen", "agent-1", widenHash)
	widened, err := reg.Widen(sess.ID, root.ID, freshVerified)
	if err != nil {
		t.Fatalf("Widen with a presence proof verified at the narrowing instant: %v", err)
	}
	if widened.ID != root.ID {
		t.Errorf("Widen returned grant %q, want the root %q", widened.ID, root.ID)
	}

	active, err := reg.Active(sess.ID)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.ID != root.ID {
		t.Errorf("session's active grant after Widen = %q, want root %q", active.ID, root.ID)
	}
}

// TestConcurrentNarrowingNeverCorruptsRegistryState is the concurrency
// property for item 3. Narrow has no single-use semantics like a Verified --
// each valid call chains onto whatever the session's active grant currently
// is -- so the meaningful property under concurrency is not "exactly one
// wins" but "the registry's mutex actually serializes narrowing instead of
// losing or corrupting updates." Every goroutine here narrows to the SAME
// scope as the root (a valid, idempotent-shaped narrow regardless of
// ordering), so every one of them must succeed however they interleave, and
// the resulting lineage depth must equal the number of goroutines: any
// discrepancy would mean a concurrent Narrow was lost or clobbered another's
// write.
func TestConcurrentNarrowingNeverCorruptsRegistryState(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	reg := liveRegistry(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "admin-device-1"

	rootScope := presence.Scope{AWSProfiles: []string{"dev"}, ClaudeProxy: true, SpendCapUSD: 100}
	root := sponsorRootGrant(t, v, reg, key, deviceID, "agent-1", rootScope, clk.Now().Add(time.Hour))
	sess, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const n = 30
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = reg.Narrow(sess.ID, rootScope, time.Time{})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Narrow #%d failed: %v", i, err)
		}
	}

	final, err := reg.Active(sess.ID)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if !final.Scope.Within(root.Scope) {
		t.Error("final active grant's scope is not Within the root's scope after concurrent narrowing")
	}
	if got := len(final.Lineage); got != n {
		t.Errorf("final grant lineage depth = %d, want %d (each concurrent Narrow should chain onto the previous, never get lost or clobbered)", got, n)
	}
}

// TestConcurrentWidenWithSameVerifiedSucceedsExactlyOnce mirrors the
// SessionStore single-use race in window_test.go, but for Widen: a real
// *Verified is single-use everywhere it is accepted, and Widen's Verified
// argument must be no exception.
//
// Widen holds the registry's lock for its entire body (check, consume, and
// mutate all under one critical section), so racing calls are fully
// serialized rather than interleaved: whichever call's turn comes first
// consumes the Verified and moves the session's active grant to the target
// (root). Every call after that no longer sees root as an ancestor of the
// (now root-equal) active grant -- root has no lineage containing itself --
// so it is correctly refused with ErrNotAncestor before it ever reaches the
// consume step at all. That was not the assumption this test started with
// (every loser reaching v.consume() and getting ErrPresenceConsumed); running
// it against the real Registry is what corrected it, which is the entire
// point of driving the real counterparty instead of predicting its behavior.
func TestConcurrentWidenWithSameVerifiedSucceedsExactlyOnce(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	reg := liveRegistry(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "admin-device-1"

	root := sponsorRootGrant(t, v, reg, key, deviceID, "agent-1", presence.Scope{ClaudeProxy: true, SpendCapUSD: 10}, clk.Now().Add(time.Hour))
	sess, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := reg.Narrow(sess.ID, presence.Scope{}, time.Time{}); err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	clk.Advance(time.Second)

	widenHash := presence.WidenHash(sess.ID, root.ID)
	verified := touchAlways(t, v, key, deviceID, "totem-widen", "agent-1", widenHash)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = reg.Widen(sess.ID, root.ID, verified)
		}(i)
	}
	wg.Wait()

	var successes, refusedAsNonAncestor int
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, presence.ErrNotAncestor):
			refusedAsNonAncestor++
		default:
			t.Fatalf("unexpected Widen error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	if refusedAsNonAncestor != n-1 {
		t.Fatalf("refused as ErrNotAncestor = %d, want %d (every call after the winner should see the "+
			"active grant already moved to the target and correctly refuse rather than double-spend the "+
			"Verified)", refusedAsNonAncestor, n-1)
	}

	// The Verified itself must still show as consumed exactly once: the
	// single winner is what spent it, not an accident of the losers'
	// refusal path.
	if !verified.Used() {
		t.Error("verified.Used() = false after a successful Widen; the winner should have consumed it")
	}
}

// TestGrantRevocationReachesEverySubGrant covers the lineage-based
// revocation property: revoking a root instantly invalidates every
// descendant, without the registry having had to walk and mark each one
// individually at revoke time.
func TestGrantRevocationReachesEverySubGrant(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	reg := liveRegistry(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "admin-device-1"

	root := sponsorRootGrant(t, v, reg, key, deviceID, "agent-1", presence.Scope{ClaudeProxy: true, SpendCapUSD: 10}, clk.Now().Add(time.Hour))
	sess, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	child, err := reg.Narrow(sess.ID, presence.Scope{ClaudeProxy: true, SpendCapUSD: 1}, time.Time{})
	if err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	grandchild, err := reg.Narrow(sess.ID, presence.Scope{}, time.Time{})
	if err != nil {
		t.Fatalf("Narrow (second level): %v", err)
	}

	reg.Revoke(root.ID)

	for name, id := range map[string]string{"root": root.ID, "child": child.ID, "grandchild": grandchild.ID} {
		if _, err := reg.Get(id); !errors.Is(err, presence.ErrGrantRevoked) {
			t.Errorf("Get(%s) after revoking the root = %v, want ErrGrantRevoked", name, err)
		}
	}
}
