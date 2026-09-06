package issuer

import (
	"errors"
	"sync"
	"testing"

	"github.com/infamousjoeg/totem/internal/presence"
)

// TestParkedStepUpApprovedFromSecondDevice is the real half of item 6: an
// agent's out-of-grant request is parked, and a device OTHER than the one
// that (hypothetically) sponsored the agent's grant approves it with a real
// presence-bound touch. The property under test is specifically that the
// approving device need not be the requesting agent's own device -- "park
// and approve from another enrolled device" (presence.go) -- proven here by
// using a completely independent key and device id for the approval and
// checking ApprovedBy names it.
func TestParkedStepUpApprovedFromSecondDevice(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	lot := presence.NewLot(clk.Now, 0, 0)

	requestHash := presence.HashRequest([]byte("aws"), []byte("prod-admin"), []byte("assume role for a one-off migration"))
	id, err := lot.Park("agent-1", "grant-abc", presence.Irreversible, "assume prod-admin via Roles Anywhere", requestHash)
	if err != nil {
		t.Fatalf("Park: %v", err)
	}

	const secondDeviceID = "admin-device-2"
	secondDeviceKey := newDeviceKey(t)
	verified := touchAlways(t, v, secondDeviceKey, secondDeviceID, "totem-stepup", "prod-admin", requestHash)

	if err := lot.Approve(id, verified); err != nil {
		t.Fatalf("Approve from the second device: %v", err)
	}

	got, err := lot.Poll(id)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got.State != presence.ParkedApproved {
		t.Errorf("State = %q, want %q", got.State, presence.ParkedApproved)
	}
	if got.ApprovedBy != secondDeviceID {
		t.Errorf("ApprovedBy = %q, want the second device %q", got.ApprovedBy, secondDeviceID)
	}

	consumed, err := lot.Consume(id)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.State != presence.ParkedConsumed {
		t.Errorf("consumed.State = %q, want %q", consumed.State, presence.ParkedConsumed)
	}

	// Negative: a second Consume must refuse. Approvals are single-use.
	if _, err := lot.Consume(id); !errors.Is(err, presence.ErrParkedConsumed) {
		t.Errorf("second Consume = %v, want ErrParkedConsumed", err)
	}
}

// TestParkedApprovalRefusesAPreSignedAssertion covers the anti-laundering
// rule for step-up specifically: "nothing is approved in advance." A
// presence proof verified before the request was ever parked -- however
// correctly it is bound to the eventual request hash -- must be refused.
func TestParkedApprovalRefusesAPreSignedAssertion(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	lot := presence.NewLot(clk.Now, 0, 0)

	requestHash := presence.HashRequest([]byte("aws"), []byte("prod-admin"))
	device := newDeviceKey(t)
	verified := touchAlways(t, v, device, "admin-device-2", "totem-stepup", "prod-admin", requestHash)

	clk.Advance(1) // ensure ParkedAt strictly postdates VerifiedAt
	id, err := lot.Park("agent-1", "grant-abc", presence.Irreversible, "assume prod-admin", requestHash)
	if err != nil {
		t.Fatalf("Park: %v", err)
	}

	if err := lot.Approve(id, verified); !errors.Is(err, presence.ErrPreSigned) {
		t.Fatalf("Approve with a pre-parking presence proof = %v, want ErrPreSigned", err)
	}
}

// TestParkedApprovalRefusesAWrongRequestHash covers approval binding: a
// presence proof bound to some other request, however freshly and validly
// signed, must not approve this one.
func TestParkedApprovalRefusesAWrongRequestHash(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	lot := presence.NewLot(clk.Now, 0, 0)

	requestHash := presence.HashRequest([]byte("aws"), []byte("prod-admin"))
	id, err := lot.Park("agent-1", "grant-abc", presence.Irreversible, "assume prod-admin", requestHash)
	if err != nil {
		t.Fatalf("Park: %v", err)
	}

	device := newDeviceKey(t)
	wrongHash := presence.HashRequest([]byte("github"), []byte("delete-repo"))
	verified := touchAlways(t, v, device, "admin-device-2", "totem-stepup", "prod-admin", wrongHash)

	if err := lot.Approve(id, verified); !errors.Is(err, presence.ErrRequestHashMismatch) {
		t.Fatalf("Approve with a presence proof bound to a different request = %v, want ErrRequestHashMismatch", err)
	}
}

// TestParkedIrreversibleRequestCannotBeBatchApproved covers the reversibility
// split from parked.go: an irreversible request has no batch path, ever,
// regardless of what other reversible ids are in the batch.
func TestParkedIrreversibleRequestCannotBeBatchApproved(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	lot := presence.NewLot(clk.Now, 0, 0)

	reversibleHash := presence.HashRequest([]byte("read"), []byte("freezer-temp"))
	reversibleID, err := lot.Park("agent-1", "grant-abc", presence.Reversible, "read the freezer sensor", reversibleHash)
	if err != nil {
		t.Fatalf("Park (reversible): %v", err)
	}
	irreversibleHash := presence.HashRequest([]byte("delete"), []byte("prod-bucket"))
	irreversibleID, err := lot.Park("agent-1", "grant-abc", presence.Irreversible, "delete a production bucket", irreversibleHash)
	if err != nil {
		t.Fatalf("Park (irreversible): %v", err)
	}

	ids := []string{reversibleID, irreversibleID}
	device := newDeviceKey(t)
	verified := touchAlways(t, v, device, "admin-device-2", "totem-stepup-batch", "batch", presence.BatchHash(ids))

	if err := lot.ApproveBatch(ids, verified); !errors.Is(err, presence.ErrIrreversibleInBatch) {
		t.Fatalf("ApproveBatch with an irreversible id mixed in = %v, want ErrIrreversibleInBatch", err)
	}

	// Neither item should have been mutated: batch approval is all or
	// nothing.
	got, err := lot.Poll(reversibleID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got.State != presence.ParkedPending {
		t.Errorf("reversible item's state after a refused batch = %q, want still %q", got.State, presence.ParkedPending)
	}
}

// TestConcurrentApprovalFromTwoDevicesOnlyOneSticks is the concurrency
// property for item 6: two DIFFERENT enrolled devices, each holding its own
// real, correctly-bound presence proof for the same parked request, race to
// approve it at once. Exactly one approval may stick; the loser must get a
// real, specific refusal (the request is no longer pending) rather than
// silently succeeding or corrupting the parked item's state.
func TestConcurrentApprovalFromTwoDevicesOnlyOneSticks(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	lot := presence.NewLot(clk.Now, 0, 0)

	requestHash := presence.HashRequest([]byte("aws"), []byte("prod-admin"))
	id, err := lot.Park("agent-1", "grant-abc", presence.Irreversible, "assume prod-admin", requestHash)
	if err != nil {
		t.Fatalf("Park: %v", err)
	}

	deviceA := newDeviceKey(t)
	deviceB := newDeviceKey(t)
	verifiedA := touchAlways(t, v, deviceA, "admin-device-A", "totem-stepup", "prod-admin", requestHash)
	verifiedB := touchAlways(t, v, deviceB, "admin-device-B", "totem-stepup", "prod-admin", requestHash)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = lot.Approve(id, verifiedA) }()
	go func() { defer wg.Done(); errs[1] = lot.Approve(id, verifiedB) }()
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, presence.ErrParkedNotPending) {
			t.Errorf("losing approval error = %v, want ErrParkedNotPending", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (only one device's approval should stick)", successes)
	}

	got, err := lot.Poll(id)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got.ApprovedBy != "admin-device-A" && got.ApprovedBy != "admin-device-B" {
		t.Fatalf("ApprovedBy = %q, want one of the two racing devices", got.ApprovedBy)
	}
	if got.State != presence.ParkedApproved {
		t.Errorf("State = %q, want %q", got.State, presence.ParkedApproved)
	}
}
