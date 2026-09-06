package presence

import (
	"errors"
	"testing"
	"time"
)

func newLot(t *testing.T) (*clock, *Lot) {
	t.Helper()
	clk := newClock()
	return clk, NewLot(clk.Now, 0, 0)
}

func park(t *testing.T, l *Lot, rev Reversibility, desc string) (string, []byte) {
	t.Helper()
	h := HashRequest([]byte(desc))
	id, err := l.Park("cassidy", "grant-1", rev, desc, h)
	if err != nil {
		t.Fatal(err)
	}
	return id, h
}

func TestParkReturnsImmediatelyAndPolls(t *testing.T) {
	clk, l := newLot(t)
	id, h := park(t, l, Irreversible, "send email to Charissa")
	if id == "" {
		t.Fatal("no id")
	}
	item, err := l.Poll(id)
	if err != nil {
		t.Fatal(err)
	}
	if item.State != ParkedPending || item.Agent != "cassidy" || item.GrantID != "grant-1" || item.Reversibility != Irreversible {
		t.Fatalf("polled item: %+v", item)
	}
	if !item.ParkedAt.Equal(clk.Now()) || !item.ExpiresAt.Equal(clk.At(DefaultParkTTL)) {
		t.Fatalf("timing: %+v", item)
	}
	if string(item.RequestHash) != string(h) {
		t.Fatal("request hash not carried")
	}
	// Polling is idempotent and never changes state on its own.
	for range 3 {
		again, _ := l.Poll(id)
		if again.State != ParkedPending {
			t.Fatal("poll changed state")
		}
	}
	_, err = l.Poll("nope")
	mustErr(t, err, ErrParkedNotFound)
}

func TestParkValidation(t *testing.T) {
	_, l := newLot(t)
	cases := []struct {
		name  string
		agent string
		rev   Reversibility
		hash  []byte
	}{
		{"no agent", "", Reversible, HashRequest([]byte("x"))},
		{"bad reversibility", "a", Reversibility("maybe"), HashRequest([]byte("x"))},
		{"empty reversibility", "a", "", HashRequest([]byte("x"))},
		{"no hash", "a", Reversible, nil},
		{"short hash", "a", Reversible, make([]byte, 31)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := l.Park(tc.agent, "g", tc.rev, "d", tc.hash)
			mustErr(t, err, ErrParkedInvalid)
		})
	}
}

func TestIrreversibleLifecycle(t *testing.T) {
	clk, l := newLot(t)
	id, h := park(t, l, Irreversible, "post to the group")
	other := HashRequest([]byte("something else"))

	cases := []struct {
		name string
		v    *Verified
		want error
	}{
		{"nil presence", nil, ErrPresenceRequired},
		{"hand-built presence", &Verified{DeviceID: "d", RequestHash: h, VerifiedAt: clk.Now()}, ErrPresenceRequired},
		{"window touch, not bound", verified("d", clk.Now(), nil), ErrRequestHashMismatch},
		{"bound to another request", verified("d", clk.Now(), other), ErrRequestHashMismatch},
		{"bound to a batch containing it", verified("d", clk.Now(), BatchHash([]string{id})), ErrRequestHashMismatch},
		{"pre-signed before parking", verified("d", clk.At(-time.Second), h), ErrPreSigned},
		{"bound and fresh", verified("d", clk.Now(), h), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := l.Approve(id, tc.v)
			mustErr(t, err, tc.want)
			item, _ := l.Poll(id)
			if tc.want != nil && item.State != ParkedPending {
				t.Fatalf("refused approval changed state to %s", item.State)
			}
		})
	}
	item, _ := l.Poll(id)
	if item.State != ParkedApproved || item.ApprovedBy != "d" || !item.ApprovalExpiresAt.Equal(clk.At(DefaultApprovalTTL)) {
		t.Fatalf("approved item: %+v", item)
	}
	// Approving again is refused; consuming works exactly once.
	mustErr(t, l.Approve(id, verified("d", clk.Now(), h)), ErrParkedNotPending)
	mustErr(t, l.Deny(id), ErrParkedNotPending)
	got, err := l.Consume(id)
	if err != nil || got.State != ParkedConsumed || string(got.RequestHash) != string(h) {
		t.Fatalf("consume: %v %+v", err, got)
	}
	_, err = l.Consume(id)
	mustErr(t, err, ErrParkedConsumed)
	item, _ = l.Poll(id)
	if item.State != ParkedConsumed {
		t.Fatal("state after consume")
	}
}

// One Verified approves one parked request, even when two carry the same
// request hash. (Reviewer M1, inverted.)
func TestOneProofApprovesOneRequest(t *testing.T) {
	clk, l := newLot(t)
	a, h := park(t, l, Irreversible, "send $50 to bob")
	b, _ := park(t, l, Irreversible, "send $50 to bob")
	v := verified("d", clk.Now(), h)
	if err := l.Approve(a, v); err != nil {
		t.Fatal(err)
	}
	mustErr(t, l.Approve(b, v), ErrPresenceConsumed)
	if item, _ := l.Poll(b); item.State != ParkedPending {
		t.Fatalf("second request moved to %s on a spent proof", item.State)
	}
	// A refused approval does not spend the proof.
	fresh := verified("d", clk.Now(), HashRequest([]byte("other")))
	mustErr(t, l.Approve(b, fresh), ErrRequestHashMismatch)
	if fresh.Used() {
		t.Fatal("refused approval consumed the proof")
	}
	// Batch consumes once for the whole batch, and a spent proof cannot
	// approve a second batch.
	r1, _ := park(t, l, Reversible, "r1")
	r2, _ := park(t, l, Reversible, "r2")
	bv := verified("d", clk.Now(), BatchHash([]string{r1, r2}))
	if err := l.ApproveBatch([]string{r1, r2}, bv); err != nil {
		t.Fatal(err)
	}
	if !bv.Used() {
		t.Fatal("batch did not consume its proof")
	}
	// A batch proof is bound to its sorted ids, so it can only ever match
	// the same batch again, which is no longer pending; consume is the
	// belt-and-braces behind that hash binding.
	mustErr(t, l.ApproveBatch([]string{r1, r2}, bv), ErrParkedNotPending)
}

// Pending requests are capped per agent. (Reviewer L1.)
func TestParkPerAgentCap(t *testing.T) {
	clk, l := newLot(t)
	for i := range MaxPendingPerAgent {
		if _, err := l.Park("a", "g", Reversible, "x", HashRequest([]byte{byte(i)})); err != nil {
			t.Fatalf("park %d: %v", i, err)
		}
	}
	_, err := l.Park("a", "g", Reversible, "x", HashRequest([]byte("over")))
	mustErr(t, err, ErrTooManyParked)
	if _, err := l.Park("b", "g", Reversible, "x", HashRequest([]byte("other agent"))); err != nil {
		t.Fatalf("cap leaked across agents: %v", err)
	}
	// Expiry frees the slots.
	clk.Advance(DefaultParkTTL)
	if _, err := l.Park("a", "g", Reversible, "x", HashRequest([]byte("after expiry"))); err != nil {
		t.Fatalf("expired items still counted: %v", err)
	}
}

func TestIrreversibleCannotBeBatched(t *testing.T) {
	clk, l := newLot(t)
	r1, _ := park(t, l, Reversible, "write notes")
	r2, _ := park(t, l, Reversible, "recompute index")
	irr, _ := park(t, l, Irreversible, "spend $40")
	ids := []string{r1, r2, irr}
	err := l.ApproveBatch(ids, verified("d", clk.Now(), BatchHash(ids)))
	mustErr(t, err, ErrIrreversibleInBatch)
	// All or nothing: the reversible ones are still pending.
	for _, id := range ids {
		item, _ := l.Poll(id)
		if item.State != ParkedPending {
			t.Fatalf("%s moved to %s in a refused batch", id, item.State)
		}
	}
}

func TestReversibleBatchApproval(t *testing.T) {
	clk, l := newLot(t)
	r1, _ := park(t, l, Reversible, "write notes")
	clk.Advance(time.Hour)
	r2, _ := park(t, l, Reversible, "recompute index")
	clk.Advance(time.Hour)
	r3, _ := park(t, l, Reversible, "cache the page")
	ids := []string{r1, r2}

	cases := []struct {
		name string
		ids  []string
		v    *Verified
		want error
	}{
		{"nil presence", ids, nil, ErrPresenceRequired},
		{"empty batch", nil, verified("d", clk.Now(), BatchHash(nil)), ErrParkedInvalid},
		{"bound to a different list", ids, verified("d", clk.Now(), BatchHash([]string{r1, r2, r3})), ErrRequestHashMismatch},
		{"bound to one item, not the batch", []string{r1}, verified("d", clk.Now(), HashRequest([]byte("write notes"))), ErrRequestHashMismatch},
		{"unknown id in list", []string{r1, "nope"}, verified("d", clk.Now(), BatchHash([]string{r1, "nope"})), ErrParkedNotFound},
		{"pre-signed before the newest item", ids, verified("d", clk.At(-90*time.Minute), BatchHash(ids)), ErrPreSigned},
		{"order and duplicates do not matter", []string{r2, r1, r1}, verified("d", clk.Now(), BatchHash(ids)), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := l.ApproveBatch(tc.ids, tc.v)
			mustErr(t, err, tc.want)
		})
	}
	for _, id := range ids {
		item, _ := l.Poll(id)
		if item.State != ParkedApproved || item.ApprovedBy != "d" {
			t.Fatalf("%s: %+v", id, item)
		}
		if _, err := l.Consume(id); err != nil {
			t.Fatal(err)
		}
	}
	if item, _ := l.Poll(r3); item.State != ParkedPending {
		t.Fatal("item outside the batch was approved")
	}
	// A batch that includes an already-approved item is refused whole.
	err := l.ApproveBatch([]string{r1, r3}, verified("d", clk.Now(), BatchHash([]string{r1, r3})))
	mustErr(t, err, ErrParkedNotPending)
	if item, _ := l.Poll(r3); item.State != ParkedPending {
		t.Fatal("refused batch approved r3")
	}
}

func TestPendingSplitsByReversibility(t *testing.T) {
	clk, l := newLot(t)
	r1, _ := park(t, l, Reversible, "b")
	clk.Advance(time.Second)
	i1, _ := park(t, l, Irreversible, "send")
	clk.Advance(time.Second)
	r2, _ := park(t, l, Reversible, "a")
	rev := l.Pending(Reversible)
	if len(rev) != 2 || rev[0].ID != r1 || rev[1].ID != r2 {
		t.Fatalf("reversible list: %+v", rev)
	}
	irr := l.Pending(Irreversible)
	if len(irr) != 1 || irr[0].ID != i1 {
		t.Fatalf("irreversible list: %+v", irr)
	}
	if err := l.Deny(i1); err != nil {
		t.Fatal(err)
	}
	if len(l.Pending(Irreversible)) != 0 {
		t.Fatal("denied item still pending")
	}
	if item, _ := l.Poll(i1); item.State != ParkedDenied {
		t.Fatal("deny did not stick")
	}
	_, err := l.Consume(i1)
	mustErr(t, err, ErrParkedNotApproved)
}

func TestParkedExpiry(t *testing.T) {
	clk, l := newLot(t)
	// Pending expires unapproved.
	p, ph := park(t, l, Irreversible, "p")
	clk.Advance(DefaultParkTTL)
	if item, _ := l.Poll(p); item.State != ParkedExpired {
		t.Fatalf("pending did not expire: %s", item.State)
	}
	mustErr(t, l.Approve(p, verified("d", clk.Now(), ph)), ErrParkedExpired)
	mustErr(t, l.Deny(p), ErrParkedExpired)
	_, err := l.Consume(p)
	mustErr(t, err, ErrParkedExpired)

	// Approval expires unconsumed.
	a, ah := park(t, l, Irreversible, "a")
	if err := l.Approve(a, verified("d", clk.Now(), ah)); err != nil {
		t.Fatal(err)
	}
	clk.Advance(DefaultApprovalTTL - time.Second)
	if item, _ := l.Poll(a); item.State != ParkedApproved {
		t.Fatal("approval expired early")
	}
	clk.Advance(time.Second)
	_, err = l.Consume(a)
	mustErr(t, err, ErrParkedExpired)
	// Once expired, a fresh approval cannot revive it.
	mustErr(t, l.Approve(a, verified("d", clk.Now(), ah)), ErrParkedExpired)

	// Sweep drops terminal items only.
	live, _ := park(t, l, Reversible, "live")
	if n := l.Sweep(0); n != 2 {
		t.Fatalf("swept %d, want 2", n)
	}
	if _, err := l.Poll(live); err != nil {
		t.Fatal("sweep dropped a pending item")
	}
	_, err = l.Poll(p)
	mustErr(t, err, ErrParkedNotFound)
}

func TestParkedErrorsAreDistinct(t *testing.T) {
	errs := []error{
		ErrParkedNotFound, ErrParkedInvalid, ErrParkedNotPending, ErrParkedNotApproved,
		ErrParkedExpired, ErrParkedConsumed, ErrIrreversibleInBatch, ErrPreSigned, ErrTooManyParked,
		ErrNotHolder, ErrPresenceConsumed, ErrScopeInvalid,
		ErrEnrollmentMalformed, ErrEnrollmentKeyUnsupported, ErrEnrollmentBadSignature,
		ErrEnrollmentNeedsPresence, ErrEnrollmentUnexpectedPresence, ErrEnrollmentChallengeSplit,
		ErrGrantNotFound, ErrGrantRevoked, ErrGrantExpired, ErrGrantInvalid, ErrGrantHashMismatch,
		ErrNotNarrower, ErrExpiryWidens, ErrSessionNotFound, ErrNotAncestor, ErrRewidenRequiresPresence,
		ErrInvalidWindow, ErrLevelHasNoSession, ErrBoundAssertionCannotOpenWindow,
	}
	for i := range errs {
		for j := range errs {
			if i != j && errors.Is(errs[i], errs[j]) {
				t.Fatalf("%v and %v are not distinct", errs[i], errs[j])
			}
		}
	}
}
