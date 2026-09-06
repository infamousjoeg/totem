package presence

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Parking timing.
const (
	// DefaultParkTTL is how long a parked request waits for a human before it
	// expires on its own: 24 hours, so a request parked at 3am is still on
	// the morning list and one parked after the human left for the day is
	// still there tomorrow. Longer means a stale "here's what I wanted to
	// do" the agent may no longer mean; shorter drops requests before anyone
	// sees them. It trades staleness of the morning list against losing
	// items to a missed morning.
	DefaultParkTTL = 24 * time.Hour
	// DefaultApprovalTTL is how long an approval waits to be consumed by the
	// agent's next heartbeat: one hour, comfortably more than any launchd
	// heartbeat interval, and short enough that an approval the agent never
	// picked up (it died, it moved on) does not sit live for a day. It trades
	// heartbeat slack against the lifetime of an unclaimed approval.
	DefaultApprovalTTL = time.Hour
)

// Reversibility is the real axis parked items split on, not the clock.
type Reversibility string

const (
	// Reversible: read, compute, write to the agent's own store. Queues for
	// one-tap batch approval so the human wakes to "here's what I wanted to
	// do".
	Reversible Reversibility = "reversible"
	// Irreversible: send, post, spend, delete. Stays parked until presence
	// bound to exactly this request, with no pre-signing and no batching;
	// 3am is exactly when scope must not widen.
	Irreversible Reversibility = "irreversible"
)

// ParkedState is where a parked request is in its lifecycle:
// parked -> approved -> consumed, or parked -> denied, or either of the first
// two -> expired.
type ParkedState string

const (
	// ParkedPending: waiting for a human.
	ParkedPending ParkedState = "parked"
	// ParkedApproved: a present human approved it; the agent may consume it
	// once before the approval expires.
	ParkedApproved ParkedState = "approved"
	// ParkedConsumed: the agent used the approval. Terminal.
	ParkedConsumed ParkedState = "consumed"
	// ParkedDenied: the human refused. Terminal.
	ParkedDenied ParkedState = "denied"
	// ParkedExpired: nobody acted in time. Terminal.
	ParkedExpired ParkedState = "expired"
)

// Parking errors.
var (
	// ErrParkedNotFound: no parked request with that id.
	ErrParkedNotFound = errors.New("presence: parked request not found")
	// ErrParkedInvalid: the request to park is malformed (bad reversibility,
	// no request hash, no agent).
	ErrParkedInvalid = errors.New("presence: parked request invalid")
	// ErrParkedNotPending: the request is past the point where approve or
	// deny applies.
	ErrParkedNotPending = errors.New("presence: parked request is not pending")
	// ErrParkedNotApproved: consume was called on a request that is not in
	// the approved state.
	ErrParkedNotApproved = errors.New("presence: parked request is not approved")
	// ErrParkedExpired: the request, or its approval, expired.
	ErrParkedExpired = errors.New("presence: parked request expired")
	// ErrParkedConsumed: the approval was already used. Approvals are
	// single-use.
	ErrParkedConsumed = errors.New("presence: parked request already consumed")
	// ErrIrreversibleInBatch: batch approval is for reversible items only.
	// An irreversible item waits for presence bound to itself.
	ErrIrreversibleInBatch = errors.New("presence: irreversible request cannot be batch-approved")
	// ErrPreSigned: the approving assertion was verified before the request
	// was parked. Nothing is approved in advance.
	ErrPreSigned = errors.New("presence: approval predates the parked request")
)

// ParkedRequest is an out-of-grant request waiting for a present human. It is
// returned by Park immediately and polled by id across later heartbeats; one
// parked task never freezes the others.
type ParkedRequest struct {
	// ID the agent polls.
	ID string
	// Agent that made the request.
	Agent string
	// GrantID the agent was operating under when the request fell outside it.
	GrantID string
	// Reversibility decides whether it may be batch-approved.
	Reversibility Reversibility
	// Description is the plain-language line the human reads: what the agent
	// wanted to do.
	Description string
	// RequestHash is the hash of the concrete request (HashRequest). An
	// irreversible approval must be bound to it.
	RequestHash []byte
	// State is the lifecycle position.
	State ParkedState
	// ParkedAt is when the request was parked.
	ParkedAt time.Time
	// ExpiresAt is when a pending request expires unapproved.
	ExpiresAt time.Time
	// ApprovedAt is when a human approved it; zero otherwise.
	ApprovedAt time.Time
	// ApprovalExpiresAt is when an unconsumed approval expires; zero otherwise.
	ApprovalExpiresAt time.Time
	// ApprovedBy is the device the human approved on; empty otherwise.
	ApprovedBy string
}

// BatchHash is the request hash a batch approval must be bound to: the sorted,
// de-duplicated ids, length-prefixed and domain-separated. The human approved
// exactly this list and nothing that arrives later.
func BatchHash(ids []string) []byte {
	ids = normalizeSet(ids)
	parts := make([][]byte, len(ids))
	for i, id := range ids {
		parts[i] = []byte(id)
	}
	return hashParts(contextBatch, parts...)
}

// Lot is the issuer-side parking lot: in memory, keyed by id, with explicit
// expiry for both pending requests and unconsumed approvals.
type Lot struct {
	mu          sync.Mutex
	now         func() time.Time
	newID       func() (string, error)
	parkTTL     time.Duration
	approvalTTL time.Duration
	items       map[string]*ParkedRequest
}

// NewLot returns an empty lot on the given clock (nil means time.Now). Zero
// TTLs take the defaults.
func NewLot(now func() time.Time, parkTTL, approvalTTL time.Duration) *Lot {
	if now == nil {
		now = time.Now
	}
	if parkTTL <= 0 {
		parkTTL = DefaultParkTTL
	}
	if approvalTTL <= 0 {
		approvalTTL = DefaultApprovalTTL
	}
	return &Lot{
		now:         now,
		newID:       randomID,
		parkTTL:     parkTTL,
		approvalTTL: approvalTTL,
		items:       make(map[string]*ParkedRequest),
	}
}

// Park records an out-of-grant request and returns its id immediately. It
// never blocks: the exchange answers "parked, id=X" and the agent polls on a
// later heartbeat.
func (l *Lot) Park(agent, grantID string, rev Reversibility, description string, requestHash []byte) (string, error) {
	switch {
	case agent == "":
		return "", fmt.Errorf("%w: no agent", ErrParkedInvalid)
	case rev != Reversible && rev != Irreversible:
		return "", fmt.Errorf("%w: reversibility %q", ErrParkedInvalid, rev)
	case len(requestHash) != RequestHashSize:
		return "", fmt.Errorf("%w: request hash length %d", ErrParkedInvalid, len(requestHash))
	}
	id, err := l.newID()
	if err != nil {
		return "", err
	}
	now := l.now()
	item := &ParkedRequest{
		ID:            id,
		Agent:         agent,
		GrantID:       grantID,
		Reversibility: rev,
		Description:   description,
		RequestHash:   slices.Clone(requestHash),
		State:         ParkedPending,
		ParkedAt:      now,
		ExpiresAt:     now.Add(l.parkTTL),
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items[id] = item
	return id, nil
}

// Poll returns the current state of a parked request without blocking.
func (l *Lot) Poll(id string) (ParkedRequest, error) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.items[id]
	if !ok {
		return ParkedRequest{}, ErrParkedNotFound
	}
	l.refresh(item, now)
	return copyParked(item), nil
}

// Pending lists pending requests of one reversibility, oldest first: the
// morning list for Reversible, the one-at-a-time presence queue for
// Irreversible.
func (l *Lot) Pending(rev Reversibility) []ParkedRequest {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []ParkedRequest
	for _, item := range l.items {
		l.refresh(item, now)
		if item.State == ParkedPending && item.Reversibility == rev {
			out = append(out, copyParked(item))
		}
	}
	slices.SortFunc(out, func(a, b ParkedRequest) int {
		if c := a.ParkedAt.Compare(b.ParkedAt); c != 0 {
			return c
		}
		return compareStrings(a.ID, b.ID)
	})
	return out
}

// Approve approves one pending request with presence. v must be bound to the
// request's own hash (never pre-signed, never a touch for something else)
// and verified no earlier than the request was parked. Works for either
// reversibility; an irreversible request has no other path.
func (l *Lot) Approve(id string, v *Verified) error {
	if !v.Valid() {
		return ErrPresenceRequired
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.items[id]
	if !ok {
		return ErrParkedNotFound
	}
	l.refresh(item, now)
	if err := pendingOnly(item); err != nil {
		return err
	}
	if !equalBytes(v.RequestHash, item.RequestHash) {
		return ErrRequestHashMismatch
	}
	if v.VerifiedAt.Before(item.ParkedAt) {
		return ErrPreSigned
	}
	l.approve(item, v, now)
	return nil
}

// ApproveBatch approves a set of pending reversible requests with one touch.
// v must be bound to BatchHash(ids) and verified no earlier than the newest
// item in the batch. Any irreversible id refuses the whole batch
// (ErrIrreversibleInBatch); any unknown or non-pending id refuses it too, so
// a batch is all or nothing.
func (l *Lot) ApproveBatch(ids []string, v *Verified) error {
	if !v.Valid() {
		return ErrPresenceRequired
	}
	ids = normalizeSet(ids)
	if len(ids) == 0 {
		return fmt.Errorf("%w: empty batch", ErrParkedInvalid)
	}
	if !equalBytes(v.RequestHash, BatchHash(ids)) {
		return ErrRequestHashMismatch
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	items := make([]*ParkedRequest, 0, len(ids))
	for _, id := range ids {
		item, ok := l.items[id]
		if !ok {
			return fmt.Errorf("%w: %s", ErrParkedNotFound, id)
		}
		l.refresh(item, now)
		if item.Reversibility != Reversible {
			return fmt.Errorf("%w: %s", ErrIrreversibleInBatch, id)
		}
		if err := pendingOnly(item); err != nil {
			return fmt.Errorf("%w: %s", err, id)
		}
		if v.VerifiedAt.Before(item.ParkedAt) {
			return fmt.Errorf("%w: %s", ErrPreSigned, id)
		}
		items = append(items, item)
	}
	for _, item := range items {
		l.approve(item, v, now)
	}
	return nil
}

// Deny refuses a pending request. Terminal.
func (l *Lot) Deny(id string) error {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.items[id]
	if !ok {
		return ErrParkedNotFound
	}
	l.refresh(item, now)
	if err := pendingOnly(item); err != nil {
		return err
	}
	item.State = ParkedDenied
	return nil
}

// Consume redeems an approval exactly once and returns the request so the
// agent can run it. A second consume, an expired approval, or a request in
// any other state each refuse with their own error.
func (l *Lot) Consume(id string) (ParkedRequest, error) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.items[id]
	if !ok {
		return ParkedRequest{}, ErrParkedNotFound
	}
	l.refresh(item, now)
	switch item.State {
	case ParkedApproved:
		item.State = ParkedConsumed
		return copyParked(item), nil
	case ParkedConsumed:
		return ParkedRequest{}, ErrParkedConsumed
	case ParkedExpired:
		return ParkedRequest{}, ErrParkedExpired
	default:
		return ParkedRequest{}, fmt.Errorf("%w: state %s", ErrParkedNotApproved, item.State)
	}
}

// Sweep drops terminal items older than keep and returns how many were
// dropped. The lot is bounded by the agent's request rate otherwise.
func (l *Lot) Sweep(keep time.Duration) int {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for id, item := range l.items {
		l.refresh(item, now)
		switch item.State {
		case ParkedConsumed, ParkedDenied, ParkedExpired:
			if now.Sub(item.ParkedAt) > keep {
				delete(l.items, id)
				n++
			}
		}
	}
	return n
}

func (l *Lot) approve(item *ParkedRequest, v *Verified, now time.Time) {
	item.State = ParkedApproved
	item.ApprovedAt = now
	item.ApprovalExpiresAt = now.Add(l.approvalTTL)
	item.ApprovedBy = v.DeviceID
}

// refresh applies expiry to an item under the lock.
func (l *Lot) refresh(item *ParkedRequest, now time.Time) {
	switch item.State {
	case ParkedPending:
		if !now.Before(item.ExpiresAt) {
			item.State = ParkedExpired
		}
	case ParkedApproved:
		if !now.Before(item.ApprovalExpiresAt) {
			item.State = ParkedExpired
		}
	}
}

func pendingOnly(item *ParkedRequest) error {
	switch item.State {
	case ParkedPending:
		return nil
	case ParkedExpired:
		return ErrParkedExpired
	default:
		return fmt.Errorf("%w: state %s", ErrParkedNotPending, item.State)
	}
}

func copyParked(item *ParkedRequest) ParkedRequest {
	c := *item
	c.RequestHash = slices.Clone(item.RequestHash)
	return c
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
