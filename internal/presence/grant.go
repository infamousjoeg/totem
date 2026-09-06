package presence

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"
)

// Grant timing from "Agents and delegation".
const (
	// DefaultGrantDuration is the thirty-day default expiry.
	DefaultGrantDuration = 30 * 24 * time.Hour
	// RenewalNotice is how far before expiry the renewal notification goes
	// out: three days.
	RenewalNotice = 3 * 24 * time.Hour
	// MaxGrantDuration is the longest a human can sign a grant for: ninety
	// days, three renewal cycles. The spec gives a thirty-day default and
	// says renewal requires presence; a grant that never needs renewing would
	// make that sentence meaningless, and the CLI rendering the grant should
	// not be the only thing between a human and a fifty-year signature.
	MaxGrantDuration = 90 * 24 * time.Hour
)

// TrivialMoneyUSD is the hard floor for delegated money: outward money
// movement above trivial is always presence, never delegated (decision 37).
// No grant, and no Money ceiling, can raise it; Money.Decide takes the smaller
// of this and the grant's own step-up threshold.
//
// The consequence, stated plainly because it is easy to miss: since the
// effective threshold is min(StepUpAboveUSD, TrivialMoneyUSD), no grant can
// authorize an unattended outward payment above $5.00, ever. A grant with a
// $1,000 per-transaction ceiling still parks every payment over $5 for a
// present human. That is deliberate. Changing this constant changes what an
// agent can spend with nobody watching.
const TrivialMoneyUSD = 5.0

// Grant errors.
var (
	// ErrGrantNotFound: no grant with that id.
	ErrGrantNotFound = errors.New("presence: grant not found")
	// ErrGrantRevoked: the grant, or one of its ancestors, was revoked.
	// Revocation is instant and reaches every sub-grant through lineage.
	ErrGrantRevoked = errors.New("presence: grant revoked")
	// ErrGrantExpired: the grant lapsed. The agent keeps running but its
	// credentials stop.
	ErrGrantExpired = errors.New("presence: grant expired")
	// ErrGrantInvalid: the grant is structurally unusable (no agent, expiry
	// not in the future or beyond MaxGrantDuration, lineage on a root).
	ErrGrantInvalid = errors.New("presence: grant invalid")
	// ErrNotHolder: a session may be opened only on the grant the caller's
	// credential names, or a descendant of it. Opening an ancestor from a
	// sub-grant credential would be the out-of-session route around
	// monotonic narrowing.
	ErrNotHolder = errors.New("presence: caller's grant does not cover the requested grant")
	// ErrGrantHashMismatch: the sponsoring assertion is not bound to this
	// grant's hash; the human signed something else.
	ErrGrantHashMismatch = errors.New("presence: sponsoring assertion not bound to this grant")
	// ErrNotNarrower: the requested sub-grant would add capability. Narrowing
	// only removes.
	ErrNotNarrower = errors.New("presence: sub-grant is not narrower than its parent")
	// ErrExpiryWidens: the requested sub-grant would outlive its parent.
	ErrExpiryWidens = errors.New("presence: sub-grant expiry is later than its parent")
	// ErrSessionNotFound: no agent session with that id.
	ErrSessionNotFound = errors.New("presence: agent session not found")
	// ErrNotAncestor: re-widening may only return to a grant in the active
	// grant's own lineage.
	ErrNotAncestor = errors.New("presence: target grant is not an ancestor of the active grant")
	// ErrRewidenRequiresPresence: returning to a wider grant needs a fresh
	// touch bound to exactly this widen, verified after the narrowing.
	// Unconditionally: "narrow, do the quiet thing, silently restore" is a
	// laundering path, and no clock condition makes it safe.
	ErrRewidenRequiresPresence = errors.New("presence: re-widening requires fresh presence")
)

// Money is the first-class money ceiling on a grant: per-transaction limit,
// per-day limit, and the amount above which a transaction steps up to
// presence even though it is inside the ceilings. A zero Money permits no
// money movement at all. Purchases span many relying parties and need a
// dimension ops grants lack: amount and velocity.
type Money struct {
	// PerTransactionUSD is the largest single transaction inside the grant.
	PerTransactionUSD float64
	// PerDayUSD is the largest running daily total inside the grant.
	PerDayUSD float64
	// StepUpAboveUSD is the in-grant threshold above which a transaction
	// requires a fresh touch. It is always capped by TrivialMoneyUSD: setting
	// it higher has no effect.
	StepUpAboveUSD float64
}

// MoneyVerdict is Money.Decide's answer.
type MoneyVerdict string

const (
	// MoneyDelegated: the amount is trivial and inside every ceiling; the
	// agent may spend under presence:delegated.
	MoneyDelegated MoneyVerdict = "delegated"
	// MoneyStepUp: inside the ceilings but above the step-up threshold or the
	// trivial floor; park as irreversible and wait for presence.
	MoneyStepUp MoneyVerdict = "step-up"
	// MoneyOverCeiling: outside the per-transaction or per-day ceiling (or a
	// negative amount); out of grant, park as irreversible. Approval does not
	// widen the grant.
	MoneyOverCeiling MoneyVerdict = "over-ceiling"
)

// Decide classifies one outward transaction of amountUSD given what the grant
// has already spent today. m is normalized first, so a NaN or negative
// ceiling reads as zero and cannot lift the floor; a NaN, negative, or
// infinite amount or running total is MoneyOverCeiling. A zero Money (no
// per-transaction ceiling) permits no movement at all, including a $0
// authorization hold.
func (m Money) Decide(amountUSD, spentTodayUSD float64) MoneyVerdict {
	m = m.normalize()
	if !finiteNonNegative(amountUSD) || !finiteNonNegative(spentTodayUSD) {
		return MoneyOverCeiling
	}
	threshold := TrivialMoneyUSD
	if m.StepUpAboveUSD < threshold {
		threshold = m.StepUpAboveUSD
	}
	switch {
	case m.PerTransactionUSD == 0:
		return MoneyOverCeiling
	case amountUSD > m.PerTransactionUSD:
		return MoneyOverCeiling
	case spentTodayUSD+amountUSD > m.PerDayUSD:
		return MoneyOverCeiling
	case amountUSD > threshold:
		return MoneyStepUp
	}
	return MoneyDelegated
}

func finiteNonNegative(f float64) bool {
	return f >= 0 && !math.IsInf(f, 0)
}

// Within reports whether m is no wider than parent on every axis. A lower
// step-up threshold is narrower, since it sends more to presence.
func (m Money) Within(parent Money) bool {
	return m.PerTransactionUSD <= parent.PerTransactionUSD &&
		m.PerDayUSD <= parent.PerDayUSD &&
		m.StepUpAboveUSD <= parent.StepUpAboveUSD
}

func (m Money) normalize() Money {
	return Money{
		PerTransactionUSD: nonNegative(m.PerTransactionUSD),
		PerDayUSD:         nonNegative(m.PerDayUSD),
		StepUpAboveUSD:    nonNegative(m.StepUpAboveUSD),
	}
}

// nonNegative maps NaN, negatives, and -0 to 0 so normalized scopes hash
// canonically; +Inf is clamped to the largest finite value so it still
// compares as a ceiling.
func nonNegative(f float64) float64 {
	if f <= 0 || math.IsNaN(f) {
		return 0
	}
	if math.IsInf(f, 1) {
		return math.MaxFloat64
	}
	return f
}

// Scope is the capability set a grant confers: which aws profiles, which
// GitHub repos and scopes, which entities and actions inside other relying
// parties, whether Claude via the proxy and under what spend cap, and the
// money ceilings.
//
// Scope holds capabilities and nothing else. Observability, logging, and
// revocability are not fields here, so no Scope, however narrow, can drop
// them: the empty Scope is the floor and it is still logged under its lineage
// and still revoked with its root. That is structural, not advisory. See
// Grant.Provenance and Registry.Revoke.
type Scope struct {
	// AWSProfiles the agent may use inside the grant.
	AWSProfiles []string
	// GitHubScopes (repos and scopes) the agent may use inside the grant.
	GitHubScopes []string
	// Capabilities are entity and action tiers inside other relying parties,
	// written "<relying-party>/<entity>#<action>", e.g.
	// "homeassistant/lock.front_door#unlock". Reading a freezer temperature
	// and unlocking a front door are the same credential; they are not the
	// same capability.
	Capabilities []string
	// ClaudeProxy allows Claude via the proxy under SpendCapUSD when true.
	ClaudeProxy bool
	// SpendCapUSD is the per-identity Claude spend cap that is the
	// runaway-agent fuse. Zero when ClaudeProxy is false.
	SpendCapUSD float64
	// Money is the outward money ceiling.
	Money Money
}

// Normalize returns a copy with sorted, de-duplicated sets, non-negative
// numbers, and SpendCapUSD zeroed when ClaudeProxy is off, so equal scopes
// compare and hash equal.
func (s Scope) Normalize() Scope {
	n := Scope{
		AWSProfiles:  normalizeSet(s.AWSProfiles),
		GitHubScopes: normalizeSet(s.GitHubScopes),
		Capabilities: normalizeSet(s.Capabilities),
		ClaudeProxy:  s.ClaudeProxy,
		Money:        s.Money.normalize(),
	}
	if s.ClaudeProxy {
		n.SpendCapUSD = nonNegative(s.SpendCapUSD)
	}
	return n
}

func normalizeSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	out = slices.Compact(out)
	return out
}

// Within reports whether s confers no capability parent does not: every set
// is a subset, ClaudeProxy is not newly on, the spend cap and every money
// ceiling are no higher. This is the monotonic-narrowing predicate.
func (s Scope) Within(parent Scope) bool {
	s, parent = s.Normalize(), parent.Normalize()
	if !subset(s.AWSProfiles, parent.AWSProfiles) ||
		!subset(s.GitHubScopes, parent.GitHubScopes) ||
		!subset(s.Capabilities, parent.Capabilities) {
		return false
	}
	if s.ClaudeProxy && !parent.ClaudeProxy {
		return false
	}
	if s.SpendCapUSD > parent.SpendCapUSD {
		return false
	}
	return s.Money.Within(parent.Money)
}

// subset reports whether every element of a (sorted) is in b (sorted).
func subset(a, b []string) bool {
	for _, x := range a {
		if _, found := slices.BinarySearch(b, x); !found {
			return false
		}
	}
	return true
}

// hashParts returns the scope's canonical framing for Grant.Hash.
func (s Scope) hashParts() [][]byte {
	s = s.Normalize()
	list := func(items []string) []byte {
		var b []byte
		for _, it := range items {
			b = appendField(b, []byte(it))
		}
		return b
	}
	flag := byte(0)
	if s.ClaudeProxy {
		flag = 1
	}
	return [][]byte{
		list(s.AWSProfiles),
		list(s.GitHubScopes),
		list(s.Capabilities),
		{flag},
		f64(s.SpendCapUSD),
		f64(s.Money.PerTransactionUSD),
		f64(s.Money.PerDayUSD),
		f64(s.Money.StepUpAboveUSD),
	}
}

func f64(v float64) []byte {
	return binary.BigEndian.AppendUint64(nil, math.Float64bits(v))
}

// Grant is the presence-signed artifact that lets a long-running agent operate
// without a prompt: which agent, which aws profiles, which GitHub repos and
// scopes, whether Claude via the proxy and under what spend cap, until when.
// The grant lives on the issuer; a hijacked agent gets exactly the grant, or
// the sub-grant it was wrapped in, and nothing else, and the human has a dated
// record of what was authorized.
//
// A root grant is sponsored by a human with presence (Registry.Sponsor). A
// sub-grant is derived by the agent itself, instantly, without presence
// (Registry.Narrow), and carries its parent's expiry, sponsor, signing time,
// and lineage.
type Grant struct {
	// ID is referenced by every credential issued under this grant.
	ID string
	// Agent is the agent SPIFFE name the grant is scoped to.
	Agent string
	// Sponsor is the enrolled device the human signed on.
	Sponsor string
	// Scope is the capability set.
	Scope Scope
	// Until is the grant expiry; 30-day default, renewal requires presence, a
	// notification goes out three days before, and if it lapses the agent
	// keeps running but its credentials stop. A sub-grant's Until is never
	// later than its parent's.
	Until time.Time
	// SignedAt is the human's signing time, recorded on every delegated
	// credential alongside ID so provenance is legible. Sub-grants inherit it
	// unchanged: the human signed once.
	SignedAt time.Time
	// Lineage is the chain of grant IDs from the root down to the parent;
	// empty for a root grant. It is set by the Registry, never by the caller,
	// and it is how revocation and audit reach every sub-grant.
	Lineage []string
	// DerivedAt is when this grant came into being: SignedAt for a root,
	// the narrowing time for a sub-grant.
	DerivedAt time.Time
}

// NewGrant is the convenience constructor for a root grant a human is about
// to sign: agent, scope, and the thirty-day default expiry from now. The
// caller hashes it (Hash), mints a challenge, has the human sign with the hash
// as the request hash, and passes both to Registry.Sponsor.
func NewGrant(agent string, scope Scope, now time.Time) Grant {
	return Grant{Agent: agent, Scope: scope.Normalize(), Until: now.Add(DefaultGrantDuration)}
}

// Hash is the canonical digest of what the human signs: agent, expiry, and
// scope. ID, sponsor, signing time and lineage are set by the registry from
// the sponsoring assertion and are not part of it.
func (g Grant) Hash() []byte {
	parts := [][]byte{
		[]byte(g.Agent),
		binary.BigEndian.AppendUint64(nil, uint64(g.Until.UnixNano())),
	}
	parts = append(parts, g.Scope.hashParts()...)
	return hashParts(contextGrant, parts...)
}

// RootID is the ID of the human-signed grant this one descends from (its own
// ID for a root).
func (g Grant) RootID() string {
	if len(g.Lineage) == 0 {
		return g.ID
	}
	return g.Lineage[0]
}

// ParentID is the ID of the grant this one was narrowed from, or empty for a
// root.
func (g Grant) ParentID() string {
	if len(g.Lineage) == 0 {
		return ""
	}
	return g.Lineage[len(g.Lineage)-1]
}

// RenewalDue reports whether the three-day renewal notice is due.
func (g Grant) RenewalDue(now time.Time) bool {
	return !now.Before(g.Until.Add(-RenewalNotice))
}

// Provenance is what every credential minted under a grant must carry so it
// answers "who authorized this": presence=delegated, the grant ID, the root
// grant ID and full lineage, the sponsor, and the human's signing time. It is
// derived from the grant, so a sub-grant cannot omit it.
type Provenance struct {
	// State is always StateDelegated for a grant-issued credential.
	State State
	// GrantID is the grant the credential was minted under.
	GrantID string
	// RootID is the human-signed grant at the top of the lineage.
	RootID string
	// Lineage is root..parent; empty for a root.
	Lineage []string
	// Sponsor is the device the human signed on.
	Sponsor string
	// SignedAt is the human's signing time.
	SignedAt time.Time
}

// Provenance returns the provenance record for a credential minted under g.
func (g Grant) Provenance() Provenance {
	return Provenance{
		State:    StateDelegated,
		GrantID:  g.ID,
		RootID:   g.RootID(),
		Lineage:  slices.Clone(g.Lineage),
		Sponsor:  g.Sponsor,
		SignedAt: g.SignedAt,
	}
}

// AgentSession is one agent's live position in its grant tree: which grant
// is active now, and when it last narrowed. It exists so that narrowing is
// monotonic within a session and re-widening can be gated.
type AgentSession struct {
	// ID of the session.
	ID string
	// Agent the session belongs to.
	Agent string
	// ActiveGrantID is the grant credentials are currently minted under.
	ActiveGrantID string
	// NarrowedAt is the last time the session narrowed; zero if never. A
	// widening assertion verified before it (strictly) cannot widen.
	NarrowedAt time.Time
}

// WidenHash is the request hash a re-widening assertion must be bound to:
// this session, back to that grant. A touch for anything else cannot widen.
func WidenHash(sessionID, toGrantID string) []byte {
	return hashParts(contextWiden, []byte(sessionID), []byte(toGrantID))
}

// Registry holds grants, revocations, and agent sessions on the issuer. It is
// the only source of sub-grants: lineage is computed here from the parent, so
// a caller cannot mint a grant that escapes its ancestors' revocation or
// audit. Grant storage on disk is the issuer's concern; this type is the
// in-memory authority the issuer consults on every exchange.
type Registry struct {
	mu       sync.Mutex
	now      func() time.Time
	newID    func() (string, error)
	grants   map[string]*Grant
	revoked  map[string]time.Time
	sessions map[string]*AgentSession
}

// NewRegistry returns an empty registry on the given clock (nil means
// time.Now).
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{
		now:      now,
		newID:    randomID,
		grants:   make(map[string]*Grant),
		revoked:  make(map[string]time.Time),
		sessions: make(map[string]*AgentSession),
	}
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("presence: id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Sponsor records a root grant a human just signed. v must be a Verified
// produced by Verify whose request hash is g.Hash(): the human touched the
// sensor for exactly this agent, scope, and expiry. The registry assigns the
// ID, sponsor device, and signing time from v.
func (r *Registry) Sponsor(g Grant, v *Verified) (*Grant, error) {
	if !v.Valid() {
		return nil, ErrPresenceRequired
	}
	now := r.now()
	switch {
	case g.Agent == "":
		return nil, fmt.Errorf("%w: no agent", ErrGrantInvalid)
	case !g.Until.After(now):
		return nil, fmt.Errorf("%w: expiry not in the future", ErrGrantInvalid)
	case g.Until.Sub(now) > MaxGrantDuration:
		return nil, fmt.Errorf("%w: expiry more than %s out", ErrGrantInvalid, MaxGrantDuration)
	case len(g.Lineage) != 0 || g.ID != "":
		return nil, fmt.Errorf("%w: a sponsored grant is a root", ErrGrantInvalid)
	}
	if !equalBytes(v.RequestHash, g.Hash()) {
		return nil, ErrGrantHashMismatch
	}
	if err := v.consume(); err != nil {
		return nil, err
	}
	id, err := r.newID()
	if err != nil {
		return nil, err
	}
	root := &Grant{
		ID:        id,
		Agent:     g.Agent,
		Sponsor:   v.DeviceID,
		Scope:     g.Scope.Normalize(),
		Until:     g.Until,
		SignedAt:  v.VerifiedAt,
		DerivedAt: v.VerifiedAt,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grants[id] = root
	return copyGrant(root), nil
}

// Get returns an active grant by id, or ErrGrantNotFound, ErrGrantRevoked
// (itself or any ancestor), or ErrGrantExpired.
func (r *Registry) Get(id string) (*Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, err := r.active(id, r.now())
	if err != nil {
		return nil, err
	}
	return copyGrant(g), nil
}

// active is Get under the lock.
func (r *Registry) active(id string, now time.Time) (*Grant, error) {
	g, ok := r.grants[id]
	if !ok {
		return nil, ErrGrantNotFound
	}
	if _, rev := r.revoked[g.ID]; rev {
		return nil, ErrGrantRevoked
	}
	for _, anc := range g.Lineage {
		if _, rev := r.revoked[anc]; rev {
			return nil, fmt.Errorf("%w: ancestor %s", ErrGrantRevoked, anc)
		}
	}
	if !now.Before(g.Until) {
		return nil, ErrGrantExpired
	}
	return g, nil
}

// Revoke revokes a grant instantly. Every sub-grant below it is revoked with
// it, not by walking and marking children but because Get checks the
// lineage: there is no descendant the revocation can miss. Revoking an
// unknown id is not an error; the outcome is the same.
func (r *Registry) Revoke(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[id] = r.now()
}

// Open starts an agent session on an active grant. presentedGrantID is the
// grant named by the credential the caller attested with; the issuer MUST
// take it from that credential's provenance and never from the request body.
// grantID must be the presented grant itself or one of its descendants
// (ErrNotHolder otherwise), so a caller wrapped in a sub-grant cannot open a
// fresh session on an ancestor and walk around monotonic narrowing without
// presence. The common case passes the same id twice. The session's active
// grant is grantID until it narrows.
func (r *Registry) Open(presentedGrantID, grantID string) (*AgentSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if _, err := r.active(presentedGrantID, now); err != nil {
		return nil, err
	}
	g, err := r.active(grantID, now)
	if err != nil {
		return nil, err
	}
	if g.ID != presentedGrantID && !slices.Contains(g.Lineage, presentedGrantID) {
		return nil, ErrNotHolder
	}
	id, err := r.newID()
	if err != nil {
		return nil, err
	}
	s := &AgentSession{ID: id, Agent: g.Agent, ActiveGrantID: g.ID}
	r.sessions[id] = s
	return copySession(s), nil
}

// Session returns the current state of an agent session.
func (r *Registry) Session(sessionID string) (*AgentSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return copySession(s), nil
}

// Active returns the session's active grant, subject to the same checks as
// Get.
func (r *Registry) Active(sessionID string) (*Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	g, err := r.active(s.ActiveGrantID, r.now())
	if err != nil {
		return nil, err
	}
	return copyGrant(g), nil
}

// Narrow derives a sub-grant under the session's active grant and makes it
// the active grant. It is instant and needs no presence, because it can only
// remove: scope must be Within the parent's (ErrNotNarrower), until must not
// be later than the parent's (ErrExpiryWidens; zero inherits). The child
// keeps the parent's agent, sponsor, signing time, and lineage plus the
// parent's ID, so the audit chain stays whole and the parent ceiling still
// binds.
func (r *Registry) Narrow(sessionID string, scope Scope, until time.Time) (*Grant, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	parent, err := r.active(s.ActiveGrantID, now)
	if err != nil {
		return nil, err
	}
	if !scope.Within(parent.Scope) {
		return nil, ErrNotNarrower
	}
	if until.IsZero() {
		until = parent.Until
	}
	if until.After(parent.Until) {
		return nil, ErrExpiryWidens
	}
	id, err := r.newID()
	if err != nil {
		return nil, err
	}
	child := &Grant{
		ID:        id,
		Agent:     parent.Agent,
		Sponsor:   parent.Sponsor,
		Scope:     scope.Normalize(),
		Until:     until,
		SignedAt:  parent.SignedAt,
		Lineage:   append(slices.Clone(parent.Lineage), parent.ID),
		DerivedAt: now,
	}
	r.grants[id] = child
	s.ActiveGrantID = id
	s.NarrowedAt = now
	return copyGrant(child), nil
}

// Widen returns the session to an ancestor of its active grant. It always
// requires v, a Verified bound to WidenHash(sessionID, toGrantID) and
// verified not before the narrowing (equal instants pass; both stamps are
// issuer clocks): fresh presence, for exactly this widen, every time, and the
// Verified is consumed. The target must be in the active grant's lineage
// (ErrNotAncestor) and still active. Nothing is re-derived; the ancestor
// simply becomes active again.
func (r *Registry) Widen(sessionID, toGrantID string, v *Verified) (*Grant, error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	cur, err := r.active(s.ActiveGrantID, now)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(cur.Lineage, toGrantID) {
		return nil, ErrNotAncestor
	}
	target, err := r.active(toGrantID, now)
	if err != nil {
		return nil, err
	}
	if !v.Valid() {
		return nil, ErrRewidenRequiresPresence
	}
	if !equalBytes(v.RequestHash, WidenHash(sessionID, toGrantID)) {
		return nil, fmt.Errorf("%w: assertion bound to a different widen", ErrRewidenRequiresPresence)
	}
	if v.VerifiedAt.Before(s.NarrowedAt) {
		return nil, fmt.Errorf("%w: assertion predates the narrowing", ErrRewidenRequiresPresence)
	}
	if err := v.consume(); err != nil {
		return nil, err
	}
	s.ActiveGrantID = target.ID
	return copyGrant(target), nil
}

func copyGrant(g *Grant) *Grant {
	c := *g
	c.Lineage = slices.Clone(g.Lineage)
	c.Scope = g.Scope.Normalize()
	return &c
}

func copySession(s *AgentSession) *AgentSession {
	c := *s
	return &c
}
