package presence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultChallengeTTL is how long a minted challenge may wait for its
// signature: two minutes. A presence prompt is answered in seconds, and the
// OS prompt itself times out well inside this, so two minutes covers a human
// reaching for the sensor and a slow retry, nothing more. Longer widens the
// interval in which a minted-but-unsigned challenge sits in issuer memory;
// shorter starts failing honest prompts on a slow laptop. It trades
// tolerance for a distracted human against the size of the outstanding set.
const DefaultChallengeTTL = 2 * time.Minute

// Rejection errors. Each is distinct because the audit line records which; a
// verifier never collapses them into one "invalid". Two facts to know when
// reading them: a challenge is spent on its first presentation whatever the
// outcome, so a rejected assertion cannot be corrected and retried; and
// ErrBadSignature covers both a wrong key and a signature over the wrong bytes
// (a canonicalization attack), because ECDSA cannot tell those apart.
var (
	// ErrUnsupportedVersion: the assertion carries an encoding version this
	// verifier does not implement.
	ErrUnsupportedVersion = errors.New("presence: unsupported assertion version")
	// ErrUnknownChallenge: the challenge was not minted by this verifier. An
	// attacker cannot mint their own; the verifier rejects a challenge it did
	// not mint.
	ErrUnknownChallenge = errors.New("presence: challenge not minted by this issuer")
	// ErrChallengeReplayed: the challenge was already presented. Challenges
	// are single-use.
	ErrChallengeReplayed = errors.New("presence: challenge already spent")
	// ErrChallengeExpired: the challenge is older than its mint TTL.
	ErrChallengeExpired = errors.New("presence: challenge expired")
	// ErrNoPresenceKey: the expectation carries a nil presence key. That is
	// what platform.Key.PresencePublic returns on a level with no presence
	// capability at all, so there is no valid assertion to verify: the device
	// is presence "none" and its Sign would have returned
	// platform.ErrPresenceUnavailable. Distinct from a bad signature on
	// purpose; the audit line must say "this device cannot assert presence",
	// not "signature failed".
	ErrNoPresenceKey = errors.New("presence: device has no presence key")
	// ErrUnsupportedPresenceKey: the presence key is present but not ECDSA
	// P-256 (the only algorithm the spec allows for device keys).
	ErrUnsupportedPresenceKey = errors.New("presence: presence key is not ECDSA P-256")
	// ErrDeviceMismatch: the assertion is bound to a different device than
	// the one the issuer is exchanging for.
	ErrDeviceMismatch = errors.New("presence: assertion bound to a different device")
	// ErrToolMismatch: the assertion is bound to a different tool.
	ErrToolMismatch = errors.New("presence: assertion bound to a different tool")
	// ErrTargetMismatch: the human approved a different target than the one
	// being exchanged for.
	ErrTargetMismatch = errors.New("presence: assertion bound to a different target")
	// ErrRequestHashRequired: a presence:always target needs an assertion
	// bound to the request and this one is not.
	ErrRequestHashRequired = errors.New("presence: request hash required for this target")
	// ErrRequestHashUnexpected: the assertion is bound to a request but the
	// target is windowed; a request-bound assertion is never reusable and
	// must not open a window.
	ErrRequestHashUnexpected = errors.New("presence: request hash present but not expected")
	// ErrRequestHashMismatch: the assertion is bound to a different request
	// than the one being exchanged for.
	ErrRequestHashMismatch = errors.New("presence: request hash does not match request")
	// ErrBadSignature: the signature does not verify under the enrolled key
	// over the canonical bytes. Wrong key, altered field, truncated or
	// extended encoding all land here.
	ErrBadSignature = errors.New("presence: signature does not verify")
	// ErrExpectation: the issuer's expectation is itself inconsistent (for
	// example, BindingRequired with no request hash to compare against). This
	// is an issuer bug, never a caller outcome, and it still refuses.
	ErrExpectation = errors.New("presence: inconsistent expectation")
)

// Binding says whether the issuer expects the assertion to be bound to a
// request hash.
type Binding int

const (
	// BindingNone: a window touch. The assertion must not carry a request
	// hash.
	BindingNone Binding = iota
	// BindingRequired: a presence:always target. The assertion must carry the
	// hash of exactly this request.
	BindingRequired
)

// Expectation is what the issuer knows about the exchange it is verifying
// presence for: which enrolled key, which device, which tool and target, and
// whether the request must be bound.
type Expectation struct {
	// PresenceKey is the device's enrolled PRESENCE public key: the value
	// platform.Key.PresencePublic returned at enrollment, as *ecdsa.PublicKey
	// on P-256. It is deliberately not named PublicKey. On Apple silicon the
	// device has two Secure Enclave keys, a device key with no presence ACL
	// that signs silent SVID renewals and a companion key with a
	// user-presence ACL that signs assertions; verifying against the device
	// key (Key.Public) would accept a signature no human gated. Nil means the
	// level has no presence capability and Verify returns ErrNoPresenceKey.
	PresenceKey crypto.PublicKey
	// DeviceID the exchange is for.
	DeviceID string
	// Tool the exchange is for.
	Tool string
	// Target the exchange is for, as the prompt named it.
	Target string
	// Binding says whether a request hash is required or forbidden.
	Binding Binding
	// RequestHash is the issuer's own hash of the request it received; only
	// read when Binding is BindingRequired.
	RequestHash []byte
}

// Verified is the issuer's proof that a human was present for one exchange. It
// is produced only by Verifier.Verify and is the value the rest of this
// package accepts wherever presence is required (opening a session, sponsoring
// a grant, re-widening, approving a parked request). A Verified constructed by
// hand is rejected everywhere, because only Verify sets the unexported marker.
//
// A Verified is single-use, like the challenge behind it: the first consumer
// that accepts it (Touch, Sponsor, Widen, Approve, ApproveBatch) marks it
// used and every later consumer refuses it with ErrPresenceConsumed. One
// touch, one purpose. Pass it by pointer; it must not be copied.
type Verified struct {
	// DeviceID the human was present on.
	DeviceID string
	// Tool the assertion authorized.
	Tool string
	// Target the human approved.
	Target string
	// RequestHash the assertion was bound to, or nil for a window touch.
	RequestHash []byte
	// Challenge that was spent; unique per assertion.
	Challenge []byte
	// VerifiedAt is the issuer clock at verification; it is the human's
	// authorization time recorded on the credential.
	VerifiedAt time.Time

	ok   bool
	used atomic.Bool
}

// Valid reports whether v was produced by Verify. It does not say whether v
// has been used; consumers find that out when they consume it.
func (v *Verified) Valid() bool { return v != nil && v.ok }

// Used reports whether a consumer has already accepted v.
func (v *Verified) Used() bool { return v != nil && v.used.Load() }

// consume marks v used. It is called by every consumer after all its other
// checks pass, so a refused use does not burn the proof, and exactly one
// consumer ever succeeds.
func (v *Verified) consume() error {
	if !v.Valid() {
		return ErrPresenceRequired
	}
	if v.used.Swap(true) {
		return ErrPresenceConsumed
	}
	return nil
}

// Presence-proof errors shared by every consumer of a Verified.
var (
	// ErrPresenceRequired is returned wherever a Verified is required and
	// none, or a hand-built one, was supplied.
	ErrPresenceRequired = errors.New("presence: a verified presence assertion is required")
	// ErrPresenceConsumed is returned when a Verified is presented to a second
	// consumer. One touch authorizes one thing.
	ErrPresenceConsumed = errors.New("presence: presence assertion already used")
	// ErrTooManyChallenges: the device already has MaxOutstandingChallenges
	// unspent challenges. A flood of mints is itself the alarm; refusing keeps
	// issuer memory bounded by devices, not by whatever a same-uid process
	// wants to send.
	ErrTooManyChallenges = errors.New("presence: too many outstanding challenges for device")
)

// MaxOutstandingChallenges is the most unspent, unexpired challenges one device
// may hold. A human answers one prompt at a time; a few dozen covers every
// tool on the machine prompting at once with room to spare.
const MaxOutstandingChallenges = 64

// Verifier mints challenges and verifies assertions against them. It is the
// issuer-side half of the assertion and holds the only record of which
// challenges exist. Minted challenges are in memory only, single-use, and
// expire on their TTL.
type Verifier struct {
	mu        sync.Mutex
	now       func() time.Time
	rand      io.Reader
	ttl       time.Duration
	minted    map[[ChallengeSize]byte]*mintedChallenge
	perDevice map[string]int
	lastSweep time.Time
}

type mintedChallenge struct {
	device string
	at     time.Time
	spent  bool
}

// NewVerifier returns a verifier whose challenges expire after ttl (zero
// means DefaultChallengeTTL). now is the issuer clock; nil means time.Now.
func NewVerifier(ttl time.Duration, now func() time.Time) *Verifier {
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		now:       now,
		rand:      rand.Reader,
		ttl:       ttl,
		minted:    make(map[[ChallengeSize]byte]*mintedChallenge),
		perDevice: make(map[string]int),
	}
}

// Mint issues a fresh single-use challenge for deviceID and records it. The
// challenge can only be spent by an assertion for that device. A device with
// MaxOutstandingChallenges unspent challenges is refused
// (ErrTooManyChallenges). Expired challenges are swept at most once per
// quarter TTL, so a flood of mints costs the issuer a map insert each, not a
// full scan each.
func (v *Verifier) Mint(deviceID string) ([]byte, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("%w: mint for empty device", ErrMalformed)
	}
	var c [ChallengeSize]byte
	if _, err := io.ReadFull(v.rand, c[:]); err != nil {
		return nil, fmt.Errorf("presence: mint: %w", err)
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep(now)
	if v.perDevice[deviceID] >= MaxOutstandingChallenges {
		return nil, fmt.Errorf("%w: %s", ErrTooManyChallenges, deviceID)
	}
	v.minted[c] = &mintedChallenge{device: deviceID, at: now}
	v.perDevice[deviceID]++
	return c[:], nil
}

// sweep drops expired challenges, under the lock, at most once per quarter
// TTL unless forced by a cap check.
func (v *Verifier) sweep(now time.Time) {
	if !v.lastSweep.IsZero() && now.Sub(v.lastSweep) < v.ttl/4 {
		return
	}
	v.lastSweep = now
	for k, m := range v.minted {
		if now.Sub(m.at) > v.ttl {
			v.forget(k, m)
		}
	}
}

// forget removes a minted challenge and releases its device slot if it was
// still counted as outstanding.
func (v *Verifier) forget(k [ChallengeSize]byte, m *mintedChallenge) {
	if !m.spent {
		v.release(m.device)
	}
	delete(v.minted, k)
}

func (v *Verifier) release(device string) {
	if v.perDevice[device] <= 1 {
		delete(v.perDevice, device)
		return
	}
	v.perDevice[device]--
}

// Outstanding reports how many minted challenges are unspent and unexpired.
func (v *Verifier) Outstanding() int {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, m := range v.minted {
		if !m.spent && now.Sub(m.at) <= v.ttl {
			n++
		}
	}
	return n
}

// Verify checks one assertion against the issuer's expectation and returns
// the Verified proof, or exactly one of the typed rejection errors. Order:
//
//  1. structure and version (ErrMalformed, ErrUnsupportedVersion): nothing
//     is spent for a malformed assertion;
//  2. challenge: unknown (never minted, or minted for another device),
//     replayed, expired. The challenge is spent here, on first presentation,
//     before anything else is decided;
//  3. presence key present (ErrNoPresenceKey) and P-256
//     (ErrUnsupportedPresenceKey);
//  4. device, tool, target bindings;
//  5. request-hash binding as the target's level requires;
//  6. signature over the reconstructed canonical bytes.
//
// The window itself is evaluated on the issuer, not the laptop: a compromised
// agent cannot extend its own window because it never decides freshness.
func (v *Verifier) Verify(a *Assertion, exp Expectation) (*Verified, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: nil assertion", ErrMalformed)
	}
	if a.Version != EncodingVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, a.Version)
	}
	in := a.signingInput()
	if err := in.validate(); err != nil {
		return nil, err
	}
	if len(a.Signature) == 0 {
		return nil, fmt.Errorf("%w: empty signature", ErrMalformed)
	}

	now := v.now()
	if err := v.spend(a.Challenge, exp.DeviceID, now); err != nil {
		return nil, err
	}

	if exp.PresenceKey == nil {
		return nil, ErrNoPresenceKey
	}
	pub, ok := exp.PresenceKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedPresenceKey, exp.PresenceKey)
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: curve %s", ErrUnsupportedPresenceKey, pub.Curve.Params().Name)
	}
	if a.DeviceID != exp.DeviceID {
		return nil, ErrDeviceMismatch
	}
	if a.Tool != exp.Tool {
		return nil, ErrToolMismatch
	}
	if a.Target != exp.Target {
		return nil, ErrTargetMismatch
	}
	switch exp.Binding {
	case BindingNone:
		if len(a.RequestHash) != 0 {
			return nil, ErrRequestHashUnexpected
		}
	case BindingRequired:
		if len(exp.RequestHash) != RequestHashSize {
			return nil, fmt.Errorf("%w: binding required with no request hash", ErrExpectation)
		}
		if len(a.RequestHash) == 0 {
			return nil, ErrRequestHashRequired
		}
		if !equalBytes(a.RequestHash, exp.RequestHash) {
			return nil, ErrRequestHashMismatch
		}
	default:
		return nil, fmt.Errorf("%w: unknown binding %d", ErrExpectation, exp.Binding)
	}

	bytes, err := in.Bytes()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(bytes)
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return nil, ErrBadSignature
	}

	return &Verified{
		DeviceID:    a.DeviceID,
		Tool:        a.Tool,
		Target:      a.Target,
		RequestHash: append([]byte(nil), a.RequestHash...),
		Challenge:   append([]byte(nil), a.Challenge...),
		VerifiedAt:  now,
		ok:          true,
	}, nil
}

// spend marks a challenge as presented. Unknown (including minted for another
// device), already spent, and expired challenges are each their own
// rejection. A challenge minted for another device is spent too: it was
// presented.
func (v *Verifier) spend(challenge []byte, deviceID string, now time.Time) error {
	var k [ChallengeSize]byte
	copy(k[:], challenge)
	v.mu.Lock()
	defer v.mu.Unlock()
	m, found := v.minted[k]
	if !found {
		return ErrUnknownChallenge
	}
	if m.spent {
		return ErrChallengeReplayed
	}
	if now.Sub(m.at) > v.ttl {
		v.forget(k, m)
		return ErrChallengeExpired
	}
	m.spent = true
	v.release(m.device)
	if m.device != deviceID {
		return fmt.Errorf("%w: minted for another device", ErrUnknownChallenge)
	}
	return nil
}

// equalBytes is a constant-time comparison; false on a length mismatch.
func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
