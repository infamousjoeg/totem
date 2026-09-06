package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
)

// Timing.
const (
	// PendingTTL is how long an enrollment waits for an admin: "the code is
	// single-use and expires in minutes".
	PendingTTL = 10 * time.Minute
	// BootstrapTTL is the bootstrap code's ten-minute expiry.
	BootstrapTTL = 10 * time.Minute
	// MaxObservations bounds what one shadow grant records, so a runaway
	// agent under shadow cannot grow issuer memory for a month.
	MaxObservations = 100_000
)

// Store collections and chain kinds. Kinds are dot-separated, never slash:
// the store's name charset forbids path separators because a kind becomes a
// tar entry name in a backup, and internal/ca already chains "svid.issued",
// so one chain has one convention.
const (
	collectionBootstrap = "bootstrap"
	bootstrapID         = "code"
	kindPolicyPrefix    = "policy."
	kindGrantNarrow     = "grant.narrow"
	kindSession         = "grant.session"
	kindExchange        = "exchange"
	kindParked          = "parked"
)

// signedRecord is one admin-signed policy change as chained. It lives ONLY
// in the hash chain: reload walks the chain and rebuilds state from it, so
// there is no second copy a host could edit without breaking a link. The
// digest the signer bound is recomputed from Action, Subject and the chained
// Payload bytes, and the signature is re-verified on every load against the
// key the signer's own earlier enrollment record holds, so a record written
// around the signature check does not survive a restart even if the chain
// was rebuilt around it.
type signedRecord struct {
	Ordinal int64     `json:"ordinal"`
	Action  Action    `json:"action"`
	At      time.Time `json:"at"`
	Subject string    `json:"subject"`
	// Payload is the action-specific body, the exact bytes that were digested.
	Payload json.RawMessage `json:"payload"`
	// Signer is the device that signed, and SignerPresence whether a human
	// was present for it: present when the assertion verified under the
	// signer's presence key, none when the signer has no presence key and
	// signed with its device key.
	Signer         string         `json:"signer"`
	SignerPresence presence.State `json:"signer_presence"`
	// Assertion is the signature itself.
	Assertion assertionJSON `json:"assertion"`
}

// assertionJSON is presence.Assertion with wire tags.
type assertionJSON struct {
	Version     uint8  `json:"version"`
	DeviceID    string `json:"device_id"`
	Tool        string `json:"tool"`
	Target      string `json:"target"`
	Challenge   []byte `json:"challenge"`
	Signature   []byte `json:"signature"`
	RequestHash []byte `json:"request_hash,omitempty"`
}

func toJSON(a *presence.Assertion) assertionJSON {
	return assertionJSON{
		Version: a.Version, DeviceID: a.DeviceID, Tool: a.Tool, Target: a.Target,
		Challenge: a.Challenge, Signature: a.Signature, RequestHash: a.RequestHash,
	}
}

func (a assertionJSON) assertion() *presence.Assertion {
	return &presence.Assertion{
		Version: a.Version, DeviceID: a.DeviceID, Tool: a.Tool, Target: a.Target,
		Challenge: a.Challenge, Signature: a.Signature, RequestHash: a.RequestHash,
	}
}

// enrollmentPayload is the body of an approve record: the device's own two
// enrollment signatures, so a stored enrollment re-proves possession and
// presence on load, plus the inventory fields the approver saw.
type enrollmentPayload struct {
	Input             enrollmentInputJSON `json:"input"`
	Signature         []byte              `json:"signature"`
	PresenceSignature []byte              `json:"presence_signature,omitempty"`
	Name              string              `json:"name,omitempty"`
	Founding          bool                `json:"founding,omitempty"`
}

type enrollmentInputJSON struct {
	Version           uint8  `json:"version"`
	Challenge         []byte `json:"challenge"`
	IssuerFingerprint []byte `json:"issuer_fingerprint"`
	DevicePublicKey   []byte `json:"device_public_key"`
	PresencePublicKey []byte `json:"presence_public_key,omitempty"`
	ProtectionLevel   string `json:"protection_level"`
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
	FirstContact      string `json:"first_contact"`
	BootstrapCodeHash []byte `json:"bootstrap_code_hash,omitempty"`
}

func inputToJSON(in presence.EnrollmentInput) enrollmentInputJSON {
	return enrollmentInputJSON{
		Version: in.Version, Challenge: in.Challenge, IssuerFingerprint: in.IssuerFingerprint,
		DevicePublicKey: in.DevicePublicKey, PresencePublicKey: in.PresencePublicKey,
		ProtectionLevel: string(in.ProtectionLevel), Hostname: in.Hostname, OS: in.OS,
		FirstContact: string(in.FirstContact), BootstrapCodeHash: in.BootstrapCodeHash,
	}
}

func (j enrollmentInputJSON) input() presence.EnrollmentInput {
	return presence.EnrollmentInput{
		Version: j.Version, Challenge: j.Challenge, IssuerFingerprint: j.IssuerFingerprint,
		DevicePublicKey: j.DevicePublicKey, PresencePublicKey: j.PresencePublicKey,
		ProtectionLevel: protectionLevel(j.ProtectionLevel), Hostname: j.Hostname, OS: j.OS,
		FirstContact: presence.FirstContact(j.FirstContact), BootstrapCodeHash: j.BootstrapCodeHash,
	}
}

// devicePayload is the body of grant-admin, revoke-admin and revoke.
type devicePayload struct {
	DeviceID string `json:"device_id"`
	Admin    bool   `json:"admin"`
	Revoked  bool   `json:"revoked"`
}

// windowsPayload is the body of a presence-policy record.
type windowsPayload struct {
	Windows []windowJSON `json:"windows"`
}

type windowJSON struct {
	Tool     string `json:"tool"`
	Target   string `json:"target,omitempty"`
	Group    string `json:"group,omitempty"`
	Duration int64  `json:"duration_ns"`
	Level    string `json:"level"`
}

// grantPayload is the body of a grant or shadow record: the grant as
// registered, with the ID the registry assigned.
type grantPayload struct {
	ID       string    `json:"id"`
	Agent    string    `json:"agent"`
	Sponsor  string    `json:"sponsor"`
	Scope    scopeJSON `json:"scope"`
	Until    time.Time `json:"until"`
	SignedAt time.Time `json:"signed_at"`
	Shadow   bool      `json:"shadow,omitempty"`
	Hash     []byte    `json:"hash"`
	Lineage  []string  `json:"lineage,omitempty"`
}

type scopeJSON struct {
	AWSProfiles  []string `json:"aws_profiles,omitempty"`
	GitHubScopes []string `json:"github_scopes,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	ClaudeProxy  bool     `json:"claude_proxy,omitempty"`
	SpendCapUSD  float64  `json:"spend_cap_usd,omitempty"`
	PerTxUSD     float64  `json:"money_per_transaction_usd,omitempty"`
	PerDayUSD    float64  `json:"money_per_day_usd,omitempty"`
	StepUpUSD    float64  `json:"money_step_up_above_usd,omitempty"`
}

func scopeToJSON(s presence.Scope) scopeJSON {
	s = s.Normalize()
	return scopeJSON{
		AWSProfiles: s.AWSProfiles, GitHubScopes: s.GitHubScopes, Capabilities: s.Capabilities,
		ClaudeProxy: s.ClaudeProxy, SpendCapUSD: s.SpendCapUSD,
		PerTxUSD: s.Money.PerTransactionUSD, PerDayUSD: s.Money.PerDayUSD, StepUpUSD: s.Money.StepUpAboveUSD,
	}
}

func (j scopeJSON) scope() presence.Scope {
	return presence.Scope{
		AWSProfiles: j.AWSProfiles, GitHubScopes: j.GitHubScopes, Capabilities: j.Capabilities,
		ClaudeProxy: j.ClaudeProxy, SpendCapUSD: j.SpendCapUSD,
		Money: presence.Money{PerTransactionUSD: j.PerTxUSD, PerDayUSD: j.PerDayUSD, StepUpAboveUSD: j.StepUpUSD},
	}.Normalize()
}

// idPayload is the body of revoke-grant, widen, step-up, step-up-batch and
// deny: the ids acted on.
type idPayload struct {
	IDs []string `json:"ids"`
}

// recordDigest is what a signer binds for a record: presence.HashRequest over
// a policy prefix, the action, the subject and the payload bytes. The prefix
// keeps a policy digest from ever equalling a bridge's request hash over the
// same strings, and HashRequest length-prefixes every part.
func recordDigest(action Action, subject string, payload []byte) []byte {
	return presence.HashRequest([]byte("policy-record"), []byte(action), []byte(subject), payload)
}

// pendingEnrollment is an enrollment verified by presence.Verifier.Enroll and
// waiting for an admin. Memory only: a restart means the device enrolls
// again, which is the documented behavior for anything not yet recorded.
type pendingEnrollment struct {
	PendingEnrollment
	payload  []byte
	enrolled *presence.Enrolled
	input    presence.EnrollmentInput
}

// grantMeta is what policy keeps about a root grant beyond the registry:
// whether it is a shadow grant and the sanctioned scope it ran under.
type grantMeta struct {
	sponsor    string
	shadow     bool
	sanctioned presence.Scope
	agent      string
	until      time.Time
}

// dailySpend is the running outward money total for a root grant today.
type dailySpend struct {
	day time.Time
	usd float64
}

type bootstrapCode struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

// state is the issuer's in-memory cache of admin-signed state.
type state struct {
	mu           sync.Mutex
	ordinal      int64
	enrollments  map[string]*EnrollmentRecord
	pending      map[string]*pendingEnrollment
	windows      []presence.Window
	grants       map[string]*grantMeta
	observations map[string][]Observation
	spend        map[string]*dailySpend
	loading      bool
}

func newState() *state {
	return &state{
		enrollments:  make(map[string]*EnrollmentRecord),
		pending:      make(map[string]*pendingEnrollment),
		grants:       make(map[string]*grantMeta),
		observations: make(map[string][]Observation),
		spend:        make(map[string]*dailySpend),
	}
}

func newIssuer(ctx context.Context, cfg Config) (*Issuer, error) {
	switch {
	case cfg.TrustDomain == "":
		return nil, errors.New("policy: config needs the issuer's own trust domain")
	case cfg.Verifier == nil || cfg.Sessions == nil || cfg.Grants == nil || cfg.Lot == nil:
		return nil, errors.New("policy: config needs the presence verifier, session store, grant registry and lot")
	case cfg.Store == nil:
		return nil, errors.New("policy: config needs a store")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	i := &Issuer{cfg: cfg, now: cfg.Now, state: newState()}
	if len(cfg.Windows) == 0 {
		i.state.windows = presence.DefaultWindows()
	} else {
		if err := validateWindows(cfg.Windows); err != nil {
			return nil, err
		}
		i.state.windows = slices.Clone(cfg.Windows)
	}
	if err := i.load(ctx); err != nil {
		return nil, err
	}
	return i, nil
}

// liveEnrollment returns the live enrollment for deviceID, under the lock.
func (s *state) liveEnrollment(deviceID string) (*EnrollmentRecord, error) {
	e, ok := s.enrollments[deviceID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceID)
	}
	if e.Revoked {
		return nil, fmt.Errorf("%w: %s", ErrDeviceRevoked, deviceID)
	}
	return e, nil
}

// liveAdmins counts live admin devices, under the lock.
func (s *state) liveAdmins() int {
	n := 0
	for _, e := range s.enrollments {
		if e.Live() && e.Admin {
			n++
		}
	}
	return n
}

// signerKeys parses the signer's enrolled keys. The presence key is what
// assertions verify against; it is nil exactly when the enrollment recorded
// no presence half, and only then is the device key returned for the
// none-level signing path.
func signerKeys(e *EnrollmentRecord) (presenceKey, deviceKey *ecdsa.PublicKey, err error) {
	deviceKey, err = parseP256(e.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: device key: %w", ErrRecordInvalid, err)
	}
	if len(e.PresencePublicKey) == 0 {
		return nil, deviceKey, nil
	}
	presenceKey, err = parseP256(e.PresencePublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: presence key: %w", ErrRecordInvalid, err)
	}
	return presenceKey, deviceKey, nil
}

func parseP256(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%T is not ECDSA", pub)
	}
	if ec.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("curve %s", ec.Curve.Params().Name)
	}
	return ec, nil
}

// verifySignature checks one signed change against the signer's enrollment
// and returns the signer, the presence state the record will carry, and the
// Verified proof when a human was present (nil for the none path).
//
// The expectation is built entirely from the issuer's side: the key from the
// enrollment record, the device id from the signature's claim of who signed
// (which must match that record), the tool and target from the action, and
// the request hash from the digest the ISSUER computed. The assertion goes
// through presence.Verifier.Verify, which spends the challenge whatever the
// outcome.
//
// A signer with no presence key gets ErrNoPresenceKey back from Verify after
// the challenge is spent; that is the documented order (challenge before
// key) and it is what makes the none path safe: the same single-use
// challenge, the same canonical bytes, verified against the device key
// because there is nothing else, and recorded as presence none. A signer
// WITH a presence key never reaches that path, so a device-key signature
// from it is simply a bad signature.
func (i *Issuer) verifySignature(sig Signature, action Action, subject string, digest []byte, requirePresence bool) (*EnrollmentRecord, presence.State, *presence.Verified, error) {
	if sig.Assertion == nil || len(sig.Assertion.Signature) == 0 {
		return nil, "", nil, ErrUnsigned
	}
	i.state.mu.Lock()
	signer, err := i.state.liveEnrollment(sig.DeviceID)
	if err == nil && signer.DeviceID != sig.Assertion.DeviceID {
		err = fmt.Errorf("%w: assertion names %s", ErrNotEnrolled, sig.Assertion.DeviceID)
	}
	var e EnrollmentRecord
	if err == nil {
		e = *signer
	}
	i.state.mu.Unlock()
	if err != nil {
		return nil, "", nil, err
	}
	presenceKey, deviceKey, err := signerKeys(&e)
	if err != nil {
		return nil, "", nil, err
	}
	exp := presence.Expectation{
		DeviceID:    e.DeviceID,
		Tool:        SigningTool,
		Target:      Target(action, subject),
		Binding:     presence.BindingRequired,
		RequestHash: digest,
	}
	if presenceKey != nil {
		exp.PresenceKey = presenceKey
	}
	v, err := i.cfg.Verifier.Verify(sig.Assertion, exp)
	switch {
	case err == nil:
		return &e, presence.StatePresent, v, nil
	case errors.Is(err, presence.ErrNoPresenceKey):
		if requirePresence {
			return nil, "", nil, fmt.Errorf("%w: %s has no presence key", ErrPresenceRequired, e.DeviceID)
		}
		// The presence:none admin path. Verify has spent the challenge and
		// found no presence half to check against. This device enrolled
		// with no presence key, so its DEVICE key is passed as the presence
		// key, here and nowhere else in the codebase: the one legitimate
		// device-key-for-presence-key substitution, recorded as approved
		// without presence. The Verified comes back already consumed, so
		// it can authorize nothing on its own.
		exp.PresenceKey = deviceKey
		if _, err := presence.VerifyDetached(sig.Assertion, exp, i.now()); err != nil {
			return nil, "", nil, err
		}
		return &e, presence.StateNone, nil, nil
	default:
		return nil, "", nil, err
	}
}

// challenge mints a signing challenge for a live enrolled device.
func (i *Issuer) challenge(deviceID string) ([]byte, error) {
	i.state.mu.Lock()
	_, err := i.state.liveEnrollment(deviceID)
	i.state.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return i.cfg.Verifier.Mint(deviceID)
}

// prepare builds the signing input for an action. The request hash is the
// digest of what the issuer will apply, computed from the issuer's own state
// for the subject; for the presence-package bindings (grant hash, widen hash,
// request hash, batch hash) it is that package's own value, because the
// consumer there checks it again.
func (i *Issuer) prepare(deviceID string, action Action, subject string) (*ToSign, error) {
	if err := i.preflight(deviceID, action, subject); err != nil {
		return nil, err
	}
	digest, err := i.digestFor(action, subject)
	if err != nil {
		return nil, err
	}
	ch, err := i.challenge(deviceID)
	if err != nil {
		return nil, err
	}
	in := presence.SigningInput{
		Version:     presence.EncodingVersion,
		DeviceID:    deviceID,
		Tool:        SigningTool,
		Target:      Target(action, subject),
		Challenge:   ch,
		RequestHash: digest,
	}
	return &ToSign{Input: in, Code: presence.RequestCode(ch, digest), Digest: digest}, nil
}

// preflight refuses to mint a challenge for an action the signer cannot
// perform or the issuer would refuse anyway: a non-admin signing an admin
// action, or a change that would remove the last admin. The apply path
// checks the same things again under the lock; this keeps a doomed request
// from prompting a human at all.
func (i *Issuer) preflight(deviceID string, action Action, subject string) error {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	switch action {
	case ActionApprove, ActionGrantAdmin, ActionRevokeAdmin, ActionRevoke, ActionPresencePolicy:
		if err := i.state.requireAdminLocked(deviceID); err != nil {
			return err
		}
	default:
		if _, err := i.state.liveEnrollment(deviceID); err != nil {
			return err
		}
	}
	switch action {
	case ActionGrantAdmin:
		_, err := i.state.checkAdminChangeLocked(subject, true, false)
		return err
	case ActionRevokeAdmin:
		_, err := i.state.checkAdminChangeLocked(subject, false, false)
		return err
	case ActionRevoke:
		_, err := i.state.checkAdminChangeLocked(subject, false, true)
		return err
	}
	return nil
}

// digestFor is the single place a subject becomes the bytes a signature must
// bind. Every apply path recomputes through it, so Prepare and apply cannot
// disagree.
func (i *Issuer) digestFor(action Action, subject string) ([]byte, error) {
	switch action {
	case ActionApprove:
		i.state.mu.Lock()
		p, err := i.state.pendingByCode(subject, i.now())
		var payload []byte
		if err == nil {
			payload = p.payload
		}
		i.state.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return recordDigest(action, subject, payload), nil
	case ActionGrantAdmin, ActionRevokeAdmin, ActionRevoke:
		payload, err := devicePayloadFor(action, subject)
		if err != nil {
			return nil, err
		}
		return recordDigest(action, subject, payload), nil
	case ActionPresencePolicy, ActionRevokeGrant, ActionDeny:
		// The subject IS the canonical content (a digest of the windows, an
		// id), so the payload adds nothing the signature does not already
		// cover.
		return recordDigest(action, subject, []byte(subject)), nil
	case ActionGrant:
		_, h, err := parseGrantSubject(subject)
		return h, err
	case ActionWiden:
		sess, to, ok := strings.Cut(subject, " ")
		if !ok || sess == "" || to == "" {
			return nil, fmt.Errorf("%w: widen subject %q", presence.ErrMalformed, subject)
		}
		return presence.WidenHash(sess, to), nil
	case ActionStepUp:
		item, err := i.cfg.Lot.Poll(subject)
		if err != nil {
			return nil, err
		}
		return item.RequestHash, nil
	case ActionStepUpBatch:
		return presence.BatchHash(strings.Split(subject, ",")), nil
	}
	return nil, fmt.Errorf("%w: unknown action %q", presence.ErrMalformed, action)
}

func devicePayloadFor(action Action, deviceID string) ([]byte, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("%w: empty device id", presence.ErrMalformed)
	}
	p := devicePayload{DeviceID: deviceID}
	switch action {
	case ActionGrantAdmin:
		p.Admin = true
	case ActionRevoke:
		p.Revoked = true
	}
	return json.Marshal(p)
}

func grantSubject(g presence.Grant) string {
	return g.Agent + " " + hex.EncodeToString(g.Hash())
}

func parseGrantSubject(subject string) (agent string, hash []byte, err error) {
	agent, h, ok := strings.Cut(subject, " ")
	if !ok || agent == "" {
		return "", nil, fmt.Errorf("%w: grant subject %q", presence.ErrMalformed, subject)
	}
	hash, err = hex.DecodeString(h)
	if err != nil || len(hash) != sha256.Size {
		return "", nil, fmt.Errorf("%w: grant subject hash", presence.ErrMalformed)
	}
	return agent, hash, nil
}

func batchSubject(ids []string) string {
	ids = slices.Clone(ids)
	sort.Strings(ids)
	ids = slices.Compact(ids)
	return strings.Join(ids, ",")
}

func windowsSubject(windows []presence.Window) string {
	b, _ := json.Marshal(windowsPayload{Windows: windowsToJSON(windows)})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func windowsToJSON(ws []presence.Window) []windowJSON {
	out := make([]windowJSON, 0, len(ws))
	for _, w := range ws {
		out = append(out, windowJSON{Tool: w.Tool, Target: w.Target, Group: w.Group, Duration: int64(w.Duration), Level: string(w.Level)})
	}
	slices.SortFunc(out, func(a, b windowJSON) int {
		if c := strings.Compare(a.Tool, b.Tool); c != 0 {
			return c
		}
		return strings.Compare(a.Target, b.Target)
	})
	return out
}

func windowsFromJSON(ws []windowJSON) []presence.Window {
	out := make([]presence.Window, 0, len(ws))
	for _, w := range ws {
		out = append(out, presence.Window{Tool: w.Tool, Target: w.Target, Group: w.Group, Duration: time.Duration(w.Duration), Level: presence.Level(w.Level)})
	}
	return out
}

// validateWindows refuses a policy presence itself would refuse: a window
// over MaxWindow or non-positive, a level outside the three, an empty tool,
// or two windows for the same tool and target.
func validateWindows(ws []presence.Window) error {
	seen := make(map[string]bool, len(ws))
	for _, w := range ws {
		key := w.Tool + "\x00" + w.Target
		switch {
		case w.Tool == "":
			return fmt.Errorf("%w: window with empty tool", ErrPolicyInvalid)
		case w.Level != presence.LevelWindow && w.Level != presence.LevelAlways && w.Level != presence.LevelStepUp:
			return fmt.Errorf("%w: %s level %q", ErrPolicyInvalid, w.Tool, w.Level)
		case w.Level == presence.LevelWindow && (w.Duration <= 0 || w.Duration > presence.MaxWindow):
			return fmt.Errorf("%w: %s duration %s", ErrPolicyInvalid, w.Tool, w.Duration)
		case seen[key]:
			return fmt.Errorf("%w: duplicate window for %s %q", ErrPolicyInvalid, w.Tool, w.Target)
		}
		seen[key] = true
	}
	return nil
}

// record chains one signed change. Under the state lock; the ordinal is
// assigned here, and the chain is the only copy.
//
// A policy record carries two times, and they are not redundant. rec.At in
// the signed payload is when the SIGNER'S change was applied by this
// issuer's clock and is what replay reasons from; store.Record.At is
// stamped by the STORE on Append and a caller's value is ignored, so it is
// when the chain recorded it. Both are under the chain hash. A large gap
// between them is itself evidence.
func (i *Issuer) record(ctx context.Context, rec *signedRecord) error {
	i.state.ordinal++
	rec.Ordinal = i.state.ordinal
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := i.cfg.Store.Append(ctx, store.Record{Kind: kindPolicyPrefix + string(rec.Action), At: rec.At, Payload: body}); err != nil {
		i.state.ordinal--
		return fmt.Errorf("policy: chain append: %w", err)
	}
	return nil
}

// audit appends an issuer event to the chain. Policy records use record;
// this is for issuance, exchanges, narrowing and parking.
func (i *Issuer) audit(ctx context.Context, rec AuditRecord) ([]byte, error) {
	if rec.At.IsZero() {
		rec.At = i.now()
	}
	if rec.Kind == "" {
		rec.Kind = kindExchange
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return i.cfg.Store.Append(ctx, store.Record{Kind: rec.Kind, At: rec.At, Payload: body})
}

// randomCode returns a bootstrap code: 20 hex characters grouped in fours.
func randomCode() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("policy: bootstrap code: %w", err)
	}
	h := strings.ToUpper(hex.EncodeToString(b[:]))
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20], nil
}

// SignWithoutPresence is the signing path for a device whose enrollment has
// no presence key: it signs the ToSign input with the device key and no
// prompt. The issuer accepts the result only from a device it enrolled
// without a presence half, and records the change as approved without
// presence. A device that has a presence key must use presence.Sign; this
// function on such a device produces a signature the issuer refuses.
func SignWithoutPresence(ctx context.Context, key platform.Key, in presence.SigningInput) (*presence.Assertion, error) {
	if key == nil {
		return nil, errors.New("policy: sign: nil key")
	}
	in.Version = presence.EncodingVersion
	b, err := in.Bytes()
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(ctx, b, platform.Prompt{Required: false, Tool: in.Tool, Target: in.Target, DeviceID: in.DeviceID})
	if err != nil {
		return nil, fmt.Errorf("policy: sign: %w", err)
	}
	return &presence.Assertion{
		Version: in.Version, DeviceID: in.DeviceID, Tool: in.Tool, Target: in.Target,
		Challenge: slices.Clone(in.Challenge), Signature: sig, RequestHash: slices.Clone(in.RequestHash),
	}, nil
}
