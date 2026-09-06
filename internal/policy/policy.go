// Package policy is the issuer's admin-signed state and the evaluation that
// turns an attested identity into a decision: allow, prompt, park, or deny.
//
// Policy is signed by admin devices, not by the issuer. Every change to
// enrollments, presence policy, grants, admin flags, and step-up approvals is
// a record signed with an admin device's presence-gated key; the issuer
// refuses to apply anything unsigned and stores the signed records in the
// same hash chain as issuance. The issuer host is a verifier and a cache of
// admin-signed state. A compromised host can mint under the CA (bounded by
// KMS) but cannot quietly widen a grant or enroll a device.
//
// The package evaluates against internal/presence and never re-implements it:
// presence assertions go through presence.Verifier, sessions through
// presence.SessionStore, grants through presence.Registry, parking through
// presence.Lot. What this package adds is the admin-signed record around each
// of those, the rules about who may sign what, the persistence of the signed
// records through store.Store, and the three structural bindings the design
// makes load-bearing:
//
//   - The grant a caller presents comes from its ATTESTED credential
//     (Attested, built only by AttestPeer from a verified certificate chain),
//     never from a request body. Request has no grant field at all.
//   - Presence assertions verify against the device's enrolled PRESENCE key.
//     The expectation is built from the EnrollmentRecord, never from the
//     request, and the device key is used only for a device that has no
//     presence key, in which case the record says presence "none".
//   - Enrollment goes through presence.Verifier.Enroll with the issuer's OWN
//     trust domain; one challenge covers both enrollment signatures.
//
// Files: policy.go (this contract), records.go (signed records and their
// digests), admin.go (enrollment, admin flags, revocation, presence policy),
// grants.go (sponsoring, sessions, step-up), evaluate.go (the decision),
// attested.go (the credential provenance extension), shadow.go (shadow
// grants and `agents propose`), persist.go (store round trip and reload).
package policy

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/store"
)

// Default is the shipped posture. Default deny in every policy file shipped: an
// identity, target, or tool not explicitly granted gets nothing.
const Default = "deny"

// Action is what an admin-signed record does. The set is closed; the signing
// target a human reads in the prompt is derived from it (Target).
type Action string

const (
	// ActionApprove approves a pending enrollment. Admin only, presence:always.
	ActionApprove Action = "approve"
	// ActionGrantAdmin flags an enrolled device admin. Admin only,
	// presence:always.
	ActionGrantAdmin Action = "grant-admin"
	// ActionRevokeAdmin clears the admin flag. Admin only, presence:always,
	// refused for the last admin.
	ActionRevokeAdmin Action = "revoke-admin"
	// ActionRevoke revokes an enrolled device. Admin only, presence:always,
	// refused for the last admin.
	ActionRevoke Action = "revoke"
	// ActionPresencePolicy replaces the per-target presence windows. Admin
	// only, presence:always.
	ActionPresencePolicy Action = "presence-policy"
	// ActionGrant sponsors a root grant. Any enrolled device with presence;
	// the assertion is bound to the grant hash, as presence.Registry.Sponsor
	// requires.
	ActionGrant Action = "grant"
	// ActionRevokeGrant revokes a grant instantly. An admin or the grant's
	// sponsor.
	ActionRevokeGrant Action = "revoke-grant"
	// ActionWiden returns an agent session to an ancestor grant. Any enrolled
	// device with presence; bound to presence.WidenHash.
	ActionWiden Action = "widen"
	// ActionStepUp approves one parked request, bound to its request hash.
	ActionStepUp Action = "step-up"
	// ActionStepUpBatch approves a batch of reversible parked requests, bound
	// to presence.BatchHash.
	ActionStepUpBatch Action = "step-up-batch"
	// ActionDeny refuses a parked request. Signed like every other change.
	ActionDeny Action = "deny"
)

// SigningTool is the Tool every policy-record assertion names, the same value
// enrollment uses: the assertion is for totem itself, not a catalog tool.
const SigningTool = presence.EnrollmentTool

// Target is the string the signing human reads in the prompt and the
// assertion is bound to: "<action> <subject>". Both sides derive it from the
// same inputs; the issuer never accepts a target the signer chose.
func Target(action Action, subject string) string {
	return string(action) + " " + subject
}

// Signature is an admin device's signature over one policy record: a presence
// assertion bound (RequestHash) to the record's digest, with Tool SigningTool
// and Target Target(action, subject). The issuer verifies it with the real
// presence.Verifier against the key its own EnrollmentRecord holds for
// DeviceID, so the signer supplies the assertion and nothing about how it is
// checked.
//
// A device whose enrollment has no presence key (presence "none") signs the
// same canonical bytes with its device key and no prompt. The issuer accepts
// that only because the enrollment says there is no presence half, records
// the resulting change as approved without presence, and never verifies a
// device with a presence key against anything but that presence key.
type Signature struct {
	// DeviceID is the enrolled device that signed.
	DeviceID string
	// Assertion is the signed assertion. Its Challenge must come from
	// Issuer.Challenge for DeviceID.
	Assertion *presence.Assertion
}

// ToSign is what the issuer hands a device that is about to sign a record:
// the exact presence.SigningInput the assertion must be over. The device
// fills nothing in; it signs these bytes with presence.Sign and returns the
// assertion in a Signature.
type ToSign struct {
	// Input is the signing input: DeviceID, SigningTool, the target the human
	// reads, a freshly minted challenge, and the record digest as the request
	// hash.
	Input presence.SigningInput
	// Code is the request code the CLI prints so the human can compare the
	// terminal against the OS prompt.
	Code string
	// Digest is Input.RequestHash: the record digest the signature binds.
	Digest []byte
}

// EnrollmentRecord is what the issuer records for a device: the public keys,
// device ID, protection level, and pinned cert. Only admin devices can approve
// enrollments, and revoking the last admin is refused.
type EnrollmentRecord struct {
	// DeviceID is the derived identifier for the enrolled device:
	// presence.PreEnrollmentDeviceID of the device public key.
	DeviceID string
	// Name is the device name given at enroll so inventory stays true across
	// reinstalls; empty means the hostname.
	Name string
	// PublicKey is the device's enrolled public key in PKIX DER (attestation
	// re-checks against it silently on every renewal). It is never used to
	// verify a presence assertion.
	PublicKey []byte
	// PresencePublicKey is the enrolled PRESENCE public key in PKIX DER, or
	// nil when the protection level has no presence capability. Every
	// presence assertion from this device verifies against this and nothing
	// else.
	PresencePublicKey []byte
	// ProtectionLevel is the assurance of the device key, carried on the
	// identity so downstream policy can act on it.
	ProtectionLevel spiffe.ProtectionLevel
	// PinnedCert is the SHA-256 fingerprint of the issuer certificate the
	// device pinned at enroll.
	PinnedCert []byte
	// Hostname and OS as shown on the approval screen.
	Hostname string
	OS       string
	// FirstContact is how the device verified the issuer at first contact.
	FirstContact presence.FirstContact
	// Admin marks a device that may approve enrollments; approve, grant-admin,
	// revoke-admin, and revoke are presence:always regardless of the device's
	// windows.
	Admin bool
	// Founding marks the device that redeemed the bootstrap code from issuer
	// init. It is the root admin.
	Founding bool
	// Presence is the device's own presence state at enrollment: present when
	// a human touched the sensor to enroll, none when the device cannot.
	Presence presence.State
	// ApprovedBy is the admin device that approved the enrollment; empty for
	// the founding device.
	ApprovedBy string
	// ApprovedByPresence records whether the approving admin was present; an
	// approval by a presence:none admin is recorded as such on the new
	// enrollment. StatePresent for the founding device, whose own enrollment
	// touch is the approval.
	ApprovedByPresence presence.State
	// EnrolledAt is when the enrollment was approved.
	EnrolledAt time.Time
	// LastSeen is the last time the device was observed.
	LastSeen time.Time
	// Revoked is set when the device was revoked; a revoked device fails every
	// live-enrollment check.
	Revoked bool
	// RevokedAt is when.
	RevokedAt time.Time
}

// Live reports whether the enrollment is usable: recorded and not revoked.
func (e EnrollmentRecord) Live() bool { return e.DeviceID != "" && !e.Revoked }

// PendingEnrollment is an enrollment waiting for an admin: everything the
// approval screen shows, plus the code the admin types.
type PendingEnrollment struct {
	// Code is the short code the enrolling device printed
	// (presence.EnrollmentCode).
	Code string
	// DeviceID, Hostname, OS, ProtectionLevel, FirstContact and Presence are
	// what the approver sees.
	DeviceID        string
	Name            string
	Hostname        string
	OS              string
	ProtectionLevel spiffe.ProtectionLevel
	FirstContact    presence.FirstContact
	Presence        presence.State
	// RequestedAt and ExpiresAt bound the code: single-use, minutes.
	RequestedAt time.Time
	ExpiresAt   time.Time
}

// EnrollRequest is what the enrolling device sent, in the shape the issuer
// verifies: the canonical input, the device-key proof of possession, the
// presence assertion signature (absent for a none-level device), and the
// bootstrap code when redeeming one. The issuer builds the assertion's Target
// from its own trust domain, so nothing here names the domain.
type EnrollRequest struct {
	// Input is the canonical enrollment input, with BootstrapCodeHash already
	// set from the code when one is being redeemed.
	Input presence.EnrollmentInput
	// Signature is the device key's proof of possession over Input.
	Signature []byte
	// PresenceSignature is the presence half's signature over the enrollment
	// assertion (Sign with RequestHash = Input.Digest()); nil for a
	// none-level device.
	PresenceSignature []byte
	// BootstrapCode is the one-time code from issuer init, when redeeming.
	BootstrapCode string
	// Name is the device name for inventory.
	Name string
	// AssertedTrustDomain is the issuer NAME the device believed it was
	// joining and signed its presence assertion for (the agent's
	// SignedTarget). It is DIAGNOSTIC ONLY and is never verified against:
	// Enroll reconstructs the assertion's target from the issuer's own
	// configured trust domain, so a device that signed for another name
	// fails as ErrBadSignature whatever this field says.
	//
	// What it is FOR: turning that failure into a thirty-second fix. When
	// the signature fails and this value differs from the issuer's, Enroll
	// wraps the error in ErrAssertedTrustDomain naming both, so the
	// operator reads "this device thinks we are called X and we are called
	// Y" and corrects the enroll command instead of chasing key material.
	// Remove this field and that message goes back to being a bare
	// signature failure.
	//
	// This does NOT weaken the rule on Request. Request carries what a
	// caller is asking for during an exchange, where a caller-supplied
	// identity is a forgery vector, and it has no identity fields and must
	// not gain any. EnrollRequest carries what a device SAID at enrollment,
	// the thing being adjudicated, not the thing being trusted. This field
	// is not precedent for a grant id, device id or presence state on
	// Request.
	AssertedTrustDomain string
}

// EnrollResult is the issuer's answer: either approved now (the founding
// device) or pending with the code an admin must type.
type EnrollResult struct {
	DeviceID string
	// Approved is true only for the founding device redeeming the bootstrap
	// code.
	Approved bool
	// Code is the approval code when pending.
	Code string
	// Presence is the enrolling device's own presence state.
	Presence presence.State
}

// Verdict is the issuer's answer to one request.
type Verdict string

const (
	// VerdictAllow: issue. Presence and provenance on the Decision say why.
	VerdictAllow Verdict = "allow"
	// VerdictPrompt: a present human is needed on the requesting device;
	// Binding says whether the assertion must be bound to the request.
	VerdictPrompt Verdict = "prompt"
	// VerdictPark: the request is parked for a human on another device;
	// ParkedID is what the caller polls.
	VerdictPark Verdict = "park"
	// VerdictDeny: refused outright, with Reason.
	VerdictDeny Verdict = "deny"
)

// Request is one exchange the issuer is asked to decide. It carries what the
// caller wants and NOTHING about who the caller is: identity, presence state
// and grant come from the Attested credential, so a request body cannot claim
// a grant, a device, or a presence state.
type Request struct {
	// Tool is the catalog tool or relying party: "claude", "aws", "gh",
	// "git", "homeassistant".
	Tool string
	// Target is the concrete target: an aws profile, a GitHub scope, the
	// entity/action capability for a relying party. Shown to the human.
	Target string
	// AmountUSD is the outward money movement this request makes, or zero.
	AmountUSD float64
	// Reversibility decides how an out-of-grant request parks. Empty means
	// Irreversible: the safe default.
	Reversibility presence.Reversibility
	// Description is the plain-language line a human reads if this parks.
	Description string
	// Hash is presence.HashRequest over the concrete request, computed by the
	// bridge; required for a presence:always target and for parking.
	Hash []byte
	// SessionID is the agent session (Issuer.OpenSession) the request runs
	// under, when the agent has narrowed. Empty evaluates against the
	// credential's own grant.
	SessionID string
}

// Decision is the issuer's answer, everything the audit line needs.
type Decision struct {
	Verdict Verdict
	// Presence is the presence state the credential will carry.
	Presence presence.State
	// Binding is what a prompted assertion must carry.
	Binding presence.Binding
	// PresenceAge is how old the covering presence is, for an allow.
	PresenceAge time.Duration
	// Provenance is the grant provenance for a delegated allow.
	Provenance presence.Provenance
	// ParkedID is the id to poll for a park.
	ParkedID string
	// Reversibility of the parked request.
	Reversibility presence.Reversibility
	// Money is the money verdict when AmountUSD was non-zero.
	Money presence.MoneyVerdict
	// Reason is the plain-language reason for a deny or park.
	Reason string
	// Shadow is true when the request was covered only by a shadow grant's
	// sanctioned scope and recorded as an observation.
	Shadow bool
}

// AuditRecord is one structured, hash-chained log line: every issuance and
// exchange records the SPIFFE ID, device, tool anchor, presence type and age,
// and outcome. The chain makes the log tamper-evident; config and policy
// changes are logged the same way so the honest threat model has no gap where
// "which device is enrolled / what presence a target needs" lives.
type AuditRecord struct {
	// Kind is the chain record kind: "exchange", "issuance",
	// "self-issuance", or "policy.<action>".
	Kind string
	// At is the record time.
	At time.Time
	// SpiffeID of the identity the credential was issued to.
	SpiffeID string
	// Device the credential was bound to.
	Device string
	// ToolAnchor is the catalog anchor the caller attested against.
	ToolAnchor string
	// Target of the request.
	Target string
	// Presence is the presence state that authorized the issuance.
	Presence presence.State
	// PresenceAgeSeconds is how old the presence assertion was at issuance.
	PresenceAgeSeconds int
	// GrantID is set when Presence is delegated, tying the action to the
	// human's signed grant so every delegated credential answers "who
	// authorized this."
	GrantID string
	// Outcome is the result of the issuance or exchange.
	Outcome string
	// Signer is the device that signed a policy record; empty otherwise.
	Signer string
	// Payload is the signed record for a policy kind, already serialised.
	Payload []byte
}

// Attested is the issuer's view of the credential a caller presented over
// mTLS: the SPIFFE ID, protection level, presence state and, for a delegated
// identity, the grant provenance. Every field is unexported and there is one
// constructor, AttestPeer, which reads them from a certificate the issuer
// signed. A request body has no way to produce one, so the grant id handed
// to presence.Registry.Open is structurally the attested one.
type Attested struct {
	id     spiffe.ID
	level  spiffe.ProtectionLevel
	state  presence.State
	prov   presence.Provenance
	serial string
}

// ID returns the SPIFFE ID.
func (a *Attested) ID() spiffe.ID { return a.id }

// State returns the presence state the credential carries.
func (a *Attested) State() presence.State { return a.state }

// GrantID returns the grant the credential was minted under, or empty.
func (a *Attested) GrantID() string { return a.prov.GrantID }

// Provenance returns the credential's provenance.
func (a *Attested) Provenance() presence.Provenance { return a.prov }

// ProtectionLevel returns the device key assurance the credential carries.
func (a *Attested) ProtectionLevel() spiffe.ProtectionLevel { return a.level }

// Claims is what the CA stamps into a credential and AttestPeer reads back:
// protection level, presence state, and provenance. Never in the path.
type Claims struct {
	ProtectionLevel spiffe.ProtectionLevel
	State           presence.State
	Provenance      presence.Provenance
}

// ProvenanceExtension encodes the claims as the X.509 extension the CA
// puts on every credential it mints. AttestPeer reads it back.
func ProvenanceExtension(c Claims) (pkix.Extension, error) {
	return provenanceExtension(c)
}

// AttestPeer builds the Attested credential from a verified mTLS chain
// (tls.ConnectionState.VerifiedChains). It takes the verified chains rather
// than a bare certificate so the caller must hand over the TLS layer's
// verification result, and reads the SPIFFE ID from the leaf's URI SAN and
// the claims from the provenance extension. An identity with no extension
// is presence none with no grant; a delegated state with no grant id is
// refused.
func AttestPeer(chains [][]*x509.Certificate) (*Attested, error) {
	return attestPeer(chains)
}

// Observation is one request recorded under a shadow grant: what the agent
// asked for, and whether the sanctioned scope covered it.
type Observation struct {
	At            time.Time
	Agent         string
	GrantID       string
	Tool          string
	Target        string
	AmountUSD     float64
	Reversibility presence.Reversibility
	// Covered is whether the sanctioned scope would have allowed it. An
	// uncovered request under shadow is still recorded (it is what the
	// proposal must not include) and still parked like any other.
	Covered bool
}

// Proposal is the output of `totem agents propose`: the minimal grant that
// would have covered the observed behavior, in three layers. Top: plain
// language grouped by relying party and risk. Middle: a diff against the
// sanctioned scope framed as a reduction, because the human is signing a
// shrink. Bottom: raw policy, collapsed, for the record. What the agent will
// not be able to do is shown as prominently as what it can; for a delegated
// agent the ceiling is the reassurance.
type Proposal struct {
	Agent string
	// Sanctioned is the widest scope the shadow ran under.
	Sanctioned presence.Scope
	// Proposed is the minimal scope covering every observed, covered request.
	Proposed presence.Scope
	// Observed and Uncovered count what the proposal was built from.
	Observed, Uncovered int
	// Can is the top layer: what the agent will be able to do, grouped by
	// relying party and risk.
	Can []Line
	// Cannot is the ceiling, shown with equal prominence: what the agent
	// will NOT be able to do, from the sanctioned scope, and the hard floors
	// no grant lifts.
	Cannot []Line
	// Reduction is the middle layer: the diff, as a shrink.
	Reduction []Line
	// Until is the proposed expiry.
	Until time.Time
}

// Line is one rendered line of a proposal layer.
type Line struct {
	// Party is the relying party the line belongs to.
	Party string
	// Risk is "read", "write", "irreversible", or "money".
	Risk string
	// Text is the plain-language line.
	Text string
}

// Config wires an Issuer to the presence primitives and the store. Every
// field except Now, Windows and Name is required.
type Config struct {
	// TrustDomain is the issuer's OWN configured trust domain, passed to
	// presence.Verifier.Enroll as the target every enrolling device must have
	// signed. Never a value a device sent.
	TrustDomain string
	// Verifier mints and verifies presence assertions.
	Verifier *presence.Verifier
	// Sessions holds presence windows.
	Sessions *presence.SessionStore
	// Grants is the grant registry.
	Grants *presence.Registry
	// Lot parks out-of-grant requests.
	Lot *presence.Lot
	// Store persists records and the hash chain.
	Store store.Store
	// Windows are the shipped defaults, used until an admin signs a presence
	// policy. Nil means presence.DefaultWindows.
	Windows []presence.Window
	// Now is the issuer clock; nil means time.Now.
	Now func() time.Time
}

// Issuer is the policy engine: admin-signed state, evaluation, and the audit
// chain. One per issuer process.
type Issuer struct {
	cfg   Config
	now   func() time.Time
	state *state
}

// New builds an Issuer and loads any existing signed state from the store,
// re-verifying every record's signature against the enrollment it names and
// verifying the hash chain. A broken chain is store.ErrChainBroken, loudly,
// and is never repaired.
func New(ctx context.Context, cfg Config) (*Issuer, error) { return newIssuer(ctx, cfg) }

// Bootstrap and enrollment.

// IssueBootstrapCode mints the one-time bootstrap code for issuer init or
// issuer recover: ten-minute expiry, single-use, returned once and never
// logged. It is stored envelope-encrypted so the daemon can verify the
// redemption. Minting a new code invalidates any outstanding one.
func (i *Issuer) IssueBootstrapCode(ctx context.Context) (code string, expires time.Time, err error) {
	return i.issueBootstrapCode(ctx)
}

// EnrollmentChallenge mints the enrollment challenge for a device public key
// (presence.PreEnrollmentDeviceID). The device signs both enrollment
// signatures over it.
func (i *Issuer) EnrollmentChallenge(devicePublicKeySPKI []byte) ([]byte, error) {
	return i.enrollmentChallenge(devicePublicKeySPKI)
}

// Enroll verifies an enrollment through presence.Verifier.Enroll, with the
// issuer's own trust domain, spending the challenge once for both
// signatures. A valid bootstrap code makes the device the founding admin,
// approved now and recorded as a signed record; otherwise the enrollment is
// pending until an admin approves its code. The issuer fingerprint must be
// the issuer's own.
func (i *Issuer) Enroll(ctx context.Context, req EnrollRequest, issuerFingerprint []byte) (*EnrollResult, error) {
	return i.enroll(ctx, req, issuerFingerprint)
}

// Pending lists enrollments waiting for approval.
func (i *Issuer) Pending() []PendingEnrollment { return i.pending() }

// Challenge mints a signing challenge for an enrolled device about to sign a
// record. It refuses an unknown or revoked device.
func (i *Issuer) Challenge(deviceID string) ([]byte, error) { return i.challenge(deviceID) }

// Prepare returns what a device must sign to perform action on subject: the
// full signing input with a fresh challenge and the record digest as the
// request hash. The digest is computed from the ISSUER's state (the pending
// enrollment behind a code, the grant behind an id), never from anything the
// signer sent, so a signature can only ever authorize what the issuer will
// apply. The device signs ToSign.Input with presence.Sign and calls the
// matching method with the result.
func (i *Issuer) Prepare(deviceID string, action Action, subject string) (*ToSign, error) {
	return i.prepare(deviceID, action, subject)
}

// Approve applies an admin's signed approval of the pending enrollment with
// code. Only admin devices approve; the approval is presence:always
// regardless of the admin's windows; a presence:none admin can approve and
// the new enrollment records ApprovedByPresence none.
func (i *Issuer) Approve(ctx context.Context, code string, sig Signature) (*EnrollmentRecord, error) {
	return i.approve(ctx, code, sig)
}

// Devices lists enrollment, protection level, admin flag, and last seen.
func (i *Issuer) Devices() []EnrollmentRecord { return i.devices() }

// Device returns one enrollment, or ErrDeviceNotFound.
func (i *Issuer) Device(deviceID string) (*EnrollmentRecord, error) { return i.device(deviceID) }

// Seen records that a device was observed now. Not a policy change; not
// signed.
func (i *Issuer) Seen(deviceID string) { i.seen(deviceID) }

// Admin flags and revocation.

// GrantAdmin flags deviceID admin. Admin only, presence:always.
func (i *Issuer) GrantAdmin(ctx context.Context, deviceID string, sig Signature) error {
	return i.setAdmin(ctx, deviceID, true, sig)
}

// RevokeAdmin clears the admin flag. Admin only, presence:always. Revoking
// the last admin is refused (ErrLastAdmin); issuer recover on the box is the
// fallback.
func (i *Issuer) RevokeAdmin(ctx context.Context, deviceID string, sig Signature) error {
	return i.setAdmin(ctx, deviceID, false, sig)
}

// RevokeDevice revokes an enrolled device instantly: its sessions drop and
// every live-enrollment check fails. Admin only, presence:always. Revoking
// the last admin device is refused (ErrLastAdmin).
func (i *Issuer) RevokeDevice(ctx context.Context, deviceID string, sig Signature) error {
	return i.revokeDevice(ctx, deviceID, sig)
}

// Presence policy.

// SetWindows replaces the per-target presence policy with an admin-signed
// one. Every window must be valid (presence refuses anything over MaxWindow).
// The subject for Prepare is WindowsSubject(windows).
func (i *Issuer) SetWindows(ctx context.Context, windows []presence.Window, sig Signature) error {
	return i.setWindows(ctx, windows, sig)
}

// Windows returns the presence policy in force.
func (i *Issuer) Windows() []presence.Window { return i.windows() }

// Window returns the window for a tool and target: an exact tool:target
// match first, then the tool-wide window. ok is false when the policy names
// neither, which is a deny (Default).
func (i *Issuer) Window(tool, target string) (w presence.Window, ok bool) {
	return i.window(tool, target)
}

// WindowsSubject is the Prepare subject for SetWindows: a digest of the
// windows so the signature covers exactly this policy.
func WindowsSubject(windows []presence.Window) string { return windowsSubject(windows) }

// Grants.

// Sponsor records a root grant a human just signed. sig must be from an
// enrolled device with presence, bound to g.Hash() (Prepare with
// ActionGrant and GrantSubject(g) does that). The grant is recorded as a
// signed record and registered.
func (i *Issuer) Sponsor(ctx context.Context, g presence.Grant, sig Signature) (*presence.Grant, error) {
	return i.sponsor(ctx, g, sig)
}

// GrantSubject is the Prepare subject for Sponsor: the grant agent and hash.
func GrantSubject(g presence.Grant) string { return grantSubject(g) }

// Shadow records a shadow grant: the agent runs under sanctioned (the human's
// widest sanctioned scope) while every request is recorded as an
// observation. Same signing as Sponsor; the grant is flagged shadow.
func (i *Issuer) Shadow(ctx context.Context, g presence.Grant, sig Signature) (*presence.Grant, error) {
	return i.shadow(ctx, g, sig)
}

// RevokeGrant revokes a grant and every sub-grant under it. Admin or the
// grant's sponsor, presence:always.
func (i *Issuer) RevokeGrant(ctx context.Context, grantID string, sig Signature) error {
	return i.revokeGrant(ctx, grantID, sig)
}

// Grant returns an active grant.
func (i *Issuer) Grant(grantID string) (*presence.Grant, error) { return i.cfg.Grants.Get(grantID) }

// RenewalsDue lists root grants whose three-day renewal notice is due.
func (i *Issuer) RenewalsDue() []presence.Grant { return i.renewalsDue() }

// Agent sessions.

// OpenSession starts an agent session for an attested delegated credential.
// The presented grant id is a.GrantID(): the credential's provenance, by
// construction, never a request field. grantID may be the presented grant
// or one of its descendants.
func (i *Issuer) OpenSession(ctx context.Context, a *Attested, grantID string) (*presence.AgentSession, error) {
	return i.openSession(ctx, a, grantID)
}

// Narrow derives a sub-grant for the session, instantly, without presence.
// The session must belong to the attested agent. Logged under its lineage.
func (i *Issuer) Narrow(ctx context.Context, a *Attested, sessionID string, scope presence.Scope, until time.Time) (*presence.Grant, error) {
	return i.narrow(ctx, a, sessionID, scope, until)
}

// Widen returns the session to an ancestor grant with fresh presence. sig
// must be bound to presence.WidenHash(sessionID, toGrantID) (Prepare with
// ActionWiden and WidenSubject).
func (i *Issuer) Widen(ctx context.Context, sessionID, toGrantID string, sig Signature) (*presence.Grant, error) {
	return i.widen(ctx, sessionID, toGrantID, sig)
}

// WidenSubject is the Prepare subject for Widen.
func WidenSubject(sessionID, toGrantID string) string { return sessionID + " " + toGrantID }

// Evaluation.

// Evaluate decides one request for an attested credential. A tool identity
// is checked against the presence policy and held sessions; an agent
// identity against its grant (or the session's active sub-grant), money
// ceilings, and entity scopes; anything outside parks with an id. It never
// issues; the caller issues on VerdictAllow and records the Decision on the
// audit line.
func (i *Issuer) Evaluate(ctx context.Context, a *Attested, req Request) (Decision, error) {
	return i.evaluate(ctx, a, req)
}

// Present is Evaluate with a presence assertion from the requesting device:
// the assertion is verified against the device's enrolled presence key with
// the binding the target's level requires, opens the window for a windowed
// target, and satisfies a presence:always target for exactly this request.
func (i *Issuer) Present(ctx context.Context, a *Attested, req Request, assertion *presence.Assertion) (Decision, error) {
	return i.present(ctx, a, req, assertion)
}

// Step-up.

// Poll returns the state of a parked request.
func (i *Issuer) Poll(id string) (presence.ParkedRequest, error) { return i.cfg.Lot.Poll(id) }

// Consume redeems an approved parked request once.
func (i *Issuer) Consume(ctx context.Context, id string) (presence.ParkedRequest, error) {
	return i.consume(ctx, id)
}

// PendingParked lists parked requests of one reversibility, oldest first.
func (i *Issuer) PendingParked(rev presence.Reversibility) []presence.ParkedRequest {
	return i.cfg.Lot.Pending(rev)
}

// ApproveParked approves one parked request with a signature bound to its
// request hash (Prepare with ActionStepUp and the id).
func (i *Issuer) ApproveParked(ctx context.Context, id string, sig Signature) error {
	return i.approveParked(ctx, id, sig)
}

// ApproveBatch approves reversible parked requests with one signature bound
// to presence.BatchHash(ids) (Prepare with ActionStepUpBatch and
// BatchSubject(ids)).
func (i *Issuer) ApproveBatch(ctx context.Context, ids []string, sig Signature) error {
	return i.approveBatch(ctx, ids, sig)
}

// BatchSubject is the Prepare subject for ApproveBatch.
func BatchSubject(ids []string) string { return batchSubject(ids) }

// DenyParked refuses a parked request, signed like every other change.
func (i *Issuer) DenyParked(ctx context.Context, id string, sig Signature) error {
	return i.denyParked(ctx, id, sig)
}

// Shadow grants and propose.

// Observations returns what a shadow grant recorded, oldest first.
func (i *Issuer) Observations(rootGrantID string) []Observation { return i.observations(rootGrantID) }

// Propose produces the minimal grant covering the observed behavior, in
// three layers, against the sanctioned scope. Pure: it reads nothing from
// the issuer, so it is testable over generated inputs.
func Propose(agent string, sanctioned presence.Scope, obs []Observation, now time.Time) Proposal {
	return propose(agent, sanctioned, obs, now)
}

// Render writes the proposal for a human in a hurry: what it can do, what it
// cannot, the reduction, and the raw scope, in that order.
func (p Proposal) Render() string { return renderProposal(p) }

// Audit.

// Audit appends an issuance or exchange line to the chain. Policy changes
// append themselves; this is for the issuer's own events.
func (i *Issuer) Audit(ctx context.Context, rec AuditRecord) ([]byte, error) {
	return i.audit(ctx, rec)
}

// Errors.
var (
	// ErrUnsigned: a change arrived with no signature. The issuer refuses to
	// apply anything unsigned.
	ErrUnsigned = errors.New("policy: record is not signed")
	// ErrNotAdmin: the signer is not an admin device.
	ErrNotAdmin = errors.New("policy: signer is not an admin device")
	// ErrNotEnrolled: the signer or subject is not a live enrollment.
	ErrNotEnrolled = errors.New("policy: device is not enrolled")
	// ErrDeviceNotFound: no enrollment with that id.
	ErrDeviceNotFound = errors.New("policy: device not found")
	// ErrDeviceRevoked: the device was revoked.
	ErrDeviceRevoked = errors.New("policy: device revoked")
	// ErrLastAdmin: revoking the last admin is refused.
	ErrLastAdmin = errors.New("policy: refusing to revoke the last admin")
	// ErrAlreadyEnrolled: the device key is already enrolled.
	ErrAlreadyEnrolled = errors.New("policy: device already enrolled")
	// ErrPendingNotFound: no pending enrollment with that code.
	ErrPendingNotFound = errors.New("policy: no pending enrollment with that code")
	// ErrPendingExpired: the approval code expired.
	ErrPendingExpired = errors.New("policy: enrollment code expired")
	// ErrBootstrapInvalid: the bootstrap code is wrong, expired, or spent.
	ErrBootstrapInvalid = errors.New("policy: bootstrap code invalid")
	// ErrIssuerFingerprint: the device pinned a certificate that is not this
	// issuer's.
	ErrIssuerFingerprint = errors.New("policy: enrollment pinned a certificate that is not this issuer's")
	// ErrAssertedTrustDomain wraps an enrollment signature failure when the
	// device's AssertedTrustDomain differs from the issuer's: the likely
	// cause is a typo'd enroll command, not key material. Diagnostic; the
	// underlying presence error is wrapped alongside it.
	ErrAssertedTrustDomain = errors.New("policy: device enrolled against a different issuer name")
	// ErrPresenceRequired: the action needs a device with presence and the
	// signer has none.
	ErrPresenceRequired = errors.New("policy: this action requires a device with presence")
	// ErrWrongSigningShape: the signature is not the shape the signer's
	// enrollment requires (a device-key signature from a device that has a
	// presence key, or a presence-shaped signature from one that has none).
	ErrWrongSigningShape = errors.New("policy: signature shape does not match the signer's enrollment")
	// ErrNotDelegated: the credential is not a delegated identity.
	ErrNotDelegated = errors.New("policy: credential is not a delegated identity")
	// ErrNotAgentIdentity: an agent session belongs to a different agent.
	ErrNotAgentIdentity = errors.New("policy: session belongs to a different agent")
	// ErrNoPolicy: the tool or target has no presence policy. Default deny.
	ErrNoPolicy = errors.New("policy: no presence policy for target")
	// ErrNotSponsor: only an admin or the grant's sponsor may revoke it.
	ErrNotSponsor = errors.New("policy: signer is neither admin nor the grant's sponsor")
	// ErrCredential: the presented certificate chain does not carry a totem
	// identity or its claims are inconsistent.
	ErrCredential = errors.New("policy: credential is not a totem identity")
	// ErrPolicyInvalid: a presence policy carries an invalid window.
	ErrPolicyInvalid = errors.New("policy: presence policy invalid")
	// ErrRecordInvalid: a stored record failed re-verification on load. The
	// issuer refuses to start on it.
	ErrRecordInvalid = errors.New("policy: stored record failed verification")
)
