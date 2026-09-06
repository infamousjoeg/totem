// Package ca is the issuer's certificate authority: the root generated at
// `issuer init` and held offline or in KMS, the intermediate that signs
// everything and rotates every thirty days with overlap, the X.509-SVIDs minted
// for device, tool and agent identities, the issuer's own self-issued identity,
// and the CRLs published under it.
//
// This file is the CONTRACT the rest of the issuer compiles against. It holds
// the exported interface, its types, its constants and its typed errors, and no
// logic at all; implementations live in other files in this package. Treat it
// the way internal/summon and internal/store are treated: propose changes to
// the build lead rather than editing it, because the issuer server, the
// enrollment path and the AWS bridge all bind to these names.
//
// Three rules from docs/totem-design.md shape every type here, and none of them
// is advisory:
//
//   - "ECDSA P-256 for device keys and SVIDs, P-384 for the CA. No Ed25519."
//     A request carrying any other algorithm is refused with
//     ErrUnsupportedAlgorithm. There is no downgrade and no best-effort
//     substitution: silently minting under a weaker or merely different key
//     than the caller asked for is how a FIPS posture becomes a lie.
//   - "Root CA generated at issuer init, held offline or in KMS ... Root
//     rotation is a deliberate operator action." Root rotation is therefore NOT
//     a method on Authority; it lives on RootOperator, which ordinary issuer
//     request paths must not hold.
//   - "The issuer has its own tool identity, spiffe://<td>/issuer, with no
//     presence, every self-issuance logged as a distinct event type." That
//     separation is enforced by the type system here, not by convention: see
//     IssueSVID, IssueIssuerSVID, ErrIssuerIdentityReserved and
//     ErrNotIssuerIdentity.
package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/summon"
)

// Authority is the issuer's CA as every request path sees it: it publishes a
// trust bundle, mints SVIDs, prepares the next intermediate, and revokes.
//
// It deliberately cannot rotate the root. See RootOperator.
//
// Every method that depends on which intermediate is current first advances the
// schedule to the current time before answering. An intermediate whose
// SigningStart has passed becomes current, and one past NotAfter leaves the
// bundle, without an operator or a cron doing anything. This is deliberate: a
// missed rotation job must not silently keep signing under a key whose signing
// window closed, and an issuer that was down for a week must come back with the
// schedule the clock says is true rather than the one it remembered.
type Authority interface {
	// Bundle returns what relying parties must trust: the root (or, during a
	// root rotation, both roots) plus every intermediate whose validity window
	// contains now, each tagged with its role.
	//
	// This is the endpoint the spec means by "the bundle endpoint publishes
	// current plus next". The invariant it exists to hold is that a relying
	// party which fetched the bundle at any point in the publication overlap
	// already trusts the intermediate that is about to start signing, so a
	// rotation is not an outage. A bundle that contains only the signing
	// intermediate is a bug, not an optimisation.
	Bundle(ctx context.Context) (*Bundle, error)

	// Schedule reports the rotation state without changing it: which
	// intermediate signs now, which is published and waiting, which is retiring
	// but still trusted, and when each boundary falls. `totem issuer status`
	// and the pre-expiry warning both read this.
	Schedule(ctx context.Context) (*Schedule, error)

	// IssueSVID mints an X.509-SVID for a device, tool or agent identity,
	// signed by the current intermediate.
	//
	// It REFUSES the issuer's own identity with ErrIssuerIdentityReserved. The
	// spec requires the issuer's self-issuance to be a distinct log event, and
	// a distinction that depends on every call site remembering to label
	// correctly is not a distinction. The only way to mint
	// spiffe://<td>/issuer is IssueIssuerSVID, and the SVID it returns carries
	// EventIssuerSelfIssuance in its Event field so the caller writing the log
	// line cannot label it as a device issuance either.
	//
	// req.PublicKey must be ECDSA P-256; anything else is
	// ErrUnsupportedAlgorithm.
	IssueSVID(ctx context.Context, req SVIDRequest) (*SVID, error)

	// IssueIssuerSVID mints the issuer's own identity, spiffe://<td>/issuer:
	// no presence, no device, one purpose, which is publishing CRLs to AWS
	// Roles Anywhere through the issuer's own profile.
	//
	// It cannot be asked for any other identity: IssuerSVIDRequest carries no
	// ID field at all, so "this call minted something that was not the issuer"
	// is unrepresentable rather than merely checked. Its request type is
	// separate from SVIDRequest rather than a flag on it for the same reason,
	// and because the issuer identity has no device, no protection level and no
	// presence: modelling it as a device issuance with three fields left empty
	// invites an audit reader to treat an empty presence field as "presence not
	// checked" on a device credential.
	//
	// The returned SVID carries EventIssuerSelfIssuance.
	IssueIssuerSVID(ctx context.Context, req IssuerSVIDRequest) (*SVID, error)

	// RotateIntermediate prepares the successor to the current intermediate:
	// generates its key, has the root sign it, and publishes it in the bundle
	// as the next intermediate. It does NOT make it start signing; the clock
	// does that at SigningStart.
	//
	// It is idempotent inside one publication overlap. Called again while a
	// successor is published and waiting it changes nothing and returns
	// ErrRotationPending with the existing schedule, because replacing a
	// published-but-not-yet-signing intermediate is precisely the outage the
	// overlap exists to prevent: every relying party still holding the earlier
	// bundle would reject the certificates the replacement signs.
	//
	// Called before the overlap opens it returns ErrRotationTooSoon, naming the
	// earliest permitted time.
	//
	// It needs the root signer. With a KMS root that is a call; with a root
	// genuinely held offline it returns ErrRootOffline and the operator must
	// run the rotation with the root material present. That is why the
	// publication overlap is long enough for a human to schedule a ceremony
	// rather than merely long enough for a bundle poll.
	RotateIntermediate(ctx context.Context) (*Schedule, error)

	// Revoke adds a certificate to the revocation set for the intermediate that
	// issued it.
	//
	// It takes the certificate rather than a serial number, and it verifies
	// that the certificate actually chains to one of this CA's intermediates
	// before recording anything; a serial number alone is a claim, and
	// revoking on an unverified claim lets a caller poison a CRL with serials
	// this CA never issued. A certificate that does not verify is
	// ErrNotOurCertificate.
	Revoke(ctx context.Context, req RevocationRequest) error

	// CRLs returns one signed CRL per intermediate still in the bundle.
	//
	// It is plural because a CRL is signed by the CA that issued the
	// certificates it revokes, and during an overlap there are up to three live
	// intermediates. Collapsing them into one list signed by the current
	// intermediate would produce a CRL that a correct verifier ignores for
	// every serial the outgoing intermediate issued, which is the revocation
	// silently not working.
	//
	// Whether Roles Anywhere additionally requires a root-signed CRL is
	// verified before step 4 (docs/totem-design.md, "Sequencing"); if it does,
	// the intermediate becomes the trust anchor and this shape is unaffected.
	CRLs(ctx context.Context) ([]*CRL, error)

	// Close releases key handles and zeroes any resolved material still held.
	Close() error
}

// RootOperator is root rotation, which is a deliberate operator action and
// never automatic. It is a separate interface so that the issuer's request
// paths can hold an Authority and be structurally incapable of rotating the
// root: an interface a handler cannot name is an interface a bug in that
// handler cannot call.
type RootOperator interface {
	// RotateRoot signs a new root and publishes both roots in the bundle for
	// the duration of the crossover, so relying parties can pick the new one up
	// before the old one stops being sufficient. The operator retires the old
	// root explicitly; nothing here does it on a timer.
	RotateRoot(ctx context.Context, req RootRotationRequest) (*Bundle, error)
}

// Constructors land with the implementation. They are named here so the shape
// of the dependency is part of the contract rather than a surprise at wiring
// time:
//
//	func Init(ctx context.Context, params InitParams) (Authority, error)
//	func Open(ctx context.Context, cfg Config) (Authority, error)
//
// Init generates the root and the first intermediate and fails with
// ErrAlreadyInitialized rather than overwriting existing CA material. Open
// loads existing material and fails with ErrNotInitialized if there is none.
// Neither takes a passphrase argument; see Config.

// Config opens an existing CA.
type Config struct {
	// Dir is where CA material lives on the issuer: the root certificate, the
	// intermediate certificates and keys, and the revocation set.
	Dir string

	// Resolver is the ONLY way the CA passphrase enters this package. There is
	// no flag, no environment variable, no plaintext path and no dev mode; see
	// internal/summon. The value is used at the moment it is needed and
	// released, never cached across a rotation, because a cached Value is a
	// zeroed buffer after one.
	Resolver summon.Resolver
	// PassphraseRef is the logical reference the resolver turns into the
	// passphrase protecting intermediate private keys at rest.
	PassphraseRef summon.Reference

	// Root reaches the root private key. Nil means the local
	// passphrase-protected root file, which is the "held offline on this box"
	// case; a KMS implementation is the other. Steady-state issuance never
	// touches it: only RotateIntermediate and RotateRoot do.
	Root RootProvider

	// TrustDomain is the validated SPIFFE trust domain every minted identity
	// must sit under. An identity from another trust domain is
	// ErrTrustDomainMismatch, not a cross-signed courtesy.
	TrustDomain string

	// RequireFIPS makes non-approved configuration fatal: if the binary is not
	// running under the FIPS Go crypto module, Open fails with ErrFIPSRequired
	// rather than serving. "In FIPS mode the issuer refuses non-approved
	// configuration" is a refusal, so it happens at open, before a single
	// certificate exists that was minted outside the boundary.
	RequireFIPS bool

	// Now is the clock. Nil means time.Now. Tests set it to drive a rotation
	// schedule across thirty-day boundaries without sleeping; nothing in
	// production sets it.
	Now func() time.Time
}

// InitParams generates a new CA at `issuer init`.
type InitParams struct {
	Config

	// RootValidity is how long the root is good for. Zero means
	// DefaultRootValidity.
	RootValidity time.Duration

	// Subject is the organisational name placed on the root and intermediate
	// subjects. Cosmetic; nothing authorises on it.
	Subject string
}

// RootProvider is how the root private key is reached. The root is "held
// offline or in KMS", and those are the two implementations: a
// passphrase-protected file the operator brings to a ceremony, and a KMS
// handle.
//
// The distinction matters operationally, not cryptographically. A KMS root
// makes the thirty-day intermediate rotation an unattended job. A genuinely
// offline root makes it a scheduled human ceremony, and an issuer whose root is
// offline and whose operator misses the window fails closed with
// ErrNoSigningIntermediate. Whichever is chosen, choose it knowing that.
type RootProvider interface {
	// Certificate returns the root certificate. Always available: the
	// certificate is public and lives in the bundle even when the key does not.
	Certificate(ctx context.Context) (*x509.Certificate, error)

	// Signer returns a signer over the root private key, or ErrRootOffline when
	// the key is not reachable right now. ErrRootOffline is the normal steady
	// state for an offline root and must be handled as "not now", never as
	// "broken".
	Signer(ctx context.Context) (crypto.Signer, error)
}

// SVIDRequest asks for an X.509-SVID for a device, tool or agent identity.
type SVIDRequest struct {
	// ID is the derived identity:
	// spiffe://<trust-domain>/device/<device-id>/tool/<tool-name>, or
	// .../agent/<name>. Its trust domain must match the CA's.
	ID spiffe.ID

	// PublicKey is the device- or agent-held public key the certificate binds
	// to. It must be ECDSA P-256. Any other key type or curve, including
	// Ed25519 and including a stronger ECDSA curve, is ErrUnsupportedAlgorithm:
	// "no Ed25519" is a statement about what the CA will mint, and quietly
	// accepting P-384 here because it is stronger would leave the fleet with
	// two profiles nobody chose.
	PublicKey crypto.PublicKey

	// ProtectionLevel is the assurance of the key that backs this identity. It
	// rides as an X.509 extension (OIDProtectionLevel), never in the path, so
	// relying-party policy can match on it.
	ProtectionLevel spiffe.ProtectionLevel

	// Presence is the presence state that authorised this issuance, and
	// PresenceAge how old the assertion was. Both ride as extensions
	// (OIDPresenceState, OIDPresenceAge). presence.StateNone is a legitimate,
	// recorded value, not a missing one: an unattended identity is
	// "presence: none in the credential, never a longer window".
	Presence    presence.State
	PresenceAge time.Duration

	// GrantID ties a delegated issuance to the human's signed grant, so every
	// delegated credential answers "who authorised this". Required when
	// Presence is presence.StateDelegated; empty otherwise.
	GrantID string

	// TTL is the certificate lifetime. Zero means DefaultSVIDTTL. Above
	// MaxSVIDTTL it is ErrTTLTooLong rather than a silent clamp, because a
	// caller that asked for eight hours and got one has a bug it will not see
	// until an outage.
	//
	// The shipped lifetimes: one hour for the device identity with renewal at
	// half-life, fifteen minutes for a bridge SVID used directly against a
	// relying party, where the SVID itself is the presence-gated artifact.
	TTL time.Duration
}

// IssuerSVIDRequest asks for the issuer's own identity, spiffe://<td>/issuer.
// It carries no device, no protection level and no presence, because the issuer
// identity has none of those things.
type IssuerSVIDRequest struct {
	// PublicKey is the issuer's own key for this credential. ECDSA P-256, same
	// rule as every other SVID.
	PublicKey crypto.PublicKey

	// TTL is the lifetime. Zero means DefaultSVIDTTL.
	TTL time.Duration
}

// SVID is a minted certificate and everything the caller needs to present and
// to log it.
type SVID struct {
	// Certificate is the parsed leaf.
	Certificate *x509.Certificate

	// Chain is what the agent presents: leaf first, then the intermediate that
	// signed it. It does NOT include the root, which the relying party already
	// holds as its trust anchor. This is the "helper presents leaf plus current
	// intermediate" shape the AWS bridge requires.
	Chain []*x509.Certificate

	// ChainDER is Chain in the same order, as raw DER, for callers that write
	// it out without re-encoding.
	ChainDER [][]byte

	// URI is the SPIFFE ID in the certificate's URI SAN, as a string, for the
	// log line.
	URI string

	// Event is the audit event kind for this issuance, set by the CA and not by
	// the caller: EventIssuance for a device, tool or agent identity,
	// EventIssuerSelfIssuance for the issuer's own. Pass it straight through to
	// store.Record.Kind. It exists so the spec's "every self-issuance logged as
	// a distinct event type" cannot be lost to a call site that picked the
	// string itself.
	Event string

	// IssuedBy is the SubjectKeyId of the signing intermediate, so an audit
	// reader can say which intermediate minted a credential across a rotation
	// boundary without re-parsing the chain.
	IssuedBy []byte

	// NotAfter is the leaf expiry, for renewal-at-half-life scheduling.
	NotAfter time.Time
}

// Bundle is what relying parties trust.
type Bundle struct {
	// Roots is normally one root. It is a slice because a root rotation is a
	// deliberate crossover during which both roots must be trusted.
	Roots []*x509.Certificate

	// Intermediates is every intermediate whose validity window contains
	// GeneratedAt, each tagged with its role. Up to three during an overlap:
	// one retiring, one current, one next.
	Intermediates []Intermediate

	// GeneratedAt is the instant the roles in this bundle were evaluated. A
	// relying party can tell from it how stale a cached bundle is.
	GeneratedAt time.Time
}

// Intermediate is one intermediate certificate and where it sits in the
// rotation schedule.
type Intermediate struct {
	// Certificate is the intermediate.
	Certificate *x509.Certificate

	// Role is what this intermediate is doing right now.
	Role IntermediateRole

	// SigningStart and SigningEnd bound the interval in which this intermediate
	// signs. Exactly one intermediate signs at any instant; the overlap is an
	// overlap of PUBLICATION and of validity, not of signing. Two intermediates
	// signing at once would mean a leaf's issuer could not be predicted from
	// the clock, which makes CRL scoping and incident reconstruction guesswork.
	SigningStart time.Time
	SigningEnd   time.Time
}

// IntermediateRole is an intermediate's position in the rotation, evaluated
// against the clock rather than stored.
type IntermediateRole string

const (
	// RoleNext is published in the bundle and trusted, but has not started
	// signing. It exists so relying parties trust it BEFORE it signs anything.
	RoleNext IntermediateRole = "next"
	// RoleCurrent is the one intermediate signing right now.
	RoleCurrent IntermediateRole = "current"
	// RoleRetiring has stopped signing but is still trusted and still in the
	// bundle, because certificates it signed are still inside their lifetime.
	// Dropping it at SigningEnd would break every unexpired leaf it minted,
	// which is the second half of "with overlap" and the half that is easy to
	// forget.
	RoleRetiring IntermediateRole = "retiring"
)

// Schedule is the rotation state: the whole timeline, evaluated at At.
type Schedule struct {
	// At is when this schedule was evaluated.
	At time.Time

	// Current is the signing intermediate. Nil means there is none, which is a
	// fail-closed state, not a transient one: see ErrNoSigningIntermediate.
	Current *Intermediate
	// Next is the published successor, or nil if none has been prepared yet.
	Next *Intermediate
	// Retiring is every intermediate past SigningEnd but still trusted.
	Retiring []Intermediate

	// RotateAfter is the earliest time RotateIntermediate will prepare a
	// successor: SigningEnd minus IntermediatePublicationOverlap. Before it,
	// RotateIntermediate returns ErrRotationTooSoon.
	RotateAfter time.Time
	// RotateBefore is when the current intermediate stops signing. A successor
	// that does not exist by then means the issuer cannot mint. The operator
	// warning fires against this, not against certificate expiry, because the
	// certificate is still valid for RetirementTail after it has stopped being
	// useful.
	RotateBefore time.Time
}

// RevocationRequest revokes one certificate this CA issued.
type RevocationRequest struct {
	// Certificate is the certificate to revoke. The CA chain-verifies it
	// against its own intermediates before recording anything; see
	// Authority.Revoke.
	Certificate *x509.Certificate
	// Reason is the CRL reason code.
	Reason RevocationReason
	// At is the revocation time. Zero means now.
	At time.Time
}

// RevocationReason is an RFC 5280 CRLReason, restricted to the values totem
// actually produces. A closed set, so an audit reader never has to interpret a
// number nothing in this codebase emits.
type RevocationReason int

const (
	// ReasonUnspecified is a revocation with no stated cause.
	ReasonUnspecified RevocationReason = 0
	// ReasonKeyCompromise is a device key believed to be in someone else's
	// hands. This is the one that must reach Roles Anywhere fastest.
	ReasonKeyCompromise RevocationReason = 1
	// ReasonCACompromise is an intermediate or root believed compromised.
	ReasonCACompromise RevocationReason = 2
	// ReasonSuperseded is a certificate replaced by a newer one, the normal
	// outcome of a re-enrollment.
	ReasonSuperseded RevocationReason = 4
	// ReasonCessationOfOperation is a device deliberately removed:
	// `totem revoke`.
	ReasonCessationOfOperation RevocationReason = 5
)

// CRL is one signed certificate revocation list, scoped to the intermediate
// that issued the certificates it lists.
type CRL struct {
	// DER is the signed CRL, ready to hand to
	// rolesanywhere:ImportCrl / UpdateCrl.
	DER []byte
	// IssuerSubjectKeyID identifies the intermediate that signed it, which is
	// also the intermediate that issued every serial it lists.
	IssuerSubjectKeyID []byte
	// ThisUpdate and NextUpdate are the CRL's own validity. A relying party
	// that is still holding a CRL past NextUpdate is failing open, so the
	// publisher must republish well before it, even when nothing changed.
	ThisUpdate time.Time
	NextUpdate time.Time
}

// RootRotationRequest is a deliberate root rotation.
type RootRotationRequest struct {
	// Validity is the new root's lifetime. Zero means DefaultRootValidity.
	Validity time.Duration
	// RetireOld drops the previous root from the bundle immediately. Default
	// false: both roots stay published until the operator says otherwise,
	// because a relying party that has not refetched the bundle still trusts
	// only the old one.
	RetireOld bool
}

// Rotation timing. These are the numbers the overlap semantics are made of;
// they are constants rather than configuration because a deployment that tunes
// them differently from another deployment has an incident nobody can reason
// about generically.
const (
	// IntermediateSigningPeriod is how long one intermediate signs: thirty
	// days, from docs/totem-design.md.
	IntermediateSigningPeriod = 30 * 24 * time.Hour

	// IntermediatePublicationOverlap is how long before it starts signing an
	// intermediate is already published in the bundle. Seven days, chosen
	// against the slower of the two constraints it serves: not a relying
	// party's bundle poll, which is minutes to hours, but an operator with an
	// offline root who has to schedule a signing ceremony. A shorter window
	// would work for KMS roots and quietly fail for offline ones.
	IntermediatePublicationOverlap = 7 * 24 * time.Hour

	// IntermediateRetirementTail is how long past SigningEnd an intermediate
	// stays valid and in the bundle so the leaves it signed still verify. It
	// must be at least MaxSVIDTTL or a leaf outlives its issuer, which presents
	// to the relying party as an expired-chain failure with a perfectly valid
	// leaf: the single most confusing PKI failure there is.
	IntermediateRetirementTail = 24 * time.Hour

	// IntermediateValidity is the full certificate lifetime of an
	// intermediate: published before it signs, signing for its period, trusted
	// after for the retirement tail.
	IntermediateValidity = IntermediatePublicationOverlap + IntermediateSigningPeriod + IntermediateRetirementTail

	// DefaultRootValidity is the root's lifetime when InitParams does not say.
	// Long, because rotating it is a deliberate operator ceremony that
	// coordinates every relying party's trust anchor, and short-lived roots
	// mean that ceremony happens on a schedule set by this constant rather than
	// by the operator.
	DefaultRootValidity = 10 * 365 * 24 * time.Hour
)

// SVID lifetimes.
const (
	// DefaultSVIDTTL is one hour: the device identity's TTL, renewed at
	// half-life.
	DefaultSVIDTTL = time.Hour

	// MaxSVIDTTL is the ceiling on any X.509-SVID this CA will mint. A request
	// above it is ErrTTLTooLong. The revocation model is "short TTL plus a live
	// enrollment check at every exchange", with a worst-case exposure of one
	// SVID TTL for local use, so this constant IS the worst case and widening
	// it widens that window for every identity at once.
	MaxSVIDTTL = time.Hour

	// DefaultCRLValidity is how long a generated CRL claims to be current. A
	// relying party still holding a CRL past NextUpdate is failing open, so the
	// publisher republishes well inside this even when nothing changed. It is
	// not the revocation latency: revocation reaches Roles Anywhere by an
	// ImportCrl push, not by the relying party noticing an expiry.
	DefaultCRLValidity = 24 * time.Hour

	// BridgeSVIDTTL is fifteen minutes: the lifetime of a bridge SVID used
	// directly against a relying party, where the SVID itself is the
	// presence-gated artifact rather than something exchanged for one.
	BridgeSVIDTTL = 15 * time.Minute
)

// Audit event kinds, written to store.Record.Kind. They are constants here, and
// set by the CA on the SVID it returns, so that the spec's requirement that the
// issuer's self-issuance be "a distinct event type" survives contact with the
// call sites. An issuer self-issuance must never be able to read as a device
// issuance in the log, which is what would happen if the kind were a string a
// handler chose.
const (
	// EventIssuance is an SVID minted for a device, tool or agent identity.
	EventIssuance = "svid.issued"
	// EventIssuerSelfIssuance is the issuer minting its OWN identity,
	// spiffe://<td>/issuer. Distinct on purpose: it has no device, no presence
	// and no human behind it, and an auditor counting device issuances must not
	// have to subtract these out.
	EventIssuerSelfIssuance = "issuer.self_issued"
	// EventIntermediateRotated is a successor intermediate prepared and
	// published.
	EventIntermediateRotated = "ca.intermediate_rotated"
	// EventIntermediatePromoted is a published successor becoming the signing
	// intermediate. Logged because it happens on the clock with no operator
	// action, and an unlogged automatic change of signing key is a gap in the
	// chain.
	EventIntermediatePromoted = "ca.intermediate_promoted"
	// EventRootRotated is a deliberate root rotation.
	EventRootRotated = "ca.root_rotated"
	// EventRevoked is a certificate added to a revocation set.
	EventRevoked = "ca.revoked"
	// EventCRLPublished is a CRL generated and signed.
	EventCRLPublished = "ca.crl_published"
)

// X.509 extension OIDs for the facts that travel on an identity. Protection
// level and presence facts "travel as X.509 extensions and JWT claims, never in
// the path", so relying-party policy matches on an extension rather than
// parsing a URI.
//
// PROVISIONAL ARC. 1.3.6.1.4.1.62733 is a placeholder private-enterprise
// number, not an IANA assignment. It must be replaced with a real PEN before
// the first release: changing an OID after relying parties match on it is a
// breaking change for every deployment at once. Every OID lives in this one
// block so that change is a single edit.
//
// This is not left to a comment somebody has to read at the right moment. See
// OIDArcProvisional and release_gate.go: while the arc is a placeholder, a
// release build does not compile.
var (
	// OIDProtectionLevel carries spiffe.ProtectionLevel as a UTF8String.
	OIDProtectionLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62733, 1, 1}
	// OIDPresenceState carries presence.State as a UTF8String: present,
	// delegated, or none.
	OIDPresenceState = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62733, 1, 2}
	// OIDPresenceAge carries the age of the presence assertion at issuance, in
	// seconds, as an INTEGER.
	OIDPresenceAge = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62733, 1, 3}
	// OIDGrantID carries the grant a delegated issuance was made under, as a
	// UTF8String. Absent when presence is not delegated.
	OIDGrantID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62733, 1, 4}
)

// OIDArcProvisional is non-empty for exactly as long as the OID arc above is a
// placeholder rather than a registered IANA Private Enterprise Number.
//
// It is a string rather than a bool because it doubles as the explanation a
// developer sees, and because release_gate.go turns its LENGTH into a
// compile-time refusal: under `-tags release`, a non-empty value gives an array
// a negative length and the build fails.
//
// A comment saying PROVISIONAL is a note somebody has to read at the right
// moment, and "the right moment" here is the one release where getting it wrong
// is unrecoverable: once relying-party trust policies match on an OID, changing
// it breaks every deployment simultaneously. So the placeholder cannot ship
// silently, which is the actual requirement.
//
// TO RELEASE: register a PEN, replace 62733 in the block above with it, and set
// this to "" in the same commit. Those two edits belong together and the gate
// exists to make sure they happen together.
const OIDArcProvisional = "the x509 extension OID arc is still placeholder PEN 62733, not a registered IANA assignment"

// IssuerPath is the path of the issuer's own identity: spiffe://<td>/issuer.
// It has no device segment and no tool segment, which is what makes it
// structurally impossible to collide with a derived device identity.
const IssuerPath = "/issuer"

// Typed errors. They are distinct because the issuer must behave differently
// for each: refuse loudly, wait, or fail closed. A caller collapsing them into
// "CA error" loses the distinction between "this request asked for something we
// will never do" and "come back after the operator runs a ceremony".
var (
	// ErrUnsupportedAlgorithm means a request carried a key that is not ECDSA
	// P-256 (SVIDs) or asked the CA to sign with something other than ECDSA
	// P-384. This is a REFUSAL. The CA does not substitute the nearest
	// approved algorithm and does not downgrade: a caller that asked for
	// Ed25519 and received P-256 would believe it holds a key it does not.
	ErrUnsupportedAlgorithm = errors.New("ca: unsupported algorithm; SVIDs are ECDSA P-256 and the CA is P-384, and no substitution is made")

	// ErrFIPSRequired means RequireFIPS was set and the binary is not running
	// under the FIPS Go crypto module. Fatal at open, before anything is
	// minted.
	ErrFIPSRequired = errors.New("ca: FIPS mode required but the FIPS crypto module is not active")

	// ErrNotInitialized means there is no CA material to open. `issuer init`
	// has not run, or Dir points somewhere else.
	ErrNotInitialized = errors.New("ca: no CA material found; run issuer init")
	// ErrAlreadyInitialized means Init found existing CA material and refused
	// to overwrite it. Regenerating a root over a live one silently invalidates
	// every enrolled device, so this is never automatic.
	ErrAlreadyInitialized = errors.New("ca: CA material already exists; refusing to overwrite a live root")

	// ErrRootOffline means the root private key is not reachable right now.
	// For an offline root this is the normal steady state and only rotation
	// paths ever see it; it is not an error condition to alert on.
	ErrRootOffline = errors.New("ca: root private key is offline; intermediate rotation needs it present")

	// ErrRotationTooSoon means RotateIntermediate was called before the
	// publication overlap opened. The successor would spend longer than the
	// overlap sitting published, which is harmless, but the schedule that
	// results is no longer the one the constants describe, and every later
	// boundary shifts. Wait until Schedule.RotateAfter.
	ErrRotationTooSoon = errors.New("ca: too soon to rotate; the publication overlap has not opened")

	// ErrRotationPending means a successor is already published and waiting to
	// start signing, so RotateIntermediate did nothing.
	//
	// This is the guard against rotating twice inside one overlap window.
	// Replacing a published successor would mean relying parties that fetched
	// the bundle during the overlap trust an intermediate that will never sign,
	// and reject everything the actual successor signs, until each of them
	// refetches. That is a fleet-wide outage produced by an operator being
	// careful, which is the worst kind.
	ErrRotationPending = errors.New("ca: a successor intermediate is already published; rotating again inside the overlap would break relying parties that already fetched the bundle")

	// ErrNoSigningIntermediate means no intermediate is in its signing window:
	// the current one's SigningEnd passed and no successor was prepared. The CA
	// mints nothing until RotateIntermediate succeeds, which needs the root.
	// Fail closed, loudly; this is the failure mode an offline root buys.
	ErrNoSigningIntermediate = errors.New("ca: no intermediate is in its signing window; rotate the intermediate")

	// ErrIssuerIdentityReserved means IssueSVID was asked for the issuer's own
	// identity: an ID with no device whose tool or agent segment is "issuer",
	// which is the only shape a caller reaching for spiffe://<td>/issuer
	// through the wrong door can express. It is distinct from
	// ErrInvalidIdentity so the caller is told which method to use rather than
	// just that its ID was malformed.
	//
	// There is no mirror error for IssueIssuerSVID being handed a device
	// identity, because IssuerSVIDRequest has no ID field: that mistake is
	// unrepresentable rather than rejected at runtime.
	ErrIssuerIdentityReserved = errors.New("ca: that is the issuer's own identity; mint it with IssueIssuerSVID so it logs as a self-issuance")

	// ErrTrustDomainMismatch means the requested identity sits in a different
	// trust domain than this CA's. Never cross-signed as a courtesy.
	ErrTrustDomainMismatch = errors.New("ca: identity is in a different trust domain")
	// ErrInvalidIdentity means the requested identity is not a legal derived
	// totem ID: an empty device, both tool and agent set, both empty, or a
	// segment that is not a legal SPIFFE path component.
	ErrInvalidIdentity = errors.New("ca: identity is not a legal derived totem SPIFFE ID")

	// ErrTTLTooLong means the requested TTL exceeds MaxSVIDTTL. Refused rather
	// than clamped: a caller that asked for eight hours and silently received
	// one discovers it during an outage.
	ErrTTLTooLong = errors.New("ca: requested TTL exceeds the maximum SVID lifetime")

	// ErrGrantRequired means Presence is presence.StateDelegated but GrantID is
	// empty. A delegated credential that cannot name the grant behind it cannot
	// answer "who authorised this", which is the entire point of the delegated
	// state.
	ErrGrantRequired = errors.New("ca: a delegated issuance must carry the grant it was made under")

	// ErrNotOurCertificate means Revoke was handed a certificate that does not
	// chain to any of this CA's intermediates. Refused, because revocation on
	// an unverified claim lets a caller write serials into a CRL that this CA
	// never issued.
	ErrNotOurCertificate = errors.New("ca: certificate does not chain to this CA; refusing to revoke on an unverified claim")

	// ErrClosed means the Authority has been closed.
	ErrClosed = errors.New("ca: authority is closed")
)
