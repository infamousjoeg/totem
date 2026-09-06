// Package spiffe holds the identity model: derived SPIFFE IDs, the protection
// level carried on each identity, and the shipped tool catalog. Scaffold only:
// types and doc comments, no derivation or validation logic.
package spiffe

// ID is a derived totem identity. There are no registration entries as a
// user-facing concept; the SPIFFE ID is derived:
// spiffe://<trust-domain>/device/<device-id>/tool/<tool-name>, and for a
// long-running agent, spiffe://<trust-domain>/device/<device-id>/agent/<name>.
// Protection level and presence facts travel as X.509 extensions and JWT
// claims, never in the path.
type ID struct {
	// TrustDomain defaults to the issuer hostname given at enroll; IP-only
	// issuers require one explicitly.
	TrustDomain string
	// DeviceID identifies the enrolled device the identity belongs to.
	DeviceID string
	// Tool is the tool-name segment for an interactive tool identity
	// (device/<device-id>/tool/<tool-name>); empty when this is an agent ID.
	Tool string
	// Agent is the name segment for a long-running agent identity
	// (device/<device-id>/agent/<name>); empty when this is a tool ID.
	Agent string
}

// ProtectionLevel is the assurance of the device key backing an identity, and
// it is carried on the identity so downstream policy can act on it. Hardware
// with no presence capability enrolls as recorded, and exchanges still work.
type ProtectionLevel string

const (
	// ProtectionHardware is a key in the Secure Enclave on Apple silicon or
	// TPM 2.0 on Linux; it cannot be exported.
	ProtectionHardware ProtectionLevel = "hardware"
	// ProtectionKeyring is a keyring-backed software key used when no hardware
	// key is available; never refused, always recorded.
	ProtectionKeyring ProtectionLevel = "keyring"
	// ProtectionSoftware is a 0600 file-backed software key used when no
	// hardware or keyring is available; never refused, always recorded.
	ProtectionSoftware ProtectionLevel = "software"
)

// Anchor names what a binary's code signature must chain to for a catalog row
// to match. It is an explicit field rather than something inferred from whether
// TeamID is set, because inference would mean an accidentally-empty TeamID
// silently widens what matches, and a catalog row that quietly accepts more
// binaries than intended is the worst failure this type can have.
//
// The zero value is deliberately NOT "unset". An empty Anchor is read as
// AnchorDeveloperID, the narrower of the two, so a row written before this
// field existed cannot widen when it is loaded by newer code.
type Anchor string

const (
	// AnchorDeveloperID requires a third-party Developer ID Application leaf
	// carrying the Developer ID marker extension, chained to the Apple root,
	// whose Subject OU equals TeamID and whose signing identifier equals
	// SigningID. TeamID must be non-empty. This is how vendor tools like
	// claude are anchored.
	AnchorDeveloperID Anchor = "developer-id"
	// AnchorApplePlatform requires an Apple platform binary: a non-zero
	// CodeDirectory platform byte, the kernel's own CS_PLATFORM_BINARY
	// judgement, and a chain to the Apple root through Apple's code-signing
	// CA, with the signing identifier equal to SigningID. TeamID must be
	// EMPTY, because Apple-shipped tools such as git from the Command Line
	// Tools and ssh carry no Team ID at all. That absence is exactly why this
	// anchor has to be stated rather than derived.
	AnchorApplePlatform Anchor = "apple-platform"
)

// CatalogEntry names a bridgeable tool. Tool names come from a shipped catalog
// of {name, anchor, team_id, signing_id, expected_paths}, because Team ID alone
// is too broad: vendors sign many binaries. Interpreter-wrapped tools get no
// identity and are not represented here.
//
// This shape is persisted by the issuer as admin-signed policy from step 2
// onward, so a field added later costs a schema migration and a policy re-sign
// across every deployment. That is why the anchor lands now, before the first
// Apple-platform row (git, ssh) actually needs it.
type CatalogEntry struct {
	// Anchor is what this row's signature must chain to. Empty means
	// AnchorDeveloperID; see Anchor.
	Anchor Anchor

	// Name is the tool-name segment used in the derived SPIFFE ID.
	Name string
	// TeamID is the Apple Developer Team Identifier the signed binary must
	// carry (the macOS platform check); the Linux equivalent is a separate
	// attestor concern.
	TeamID string
	// SigningID is the code-signing identifier the binary must carry; signed
	// downgrades are accepted in v1, a minimum-version field is v1.x hardening.
	SigningID string
	// ExpectedPaths are the locations the binary is expected to run from.
	//
	// These are NOT guaranteed to be non-user-writable, and for the shipped
	// claude row they are not: both ~/.local/share/claude/versions and the
	// Homebrew prefix are owned by the console user, because the Homebrew
	// prefix is user-owned by design. A strict non-user-writable requirement
	// here would refuse every genuine Claude Code install on every Mac.
	//
	// So the path is a locator, not the control. The control is the anchor:
	// a chain-verified signature plus a cross-check of the on-disk hash
	// against the kernel's cdhash for the running process, which is what
	// closes swapping the file after exec. Whether a path happened to be
	// protected is recorded on the attested identity rather than required.
	ExpectedPaths []string
}
