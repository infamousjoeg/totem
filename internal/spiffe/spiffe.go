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

// CatalogEntry names a bridgeable tool. Tool names come from a shipped catalog
// of {name, team_id, signing_id, expected_paths}, because Team ID alone is too
// broad: vendors sign many binaries. Interpreter-wrapped tools get no identity
// and are not represented here.
type CatalogEntry struct {
	// Name is the tool-name segment used in the derived SPIFFE ID.
	Name string
	// TeamID is the Apple Developer Team Identifier the signed binary must
	// carry (the macOS platform check); the Linux equivalent is a separate
	// attestor concern.
	TeamID string
	// SigningID is the code-signing identifier the binary must carry; signed
	// downgrades are accepted in v1, a minimum-version field is v1.x hardening.
	SigningID string
	// ExpectedPaths are the non-user-writable locations the binary is expected
	// to run from.
	ExpectedPaths []string
}
