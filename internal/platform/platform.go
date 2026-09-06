// Package platform is the device-key layer: a hardware-bound key that never
// leaves hardware, and a signature over an issuer challenge that only happens
// when a human is present. macOS uses the Secure Enclave with a user-presence
// access control and a LocalAuthentication prompt; Linux uses TPM 2.0 with an
// EK/AK/device-key attestation chain; a software fallback (keyring, then a 0600
// file) is never refused and always recorded at its true protection level.
//
// This file is the FROZEN CONTRACT between the platform implementation and its
// callers (internal/workloadapi, cmd/totem, internal/presence). It is owned by
// the build lead. Implementations live in other files in this package. Do not
// change the signatures here without asking the lead: other teammates are
// compiling against them right now.
package platform

import (
	"context"
	"crypto"
	"errors"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// Prompt is the human-facing reason text for a presence check. The spec
// requires the prompt to name the tool, the target, and the device, so a human
// approving a touch knows exactly what they are approving. It is also the
// binding record for the assertion: the same three fields travel with the
// signature to the issuer.
type Prompt struct {
	// Required is false for a signature that does not need a human (device SVID
	// renewal at half-life, for example). When false, implementations must not
	// raise a biometric prompt.
	Required bool
	// Tool is the catalog tool name the signature authorizes, e.g. "claude".
	Tool string
	// Target is the concrete thing being reached, e.g. an AWS profile name or
	// an Anthropic endpoint. Shown to the human verbatim.
	Target string
	// DeviceID is the enrolled device the key belongs to.
	DeviceID string
}

// Key is one device key. The private half never leaves hardware on a hardware
// protection level; Sign is the only operation that uses it.
type Key interface {
	// Public returns the public half, which is what the issuer enrolled and
	// what it re-checks silently on every renewal.
	Public() crypto.PublicKey

	// Sign produces a signature over challenge. The challenge is issuer-minted
	// and one-shot; nothing replayable is ever held on the laptop. When
	// prompt.Required is true, the implementation must gate the signature on a
	// real human presence check (Touch ID / LocalAuthentication on macOS, the
	// TPM policy session on Linux) and return ErrPresenceDenied if the human
	// declines or the check times out, or ErrPresenceUnavailable if this
	// protection level has no presence capability at all.
	//
	// The signature is ECDSA P-256 over a SHA-256 digest of challenge, in
	// ASN.1 DER, per docs/totem-design.md "Algorithms and FIPS".
	Sign(ctx context.Context, challenge []byte, prompt Prompt) ([]byte, error)

	// ProtectionLevel is the true assurance of this key. It is recorded on the
	// enrollment and travels on every identity as an X.509 extension or JWT
	// claim; it is never inflated to make an exchange succeed.
	ProtectionLevel() spiffe.ProtectionLevel
}

// KeyStore is the per-OS device-key backend. Selection is by capability, best
// available first: Secure Enclave or TPM 2.0, then keyring, then a 0600 file.
// A missing hardware key is a recorded protection level, never a refusal.
type KeyStore interface {
	// Generate creates a new device key under label, replacing nothing. It
	// returns ErrKeyExists if label is already present, so enrollment cannot
	// silently orphan a key the issuer still trusts.
	Generate(ctx context.Context, label string) (Key, error)

	// Load returns the existing key under label, or ErrKeyNotFound.
	Load(ctx context.Context, label string) (Key, error)

	// Delete removes the key under label. It is what `totem uninstall` calls,
	// and it is recorded in the change manifest.
	Delete(ctx context.Context, label string) error

	// ProtectionLevel is the level this store's keys will carry, queryable
	// before a key exists so `totem doctor` can report what enrollment would
	// get without creating anything.
	ProtectionLevel() spiffe.ProtectionLevel
}

// Open selects the best available KeyStore for this machine. Implementations
// are per-OS build-tagged files in this package. Callers get one KeyStore and
// never branch on the OS themselves.
//
// Implemented by the platform teammate. Declared here so callers can compile.
var Open func(ctx context.Context) (KeyStore, error)

// Errors from this package are typed because the harness contract in
// internal/errors branches on them: presence denial is terminal for this
// attempt but not for the next one, while an unavailable presence capability
// is a permanent property of the device.
var (
	// ErrPresenceDenied means the human was asked and declined, or the prompt
	// timed out. The exchange fails; a later attempt may succeed.
	ErrPresenceDenied = errors.New("platform: presence denied")
	// ErrPresenceUnavailable means this protection level cannot check for a
	// human at all. The device enrolls and works, but presence:always targets
	// are closed to it and the credential says presence "none".
	ErrPresenceUnavailable = errors.New("platform: presence unavailable on this protection level")
	// ErrKeyNotFound means label has no key; the device is not enrolled.
	ErrKeyNotFound = errors.New("platform: device key not found")
	// ErrKeyExists means label already has a key and Generate refused to
	// replace it.
	ErrKeyExists = errors.New("platform: device key already exists")
)

// DeviceKeyLabel is the label the agent stores its device key under. One device
// key per machine; per-tool separation happens at the SVID layer, not here.
const DeviceKeyLabel = "totem-device-key"
