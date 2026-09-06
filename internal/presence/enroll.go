package presence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// contextEnroll is the domain-separation context for the enrollment signing
// input. It is unexported, like every other context in this package: the set
// of purposes a device key can sign for is closed here, so no caller can
// invent a context that collides with another or forget one entirely.
const contextEnroll = "totem/enrollment"

// Enrollment errors.
var (
	// ErrEnrollmentMalformed: a field is missing, over length, or the wrong
	// size.
	ErrEnrollmentMalformed = errors.New("presence: malformed enrollment input")
	// ErrEnrollmentKeyUnsupported: a public key in the input is not ECDSA
	// P-256 in SubjectPublicKeyInfo DER.
	ErrEnrollmentKeyUnsupported = errors.New("presence: enrollment key is not ECDSA P-256")
	// ErrEnrollmentBadSignature: the proof-of-possession signature does not
	// verify under the device public key in the input.
	ErrEnrollmentBadSignature = errors.New("presence: enrollment signature does not verify")
)

// EnrollmentInput is exactly what the device key signs at enroll: the proof
// that the device holding this key answered this issuer's challenge and
// asserted these facts about itself. It mirrors SigningInput and follows the
// same rules: every variable field is big-endian uint32 length-prefixed,
// a fixed context comes first, a version byte is bound in, and the verifier
// re-encodes from the fields rather than trusting caller-supplied bytes.
// Layout, version 1:
//
//	u32 len | "totem/enrollment"        fixed context, domain separation
//	u8      | 0x01                       EncodingVersion
//	u32 len | Challenge                  exactly ChallengeSize bytes
//	u32 len | IssuerFingerprint          SHA-256 of the issuer cert the device pinned
//	u32 len | DevicePublicKey            SPKI DER of platform.Key.Public
//	u32 len | PresencePublicKey          SPKI DER of platform.Key.PresencePublic, or empty
//	u32 len | ProtectionLevel            spiffe.ProtectionLevel string
//	u32 len | Hostname                   as shown on the approval screen
//	u32 len | OS                         as shown on the approval screen
//
// The enrollment code the human types is NOT a field: like RequestCode it is
// a human cross-check derived from the digest (EnrollmentCode), not a second
// binding that could disagree with the first. The device ID is not a field
// either; the issuer derives it from DevicePublicKey after verifying, so a
// device cannot choose its own identifier.
type EnrollmentInput struct {
	// Version is the encoding version. SignEnrollment signs under
	// EncodingVersion regardless of what is set here; the input handed to
	// VerifyEnrollment must carry EncodingVersion explicitly.
	Version uint8
	// Challenge is the issuer-minted, single-use enrollment challenge.
	Challenge []byte
	// IssuerFingerprint is the SHA-256 fingerprint of the issuer certificate
	// the device pinned at first contact. Binding it lets the issuer refuse an
	// enrollment that was made against someone else's certificate.
	IssuerFingerprint []byte
	// DevicePublicKey is the SubjectPublicKeyInfo DER of the device key: what
	// the issuer enrolls and re-checks silently on every renewal.
	DevicePublicKey []byte
	// PresencePublicKey is the SubjectPublicKeyInfo DER of the presence key,
	// or empty when the protection level has no presence capability. The
	// issuer stores it in the PresenceKey slot; it is never the device key.
	PresencePublicKey []byte
	// ProtectionLevel is the true assurance of the device key, as recorded.
	ProtectionLevel spiffe.ProtectionLevel
	// Hostname is the device's hostname as shown on the approval screen.
	Hostname string
	// OS is the device's operating system as shown on the approval screen.
	OS string
}

// Bytes returns the canonical signing bytes, or ErrEnrollmentMalformed.
func (in EnrollmentInput) Bytes() ([]byte, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 512)
	b = appendField(b, []byte(contextEnroll))
	b = append(b, in.Version)
	b = appendField(b, in.Challenge)
	b = appendField(b, in.IssuerFingerprint)
	b = appendField(b, in.DevicePublicKey)
	b = appendField(b, in.PresencePublicKey)
	b = appendField(b, []byte(in.ProtectionLevel))
	b = appendField(b, []byte(in.Hostname))
	b = appendField(b, []byte(in.OS))
	return b, nil
}

func (in EnrollmentInput) validate() error {
	switch {
	case len(in.Challenge) != ChallengeSize:
		return fmt.Errorf("%w: challenge length %d", ErrEnrollmentMalformed, len(in.Challenge))
	case len(in.IssuerFingerprint) != sha256.Size:
		return fmt.Errorf("%w: issuer fingerprint length %d", ErrEnrollmentMalformed, len(in.IssuerFingerprint))
	case len(in.DevicePublicKey) == 0 || len(in.DevicePublicKey) > maxFieldLen:
		return fmt.Errorf("%w: device public key length %d", ErrEnrollmentMalformed, len(in.DevicePublicKey))
	case len(in.PresencePublicKey) > maxFieldLen:
		return fmt.Errorf("%w: presence public key length %d", ErrEnrollmentMalformed, len(in.PresencePublicKey))
	case in.ProtectionLevel == "" || len(in.ProtectionLevel) > maxFieldLen:
		return fmt.Errorf("%w: protection level %q", ErrEnrollmentMalformed, in.ProtectionLevel)
	case len(in.Hostname) > maxFieldLen || len(in.OS) > maxFieldLen:
		return fmt.Errorf("%w: hostname or os over length", ErrEnrollmentMalformed)
	}
	return nil
}

// Digest returns SHA-256 of the canonical bytes: what the device key signs,
// and what an approving admin's presence assertion binds to as its request
// hash (Expectation.Binding = BindingRequired, RequestHash = Digest).
func (in EnrollmentInput) Digest() ([]byte, error) {
	b, err := in.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// EnrollmentCode is the short code the enrolling device prints and the
// approver types, derived from the digest so it cannot disagree with what was
// signed. Same construction and length as RequestCode.
func EnrollmentCode(in EnrollmentInput) (string, error) {
	d, err := in.Digest()
	if err != nil {
		return "", err
	}
	return RequestCode(in.Challenge, d), nil
}

// SignEnrollment produces the device's proof-of-possession signature over the
// canonical enrollment bytes with the device key. No presence is required:
// the approving admin's presence is a separate assertion over Digest via the
// normal Sign/Verify path. Version is forced to EncodingVersion.
func SignEnrollment(ctx context.Context, key platform.Key, in EnrollmentInput) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("presence: sign enrollment: nil key")
	}
	in.Version = EncodingVersion
	b, err := in.Bytes()
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(ctx, b, platform.Prompt{Required: false})
	if err != nil {
		return nil, fmt.Errorf("presence: sign enrollment: %w", err)
	}
	return sig, nil
}

// VerifyEnrollment checks the proof-of-possession: sig must verify, under the
// P-256 device public key carried in the input, over the canonical bytes
// re-encoded from the input's fields. It returns the parsed device key and
// presence key (nil when absent) so the issuer stores exactly what it
// verified. Challenge single-use and issuer-side expectations (which
// fingerprint, which challenge was minted for this enrollment) are the
// issuer's checks; this function is the signature half.
func VerifyEnrollment(in EnrollmentInput, sig []byte) (device, presence *ecdsa.PublicKey, err error) {
	if in.Version != EncodingVersion {
		return nil, nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, in.Version)
	}
	b, err := in.Bytes()
	if err != nil {
		return nil, nil, err
	}
	if len(sig) == 0 {
		return nil, nil, fmt.Errorf("%w: empty signature", ErrEnrollmentMalformed)
	}
	device, err = parseP256(in.DevicePublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: device key: %w", ErrEnrollmentKeyUnsupported, err)
	}
	if len(in.PresencePublicKey) != 0 {
		presence, err = parseP256(in.PresencePublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: presence key: %w", ErrEnrollmentKeyUnsupported, err)
		}
	}
	digest := sha256.Sum256(b)
	if !ecdsa.VerifyASN1(device, digest[:], sig) {
		return nil, nil, ErrEnrollmentBadSignature
	}
	return device, presence, nil
}

// parseP256 parses a SubjectPublicKeyInfo DER and requires ECDSA P-256.
func parseP256(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%T", pub)
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("curve %s", ec.Curve.Params().Name)
	}
	return ec, nil
}
