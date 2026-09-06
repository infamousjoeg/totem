package presence

import (
	"context"
	"fmt"

	"github.com/infamousjoeg/totem/internal/platform"
)

// Assertion is a one-shot presence assertion: a signature over an issuer
// challenge from a biometric-gated key on the device, bound to the device, the
// tool, and, for sensitive targets, the specific request. Presence state lives
// on the issuer as a short session; the laptop never holds anything replayable.
//
// The signature is over SigningInput.Bytes built from the other fields, so a
// verifier reconstructs the exact bytes and never trusts a caller-supplied
// encoding.
type Assertion struct {
	// Version is the encoding version the signature was made under.
	Version uint8
	// DeviceID is the enrolled device the assertion is bound to.
	DeviceID string
	// Tool is the tool the assertion authorizes.
	Tool string
	// Target is the concrete target the human was shown and approved.
	Target string
	// Challenge is the issuer-minted value that was signed.
	Challenge []byte
	// Signature is over the issuer challenge from the biometric-gated key:
	// ECDSA P-256 over SHA-256 of SigningInput.Bytes, ASN.1 DER.
	Signature []byte
	// RequestHash binds the assertion to a specific request for presence:always
	// targets, where the assertion cannot be reused. Nil for a window touch.
	RequestHash []byte
}

// signingInput rebuilds the bytes the signature must be over.
func (a *Assertion) signingInput() SigningInput {
	return SigningInput{
		Version:     a.Version,
		DeviceID:    a.DeviceID,
		Tool:        a.Tool,
		Target:      a.Target,
		Challenge:   a.Challenge,
		RequestHash: a.RequestHash,
	}
}

// Sign produces a presence assertion on the laptop. It builds the canonical
// signing bytes from in (Version is forced to EncodingVersion), raises a real
// presence check through the platform key with a prompt that names the tool,
// the target, the device, and (for a request-bound assertion) the request
// code, and returns the assertion. The signature comes from the key's
// presence half, so the issuer verifies it against Key.PresencePublic, never
// Key.Public. Errors from the key (platform.ErrPresenceDenied,
// platform.ErrPresenceUnavailable) are returned wrapped so callers can branch
// on them; the rogue process hits a fingerprint prompt it cannot answer, which
// is both a block and an alarm.
//
// Sign holds nothing after it returns. The challenge is single-use on the
// issuer, so the returned assertion is worthless once presented.
func Sign(ctx context.Context, key platform.Key, in SigningInput) (*Assertion, error) {
	if key == nil {
		return nil, fmt.Errorf("presence: sign: nil key")
	}
	in.Version = EncodingVersion
	bytes, err := in.Bytes()
	if err != nil {
		return nil, err
	}
	prompt := platform.Prompt{
		Required:    true,
		Tool:        in.Tool,
		Target:      in.Target,
		DeviceID:    in.DeviceID,
		RequestCode: RequestCode(in.RequestHash),
	}
	sig, err := key.Sign(ctx, bytes, prompt)
	if err != nil {
		return nil, fmt.Errorf("presence: sign: %w", err)
	}
	return &Assertion{
		Version:     in.Version,
		DeviceID:    in.DeviceID,
		Tool:        in.Tool,
		Target:      in.Target,
		Challenge:   append([]byte(nil), in.Challenge...),
		Signature:   sig,
		RequestHash: append([]byte(nil), in.RequestHash...),
	}, nil
}
