package presence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Wire constants for the presence assertion signing input.
const (
	// EncodingVersion is the format version carried in every assertion and
	// bound into the signed bytes. The verifier accepts exactly this version.
	EncodingVersion uint8 = 1
	// ChallengeSize is the length of an issuer-minted challenge in bytes.
	ChallengeSize = 32
	// RequestHashSize is the length of a request hash: SHA-256.
	RequestHashSize = sha256.Size
	// maxFieldLen caps any variable-length field. Fields are u32
	// length-prefixed so the format itself allows more; the cap keeps a hostile
	// peer from making the issuer hash megabytes per prompt.
	maxFieldLen = 1 << 16
)

// Domain-separation contexts. Each is a fixed ASCII string written as the
// first field of its encoding so a device-key signature made for one purpose
// can never verify as another (an assertion cannot be replayed as a grant
// sponsorship, a request hash cannot be confused with a batch hash).
const (
	contextAssertion = "totem/presence-assertion"
	contextRequest   = "totem/request"
	contextBatch     = "totem/parked-batch"
	contextGrant     = "totem/grant"
	contextWiden     = "totem/widen"
	contextCode      = "totem/request-code"
)

// ErrMalformed is a structural rejection: a field is missing, over length, or
// the wrong size (a challenge that is not ChallengeSize bytes, a request hash
// that is neither absent nor RequestHashSize bytes). It fires before any
// challenge lookup, so a malformed assertion never spends a challenge.
var ErrMalformed = errors.New("presence: malformed assertion")

// SigningInput is exactly what the device key signs. It is the binding record
// the spec names, "bound to the device, the tool, and, for sensitive targets,
// the specific request", plus the target the human was shown, because
// platform.Prompt says the same three fields travel with the signature.
//
// Bytes encodes it canonically. Every variable-length field carries a
// big-endian uint32 length prefix, so a field boundary can never be shifted:
// (DeviceID "ab", Tool "c") and (DeviceID "a", Tool "bc") produce different
// bytes, and appending or truncating a byte changes a length or leaves the
// decoder short. Layout, version 1:
//
//	u32 len | "totem/presence-assertion"   fixed context, domain separation
//	u8      | 0x01                          EncodingVersion
//	u32 len | DeviceID                      1..maxFieldLen bytes
//	u32 len | Tool                          1..maxFieldLen bytes
//	u32 len | Target                        0..maxFieldLen bytes
//	u32 len | Challenge                     exactly ChallengeSize bytes
//	u32 len | RequestHash                   0 (absent) or RequestHashSize bytes
//
// The platform key signs SHA-256 of these bytes (ECDSA P-256, ASN.1 DER).
type SigningInput struct {
	// Version is the encoding version; Sign fills it with EncodingVersion.
	Version uint8
	// DeviceID is the enrolled device the assertion is bound to.
	DeviceID string
	// Tool is the tool the assertion authorizes.
	Tool string
	// Target is the concrete thing being reached, as shown to the human.
	Target string
	// Challenge is the issuer-minted, single-use value.
	Challenge []byte
	// RequestHash binds the assertion to one request for presence:always
	// targets. Nil for a window touch.
	RequestHash []byte
}

// Bytes returns the canonical signing bytes, or ErrMalformed.
func (in SigningInput) Bytes() ([]byte, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 128)
	b = appendField(b, []byte(contextAssertion))
	b = append(b, in.Version)
	b = appendField(b, []byte(in.DeviceID))
	b = appendField(b, []byte(in.Tool))
	b = appendField(b, []byte(in.Target))
	b = appendField(b, in.Challenge)
	b = appendField(b, in.RequestHash)
	return b, nil
}

func (in SigningInput) validate() error {
	switch {
	case in.DeviceID == "" || len(in.DeviceID) > maxFieldLen:
		return fmt.Errorf("%w: device id length %d", ErrMalformed, len(in.DeviceID))
	case in.Tool == "" || len(in.Tool) > maxFieldLen:
		return fmt.Errorf("%w: tool length %d", ErrMalformed, len(in.Tool))
	case len(in.Target) > maxFieldLen:
		return fmt.Errorf("%w: target length %d", ErrMalformed, len(in.Target))
	case len(in.Challenge) != ChallengeSize:
		return fmt.Errorf("%w: challenge length %d", ErrMalformed, len(in.Challenge))
	case len(in.RequestHash) != 0 && len(in.RequestHash) != RequestHashSize:
		return fmt.Errorf("%w: request hash length %d", ErrMalformed, len(in.RequestHash))
	}
	return nil
}

// Digest returns SHA-256 of the canonical bytes: the value the ECDSA
// signature is actually over.
func (in SigningInput) Digest() ([]byte, error) {
	b, err := in.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// appendField writes a big-endian uint32 length prefix followed by the bytes.
func appendField(b, field []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
	return append(b, field...)
}

// hashParts is the shared hasher behind HashRequest, BatchHash, Grant.Hash and
// WidenHash: SHA-256 over a length-prefixed context followed by each part
// length-prefixed. Same canonicalization argument as SigningInput.Bytes.
func hashParts(context string, parts ...[]byte) []byte {
	h := sha256.New()
	h.Write(appendField(nil, []byte(context)))
	for _, p := range parts {
		h.Write(appendField(nil, p))
	}
	return h.Sum(nil)
}

// RequestCodeLen is the number of hex digits in the request code: 12, so 48
// bits. The code is the only channel binding "what the human's terminal
// said" to "what the OS prompt is asking", and a same-uid process can grind a
// free-text field of its own request until the codes collide. At 32 bits
// that grind takes about a minute on a workstation, inside the challenge
// TTL; at 48 bits it takes days. Do not shorten this for readability; it is
// displayed as three groups of four.
const RequestCodeLen = 12

// RequestCode is the short code the CLI prints for a presence:always request
// and the OS prompt shows verbatim, so the human can compare the two. It is
// derived from BOTH the issuer-minted challenge and the request hash, under
// its own context, so nothing about it is computable before the issuer mints
// the challenge for this request: a same-uid process cannot precompute a
// colliding request from shell history, and two requests for the same target
// in the same second still show different codes. Rendered as
// "XXXX-XXXX-XXXX" (upper-case hex). Empty for an absent request hash, so a
// window touch carries no code.
//
// A malicious caller owns its own TTY, so the code is only meaningful because
// it appears in a prompt the caller cannot draw.
func RequestCode(challenge, requestHash []byte) string {
	if len(requestHash) == 0 {
		return ""
	}
	h := strings.ToUpper(hex.EncodeToString(hashParts(contextCode, challenge, requestHash)))[:RequestCodeLen]
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12]
}

// HashRequest computes the request hash a presence:always assertion binds to.
// Bridges pass the parts that identify the concrete request (for example
// method, target, canonical body) and both sides, agent and issuer, must pass
// the same parts in the same order. Parts are length-prefixed and
// domain-separated, so ("ab","c") and ("a","bc") hash differently.
func HashRequest(parts ...[]byte) []byte {
	return hashParts(contextRequest, parts...)
}
