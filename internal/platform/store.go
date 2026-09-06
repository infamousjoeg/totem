package platform

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// Candidate is one backend Open considered, in the order it considered them,
// with whether it is usable on this machine and why not when it is not. It is
// what `totem doctor` shows so an operator can see what enrollment would get
// and what is standing between them and a better level, without creating
// anything.
type Candidate struct {
	// Name is the backend, e.g. "secure-enclave", "tpm", "keyring", "file".
	Name string
	// Level is the protection level keys from this backend would carry.
	Level spiffe.ProtectionLevel
	// Presence is true when this backend can gate a signature on a human.
	Presence bool
	// Available is true when Open would select this backend if nothing better
	// were available.
	Available bool
	// Reason explains an unavailable backend in one line, or notes a caveat on
	// an available one (for example, that the Secure Enclave device key is
	// unattested). Empty when there is nothing to say.
	Reason string
}

// Probe reports every backend Open would consider on this machine, best first,
// without creating any key. It is the `totem doctor` view of the platform
// layer; Open is the same walk that stops at the first available candidate.
var Probe func(ctx context.Context) []Candidate

// ErrBadKeyFile means a software key file was refused on load because it is
// not a regular file, is not owned by this user, or is readable by anyone else.
// A key that another user could have read is not a key we vouch for.
var ErrBadKeyFile = errors.New("platform: refusing key file with unsafe ownership or permissions")

// ErrInvalidLabel means the label is empty or contains a path separator or
// control character. Labels name files and keychain items, so they are
// restricted to a conservative character set.
var ErrInvalidLabel = errors.New("platform: invalid key label")

// ErrKeyUnloadable means a stored hardware key record exists but the hardware
// refused to re-import it (for example after an OS change to the wrapped-blob
// format). The device must re-enroll. This is deliberately not ErrKeyNotFound:
// a caller that treated it as "not enrolled" would silently re-enroll at
// whatever level Open offers next, which is the degradation this package
// exists to prevent.
var ErrKeyUnloadable = errors.New("platform: stored hardware key cannot be re-imported; the device must re-enroll")

// ErrHardwareKeyStranded means a hardware key record exists on disk but the
// hardware store is unavailable in this process, so Open refused to hand back
// a weaker store. Fix the hardware condition or explicitly revoke and re-enroll.
var ErrHardwareKeyStranded = errors.New("platform: hardware device key exists but its store is unavailable; refusing to fall back to a weaker level")

// Check is what `totem doctor` runs against an enrolled device: it opens the
// selected store, loads label (on the Secure Enclave and TPM that is a real
// re-import of the stored blob into the hardware), produces a silent
// signature, and verifies it against Public. Any failure is returned as-is so
// a breaking OS update is caught by a doctor run rather than by the next
// exchange. It creates nothing.
func Check(ctx context.Context, label string) (Key, error) {
	store, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	k, err := store.Load(ctx, label)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sig, err := k.Sign(ctx, nonce, Prompt{Required: false, Tool: "totem", Target: "doctor", DeviceID: label})
	if err != nil {
		return nil, fmt.Errorf("platform: doctor signature: %w", err)
	}
	if !VerifyChallenge(k.Public(), nonce, sig) {
		return nil, errors.New("platform: doctor signature did not verify against the enrolled public key")
	}
	return k, nil
}

// hasRecords reports whether dir holds any key record; Open uses it to refuse
// a silent fallback when a hardware record is stranded.
func hasRecords(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			return true
		}
	}
	return false
}

// validateLabel enforces the character set a label may use. Labels become file
// names and keychain accounts, so anything that could traverse or confuse is
// refused up front rather than sanitized.
func validateLabel(label string) error {
	if label == "" || len(label) > 128 {
		return ErrInvalidLabel
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return ErrInvalidLabel
		}
	}
	if strings.HasPrefix(label, ".") {
		return ErrInvalidLabel
	}
	return nil
}

// stateDir is the agent's on-disk state directory, ~/.totem, overridable with
// TOTEM_HOME for tests and for running several agents as one user.
func stateDir() (string, error) {
	if d := os.Getenv("TOTEM_HOME"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("platform: resolving home directory: %w", err)
	}
	return filepath.Join(home, ".totem"), nil
}

// signDigestDER signs challenge with a software ECDSA P-256 key and returns the
// ASN.1 DER signature over the SHA-256 digest, the format every backend in this
// package emits so the issuer verifies one way regardless of protection level.
func signDigestDER(priv *ecdsa.PrivateKey, challenge []byte) ([]byte, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("platform: device key is not P-256")
	}
	digest := sha256.Sum256(challenge)
	return ecdsa.SignASN1(nil, priv, digest[:])
}

// VerifyChallenge checks an ECDSA P-256 ASN.1 DER signature over the SHA-256
// digest of challenge against pub. It is the verification the issuer performs
// and the one the tests round-trip every backend through.
func VerifyChallenge(pub crypto.PublicKey, challenge, sig []byte) bool {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return false
	}
	digest := sha256.Sum256(challenge)
	return ecdsa.VerifyASN1(ec, digest[:], sig)
}
