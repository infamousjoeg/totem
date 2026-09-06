package summon

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// hashFile returns the lowercase hex SHA-256 of the file at p.
func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("summon: opening provider %s: %w", p, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("summon: reading provider %s: %w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// validatePinnedHash rejects a pin that is not a SHA-256 hex digest, so a
// truncated or hand-edited config fails at load rather than silently comparing
// against something that can never match.
func validatePinnedHash(h string) error {
	if len(h) != sha256.Size*2 {
		return fmt.Errorf("%w: pinned hash %q is not a %d-character sha256 hex digest", ErrProviderUntrusted, h, sha256.Size*2)
	}
	if _, err := hex.DecodeString(strings.ToLower(h)); err != nil {
		return fmt.Errorf("%w: pinned hash %q is not hex", ErrProviderUntrusted, h)
	}
	return nil
}

// TrustProvider is the explicit trust-provider action: it verifies the
// provider path is safe and returns the hash the operator should pin.
//
// This is the ONLY way a new hash is produced. Nothing in this package re-pins
// on its own, because "provider hash pinned at issuer init... re-pinned ONLY
// by an explicit trust-provider action" is meaningless if a mismatch can
// quietly become the new pin: an automatic re-pin turns the pin into a record
// of whatever binary happens to be there, which is what an attacker who
// swapped it wants.
//
// The caller writes the returned hash into the config. `totem issuer init`
// calls this once; `totem issuer trust-provider` calls it again after a
// deliberate provider upgrade.
func TrustProvider(providerPath string) (string, error) {
	return trustProvider(providerPath, rootUID)
}

func trustProvider(providerPath string, trustedUID int) (string, error) {
	if providerPath == "" {
		return "", fmt.Errorf("summon: no provider path to trust")
	}
	if err := checkTree(providerPath, trustedUID); err != nil {
		return "", err
	}
	return hashFile(providerPath)
}

// equalHash compares two hex digests case-insensitively and in constant time,
// so a comparison cannot be used to learn the pin one character at a time.
func equalHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(a)), []byte(strings.ToLower(b))) == 1
}
