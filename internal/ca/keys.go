package ca

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// Curves, stated once. "ECDSA P-256 for device keys and SVIDs, P-384 for the
// CA. No Ed25519." Everything algorithmic in this package reads from here, so
// there is no second place where a curve could be decided differently.
var (
	svidCurve = elliptic.P256()
	caCurve   = elliptic.P384()
)

// caSignatureAlgorithm pairs with caCurve: P-384 signs with SHA-384. Set
// explicitly on every template rather than left to x509's default, so a change
// of curve cannot silently drag the digest with it.
const caSignatureAlgorithm = x509.ECDSAWithSHA384

// KDF parameters for sealing private keys at rest under the Summon-resolved
// passphrase. PBKDF2-HMAC-SHA256 and AES-256-GCM are both FIPS-approved, which
// matters because Config.RequireFIPS is a refusal: a CA that refused to start
// outside the FIPS boundary and then protected its own keys with something
// outside it would be a paperwork exercise.
const (
	kdfIterations = 210000
	kdfKeyLen     = 32
	saltLen       = 16
)

// sealedKeyPEMType is the PEM block type for a sealed private key. It is
// deliberately not "EC PRIVATE KEY": a file that announces itself as a private
// key an ordinary tool can open invites someone to try, and the failure is
// confusing. This name says what it is.
const sealedKeyPEMType = "TOTEM SEALED PRIVATE KEY"

// newCAKey generates a CA key: ECDSA P-384, per "P-384 for the CA".
func newCAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(caCurve, rand.Reader)
}

// requireSVIDKey enforces "ECDSA P-256 for device keys and SVIDs" on an
// incoming public key.
//
// It refuses rather than substitutes, and it refuses a STRONGER curve as
// readily as a weaker one. P-384 is not a safe silent upgrade here: the fleet
// would end up with two certificate profiles nobody chose, and the caller that
// generated a P-384 key would still be holding a key it believes matches a
// P-256 profile. Refusal is the only answer that leaves the caller's belief
// about its own key correct.
func requireSVIDKey(pub crypto.PublicKey) (*ecdsa.PublicKey, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T is not an ECDSA key", ErrUnsupportedAlgorithm, pub)
	}
	if ec.Curve != svidCurve {
		name := "unnamed curve"
		if ec.Curve != nil && ec.Curve.Params() != nil {
			name = ec.Curve.Params().Name
		}
		return nil, fmt.Errorf("%w: SVID keys are P-256, got %s", ErrUnsupportedAlgorithm, name)
	}
	if ec.X == nil || ec.Y == nil || !ec.Curve.IsOnCurve(ec.X, ec.Y) {
		return nil, fmt.Errorf("%w: public key is not a point on P-256", ErrUnsupportedAlgorithm)
	}
	return ec, nil
}

// requireCAKey enforces P-384 on a key that is about to sign as a CA. It exists
// so a RootProvider implementation (a KMS handle, say) that returns the wrong
// key type is caught at the CA boundary rather than producing certificates
// nobody meant to allow.
func requireCAKey(pub crypto.PublicKey) error {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: CA keys are ECDSA P-384, got %T", ErrUnsupportedAlgorithm, pub)
	}
	if ec.Curve != caCurve {
		name := "unnamed curve"
		if ec.Curve != nil && ec.Curve.Params() != nil {
			name = ec.Curve.Params().Name
		}
		return fmt.Errorf("%w: CA keys are P-384, got %s", ErrUnsupportedAlgorithm, name)
	}
	return nil
}

// newSerial returns a random 128-bit positive serial number.
func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("ca: generating a serial number: %w", err)
	}
	// Zero is a legal but useless serial; nudge it rather than reject, since
	// the odds make a retry loop untestable dead code.
	return n.Add(n, big.NewInt(1)), nil
}

// subjectKeyID is SHA-256 of the SubjectPublicKeyInfo, truncated to 20 bytes.
// RFC 5280's example uses SHA-1; this uses SHA-256 because a FIPS deployment
// should not have to explain a SHA-1 call in its own certificates, and the
// field is an identifier rather than a security boundary either way.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: marshalling a public key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return sum[:20], nil
}

// seal encrypts plaintext under a key derived from the passphrase and salt.
// Layout: nonce || AES-256-GCM ciphertext. The salt lives beside the CA
// material, once per directory, so opening a CA derives the key once per key
// file rather than once per file with a different salt each time.
func seal(passphrase, salt, plaintext []byte) ([]byte, error) {
	aead, err := aeadFor(passphrase, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ca: generating a nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// unseal reverses seal. A wrong passphrase surfaces as an authentication
// failure, which is the correct and only signal GCM gives.
func unseal(passphrase, salt, blob []byte) ([]byte, error) {
	aead, err := aeadFor(passphrase, salt)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, errors.New("ca: sealed key is truncated")
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("ca: cannot unseal CA key material; the passphrase the Summon provider returned does not open it: %w", err)
	}
	return pt, nil
}

func aeadFor(passphrase, salt []byte) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, kdfIterations, kdfKeyLen)
	if err != nil {
		return nil, fmt.Errorf("ca: deriving the key-encryption key: %w", err)
	}
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ca: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// writeSealedKey writes a private key sealed under the passphrase, 0600.
func writeSealedKey(path string, key *ecdsa.PrivateKey, passphrase, salt []byte) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("ca: marshalling a CA key: %w", err)
	}
	defer zero(der)
	blob, err := seal(passphrase, salt, der)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: sealedKeyPEMType, Bytes: blob}), 0o600)
}

// readSealedKey reads a key written by writeSealedKey.
func readSealedKey(path string, passphrase, salt []byte) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != sealedKeyPEMType {
		return nil, fmt.Errorf("ca: %s is not a sealed CA key", filepath.Base(path))
	}
	der, err := unseal(passphrase, salt, block.Bytes)
	if err != nil {
		return nil, err
	}
	defer zero(der)
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing a CA key: %w", err)
	}
	return key, nil
}

func writeCert(path string, der []byte) error {
	return writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func readCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: %s is not a PEM certificate", filepath.Base(path))
	}
	return x509.ParseCertificate(block.Bytes)
}

// writeFileAtomic writes through a temp file and renames, so a crash mid-write
// leaves the previous file rather than a half-written one. CA material that is
// half-written is CA material that is gone.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cryptoRand is the entropy source, named once so every signing call in the
// package is visibly reading from the same place.
var cryptoRand = rand.Reader
