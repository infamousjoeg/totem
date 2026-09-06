package platform

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// fileKeyPEMType is the PEM block type the file store writes. PKCS#8 keeps the
// curve OID inside the blob so a swapped file cannot be misread as P-256.
const fileKeyPEMType = "PRIVATE KEY"

// FileStore is the 0600 file-backed software key store, the floor every machine
// reaches: "keyring or 0600 file-backed software key when no hardware exists;
// never refused, always recorded." Keys carry ProtectionSoftware and have no
// presence capability, so Sign with Prompt.Required returns
// ErrPresenceUnavailable rather than a signature that pretends a human was
// there.
type FileStore struct {
	dir string
}

// NewFileStore returns a FileStore rooted at dir, creating dir with mode 0700
// when absent. An empty dir means <state dir>/keys. It is exported so tests and
// `totem doctor` can point at a scratch directory; production callers go
// through Open.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		base, err := stateDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "keys")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("platform: creating key directory: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

// ProtectionLevel is ProtectionSoftware, queryable before any key exists.
func (s *FileStore) ProtectionLevel() spiffe.ProtectionLevel {
	return spiffe.ProtectionSoftware
}

func (s *FileStore) path(label string) string {
	return filepath.Join(s.dir, label+".pem")
}

// Generate creates a new P-256 key under label. The file is opened with
// O_CREATE|O_EXCL and mode 0600 in one call, so it is never world-readable for
// even an instant and an existing file is ErrKeyExists atomically rather than
// via a check-then-create race.
func (s *FileStore) Generate(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("platform: generating key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("platform: encoding key: %w", err)
	}
	f, err := os.OpenFile(s.path(label), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrKeyExists
		}
		return nil, fmt.Errorf("platform: creating key file: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: fileKeyPEMType, Bytes: der}); err != nil {
		f.Close()
		os.Remove(s.path(label))
		return nil, fmt.Errorf("platform: writing key file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(s.path(label))
		return nil, fmt.Errorf("platform: closing key file: %w", err)
	}
	return &softwareKey{priv: priv, level: spiffe.ProtectionSoftware}, nil
}

// Load returns the key under label or ErrKeyNotFound. Before reading it checks
// the file is a regular file (not a symlink), owned by the current user, and
// not group- or world-readable; anything else is ErrBadKeyFile, because a key
// another user could have copied is not one we can vouch for.
func (s *FileStore) Load(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	p := s.path(label)
	if err := checkKeyFile(p); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("platform: reading key file: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != fileKeyPEMType {
		return nil, errors.New("platform: key file is not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("platform: parsing key file: %w", err)
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("platform: key file is not an ECDSA P-256 key")
	}
	return &softwareKey{priv: priv, level: spiffe.ProtectionSoftware}, nil
}

// Delete removes the key file under label. A missing file is ErrKeyNotFound so
// `totem uninstall` can record exactly what it removed.
func (s *FileStore) Delete(ctx context.Context, label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}
	if err := os.Remove(s.path(label)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("platform: removing key file: %w", err)
	}
	return nil
}

// checkKeyFile refuses a key file that is not a regular file, is a symlink, is
// owned by someone else, or has any group/other permission bits set.
func checkKeyFile(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("platform: stat key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrBadKeyFile, p)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o", ErrBadKeyFile, p, fi.Mode().Perm())
	}
	return checkKeyFileOwner(p, fi)
}

// softwareKey is an in-process ECDSA P-256 key at ProtectionKeyring or
// ProtectionSoftware. It has no presence capability, and it says so.
type softwareKey struct {
	priv  *ecdsa.PrivateKey
	level spiffe.ProtectionLevel
}

// Public returns the public half the issuer enrolled.
func (k *softwareKey) Public() crypto.PublicKey { return &k.priv.PublicKey }

// Sign produces an ECDSA P-256 ASN.1 DER signature over SHA-256(challenge).
// When prompt.Required is true it returns ErrPresenceUnavailable: a software key
// cannot check for a human, and it must never return a signature that implies
// one was there. The credential says presence "none" and exchanges still work
// for targets that allow it.
func (k *softwareKey) Sign(ctx context.Context, challenge []byte, prompt Prompt) ([]byte, error) {
	if prompt.Required {
		return nil, ErrPresenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return signDigestDER(k.priv, challenge)
}

// ProtectionLevel is the true level this key was stored at, never inflated.
func (k *softwareKey) ProtectionLevel() spiffe.ProtectionLevel { return k.level }

// PresencePublic is nil: a software key has no companion presence key.
func (k *softwareKey) PresencePublic() crypto.PublicKey { return nil }

// fileCandidate is the Probe entry for the file store, which is always
// available (it only needs a writable home directory).
func fileCandidate() Candidate {
	c := Candidate{Name: "file", Level: spiffe.ProtectionSoftware, Available: true}
	if _, err := stateDir(); err != nil {
		c.Available = false
		c.Reason = err.Error()
	}
	return c
}
