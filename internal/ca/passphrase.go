package ca

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var _ PassphraseOperator = (*authority)(nil)

// sealedKeyFiles lists every sealed key file in the CA directory: roots and
// intermediates alike. Re-sealing or verifying a subset is worse than doing
// neither, because a half-sealed directory opens today and fails at the next
// restart, which is the exact failure shape this whole mechanism exists to
// remove.
func (a *authority) sealedKeyFiles() ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(a.dir, "*"+keySuffix))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// unopenable returns the base names of the sealed key files that pass does not
// open, in order.
//
// Any failure counts, not just an authentication failure: a corrupt file and a
// wrong passphrase are different causes with the same consequence, which is
// that the issuer will not come back up. The question being answered is "will a
// restart succeed", so the answer must not be narrowed to one reason it might
// not.
func (a *authority) unopenable(pass []byte) ([]string, error) {
	paths, err := a.sealedKeyFiles()
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, p := range paths {
		if _, err := readSealedKey(p, pass, a.salt); err != nil {
			bad = append(bad, filepath.Base(p))
		}
	}
	return bad, nil
}

// VerifyPassphrase implements PassphraseOperator.VerifyPassphrase: it resolves
// the CA passphrase and attempts the real unseal a restart would attempt.
func (a *authority) VerifyPassphrase(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	pass, err := a.passphrase(ctx)
	if err != nil {
		return err
	}
	defer pass.Zero()

	bad, err := a.unopenable(pass.Bytes())
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: %s", ErrPassphraseChanged, strings.Join(bad, ", "))
	}
	return nil
}

// inMemoryKeyFor returns the unsealed intermediate key behind a key file, if
// this process is already holding it.
//
// This is what lets an intermediate be re-sealed without the previous
// passphrase: the process that noticed the rotation is the same process that
// still has the plaintext keys, so for the intermediates the previous value is
// not needed at all. The root is different, because its key is only ever on
// disk (or off the box entirely) and is never held unsealed in memory.
func (a *authority) inMemoryKeyFor(path string) *ecdsa.PrivateKey {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, interPrefix) {
		return nil
	}
	want := strings.TrimSuffix(strings.TrimPrefix(base, interPrefix), keySuffix)
	for _, in := range a.inters {
		if hex.EncodeToString(in.cert.SubjectKeyId) == want {
			return in.key
		}
	}
	return nil
}

// Reseal implements PassphraseOperator.Reseal.
func (a *authority) Reseal(ctx context.Context, previous []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	// Sealed key files are rewritten through writeFileAtomic, which creates the
	// replacement alongside and renames over the original, so an interrupted
	// re-seal leaves the previous file intact rather than a truncated one.
	current, err := a.passphrase(ctx)
	if err != nil {
		return err
	}
	defer current.Zero()

	paths, err := a.sealedKeyFiles()
	if err != nil {
		return err
	}

	var needPrevious []string
	for _, p := range paths {
		// Already under the current passphrase: leave it alone. This is what
		// makes Reseal idempotent, and therefore what makes an interrupted
		// Reseal completable by running it again rather than by reasoning about
		// which files got through.
		if _, err := readSealedKey(p, current.Bytes(), a.salt); err == nil {
			continue
		}

		key := a.inMemoryKeyFor(p)
		if key == nil {
			if len(previous) == 0 {
				needPrevious = append(needPrevious, filepath.Base(p))
				continue
			}
			key, err = readSealedKey(p, previous, a.salt)
			if err != nil {
				return fmt.Errorf("ca: %s opens under neither the current nor the previous passphrase: %w", filepath.Base(p), err)
			}
		}
		if err := writeSealedKey(p, key, current.Bytes(), a.salt); err != nil {
			return err
		}
	}
	if len(needPrevious) > 0 {
		return fmt.Errorf("%w: %s cannot be re-sealed without the previous passphrase; re-run reseal with it",
			ErrPassphraseChanged, strings.Join(needPrevious, ", "))
	}

	// Confirm the thing that was actually wanted, rather than trusting that the
	// writes above added up to it. The whole point of this mechanism is that a
	// restart will succeed, so check that a restart would succeed.
	bad, err := a.unopenable(current.Bytes())
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: after re-sealing, %s still does not open", ErrPassphraseChanged, strings.Join(bad, ", "))
	}
	return nil
}
