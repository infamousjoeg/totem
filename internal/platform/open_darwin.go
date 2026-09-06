//go:build darwin && cgo

package platform

import (
	"context"
	"fmt"
	"path/filepath"
)

// macOS selection order: Secure Enclave (hardware), then the login keychain
// (keyring), then the 0600 file (software). Each is probed for real
// availability; the first that answers is the store, and Probe reports the
// whole walk for `totem doctor`. If a Secure Enclave record already exists on
// disk and the Secure Enclave is unavailable, Open fails with
// ErrHardwareKeyStranded instead of handing back a weaker store.
func init() {
	Open = func(ctx context.Context) (KeyStore, error) {
		s, seErr := NewSecureEnclaveStore("")
		if seErr == nil {
			return s, nil
		}
		if base, err := stateDir(); err == nil && hasRecords(filepath.Join(base, "se")) {
			return nil, fmt.Errorf("%w: %v", ErrHardwareKeyStranded, seErr)
		}
		if s, err := NewKeychainStore(); err == nil {
			return s, nil
		}
		return NewFileStore("")
	}
	Probe = func(ctx context.Context) []Candidate {
		return []Candidate{seCandidate(), keychainCandidate(), fileCandidate()}
	}
}
