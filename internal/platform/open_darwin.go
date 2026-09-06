//go:build darwin && cgo

package platform

import "context"

// macOS selection order: Secure Enclave (hardware), then the login keychain
// (keyring), then the 0600 file (software). Each is probed for real
// availability; the first that answers is the store, and Probe reports the
// whole walk for `totem doctor`.
func init() {
	Open = func(ctx context.Context) (KeyStore, error) {
		if s, err := NewSecureEnclaveStore(""); err == nil {
			return s, nil
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
