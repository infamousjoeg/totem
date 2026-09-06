//go:build !darwin && !linux

package platform

import "context"

// On platforms with no hardware or keyring backend implemented, Open returns
// the file store: never refused, recorded as ProtectionSoftware.
func init() {
	Open = func(ctx context.Context) (KeyStore, error) {
		return NewFileStore("")
	}
	Probe = func(ctx context.Context) []Candidate {
		return []Candidate{fileCandidate()}
	}
}
