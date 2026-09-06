//go:build darwin && !cgo

package platform

import (
	"context"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// A CGO_ENABLED=0 macOS build cannot reach the Secure Enclave or the keychain
// (decision 21: cgo on macOS only, and only for this layer). It gets the file
// store and says so, rather than reporting a level it does not have.
func init() {
	Open = func(ctx context.Context) (KeyStore, error) {
		return NewFileStore("")
	}
	Probe = func(ctx context.Context) []Candidate {
		return []Candidate{
			{Name: "secure-enclave", Level: spiffe.ProtectionHardware, Available: false, Reason: "built without cgo"},
			{Name: "keyring", Level: spiffe.ProtectionKeyring, Available: false, Reason: "built without cgo"},
			fileCandidate(),
		}
	}
}
