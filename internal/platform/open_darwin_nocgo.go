//go:build darwin && !cgo

package platform

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// A CGO_ENABLED=0 macOS build cannot reach the Secure Enclave or the keychain
// (decision 21: cgo on macOS only, and only for this layer). It gets the file
// store and says so, rather than reporting a level it does not have. A
// Secure Enclave record on disk is ErrHardwareKeyStranded here too, so the
// message does not depend on how totem was built.
func init() {
	Open = func(ctx context.Context) (KeyStore, error) {
		if base, err := stateDir(); err == nil && hasRecords(filepath.Join(base, "se")) {
			return nil, fmt.Errorf("%w: this binary was built without cgo and cannot reach the Secure Enclave", ErrHardwareKeyStranded)
		}
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
