//go:build linux

package platform

import (
	"context"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// Linux selection order: TPM 2.0 (hardware), then the 0600 file (software).
//
// There is no keyring level on Linux in this build, and it is reported that
// way rather than papered over: the kernel keyring does not survive a reboot,
// so it cannot hold a device key the issuer enrolled once, and the desktop
// Secret Service (gnome-keyring, KWallet) needs a D-Bus client that is not in
// go.mod. Adding one would slot in between the two candidates below.
func init() {
	Open = func(ctx context.Context) (KeyStore, error) {
		if s, err := NewTPMStore(""); err == nil {
			return s, nil
		}
		return NewFileStore("")
	}
	Probe = func(ctx context.Context) []Candidate {
		return []Candidate{
			tpmCandidate(),
			{Name: "keyring", Level: spiffe.ProtectionKeyring, Available: false,
				Reason: "not implemented on Linux: kernel keyring does not persist across reboot; Secret Service needs a D-Bus client not in go.mod"},
			fileCandidate(),
		}
	}
}
