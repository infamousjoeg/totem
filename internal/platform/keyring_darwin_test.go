//go:build darwin && cgo

package platform

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// The keychain tests use the real login keychain under a unique label and
// clean up after themselves; they skip only when the process has no keychain.
func newTestKeychainStore(t *testing.T) (*KeychainStore, string) {
	t.Helper()
	s, err := NewKeychainStore()
	if err != nil {
		t.Skipf("no login keychain in this process (%v); would have asserted keychain Generate/Load/Sign/Delete, ErrKeyExists, ErrKeyNotFound, and ErrPresenceUnavailable", err)
	}
	label := "totem-test-keyring-" + randomSuffix(t)
	t.Cleanup(func() { _ = s.Delete(context.Background(), label) })
	return s, label
}

func TestKeychainStoreProtectionLevelBeforeKey(t *testing.T) {
	s, label := newTestKeychainStore(t)
	if s.ProtectionLevel() != spiffe.ProtectionKeyring {
		t.Fatalf("level = %q", s.ProtectionLevel())
	}
	if _, err := s.Load(context.Background(), label); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load before Generate = %v, want ErrKeyNotFound", err)
	}
}

func TestKeychainStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s, label := newTestKeychainStore(t)
	k, err := s.Generate(ctx, label)
	if err != nil {
		t.Fatal(err)
	}
	if k.ProtectionLevel() != spiffe.ProtectionKeyring {
		t.Fatalf("key level = %q, want keyring", k.ProtectionLevel())
	}
	pub := k.Public().(*ecdsa.PublicKey)
	challenge := []byte("keychain challenge")
	sig, err := k.Sign(ctx, challenge, Prompt{Required: false, Tool: "gh", Target: "github.com", DeviceID: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyChallenge(pub, challenge, sig) {
		t.Fatal("signature did not round-trip through crypto/ecdsa")
	}
	if _, err := k.Sign(ctx, challenge, Prompt{Required: true, Tool: "gh", Target: "github.com", DeviceID: "d"}); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("Sign(Required) = %v, want ErrPresenceUnavailable", err)
	}
	if k.PresencePublic() != nil {
		t.Fatal("keyring key must have no companion presence key")
	}
	if _, err := s.Generate(ctx, label); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Generate = %v, want ErrKeyExists", err)
	}
	k2, err := s.Load(ctx, label)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(k2.Public()) {
		t.Fatal("Load returned a different key")
	}
	if err := s.Delete(ctx, label); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, label); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("second Delete = %v, want ErrKeyNotFound", err)
	}
	if _, err := s.Load(ctx, label); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load after Delete = %v, want ErrKeyNotFound", err)
	}
}
