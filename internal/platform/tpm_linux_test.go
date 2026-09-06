//go:build linux

package platform

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"os"
	"testing"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

func newTestTPMStore(t *testing.T) *TPMStore {
	t.Helper()
	s, err := NewTPMStore(t.TempDir())
	if err != nil {
		t.Skipf("no TPM 2.0 (%v); would have asserted: TPM Generate/Load/Delete lifecycle, ErrKeyExists, ErrKeyNotFound, DER signature round-trip through crypto/ecdsa, ErrPresenceUnavailable on Required=true, and that Attest returns an AK-signed TPM2_Certify of the device key", err)
	}
	return s
}

func TestTPMCandidate(t *testing.T) {
	c := tpmCandidate()
	t.Logf("tpm: available=%v reason=%q", c.Available, c.Reason)
	if c.Level != spiffe.ProtectionHardware || c.Presence {
		t.Fatalf("tpm candidate must be hardware level with no presence: %+v", c)
	}
}

func TestTPMProtectionLevelBeforeKey(t *testing.T) {
	s := newTestTPMStore(t)
	if s.ProtectionLevel() != spiffe.ProtectionHardware {
		t.Fatalf("level = %q", s.ProtectionLevel())
	}
	if _, err := s.Load(context.Background(), DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load before Generate = %v", err)
	}
	if entries, _ := os.ReadDir(s.dir); len(entries) != 0 {
		t.Fatal("ProtectionLevel/Load created files")
	}
}

func TestTPMLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestTPMStore(t)
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public().(*ecdsa.PublicKey)
	challenge := []byte("tpm challenge")
	sig, err := k.Sign(ctx, challenge, Prompt{Required: false})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyChallenge(pub, challenge, sig) {
		t.Fatal("TPM signature did not verify with crypto/ecdsa")
	}
	if _, err := k.Sign(ctx, challenge, Prompt{Required: true, Tool: "aws", Target: "prod", DeviceID: "d"}); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("Sign(Required) = %v, want ErrPresenceUnavailable", err)
	}
	if k.PresencePublic() != nil {
		t.Fatal("TPM key must have no companion presence key")
	}
	if _, err := s.Generate(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Generate = %v", err)
	}
	k2, err := s.Load(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(k2.Public()) {
		t.Fatal("Load returned a different key")
	}
	att, err := k2.(Attester).Attest(ctx, randomNonce())
	if err != nil {
		t.Fatalf("Attest = %v", err)
	}
	if len(att.EKPublic) == 0 || len(att.AKPublic) == 0 || len(att.CertifyInfo) == 0 || len(att.CertifySignature) == 0 {
		t.Fatalf("attestation incomplete: %+v", att)
	}
	t.Logf("EK certificate present: %v (%d bytes)", len(att.EKCertificate) > 0, len(att.EKCertificate))
	if err := s.Delete(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load after Delete = %v", err)
	}
}
