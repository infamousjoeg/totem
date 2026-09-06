//go:build darwin && cgo

package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

func newTestSEStore(t *testing.T) *SecureEnclaveStore {
	t.Helper()
	s, err := NewSecureEnclaveStore(t.TempDir())
	if err != nil {
		t.Skipf("Secure Enclave unavailable (%v); would have asserted: SE Generate/Load/Delete lifecycle, ErrKeyExists, ErrKeyNotFound, silent device-key signature round-trip, and that the presence key refuses a non-interactive signature", err)
	}
	return s
}

func TestSecureEnclaveCandidate(t *testing.T) {
	c := seCandidate()
	t.Logf("secure-enclave: available=%v presence=%v reason=%q", c.Available, c.Presence, c.Reason)
	if c.Level != spiffe.ProtectionHardware {
		t.Fatalf("level = %q", c.Level)
	}
}

func TestSecureEnclaveProtectionLevelBeforeKey(t *testing.T) {
	s := newTestSEStore(t)
	if s.ProtectionLevel() != spiffe.ProtectionHardware {
		t.Fatalf("level = %q", s.ProtectionLevel())
	}
	if _, err := s.Load(context.Background(), DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load before Generate = %v, want ErrKeyNotFound", err)
	}
	if entries, _ := os.ReadDir(s.dir); len(entries) != 0 {
		t.Fatal("ProtectionLevel/Load created files")
	}
}

func TestSecureEnclaveLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestSEStore(t)
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	if k.ProtectionLevel() != spiffe.ProtectionHardware {
		t.Fatalf("key level = %q", k.ProtectionLevel())
	}
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T", k.Public())
	}
	// Silent signature: Required=false must complete with no UI. This test
	// runs headless (and, on the machine it was written on, with the screen
	// locked), so a prompt here would hang or fail rather than pass.
	challenge := []byte("device svid renewal challenge")
	sig, err := k.Sign(ctx, challenge, Prompt{Required: false, Tool: "totem", Target: "issuer", DeviceID: "d"})
	if err != nil {
		t.Fatalf("silent Sign = %v", err)
	}
	if !VerifyChallenge(pub, challenge, sig) {
		t.Fatal("Secure Enclave device-key signature did not verify with crypto/ecdsa")
	}
	if sig[0] != 0x30 {
		t.Fatalf("signature is not DER, first byte %#x", sig[0])
	}
	// Companion presence key is present iff a presence method exists.
	presPub := k.PresencePublic()
	if can, _ := sePresenceAvailable(); can != (presPub != nil) {
		t.Fatalf("presence available=%v but PresencePublic nil=%v", can, presPub == nil)
	}
	if presPub != nil && pub.Equal(presPub) {
		t.Fatal("presence key must be a distinct key from the device key")
	}
	// Record file is 0600 and reloads to the same keys.
	fi, err := os.Stat(s.path(DeviceKeyLabel))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %04o", fi.Mode().Perm())
	}
	k2, err := s.Load(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(k2.Public()) {
		t.Fatal("Load returned a different device key")
	}
	if presPub != nil && !presPub.(*ecdsa.PublicKey).Equal(k2.PresencePublic()) {
		t.Fatal("Load returned a different presence key")
	}
	sig2, err := k2.Sign(ctx, challenge, Prompt{})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyChallenge(pub, challenge, sig2) {
		t.Fatal("reloaded key signature did not verify")
	}
	if _, err := s.Generate(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Generate = %v, want ErrKeyExists", err)
	}
	if err := s.Delete(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load after Delete = %v", err)
	}
	if err := s.Delete(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("second Delete = %v", err)
	}
}

// The proof that the presence gate is in the Secure Enclave's access control
// and not in this package: load the presence key under a LocalAuthentication
// context that forbids interaction and ask the SEP to sign. If the gate were
// in Go, this direct call would produce a signature. It must not.
func TestSecureEnclavePresenceGateIsInACL(t *testing.T) {
	ctx := context.Background()
	s := newTestSEStore(t)
	if can, code := sePresenceAvailable(); !can {
		t.Skipf("no presence method on this Mac (LAError %d); would have asserted the presence key refuses a non-interactive signature while the device key allows one", code)
	}
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	rec := k.(*seKey).rec
	digest := sha256.Sum256([]byte("challenge"))

	// Device key, no interaction: signs.
	if _, err := seSign(ctx, rec.Device, "test", false, digest[:]); err != nil {
		t.Fatalf("device key refused a non-interactive signature: %v", err)
	}
	// Presence key, no interaction: the SEP must refuse.
	sig, err := seSign(ctx, rec.Presence, "test", false, digest[:])
	if err == nil {
		t.Fatalf("presence key produced a signature with interaction forbidden: the gate is not in the ACL (sig %x)", sig)
	}
	var se *seErr
	if !errors.As(err, &se) {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	t.Logf("SEP refused non-interactive presence signature: domain=%s code=%d desc=%q", se.Domain, se.Code, se.Desc)
	mapped := mapPresenceErr(se)
	if !errors.Is(mapped, ErrPresenceUnavailable) && !errors.Is(mapped, ErrPresenceDenied) {
		t.Fatalf("refusal did not map to a contract error: %v", mapped)
	}
	// And through the public path with Required=true but a context that is
	// already expired: no signature, ErrPresenceDenied (timed out).
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	if _, err := k.Sign(expired, []byte("c"), Prompt{Required: true, Tool: "aws", Target: "prod", DeviceID: "d"}); err == nil {
		t.Fatal("Sign with an expired context returned a signature")
	}
}

func TestSecureEnclaveRequiresCompletePrompt(t *testing.T) {
	ctx := context.Background()
	s := newTestSEStore(t)
	if can, code := sePresenceAvailable(); !can {
		t.Skipf("no presence method (LAError %d); would have asserted Sign(Required) with an empty tool/target/device is ErrIncompletePrompt", code)
	}
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Prompt{
		{Required: true, Target: "x", DeviceID: "d"},
		{Required: true, Tool: "aws", DeviceID: "d"},
		{Required: true, Tool: "aws", Target: "x"},
	} {
		if _, err := k.Sign(ctx, []byte("c"), p); !errors.Is(err, ErrIncompletePrompt) {
			t.Fatalf("Sign(%+v) = %v, want ErrIncompletePrompt", p, err)
		}
	}
}

// Interactive: a human must be at the Mac. Set TOTEM_TEST_INTERACTIVE=1.
func TestSecureEnclaveInteractivePresence(t *testing.T) {
	if os.Getenv("TOTEM_TEST_INTERACTIVE") == "" {
		t.Skip("TOTEM_TEST_INTERACTIVE not set; would have asserted: Sign(Required=true) raises a Touch ID / password prompt naming tool, target, and device; approval yields a DER signature that verifies against PresencePublic (not Public); cancelling yields ErrPresenceDenied")
	}
	ctx := context.Background()
	s := newTestSEStore(t)
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	presPub := k.PresencePublic()
	if presPub == nil {
		t.Skip("no presence method on this Mac")
	}
	challenge := []byte("interactive challenge")
	t.Log("APPROVE the prompt now")
	sig, err := k.Sign(ctx, challenge, Prompt{Required: true, Tool: "claude", Target: "api.anthropic.com", DeviceID: "test-mac"})
	if err != nil {
		t.Fatalf("approved Sign = %v", err)
	}
	if !VerifyChallenge(presPub, challenge, sig) {
		t.Fatal("presence signature did not verify against PresencePublic")
	}
	if VerifyChallenge(k.Public(), challenge, sig) {
		t.Fatal("presence signature verified against the device key; keys are not distinct")
	}
	t.Log("CANCEL the prompt now")
	if _, err := k.Sign(ctx, challenge, Prompt{Required: true, Tool: "claude", Target: "api.anthropic.com", DeviceID: "test-mac"}); !errors.Is(err, ErrPresenceDenied) {
		t.Fatalf("cancelled Sign = %v, want ErrPresenceDenied", err)
	}
}

func TestSecureEnclaveRefusesLoosePermissions(t *testing.T) {
	ctx := context.Background()
	s := newTestSEStore(t)
	if _, err := s.Generate(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.path(DeviceKeyLabel), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, DeviceKeyLabel); !errors.Is(err, ErrBadKeyFile) {
		t.Fatalf("Load of 0644 record = %v, want ErrBadKeyFile", err)
	}
}

// The prompt must show what the human is approving: tool, target, device, and
// the CLI's request code verbatim when there is one.
func TestPresenceReasonNamesEverything(t *testing.T) {
	p := Prompt{Required: true, Tool: "aws", Target: "prod-admin", DeviceID: "joes-mbp", RequestCode: "7F3A9C01"}
	got := presenceReason(p)
	for _, want := range []string{"aws", "prod-admin", "joes-mbp", "7F3A9C01"} {
		if !strings.Contains(got, want) {
			t.Fatalf("reason %q does not contain %q", got, want)
		}
	}
	if strings.Contains(presenceReason(Prompt{Tool: "gh", Target: "github.com", DeviceID: "d"}), "request code") {
		t.Fatal("windowed target must not show a request code")
	}
}
