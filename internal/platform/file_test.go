package platform

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The store must report its level before any key exists (totem doctor).
func TestFileStoreProtectionLevelBeforeKey(t *testing.T) {
	s := newTestFileStore(t)
	if got := s.ProtectionLevel(); got != spiffe.ProtectionSoftware {
		t.Fatalf("ProtectionLevel = %q, want %q", got, spiffe.ProtectionSoftware)
	}
	if _, err := s.Load(context.Background(), DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load before Generate = %v, want ErrKeyNotFound", err)
	}
	entries, _ := os.ReadDir(s.dir)
	if len(entries) != 0 {
		t.Fatalf("ProtectionLevel/Load created %d files", len(entries))
	}
}

func TestFileStoreGenerateSignVerify(t *testing.T) {
	ctx := context.Background()
	s := newTestFileStore(t)
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	if k.ProtectionLevel() != spiffe.ProtectionSoftware {
		t.Fatalf("key level = %q", k.ProtectionLevel())
	}
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want *ecdsa.PublicKey", k.Public())
	}
	challenge := []byte("issuer-minted one-shot challenge")
	sig, err := k.Sign(ctx, challenge, Prompt{Required: false, Tool: "claude", Target: "api.anthropic.com", DeviceID: "dev-1"})
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip against crypto/ecdsa directly, not only our helper.
	if !VerifyChallenge(pub, challenge, sig) {
		t.Fatal("signature did not verify with crypto/ecdsa (ASN.1 DER over SHA-256)")
	}
	if VerifyChallenge(pub, []byte("different"), sig) {
		t.Fatal("signature verified against a different challenge")
	}
	if sig[0] != 0x30 {
		t.Fatalf("signature is not an ASN.1 SEQUENCE, first byte %#x", sig[0])
	}
	// Companion presence key: none at this level.
	if k.PresencePublic() != nil {
		t.Fatal("software key must have no presence key")
	}
	// Reload yields the same public key.
	k2, err := s.Load(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(k2.Public()) {
		t.Fatal("Load returned a different public key than Generate")
	}
	// File was created 0600.
	fi, err := os.Stat(s.path(DeviceKeyLabel))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %04o, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(s.dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("key dir mode = %04o, want 0700", di.Mode().Perm())
	}
}

// A software key must never return a signature when presence was required.
func TestFileStorePresenceUnavailable(t *testing.T) {
	ctx := context.Background()
	s := newTestFileStore(t)
	k, err := s.Generate(ctx, DeviceKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := k.Sign(ctx, []byte("c"), Prompt{Required: true, Tool: "aws", Target: "prod-admin", DeviceID: "dev-1"})
	if !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("Sign(Required) err = %v, want ErrPresenceUnavailable", err)
	}
	if sig != nil {
		t.Fatal("Sign(Required) returned a signature alongside the error")
	}
}

func TestFileStoreErrKeyExists(t *testing.T) {
	ctx := context.Background()
	s := newTestFileStore(t)
	if _, err := s.Generate(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.path(DeviceKeyLabel))
	if _, err := s.Generate(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Generate = %v, want ErrKeyExists", err)
	}
	after, _ := os.ReadFile(s.path(DeviceKeyLabel))
	if string(before) != string(after) {
		t.Fatal("second Generate overwrote the existing key")
	}
}

func TestFileStoreDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestFileStore(t)
	if err := s.Delete(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete of missing key = %v, want ErrKeyNotFound", err)
	}
	if _, err := s.Generate(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, DeviceKeyLabel); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Load after Delete = %v, want ErrKeyNotFound", err)
	}
	// Delete then Generate works again (uninstall then re-enroll).
	if _, err := s.Generate(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
}

// A key file anyone else can read is refused, not loaded.
func TestFileStoreRefusesLoosePermissions(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o610} {
		s := newTestFileStore(t)
		if _, err := s.Generate(ctx, DeviceKeyLabel); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(s.path(DeviceKeyLabel), mode); err != nil {
			t.Fatal(err)
		}
		k, err := s.Load(ctx, DeviceKeyLabel)
		if !errors.Is(err, ErrBadKeyFile) {
			t.Fatalf("mode %04o: Load = %v, want ErrBadKeyFile", mode, err)
		}
		if k != nil {
			t.Fatalf("mode %04o: Load returned a key with the error", mode)
		}
	}
}

// A symlink where the key file should be is refused: the target could be
// anywhere and owned by anyone.
func TestFileStoreRefusesSymlink(t *testing.T) {
	ctx := context.Background()
	s := newTestFileStore(t)
	other := newTestFileStore(t)
	if _, err := other.Generate(ctx, DeviceKeyLabel); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other.path(DeviceKeyLabel), s.path(DeviceKeyLabel)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, DeviceKeyLabel); !errors.Is(err, ErrBadKeyFile) {
		t.Fatalf("Load through symlink = %v, want ErrBadKeyFile", err)
	}
}

func TestFileStoreRejectsBadLabels(t *testing.T) {
	ctx := context.Background()
	s := newTestFileStore(t)
	for _, label := range []string{"", "../escape", "a/b", ".hidden", "with space", "nul\x00"} {
		if _, err := s.Generate(ctx, label); !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("Generate(%q) = %v, want ErrInvalidLabel", label, err)
		}
		if _, err := s.Load(ctx, label); !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("Load(%q) = %v, want ErrInvalidLabel", label, err)
		}
	}
}

func TestFileStoreDefaultDirUsesTotemHome(t *testing.T) {
	t.Setenv("TOTEM_HOME", t.TempDir())
	s, err := NewFileStore("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(os.Getenv("TOTEM_HOME"), "keys")
	if s.dir != want {
		t.Fatalf("dir = %q, want %q", s.dir, want)
	}
}

// Open must never fail on a machine with a home directory, and whatever it
// returns must honor the contract end to end at its recorded level.
func TestOpenNeverRefuses(t *testing.T) {
	t.Setenv("TOTEM_HOME", t.TempDir())
	ctx := context.Background()
	store, err := Open(ctx)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	level := store.ProtectionLevel()
	switch level {
	case spiffe.ProtectionHardware, spiffe.ProtectionKeyring, spiffe.ProtectionSoftware:
	default:
		t.Fatalf("unknown protection level %q", level)
	}
	cands := Probe(ctx)
	if len(cands) == 0 {
		t.Fatal("Probe returned no candidates")
	}
	var first *Candidate
	for i := range cands {
		if cands[i].Available {
			first = &cands[i]
			break
		}
	}
	if first == nil {
		t.Fatal("Probe reports nothing available but Open succeeded")
	}
	if first.Level != level {
		t.Fatalf("Probe's first available level %q != Open's store level %q", first.Level, level)
	}
	t.Logf("Open selected %s (%s); candidates:", first.Name, level)
	for _, c := range cands {
		t.Logf("  %-15s level=%-9s presence=%-5v available=%-5v %s", c.Name, c.Level, c.Presence, c.Available, c.Reason)
	}
	if level == spiffe.ProtectionHardware {
		t.Skip("hardware store selected; its lifecycle is exercised by the OS-specific tests, not by a blind Generate here")
	}
	label := "totem-test-open-" + randomSuffix(t)
	k, err := store.Generate(ctx, label)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Delete(ctx, label) })
	sig, err := k.Sign(ctx, []byte("x"), Prompt{Required: false})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyChallenge(k.Public(), []byte("x"), sig) {
		t.Fatal("round-trip failed")
	}
	if _, err := k.Sign(ctx, []byte("x"), Prompt{Required: true}); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("software-level Sign(Required) = %v, want ErrPresenceUnavailable", err)
	}
}

// Check is the doctor path: load, silent sign, verify. It must work at every
// level that Open selects and never create a key.
func TestCheck(t *testing.T) {
	t.Setenv("TOTEM_HOME", t.TempDir())
	ctx := context.Background()
	label := "totem-test-check-" + randomSuffix(t)
	if _, err := Check(ctx, label); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Check on unenrolled label = %v, want ErrKeyNotFound", err)
	}
	store, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k, err := store.Generate(ctx, label)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Delete(ctx, label) })
	k2, err := Check(ctx, label)
	if err != nil {
		t.Fatalf("Check = %v", err)
	}
	if !k.Public().(*ecdsa.PublicKey).Equal(k2.Public()) {
		t.Fatal("Check loaded a different key")
	}
	t.Logf("Check passed at level %s", k2.ProtectionLevel())
}
