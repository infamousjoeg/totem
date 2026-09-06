package issuer

import (
	"context"
	"errors"
	"testing"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/summon"
)

// TestCARefusesToOpenOrInitWhenThePassphraseIsNotDeclaredSealing exercises
// internal/ca's requirePassphraseSealed refusal, and is exactly why
// fakeResolver's RotationOf has to be able to answer BOTH shapes rather than
// hardcode one: a fake that only ever said "sealing" would make this
// refusal permanently unreachable from this package, which is
// indistinguishable from a refusal that does not work at all -- the same
// failure shape as a key fake that signs both halves of an enrollment with
// one key and lets every positive assertion pass by construction.
//
// Both directions are proven here, on the same resolver interface, so
// neither is trusted on its own: rotatingSecret must be refused, and the
// already-covered sealingSecret path (see TestFoundingDeviceReceivesAnSVID)
// must keep succeeding.
func TestCARefusesToOpenOrInitWhenThePassphraseIsNotDeclaredSealing(t *testing.T) {
	ctx := context.Background()

	t.Run("Init refuses a passphrase declared Rotating", func(t *testing.T) {
		res := &fakeResolver{entries: map[string]fakeSecretEntry{
			"ca_passphrase": rotatingSecret([]byte("a-passphrase-only-summon-knows")),
		}}
		_, err := ca.Init(ctx, ca.InitParams{
			Config: ca.Config{
				Dir:           t.TempDir(),
				Resolver:      res,
				PassphraseRef: "ca_passphrase",
				TrustDomain:   testTrustDomain,
			},
			Subject: "Totem Test Issuer",
		})
		if err == nil {
			t.Fatal("Init succeeded with the CA passphrase declared Rotating, want a refusal")
		}
		if !errors.Is(err, summon.ErrNotSealing) {
			t.Fatalf("Init with a Rotating passphrase = %v, want it to wrap summon.ErrNotSealing", err)
		}
	})

	t.Run("Init refuses an undeclared (unknown) passphrase reference", func(t *testing.T) {
		res := &fakeResolver{entries: map[string]fakeSecretEntry{}}
		_, err := ca.Init(ctx, ca.InitParams{
			Config: ca.Config{
				Dir:           t.TempDir(),
				Resolver:      res,
				PassphraseRef: "ca_passphrase",
				TrustDomain:   testTrustDomain,
			},
			Subject: "Totem Test Issuer",
		})
		if err == nil {
			t.Fatal("Init succeeded with an unconfigured passphrase reference, want a refusal")
		}
		if !errors.Is(err, summon.ErrNoSuchReference) {
			t.Fatalf("Init with an unconfigured passphrase reference = %v, want it to wrap summon.ErrNoSuchReference", err)
		}
	})

	t.Run("Init succeeds, and a later Open refuses once the reference is redeclared Rotating", func(t *testing.T) {
		dir := t.TempDir()
		sealed := &fakeResolver{entries: map[string]fakeSecretEntry{
			"ca_passphrase": sealingSecret([]byte("a-passphrase-only-summon-knows")),
		}}
		authority, err := ca.Init(ctx, ca.InitParams{
			Config: ca.Config{
				Dir:           dir,
				Resolver:      sealed,
				PassphraseRef: "ca_passphrase",
				TrustDomain:   testTrustDomain,
			},
			Subject: "Totem Test Issuer",
		})
		if err != nil {
			t.Fatalf("Init with a Sealing passphrase: %v", err)
		}
		if err := authority.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		// Same material on disk, same passphrase value, but the operator's
		// config now (wrongly) declares it Rotating -- the exact
		// misconfiguration this check exists to catch before it seals a key
		// under a value pull-rotation can later take away.
		rotating := &fakeResolver{entries: map[string]fakeSecretEntry{
			"ca_passphrase": rotatingSecret([]byte("a-passphrase-only-summon-knows")),
		}}
		_, err = ca.Open(ctx, ca.Config{
			Dir:           dir,
			Resolver:      rotating,
			PassphraseRef: "ca_passphrase",
			TrustDomain:   testTrustDomain,
		})
		if err == nil {
			t.Fatal("Open succeeded with the CA passphrase declared Rotating, want a refusal")
		}
		if !errors.Is(err, summon.ErrNotSealing) {
			t.Fatalf("Open with a Rotating passphrase = %v, want it to wrap summon.ErrNotSealing", err)
		}

		// And Open with the SAME resolver shape Init used must still succeed:
		// the refusal is about the declaration, not about Open being broken.
		reopened, err := ca.Open(ctx, ca.Config{
			Dir:           dir,
			Resolver:      sealed,
			PassphraseRef: "ca_passphrase",
			TrustDomain:   testTrustDomain,
		})
		if err != nil {
			t.Fatalf("Open with the correctly Sealing-declared passphrase: %v", err)
		}
		defer reopened.Close()
	})
}
