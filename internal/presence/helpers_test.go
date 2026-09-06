package presence

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// clock is a settable test clock.
type clock struct{ t time.Time }

func newClock() *clock {
	return &clock{t: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time               { return c.t }
func (c *clock) Advance(d time.Duration)      { c.t = c.t.Add(d) }
func (c *clock) Set(t time.Time)              { c.t = t }
func (c *clock) At(d time.Duration) time.Time { return c.t.Add(d) }

// fakeKey is a software stand-in for a platform.Key: a real P-256 key that
// signs like the Secure Enclave would, with hooks to refuse or to sign the
// wrong bytes for attack tests.
type fakeKey struct {
	priv       *ecdsa.PrivateKey
	deny       error
	lastPrompt platform.Prompt
	// mangle rewrites the bytes about to be signed; nil signs them as given.
	mangle func([]byte) []byte
}

func newFakeKey(t *testing.T) *fakeKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKey{priv: priv}
}

func (k *fakeKey) Public() crypto.PublicKey { return &k.priv.PublicKey }

func (k *fakeKey) PresencePublic() crypto.PublicKey { return &k.priv.PublicKey }

func (k *fakeKey) Sign(_ context.Context, challenge []byte, prompt platform.Prompt) ([]byte, error) {
	k.lastPrompt = prompt
	if k.deny != nil {
		return nil, k.deny
	}
	if k.mangle != nil {
		challenge = k.mangle(challenge)
	}
	sum := sha256.Sum256(challenge)
	return ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
}

func (k *fakeKey) ProtectionLevel() spiffe.ProtectionLevel { return spiffe.ProtectionSoftware }

// verified builds an in-package Verified as Verify would, for the session,
// grant, and parking tests that are not about signature verification.
func verified(device string, at time.Time, requestHash []byte) *Verified {
	return verifiedFor(device, "test", "", at, requestHash)
}

// verifiedFor is verified with an explicit tool and target.
func verifiedFor(device, tool, target string, at time.Time, requestHash []byte) *Verified {
	return &Verified{
		DeviceID:    device,
		Tool:        tool,
		Target:      target,
		RequestHash: requestHash,
		Challenge:   make([]byte, ChallengeSize),
		VerifiedAt:  at,
		ok:          true,
	}
}

func mustErr(t *testing.T, got, want error) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("unexpected error: %v", got)
		}
		return
	}
	if !errors.Is(got, want) {
		t.Fatalf("got error %v, want %v", got, want)
	}
}
