// Package issuer is the step-2 gate: integration tests that drive the real
// issuer-side building blocks together, rather than re-testing any one of
// them in isolation (each already has its own thorough unit-test suite, e.g.
// internal/presence's own *_test.go files).
//
// The step-1 lesson this suite is built around: every real defect found in
// step 1 came from two independently-built things being forced to disagree,
// never from more careful review of one side alone. A fake that only proves
// self-consistency (signs a thing, then checks the signature against the key
// it just signed with) proves nothing about agreement with the real
// counterparty. So wherever this suite could either drive the real
// presence.Verifier / presence.SessionStore / presence.Registry / presence.Lot
// or reimplement a convenient stand-in, it drives the real ones. The only
// fake in this package is deviceKey, and it is a narrow one: a real ECDSA
// P-256 key that signs for real, standing in only for the hardware presence
// prompt (Secure Enclave / TPM) that a human, not a test process, answers.
// Every check of what deviceKey produces -- freshness, binding, replay,
// signature validity -- is done by the real production Verifier, never by
// deviceKey itself.
//
// Coverage, updated as store/ca/summon/policy landed mid-step-2:
//
//   - Fully real: enrollment cryptography including the founding device's
//     bootstrap-code redemption and its real device SVID minted by a real
//     internal/ca.Authority, chain-verified with stdlib crypto/x509 against
//     exactly what Authority.Bundle publishes (enroll_test.go); presence
//     window evaluation (window_test.go); grant narrowing and re-widening
//     (grant_test.go); parked step-up approval (parked_test.go); and a full
//     timed Backup+Restore round trip through a real internal/store.DB,
//     including the release gate's ten-minute budget with the measured
//     duration logged (backup_test.go). Each includes negative assertions
//     and, where the property is actually about concurrency (single-use
//     consumption racing, concurrent narrowing), a real concurrency test
//     under -race rather than a round trip.
//
//   - Honestly skipped, for two different reasons:
//
//     internal/policy is mid-transition as of this writing (its stub.go,
//     explicitly marked temporary, still declares symbols records.go/
//     admin.go/grants.go/evaluate.go have already replaced, so the package
//     does not currently build) -- see TestFoundingDeviceIsRecordedAsAdmin
//     in enroll_test.go, which needs it to record the founding device as
//     admin and refuse a second redemption of the same bootstrap code.
//
//     internal/summon's three provider-ownership refusals (secrets_test.go)
//     are not a gap at all, ruled and closed: the implementation is real and
//     complete, every exported entry point (summon.New, summon.TrustProvider)
//     hardcodes the trusted provider-chain owner to root with no override, and
//     that is deliberate -- no test seam will be added, because an override
//     is exactly the code path the hardening control exists to forbid.
//     TestProviderHardeningIsUnreachableWithoutRootFromThisPackage pins the
//     ruling as a property the code asserts about itself, proven empirically
//     rather than assumed. Coverage for all three lives, for real, inside
//     internal/summon's own test suite via its unexported newForTest.
package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/summon"
)

// testTrustDomain is the trust domain these tests enroll devices against,
// mirroring test/conformance's wltest default ("totem.test") for consistency
// across the suite.
const testTrustDomain = "totem.test"

// deviceKey is a real ECDSA P-256 software key standing in for a hardware
// platform.Key. It implements platform.Key honestly -- Public and
// PresencePublic return the same real key (this suite has no need to
// exercise the Apple-silicon two-key split, which is platform's own concern
// and already covered by platform's tests), and Sign really hashes and
// really signs with real crypto/ecdsa, exactly mirroring how the Secure
// Enclave would respond to an approved touch.
//
// What deviceKey does NOT do is decide whether presence was given: it always
// signs, regardless of Prompt.Required. That is correct for this suite's
// purpose. These tests are about the ISSUER's behavior once it holds a
// signature -- window evaluation, grant narrowing, parked approval -- not
// about whether Touch ID fires, which is platform's job and platform's test
// suite. Every signature deviceKey produces is checked by the real
// presence.Verifier; deviceKey has no opinion on whether it is correct.
type deviceKey struct {
	priv *ecdsa.PrivateKey
}

func newDeviceKey(t *testing.T) *deviceKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	return &deviceKey{priv: priv}
}

func (k *deviceKey) Public() crypto.PublicKey         { return &k.priv.PublicKey }
func (k *deviceKey) PresencePublic() crypto.PublicKey { return &k.priv.PublicKey }

func (k *deviceKey) Sign(_ context.Context, challenge []byte, _ platform.Prompt) ([]byte, error) {
	sum := sha256.Sum256(challenge)
	return ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
}

func (k *deviceKey) ProtectionLevel() spiffe.ProtectionLevel { return spiffe.ProtectionSoftware }

// marshalPub returns the SubjectPublicKeyInfo DER of pub, the encoding every
// wire type in internal/presence expects for a public key field.
func marshalPub(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// testClock is a settable, concurrency-safe clock for issuer-side components
// that take a `now func() time.Time`. It is guarded by a mutex because
// several tests in this package deliberately race goroutines against the
// components under test, and those goroutines all call Now() concurrently.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// touchWindow mints a real challenge, produces a real device signature over
// it via presence.Sign, and verifies it via the real presence.Verifier as a
// plain window touch (no request binding). It is the standard way these
// tests obtain a *presence.Verified: that type's success marker is
// unexported, so a test in this package -- unlike internal/presence's own
// white-box tests -- has no way to construct one except by going through the
// real Mint/Sign/Verify path end to end.
func touchWindow(t *testing.T, v *presence.Verifier, key *deviceKey, deviceID, tool, target string) *presence.Verified {
	t.Helper()
	challenge, err := v.Mint(deviceID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	a, err := presence.Sign(context.Background(), key, presence.SigningInput{
		DeviceID: deviceID, Tool: tool, Target: target, Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verified, err := v.Verify(a, presence.Expectation{
		PresenceKey: key.PresencePublic(),
		DeviceID:    deviceID,
		Tool:        tool,
		Target:      target,
		Binding:     presence.BindingNone,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified
}

// touchAlways is touchWindow's request-bound counterpart: it mints, signs,
// and verifies a presence:always-shaped assertion bound to requestHash. This
// is what grant sponsorship, re-widening, and parked-request approval all
// consume.
func touchAlways(t *testing.T, v *presence.Verifier, key *deviceKey, deviceID, tool, target string, requestHash []byte) *presence.Verified {
	t.Helper()
	challenge, err := v.Mint(deviceID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	a, err := presence.Sign(context.Background(), key, presence.SigningInput{
		DeviceID: deviceID, Tool: tool, Target: target, Challenge: challenge, RequestHash: requestHash,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verified, err := v.Verify(a, presence.Expectation{
		PresenceKey: key.PresencePublic(),
		DeviceID:    deviceID,
		Tool:        tool,
		Target:      target,
		Binding:     presence.BindingRequired,
		RequestHash: requestHash,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified
}

// fakeResolver is the test-only Summon provider the spec calls for: "Tests
// use a fake provider that only compiles into the test binary"
// (docs/totem-design.md, "Secrets"). It hands back a FRESH copy of the value
// on every resolve, because callers are required to Zero what they receive:
// a fake that returned the same backing slice would let one caller's Zero()
// corrupt every other caller's view of "the same" secret, which would be a
// fake that agrees with itself rather than one that models the contract --
// exactly the shape internal/ca's and internal/store's own fakeResolvers use.
type fakeResolver struct {
	mu     sync.Mutex
	values map[string][]byte
	err    error
}

// newFakeResolver returns a resolver serving values keyed by logical
// reference name (e.g. store.DataKeyRefName, "ca_passphrase").
func newFakeResolver(values map[string][]byte) *fakeResolver {
	return &fakeResolver{values: values}
}

func (f *fakeResolver) Resolve(_ context.Context, ref summon.Reference) (summon.Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[string(ref)]
	if !ok {
		return nil, summon.ErrNoSuchReference
	}
	return &fakeValue{b: append([]byte(nil), v...)}, nil
}

func (f *fakeResolver) Refs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.values))
	for k := range f.values {
		out = append(out, k)
	}
	return out
}

type fakeValue struct{ b []byte }

func (v *fakeValue) Bytes() []byte { return v.b }
func (v *fakeValue) Zero() {
	for i := range v.b {
		v.b[i] = 0
	}
}

// sponsorRootGrant builds and signs a root Grant for real (Hash, a real
// presence-bound touch over that hash, Registry.Sponsor) and fails the test
// on any error, for grant tests that only care about what happens after
// sponsorship.
func sponsorRootGrant(t *testing.T, v *presence.Verifier, reg *presence.Registry, key *deviceKey, deviceID, agent string, scope presence.Scope, until time.Time) *presence.Grant {
	t.Helper()
	g := presence.Grant{Agent: agent, Scope: scope.Normalize(), Until: until}
	verified := touchAlways(t, v, key, deviceID, "totem-agents-grant", agent, g.Hash())
	grant, err := reg.Sponsor(g, verified)
	if err != nil {
		t.Fatalf("Sponsor: %v", err)
	}
	return grant
}
