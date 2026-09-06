package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// fakeKey is a device key whose two public halves the test controls, so the
// enrollment-record comparison can be driven into every case that matters.
type fakeKey struct {
	device   *ecdsa.PrivateKey
	presence *ecdsa.PrivateKey
	level    spiffe.ProtectionLevel
}

func (k *fakeKey) Public() crypto.PublicKey { return &k.device.PublicKey }

func (k *fakeKey) PresencePublic() crypto.PublicKey {
	if k.presence == nil {
		return nil
	}
	return &k.presence.PublicKey
}

func (k *fakeKey) Sign(_ context.Context, challenge []byte, _ platform.Prompt) ([]byte, error) {
	sum := sha256.Sum256(challenge)
	return ecdsa.SignASN1(rand.Reader, k.device, sum[:])
}

func (k *fakeKey) ProtectionLevel() spiffe.ProtectionLevel {
	if k.level == "" {
		return spiffe.ProtectionHardware
	}
	return k.level
}

type fakeStore struct {
	key *fakeKey
	err error
}

func (s *fakeStore) Generate(context.Context, string) (platform.Key, error) {
	return s.key, s.err
}

func (s *fakeStore) Load(context.Context, string) (platform.Key, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.key, nil
}

func (s *fakeStore) Delete(context.Context, string) error { return nil }

func (s *fakeStore) ProtectionLevel() spiffe.ProtectionLevel { return s.key.ProtectionLevel() }

func newFakeKey(t *testing.T, withPresence bool) *fakeKey {
	t.Helper()
	dev, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKey{device: dev}
	if withPresence {
		pres, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.presence = pres
	}
	return k
}

// useKey swaps platform.Open for the duration of one test so doctor's real
// code path runs against a key the test controls. platform.Open is a package
// variable precisely so a caller can be exercised without hardware.
func useKey(t *testing.T, store *fakeStore) {
	t.Helper()
	prev := platform.Open
	platform.Open = func(context.Context) (platform.KeyStore, error) { return store, nil }
	t.Cleanup(func() { platform.Open = prev })
}

func enrolledState(t *testing.T, k *fakeKey) *workloadapi.State {
	t.Helper()
	dev, err := publicKeyDER(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	st := &workloadapi.State{
		TrustDomain:       "issuer.example",
		DeviceID:          "dev1",
		IssuerURL:         "https://issuer.example",
		IssuerFingerprint: testFingerprint,
		KeyLabel:          platform.DeviceKeyLabel,
		DevicePublicDER:   dev,
		Presence:          presence.StateNone,
	}
	if pp := k.PresencePublic(); pp != nil {
		pres, err := publicKeyDER(pp)
		if err != nil {
			t.Fatal(err)
		}
		st.PresencePublicDER = pres
		st.Presence = presence.StatePresent
	}
	return st
}

// TestDoctorAcceptsTheEnrolledKey is the baseline: the key that loads is the
// key the issuer has, on both halves, and doctor says so.
func TestDoctorAcceptsTheEnrolledKey(t *testing.T) {
	k := newFakeKey(t, true)
	useKey(t, &fakeStore{key: k})
	got := checkDeviceKey(context.Background(), enrolledState(t, k))
	if !got.ok {
		t.Fatalf("check failed on a healthy device: %s / %s", got.detail, got.fix)
	}
}

// TestDoctorCatchesADifferentDeviceKey is the failure the platform teammate
// actually hit: a Secure Enclave re-import that goes subtly wrong does not
// error, it hands back a fresh working key that signs happily and verifies
// against nothing anyone enrolled. Only this comparison catches it locally.
func TestDoctorCatchesADifferentDeviceKey(t *testing.T) {
	enrolled := newFakeKey(t, true)
	state := enrolledState(t, enrolled)

	// A different key loads. It works perfectly. That is the whole problem.
	imposter := newFakeKey(t, true)
	useKey(t, &fakeStore{key: imposter})

	got := checkDeviceKey(context.Background(), state)
	if got.ok {
		t.Fatal("doctor passed a device whose key is not the one that enrolled")
	}
	if !strings.Contains(got.fix, "totem enroll") {
		t.Errorf("the fix %q does not tell the human to set the device up again", got.fix)
	}
	if strings.Contains(strings.ToLower(got.detail), "warning") {
		t.Error("a wrong device key is not a warning")
	}
}

// TestDoctorCatchesADifferentPresenceKey covers the quieter half: silent
// renewals keep working and every confirmation fails, which reads as a flaky
// sensor rather than a wrong key unless doctor names it.
func TestDoctorCatchesADifferentPresenceKey(t *testing.T) {
	enrolled := newFakeKey(t, true)
	state := enrolledState(t, enrolled)

	// Same device half, different presence half.
	mixed := &fakeKey{device: enrolled.device, presence: newFakeKey(t, true).presence}
	useKey(t, &fakeStore{key: mixed})

	got := checkDeviceKey(context.Background(), state)
	if got.ok {
		t.Fatal("doctor passed a device whose presence key is not the one that enrolled")
	}
	if !strings.Contains(got.detail, "confirm it's you") {
		t.Errorf("the message %q does not say which key is wrong", got.detail)
	}
}

// TestDoctorCatchesALostPresenceCapability: enrolled able to confirm, now not.
func TestDoctorCatchesALostPresenceCapability(t *testing.T) {
	enrolled := newFakeKey(t, true)
	state := enrolledState(t, enrolled)

	lost := &fakeKey{device: enrolled.device}
	useKey(t, &fakeStore{key: lost})

	got := checkDeviceKey(context.Background(), state)
	if got.ok {
		t.Fatal("doctor passed a device that lost the ability to confirm a person is present")
	}
}

// TestDoctorPassesAPresenceNoneDevice: a device with no way to check for a
// human enrolls at presence "none" and is healthy, not broken.
func TestDoctorPassesAPresenceNoneDevice(t *testing.T) {
	k := newFakeKey(t, false)
	useKey(t, &fakeStore{key: k})
	got := checkDeviceKey(context.Background(), enrolledState(t, k))
	if !got.ok {
		t.Fatalf("a presence-none device is a recorded level, not a failure: %s / %s", got.detail, got.fix)
	}
	if !strings.Contains(got.detail, "cannot ask you to confirm") {
		t.Errorf("the message %q does not say this device cannot confirm", got.detail)
	}
}

// TestDoctorDistinguishesPlatformFailures: not-found, unloadable and stranded
// mean three different things to a human, and conflating them is how somebody
// re-enrolls at a weaker protection level by mistake.
func TestDoctorDistinguishesPlatformFailures(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantsEnroll bool
		saysNot     string
	}{
		{"not found", platform.ErrKeyNotFound, true, ""},
		{"unloadable", platform.ErrKeyUnloadable, true, ""},
		{"stranded", platform.ErrHardwareKeyStranded, false, "re-enroll"},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useKey(t, &fakeStore{key: newFakeKey(t, true), err: tc.err})
			got := checkDeviceKey(context.Background(), &workloadapi.State{KeyLabel: platform.DeviceKeyLabel})
			if got.ok {
				t.Fatalf("%v passed", tc.err)
			}
			if seen[got.detail] {
				t.Errorf("%v produces the same message as another failure; they mean different things", tc.err)
			}
			seen[got.detail] = true

			mentionsEnroll := strings.Contains(got.fix, "totem enroll")
			if tc.wantsEnroll && !mentionsEnroll {
				t.Errorf("the fix %q does not tell the human to enroll", got.fix)
			}
			if !tc.wantsEnroll && mentionsEnroll && !strings.Contains(got.fix, "Do NOT re-enroll") {
				t.Errorf("the fix %q suggests re-enrolling, which would land them at a weaker level", got.fix)
			}
		})
	}
}

// TestToolAnchorReportsAMovedBinary: a pinned tool whose hash moved is a
// refusal with the exact command that resolves it, not a warning.
func TestToolAnchorReportsAMovedBinary(t *testing.T) {
	entry := spiffe.Catalog[0]
	path := resolveToolPath(entry.ExpectedPaths)
	if path == "" {
		t.Skip("the catalog tool is not installed on this machine")
	}
	got := checkOneToolAnchor(entry, strings.Repeat("ab", 32))
	if got.ok {
		t.Fatal("a pinned tool whose hash does not match was reported as fine")
	}
	if !strings.Contains(got.fix, "totem trust "+entry.Name) {
		t.Errorf("the fix %q does not name the command that re-pins it", got.fix)
	}
	if !strings.Contains(got.fix, "do not confirm it") {
		t.Errorf("the fix %q does not warn against re-pinning an unexpected change", got.fix)
	}
}

// TestToolAnchorReportsSignatureOnly: an unpinned tool is not a failure, it is
// a weaker anchor, and doctor says which one is in force.
func TestToolAnchorReportsSignatureOnly(t *testing.T) {
	entry := spiffe.Catalog[0]
	if resolveToolPath(entry.ExpectedPaths) == "" {
		t.Skip("the catalog tool is not installed on this machine")
	}
	got := checkOneToolAnchor(entry, "")
	if !got.ok {
		t.Fatalf("an unpinned but installed tool is not a failure: %s", got.detail)
	}
	if !strings.Contains(got.detail, "signature") {
		t.Errorf("the message %q does not say which anchor is in force", got.detail)
	}
}
