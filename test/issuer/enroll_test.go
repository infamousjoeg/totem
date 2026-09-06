package issuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// fixedIssuerFingerprint stands in for the SHA-256 of a real issuer
// certificate. Its value doesn't matter to these tests: presence.Verifier.
// Enroll never checks it against anything (the doc comment on Enroll is
// explicit that checking IssuerFingerprint against the issuer's own
// certificate is one of the issuer's own checks, not the signature-layer
// function's), so all it needs to be is a valid-shaped, non-empty SHA-256
// value that both sides of a given enrollment agree on.
func fixedIssuerFingerprint() []byte {
	sum := sha256.Sum256([]byte("test issuer certificate"))
	return sum[:]
}

// enrollmentMaterials is everything one enrollment attempt needs: the
// pre-enrollment device id, the challenge it was minted for, the signed
// EnrollmentInput, and the presence assertion bound to its digest.
type enrollmentMaterials struct {
	deviceID  string
	challenge []byte
	input     presence.EnrollmentInput
	deviceSig []byte
	presence  *presence.Assertion
}

// buildEnrollment mints a fresh challenge for key's device id and produces a
// complete, validly signed enrollment attempt against trustDomain, real
// device proof-of-possession and real presence assertion included.
// bootstrapCode, when non-empty, is bound under BootstrapCodeHash the way a
// device redeeming issuer init's founding bootstrap code would.
func buildEnrollment(t *testing.T, v *presence.Verifier, key *deviceKey, trustDomain, bootstrapCode string) enrollmentMaterials {
	t.Helper()
	devicePub := marshalPub(t, key.Public())
	presencePub := marshalPub(t, key.PresencePublic())
	deviceID := presence.PreEnrollmentDeviceID(devicePub)

	challenge, err := v.Mint(deviceID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return buildEnrollmentWithChallenge(t, key, deviceID, challenge, devicePub, presencePub, trustDomain, bootstrapCode)
}

// buildEnrollmentWithChallenge is buildEnrollment for a caller that already
// has a challenge (used to attempt reusing one that was minted for a
// different device, to prove single-use holds end to end through the public
// Enroll API).
func buildEnrollmentWithChallenge(t *testing.T, key *deviceKey, deviceID string, challenge, devicePub, presencePub []byte, trustDomain, bootstrapCode string) enrollmentMaterials {
	t.Helper()
	var codeHash []byte
	if bootstrapCode != "" {
		codeHash = presence.BootstrapCodeHash(challenge, bootstrapCode)
	}
	in := presence.EnrollmentInput{
		Version:           presence.EncodingVersion,
		Challenge:         challenge,
		IssuerFingerprint: fixedIssuerFingerprint(),
		DevicePublicKey:   devicePub,
		PresencePublicKey: presencePub,
		ProtectionLevel:   spiffe.ProtectionSoftware,
		Hostname:          "joes-mac-studio",
		OS:                "darwin",
		FirstContact:      presence.FirstContactFragment,
		BootstrapCodeHash: codeHash,
	}
	sig, err := presence.SignEnrollment(context.Background(), key, in)
	if err != nil {
		t.Fatalf("SignEnrollment: %v", err)
	}
	digest, err := in.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	a, err := presence.Sign(context.Background(), key, presence.SigningInput{
		DeviceID:    deviceID,
		Tool:        presence.EnrollmentTool,
		Target:      trustDomain,
		Challenge:   challenge,
		RequestHash: digest,
	})
	if err != nil {
		t.Fatalf("Sign (enrollment presence half): %v", err)
	}
	return enrollmentMaterials{deviceID: deviceID, challenge: challenge, input: in, deviceSig: sig, presence: a}
}

// TestFoundingDeviceEnrollsWithBootstrapCode is the real half of the step-2
// gate's item 1, "the founding device enrolls with the bootstrap code and
// receives an SVID, end to end": it drives the real presence.Verifier.Enroll
// with a real device key, a real presence-bound touch, and a real bootstrap
// code hash, exactly as `totem enroll <issuer-url-with-code>` would produce
// on the wire. See TestFoundingDeviceReceivesAnSVID for the remaining half
// (minting the SVID), which is not yet functional pending internal/ca.
func TestFoundingDeviceEnrollsWithBootstrapCode(t *testing.T) {
	v := presence.NewVerifier(0, nil)
	key := newDeviceKey(t)
	const bootstrapCode = "the-one-time-code-issuer-init-printed"

	m := buildEnrollment(t, v, key, testTrustDomain, bootstrapCode)

	enrolled, err := v.Enroll(m.input, m.deviceSig, m.presence, testTrustDomain)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if enrolled.DeviceID != m.deviceID {
		t.Errorf("DeviceID = %q, want %q", enrolled.DeviceID, m.deviceID)
	}
	if enrolled.State != presence.StatePresent {
		t.Errorf("State = %q, want %q (a bootstrap enrollment carries a presence key and assertion)", enrolled.State, presence.StatePresent)
	}
	if enrolled.DeviceKey == nil {
		t.Fatal("DeviceKey is nil")
	}
	if enrolled.PresenceKey == nil {
		t.Fatal("PresenceKey is nil")
	}
	wantDevicePub := marshalPub(t, key.Public())
	gotDevicePub := marshalPub(t, enrolled.DeviceKey)
	if !bytes.Equal(wantDevicePub, gotDevicePub) {
		t.Error("enrolled.DeviceKey does not match the key that was enrolled")
	}

	// Enroll must consume the presence proof itself: it is what the
	// enrollment authorized, and nothing else may spend it afterward.
	if enrolled.Presence == nil {
		t.Fatal("Presence is nil for a bootstrap enrollment")
	}
	if !enrolled.Presence.Used() {
		t.Error("Enroll returned an unconsumed presence proof; a second consumer could still spend it")
	}

	// This is the check the issuer's policy layer performs to decide whether
	// to auto-approve the enrollment as the founding admin: recompute the
	// hash independently from the code and compare against what rode under
	// the signature. Enroll itself does not do this (it is explicitly an
	// issuer-side check per its doc comment), so this test does it the way
	// the issuer will. The meaningful assertion is the negative one: a wrong
	// code must not produce the same hash.
	if !bytes.Equal(m.input.BootstrapCodeHash, presence.BootstrapCodeHash(m.challenge, bootstrapCode)) {
		t.Error("BootstrapCodeHash recomputed from the same challenge and code does not match the signed value")
	}
	if bytes.Equal(m.input.BootstrapCodeHash, presence.BootstrapCodeHash(m.challenge, "definitely-the-wrong-code")) {
		t.Error("BootstrapCodeHash collided for a different code; the founding-admin check would accept any device")
	}
}

// TestEnrollmentChallengeIsSingleUseAcrossDevices proves single-use holds
// through the full public Enroll API, not just Verifier.Verify: once a
// challenge has been spent by one device's enrollment, a second device
// cannot redeem it, even though it is a completely different device key
// signing completely different enrollment fields. This is the property that
// makes the founding-device flow safe against a second, uninvited device
// racing to claim the same bootstrap code's challenge.
func TestEnrollmentChallengeIsSingleUseAcrossDevices(t *testing.T) {
	v := presence.NewVerifier(0, nil)

	key1 := newDeviceKey(t)
	m1 := buildEnrollment(t, v, key1, testTrustDomain, "")
	if _, err := v.Enroll(m1.input, m1.deviceSig, m1.presence, testTrustDomain); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	key2 := newDeviceKey(t)
	devicePub2 := marshalPub(t, key2.Public())
	presencePub2 := marshalPub(t, key2.PresencePublic())
	deviceID2 := presence.PreEnrollmentDeviceID(devicePub2)
	m2 := buildEnrollmentWithChallenge(t, key2, deviceID2, m1.challenge, devicePub2, presencePub2, testTrustDomain, "")

	_, err := v.Enroll(m2.input, m2.deviceSig, m2.presence, testTrustDomain)
	if !errors.Is(err, presence.ErrChallengeReplayed) {
		t.Fatalf("second device's Enroll with an already-spent challenge = %v, want ErrChallengeReplayed", err)
	}
}

// TestFoundingDeviceReceivesAnSVID completes the step-2 gate's item 1: after
// the founding device enrolls for real (exactly as
// TestFoundingDeviceEnrollsWithBootstrapCode proves), the issuer mints it a
// real device SVID from a real internal/ca.Authority, and that SVID must
// chain to the issuer's own bundle. Verification runs stdlib crypto/x509
// against exactly what Authority.Bundle publishes -- the same discipline
// internal/ca's own tests use and test/conformance's own
// TestWorkloadAPIConformance uses via x509svid.Verify -- rather than any
// verifier this package or the CA package could privately agree with itself
// about.
func TestFoundingDeviceReceivesAnSVID(t *testing.T) {
	ctx := context.Background()
	res := &fakeResolver{values: map[string][]byte{"ca_passphrase": []byte("a-passphrase-only-summon-knows")}}
	authority, err := ca.Init(ctx, ca.InitParams{
		Config: ca.Config{
			Dir:           t.TempDir(),
			Resolver:      res,
			PassphraseRef: "ca_passphrase",
			TrustDomain:   testTrustDomain,
		},
		Subject: "Totem Test Issuer",
	})
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	defer authority.Close()

	// Enroll the founding device for real, exactly as
	// TestFoundingDeviceEnrollsWithBootstrapCode does.
	v := presence.NewVerifier(0, nil)
	deviceKey := newDeviceKey(t)
	m := buildEnrollment(t, v, deviceKey, testTrustDomain, "the-one-time-code-issuer-init-printed")
	enrolled, err := v.Enroll(m.input, m.deviceSig, m.presence, testTrustDomain)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	svid, err := authority.IssueSVID(ctx, ca.SVIDRequest{
		ID:              spiffe.ID{TrustDomain: testTrustDomain, DeviceID: enrolled.DeviceID, Tool: "claude"},
		PublicKey:       enrolled.DeviceKey,
		ProtectionLevel: spiffe.ProtectionSoftware,
		Presence:        enrolled.State,
	})
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}

	wantURISuffix := "/device/" + enrolled.DeviceID + "/tool/claude"
	if !strings.HasSuffix(svid.URI, wantURISuffix) {
		t.Errorf("SVID.URI = %q, want it to end with %q", svid.URI, wantURISuffix)
	}
	if svid.Event != ca.EventIssuance {
		t.Errorf("SVID.Event = %q, want %q (a device identity must never read as the issuer's own self-issuance)", svid.Event, ca.EventIssuance)
	}

	bundle, err := authority.Bundle(ctx)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	roots := x509.NewCertPool()
	for _, r := range bundle.Roots {
		roots.AddCert(r)
	}
	inters := x509.NewCertPool()
	for _, in := range bundle.Intermediates {
		inters.AddCert(in.Certificate)
	}
	chains, err := svid.Certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("the founding device's SVID does not chain to the issuer's own published bundle: %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("Verify reported success but returned zero chains to a trusted root")
	}
}

// TestFoundingDeviceIsRecordedAsAdmin is the remaining piece of item 1 beyond
// the SVID: the issuer must persist an EnrollmentRecord for the founding
// device with Admin set, and must refuse a second device that tries to
// redeem the same already-consumed bootstrap code. Both are policy/store
// concerns (internal/policy is still the step-1 scaffold with no evaluation
// or persistence logic; internal/store has no concrete implementation yet),
// not something presence.Verifier.Enroll does on its own -- it verifies
// signatures and challenge freshness only, and returns no Admin field.
func TestFoundingDeviceIsRecordedAsAdmin(t *testing.T) {
	t.Skip("not yet functional: internal/policy has no admin-recording or enrollment-persistence logic " +
		"yet beyond its step-1 scaffold types, and internal/store has no concrete implementation to " +
		"persist an EnrollmentRecord against. Will enroll the founding device for real, hand the " +
		"Enrolled result and the redeemed bootstrap code to the real policy/store layer, assert the " +
		"resulting EnrollmentRecord has Admin=true, and assert a second enrollment attempt bearing the " +
		"same (now-redeemed) bootstrap code is refused even with a freshly minted challenge.")
}
