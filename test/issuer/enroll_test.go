package issuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/store"
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
	res := &fakeResolver{entries: map[string]fakeSecretEntry{"ca_passphrase": sealingSecret([]byte("a-passphrase-only-summon-knows"))}}
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

// newTestPolicyIssuer builds a real policy.Issuer wired to a real store.DB
// (SQLite, sealed data key) and real presence components -- Verifier,
// SessionStore, Registry, Lot -- exactly as cmd/totem-issuer will assemble
// them, rather than a policy-package-internal fake of any of them.
func newTestPolicyIssuer(t *testing.T, clk *testClock) *policy.Issuer {
	t.Helper()
	ctx := context.Background()

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatalf("generate data key: %v", err)
	}
	resolver := newFakeResolver(map[string]fakeSecretEntry{store.DataKeyRefName: sealingSecret(dataKey)})
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "state.db"), store.Options{Resolver: resolver, Clock: clk.Now})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	iss, err := policy.New(ctx, policy.Config{
		TrustDomain: testTrustDomain,
		Verifier:    presence.NewVerifier(0, clk.Now),
		Sessions:    presence.NewSessionStore(clk.Now),
		Grants:      presence.NewRegistry(clk.Now),
		Lot:         presence.NewLot(clk.Now, 0, 0),
		Store:       db,
		Now:         clk.Now,
	})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return iss
}

// enrollDevice drives one device through the real wire shape a `totem
// enroll` would produce against a real policy.Issuer: mint the enrollment
// challenge from the issuer itself, sign both halves for real, and submit.
// bootstrapCode is the plaintext code when redeeming the founding bootstrap
// code, or "" for an ordinary (pending) enrollment.
func enrollDevice(t *testing.T, iss *policy.Issuer, key *deviceKey, bootstrapCode string) (*policy.EnrollResult, string) {
	t.Helper()
	devicePub := marshalPub(t, key.Public())
	presencePub := marshalPub(t, key.PresencePublic())
	deviceID := presence.PreEnrollmentDeviceID(devicePub)

	challenge, err := iss.EnrollmentChallenge(devicePub)
	if err != nil {
		t.Fatalf("EnrollmentChallenge: %v", err)
	}

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
	deviceSig, err := presence.SignEnrollment(context.Background(), key, in)
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
		Target:      testTrustDomain,
		Challenge:   challenge,
		RequestHash: digest,
	})
	if err != nil {
		t.Fatalf("Sign (enrollment presence half): %v", err)
	}

	result, err := iss.Enroll(context.Background(), policy.EnrollRequest{
		Input:             in,
		Signature:         deviceSig,
		PresenceSignature: a.Signature,
		BootstrapCode:     bootstrapCode,
		Name:              "test-device",
	}, fixedIssuerFingerprint())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return result, deviceID
}

// TestFoundingDeviceIsRecordedAsAdmin is the remaining piece of item 1 beyond
// the SVID, now real: the issuer persists an EnrollmentRecord for the
// founding device with Admin and Founding set, through a real policy.Issuer
// backed by a real store.DB, and refuses a second device that tries to
// redeem the same already-consumed bootstrap code, with a freshly minted
// challenge of its own.
func TestFoundingDeviceIsRecordedAsAdmin(t *testing.T) {
	clk := newTestClock()
	iss := newTestPolicyIssuer(t, clk)

	code, expires, err := iss.IssueBootstrapCode(context.Background())
	if err != nil {
		t.Fatalf("IssueBootstrapCode: %v", err)
	}
	if !expires.After(clk.Now()) {
		t.Fatalf("bootstrap code expiry %s is not after now %s", expires, clk.Now())
	}

	key := newDeviceKey(t)
	result, deviceID := enrollDevice(t, iss, key, code)
	if !result.Approved {
		t.Fatal("founding device's EnrollResult.Approved = false, want true")
	}
	if result.DeviceID != deviceID {
		t.Errorf("EnrollResult.DeviceID = %q, want %q", result.DeviceID, deviceID)
	}

	rec, err := iss.Device(deviceID)
	if err != nil {
		t.Fatalf("Device: %v", err)
	}
	if !rec.Admin {
		t.Error("founding device's EnrollmentRecord.Admin = false, want true")
	}
	if !rec.Founding {
		t.Error("founding device's EnrollmentRecord.Founding = false, want true")
	}
	if !rec.Live() {
		t.Error("founding device's EnrollmentRecord.Live() = false, want true")
	}

	// A second device tries to redeem the SAME bootstrap code with its OWN,
	// freshly minted challenge: the code was spent by the first redemption,
	// so this must be refused even though the hash-over-challenge binding is
	// individually well formed.
	secondKey := newDeviceKey(t)
	devicePub2 := marshalPub(t, secondKey.Public())
	presencePub2 := marshalPub(t, secondKey.PresencePublic())
	deviceID2 := presence.PreEnrollmentDeviceID(devicePub2)
	challenge2, err := iss.EnrollmentChallenge(devicePub2)
	if err != nil {
		t.Fatalf("EnrollmentChallenge (second device): %v", err)
	}
	in2 := presence.EnrollmentInput{
		Version:           presence.EncodingVersion,
		Challenge:         challenge2,
		IssuerFingerprint: fixedIssuerFingerprint(),
		DevicePublicKey:   devicePub2,
		PresencePublicKey: presencePub2,
		ProtectionLevel:   spiffe.ProtectionSoftware,
		Hostname:          "a-second-machine",
		OS:                "darwin",
		FirstContact:      presence.FirstContactFragment,
		BootstrapCodeHash: presence.BootstrapCodeHash(challenge2, code),
	}
	deviceSig2, err := presence.SignEnrollment(context.Background(), secondKey, in2)
	if err != nil {
		t.Fatalf("SignEnrollment (second device): %v", err)
	}
	digest2, err := in2.Digest()
	if err != nil {
		t.Fatalf("Digest (second device): %v", err)
	}
	a2, err := presence.Sign(context.Background(), secondKey, presence.SigningInput{
		DeviceID: deviceID2, Tool: presence.EnrollmentTool, Target: testTrustDomain,
		Challenge: challenge2, RequestHash: digest2,
	})
	if err != nil {
		t.Fatalf("Sign (second device): %v", err)
	}

	_, err = iss.Enroll(context.Background(), policy.EnrollRequest{
		Input:             in2,
		Signature:         deviceSig2,
		PresenceSignature: a2.Signature,
		BootstrapCode:     code,
		Name:              "second-machine",
	}, fixedIssuerFingerprint())
	if !errors.Is(err, policy.ErrBootstrapInvalid) {
		t.Fatalf("second device redeeming the already-spent bootstrap code = %v, want ErrBootstrapInvalid", err)
	}

	// The second device must not have been recorded at all.
	if _, err := iss.Device(deviceID2); !errors.Is(err, policy.ErrDeviceNotFound) {
		t.Errorf("Device(second device) after a refused enrollment = %v, want ErrDeviceNotFound", err)
	}
}
