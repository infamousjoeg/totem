package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// These tests drive the REAL internal/presence verifier. Nothing here is a
// fake, because the only defect worth catching in this file is the one where
// the issuer's mapping and the agent's signing disagree by one field, and two
// self-consistent fakes agree with each other by construction.

const testTrustDomain = "issuer.example.ts.net"

// enrollingDevice is a device's key material and the facts it asserts.
type enrollingDevice struct {
	device      *ecdsa.PrivateKey
	presenceKey *ecdsa.PrivateKey
	deviceDER   []byte
	presenceDER []byte
	deviceID    string
}

func newEnrollingDevice(t *testing.T, withPresence bool) *enrollingDevice {
	t.Helper()
	d := &enrollingDevice{}
	var err error
	if d.device, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if d.deviceDER, err = x509.MarshalPKIXPublicKey(&d.device.PublicKey); err != nil {
		t.Fatal(err)
	}
	d.deviceID = presence.PreEnrollmentDeviceID(d.deviceDER)
	if withPresence {
		if d.presenceKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
		if d.presenceDER, err = x509.MarshalPKIXPublicKey(&d.presenceKey.PublicKey); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// request builds the wire request exactly as cmd/totem's enroll does, then
// signs it: the device half over the canonical enrollment bytes, and the
// presence half over the enrollment digest with the SAME challenge.
func (d *enrollingDevice) request(t *testing.T, challenge []byte, signedTarget, code string, issuerFP []byte) (EnrollRequest, *presence.Assertion) {
	t.Helper()
	req := EnrollRequest{
		DevicePublicDER:   d.deviceDER,
		PresencePublicDER: d.presenceDER,
		ProtectionLevel:   spiffe.ProtectionHardware,
		Hostname:          "laptop.local",
		OS:                "darwin",
		DeviceFingerprint: d.deviceID,
		SignedTarget:      signedTarget,
		EncodingVersion:   presence.EncodingVersion,
		IssuerURL:         "https://" + testTrustDomain,
		IssuerFingerprint: hex.EncodeToString(issuerFP),
		FirstContact:      presence.FirstContactFragment,
		Challenge:         challenge,
		BootstrapCode:     code,
	}
	in, err := EnrollmentInput(req)
	if err != nil {
		t.Fatalf("mapping the request: %v", err)
	}
	req.Signature = signBytes(t, d.device, mustBytes(t, in))
	if d.presenceKey == nil {
		return req, nil
	}
	digest, err := in.Digest()
	if err != nil {
		t.Fatal(err)
	}
	a := &presence.Assertion{
		Version:     presence.EncodingVersion,
		DeviceID:    d.deviceID,
		Tool:        presence.EnrollmentTool,
		Target:      signedTarget,
		Challenge:   challenge,
		RequestHash: digest,
	}
	a.Signature = signBytes(t, d.presenceKey, mustBytes(t, presence.SigningInput{
		Version:     a.Version,
		DeviceID:    a.DeviceID,
		Tool:        a.Tool,
		Target:      a.Target,
		Challenge:   a.Challenge,
		RequestHash: a.RequestHash,
	}))
	req.PresenceAssertion = a.Signature
	return req, a
}

type canonical interface{ Bytes() ([]byte, error) }

func mustBytes(t *testing.T, c canonical) []byte {
	t.Helper()
	b, err := c.Bytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	return b
}

func signBytes(t *testing.T, k *ecdsa.PrivateKey, b []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func issuerFingerprint(t *testing.T) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte("a self-signed front door certificate"))
	return sum[:]
}

// TestEnrollmentInputAgreesWithRealVerifier is the agreement test. It takes the
// wire request the agent sends, runs it through THIS package's mapping, and
// feeds the result to the real presence.Verifier.Enroll with the issuer's own
// trust domain. A mapping that differs from cmd/totem's by one field produces
// canonical bytes that do not verify, and this is where that shows up.
func TestEnrollmentInputAgreesWithRealVerifier(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, assertion := d.request(t, challenge, testTrustDomain, "", issuerFingerprint(t))
	in, err := EnrollmentInput(req)
	if err != nil {
		t.Fatal(err)
	}

	out, err := v.Enroll(in, req.Signature, assertion, testTrustDomain)
	if err != nil {
		t.Fatalf("the real verifier refused an enrollment this package mapped: %v", err)
	}
	if out.DeviceID != d.deviceID {
		t.Errorf("device id: got %s, want %s", out.DeviceID, d.deviceID)
	}
	if out.State != presence.StatePresent {
		t.Errorf("presence state: got %s, want %s", out.State, presence.StatePresent)
	}
	if out.PresenceKey == nil || !out.PresenceKey.Equal(&d.presenceKey.PublicKey) {
		t.Error("the verifier recorded a presence key that is not the one the device sent")
	}
	if out.DeviceKey == nil || !out.DeviceKey.Equal(&d.device.PublicKey) {
		t.Error("the verifier recorded a device key that is not the one the device sent")
	}
	// The presence half must be the PRESENCE key, never the device key. On
	// Apple silicon the device key signs silent renewals with no human, so an
	// enrollment that recorded the device key in the presence slot would accept
	// a signature no person ever gated, forever, and look healthy doing it.
	if out.PresenceKey.Equal(&d.device.PublicKey) {
		t.Fatal("the presence key and the device key are the same key")
	}
}

// TestOneChallengeCoversBothSignatures is the reason Enroll exists as a single
// call. Verifying the two halves separately spends the challenge on the first,
// and the second then fails as a replay: a bug that only appears against real
// hardware, where the two halves are genuinely two keys.
func TestOneChallengeCoversBothSignatures(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, assertion := d.request(t, challenge, testTrustDomain, "", issuerFingerprint(t))
	in, err := EnrollmentInput(req)
	if err != nil {
		t.Fatal(err)
	}

	// The wrong way round: verify the presence half on its own first.
	if _, err := v.Verify(assertion, presence.Expectation{
		PresenceKey: &d.presenceKey.PublicKey,
		DeviceID:    d.deviceID,
		Tool:        presence.EnrollmentTool,
		Target:      testTrustDomain,
		Binding:     presence.BindingRequired,
		RequestHash: assertion.RequestHash,
	}); err != nil {
		t.Fatalf("the assertion itself is valid, so this should have passed: %v", err)
	}
	// And now the enrollment cannot complete, because its challenge is spent.
	_, err = v.Enroll(in, req.Signature, assertion, testTrustDomain)
	if !errors.Is(err, presence.ErrChallengeReplayed) {
		t.Fatalf("splitting the verification should have burned the challenge; got %v", err)
	}
}

// TestAssertedTrustDomainIsDiagnosticOnly documents WHY internal/policy
// reconstructs the assertion target from the issuer's own configured value
// unconditionally, and why it produces its diagnostic some other way.
//
// Both branches below are true facts about internal/presence. Substituting the
// device's asserted name into the assertion would yield ErrTargetMismatch, a
// precise sentinel, and it cannot widen acceptance: asserting our own name
// changes nothing and asserting another fails earlier rather than later. policy
// still refuses to do it, and is right to. Assertion.Target is the verifier's
// INPUT, so that substitution puts a device-chosen string back into the struct
// presence checks, in the one place this build spent its time establishing that
// a device sends signature bytes and never a target. The invariant is worth
// more than the better sentinel, so policy pays a heuristic instead
// (policy.ErrAssertedTrustDomain) and keeps Target: cfg.TrustDomain readable at
// the call site.
//
// This test is therefore documentation of a road not taken, and it is the test
// that would notice if anyone ever took it.
func TestAssertedTrustDomainIsDiagnosticOnly(t *testing.T) {
	t.Parallel()
	const wrong = "issuer.example.com"

	t.Run("reconstructed as the device signed it, the error names the mismatch", func(t *testing.T) {
		v := presence.NewVerifier(0, nil)
		d := newEnrollingDevice(t, true)
		challenge, err := v.Mint(d.deviceID)
		if err != nil {
			t.Fatal(err)
		}
		req, assertion := d.request(t, challenge, wrong, "", issuerFingerprint(t))
		in, err := EnrollmentInput(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Enroll(in, req.Signature, assertion, testTrustDomain)
		if !errors.Is(err, presence.ErrTargetMismatch) {
			t.Fatalf("want ErrTargetMismatch (a name mismatch a human can act on); got %v", err)
		}
	})

	t.Run("reconstructed with the issuer's own name, the diagnostic is lost", func(t *testing.T) {
		v := presence.NewVerifier(0, nil)
		d := newEnrollingDevice(t, true)
		challenge, err := v.Mint(d.deviceID)
		if err != nil {
			t.Fatal(err)
		}
		req, assertion := d.request(t, challenge, wrong, "", issuerFingerprint(t))
		in, err := EnrollmentInput(req)
		if err != nil {
			t.Fatal(err)
		}
		assertion.Target = testTrustDomain // what policy.EnrollRequest forces today
		_, err = v.Enroll(in, req.Signature, assertion, testTrustDomain)
		if !errors.Is(err, presence.ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, which is the unhelpful outcome this documents; got %v", err)
		}
	})
}

// TestPresenceAssertionNeverVerifiesAgainstTheDeviceKey is the second
// non-negotiable rule, stated as a test rather than a comment.
func TestPresenceAssertionNeverVerifiesAgainstTheDeviceKey(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, assertion := d.request(t, challenge, testTrustDomain, "", issuerFingerprint(t))
	in, err := EnrollmentInput(req)
	if err != nil {
		t.Fatal(err)
	}
	// Sign the assertion with the DEVICE key, which is what a device would do
	// if the two halves were confused anywhere in the chain. The device key
	// signs silently, so this signature was gated by no human at all.
	assertion.Signature = signBytes(t, d.device, mustBytes(t, presence.SigningInput{
		Version: assertion.Version, DeviceID: assertion.DeviceID, Tool: assertion.Tool,
		Target: assertion.Target, Challenge: assertion.Challenge, RequestHash: assertion.RequestHash,
	}))
	if _, err := v.Enroll(in, req.Signature, assertion, testTrustDomain); !errors.Is(err, presence.ErrBadSignature) {
		t.Fatalf("a device-key signature must never satisfy the presence half; got %v", err)
	}
}

// TestBootstrapCodeIsBoundUnderTheSignature. Redeeming a code makes a device
// the founding admin, so an attacker who sees one ordinary enrollment must not
// be able to staple a stolen code onto it.
func TestBootstrapCodeIsBoundUnderTheSignature(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, assertion := d.request(t, challenge, testTrustDomain, "", issuerFingerprint(t))

	// Staple a code onto an enrollment that was signed without one.
	req.BootstrapCode = "STOLEN-CODE"
	in, err := EnrollmentInput(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Enroll(in, req.Signature, assertion, testTrustDomain); !errors.Is(err, presence.ErrEnrollmentBadSignature) {
		t.Fatalf("adding a bootstrap code after signing must break the signature; got %v", err)
	}

	// And a genuine one verifies, with only its hash ever encoded.
	v2 := presence.NewVerifier(0, nil)
	d2 := newEnrollingDevice(t, true)
	c2, err := v2.Mint(d2.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req2, a2 := d2.request(t, c2, testTrustDomain, "REAL-CODE", issuerFingerprint(t))
	in2, err := EnrollmentInput(req2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Enroll(in2, req2.Signature, a2, testTrustDomain); err != nil {
		t.Fatalf("a genuine bootstrap enrollment was refused: %v", err)
	}
	encoded := mustBytes(t, in2)
	if idx := indexOf(encoded, []byte("REAL-CODE")); idx >= 0 {
		t.Fatal("the bootstrap code itself appears in the canonical enrollment bytes; only its hash may")
	}
	if len(in2.BootstrapCodeHash) != sha256.Size {
		t.Fatalf("bootstrap code hash length %d, want %d", len(in2.BootstrapCodeHash), sha256.Size)
	}
}

func indexOf(haystack, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// TestFirstContactNormalisesToTheWeakerPath. A field that names the weaker path
// is exactly the field worth rewriting, so anything that is not precisely
// "fragment" must be recorded as the prompt path.
func TestFirstContactNormalisesToTheWeakerPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   presence.FirstContact
		want presence.FirstContact
	}{
		{presence.FirstContactFragment, presence.FirstContactFragment},
		{presence.FirstContactPrompt, presence.FirstContactPrompt},
		{"", presence.FirstContactPrompt},
		{"FRAGMENT", presence.FirstContactPrompt},
		{"something else", presence.FirstContactPrompt},
	} {
		if got := firstContactOrWeakest(tc.in); got != tc.want {
			t.Errorf("firstContactOrWeakest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeviceIDIsDerivedNotReported. A device does not choose its own identifier.
func TestDeviceIDIsDerivedNotReported(t *testing.T) {
	t.Parallel()
	d := newEnrollingDevice(t, false)

	got, err := deviceIDFor(d.deviceDER, "")
	if err != nil || got != d.deviceID {
		t.Fatalf("derived id: got %q, %v; want %q", got, err, d.deviceID)
	}
	if _, err := deviceIDFor(d.deviceDER, "0123456789abcdef"); err == nil {
		t.Fatal("a reported fingerprint that disagrees with the key must be refused")
	}
	if _, err := deviceIDFor(nil, d.deviceID); err == nil {
		t.Fatal("an enrollment challenge must not be mintable from a fingerprint alone")
	}
}

// TestNoPresenceEnrollmentIsRecordedNotRefused. "Hardware with none of these
// enrolls with presence: none, recorded and carried on the identity, and
// exchanges still work."
func TestNoPresenceEnrollmentIsRecordedNotRefused(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, false)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, assertion := d.request(t, challenge, testTrustDomain, "", issuerFingerprint(t))
	if assertion != nil {
		t.Fatal("a device with no presence key must not produce an assertion")
	}
	in, err := EnrollmentInput(req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := v.Enroll(in, req.Signature, nil, testTrustDomain)
	if err != nil {
		t.Fatalf("a presence:none device must still enroll: %v", err)
	}
	if out.State != presence.StateNone {
		t.Errorf("state: got %s, want %s", out.State, presence.StateNone)
	}
	if out.PresenceKey != nil {
		t.Error("a presence:none enrollment recorded a presence key")
	}
}

// TestEncodingVersionMismatchIsRefusedBeforeAnythingIsSpent.
func TestEncodingVersionMismatchIsRefusedBeforeAnythingIsSpent(t *testing.T) {
	t.Parallel()
	d := newEnrollingDevice(t, true)
	req := EnrollRequest{
		DevicePublicDER: d.deviceDER,
		EncodingVersion: presence.EncodingVersion + 1,
	}
	if _, err := EnrollmentInput(req); err == nil {
		t.Fatal("an enrollment in an unknown format must be refused")
	}
}
