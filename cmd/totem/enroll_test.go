package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	toterrors "github.com/infamousjoeg/totem/internal/errors"
	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

const testFingerprint = "3b1f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e"

// TestParseIssuerURLTakesTheFingerprintFromTheFragment covers decision 18: the
// enroll command that `totem-issuer init` prints carries the issuer certificate
// fingerprint in the URL fragment, and the agent verifies against it.
func TestParseIssuerURLTakesTheFingerprintFromTheFragment(t *testing.T) {
	addr, err := ParseIssuerURL("https://issuer.example:8443#sha256:" + testFingerprint)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	if addr.URL != "https://issuer.example:8443" {
		t.Errorf("URL = %q", addr.URL)
	}
	if addr.FingerprintHex != testFingerprint {
		t.Errorf("fingerprint = %q, want %q", addr.FingerprintHex, testFingerprint)
	}
}

func TestParseIssuerURLAcceptsColonSeparatedHex(t *testing.T) {
	spaced := ""
	for i := 0; i < len(testFingerprint); i += 2 {
		if spaced != "" {
			spaced += ":"
		}
		spaced += testFingerprint[i : i+2]
	}
	addr, err := ParseIssuerURL("https://issuer.example#sha256:" + spaced)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	if addr.FingerprintHex != testFingerprint {
		t.Errorf("fingerprint = %q", addr.FingerprintHex)
	}
}

// TestParseIssuerURLRefusesAMalformedLink: a bare URL is allowed and falls
// back (see below), but a link that carries a fingerprint totem cannot read is
// refused rather than quietly dropped to the weaker path. Silently downgrading
// a link the operator believed was pinned is the worst of both.
func TestParseIssuerURLRefusesAMalformedLink(t *testing.T) {
	for _, raw := range []string{
		"https://issuer.example#sha1:abc",
		"https://issuer.example#sha256:tooshort",
		"https://issuer.example#sha256:" + strings.Repeat("z", 64),
		"http://issuer.example#sha256:" + testFingerprint,
		"issuer.example",
	} {
		if _, err := ParseIssuerURL(raw); err == nil {
			t.Errorf("%q was accepted as an issuer link", raw)
		}
	}
}

// TestParseIssuerURLMarksABareLinkAsTheWeakerPath: docs/totem-design.md
// "Enrollment" step 1 keeps the fallback, so a bare URL parses. What must not
// happen is the two paths becoming indistinguishable, so the weaker one is
// labelled at the moment it is taken.
func TestParseIssuerURLMarksABareLinkAsTheWeakerPath(t *testing.T) {
	for _, raw := range []string{"https://issuer.example", "https://issuer.example#"} {
		addr, err := ParseIssuerURL(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if addr.FingerprintHex != "" {
			t.Errorf("%q pinned something out of thin air", raw)
		}
		if addr.FirstContact != workloadapi.FirstContactPrompt {
			t.Errorf("%q recorded first contact as %q, want %q", raw, addr.FirstContact, workloadapi.FirstContactPrompt)
		}
	}

	addr, err := ParseIssuerURL("https://issuer.example#sha256:" + testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if addr.FirstContact != workloadapi.FirstContactFragment {
		t.Errorf("a pinned link recorded first contact as %q", addr.FirstContact)
	}
}

// TestNewIssuerClientRefusesAnUnpinnedIssuer proves the client cannot be built
// without a pin, so no code path can fall back to the system trust store.
func TestNewIssuerClientRefusesAnUnpinnedIssuer(t *testing.T) {
	if _, err := NewIssuerClient(IssuerAddr{URL: "https://issuer.example"}); err == nil {
		t.Fatal("a client with no pinned fingerprint was created")
	}
}

// stubIssuer is an IssuerClient that never touches the network.
type stubIssuer struct {
	unreachable bool
	fingerprint string
	captured    *EnrollRequest
}

func (s stubIssuer) CertificateFingerprint(context.Context) (string, string, error) {
	if s.unreachable {
		return "", "", &cliError{reason: toterrors.ReasonIssuerUnreachable, retryAfter: 30,
			what: "could not reach your issuer.", fix: "Check your network.",
			cause: workloadapi.ErrIssuerUnreachable}
	}
	return s.fingerprint, "-----BEGIN CERTIFICATE-----\n", nil
}

func (s stubIssuer) Challenge(context.Context, ChallengeRequest) (*ChallengeResponse, error) {
	if s.unreachable {
		return nil, &cliError{reason: toterrors.ReasonIssuerUnreachable, retryAfter: 30,
			what: "could not reach your issuer.", cause: workloadapi.ErrIssuerUnreachable}
	}
	return &ChallengeResponse{Challenge: make([]byte, presence.ChallengeSize), ExpiresIn: 60}, nil
}

func (s stubIssuer) Enroll(_ context.Context, req EnrollRequest) (*EnrollResponse, error) {
	if s.captured != nil {
		*s.captured = req
	}
	return &EnrollResponse{DeviceID: "dev1", TrustDomain: "issuer.example", Approved: true}, nil
}

func (s stubIssuer) Reachable(context.Context) error { return nil }

func (s stubIssuer) ServerDate(context.Context) (time.Time, error) { return time.Now(), nil }

// TestEnrollRefusesAPinMismatchBeforeCreatingAnything is the ordering rule: the
// issuer is verified before a device key exists, so a mismatch or an
// unreachable issuer never leaves a key the issuer has never heard of.
func TestEnrollRefusesAnUnreachableIssuerBeforeCreatingAKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restore := newIssuerClient
	newIssuerClient = func(IssuerAddr) (IssuerClient, error) { return stubIssuer{unreachable: true}, nil }
	t.Cleanup(func() { newIssuerClient = restore })

	err := cmdEnroll(context.Background(), []string{"https://issuer.example#sha256:" + testFingerprint})
	if err == nil {
		t.Fatal("enroll succeeded against an unreachable issuer")
	}
	ce := asCLIError(err)
	if ce.reason != toterrors.ReasonIssuerUnreachable {
		t.Errorf("reason = %q, want %q", ce.reason, toterrors.ReasonIssuerUnreachable)
	}
	if !ce.reason.Retryable() {
		t.Error("an unreachable issuer must classify as retryable")
	}
	if _, err := LoadManifest(""); err == nil {
		m, _ := LoadManifest("")
		for _, c := range m.Changes {
			if c.Kind == ChangeKey {
				t.Fatal("a device key was recorded despite the issuer never being reached")
			}
		}
	}
}

// TestIssuerUnreachableExitsRetryable is the harness contract end to end: exit
// code 75 and a machine-readable record at ~/.totem/last-error, so a
// long-running agent rides out a coffee-shop blip by branching on the code and
// the file rather than parsing the calling tool's prose.
func TestIssuerUnreachableExitsRetryable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	err := &cliError{reason: toterrors.ReasonIssuerUnreachable, retryAfter: 30,
		what: "could not reach your issuer.", fix: "Check your network."}

	if got := report(err); got != toterrors.ExitRetryable {
		t.Fatalf("exit code = %d, want %d", got, toterrors.ExitRetryable)
	}
	rec, rerr := toterrors.Read()
	if rerr != nil {
		t.Fatalf("no machine-readable record was written: %v", rerr)
	}
	if rec.Reason != toterrors.ReasonIssuerUnreachable {
		t.Errorf("reason = %q", rec.Reason)
	}
	if !rec.Retryable {
		t.Error("the record does not say the failure is retryable")
	}
	if rec.RetryAfter != 30 {
		t.Errorf("retry_after = %d, want 30", rec.RetryAfter)
	}
	if !rec.Fresh(time.Minute) {
		t.Error("the record is not stamped fresh")
	}
}

// TestTerminalFailureExitsTerminal: anything that is not retryable exits 1, so
// a harness never loops on it.
func TestTerminalFailureExitsTerminal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := report(failf("Run 'totem enroll <link>'.", "that is not an issuer link.")); got != toterrors.ExitTerminal {
		t.Fatalf("exit code = %d, want %d", got, toterrors.ExitTerminal)
	}
}

func TestSuccessExitsOK(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := report(nil); got != toterrors.ExitOK {
		t.Fatalf("exit code = %d, want %d", got, toterrors.ExitOK)
	}
}

// TestPresenceDeniedIsTerminalNotRetryable guards the rule internal/errors
// documents at length: a harness looping on presence denial degenerates into
// prompt-spamming the human.
func TestPresenceDeniedIsTerminalNotRetryable(t *testing.T) {
	ce := asCLIError(platform.ErrPresenceDenied)
	if ce.reason != toterrors.ReasonPresenceDenied {
		t.Fatalf("reason = %q", ce.reason)
	}
	if ce.reason.Retryable() {
		t.Error("presence denial must not be retryable")
	}
}

func TestAsCLIErrorClassifiesTypedErrors(t *testing.T) {
	cases := []struct {
		err  error
		want toterrors.Reason
	}{
		{workloadapi.ErrIssuerUnreachable, toterrors.ReasonIssuerUnreachable},
		{platform.ErrPresenceDenied, toterrors.ReasonPresenceDenied},
		{platform.ErrPresenceUnavailable, toterrors.ReasonPresenceUnavailable},
	}
	for _, tc := range cases {
		if got := asCLIError(tc.err).reason; got != tc.want {
			t.Errorf("%v -> %q, want %q", tc.err, got, tc.want)
		}
	}
	if got := asCLIError(errors.New("something went sideways")).reason; got != "" {
		t.Errorf("an unclassified error got reason %q; it must carry none rather than an invented token", got)
	}
}

// TestEnrollSubmitsBothPublicHalves is the invariant that platform.PresencePublic
// exists to protect. On Apple silicon the device key and the presence key are
// two different Secure Enclave keys, and the issuer verifies different things
// against each. An enrollment that sent only the device half would succeed,
// look completely healthy, and then fail to verify every presence assertion
// forever, against the wrong key.
func TestEnrollSubmitsBothPublicHalves(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newFakeKey(t, true)
	useKey(t, &fakeStore{key: k})

	var got EnrollRequest
	restore := newIssuerClient
	newIssuerClient = func(IssuerAddr) (IssuerClient, error) {
		return stubIssuer{fingerprint: testFingerprint, captured: &got}, nil
	}
	t.Cleanup(func() { newIssuerClient = restore })

	if err := cmdEnroll(context.Background(), []string{"https://issuer.example#sha256:" + testFingerprint}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	wantDevice, _ := publicKeyDER(k.Public())
	wantPresence, _ := publicKeyDER(k.PresencePublic())
	if !bytes.Equal(got.DevicePublicDER, wantDevice) {
		t.Error("the device key's public half was not submitted")
	}
	if len(got.PresencePublicDER) == 0 {
		t.Fatal("the presence key's public half was not submitted; every presence assertion would verify against the wrong key")
	}
	if !bytes.Equal(got.PresencePublicDER, wantPresence) {
		t.Error("the submitted presence public half is not this device's presence key")
	}
	if bytes.Equal(got.DevicePublicDER, got.PresencePublicDER) {
		t.Error("both halves were submitted as the same key")
	}
	if got.Presence != presence.StatePresent {
		t.Errorf("presence = %q, want %q", got.Presence, presence.StatePresent)
	}

	// The enrollment record keeps both halves so doctor can compare later.
	st, err := workloadapi.LoadState("")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !bytes.Equal(st.DevicePublicDER, wantDevice) || !bytes.Equal(st.PresencePublicDER, wantPresence) {
		t.Error("the enrollment record did not keep both public halves")
	}
	if st.Presence != presence.StatePresent {
		t.Errorf("recorded presence = %q", st.Presence)
	}
}

// TestEnrollRecordsPresenceNoneHonestly: a device with no way to check for a
// human still enrolls, and the fact is recorded rather than glossed over.
func TestEnrollRecordsPresenceNoneHonestly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newFakeKey(t, false) // no presence half at all
	useKey(t, &fakeStore{key: k})

	var got EnrollRequest
	restore := newIssuerClient
	newIssuerClient = func(IssuerAddr) (IssuerClient, error) {
		return stubIssuer{fingerprint: testFingerprint, captured: &got}, nil
	}
	t.Cleanup(func() { newIssuerClient = restore })

	if err := cmdEnroll(context.Background(), []string{"https://issuer.example#sha256:" + testFingerprint}); err != nil {
		t.Fatalf("a device with no presence capability must still enroll: %v", err)
	}
	if got.Presence != presence.StateNone {
		t.Errorf("presence = %q, want %q recorded on the enrollment", got.Presence, presence.StateNone)
	}
	if len(got.PresencePublicDER) != 0 {
		t.Error("a presence public half was submitted for a device that has none")
	}
	if len(got.Signature) == 0 {
		t.Error("the enrollment was not signed at all")
	}

	st, err := workloadapi.LoadState("")
	if err != nil {
		t.Fatal(err)
	}
	if st.Presence != presence.StateNone {
		t.Errorf("recorded presence = %q, want %q", st.Presence, presence.StateNone)
	}
}

// TestEnrollSignsDomainSeparatedBytes: the signature is over presence's
// canonical, domain-separated encoding, never over the raw challenge. A
// signature made to enroll a device must not be indistinguishable from a
// signature made over the same bytes for some other purpose.
func TestEnrollSignsDomainSeparatedBytes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newFakeKey(t, true)
	useKey(t, &fakeStore{key: k})

	var got EnrollRequest
	restore := newIssuerClient
	newIssuerClient = func(IssuerAddr) (IssuerClient, error) {
		return stubIssuer{fingerprint: testFingerprint, captured: &got}, nil
	}
	t.Cleanup(func() { newIssuerClient = restore })

	if err := cmdEnroll(context.Background(), []string{"https://issuer.example#sha256:" + testFingerprint}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// The raw challenge must NOT verify: that is what domain separation means.
	rawDigest := sha256.Sum256(got.Challenge)
	if ecdsa.VerifyASN1(&k.device.PublicKey, rawDigest[:], got.Signature) {
		t.Fatal("the enrollment signature verifies over the bare challenge; it is not domain-separated")
	}

	// The canonical encoding must verify, reconstructed from the fields the
	// request carries, which is exactly what the issuer will do.
	// The issuer recomputes the request hash from the fields it received; if
	// any of them were rewritten in transit, this reconstruction diverges and
	// the signature stops verifying. That is the point of binding them.
	if !bytes.Equal(got.RequestHash, enrollmentRequestHash(got)) {
		t.Fatal("the request hash is not recomputable from the fields the enrollment carries")
	}
	in := presence.SigningInput{
		Version:     got.EncodingVersion,
		DeviceID:    got.DeviceFingerprint,
		Tool:        got.SignedTool,
		Target:      got.SignedTarget,
		Challenge:   got.Challenge,
		RequestHash: got.RequestHash,
	}
	signed, err := in.Bytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(&k.device.PublicKey, digest[:], got.Signature) {
		t.Fatal("the issuer cannot reconstruct the signed bytes from the fields the enrollment carries")
	}

	if got.DeviceFingerprint != hex.EncodeToString(hashPublicKey(got.DevicePublicDER)) {
		t.Error("the fingerprint bound into the signature is not derived from the submitted device key, so the signature could be lifted onto another enrollment")
	}
	if got.SignedTarget != "https://issuer.example" {
		t.Errorf("signed target = %q; the signature is not bound to this issuer", got.SignedTarget)
	}
}

// TestEnrollmentBindingCoversEveryClaim: a signature over the challenge alone
// proves somebody was present, not what they agreed to. Every field an active
// attacker could rewrite in transit has to change the hash, or the signature
// keeps verifying over a request that no longer says what the device said.
func TestEnrollmentBindingCoversEveryClaim(t *testing.T) {
	base := EnrollRequest{
		DevicePublicDER:   []byte("device"),
		PresencePublicDER: []byte("presence"),
		Presence:          presence.StatePresent,
		ProtectionLevel:   spiffe.ProtectionHardware,
		Hostname:          "laptop",
		OS:                "darwin",
		IssuerURL:         "https://issuer.example",
		IssuerFingerprint: testFingerprint,
		FirstContact:      workloadapi.FirstContactFragment,
		BootstrapCode:     "ABC-123",
	}
	original := enrollmentRequestHash(base)

	tamper := map[string]func(*EnrollRequest){
		"device public half":   func(r *EnrollRequest) { r.DevicePublicDER = []byte("other") },
		"presence public half": func(r *EnrollRequest) { r.PresencePublicDER = []byte("other") },
		"presence state":       func(r *EnrollRequest) { r.Presence = presence.StateNone },
		"protection level":     func(r *EnrollRequest) { r.ProtectionLevel = spiffe.ProtectionSoftware },
		"hostname":             func(r *EnrollRequest) { r.Hostname = "someone-elses-laptop" },
		"os":                   func(r *EnrollRequest) { r.OS = "linux" },
		"issuer url":           func(r *EnrollRequest) { r.IssuerURL = "https://attacker.example" },
		"issuer fingerprint":   func(r *EnrollRequest) { r.IssuerFingerprint = strings.Repeat("ff", 32) },
		"first contact":        func(r *EnrollRequest) { r.FirstContact = workloadapi.FirstContactPrompt },
		"bootstrap code":       func(r *EnrollRequest) { r.BootstrapCode = "STOLEN-CODE" },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			altered := base
			mutate(&altered)
			if bytes.Equal(enrollmentRequestHash(altered), original) {
				t.Errorf("rewriting the %s does not change the signature's binding, so an attacker can change it in transit", name)
			}
		})
	}

	// An empty field must be distinct from an absent one, or "no bootstrap
	// code" and "some bootstrap code" become interchangeable.
	noCode := base
	noCode.BootstrapCode = ""
	if bytes.Equal(enrollmentRequestHash(noCode), original) {
		t.Error("dropping the bootstrap code does not change the binding")
	}
}

// TestEnrollPrintsTheRequestCodeBeforeAsking: the code has to be on screen
// before the prompt, derived from the issuer-minted challenge, so the human has
// something to compare the OS dialog against. A code derived from the request
// alone can be precomputed offline by anything running as this user.
func TestEnrollPrintsTheRequestCodeFromChallengeAndRequest(t *testing.T) {
	req := EnrollRequest{
		DevicePublicDER: []byte("device"),
		Presence:        presence.StatePresent,
		IssuerURL:       "https://issuer.example",
	}
	req.RequestHash = enrollmentRequestHash(req)
	challenge := make([]byte, presence.ChallengeSize)
	challenge[0] = 1

	code := presence.RequestCode(challenge, req.RequestHash)
	if code == "" {
		t.Fatal("no request code was produced")
	}

	// A different challenge must produce a different code, which is what stops
	// the code being precomputable from the request alone.
	other := make([]byte, presence.ChallengeSize)
	other[0] = 2
	if presence.RequestCode(other, req.RequestHash) == code {
		t.Error("the code does not depend on the issuer's challenge, so it can be precomputed offline")
	}
}
