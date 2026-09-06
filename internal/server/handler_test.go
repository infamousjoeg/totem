package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
)

// The fake below stands in for internal/policy so the TRANSPORT can be
// exercised: routing, status codes, headers, what reaches the audit stream. It
// deliberately makes no claim about whether an enrollment is valid, because
// that question belongs to the real verifier and is answered in enroll_test.go
// against it. A fake that decided validity would agree with itself and prove
// nothing.
type fakeEngine struct {
	challenge    []byte
	challengeErr error
	enrolled     *policy.EnrollResult
	enrollErr    error
	lastEnroll   policy.EnrollRequest
	lastIssuerFP []byte
	seen         []string
}

func (f *fakeEngine) IssueBootstrapCode(context.Context) (string, time.Time, error) {
	return "CODE-1234", time.Now().Add(BootstrapCodeTTL), nil
}
func (f *fakeEngine) EnrollmentChallenge([]byte) ([]byte, error) {
	return f.challenge, f.challengeErr
}
func (f *fakeEngine) Enroll(_ context.Context, req policy.EnrollRequest, fp []byte) (*policy.EnrollResult, error) {
	f.lastEnroll, f.lastIssuerFP = req, fp
	return f.enrolled, f.enrollErr
}
func (f *fakeEngine) Pending() []policy.PendingEnrollment { return nil }
func (f *fakeEngine) Challenge(string) ([]byte, error)    { return f.challenge, f.challengeErr }
func (f *fakeEngine) Prepare(string, policy.Action, string) (*policy.ToSign, error) {
	return &policy.ToSign{Input: presence.SigningInput{Version: presence.EncodingVersion}}, nil
}
func (f *fakeEngine) Approve(context.Context, string, policy.Signature) (*policy.EnrollmentRecord, error) {
	return &policy.EnrollmentRecord{DeviceID: "abc"}, nil
}
func (f *fakeEngine) GrantAdmin(context.Context, string, policy.Signature) error   { return nil }
func (f *fakeEngine) RevokeAdmin(context.Context, string, policy.Signature) error  { return nil }
func (f *fakeEngine) RevokeDevice(context.Context, string, policy.Signature) error { return nil }
func (f *fakeEngine) Devices() []policy.EnrollmentRecord                           { return nil }
func (f *fakeEngine) Device(string) (*policy.EnrollmentRecord, error) {
	return nil, policy.ErrDeviceNotFound
}
func (f *fakeEngine) Seen(id string) { f.seen = append(f.seen, id) }

var _ Engine = (*fakeEngine)(nil)

func newTestServer(t *testing.T, e Engine) (*Server, *bytes.Buffer) {
	t.Helper()
	var audit bytes.Buffer
	id, err := GenerateIdentity(t.TempDir(), []string{testTrustDomain}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		TrustDomain: testTrustDomain,
		ExternalURL: "https://" + testTrustDomain,
		Identity:    id,
		Engine:      e,
		Audit:       NewAuditLog(&audit, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, &audit
}

func post(t *testing.T, s *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestEnrollmentEndpointsAreOpenAndEverythingElseIsNot. A device that has not
// enrolled has no credential, so the enrollment endpoints have to be reachable
// without one; every other endpoint must refuse an anonymous caller rather than
// treating it as some default identity.
func TestEnrollmentEndpointsAreOpenAndEverythingElseIsNot(t *testing.T) {
	t.Parallel()
	d := newEnrollingDevice(t, true)
	f := &fakeEngine{challenge: make([]byte, presence.ChallengeSize)}
	s, _ := newTestServer(t, f)

	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{
		DevicePublicDER: d.deviceDER, DeviceFingerprint: d.deviceID,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("enrollment challenge should be open: got %d, %s", w.Code, w.Body.String())
	}

	for _, path := range []string{
		"/v1/devices/approve", "/v1/devices/grant-admin",
		"/v1/devices/revoke-admin", "/v1/devices/revoke",
		"/v1/sign/challenge", "/v1/sign/prepare",
	} {
		w := post(t, s, path, SignedRequest{Subject: "abc"})
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s with no credential: got %d, want 401", path, w.Code)
		}
	}
}

// TestAdminOperationsHaveNoUnsignedPath. Approve, grant-admin, revoke-admin and
// revoke are presence:always. This package cannot enforce that (it verifies
// nothing), but it CAN guarantee there is no route that reaches them without
// carrying a signature, which is the only structural promise a transport layer
// can make about them.
func TestAdminOperationsHaveNoUnsignedPath(t *testing.T) {
	t.Parallel()
	src := packageSource(t)
	for _, method := range []string{"Approve", "GrantAdmin", "RevokeAdmin", "RevokeDevice"} {
		if n := countOutsideComments(src, "s.cfg.Engine."+method); n != 1 {
			t.Errorf("Engine.%s is reached from %d places; each admin operation must have exactly one, "+
				"and it must go through signed()", method, n)
		}
	}
	// The signature handed to the engine is built in exactly one place, from
	// the attested credential. A second construction site is a second chance to
	// build one out of a request body.
	if n := countOutsideComments(src, "policy.Signature{DeviceID:"); n != 1 {
		t.Errorf("policy.Signature is populated in %d places; it must be built once, from the attested credential", n)
	}
}

// TestSignerIsTheAttestedDeviceNotTheBody. A body that could name its own
// signer would let any enrolled device claim to be the admin whose key the
// issuer is about to verify against.
func TestSignerIsTheAttestedDeviceNotTheBody(t *testing.T) {
	t.Parallel()
	f := &fakeEngine{}
	s, _ := newTestServer(t, f)

	r := httptest.NewRequest(http.MethodPost, "/v1/devices/approve", strings.NewReader(
		`{"subject":"CODE","assertion":{"device_id":"somebody-else"}}`))
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	// With no verified chain the request never reaches the body at all, which
	// is the point: identity is decided before anything is decoded.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 for a connection with no verified chain", w.Code)
	}
}

// TestEnrollPassesTheIssuersOwnFingerprintAndNotTheDevices.
func TestEnrollPassesTheIssuersOwnFingerprintAndNotTheDevices(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	deviceClaimedFP := issuerFingerprint(t)
	req, _ := d.request(t, challenge, testTrustDomain, "", deviceClaimedFP)

	f := &fakeEngine{enrolled: &policy.EnrollResult{DeviceID: d.deviceID, Approved: true, Presence: presence.StatePresent}}
	s, _ := newTestServer(t, f)
	if w := post(t, s, "/v1/enroll", req); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(f.lastIssuerFP, s.cfg.Identity.Fingerprint) {
		t.Error("the issuer must hand the engine its OWN fingerprint, not the one the device sent")
	}
	if bytes.Equal(f.lastIssuerFP, deviceClaimedFP) {
		t.Error("the fingerprint handed to the engine came from the request")
	}
	if !bytes.Equal(f.lastEnroll.Input.IssuerFingerprint, deviceClaimedFP) {
		t.Error("the device's asserted fingerprint must still travel inside the signed input, for the engine to compare")
	}
}

// TestAnAssertedNameIsNeverItselfGroundsForRefusal replaces the pre-flight
// comparison this handler used to make, and asserts the opposite property.
//
// The asserted name is DIAGNOSTIC ONLY. A device that claims the wrong issuer
// name and presents a valid signature must enroll, because the name was never
// an input to the decision: the issuer verifies against its own configured
// trust domain either way. This is the guard against someone reintroducing a
// convenience check here, which is where the check used to live and where the
// build lead ruled it must not.
func TestAnAssertedNameIsNeverItselfGroundsForRefusal(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := d.request(t, challenge, "an-issuer-that-is-not-us", "", issuerFingerprint(t))

	f := &fakeEngine{enrolled: &policy.EnrollResult{DeviceID: d.deviceID, Approved: true, Presence: presence.StatePresent}}
	s, _ := newTestServer(t, f)

	w := post(t, s, "/v1/enroll", req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d (%s); an asserted name is never itself grounds for refusal, only for a better message when something else fails",
			w.Code, w.Body.String())
	}
	// And the value still reaches the engine, or the diagnostic it enables
	// cannot be produced when a signature does fail.
	if f.lastEnroll.AssertedTrustDomain != "an-issuer-that-is-not-us" {
		t.Errorf("the asserted name did not reach the engine: %q", f.lastEnroll.AssertedTrustDomain)
	}
}

// TestBootstrapCodeNeverReachesTheAuditStream. The audit stream is the one
// thing this issuer is built to ship off the box, so it is exactly where the
// founding-admin code must never appear.
func TestBootstrapCodeNeverReachesTheAuditStream(t *testing.T) {
	t.Parallel()
	const code = "SUPER-SECRET-BOOTSTRAP"
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, _ := v.Mint(d.deviceID)
	req, _ := d.request(t, challenge, testTrustDomain, code, issuerFingerprint(t))

	f := &fakeEngine{enrolled: &policy.EnrollResult{DeviceID: d.deviceID, Approved: true, Presence: presence.StatePresent}}
	s, audit := newTestServer(t, f)
	if w := post(t, s, "/v1/enroll", req); w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(audit.String(), code) {
		t.Fatalf("the bootstrap code appeared in the audit stream:\n%s", audit.String())
	}
	// Redemption is still recorded, with the device fingerprint, which is what
	// an incident needs and what is safe to write.
	if !strings.Contains(audit.String(), EventBootstrapRedeemed) {
		t.Error("a redemption must be logged")
	}
	if !strings.Contains(audit.String(), d.deviceID) {
		t.Error("the redemption line must carry the device fingerprint")
	}
}

// TestEveryRefusalIsLogged. "Refusals are never silent."
func TestEveryRefusalIsLogged(t *testing.T) {
	t.Parallel()
	s, audit := newTestServer(t, &fakeEngine{})
	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{DeviceFingerprint: "abc"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
	if !strings.Contains(audit.String(), EventRefused) {
		t.Fatalf("a refused request left no audit line:\n%s", audit.String())
	}
}

// TestErrorBodyFirstLineIsProse is the measured-client test. cmd/totem's
// httpIssuerClient.post prints firstLine(body) verbatim to the human, so a JSON
// body would show a person a brace and a key name at exactly the moment they
// need a sentence.
func TestErrorBodyFirstLineIsProse(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t, &fakeEngine{})
	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{DeviceFingerprint: "abc"})

	first := strings.SplitN(strings.TrimSpace(w.Body.String()), "\n", 2)[0]
	switch {
	case strings.HasPrefix(first, "{"), strings.HasPrefix(first, "["):
		t.Fatalf("the first line of an error body is machine syntax, and the agent prints it to a person: %q", first)
	case first == "":
		t.Fatal("an error body must carry a sentence; the agent prints it verbatim")
	case !strings.Contains(first, "."):
		t.Errorf("the first line should be a sentence with the fix in it; got %q", first)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type %q; the body is prose for a human", ct)
	}
}

// TestRetryableFailuresCarryTheirMachineSignal. The current agent treats every
// non-2xx as terminal, so these headers are for the harness reading
// ~/.totem/last-error and for future clients; an issuer that says "come back in
// thirty seconds" in a way nothing can read fails silently.
func TestRetryableFailuresCarryTheirMachineSignal(t *testing.T) {
	t.Parallel()
	f := &fakeEngine{challengeErr: presence.ErrTooManyChallenges}
	s, _ := newTestServer(t, f)
	d := newEnrollingDevice(t, false)
	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{
		DevicePublicDER: d.deviceDER, DeviceFingerprint: d.deviceID,
	})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a retryable refusal must say when to come back")
	}
}

// TestHealthCarriesTheClock. cmd/totem's ServerDate reads the Date header off
// /healthz for its clock-skew check, and a HEAD must answer it too.
func TestHealthCarriesTheClock(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t, &fakeEngine{})
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "/healthz", nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s /healthz: got %d", method, w.Code)
		}
		if _, err := http.ParseTime(w.Header().Get("Date")); err != nil {
			t.Errorf("%s /healthz: Date header unreadable: %v", method, err)
		}
	}
}

// TestApprovalURLIsWithheldFromAnIPOnlyIssuer. WebAuthn cannot use an IP, so
// offering a browser link that cannot work is worse than offering none.
func TestApprovalURLIsWithheldFromAnIPOnlyIssuer(t *testing.T) {
	t.Parallel()
	id, err := GenerateIdentity(t.TempDir(), []string{"10.0.0.5"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		TrustDomain: "issuer",
		ExternalURL: "https://10.0.0.5:8443",
		Identity:    id,
		Engine:      &fakeEngine{},
		Audit:       NewAuditLog(&bytes.Buffer{}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.approvalURL("CODE"); got != "" {
		t.Errorf("an IP-only issuer offered a browser approval link: %q", got)
	}
}

// TestNewRefusesAnIncompleteFrontDoor.
func TestNewRefusesAnIncompleteFrontDoor(t *testing.T) {
	t.Parallel()
	id, err := GenerateIdentity(t.TempDir(), []string{testTrustDomain}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	full := Config{TrustDomain: "td", Identity: id, Engine: &fakeEngine{}, Audit: NewAuditLog(&bytes.Buffer{}, nil)}
	for name, mutate := range map[string]func(*Config){
		"no trust domain": func(c *Config) { c.TrustDomain = "" },
		"no identity":     func(c *Config) { c.Identity = nil },
		"no engine":       func(c *Config) { c.Engine = nil },
		"no audit":        func(c *Config) { c.Audit = nil },
	} {
		cfg := full
		mutate(&cfg)
		if _, err := New(cfg); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: got %v, want ErrConfig", name, err)
		}
	}
}

// TestEnrollmentNameMismatchReadsAsATypoNotAKeyProblem.
//
// internal/policy detects the mismatch and wraps the signature failure as
// ErrAssertedTrustDomain carrying both names. Two things have to be true of
// what reaches the person: it must name both issuers, and it must NOT read as
// a signature or a prompt problem, because both send an operator somewhere
// expensive for what is a typo in a command.
func TestEnrollmentNameMismatchReadsAsATypoNotAKeyProblem(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	const asserted = "issuer.example.com"
	req, _ := d.request(t, challenge, asserted, "", issuerFingerprint(t))

	// The engine reports what policy reports: the sentinel wrapping the
	// presence error, exactly as policy builds it.
	f := &fakeEngine{enrollErr: fmt.Errorf("%w: %w: this device thinks we are called %q and we are called %q; fix the enroll command",
		policy.ErrAssertedTrustDomain, presence.ErrBadSignature, asserted, testTrustDomain)}
	s, _ := newTestServer(t, f)

	w := post(t, s, "/v1/enroll", req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: a name mismatch is a typo, not a signature problem", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, asserted) || !strings.Contains(body, testTrustDomain) {
		t.Errorf("the refusal must name BOTH issuers so the operator can see the typo; got %q", body)
	}
	if !strings.Contains(body, "--trust-domain") {
		t.Errorf("the refusal does not name the flag that fixes it: %q", body)
	}
	// The wrapped error still satisfies errors.Is for the presence failure, so
	// the generic bad-signature mapping would happily claim it. It must not:
	// "this device's enrollment did not verify" is true and useless here.
	if strings.Contains(strings.ToLower(body), "did not verify") {
		t.Errorf("the name mismatch was rendered as a signature failure: %q", body)
	}
	// And no package names or wrapping chain reach the person. cmd/totem
	// prints the first line of this body verbatim.
	for _, leak := range []string{"policy:", "presence:", "ca:", "store:"} {
		if strings.Contains(body, leak) {
			t.Errorf("the wrapped error chain leaked %q to the operator: %q", leak, body)
		}
	}

	// The same presence sentinel on a path that is NOT an enrollment keeps the
	// presence reading, so the two do not collapse into one message.
	generic := classify(presence.ErrTargetMismatch)
	if !strings.Contains(strings.ToLower(generic.fix), "prompt") {
		t.Errorf("the generic mapping lost the presence reading: %q", generic.fix)
	}
}

// TestABareSignatureFailureStaysASignatureFailure. policy only wraps when the
// device actually claimed a different name, so a genuine bad signature must
// still read as one rather than blaming a typo that did not happen.
func TestABareSignatureFailureStaysASignatureFailure(t *testing.T) {
	t.Parallel()
	v := presence.NewVerifier(0, nil)
	d := newEnrollingDevice(t, true)
	challenge, err := v.Mint(d.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := d.request(t, challenge, testTrustDomain, "", issuerFingerprint(t))
	f := &fakeEngine{enrollErr: presence.ErrBadSignature}
	s, _ := newTestServer(t, f)

	w := post(t, s, "/v1/enroll", req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 for a signature that does not verify", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "--trust-domain") {
		t.Errorf("a genuine signature failure was blamed on a name mismatch: %q", body)
	}
}
