package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// This file drives the front door against the REAL policy engine, the REAL
// presence verifier and the REAL store. Nothing here is a fake except the
// secrets provider, which the spec itself says is the one thing tests may
// substitute ("Tests use a fake provider that only compiles into the test
// binary").
//
// It exists because every defect that matters in this system comes from two
// independently-built things being forced to disagree, and the front door's
// mapping and the engine's verification are exactly such a pair. A test that
// stopped at a fake engine would prove the handler returns 200 when the fake
// says so, which is a fact about the fake.

// testProvider is the fake provider the spec sanctions. It compiles only into
// the test binary and returns fixed material.
type testProvider struct{ refs map[summon.Reference][]byte }

func (p *testProvider) Resolve(_ context.Context, ref summon.Reference) (summon.Value, error) {
	v, ok := p.refs[ref]
	if !ok {
		return nil, summon.ErrNoSuchReference
	}
	return testValue(append([]byte(nil), v...)), nil
}

// RotationOf answers the shape the issuer declares for these references. The
// data key seals rows at rest, so it is Sealing; anything else a test wires up
// is an ordinary credential. A fake that declared nothing here would be exactly
// the shape a future non-test caller copies, which is why the method is
// required rather than optional.
func (p *testProvider) RotationOf(ref summon.Reference) (summon.Rotation, error) {
	if _, ok := p.refs[ref]; !ok {
		return summon.RotationUnset, summon.ErrNoSuchReference
	}
	if ref == summon.Reference(store.DataKeyRefName) {
		return summon.Sealing(ref).Rotation, nil
	}
	return summon.Rotating(ref).Rotation, nil
}

func (p *testProvider) Refs() []string {
	out := make([]string, 0, len(p.refs))
	for r := range p.refs {
		out = append(out, string(r))
	}
	return out
}

type testValue []byte

func (v testValue) Bytes() []byte { return v }
func (v testValue) Zero() {
	for i := range v {
		v[i] = 0
	}
}

var _ summon.Resolver = (*testProvider)(nil)

// realIssuer wires a policy engine over a real SQLite store.
func realIssuer(t *testing.T) (*policy.Issuer, *store.DB) {
	t.Helper()
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x2b}, 32)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "issuer.db"), store.Options{
		Resolver: &testProvider{refs: map[summon.Reference][]byte{
			summon.Reference(store.DataKeyRefName): key,
		}},
	})
	if err != nil {
		t.Fatalf("opening the real store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	issuer, err := policy.New(ctx, policy.Config{
		TrustDomain: testTrustDomain,
		Verifier:    presence.NewVerifier(0, nil),
		Sessions:    presence.NewSessionStore(nil),
		Grants:      presence.NewRegistry(nil),
		Lot:         presence.NewLot(nil, 0, 0),
		Store:       db,
		Windows:     presence.DefaultWindows(),
	})
	if err != nil {
		t.Fatalf("building the real policy engine: %v", err)
	}
	return issuer, db
}

func realServer(t *testing.T, issuer *policy.Issuer) (*Server, *bytes.Buffer) {
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
		Engine:      issuer,
		Audit:       NewAuditLog(&audit, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, &audit
}

// enrollThrough runs the whole two-call flow the agent runs, through the HTTP
// front door, against the real engine.
func enrollThrough(t *testing.T, s *Server, d *enrollingDevice, code string) *httptest.ResponseRecorder {
	t.Helper()
	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{
		DevicePublicDER: d.deviceDER, DeviceFingerprint: d.deviceID,
		Hostname: "laptop.local", OS: "darwin",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", w.Code, w.Body.String())
	}
	var ch ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if len(ch.Challenge) != presence.ChallengeSize {
		t.Fatalf("challenge is %d bytes, want %d", len(ch.Challenge), presence.ChallengeSize)
	}
	req, _ := d.request(t, ch.Challenge, testTrustDomain, code, s.cfg.Identity.Fingerprint)
	return post(t, s, "/v1/enroll", req)
}

// TestFoundingDeviceEnrollsEndToEnd. docs/totem-design.md: "The operator's own
// `totem enroll` with that code is auto-approved as the founding device and
// flagged admin."
func TestFoundingDeviceEnrollsEndToEnd(t *testing.T) {
	t.Parallel()
	issuer, db := realIssuer(t)
	s, audit := realServer(t, issuer)

	code, expires, err := issuer.IssueBootstrapCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(expires); d > BootstrapCodeTTL+time.Minute || d <= 0 {
		t.Errorf("bootstrap code expires in %s; the spec says ten minutes", d)
	}

	d := newEnrollingDevice(t, true)
	w := enrollThrough(t, s, d, code)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	var resp EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Approved {
		t.Fatal("the founding device was not auto-approved")
	}
	if resp.TrustDomain != testTrustDomain {
		t.Errorf("trust domain %q; the issuer must answer with its OWN name", resp.TrustDomain)
	}

	devices := issuer.Devices()
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	founding := devices[0]
	if !founding.Admin || !founding.Founding {
		t.Errorf("the founding device is not flagged admin/founding: %+v", founding)
	}
	if founding.Presence != presence.StatePresent {
		t.Errorf("presence %q, want %q", founding.Presence, presence.StatePresent)
	}
	if !founding.FirstContact.Verified() {
		t.Error("first contact was recorded as the weaker path even though the device signed the fragment path")
	}

	// The code is spent. A second device redeeming it must be refused, or the
	// bootstrap code is a standing admin credential rather than a one-time one.
	second := newEnrollingDevice(t, true)
	if w := enrollThrough(t, s, second, code); w.Code == http.StatusOK {
		var r2 EnrollResponse
		_ = json.Unmarshal(w.Body.Bytes(), &r2)
		if r2.Approved {
			t.Fatal("a second device redeemed the same bootstrap code and became an admin")
		}
	}

	if strings.Contains(audit.String(), code) {
		t.Fatal("the bootstrap code reached the audit stream")
	}
	records := decodeRecords(t, audit.String())
	if ok, bad := VerifyChain(records); !ok {
		t.Fatalf("the audit chain broke at seq %d", bad)
	}

	// The durable chain, not just the stdout stream. This is the regression
	// guard for the defect that blocked this test: internal/store forbids "/"
	// in a record kind (its backup writes a tarball, so a kind with a separator
	// becomes a path inside a tar entry) while internal/policy wrote
	// "policy/<action>". Both suites were green and the seam was broken, and
	// the symptom was that no policy record persisted at all, so no enrollment
	// could complete. Asserting the record is really in the chain is what makes
	// a repeat of that loud here instead of silent.
	var kinds []string
	if err := db.Walk(context.Background(), 0, func(rec store.Record) error {
		kinds = append(kinds, rec.Kind)
		return nil
	}); err != nil {
		t.Fatalf("walking the durable chain: %v", err)
	}
	if len(kinds) == 0 {
		t.Fatal("the founding enrollment wrote nothing to the durable hash chain")
	}
	var sawPolicy bool
	for _, k := range kinds {
		if strings.Contains(k, "/") {
			t.Errorf("record kind %q contains a path separator; internal/store refuses those and backup would "+
				"turn it into a path inside a tar entry", k)
		}
		if strings.HasPrefix(k, "policy.") {
			sawPolicy = true
		}
	}
	if !sawPolicy {
		t.Errorf("no admin-signed policy record reached the chain; kinds were %v", kinds)
	}
	if ok, badSeq, err := db.Verify(context.Background()); err != nil || !ok {
		t.Fatalf("the durable chain does not verify (first bad seq %d): %v", badSeq, err)
	}
}

// TestSecondDeviceIsPendingAndPrintsItsApprovalCode. "A second device prints
// the exact `totem devices approve` command to run on an existing one."
func TestSecondDeviceIsPendingAndPrintsItsApprovalCode(t *testing.T) {
	t.Parallel()
	issuer, _ := realIssuer(t)
	s, _ := realServer(t, issuer)
	code, _, err := issuer.IssueBootstrapCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if w := enrollThrough(t, s, newEnrollingDevice(t, true), code); w.Code != http.StatusOK {
		t.Fatalf("founding enroll: %d %s", w.Code, w.Body.String())
	}

	second := newEnrollingDevice(t, true)
	w := enrollThrough(t, s, second, "")
	if w.Code != http.StatusOK {
		t.Fatalf("second enroll: %d %s", w.Code, w.Body.String())
	}
	var resp EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Approved {
		t.Fatal("a device with no bootstrap code was approved without an admin")
	}
	if resp.ApprovalCode == "" {
		t.Fatal("a pending device was given no code for an admin to type")
	}
	if resp.ApprovalURL == "" {
		t.Error("a named issuer should offer the browser path too")
	}
	if !strings.Contains(resp.ApprovalURL, resp.ApprovalCode) {
		t.Errorf("the approval URL does not carry the code: %q", resp.ApprovalURL)
	}
	pending := issuer.Pending()
	if len(pending) != 1 || pending[0].Code != resp.ApprovalCode {
		t.Fatalf("the issuer's queue does not match what it told the device: %+v", pending)
	}
}

// TestEnrollmentAgainstAnotherIssuersCertificateIsRefused. "if what the device
// pinned is not the issuer's own leaf, something terminated TLS in between and
// the enrollment is not one the issuer should record."
func TestEnrollmentAgainstAnotherIssuersCertificateIsRefused(t *testing.T) {
	t.Parallel()
	issuer, _ := realIssuer(t)
	s, _ := realServer(t, issuer)

	d := newEnrollingDevice(t, true)
	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{
		DevicePublicDER: d.deviceDER, DeviceFingerprint: d.deviceID,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", w.Code, w.Body.String())
	}
	var ch ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	// The device signs a DIFFERENT issuer's fingerprint, which is what a
	// machine-in-the-middle would produce.
	req, _ := d.request(t, ch.Challenge, testTrustDomain, "", issuerFingerprint(t))
	if w := post(t, s, "/v1/enroll", req); w.Code == http.StatusOK {
		t.Fatal("an enrollment made against somebody else's certificate was accepted")
	}
}

// TestReplayingAnEnrollmentIsRefused. The challenge is single-use, and a
// captured enrollment must not be replayable.
func TestReplayingAnEnrollmentIsRefused(t *testing.T) {
	t.Parallel()
	issuer, _ := realIssuer(t)
	s, _ := realServer(t, issuer)
	code, _, err := issuer.IssueBootstrapCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := newEnrollingDevice(t, true)

	w := post(t, s, "/v1/enroll/challenge", ChallengeRequest{
		DevicePublicDER: d.deviceDER, DeviceFingerprint: d.deviceID,
	})
	var ch ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	req, _ := d.request(t, ch.Challenge, testTrustDomain, code, s.cfg.Identity.Fingerprint)

	if w := post(t, s, "/v1/enroll", req); w.Code != http.StatusOK {
		t.Fatalf("first enroll: %d %s", w.Code, w.Body.String())
	}
	if w := post(t, s, "/v1/enroll", req); w.Code == http.StatusOK {
		t.Fatal("the same enrollment was accepted twice")
	}
}
