package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// liveIssuer starts a real TLS server and returns its URL and certificate
// fingerprint, so the fallback path is exercised against a real handshake
// rather than a stub.
func liveIssuer(t *testing.T) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

// TestFallbackAcceptsATranscriptionFromTheIssuerConsole is the fallback working
// as intended: the human reads the fingerprint off the issuer's own console and
// types it, totem compares, and the enrollment is marked as having taken the
// weaker path.
func TestFallbackAcceptsATranscriptionFromTheIssuerConsole(t *testing.T) {
	url, fp := liveIssuer(t)
	in := strings.NewReader(fp[:MinFingerprintPrefix] + "\n")
	var out bytes.Buffer

	_, addr, certPEM, err := establishIssuer(context.Background(),
		IssuerAddr{URL: url, FirstContact: workloadapi.FirstContactPrompt}, in, &out)
	if err != nil {
		t.Fatalf("establishIssuer: %v", err)
	}
	if addr.FingerprintHex != fp {
		t.Errorf("pinned %q, want the certificate actually presented (%q)", addr.FingerprintHex, fp)
	}
	if addr.FirstContact != workloadapi.FirstContactPrompt {
		t.Errorf("first contact = %q, want %q; the weaker path must stay labelled", addr.FirstContact, workloadapi.FirstContactPrompt)
	}
	if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("the certificate was not returned for pinning")
	}

	// The prompt must send the human to the issuer's own console, not to
	// whatever totem is showing them, or the comparison proves nothing.
	shown := out.String()
	for _, want := range []string{"totem-issuer init", "not from anything", "weaker"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the prompt does not mention %q:\n%s", want, shown)
		}
	}
	if strings.Contains(strings.ToLower(shown), "[y/n]") {
		t.Error("the fallback asks a yes/no question; a prompt a human clicks through is trust-on-first-use in a costume")
	}
}

// TestFallbackAcceptsAFullPastedFingerprint: somebody will paste all 64, and
// the sha256: prefix and separators come along with it.
func TestFallbackAcceptsAFullPastedFingerprint(t *testing.T) {
	url, fp := liveIssuer(t)
	spaced := "sha256:"
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			spaced += ":"
		}
		spaced += fp[i : i+2]
	}
	_, addr, _, err := establishIssuer(context.Background(),
		IssuerAddr{URL: url}, strings.NewReader(spaced+"\n"), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("establishIssuer: %v", err)
	}
	if addr.FingerprintHex != fp {
		t.Errorf("pinned %q, want %q", addr.FingerprintHex, fp)
	}
}

// TestFallbackRefusesAMismatch is the case the fallback exists to catch: an
// attacker terminating TLS with their own certificate. What the operator reads
// off their console will not match what this machine is talking to.
func TestFallbackRefusesAMismatch(t *testing.T) {
	url, fp := liveIssuer(t)
	wrong := "ffff" + fp[4:MinFingerprintPrefix]

	_, addr, _, err := establishIssuer(context.Background(),
		IssuerAddr{URL: url}, strings.NewReader(wrong+"\n"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("a fingerprint that does not match the presented certificate was accepted")
	}
	if addr.FingerprintHex != "" {
		t.Error("something was pinned despite the mismatch")
	}
	ce := asCLIError(err)
	if !strings.Contains(ce.fix, "Do not try again") {
		t.Errorf("the fix %q does not tell the human to stop", ce.fix)
	}
	if !strings.Contains(ce.fix, "between this machine and your issuer") {
		t.Errorf("the fix %q does not say what a mismatch means", ce.fix)
	}
}

// TestFallbackRefusesATooShortAnswer: four characters is not a comparison.
func TestFallbackRefusesATooShortAnswer(t *testing.T) {
	url, _ := liveIssuer(t)
	if _, _, _, err := establishIssuer(context.Background(),
		IssuerAddr{URL: url}, strings.NewReader("abcd\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("a four-character answer was accepted")
	}
}

// TestFallbackRefusesAnEmptyAnswer: a bare enter is not a confirmation. This is
// the specific shape the lead asked for, because a prompt that accepts enter is
// the checkbox that looks like security.
func TestFallbackRefusesAnEmptyAnswer(t *testing.T) {
	url, _ := liveIssuer(t)
	if _, _, _, err := establishIssuer(context.Background(),
		IssuerAddr{URL: url}, strings.NewReader("\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("pressing enter was accepted as confirmation")
	}
}

// TestPinnedPathNeverPrompts: when the link carried a fingerprint, nothing is
// asked of the human at all. Decision 18 exists so humans never compare hex.
func TestPinnedPathNeverPrompts(t *testing.T) {
	url, fp := liveIssuer(t)
	var out bytes.Buffer
	// A reader that fails the test if anything tries to read from it.
	_, addr, _, err := establishIssuer(context.Background(),
		IssuerAddr{URL: url, FingerprintHex: fp, FirstContact: workloadapi.FirstContactFragment},
		refusingReader{t}, &out)
	if err != nil {
		t.Fatalf("establishIssuer: %v", err)
	}
	if addr.FirstContact != workloadapi.FirstContactFragment {
		t.Errorf("first contact = %q", addr.FirstContact)
	}
	if strings.Contains(out.String(), "console") {
		t.Errorf("the pinned path prompted the human:\n%s", out.String())
	}
}

type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("the pinned path read from stdin; it must never ask the human anything")
	return 0, nil
}

// TestFingerprintFlagIsRecordedAsThePinnedPath: --fingerprint is the headless
// equivalent of the link's fragment, so it carries the same trust and the same
// label. docs/totem-design.md "Experience" requires every question to have a
// flag so scripted setups never block.
func TestFingerprintFlagIsRecordedAsThePinnedPath(t *testing.T) {
	url, fp := liveIssuer(t)
	t.Setenv("HOME", t.TempDir())

	k := newFakeKey(t, true)
	useKey(t, &fakeStore{key: k})
	var got EnrollRequest
	restore := newIssuerClient
	newIssuerClient = func(a IssuerAddr) (IssuerClient, error) {
		return stubIssuer{fingerprint: a.FingerprintHex, captured: &got}, nil
	}
	t.Cleanup(func() { newIssuerClient = restore })

	// An IP-only issuer requires an explicit trust domain, per
	// docs/totem-design.md "Identity model": an address is not a name.
	if err := cmdEnroll(context.Background(), []string{"--fingerprint", "sha256:" + fp, "--trust-domain", "issuer.example", url}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got.FirstContact != workloadapi.FirstContactFragment {
		t.Errorf("first contact = %q, want %q", got.FirstContact, workloadapi.FirstContactFragment)
	}
	if got.IssuerFingerprint != fp {
		t.Errorf("issuer fingerprint = %q, want %q", got.IssuerFingerprint, fp)
	}

	st, err := workloadapi.LoadState("")
	if err != nil {
		t.Fatal(err)
	}
	if st.FirstContact != workloadapi.FirstContactFragment {
		t.Errorf("the enrollment record says %q", st.FirstContact)
	}
}

// TestFirstContactTravelsToTheIssuer is the lead's requirement stated directly:
// the two paths must not become indistinguishable after the fact, so the fact
// reaches the issuer and is bound into the signature.
func TestFirstContactTravelsToTheIssuer(t *testing.T) {
	for _, fc := range []workloadapi.FirstContact{workloadapi.FirstContactFragment, workloadapi.FirstContactPrompt} {
		req := EnrollRequest{DevicePublicDER: []byte("d"), FirstContact: fc}
		other := req
		if fc == workloadapi.FirstContactFragment {
			other.FirstContact = workloadapi.FirstContactPrompt
		} else {
			other.FirstContact = workloadapi.FirstContactFragment
		}
		if bytes.Equal(enrollmentRequestHash(req), enrollmentRequestHash(other)) {
			t.Fatal("how first contact happened is not bound into the signature, so it can be relabelled in transit")
		}
	}
}
