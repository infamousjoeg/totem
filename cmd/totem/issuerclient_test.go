package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	toterrors "github.com/infamousjoeg/totem/internal/errors"
)

// tlsIssuer starts a real TLS server and returns its address and the SHA-256 of
// the certificate it serves, which is what an enroll link's fragment carries.
func tlsIssuer(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	cert := srv.Certificate()
	sum := sha256.Sum256(cert.Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

// TestPinnedIssuerAcceptsTheRightCertificate proves the pin is what decides
// trust: the system trust store is never consulted, and an httptest
// certificate no root trusts is accepted purely because it matches.
func TestPinnedIssuerAcceptsTheRightCertificate(t *testing.T) {
	url, fp := tlsIssuer(t, http.NotFoundHandler())
	client, err := NewIssuerClient(IssuerAddr{URL: url, FingerprintHex: fp})
	if err != nil {
		t.Fatal(err)
	}
	got, pemStr, err := client.CertificateFingerprint(context.Background())
	if err != nil {
		t.Fatalf("CertificateFingerprint: %v", err)
	}
	if got != fp {
		t.Errorf("fingerprint = %q, want %q", got, fp)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Error("the pinned certificate was not returned in a form totem can store")
	}
}

// TestPinnedIssuerRefusesTheWrongCertificate is decision 18's refusal: the
// agent verifies the fingerprint and refuses on mismatch, so a human never has
// to compare hex and never gets the chance to shrug one off.
func TestPinnedIssuerRefusesTheWrongCertificate(t *testing.T) {
	url, _ := tlsIssuer(t, http.NotFoundHandler())
	wrong := strings.Repeat("ab", 32)
	client, err := NewIssuerClient(IssuerAddr{URL: url, FingerprintHex: wrong})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.CertificateFingerprint(context.Background())
	if !errors.Is(err, ErrIssuerPinMismatch) {
		t.Fatalf("err = %v, want ErrIssuerPinMismatch", err)
	}
	ce := asCLIError(err)
	if !strings.Contains(ce.fix, "Do not continue") {
		t.Errorf("the fix %q does not tell the human to stop", ce.fix)
	}
}

// TestPinnedIssuerRefusesAWrongCertOnEveryRequest proves the pin is enforced on
// the request path too, not only on the one-off certificate fetch.
func TestPinnedIssuerRefusesAWrongCertOnEveryRequest(t *testing.T) {
	url, _ := tlsIssuer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: []byte("x")})
	}))
	client, err := NewIssuerClient(IssuerAddr{URL: url, FingerprintHex: strings.Repeat("cd", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Challenge(context.Background(), ChallengeRequest{}); err == nil {
		t.Fatal("a request went through to an issuer whose certificate did not match the pin")
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	url, fp := tlsIssuer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll/challenge" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: []byte("nonce"), ExpiresIn: 60})
	}))
	client, err := NewIssuerClient(IssuerAddr{URL: url, FingerprintHex: fp})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Challenge(context.Background(), ChallengeRequest{Hostname: "laptop"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if string(resp.Challenge) != "nonce" {
		t.Errorf("challenge = %q", resp.Challenge)
	}
}

// TestUnreachableIssuerIsRetryable is the harness contract: a closed issuer is
// ExitRetryable with a machine record, not a crash and not a terminal failure.
func TestUnreachableIssuerIsRetryable(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	url := srv.URL
	sum := sha256.Sum256(srv.Certificate().Raw)
	srv.Close() // now nothing is listening

	client, err := NewIssuerClient(IssuerAddr{URL: url, FingerprintHex: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.CertificateFingerprint(context.Background())
	if err == nil {
		t.Fatal("a closed issuer answered")
	}
	ce := asCLIError(err)
	if ce.reason != toterrors.ReasonIssuerUnreachable {
		t.Fatalf("reason = %q, want %q", ce.reason, toterrors.ReasonIssuerUnreachable)
	}
	if !ce.reason.Retryable() || ce.reason.ExitCode() != toterrors.ExitRetryable {
		t.Error("an unreachable issuer must be retryable with exit code 75")
	}
	if !strings.Contains(ce.what, url) {
		t.Errorf("the message %q does not name the issuer address", ce.what)
	}
	if !strings.Contains(ce.what, "last reached") {
		t.Errorf("the message %q does not say when the issuer was last reached", ce.what)
	}
}

// TestIssuerRefusalIsTerminal: an issuer that answers and says no is not
// something a harness should retry.
func TestIssuerRefusalIsTerminal(t *testing.T) {
	url, fp := tlsIssuer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "that bootstrap code has expired", http.StatusForbidden)
	}))
	client, err := NewIssuerClient(IssuerAddr{URL: url, FingerprintHex: fp})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Enroll(context.Background(), EnrollRequest{})
	if err == nil {
		t.Fatal("a refused enrollment looked like a success")
	}
	if asCLIError(err).reason.Retryable() {
		t.Error("an issuer that answered and refused must not be retryable")
	}
}
