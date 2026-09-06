package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFingerprintIsWhatTheAgentComputes. cmd/totem hashes rawCerts[0], the
// leaf's DER, in its VerifyPeerCertificate hook. Any other digest input here
// produces a value that never matches, and the mismatch looks exactly like a
// machine-in-the-middle: the most alarming possible presentation of an
// off-by-one in a hash input.
func TestFingerprintIsWhatTheAgentComputes(t *testing.T) {
	t.Parallel()
	id, err := GenerateIdentity(t.TempDir(), []string{testTrustDomain}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	agentSaw := sha256.Sum256(id.Certificate.Certificate[0]) // exactly rawCerts[0]
	if hex.EncodeToString(agentSaw[:]) != id.FingerprintHex() {
		t.Fatal("the fingerprint the issuer prints is not the one the agent computes over the certificate it receives")
	}
	if len(id.FingerprintHex()) != 64 {
		t.Fatalf("fingerprint is %d hex characters; cmd/totem's ParseFingerprint requires 64", len(id.FingerprintHex()))
	}
}

// TestEnrollCommandCarriesTheFingerprintInTheFragment. Decision 18: the
// fingerprint goes in the URL fragment so the agent verifies it and no human
// compares hex. A fingerprint on its own line is one a person glances at.
func TestEnrollCommandCarriesTheFingerprintInTheFragment(t *testing.T) {
	t.Parallel()
	cmd := EnrollCommand("https://issuer.example.ts.net/", "abc123", "CODE-1")
	if !strings.Contains(cmd, "#sha256:abc123") {
		t.Errorf("the fingerprint is not in the fragment: %q", cmd)
	}
	if strings.Contains(cmd, ".net/#") {
		t.Errorf("the trailing slash was not trimmed, so the URL and the pin do not read as one address: %q", cmd)
	}
	if !strings.Contains(cmd, "--code CODE-1") {
		t.Errorf("the bootstrap code is not on the command, so it is a second thing to copy: %q", cmd)
	}
	if strings.Contains(EnrollCommand("https://x", "aa", ""), "--code") {
		t.Error("an enroll command with no bootstrap code must not carry an empty --code")
	}
}

// TestGenerateIdentityRefusesToReplaceALiveCertificate. Every enrolled device
// has this certificate's fingerprint written into its state and trusts nothing
// else, so replacing it is a fleet-wide re-enrollment that presents on every
// laptop as an attack.
func TestGenerateIdentityRefusesToReplaceALiveCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := GenerateIdentity(dir, []string{testTrustDomain}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateIdentity(dir, []string{testTrustDomain}, time.Now()); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("a second init overwrote the certificate the fleet has pinned: %v", err)
	}
}

// TestPrivateKeyIsNotReadableByAnyoneElse.
func TestPrivateKeyIsNotReadableByAnyoneElse(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := GenerateIdentity(dir, []string{testTrustDomain}, time.Now()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("front-door private key mode %o, want 600", perm)
	}
}

// TestIdentityCarriesEveryNameAgentsWillDial. A name that is not in the
// certificate cannot be used to reach the issuer even though the pin matches.
func TestIdentityCarriesEveryNameAgentsWillDial(t *testing.T) {
	t.Parallel()
	id, err := GenerateIdentity(t.TempDir(), []string{"issuer.ts.net", "10.0.0.5"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Leaf.DNSNames) != 1 || id.Leaf.DNSNames[0] != "issuer.ts.net" {
		t.Errorf("DNS names: %v", id.Leaf.DNSNames)
	}
	if len(id.Leaf.IPAddresses) != 1 || id.Leaf.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IP addresses: %v", id.Leaf.IPAddresses)
	}
}

// TestClientAuthIsVerifyIfGiven. An unenrolled device must reach the enrollment
// endpoints with no client certificate at all, and an offered-but-unverifiable
// certificate must fail the handshake rather than arriving as an anonymous
// request that some handler treats as a default identity.
func TestClientAuthIsVerifyIfGiven(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t, &fakeEngine{})
	cfg := s.TLSConfig()
	inner, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if inner.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth is %v; enrollment must be reachable without a credential and a bad one must still fail", inner.ClientAuth)
	}
	// With no CA wired the pool must trust NOTHING, never the host's system
	// roots: failing closed here is the difference between a brief outage for
	// admin endpoints and any publicly trusted certificate getting in.
	if inner.ClientCAs == nil {
		t.Fatal("ClientCAs is nil, which falls back to the host's system roots")
	}
	if n := len(inner.ClientCAs.Subjects()); n != 0 { //nolint:staticcheck // counting an empty pool is the assertion
		t.Fatalf("with no CA available the client pool trusts %d subjects, want 0", n)
	}
}

// TestHostsFor.
func TestHostsFor(t *testing.T) {
	t.Parallel()
	got, err := HostsFor("https://issuer.ts.net:8443", "issuer.local", "issuer.ts.net")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"issuer.ts.net", "issuer.local"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (duplicates must collapse)", got, want)
	}
	if _, err := HostsFor(""); err == nil {
		t.Fatal("a certificate with no names must be refused")
	}
}

// TestIsIPOnly.
func TestIsIPOnly(t *testing.T) {
	t.Parallel()
	for url, want := range map[string]bool{
		"https://10.0.0.5:8443": true,
		"https://[::1]:8443":    true,
		"https://issuer.ts.net": false,
	} {
		if got := IsIPOnly(url); got != want {
			t.Errorf("IsIPOnly(%q) = %v, want %v", url, got, want)
		}
	}
}

var _ = x509.NewCertPool

// TestFrontDoorOverRealTLS exercises the listener the agent actually dials: an
// unenrolled device must reach the enrollment endpoints with no client
// certificate at all, and a client that offers one this CA did not sign must
// fail the HANDSHAKE rather than arriving as an anonymous request some handler
// might treat as a default identity.
func TestFrontDoorOverRealTLS(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t, &fakeEngine{challenge: make([]byte, 32)})

	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	defer ts.Close()

	// The pinned client, built the way cmd/totem builds it: the pin replaces
	// chain validation entirely, and the system trust store is not consulted.
	want := s.cfg.Identity.Fingerprint
	pinned := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the pin below is the whole check
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(got[:], want) {
				return errors.New("pin mismatch")
			}
			return nil
		},
	}}}

	resp, err := pinned.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("an unenrolled device could not reach the issuer: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz over TLS: %d", resp.StatusCode)
	}

	// A client certificate this issuer's CA never signed must not get through.
	// The handshake is where that is decided, so the failure is a transport
	// error and never a request.
	strangerDir := t.TempDir()
	stranger, err := GenerateIdentity(strangerDir, []string{"stranger.example"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	hostile := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // testing the server's client-auth decision
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{stranger.Certificate},
	}}}
	if resp, err := hostile.Get(ts.URL + "/healthz"); err == nil {
		resp.Body.Close()
		t.Fatal("a client certificate this CA never signed completed the handshake")
	}
}
