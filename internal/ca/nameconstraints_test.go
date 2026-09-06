package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
	"time"
)

// oidNameConstraints is RFC 5280's id-ce-nameConstraints.
var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

// forgeLeafUnder mints a leaf directly with an intermediate's PRIVATE KEY,
// bypassing this package's API entirely.
//
// That is the whole point. IssueSVID refusing a foreign trust domain only binds
// callers who come through this package; it does nothing about someone who has
// stolen the intermediate key and writes their own x509.CreateCertificate call.
// This helper is that attacker, and the name constraint is the only thing
// standing between them and a usable credential in someone else's trust domain.
func forgeLeafUnder(t *testing.T, signer *loadedIntermediate, uri string, at time.Time) *x509.Certificate {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := newSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: uri},
		NotBefore:             at,
		NotAfter:              at.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
		SignatureAlgorithm:    caSignatureAlgorithm,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, newSVIDKey(t).Public(), signer.key)
	if err != nil {
		t.Fatalf("forging a leaf under the intermediate key: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func currentIntermediate(t *testing.T, ca *testCA) *loadedIntermediate {
	t.Helper()
	a, ok := ca.Authority.(*authority)
	if !ok {
		t.Fatal("expected the local authority")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	in, err := a.currentSigner(a.now())
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// TestIntermediateCarriesACriticalURINameConstraint checks the shape of the
// extension. Critical matters: a non-critical name constraint is advisory, and
// a verifier is free to ignore it, which would leave the control looking
// present while doing nothing.
func TestIntermediateCarriesACriticalURINameConstraint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inter := bundle.Intermediates[0].Certificate
	if len(inter.PermittedURIDomains) != 1 || inter.PermittedURIDomains[0] != testTrustDomain {
		t.Fatalf("PermittedURIDomains = %v, want exactly [%s]", inter.PermittedURIDomains, testTrustDomain)
	}
	var found bool
	for _, e := range inter.Extensions {
		if e.Id.Equal(oidNameConstraints) {
			found = true
			if !e.Critical {
				t.Fatal("nameConstraints must be critical; RFC 5280 requires it and a non-critical constraint may simply be ignored")
			}
		}
	}
	if !found {
		t.Fatal("the intermediate carries no nameConstraints extension")
	}
	// The root is deliberately unconstrained: backing the control out of an
	// intermediate costs one rotation, backing it out of a root costs a
	// ceremony across every relying party's trust anchor.
	if len(bundle.Roots[0].PermittedURIDomains) != 0 {
		t.Fatal("the root must not carry name constraints")
	}
}

// TestNameConstraintBindsWhoeverHoldsTheIntermediateKey is the control itself:
// a compromised intermediate structurally cannot mint a usable identity outside
// its trust domain, whatever the holder of the key chooses to sign.
func TestNameConstraintBindsWhoeverHoldsTheIntermediateKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer := currentIntermediate(t, ca)
	now := ca.clk.now()

	// Control: a forged leaf INSIDE the trust domain verifies. Without this the
	// test below would pass even if the forging helper were simply broken, and
	// it would be proving nothing.
	inside := forgeLeafUnder(t, signer, "spiffe://"+testTrustDomain+"/device/forged/tool/claude", now)
	if err := verifyAgainstBundle(t, inside, bundle, now); err != nil {
		t.Fatalf("a forged leaf inside the trust domain should verify, so the failure below is attributable to the constraint: %v", err)
	}

	// The actual control: outside the trust domain, crypto/x509 rejects it.
	for _, foreign := range []string{
		"spiffe://evil.example/device/forged/tool/claude",
		"spiffe://issuer.example.evil.test/device/forged/tool/claude",
	} {
		outside := forgeLeafUnder(t, signer, foreign, now)
		err := verifyAgainstBundle(t, outside, bundle, now)
		if err == nil {
			t.Fatalf("a stolen intermediate key minted a verifiable identity at %s; the name constraint is not binding", foreign)
		}
		var invalid x509.CertificateInvalidError
		if !asCertInvalid(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Fatalf("rejected for the wrong reason (%v); the test must fail because of the name constraint, not incidentally", err)
		}
	}
}

func asCertInvalid(err error, target *x509.CertificateInvalidError) bool {
	if e, ok := err.(x509.CertificateInvalidError); ok {
		*target = e
		return true
	}
	return false
}

// TestDisableNameConstraintsIsTheDocumentedBackOut proves the flag is what does
// the work, and gives step 4 a way out if Roles Anywhere turns out not to
// accept a URI-name-constrained chain.
func TestDisableNameConstraintsIsTheDocumentedBackOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	clk := newClock(T0)
	res := &fakeResolver{pass: "a-passphrase-only-summon-knows"}
	a, err := Init(ctx, InitParams{Config: Config{
		Dir: dir, Resolver: res, PassphraseRef: "ca_passphrase",
		TrustDomain: testTrustDomain, Now: clk.now,
		DisableNameConstraints: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ca := &testCA{Authority: a, dir: dir, clk: clk, res: res, tb: t}

	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Intermediates[0].Certificate.PermittedURIDomains) != 0 {
		t.Fatal("DisableNameConstraints must remove the constraint")
	}
	// With the constraint gone, the same forgery that was rejected above now
	// verifies. That is what makes the previous test attributable to the
	// constraint rather than to anything else in the chain.
	outside := forgeLeafUnder(t, currentIntermediate(t, ca), "spiffe://evil.example/device/forged/tool/claude", clk.now())
	if err := verifyAgainstBundle(t, outside, bundle, clk.now()); err != nil {
		t.Fatalf("with constraints disabled the foreign identity should verify, which is exactly why the control matters: %v", err)
	}

	// Ordinary issuance is unaffected either way.
	svid, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstBundle(t, svid.Certificate, bundle, clk.now()); err != nil {
		t.Fatal(err)
	}
}
