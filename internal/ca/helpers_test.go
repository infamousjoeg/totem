package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/summon"
)

// The Summon fake compiles only into the test binary, as internal/summon's
// contract requires: "Tests use a fake provider that compiles only into the
// test binary." There is no plaintext path into the CA, in tests either.

type fakeValue struct{ b []byte }

func (v *fakeValue) Bytes() []byte { return v.b }
func (v *fakeValue) Zero() {
	for i := range v.b {
		v.b[i] = 0
	}
}

type fakeResolver struct {
	mu    sync.Mutex
	pass  string
	calls int
	err   error
	// rotation is what RotationOf reports. The zero value would be
	// summon.RotationUnset, which Open refuses, so the constructor sets it
	// explicitly: a test fake must not be able to pass the gate by accident,
	// and it must not fail it by accident either.
	rotation    summon.Rotation
	rotationErr error
}

// Resolve hands back a FRESH copy every time, because callers are required to
// Zero what they receive. A fake that returned the same buffer would be zeroed
// by its first caller and would then quietly hand every later caller an empty
// passphrase, which is a fake that agrees with itself rather than one that
// models the contract.
func (r *fakeResolver) Resolve(_ context.Context, _ summon.Reference) (summon.Value, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return &fakeValue{b: []byte(r.pass)}, nil
}

func (r *fakeResolver) Refs() []string { return []string{"ca_passphrase"} }

// RotationOf reports the declared rotation shape, the property ca.Open gates
// on. A real Summoner reads this from the operator's declaration; this fake
// lets a test choose it so every branch of the gate is reachable.
func (r *fakeResolver) RotationOf(_ summon.Reference) (summon.Rotation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rotationErr != nil {
		return summon.RotationUnset, r.rotationErr
	}
	return r.rotation, nil
}

func (r *fakeResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// clock is a race-safe test clock. The rotation schedule spans months, so every
// interesting test drives it rather than sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *clock { return &clock{t: t} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// T0 is the instant every test CA is initialised at.
var T0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

const testTrustDomain = "issuer.example"

type testCA struct {
	Authority
	dir string
	clk *clock
	res *fakeResolver
	tb  testing.TB
}

func newTestCA(tb testing.TB) *testCA {
	tb.Helper()
	dir := tb.TempDir()
	clk := newClock(T0)
	res := &fakeResolver{pass: "a-passphrase-only-summon-knows", rotation: summon.RotationSealsDataAtRest}
	a, err := Init(context.Background(), InitParams{
		Config: Config{
			Dir:           dir,
			Resolver:      res,
			PassphraseRef: "ca_passphrase",
			TrustDomain:   testTrustDomain,
			Now:           clk.now,
		},
		Subject: "Totem Test",
	})
	if err != nil {
		tb.Fatalf("Init: %v", err)
	}
	tb.Cleanup(func() { a.Close() })
	return &testCA{Authority: a, dir: dir, clk: clk, res: res, tb: tb}
}

func newSVIDKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating an SVID key: %v", err)
	}
	return k
}

// verifyAgainstBundle round-trips a leaf through crypto/x509's OWN chain
// verification, using only what the bundle endpoint publishes.
//
// This is the point of the exercise. Verifying our chain with our own verifier
// would prove the package agrees with itself and nothing more; a relying party
// runs crypto/x509 (or something that behaves like it) against the bundle it
// fetched, so that is what the test has to run too.
func verifyAgainstBundle(tb testing.TB, leaf *x509.Certificate, b *Bundle, at time.Time) error {
	tb.Helper()
	roots := x509.NewCertPool()
	for _, r := range b.Roots {
		roots.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, in := range b.Intermediates {
		inter.AddCert(in.Certificate)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// foreignLeaf mints a leaf under a CA that has nothing to do with this one, for
// the tests that check we refuse to act on someone else's certificate.
func foreignLeaf(tb testing.TB, notBefore time.Time) *x509.Certificate {
	tb.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	serial, _ := newSerial()
	rootTmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		tb.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		tb.Fatal(err)
	}
	leafKey := newSVIDKey(tb)
	lserial, _ := newSerial()
	leafTmpl := &x509.Certificate{
		SerialNumber:          lserial,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, leafKey.Public(), rootKey)
	if err != nil {
		tb.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		tb.Fatal(err)
	}
	return leaf
}
