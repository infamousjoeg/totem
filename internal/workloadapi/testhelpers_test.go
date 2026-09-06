package workloadapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/attest"
	tspiffe "github.com/infamousjoeg/totem/internal/spiffe"
)

const (
	testTrustDomain = "issuer.example"
	testDeviceID    = "d3v1ce"
	testTool        = "claude"
)

// fakeAttestor stands in for the real attestor, which another teammate owns.
// It answers with whatever the test set, and counts calls so a test can prove
// attestation happened once per connection rather than once per RPC.
type fakeAttestor struct {
	mu       sync.Mutex
	identity *attest.Identity
	err      error
	calls    int
	// onCall, when set, is consulted per call so a test can change the answer
	// between the accept-time attestation and a renewal re-check.
	onCall func(n int) (*attest.Identity, error)
}

func (f *fakeAttestor) AttestPeer(_ context.Context, conn *net.UnixConn) (*attest.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if conn == nil {
		panic("attestor was handed a nil *net.UnixConn; the listener did not capture the raw conn")
	}
	if f.onCall != nil {
		return f.onCall(f.calls)
	}
	return f.identity, f.err
}

func (f *fakeAttestor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func toolIdentity(t *testing.T) *attest.Identity {
	t.Helper()
	return &attest.Identity{
		Tool:       testTool,
		Entry:      tspiffe.Catalog[0],
		BinaryHash: "abc123",
		TeamID:     "Q6L2SF6YDW",
		SigningID:  "com.anthropic.claude-code",
		Peer: attest.Peer{
			PID:        4242,
			UID:        uint32(1000),
			GID:        uint32(1000),
			StartTime:  time.Unix(1700000000, 0),
			BinaryPath: "/opt/claude/bin/claude",
		},
	}
}

// testCA is a real ECDSA P-256 CA that mints real SVIDs, so the conformance
// assertions verify an actual chain rather than a fixture.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "totem test issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: testTrustDomain}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{key: key, cert: cert, der: der}
}

// mint issues an X509-SVID for id, encoded exactly as the Workload API puts it
// on the wire: concatenated DER chain leaf first, unencrypted PKCS#8 key.
func (ca *testCA) mint(t *testing.T, id string, lifetime time.Duration) *X509SVID {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	u, err := url.Parse(id)
	if err != nil {
		t.Fatalf("parse spiffe id: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return &X509SVID{
		ID:           id,
		CertChainDER: der,
		KeyPKCS8DER:  keyDER,
		BundleDER:    ca.der,
		IssuedAt:     now,
		ExpiresAt:    now.Add(lifetime),
	}
}

// fakeSource is a Source backed by a testCA. It counts fetches so a test can
// prove the cache renews at half-life rather than on every call.
type fakeSource struct {
	ca *testCA

	mu       sync.Mutex
	fetches  int
	err      error
	lifetime time.Duration
	jwt      *JWTSVID
	jwtErr   error
	bundles  map[string][]byte
}

func newFakeSource(ca *testCA) *fakeSource {
	return &fakeSource{
		ca:       ca,
		lifetime: time.Hour,
		bundles:  map[string][]byte{"spiffe://" + testTrustDomain: ca.der},
	}
}

func (f *fakeSource) FetchX509SVID(_ context.Context, id Derived) (*X509SVID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	if f.err != nil {
		return nil, f.err
	}
	return f.mintLocked(id.String()), nil
}

func (f *fakeSource) mintLocked(id string) *X509SVID {
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(id)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(f.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca.cert, &leafKey.PublicKey, f.ca.key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	return &X509SVID{
		ID: id, CertChainDER: der, KeyPKCS8DER: keyDER, BundleDER: f.ca.der,
		IssuedAt: now, ExpiresAt: now.Add(f.lifetime),
	}
}

func (f *fakeSource) FetchJWTSVID(context.Context, Derived, []string) (*JWTSVID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwt, f.jwtErr
}

func (f *fakeSource) X509Bundles(context.Context) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.bundles, nil
}

func (f *fakeSource) JWTBundles(context.Context) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.bundles, nil
}

func (f *fakeSource) fetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func (f *fakeSource) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// testSocketPath returns a short path under a private temp dir. Unix socket
// paths are capped near 104 bytes on macOS and t.TempDir() can exceed that on
// its own, so this falls back to a short directory when it would.
func testSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	p := filepath.Join(dir, "a.sock")
	if len(p) < 100 {
		return p
	}
	short, err := os.MkdirTemp("", "tt")
	if err != nil {
		t.Fatalf("short temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	if short, err = filepath.EvalSymlinks(short); err != nil {
		t.Fatalf("resolve short temp dir: %v", err)
	}
	return filepath.Join(short, "a.sock")
}
