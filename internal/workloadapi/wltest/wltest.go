// Package wltest starts a fully wired totem agent for tests: a real SPIFFE
// Workload API on a real unix socket at mode 0600, with real per-connection
// attestation plumbing, backed by an in-memory CA that mints real ECDSA P-256
// X509-SVIDs.
//
// It exists because the claim this whole component has to make true is
// "anything that already speaks SPIFFE works unchanged" (docs/totem-design.md,
// "Agent (laptop)"), and that claim is only proven by pointing a real
// go-spiffe client at a real socket. The issuer is step 2 of the spec's
// "Sequencing", so until it exists there is no credential source, and without
// one the conformance suite has nothing to fetch. This package is that source,
// and nothing else: it is the CA, not the attestor and not the socket, both of
// which are the production code under test.
//
// It is deliberately a separate package rather than a flag on the shipping
// binary. docs/totem-design.md "Scope" puts dev mode under "Never", and a
// totem that can be told to mint its own credentials is a dev mode. Nothing
// under cmd/ imports this, and internal/ keeps it inside the module.
package wltest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/infamousjoeg/totem/internal/attest"
	tspiffe "github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// Options configures a test agent. The zero value is usable: it serves one
// tool identity for "claude" on a temporary socket in a private directory.
type Options struct {
	// SocketPath is where to serve. Empty means a fresh socket in a private
	// temporary directory, which is what most callers want because unix socket
	// paths are capped near 104 bytes and a long test path silently fails to
	// bind.
	SocketPath string
	// TrustDomain defaults to "totem.test".
	TrustDomain string
	// DeviceID defaults to "testdevice".
	DeviceID string
	// Tool is the catalog tool every connection attests as. Defaults to
	// "claude", the one verified catalog entry.
	Tool string
	// AgentUID, when non-zero, makes connections attest as coming from that
	// uid, which is how a long-running agent identity is derived.
	AgentUID uint32
	// AgentName pairs with AgentUID to derive
	// spiffe://<td>/device/<device>/agent/<name>.
	AgentName string
	// SVIDLifetime is how long each minted SVID lives. It defaults to one
	// hour, matching the spec's device SVID lifetime. Set it to a couple of
	// seconds to exercise rotation: the agent renews at half-life and pushes
	// the new SVID down every open FetchX509SVID stream, so a short lifetime
	// drives the real rotation path with no test-only hook in the server.
	SVIDLifetime time.Duration
	// AttestError, when set, makes every connection fail attestation with it.
	// Use it to check that a refusal reaches a client as a legible status.
	AttestError error
}

// Agent is a running test agent. Close it when the test ends.
type Agent struct {
	srv    *workloadapi.Server
	ca     *testCA
	sock   string
	tmpDir string
	cancel context.CancelFunc
	done   chan struct{}
}

// Start brings up an agent and waits until its socket accepts connections.
// The returned Agent must be closed.
func Start(opts Options) (*Agent, error) {
	if opts.TrustDomain == "" {
		opts.TrustDomain = "totem.test"
	}
	if opts.DeviceID == "" {
		opts.DeviceID = "testdevice"
	}
	if opts.Tool == "" {
		opts.Tool = "claude"
	}
	if opts.SVIDLifetime <= 0 {
		opts.SVIDLifetime = time.Hour
	}

	var tmpDir string
	if opts.SocketPath == "" {
		// A short path: unix socket paths are capped near 104 bytes, and a
		// test temp directory is long enough to blow that on its own.
		dir, err := os.MkdirTemp("", "tw")
		if err != nil {
			return nil, fmt.Errorf("wltest: temporary directory: %w", err)
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, fmt.Errorf("wltest: resolve temporary directory: %w", err)
		}
		tmpDir, opts.SocketPath = dir, filepath.Join(resolved, "a.sock")
	}

	ca, err := newTestCA(opts.TrustDomain, opts.SVIDLifetime)
	if err != nil {
		return nil, err
	}

	att := &fixedAttestor{tool: opts.Tool, uid: opts.AgentUID, err: opts.AttestError}
	idCfg := workloadapi.IdentityConfig{TrustDomain: opts.TrustDomain, DeviceID: opts.DeviceID}
	if opts.AgentUID != 0 && opts.AgentName != "" {
		idCfg.AgentUsers = map[uint32]string{opts.AgentUID: opts.AgentName}
	}

	srv := workloadapi.New(workloadapi.Config{
		SocketPath:        opts.SocketPath,
		RuntimeStatusPath: opts.SocketPath + ".status.json",
		Identity:          idCfg,
		Attestor:          att,
		Source:            ca,
		ProtectionLevel:   tspiffe.ProtectionSoftware,
	})

	lis, err := workloadapi.ListenSocket(opts.SocketPath)
	if err != nil {
		if tmpDir != "" {
			_ = os.RemoveAll(tmpDir)
		}
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	a := &Agent{srv: srv, ca: ca, sock: opts.SocketPath, tmpDir: tmpDir, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(a.done)
		_ = srv.ServeListener(ctx, workloadapi.NewListener(lis, att, nil))
	}()

	if err := waitForSocket(opts.SocketPath, 5*time.Second); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// SocketPath is the filesystem path of the agent's socket.
func (a *Agent) SocketPath() string { return a.sock }

// Endpoint is the socket as the unix:// URI a SPIFFE client expects in
// SPIFFE_ENDPOINT_SOCKET.
func (a *Agent) Endpoint() string { return "unix://" + a.sock }

// TrustDomainID is the trust domain's own SPIFFE ID, which is the key the
// bundle maps use.
func (a *Agent) TrustDomainID() string { return "spiffe://" + a.ca.trustDomain }

// BundleDER is the ASN.1 DER issuer bundle every SVID this agent serves chains
// to, so a test can verify the chain independently.
func (a *Agent) BundleDER() []byte { return a.ca.der }

// Issued is how many SVIDs the agent has minted. A rotation test asserts this
// grew while a stream stayed open.
func (a *Agent) Issued() int { return a.ca.issued() }

// Close stops the agent and removes its socket and temporary directory.
func (a *Agent) Close() {
	a.cancel()
	a.srv.Stop()
	<-a.done
	_ = os.Remove(a.sock + ".status.json")
	if a.tmpDir != "" {
		_ = os.RemoveAll(a.tmpDir)
	}
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wltest: socket %s did not come up within %s: %w", path, timeout, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fixedAttestor answers every connection with the same catalog identity. It
// stands in for the real attestor, which decides who the caller is from the
// kernel's peer credentials; what is under test here is the Workload API, not
// the attestation.
type fixedAttestor struct {
	tool string
	uid  uint32
	err  error
}

func (f *fixedAttestor) AttestPeer(_ context.Context, conn *net.UnixConn) (*attest.Identity, error) {
	if conn == nil {
		return nil, errors.New("wltest: the listener did not capture the raw unix connection")
	}
	if f.err != nil {
		return nil, f.err
	}
	return &attest.Identity{
		Tool:       f.tool,
		BinaryHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Peer: attest.Peer{
			PID:        int32(os.Getpid()),
			UID:        f.uid,
			StartTime:  time.Unix(1_700_000_000, 0),
			BinaryPath: "/usr/local/bin/" + f.tool,
		},
	}, nil
}

// testCA is an in-memory ECDSA P-256 CA acting as the credential source. It is
// the only fake in this package: everything it hands back is a real
// certificate, really signed, that really chains.
type testCA struct {
	trustDomain string
	lifetime    time.Duration
	key         *ecdsa.PrivateKey
	cert        *x509.Certificate
	der         []byte

	mu    sync.Mutex
	count int
}

func newTestCA(trustDomain string, lifetime time.Duration) (*testCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "totem test issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: trustDomain}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &testCA{trustDomain: trustDomain, lifetime: lifetime, key: key, cert: cert, der: der}, nil
}

func (c *testCA) issued() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// FetchX509SVID mints a fresh SVID for the derived identity.
func (c *testCA) FetchX509SVID(_ context.Context, id workloadapi.Derived) (*workloadapi.X509SVID, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(id.String())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(c.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{u},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	return &workloadapi.X509SVID{
		ID:           id.String(),
		CertChainDER: leaf,
		KeyPKCS8DER:  keyDER,
		BundleDER:    c.der,
		IssuedAt:     now,
		ExpiresAt:    now.Add(c.lifetime),
	}, nil
}

// FetchJWTSVID is not implemented: the JWT profile needs the issuer's signing
// key, which is step 2. A test that needs one should say so rather than get a
// token this package invented.
func (c *testCA) FetchJWTSVID(context.Context, workloadapi.Derived, []string) (*workloadapi.JWTSVID, error) {
	return nil, workloadapi.ErrSourceUnavailable
}

// X509Bundles returns the issuer bundle keyed by trust domain SPIFFE ID.
func (c *testCA) X509Bundles(context.Context) (map[string][]byte, error) {
	return map[string][]byte{"spiffe://" + c.trustDomain: c.der}, nil
}

// JWTBundles returns an empty JWKS, which is the honest answer while there is
// no issuer signing key.
func (c *testCA) JWTBundles(context.Context) (map[string][]byte, error) {
	return map[string][]byte{"spiffe://" + c.trustDomain: []byte(`{"keys":[]}`)}, nil
}
