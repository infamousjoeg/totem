// Package server is the issuer's front door: the mTLS listener, the enrollment
// endpoints, the device-administration endpoints, and the hash-chained audit
// log every one of them writes to.
//
// docs/totem-design.md "Issuer (broker box)": "One container, one config file,
// mTLS only. Self-signed server cert generated at `issuer init`; the printed
// enroll command embeds its fingerprint as a URL fragment so the agent verifies
// it with no human comparison. Publicly trusted certs are still pinned."
//
// This package owns transport and nothing else. Three rules define what it must
// never do, and each is enforced structurally rather than by review:
//
//   - It NEVER verifies a signature. Enrollment verification is one call to
//     presence.Verifier.Enroll, made by internal/policy, because that one spend
//     of one challenge has to cover BOTH enrollment signatures. A second
//     verification path here would spend the challenge first and turn the
//     honest second signature into a replay. TestServerNeverVerifiesSignatures
//     asserts the package contains no verification call at all.
//   - It NEVER reads a grant, a device identity, or a presence state from a
//     request body. Those come from the attested credential, through the single
//     call to policy.AttestPeer in attest below.
//     TestAttestPeerCalledExactlyOnce and TestRequestBodiesCarryNoIdentity
//     assert it.
//   - It NEVER writes the bootstrap code to the audit log. See bootstrap.go.
//
// The wire types in this package mirror cmd/totem's by hand, because the agent's
// live in package main and cannot be imported. That mirroring is a drift hazard
// the build lead should close by moving them to a shared package; see the note
// on EnrollRequest.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/policy"
)

// Engine is the policy engine as the front door sees it: admin-signed state,
// enrollment, and the audit chain. It is a consumer-defined interface rather
// than a direct dependency on *policy.Issuer so handlers can be driven in tests
// without a database, and the compile-time assertion below is what keeps the
// two from drifting: if internal/policy changes a signature, this package stops
// building immediately rather than at wiring time.
type Engine interface {
	// IssueBootstrapCode mints the one-time code `issuer init` and
	// `issuer recover` print. Ten-minute expiry, single-use, never logged.
	IssueBootstrapCode(ctx context.Context) (code string, expires time.Time, err error)

	// EnrollmentChallenge mints the single challenge that covers BOTH
	// signatures of one enrollment. It takes the device public key's SPKI, not
	// a fingerprint, so the identifier a challenge is minted for is always the
	// hash of a real P-256 key rather than a string a caller chose.
	EnrollmentChallenge(devicePublicKeySPKI []byte) ([]byte, error)

	// Enroll verifies and records one enrollment. issuerFingerprint is the
	// ISSUER's own certificate fingerprint, supplied here because the front
	// door is the only thing that knows it; the device's asserted fingerprint
	// travels inside req.Input, under its signature, and the engine compares
	// the two.
	Enroll(ctx context.Context, req policy.EnrollRequest, issuerFingerprint []byte) (*policy.EnrollResult, error)

	// Pending lists enrollments waiting for an admin.
	Pending() []policy.PendingEnrollment

	// Challenge mints a signing challenge for an already-enrolled device that
	// is about to sign a policy record.
	Challenge(deviceID string) ([]byte, error)

	// Prepare returns the exact bytes a device must sign for one action. The
	// digest comes from issuer state, never from anything the signer sent, so
	// a signature can only ever authorize what the issuer will apply.
	Prepare(deviceID string, action policy.Action, subject string) (*policy.ToSign, error)

	// Approve, GrantAdmin, RevokeAdmin and RevokeDevice are the four
	// admin operations. docs/totem-design-decisions.md 32: they are
	// presence:always regardless of the signing device's windows, a
	// presence:none admin CAN approve and the new enrollment records that it
	// was approved without presence, and revoking the last admin is refused.
	// All four are enforced in internal/policy; this package only carries the
	// signature, and offers no unsigned path to any of them.
	Approve(ctx context.Context, code string, sig policy.Signature) (*policy.EnrollmentRecord, error)
	GrantAdmin(ctx context.Context, deviceID string, sig policy.Signature) error
	RevokeAdmin(ctx context.Context, deviceID string, sig policy.Signature) error
	RevokeDevice(ctx context.Context, deviceID string, sig policy.Signature) error

	// Devices and Device read the enrollment inventory.
	Devices() []policy.EnrollmentRecord
	Device(deviceID string) (*policy.EnrollmentRecord, error)

	// Seen records that a device was observed. Not a policy change.
	Seen(deviceID string)
}

// The anti-drift guard. It costs nothing at runtime and fails the build the
// moment internal/policy changes one of the signatures above.
var _ Engine = (*policy.Issuer)(nil)

// Config wires the front door. Every field except Now and ExternalURL is
// required.
type Config struct {
	// TrustDomain is the issuer's OWN configured trust domain: its hostname by
	// default, or the explicit value an IP-only issuer was given at init. It is
	// what gets passed down as the enrollment target, and it is NEVER read from
	// a request. A device sends the name it believes it is joining as a
	// diagnostic only; see enroll.go.
	TrustDomain string

	// Addr is the listen address.
	Addr string

	// ExternalURL is how devices reach this issuer, used to build the browser
	// approval link. Empty (an IP-only issuer) means no approval URL is
	// offered: docs/totem-design.md, "A hostname is required for the browser
	// admin path (WebAuthn cannot use an IP) ... IP-only issuers get the
	// headless path only."
	ExternalURL string

	// Identity is the self-signed server certificate generated at init. Its
	// fingerprint is what the enroll command embeds as a URL fragment.
	Identity *Identity

	// CA supplies the client trust bundle. It is read per connection rather
	// than once at start, so an intermediate rotation takes effect without a
	// restart; see TLSConfig.
	CA ca.Authority

	// Engine is the policy engine.
	Engine Engine

	// Audit is the hash-chained structured log every handler writes to.
	Audit *AuditLog

	// Version is this issuer's build version, used for the compatibility gate.
	// Empty means internal/version.Version.
	Version string

	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Server is the issuer's HTTP front door.
type Server struct {
	cfg  Config
	now  func() time.Time
	mux  *http.ServeMux
	http *http.Server
}

// ErrConfig means the front door was wired with something missing. It is a
// programming error, caught at New rather than at the first request.
var ErrConfig = errors.New("server: incomplete configuration")

// New builds the front door.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.TrustDomain == "":
		return nil, fmt.Errorf("%w: trust domain", ErrConfig)
	case cfg.Identity == nil:
		return nil, fmt.Errorf("%w: server identity", ErrConfig)
	case cfg.Engine == nil:
		return nil, fmt.Errorf("%w: policy engine", ErrConfig)
	case cfg.Audit == nil:
		return nil, fmt.Errorf("%w: audit log", ErrConfig)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, now: cfg.Now, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// routes registers every endpoint. The split is deliberate and is the whole of
// the authorization model at this layer: the enrollment endpoints are reachable
// without a client certificate, because a device that has not enrolled does not
// have one yet, and EVERYTHING else requires an attested credential.
func (s *Server) routes() {
	// Open: a device with no credential yet, or a relying party fetching trust.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("HEAD /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /v1/bundle", s.handleBundle)
	s.mux.HandleFunc("GET /v1/crls", s.handleCRLs)
	s.mux.HandleFunc("POST /v1/enroll/challenge", s.handleEnrollChallenge)
	s.mux.HandleFunc("POST /v1/enroll", s.handleEnroll)

	// Attested: an enrolled device presenting its credential over mTLS.
	s.mux.HandleFunc("GET /v1/devices", s.attested(s.handleDevices))
	s.mux.HandleFunc("GET /v1/enrollments/pending", s.attested(s.handlePending))
	s.mux.HandleFunc("POST /v1/sign/challenge", s.attested(s.handleSignChallenge))
	s.mux.HandleFunc("POST /v1/sign/prepare", s.attested(s.handlePrepare))
	s.mux.HandleFunc("POST /v1/devices/approve", s.attested(s.handleApprove))
	s.mux.HandleFunc("POST /v1/devices/grant-admin", s.attested(s.handleGrantAdmin))
	s.mux.HandleFunc("POST /v1/devices/revoke-admin", s.attested(s.handleRevokeAdmin))
	s.mux.HandleFunc("POST /v1/devices/revoke", s.attested(s.handleRevokeDevice))
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler { return s.mux }

// TLSConfig is the mTLS front door.
//
// Two things about it are load-bearing. First, client certificates are
// VERIFIED IF GIVEN rather than required: an unenrolled device must be able to
// reach the enrollment endpoints, and an offered-but-unverifiable certificate
// still fails the handshake rather than arriving as an anonymous request.
// Second, the client trust pool is rebuilt per connection from ca.Bundle rather
// than captured once, because the intermediate rotates every thirty days with
// overlap and a pool captured at start would begin refusing every freshly
// minted credential a month after the process started, with no operator action
// to correlate it with.
func (s *Server) TLSConfig() *tls.Config {
	base := &tls.Config{
		Certificates: []tls.Certificate{s.cfg.Identity.Certificate},
		MinVersion:   tls.VersionTLS12,
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		c.ClientAuth = tls.VerifyClientCertIfGiven
		if pool, err := s.clientPool(); err == nil {
			c.ClientCAs = pool
		} else {
			// No bundle means no client certificate can verify, so present a
			// pool that trusts nothing rather than one that trusts the host's
			// system roots. Failing closed here is the difference between "no
			// enrolled device can reach the admin endpoints for a moment" and
			// "any publicly trusted certificate can".
			c.ClientCAs = x509.NewCertPool()
		}
		return c, nil
	}
	return base
}

// clientPool builds the pool an enrolled device's credential must chain to:
// the roots and every intermediate currently in the bundle.
func (s *Server) clientPool() (*x509.CertPool, error) {
	if s.cfg.CA == nil {
		return nil, fmt.Errorf("%w: certificate authority", ErrConfig)
	}
	b, err := s.cfg.CA.Bundle(context.Background())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, root := range b.Roots {
		pool.AddCert(root)
	}
	for _, in := range b.Intermediates {
		pool.AddCert(in.Certificate)
	}
	return pool, nil
}

// ListenAndServe runs the front door until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, tls.NewListener(ln, s.TLSConfig()))
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	s.http = &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	done := make(chan error, 1)
	go func() { done <- s.http.Serve(ln) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdown)
		return nil
	}
}

// handleHealth answers the reachability probe `totem doctor` makes first and
// carries the Date header the agent's clock-skew check reads.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// attested wraps a handler so it runs only for a caller presenting a
// credential this issuer's CA signed. The credential is the ONLY source of
// caller identity: it is read from the TLS layer's own verification result,
// never from the request body.
func (s *Server) attested(h func(http.ResponseWriter, *http.Request, *policy.Attested)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := attest(r)
		if err != nil {
			writeError(w, r, err)
			return
		}
		s.cfg.Engine.Seen(a.ID().DeviceID)
		h(w, r, a)
	}
}

// attest is the ONLY place in this package that turns a connection into a
// caller identity, and policy.AttestPeer is the only way to build one.
//
// This is the structural half of the rule the design makes load-bearing: the
// grant id handed to presence.Registry.Open must come from the attested
// credential's provenance and never from a request body. presence refuses the
// wrong SHAPE, but that is worthless if a caller can supply the shape, because
// an agent narrowed to nothing would otherwise claim its own root grant and
// walk straight around monotonic narrowing. policy.Attested has no exported
// fields and one constructor, this is the one call to it, and no request type
// in this package has a grant, device, or presence field for a body to fill.
func attest(r *http.Request) (*policy.Attested, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nil, &apiError{
			status: http.StatusUnauthorized,
			what:   "this request arrived without an identity this issuer recognises.",
			fix:    "Run this from a device that has finished enrolling. 'totem status' says whether this one has.",
		}
	}
	a, err := policy.AttestPeer(r.TLS.VerifiedChains)
	if err != nil {
		return nil, err
	}
	return a, nil
}
