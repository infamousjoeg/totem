package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"

	"github.com/infamousjoeg/totem/internal/attest"
	tspiffe "github.com/infamousjoeg/totem/internal/spiffe"
)

// SecurityHeader is the metadata header the SPIFFE Workload API requires on
// every request. go-spiffe's client sets it on every call
// (metadata.Pairs("workload.spiffe.io", "true")), and the spec requires the
// server to reject requests that lack it. Rejecting is not decoration: the
// header is what stops a browser or a naive HTTP client from being talked into
// making a request to the socket on someone else's behalf.
const SecurityHeader = "workload.spiffe.io"

// bundleRecheckInterval is how often the bundle streams re-read the trust
// bundle from the source. A change is pushed to connected clients; an unchanged
// bundle sends nothing, so an idle client sees exactly one message.
const bundleRecheckInterval = 5 * time.Minute

// Config is everything the Workload API server needs. Nothing in it is
// discovered at runtime: the agent reads its enrollment record, builds this,
// and serves.
type Config struct {
	// SocketPath is where the Workload API is served. Empty means
	// DefaultSocketPath.
	SocketPath string
	// Identity carries the trust domain, device id, and agent uid map that
	// identity derivation needs.
	Identity IdentityConfig
	// Attestor resolves each accepted connection to a catalog tool. A nil
	// Attestor is served but answers every caller with a legible
	// "this build cannot identify callers" rather than hanging.
	Attestor attest.Attestor
	// Source is where credentials come from. A nil Source is the honest state
	// of an agent that is not connected to an issuer yet.
	Source Source
	// Log is the agent's local structured log. A nil Log discards events.
	Log *Logger
	// ProtectionLevel is the assurance of the device key, reported in the
	// runtime status. It rides on identities as an X.509 extension, which the
	// issuer sets; the agent only reports it.
	ProtectionLevel tspiffe.ProtectionLevel
	// RuntimeStatusPath is where the agent publishes its snapshot for
	// `totem status`. Empty means DefaultRuntimeStatusPath.
	RuntimeStatusPath string
	// BinaryPath and BinaryHash identify the totem binary this agent is
	// running from. `totem serve` fills them so `totem doctor` can detect an
	// in-place upgrade, which silently breaks helper connections until the
	// agent restarts.
	BinaryPath string
	BinaryHash string
	// Clock is overridable for tests. Nil means time.Now.
	Clock func() time.Time
}

// Server is the SPIFFE Workload API served on a unix socket. It implements the
// real SpiffeWorkloadAPI service from go-spiffe's generated code, so a stock
// go-spiffe client, spiffe-helper, or anything else that already speaks SPIFFE
// works against it unchanged.
type Server struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	cfg   Config
	cache *svidCache
	grpc  *grpc.Server

	mu        sync.Mutex
	lis       *Listener
	startedAt time.Time
}

// New builds a Server. It creates no socket and contacts nothing; Serve does
// that, so a caller can construct and inspect a Server in a test without side
// effects on the filesystem.
func New(cfg Config) *Server {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath()
	}
	if cfg.RuntimeStatusPath == "" {
		cfg.RuntimeStatusPath = DefaultRuntimeStatusPath()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Source == nil {
		cfg.Source = unavailableSource{}
	}
	s := &Server{cfg: cfg, cache: newSVIDCache(cfg.Source, cfg.Clock)}
	s.grpc = grpc.NewServer(
		grpc.Creds(Credentials()),
		grpc.ChainUnaryInterceptor(s.unaryHeaderInterceptor),
		grpc.ChainStreamInterceptor(s.streamHeaderInterceptor),
	)
	workload.RegisterSpiffeWorkloadAPIServer(s.grpc, s)
	return s
}

// SocketPath is where this server serves, whether or not it is running.
func (s *Server) SocketPath() string { return s.cfg.SocketPath }

// Endpoint is the SocketPath as the unix:// URI a SPIFFE client puts in
// SPIFFE_ENDPOINT_SOCKET.
func (s *Server) Endpoint() string { return "unix://" + s.cfg.SocketPath }

// Serve creates the socket at mode 0600, serves the Workload API on it until
// ctx ends, and removes the socket and the runtime status file on the way out.
func (s *Server) Serve(ctx context.Context) error {
	raw, err := ListenSocket(s.cfg.SocketPath)
	if err != nil {
		return err
	}
	return s.serveListener(ctx, NewListener(raw, s.cfg.Attestor, s.cfg.Log))
}

// ServeListener serves on an already-created listener. Tests and the
// conformance suite use it to run the server on a socket they control.
func (s *Server) ServeListener(ctx context.Context, lis *Listener) error {
	return s.serveListener(ctx, lis)
}

func (s *Server) serveListener(ctx context.Context, lis *Listener) error {
	s.mu.Lock()
	s.lis = lis
	s.startedAt = s.cfg.Clock()
	s.mu.Unlock()

	s.publishStatus("")

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.grpc.GracefulStop()
		case <-done:
		}
	}()

	err := s.grpc.Serve(lis)
	close(done)
	_ = os.Remove(s.cfg.RuntimeStatusPath)
	if errors.Is(err, grpc.ErrServerStopped) || errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return err
}

// Stop stops the server immediately, closing the socket.
func (s *Server) Stop() { s.grpc.Stop() }

// ForceRotate renews every identity the agent is currently holding, now,
// instead of waiting for its half-life, and pushes the result down every open
// FetchX509SVID stream.
//
// This is an operational verb, not a debug hook: "renew everything now" is what
// an operator wants after a suspected compromise, after a revocation, or when
// the network came back and they would rather not wait out a half-life. It
// takes the ordinary path in full, asking the issuer for a fresh SVID and
// re-attesting each connection before pushing, so nothing here can produce a
// credential the issuer did not mint.
//
// `totem serve` wires it to SIGUSR1 and `totem rotate` sends that signal.
func (s *Server) ForceRotate() { s.cache.invalidateAll() }

// unaryHeaderInterceptor enforces the Workload API security header on unary
// calls before any handler runs.
func (s *Server) unaryHeaderInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := requireSecurityHeader(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// streamHeaderInterceptor enforces the Workload API security header on streams.
func (s *Server) streamHeaderInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := requireSecurityHeader(ss.Context()); err != nil {
		return err
	}
	return handler(srv, ss)
}

// requireSecurityHeader rejects a request without workload.spiffe.io: true. The
// message is the one SPIRE uses, so a developer searching the error finds the
// spec rather than a totem-specific string.
func requireSecurityHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for _, v := range md.Get(SecurityHeader) {
			if v == "true" {
				return nil
			}
		}
	}
	return status.Error(codes.InvalidArgument, "security header missing from request")
}

// callerIdentity resolves the attested caller on this RPC's connection to its
// derived SPIFFE ID. It is the single default-deny gate: every handler starts
// here, and a caller that did not attest to a catalog tool leaves with a
// legible status and no identity.
func (s *Server) callerIdentity(ctx context.Context) (*Conn, *attest.Identity, Derived, error) {
	conn, ok := ConnFromContext(ctx)
	if !ok {
		return nil, nil, Derived{}, StatusFromError(ErrNotUnixConn, nil)
	}
	ident, err := conn.Identity()
	if err != nil {
		s.record(EventFor(KindRefusal, nil, err))
		return nil, nil, Derived{}, StatusFromError(err, nil)
	}
	derived, err := Derive(s.cfg.Identity, ident)
	if err != nil {
		s.record(EventFor(KindRefusal, ident, err))
		return nil, nil, Derived{}, StatusFromError(err, ident)
	}
	return conn, ident, derived, nil
}

// FetchX509SVID streams X509-SVIDs to a caller. It is a stream, not a one-shot:
// go-spiffe clients hold it open and expect the agent to push a fresh SVID on
// rotation. The device SVID lives one hour and is renewed at half-life, so a
// connected client is handed a new SVID roughly every thirty minutes without
// ever asking for one.
//
// On each renewal the connection is re-attested: process start time and binary
// hash are re-checked against the peer that opened it. A peer that moved loses
// the stream with the status that says why.
func (s *Server) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	conn, ident, derived, err := s.callerIdentity(ctx)
	if err != nil {
		return err
	}

	for {
		// Captured before the fetch so a rotation forced between the fetch and
		// the wait below wakes this stream instead of being missed.
		rotated := s.cache.rotateSignal()

		svid, ferr := s.cache.get(ctx, derived)
		if ferr != nil {
			ev := EventFor(KindFailure, ident, ferr)
			ev.SpiffeID = derived.String()
			s.record(ev)
			return StatusFromError(ferr, ident)
		}

		resp := &workload.X509SVIDResponse{
			Svids: []*workload.X509SVID{{
				SpiffeId:    svid.ID,
				X509Svid:    svid.CertChainDER,
				X509SvidKey: svid.KeyPKCS8DER,
				Bundle:      svid.BundleDER,
				Hint:        svid.Hint,
			}},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
		ev := EventFor(KindIssuance, ident, nil)
		ev.SpiffeID = derived.String()
		s.record(ev)
		s.publishStatus("")

		if err := s.cache.waitForRenewal(ctx, svid, rotated); err != nil {
			return nil
		}
		// Attestation is per connection, but renewal re-checks the peer.
		if _, err := conn.Reattest(ctx); err != nil {
			ev := EventFor(KindRefusal, ident, err)
			ev.SpiffeID = derived.String()
			s.record(ev)
			return StatusFromError(err, ident)
		}
	}
}

// FetchX509Bundles streams the X.509 trust bundles, for clients that only need
// to validate SVIDs without holding one. Default deny still applies: the caller
// must attest to a catalog tool.
func (s *Server) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	_, ident, _, err := s.callerIdentity(ctx)
	if err != nil {
		return err
	}

	var last map[string][]byte
	for {
		bundles, berr := s.cfg.Source.X509Bundles(ctx)
		if berr != nil {
			return StatusFromError(berr, ident)
		}
		if !sameBundles(last, bundles) {
			if err := stream.Send(&workload.X509BundlesResponse{Bundles: bundles}); err != nil {
				return err
			}
			last = bundles
		}
		if err := sleepCtx(ctx, bundleRecheckInterval); err != nil {
			return nil
		}
	}
}

// FetchJWTSVID returns JWT-SVIDs for the requested audience. It is a unary
// call in the spec and stays one here.
func (s *Server) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	_, ident, derived, err := s.callerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetAudience()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "this request did not say what it wants the identity for. Ask for at least one audience.")
	}
	if want := req.GetSpiffeId(); want != "" && want != derived.String() {
		return nil, status.Errorf(codes.PermissionDenied,
			"%s asked for an identity it is not entitled to. On this device it is %s. Run 'totem status' to see what each program gets.",
			ident.Tool, derived.String())
	}

	svid, ferr := s.cfg.Source.FetchJWTSVID(ctx, derived, req.GetAudience())
	if ferr != nil {
		ev := EventFor(KindFailure, ident, ferr)
		ev.SpiffeID = derived.String()
		s.record(ev)
		return nil, StatusFromError(ferr, ident)
	}
	issued := EventFor(KindIssuance, ident, nil)
	issued.SpiffeID = derived.String()
	s.record(issued)
	return &workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{{SpiffeId: svid.ID, Svid: svid.Token, Hint: svid.Hint}},
	}, nil
}

// FetchJWTBundles streams the JWKS documents for JWT-SVID validation, keyed by
// the SPIFFE ID of the trust domain.
func (s *Server) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	_, ident, _, err := s.callerIdentity(ctx)
	if err != nil {
		return err
	}

	var last map[string][]byte
	for {
		bundles, berr := s.cfg.Source.JWTBundles(ctx)
		if berr != nil {
			return StatusFromError(berr, ident)
		}
		if !sameBundles(last, bundles) {
			if err := stream.Send(&workload.JWTBundlesResponse{Bundles: bundles}); err != nil {
				return err
			}
			last = bundles
		}
		if err := sleepCtx(ctx, bundleRecheckInterval); err != nil {
			return nil
		}
	}
}

// ValidateJWTSVID validates a JWT-SVID against the requested audience and
// returns its SPIFFE ID and claims. Validation is local, against the JWT
// bundles the source publishes: the issuer is not asked to validate a token the
// agent already has the keys to check.
func (s *Server) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	_, ident, _, err := s.callerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSvid() == "" {
		return nil, status.Error(codes.InvalidArgument, "this request did not include an identity to check.")
	}
	if req.GetAudience() == "" {
		return nil, status.Error(codes.InvalidArgument, "this request did not say which audience to check the identity against.")
	}

	bundles, berr := s.cfg.Source.JWTBundles(ctx)
	if berr != nil {
		return nil, StatusFromError(berr, ident)
	}
	id, claims, verr := validateJWTSVID(req.GetSvid(), req.GetAudience(), bundles, s.cfg.Clock())
	if verr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "that identity did not check out: %v", verr)
	}
	return &workload.ValidateJWTSVIDResponse{SpiffeId: id, Claims: claims}, nil
}

// record appends to the agent's local log, tolerating a nil logger.
func (s *Server) record(ev Event) {
	if s.cfg.Log != nil {
		s.cfg.Log.Record(ev)
	}
}

// publishStatus refreshes the snapshot `totem status` reads. It is best effort:
// a status file that cannot be written never stops a credential being issued.
func (s *Server) publishStatus(lastError string) {
	s.mu.Lock()
	started := s.startedAt
	s.mu.Unlock()

	rs := &RuntimeStatus{
		PID:             os.Getpid(),
		StartedAt:       started,
		SocketPath:      s.cfg.SocketPath,
		Endpoint:        s.Endpoint(),
		TrustDomain:     s.cfg.Identity.TrustDomain,
		DeviceID:        s.cfg.Identity.DeviceID,
		ProtectionLevel: s.cfg.ProtectionLevel,
		LastError:       lastError,
		BinaryPath:      s.cfg.BinaryPath,
		BinaryHash:      s.cfg.BinaryHash,
	}
	s.cache.mu.Lock()
	for id, e := range s.cache.entries {
		if e.svid == nil {
			continue
		}
		rs.SVIDs = append(rs.SVIDs, SVIDStatus{
			SpiffeID:  id,
			Tool:      lastPathSegment(id),
			ExpiresAt: e.svid.ExpiresAt,
			RenewsAt:  e.svid.RenewAt(),
		})
	}
	s.cache.mu.Unlock()
	_ = rs.Save(s.cfg.RuntimeStatusPath)
}

// lastPathSegment is the tool or agent name at the end of a derived SPIFFE ID,
// which is the only part of it `totem status` shows a human by default.
func lastPathSegment(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}

// sameBundles reports whether two bundle maps are byte-identical, so a bundle
// stream only sends on an actual change.
func sameBundles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}

// sleepCtx waits for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Compile-time proof that this really is the SPIFFE project's generated
// service, not a look-alike, and that the attesting Listener really is a
// net.Listener gRPC will accept. If go-spiffe's proto changes shape, these
// break the build rather than the conformance suite.
var (
	_ workload.SpiffeWorkloadAPIServer = (*Server)(nil)
	_ net.Listener                     = (*Listener)(nil)
	_ fmt.Stringer                     = Derived{}
)
