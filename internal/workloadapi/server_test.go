package workloadapi

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/infamousjoeg/totem/internal/attest"
)

// testServer starts a Server on a real unix socket and returns a raw gRPC
// client for the generated SpiffeWorkloadAPI service. Using the generated
// client rather than a hand-rolled one is the point: the wire shape under test
// is the SPIFFE project's, not totem's idea of it.
func testServer(t *testing.T, attestor attest.Attestor, src Source) (workload.SpiffeWorkloadAPIClient, *Server, string) {
	t.Helper()
	sock := testSocketPath(t)
	statusPath := sock + ".status.json"

	srv := New(Config{
		SocketPath:        sock,
		RuntimeStatusPath: statusPath,
		Identity:          IdentityConfig{TrustDomain: testTrustDomain, DeviceID: testDeviceID},
		Attestor:          attestor,
		Source:            src,
	})

	raw, err := ListenSocket(sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ServeListener(ctx, NewListener(raw, attestor, nil)) }()
	t.Cleanup(func() {
		cancel()
		srv.Stop()
		<-done
		os.Remove(statusPath)
	})

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return workload.NewSpiffeWorkloadAPIClient(conn), srv, sock
}

// clientCtx mirrors exactly what go-spiffe's workloadapi.Client does on every
// call: metadata.Pairs("workload.spiffe.io", "true") on the outgoing context.
func clientCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(SecurityHeader, "true")), cancel
}

// TestFetchX509SVIDConformance is the gate for this package: the response is
// parsed with x509svid.ParseRaw and verified with x509svid.Verify, which are
// the exact functions go-spiffe's workloadapi.Client uses on the bytes it gets
// back. If this passes, a stock client fetches an SVID from this socket and
// chains it to the issuer bundle.
func TestFetchX509SVIDConformance(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	att := &fakeAttestor{identity: toolIdentity(t)}
	client, _, _ := testServer(t, att, src)

	ctx, cancel := clientCtx(t)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("first stream message: %v", err)
	}
	if len(resp.Svids) != 1 {
		t.Fatalf("want 1 SVID, got %d", len(resp.Svids))
	}
	got := resp.Svids[0]

	want := "spiffe://" + testTrustDomain + "/device/" + testDeviceID + "/tool/" + testTool
	if got.SpiffeId != want {
		t.Errorf("spiffe_id = %q, want %q", got.SpiffeId, want)
	}

	// The exact call go-spiffe's parseX509SVIDs makes.
	svid, err := x509svid.ParseRaw(got.X509Svid, got.X509SvidKey)
	if err != nil {
		t.Fatalf("a go-spiffe client could not parse this SVID: %v", err)
	}
	if svid.ID.String() != want {
		t.Errorf("parsed SVID id = %q, want %q", svid.ID, want)
	}

	// The exact call go-spiffe's parseX509Bundle makes, then a real chain
	// verification against it.
	td, err := spiffeid.TrustDomainFromString(got.SpiffeId)
	if err != nil {
		t.Fatalf("trust domain: %v", err)
	}
	bundle, err := x509bundle.ParseRaw(td, got.Bundle)
	if err != nil {
		t.Fatalf("a go-spiffe client could not parse this bundle: %v", err)
	}
	if _, _, err := x509svid.Verify(svid.Certificates, bundle); err != nil {
		t.Fatalf("SVID does not chain to the issuer bundle: %v", err)
	}
}

// TestFetchX509SVIDIsAStream proves the RPC is a stream a client holds open and
// that the agent pushes a renewed SVID without the client asking, per the
// one-hour lifetime renewed at half-life.
func TestFetchX509SVIDIsAStream(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.lifetime = 400 * time.Millisecond // half-life 200ms
	att := &fakeAttestor{identity: toolIdentity(t)}
	client, _, _ := testServer(t, att, src)

	ctx, cancel := clientCtx(t)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := stream.Recv()
	if err != nil {
		t.Fatalf("the stream did not push a renewed SVID: %v", err)
	}
	if string(first.Svids[0].X509Svid) == string(second.Svids[0].X509Svid) {
		t.Error("the renewed SVID is byte-identical to the first; nothing rotated")
	}
	if att.callCount() < 2 {
		t.Errorf("renewal did not re-attest the connection: attestor called %d times", att.callCount())
	}
}

// TestAttestationIsPerConnection proves attestation happens once at accept and
// is reused for every RPC on that connection, rather than once per RPC.
func TestAttestationIsPerConnection(t *testing.T) {
	ca := newTestCA(t)
	att := &fakeAttestor{identity: toolIdentity(t)}
	client, _, _ := testServer(t, att, newFakeSource(ca))

	ctx, cancel := clientCtx(t)
	defer cancel()

	for i := 0; i < 3; i++ {
		stream, err := client.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
		if err != nil {
			t.Fatalf("FetchX509Bundles: %v", err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("recv: %v", err)
		}
	}
	if n := att.callCount(); n != 1 {
		t.Errorf("attestor called %d times across 3 RPCs on one connection, want 1", n)
	}
}

// TestSecurityHeaderRequired covers the non-obvious go-spiffe client
// expectation: every call carries workload.spiffe.io: true and the server must
// reject a request that does not.
func TestSecurityHeaderRequired(t *testing.T) {
	ca := newTestCA(t)
	client, _, _ := testServer(t, &fakeAttestor{identity: toolIdentity(t)}, newFakeSource(ca))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	_, err = stream.Recv()
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}

	_, err = client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{"x"}})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("unary code = %v, want InvalidArgument", got)
	}
}

// TestRejectionsAreLegible checks the spec's rejection-UX rule: each typed
// attestation failure gets its own status code and a message that says what to
// do, not "permission denied".
func TestRejectionsAreLegible(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
		says string
	}{
		{"not in catalog", attest.ErrNotInCatalog, codes.PermissionDenied, "totem status"},
		{"signature mismatch", attest.ErrSignatureMismatch, codes.FailedPrecondition, "totem trust"},
		{"pid reused", attest.ErrPIDReused, codes.Aborted, "Run the command again"},
		{"too many shell hops", attest.ErrTooManyShellHops, codes.OutOfRange, "totem doctor"},
		{"interpreter wrapped", attest.ErrInterpreterWrapped, codes.Unimplemented, "native build"},
		{"unsigned at writable path", attest.ErrUnsignedAtWritablePath, codes.Unauthenticated, "only an administrator can write"},
	}
	seen := map[codes.Code]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			client, _, _ := testServer(t, &fakeAttestor{err: tc.err}, newFakeSource(ca))
			ctx, cancel := clientCtx(t)
			defer cancel()

			stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
			if err != nil {
				t.Fatalf("FetchX509SVID: %v", err)
			}
			_, err = stream.Recv()
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("not a gRPC status: %v", err)
			}
			if st.Code() != tc.want {
				t.Errorf("code = %v, want %v", st.Code(), tc.want)
			}
			if !contains(st.Message(), tc.says) {
				t.Errorf("message %q does not tell the developer what to do (wanted mention of %q)", st.Message(), tc.says)
			}
			if contains(st.Message(), "permission denied") {
				t.Errorf("message %q is a bare permission error", st.Message())
			}
		})
		if prev, ok := seen[tc.want]; ok {
			t.Errorf("%s shares a status code with %s; the spec asks for distinct statuses", tc.name, prev)
		}
		seen[tc.want] = tc.name
	}
}

// TestIssuerUnreachableIsRetryable proves an unreachable issuer surfaces as an
// Unavailable status and is classified retryable, so a harness backs off
// instead of treating a coffee-shop blip as terminal.
func TestIssuerUnreachableIsRetryable(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.setErr(ErrIssuerUnreachable)
	client, _, _ := testServer(t, &fakeAttestor{identity: toolIdentity(t)}, src)

	ctx, cancel := clientCtx(t)
	defer cancel()
	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	_, err = stream.Recv()
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
	if !Retryable(ErrIssuerUnreachable) {
		t.Error("ErrIssuerUnreachable must be classified retryable")
	}
}

// TestNoSourceIsNotACrash covers the state this agent is actually in before the
// issuer exists: no credential source at all. The caller gets a legible
// unavailable status, and nothing panics.
func TestNoSourceIsNotACrash(t *testing.T) {
	client, _, _ := testServer(t, &fakeAttestor{identity: toolIdentity(t)}, nil)
	ctx, cancel := clientCtx(t)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}
}

// TestNilAttestorIsNotACrash covers the state this repo is in while the
// attestation backend is being written in parallel: attest.New is nil.
func TestNilAttestorIsNotACrash(t *testing.T) {
	ca := newTestCA(t)
	client, _, _ := testServer(t, nil, newFakeSource(ca))
	ctx, cancel := clientCtx(t)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}
}

// TestFetchJWTSVIDRefusesForeignIdentity proves a caller cannot ask for an
// identity other than the one its attestation derived.
func TestFetchJWTSVIDRefusesForeignIdentity(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.jwt = &JWTSVID{ID: "x", Token: "y"}
	client, _, _ := testServer(t, &fakeAttestor{identity: toolIdentity(t)}, src)

	ctx, cancel := clientCtx(t)
	defer cancel()
	_, err := client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{
		Audience: []string{"aud"},
		SpiffeId: "spiffe://" + testTrustDomain + "/device/other/tool/aws",
	})
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", got)
	}
}

// TestSocketIsMode0600 proves the served socket really is 0600 on disk, which
// is the spec's requirement, not an implementation detail.
func TestSocketIsMode0600(t *testing.T) {
	ca := newTestCA(t)
	_, _, sock := testServer(t, &fakeAttestor{identity: toolIdentity(t)}, newFakeSource(ca))
	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode().Perm() != SocketMode {
		t.Errorf("socket mode = %#o, want %#o", fi.Mode().Perm(), SocketMode)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Error("path is not a socket")
	}
}

// TestServerImplementsGeneratedService is a compile-and-run assertion that the
// server registered is the SPIFFE project's generated service.
func TestServerImplementsGeneratedService(t *testing.T) {
	var _ workload.SpiffeWorkloadAPIServer = New(Config{})
	var _ net.Listener = (*Listener)(nil)
	_ = errors.New
}

// TestAuditLineCarriesAttestationFacts: PathProtected, ShellHops and the parent
// chain are recorded on every line, never acted on, and never shown in normal
// `totem log` output. A false PathProtected is the ordinary case for a real
// Claude Code install, so surfacing it would train people to ignore a warning
// that might one day matter.
func TestAuditLineCarriesAttestationFacts(t *testing.T) {
	ident := toolIdentity(t)
	ident.PathProtected = false
	ident.ShellHops = 1
	ident.ParentChain = []string{"/opt/claude/bin/claude", "/bin/sh"}

	ev := EventFor(KindIssuance, ident, nil)
	if ev.Tool != testTool || ev.PID != ident.Peer.PID {
		t.Errorf("event did not carry the attested caller: %+v", ev)
	}
	if ev.ShellHops != 1 {
		t.Errorf("shell hops = %d, want 1", ev.ShellHops)
	}
	if len(ev.ParentChain) != 2 {
		t.Errorf("parent chain = %v, want the walk that reached the tool", ev.ParentChain)
	}
	if ev.Message != "" || ev.Fix != "" {
		t.Error("a successful issuance must not carry a refusal message")
	}

	ident.PathProtected = true
	if !EventFor(KindIssuance, ident, nil).PathProtected {
		t.Error("a true PathProtected must be recorded as true")
	}

	// The refusal path carries the same facts plus the reason.
	ref := EventFor(KindRefusal, ident, attest.ErrUnsignedAtWritablePath)
	if ref.Reason != "unsigned_at_writable_path" || ref.Fix == "" {
		t.Errorf("refusal event = %+v, want a reason token and a fix", ref)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// TestForceRotatePushesThroughTheRealPath proves the rotation trigger is not a
// synthetic update injected into the stream: the SVID lifetime here is an hour,
// so no half-life renewal is due, and the only way a second message arrives is
// if ForceRotate drove a genuine re-mint at the source and pushed the result
// down the open stream. The client never re-fetches.
func TestForceRotatePushesThroughTheRealPath(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.lifetime = time.Hour // half-life is 30 minutes away; nothing is due
	att := &fakeAttestor{identity: toolIdentity(t)}
	client, srv, _ := testServer(t, att, src)

	ctx, cancel := clientCtx(t)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if got := src.fetchCount(); got != 1 {
		t.Fatalf("issuer fetches = %d before rotating, want 1", got)
	}

	srv.ForceRotate()

	second, err := stream.Recv()
	if err != nil {
		t.Fatalf("ForceRotate did not push a renewed SVID: %v", err)
	}
	if string(first.Svids[0].X509Svid) == string(second.Svids[0].X509Svid) {
		t.Error("the pushed SVID is byte-identical to the first; nothing was actually re-minted")
	}
	if got := src.fetchCount(); got != 2 {
		t.Errorf("issuer fetches = %d after rotating, want 2; the update did not come from the issuer", got)
	}
	if att.callCount() < 2 {
		t.Errorf("attestor called %d times; a forced rotation must re-check the connection like any other renewal", att.callCount())
	}
}

// TestForceRotateStillRefusesAMovedPeer: a forced rotation is an ordinary
// renewal, so it re-attests, and a peer whose binary changed loses the stream
// rather than being handed a fresh credential.
func TestForceRotateStillRefusesAMovedPeer(t *testing.T) {
	ca := newTestCA(t)
	first := toolIdentity(t)
	moved := toolIdentity(t)
	moved.BinaryHash = "changed"
	att := &fakeAttestor{onCall: func(n int) (*attest.Identity, error) {
		if n == 1 {
			return first, nil
		}
		return moved, nil
	}}
	client, srv, _ := testServer(t, att, newFakeSource(ca))

	ctx, cancel := clientCtx(t)
	defer cancel()
	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("first: %v", err)
	}

	srv.ForceRotate()

	_, err = stream.Recv()
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}
