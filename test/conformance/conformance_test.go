// Package conformance runs the real github.com/spiffe/go-spiffe/v2 client
// against a running totem agent's Workload API socket. This is what proves the
// design's central claim, "anything that already speaks SPIFFE works
// unchanged" (docs/totem-design.md, "Agent (laptop)"): a hand-rolled gRPC
// client would exercise totem's wire format but would prove nothing about
// compatibility with the ecosystem client that spiffe-helper, Envoy SDS, and
// everything else in the wild actually uses.
//
// Every test here gates on the agent's socket being reachable and SKIPs,
// naming exactly what it would have asserted, until it is. No test in this
// file is allowed to pass without exercising the real assertion it names —
// see the individual skip messages for what remains a documented gap even
// once the socket exists.
package conformance

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// defaultSocketRelPath, under the user's home directory, is used only when
// SPIFFE_ENDPOINT_SOCKET is unset.
//
// PLACEHOLDER pending confirmation: docs/totem-design.md says only "Standard
// SPIFFE Workload API on a unix socket, mode 0600" and does not name a path.
// This mirrors internal/errors.LastErrorPath's ~/.totem/ convention as the
// most likely default. The lead will confirm the agent's actual default once
// the workload teammate reports; update only this constant when that happens
// — socketAddress already reads SPIFFE_ENDPOINT_SOCKET first, which is the
// standard override every SPIFFE-aware client and this suite both honor, so
// nothing else here needs to change.
const defaultSocketRelPath = ".totem/agent.sock"

// defaultSocketAddress resolves the home directory and builds an absolute
// "unix:///..." address. It deliberately does not embed a literal "~" in the
// URI: a unix:// address's authority component is parsed before its path, so
// "unix://~/x" would put "~" in the URL's host, not its path, and silently
// fail to expand. Resolving the home directory first and emitting an already-
// absolute path sidesteps that trap entirely.
func defaultSocketAddress() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("conformance: resolve home directory for default socket address: %w", err)
	}
	return "unix://" + filepath.Join(home, defaultSocketRelPath), nil
}

// rotationTriggerEnv, when set, names a shell command this suite runs (via `sh
// -c`) to make the connected totem agent rotate the SVID it is currently
// serving. No such hook exists yet. Until the workload teammate wires one (or
// tells this suite how to trigger a rotation some other way), TestRotationIsPushedNotPolled
// documents exactly what it would assert and skips rather than passing hollow
// on a rotation that was never actually forced to happen.
const rotationTriggerEnv = "TOTEM_TEST_ROTATE_SVID_CMD"

// socketAddress resolves the Workload API address using the standard
// SPIFFE_ENDPOINT_SOCKET convention (unix:///path/to/socket), per the spec's
// socket-discovery requirement, falling back to defaultSocketAddress when the
// variable is unset.
func socketAddress() (string, error) {
	if addr, ok := workloadapi.GetDefaultAddress(); ok {
		return addr, nil
	}
	return defaultSocketAddress()
}

// socketFilePath extracts the filesystem path from a unix:// Workload API
// address, for the checks (os.Stat, net.Dial) that need a bare path rather
// than a URI. Addresses reaching here are always already-absolute unix paths
// (see defaultSocketAddress's doc comment on why "~" is never embedded in the
// URI itself), so no further expansion happens here.
func socketFilePath(addr string) (string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", fmt.Errorf("conformance: parse socket address %q: %w", addr, err)
	}
	if u.Scheme != "unix" {
		return "", fmt.Errorf("conformance: only unix:// socket addresses are supported, got scheme %q", u.Scheme)
	}
	path := u.Path
	if path == "" {
		path = u.Opaque
	}
	if path == "" {
		return "", fmt.Errorf("conformance: socket address %q has no path", addr)
	}
	return path, nil
}

// socketWaitTimeout bounds how long reachableSocket will keep retrying before
// reporting the socket unreachable. The agent creates its socket file during
// startup, so a test process that starts the agent (or races an
// already-starting one) can see ENOENT or a refused connection for a brief
// window that means "not up yet," not "doesn't exist" — a single stat-and-dial
// would misreport that window as "not yet functional" and skip a suite that
// would have passed a moment later. This is a fixed guess at that window
// pending real numbers from the workload teammate on agent startup latency.
const socketWaitTimeout = 2 * time.Second

// socketWaitInterval is the poll cadence within socketWaitTimeout.
const socketWaitInterval = 50 * time.Millisecond

// reachableSocket resolves the configured Workload API address and reports
// whether a listener answers there within socketWaitTimeout. It never asserts
// anything about what the listener returns — that is every other test's job —
// only whether the suite should run at all yet. Before step 1 lands this
// always spends the full socketWaitTimeout finding nothing and returning
// false; that fixed cost is the trade-off for not misreporting a genuine
// startup race as "doesn't exist" once the agent does.
func reachableSocket() (addr, path string, ok bool) {
	addr, err := socketAddress()
	if err != nil {
		return fmt.Sprintf("<unresolved: %v>", err), "", false
	}
	path, err = socketFilePath(addr)
	if err != nil {
		return addr, "", false
	}

	deadline := time.Now().Add(socketWaitTimeout)
	for {
		if _, statErr := os.Stat(path); statErr == nil {
			if conn, dialErr := net.DialTimeout("unix", path, time.Second); dialErr == nil {
				conn.Close()
				return addr, path, true
			}
		}
		if time.Now().After(deadline) {
			return addr, path, false
		}
		time.Sleep(socketWaitInterval)
	}
}

// skipUntilAgentExists is the shared gate: every test in this file calls this
// first and skips, naming what it would have asserted, until a totem agent is
// actually listening. This is the mechanism by which "the skip disappears on
// its own once the socket is reachable" — nothing here needs editing when the
// workload API server lands, only SPIFFE_ENDPOINT_SOCKET (or a correct
// defaultSocketAddress) needs to point at it.
func skipUntilAgentExists(t *testing.T, willAssert string) (addr, path string) {
	t.Helper()
	addr, path, ok := reachableSocket()
	if !ok {
		t.Skipf("not yet functional: no totem agent Workload API socket reachable at %s "+
			"(SPIFFE_ENDPOINT_SOCKET to override; resolved path %s). Will %s once "+
			"internal/workloadapi serves the Workload API on this socket.", addr, path, willAssert)
	}
	return addr, path
}

// TestUnixURITildeIsParsedAsHostNotPath pins the trap that produced a real bug
// during development: a "unix://" address's authority component is parsed
// before its path, so a literal "~" placed right after the double slash
// becomes the URL's Host, not part of Path, and is silently dropped rather
// than expanded to the home directory. defaultSocketAddress resolves the home
// directory itself and never embeds "~" in the URI for exactly this reason —
// this test exists so that if someone "simplifies" it back to embedding "~",
// a test fails instead of the default socket path silently resolving to
// "/.totem/agent.sock" at the filesystem root.
func TestUnixURITildeIsParsedAsHostNotPath(t *testing.T) {
	u, err := url.Parse("unix://~/.totem/agent.sock")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Host != "~" {
		t.Fatalf("url.Parse(\"unix://~/.totem/agent.sock\").Host = %q, want %q — "+
			"if this fails, net/url's behavior changed and the reasoning in "+
			"defaultSocketAddress's doc comment should be revisited", u.Host, "~")
	}
	if strings.Contains(u.Path, "~") {
		t.Fatalf("url.Parse(\"unix://~/.totem/agent.sock\").Path = %q unexpectedly retained the \"~\"; "+
			"the historical bug was exactly that Path silently lost it", u.Path)
	}
}

// TestDefaultSocketAddressNeverEmbedsATilde is the regression test for the
// real bug this pins: defaultSocketAddress must produce an already-absolute
// "unix:///..." address with an empty URL host, never a literal "~" that
// socketFilePath would then silently fail to expand.
func TestDefaultSocketAddressNeverEmbedsATilde(t *testing.T) {
	addr, err := defaultSocketAddress()
	if err != nil {
		t.Fatalf("defaultSocketAddress: %v", err)
	}
	if strings.Contains(addr, "~") {
		t.Fatalf("defaultSocketAddress() = %q contains a literal \"~\"", addr)
	}

	u, err := url.Parse(addr)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", addr, err)
	}
	if u.Host != "" {
		t.Fatalf("defaultSocketAddress() = %q has non-empty URL host %q; "+
			"it must be a bare unix:///absolute/path URI", addr, u.Host)
	}
	if !filepath.IsAbs(u.Path) {
		t.Fatalf("defaultSocketAddress() = %q has non-absolute path %q", addr, u.Path)
	}

	path, err := socketFilePath(addr)
	if err != nil {
		t.Fatalf("socketFilePath(%q): %v", addr, err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	want := filepath.Join(home, defaultSocketRelPath)
	if path != want {
		t.Fatalf("socketFilePath(defaultSocketAddress()) = %q, want %q", path, want)
	}
}

// TestSocketPermissions asserts the agent's Workload API socket is mode 0600,
// per docs/totem-design.md: "Standard SPIFFE Workload API on a unix socket,
// mode 0600."
func TestSocketPermissions(t *testing.T) {
	_, path := skipUntilAgentExists(t, "stat the socket and assert its mode is exactly 0600, refusing to pass otherwise")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("socket was reachable a moment ago but Stat(%s) now fails: %v", path, err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("totem agent socket %s has mode %#o, want 0600", path, mode)
	}
}

// TestWorkloadAPIConformance is the step-1 gate itself: it fetches an
// X509-SVID from a running totem agent using the real, unmodified
// github.com/spiffe/go-spiffe/v2 workloadapi.Client — the same client
// spiffe-helper and every other SPIFFE-aware consumer uses — and asserts the
// SVID verifies against the issuer bundle returned in the same call. A
// hand-rolled gRPC client against totem's wire format would not prove
// interoperability; this does.
func TestWorkloadAPIConformance(t *testing.T) {
	addr, _ := skipUntilAgentExists(t, "connect with workloadapi.New, call FetchX509Context, and assert "+
		"x509svid.Verify chains the returned SVID to the returned bundle")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(addr))
	if err != nil {
		t.Fatalf("workloadapi.New(%s): %v", addr, err)
	}
	defer client.Close()

	x509Ctx, err := client.FetchX509Context(ctx)
	if err != nil {
		t.Fatalf("FetchX509Context: %v", err)
	}
	if len(x509Ctx.SVIDs) == 0 {
		t.Fatal("FetchX509Context returned an X509Context with zero SVIDs")
	}

	svid := x509Ctx.DefaultSVID()
	if len(svid.Certificates) == 0 {
		t.Fatal("default X509-SVID has zero certificates")
	}

	id, chains, err := x509svid.Verify(svid.Certificates, x509Ctx.Bundles)
	if err != nil {
		t.Fatalf("x509svid.Verify: SVID does not chain to the issuer bundle returned alongside it: %v", err)
	}
	if id != svid.ID {
		t.Fatalf("x509svid.Verify returned SPIFFE ID %s, want it to match the SVID's own ID %s", id, svid.ID)
	}
	if len(chains) == 0 {
		t.Fatal("x509svid.Verify reported success but returned zero chains to a trusted root")
	}

	t.Logf("verified X509-SVID %s via go-spiffe workloadapi.Client, %d chain(s) to the issuer bundle", id, len(chains))
}

// rotationWatcher adapts workloadapi.X509ContextWatcher's push callbacks onto
// channels a test goroutine can select on. It must never call testing.T
// methods itself: OnX509ContextUpdate/OnX509ContextWatchError run on the
// client's internal goroutine, and only the test's own goroutine is allowed to
// fail the test.
type rotationWatcher struct {
	updates chan *workloadapi.X509Context
}

func (w *rotationWatcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	select {
	case w.updates <- c:
	default:
		// A slow test goroutine should never make the watcher itself block or
		// panic; drop the update, the test's select loop already has an earlier
		// one queued and this streaming path is what's under test, not buffering.
	}
}

func (w *rotationWatcher) OnX509ContextWatchError(error) {
	// Transient watch errors are expected around a forced rotation (the stream
	// may reconnect); the timeout in the test's select is the real failure
	// signal, not this callback.
}

// TestRotationIsPushedNotPolled exercises the spiffe-helper-shaped usage
// pattern: hold client.WatchX509Context open and assert a rotation is pushed
// to the callback, rather than requiring the caller to poll FetchX509SVID in a
// loop. This is currently gated behind rotationTriggerEnv because nothing in
// this repo yet exposes a way to force the agent to rotate on demand; without
// that, "wait and see if an update arrives" would be a hollow pass on any run
// that happens not to cross a real rotation boundary. See the reported gap in
// the teammate summary: this is what's needed from the workload teammate to
// turn this from a skip into a real assertion.
func TestRotationIsPushedNotPolled(t *testing.T) {
	addr, _ := skipUntilAgentExists(t, "hold client.WatchX509Context open, run the "+rotationTriggerEnv+
		" command to force a rotation, and assert a second OnX509ContextUpdate delivers a different "+
		"leaf certificate without the client calling FetchX509SVID again")

	trigger := os.Getenv(rotationTriggerEnv)
	if trigger == "" {
		t.Skipf("not yet functional: socket %s is reachable but %s is unset, so this suite has no way "+
			"to force the agent to rotate its SVID on demand. Will hold client.WatchX509Context open, "+
			"run the configured trigger command, and assert a second OnX509ContextUpdate delivers a "+
			"different leaf certificate than the first — without the client polling FetchX509SVID — "+
			"once a trigger mechanism exists.", addr, rotationTriggerEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(addr))
	if err != nil {
		t.Fatalf("workloadapi.New(%s): %v", addr, err)
	}
	defer client.Close()

	watcher := &rotationWatcher{updates: make(chan *workloadapi.X509Context, 4)}
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()

	go func() {
		// Any error here surfaces indirectly: the test's select loops below time
		// out if the watch dies without delivering the expected updates. We
		// deliberately do not call t methods from this goroutine.
		_ = client.WatchX509Context(watchCtx, watcher)
	}()

	var first *workloadapi.X509Context
	select {
	case first = <-watcher.updates:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the initial X509Context to be pushed via WatchX509Context")
	}
	if len(first.DefaultSVID().Certificates) == 0 {
		t.Fatal("initial pushed X509Context's default SVID has zero certificates")
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", trigger)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("rotation trigger %q failed: %v (stderr: %s)", trigger, err, stderr.String())
	}

	select {
	case second := <-watcher.updates:
		firstLeaf := first.DefaultSVID().Certificates[0]
		secondLeaf := second.DefaultSVID().Certificates[0]
		if bytes.Equal(firstLeaf.Raw, secondLeaf.Raw) {
			t.Fatal("second pushed update carried the same leaf certificate as the first; " +
				"the trigger ran but no rotation was observed")
		}
		id, chains, err := x509svid.Verify(second.DefaultSVID().Certificates, second.Bundles)
		if err != nil {
			t.Fatalf("rotated SVID does not chain to the bundle pushed alongside it: %v", err)
		}
		if len(chains) == 0 {
			t.Fatal("rotated SVID verified with zero chains to a trusted root")
		}
		t.Logf("rotation was pushed without a poll: new SVID %s", id)
	case <-ctx.Done():
		t.Fatal("rotation trigger ran but no second update was pushed before the timeout; " +
			"rotation is not reaching the client via the watch, or is only visible via polling")
	}
}
