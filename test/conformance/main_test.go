package conformance

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/workloadapi/wltest"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// selfContained is true when TestMain started its own wltest agent (the
// default: nobody pointed the suite at a real one via SPIFFE_ENDPOINT_SOCKET).
// TestRotationIsPushedNotPolled uses it to tell "no second update arrived
// because nothing here drives or forces rotation" (skip, external-agent case)
// apart from "no second update arrived even though a short-lived self-issued
// SVID guarantees one" (fail, self-contained case).
var selfContained bool

// TestMain makes this suite runnable with `go test ./test/conformance/` and
// nothing else: no external totem agent, no environment variables. When
// SPIFFE_ENDPOINT_SOCKET is not already set, it starts a real totem Workload
// API server via internal/workloadapi/wltest — a real 0600 unix socket, real
// per-connection attestation, a real in-memory ECDSA P-256 CA minting real
// chaining X509-SVIDs — and points socketAddress() at it through the same
// standard environment variable a real agent would use, so no other code in
// this package needs to know which case it's in.
//
// SVIDLifetime is short (6s) specifically so TestRotationIsPushedNotPolled
// exercises a genuine rotation: the agent renews at half-life through its
// real production renewal path and pushes the result down the test's open
// stream. There is no test-only trigger hook in the server for this — the
// short lifetime is the trigger — which is a stronger proof of "rotation is
// pushed, not polled" than a forced signal would be.
//
// If SPIFFE_ENDPOINT_SOCKET IS already set, this leaves it untouched: that is
// the external-agent case (a real totem agent already running, or a caller
// wiring their own for CI), and every test must keep honoring it exactly as
// it did before wltest existed.
func TestMain(m *testing.M) {
	if _, already := os.LookupEnv(workloadapi.SocketEnv); already {
		os.Exit(m.Run())
	}

	agent, err := wltest.Start(wltest.Options{SVIDLifetime: 6 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "conformance: wltest.Start: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv(workloadapi.SocketEnv, agent.Endpoint()); err != nil {
		fmt.Fprintf(os.Stderr, "conformance: set %s: %v\n", workloadapi.SocketEnv, err)
		agent.Close()
		os.Exit(1)
	}
	selfContained = true

	code := m.Run()
	agent.Close()
	os.Exit(code)
}
