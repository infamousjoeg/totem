package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infamousjoeg/totem/internal/attest"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// cmdServe runs the agent: the SPIFFE Workload API on a unix socket at mode
// 0600, with per-connection attestation. It is what the login agent starts, and
// it is the process every other totem command reports on.
func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", "", "socket to serve on (default: the one recorded at enroll)")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem serve'.", "could not read those options.")
	}

	state, err := workloadapi.LoadState("")
	if err != nil {
		return err
	}
	if !state.Enrolled() {
		return failf("Run the 'totem enroll' command your issuer operator gave you.",
			"this device is not set up with an issuer yet, so there is nothing to serve.")
	}

	sockPath := *socket
	if sockPath == "" {
		sockPath = state.SocketPath
	}
	if sockPath == "" {
		sockPath = workloadapi.DefaultSocketPath()
	}

	attestor, err := openAttestor()
	if err != nil {
		return err
	}

	srv := workloadapi.New(workloadapi.Config{
		SocketPath: sockPath,
		Identity: workloadapi.IdentityConfig{
			TrustDomain: state.TrustDomain,
			DeviceID:    state.DeviceID,
			AgentUsers:  state.AgentUsers,
		},
		Attestor:        attestor,
		Source:          nil, // the issuer is step 2; until then every caller is told so plainly
		Log:             workloadapi.NewLogger(""),
		ProtectionLevel: state.ProtectionLevel,
	})

	// SIGUSR1 means "renew everything now". It takes the ordinary path in
	// full, asking the issuer for fresh credentials and re-checking each
	// connection, so it can only ever produce what the issuer would have
	// produced at the next half-life anyway. `totem rotate` sends it.
	rotate := make(chan os.Signal, 1)
	signal.Notify(rotate, syscall.SIGUSR1)
	defer signal.Stop(rotate)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-rotate:
				srv.ForceRotate()
			}
		}
	}()

	fmt.Printf("totem is serving on %s\n", srv.Endpoint())
	fmt.Printf("Point tools at it with SPIFFE_ENDPOINT_SOCKET=%s\n", srv.Endpoint())
	return srv.Serve(ctx)
}

// openAttestor builds the attestor for this machine.
//
// The pin table is loaded from ~/.totem/pins.json and passed explicitly. attest
// makes pins a required parameter so that passing none is a visible decision at
// the call site rather than a silent downgrade to the weaker Team ID anchor;
// this is that call site, and on a device that has not run `totem init` the
// table really is empty, which is said out loud rather than hidden.
//
// attest.New is written by the attestation implementation. A build without it
// serves anyway and tells every caller plainly, rather than pretending or
// hanging.
func openAttestor() (attest.Attestor, error) {
	if attest.New == nil {
		fmt.Fprintln(os.Stderr, "totem: this build cannot identify callers yet, so it will refuse every request with an explanation.")
		return nil, nil
	}
	pins, err := LoadPins()
	if err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		fmt.Fprintln(os.Stderr, "totem: no programs are pinned on this device yet, so totem is relying on each program's signature alone.")
	}
	a, err := attest.New(spiffe.Catalog, pins)
	if err != nil {
		return nil, failf("Run 'totem doctor' to check this machine.",
			"totem could not set up caller identification: %v", err)
	}
	return a, nil
}
