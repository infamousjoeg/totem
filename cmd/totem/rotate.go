package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// cmdRotate tells the running agent to renew everything now instead of waiting
// for its half-life, and to push the result to every tool holding a connection
// open.
//
// It mints nothing itself. All it does is signal the agent, which then takes
// the ordinary path: ask the issuer, re-check the caller, push. So this is a
// convenience over waiting, never a way around the issuer.
func cmdRotate(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	wait := fs.Duration("wait", 0, "wait this long for the agent to finish renewing before returning")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem rotate'.", "could not read those options.")
	}

	rs, err := workloadapi.LoadRuntimeStatus("")
	if err != nil {
		return err
	}
	if rs == nil || rs.PID == 0 {
		return failf("Start it with 'totem serve', then try again.",
			"the agent is not running, so there is nothing to renew.")
	}
	// Confirm the socket is live before signalling: a stale status file could
	// otherwise point at a pid the OS has since handed to something else, and
	// signalling a stranger is not something totem does.
	conn, derr := net.DialTimeout("unix", rs.SocketPath, 500*time.Millisecond)
	if derr != nil {
		return failf("Start it with 'totem serve', then try again.",
			"the agent is not answering on %s, so it is not running.", rs.SocketPath)
	}
	_ = conn.Close()

	if err := syscall.Kill(rs.PID, syscall.SIGUSR1); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return failf("Start it with 'totem serve', then try again.",
				"the agent is no longer running.")
		}
		return failf("Check that the agent is running as you, then try again.",
			"totem could not reach the running agent: %v", err)
	}
	fmt.Println("Asked the agent to renew now. Tools holding a connection open get the new identity without asking for it.")

	if *wait > 0 {
		deadline := time.Now().Add(*wait)
		for time.Now().Before(deadline) {
			if next, lerr := workloadapi.LoadRuntimeStatus(""); lerr == nil && next != nil && next.UpdatedAt.After(rs.UpdatedAt) {
				fmt.Println("Renewed.")
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return failf("Run 'totem status' to see what the agent is holding, and 'totem log' for anything it refused.",
			"the agent did not finish renewing within %s.", *wait)
	}
	return nil
}
