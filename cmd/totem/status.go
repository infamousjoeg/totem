package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// cmdStatus shows what this device is and what it can do right now: the device,
// how its key is protected, which issuer it trusts, whether it is set up, where
// tools reach it, and the identity it is currently holding with its expiry.
//
// It reads the running agent's snapshot rather than calling the Workload API,
// because default deny applies to `totem` exactly as it does to anything else:
// totem is not in the tool catalog and does not get an identity from its own
// socket.
func cmdStatus(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	verbose := fs.Bool("verbose", false, "include the exact identity strings")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem status'.", "could not read those options.")
	}

	state, err := workloadapi.LoadState("")
	if err != nil {
		return err
	}

	// docs/totem-design.md "Experience": refusals land in the local log and
	// status surfaces them first.
	if line := latestRefusal(); line != "" {
		fmt.Println("Needs your attention:")
		fmt.Println("  " + line)
		fmt.Println()
	}

	fmt.Println("This device")
	fmt.Printf("  set up:        %s\n", yesNo(state.Enrolled()))
	if state.DeviceID != "" {
		fmt.Printf("  device:        %s\n", state.DeviceID)
	}
	fmt.Printf("  key kept in:   %s\n", orDash(string(state.ProtectionLevel)))
	fmt.Printf("  can confirm:   %s\n", confirmDescription(state))
	fmt.Printf("  name:          %s\n", orDash(state.TrustDomain))
	fmt.Println()

	fmt.Println("Your issuer")
	fmt.Printf("  address:       %s\n", orDash(state.IssuerURL))
	fmt.Printf("  verified as:   %s\n", orDash(shortFingerprint(state.IssuerFingerprint)))
	fmt.Printf("  last reached:  %s\n", whenOrNever(state.LastIssuerContact))
	if state.Enrolled() {
		fmt.Printf("  checked:       %s\n", describeFirstContact(state.FirstContact))
	}
	fmt.Println()

	rs, err := workloadapi.LoadRuntimeStatus("")
	if err != nil {
		return err
	}
	fmt.Println("The agent")
	if rs == nil {
		fmt.Println("  running:       no")
		fmt.Printf("  socket:        %s (not there right now)\n", orDash(state.SocketPath))
		fmt.Println()
		fmt.Println("  Start it with 'totem serve', or check 'totem doctor'.")
		return nil
	}
	fmt.Printf("  running:       yes (since %s)\n", rs.StartedAt.Local().Format(time.RFC1123))
	fmt.Printf("  socket:        %s\n", rs.SocketPath)
	fmt.Printf("  tools use:     SPIFFE_ENDPOINT_SOCKET=%s\n", rs.Endpoint)
	fmt.Println()

	fmt.Println("Identity right now")
	if len(rs.SVIDs) == 0 {
		fmt.Println("  none held. Nothing has asked for one, or your issuer is not reachable.")
		return nil
	}
	for _, s := range rs.SVIDs {
		label := s.Tool
		if label == "" {
			label = lastSegment(s.SpiffeID)
		}
		fmt.Printf("  %-12s expires %s, renews on its own %s\n",
			label+":", s.ExpiresAt.Local().Format(time.Kitchen), humanUntil(s.RenewsAt))
		if *verbose {
			fmt.Printf("               %s\n", s.SpiffeID)
		}
	}
	return nil
}

// latestRefusal returns the newest refusal or failure from the local log, as
// one line, or empty when there is nothing to show.
func latestRefusal() string {
	events, err := workloadapi.ReadEvents("", 200)
	if err != nil {
		return ""
	}
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.Kind == workloadapi.KindIssuance {
			continue
		}
		if time.Since(ev.Time) > 24*time.Hour {
			return ""
		}
		msg := ev.Message
		if ev.Fix != "" {
			msg += " " + ev.Fix
		}
		return strings.TrimSpace(msg)
	}
	return ""
}

// confirmDescription says whether this device can ask a human to confirm. A
// device that cannot still works; the fact is recorded on its setup and travels
// with every identity, so a target that needs a person refuses this device
// rather than being fooled by it.
func confirmDescription(state *workloadapi.State) string {
	if !state.Enrolled() {
		return "not set up yet"
	}
	if state.Presence == presence.StatePresent {
		return "yes, this device can ask you to confirm"
	}
	return "no (recorded on this device's setup; anything needing a person will refuse it)"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "not set up yet"
	}
	return s
}

func whenOrNever(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format(time.RFC1123)
}

func humanUntil(t time.Time) string {
	if t.IsZero() {
		return "when it needs to"
	}
	d := time.Until(t).Round(time.Minute)
	if d <= 0 {
		return "any moment"
	}
	return "in " + d.String()
}

func lastSegment(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}
