package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// maxClockSkew is how far this machine's clock may sit from the issuer's before
// short-lived credentials start failing in ways nobody can debug. A five-minute
// JWT-SVID leaves no room for more.
const maxClockSkew = 60 * time.Second

// check is one thing doctor looked at. Every failure carries its fix, because
// docs/totem-design.md "Experience" says an error tells the human what to do
// next, and a diagnostic that only says "broken" is the worst kind of error.
type check struct {
	name   string
	ok     bool
	detail string
	fix    string
	// skipped marks a check that could not run, which is neither pass nor fail.
	skipped bool
}

// cmdDoctor checks this machine and prints the fix for anything wrong. It
// checks reachability first, per docs/totem-design.md "Experience", because an
// unreachable issuer explains most of the other symptoms.
func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem doctor'.", "could not read those options.")
	}

	state, serr := workloadapi.LoadState("")
	if errors.Is(serr, workloadapi.ErrNoState) {
		state = &workloadapi.State{}
	} else if serr != nil {
		return serr
	}

	checks := []check{
		checkEnrollment(state),
		checkIssuerReachable(ctx, state),
		checkClockSkew(ctx, state),
		checkKeyStore(ctx),
		checkSocket(state),
		checkCatalog(),
	}

	failed := 0
	for _, c := range checks {
		switch {
		case c.skipped:
			fmt.Printf("  ?  %s: %s\n", c.name, c.detail)
		case c.ok:
			fmt.Printf("  ok %s: %s\n", c.name, c.detail)
		default:
			failed++
			fmt.Printf("  !! %s: %s\n", c.name, c.detail)
			if c.fix != "" {
				fmt.Printf("       %s\n", c.fix)
			}
		}
	}
	fmt.Println()
	if failed == 0 {
		fmt.Println("Everything totem needs is in place.")
		clearLastError()
		return nil
	}
	return failf("Fix the items marked !! above, then run 'totem doctor' again.",
		"%d of %d checks did not pass.", failed, len(checks))
}

// checkEnrollment reports whether this device has been set up with an issuer at
// all, which is the precondition for every other check that matters.
func checkEnrollment(state *workloadapi.State) check {
	if state.Enrolled() {
		return check{name: "set up", ok: true, detail: fmt.Sprintf("this device is set up with %s", state.IssuerURL)}
	}
	return check{
		name:   "set up",
		detail: "this device is not set up with an issuer yet",
		fix:    "Run the 'totem enroll' command your issuer operator gave you.",
	}
}

// checkIssuerReachable is deliberately first among the network checks: an
// unreachable issuer is the common cause and the retryable one.
func checkIssuerReachable(ctx context.Context, state *workloadapi.State) check {
	if state.IssuerURL == "" {
		return check{name: "issuer", skipped: true, detail: "no issuer set up yet"}
	}
	client, err := newIssuerClient(IssuerAddr{URL: state.IssuerURL, FingerprintHex: state.IssuerFingerprint})
	if err != nil {
		return check{name: "issuer", detail: "totem cannot identify this issuer", fix: "Run 'totem enroll' again with the link your issuer operator gave you."}
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := client.Reachable(cctx); err != nil {
		last := "never"
		if !state.LastIssuerContact.IsZero() {
			last = state.LastIssuerContact.Local().Format(time.RFC1123)
		}
		return check{
			name:   "issuer",
			detail: fmt.Sprintf("%s did not answer (last reached: %s)", state.IssuerURL, last),
			fix:    "Check your network. If you are away from home, a VPN or Tailscale connection to your issuer is what makes this work from a coffee shop.",
		}
	}
	return check{name: "issuer", ok: true, detail: state.IssuerURL + " answered, and it is the one this device trusts"}
}

// checkClockSkew compares this machine's clock to the issuer's. Credentials in
// totem are minutes long, so a clock that drifts turns every exchange into an
// unexplainable failure; naming the skew is the difference between a fix and a
// mystery.
func checkClockSkew(ctx context.Context, state *workloadapi.State) check {
	if state.IssuerURL == "" {
		return check{name: "clock", skipped: true, detail: "no issuer to compare against"}
	}
	client, err := newIssuerClient(IssuerAddr{URL: state.IssuerURL, FingerprintHex: state.IssuerFingerprint})
	if err != nil {
		return check{name: "clock", skipped: true, detail: "no issuer to compare against"}
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	remote, err := client.ServerDate(cctx)
	if err != nil {
		return check{name: "clock", skipped: true, detail: "your issuer did not report its time"}
	}
	skew := time.Since(remote)
	if skew < 0 {
		skew = -skew
	}
	if skew > maxClockSkew {
		return check{
			name:   "clock",
			detail: fmt.Sprintf("this machine's clock is %s away from your issuer's", skew.Round(time.Second)),
			fix:    "Turn on automatic time setting on this machine. Short-lived credentials stop working when the clocks disagree.",
		}
	}
	return check{name: "clock", ok: true, detail: fmt.Sprintf("within %s of your issuer", skew.Round(time.Second))}
}

// checkKeyStore reports what enrollment would get without creating anything.
// KeyStore.ProtectionLevel is queryable before a key exists precisely so this
// check does not have to make one.
func checkKeyStore(ctx context.Context) check {
	if platform.Open == nil {
		return check{name: "device key", detail: "this build cannot keep a device key",
			fix: "Use a build of totem for this operating system."}
	}
	store, err := platform.Open(ctx)
	if err != nil {
		return check{name: "device key", detail: fmt.Sprintf("no place to keep this device's key: %v", err),
			fix: "Check that your login keychain is unlocked, then run 'totem doctor' again."}
	}
	level := store.ProtectionLevel()
	detail := fmt.Sprintf("kept in: %s", level)
	switch level {
	case spiffe.ProtectionHardware:
		detail += " (this device's key cannot be copied off it)"
	case spiffe.ProtectionKeyring, spiffe.ProtectionSoftware:
		detail += " (no secure hardware here, which is fine and is recorded as part of this device's setup)"
	}
	return check{name: "device key", ok: true, detail: detail}
}

// checkSocket verifies the Workload API socket is present, is a socket, is mode
// 0600, and sits in a directory no other account can traverse.
func checkSocket(state *workloadapi.State) check {
	path := state.SocketPath
	if path == "" {
		path = workloadapi.DefaultSocketPath()
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return check{name: "socket", detail: "the agent is not running, so tools have nowhere to ask",
			fix: "Start it with 'totem serve'."}
	}
	if err != nil {
		return check{name: "socket", detail: fmt.Sprintf("cannot look at %s: %v", path, err),
			fix: "Check the permissions on " + filepath.Dir(path) + "."}
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return check{name: "socket", detail: path + " is not a socket",
			fix: "Move that file out of the way and run 'totem serve' again."}
	}
	if perm := fi.Mode().Perm(); perm != workloadapi.SocketMode {
		return check{name: "socket", detail: fmt.Sprintf("%s can be reached by other accounts on this machine (%#o)", path, perm),
			fix: fmt.Sprintf("Run: chmod %#o %s", workloadapi.SocketMode, path)}
	}
	if dir, derr := os.Stat(filepath.Dir(path)); derr == nil && dir.Mode().Perm()&0o077 != 0 {
		return check{name: "socket", detail: fmt.Sprintf("the folder holding the socket can be reached by other accounts (%#o)", dir.Mode().Perm()),
			fix: fmt.Sprintf("Run: chmod 700 %s", filepath.Dir(path))}
	}
	return check{name: "socket", ok: true, detail: fmt.Sprintf("%s, reachable only by you", path)}
}

// checkCatalog reports which programs totem is set up to identify, and where it
// expects to find each one. A tool whose expected locations are all missing is
// reported, because that is the difference between "not installed" and "totem
// will refuse it".
func checkCatalog() check {
	if len(spiffe.Catalog) == 0 {
		return check{name: "programs", detail: "no programs are set up, so totem would refuse every request",
			fix: "Use a release build of totem; this one shipped without its program list."}
	}
	var names, missing []string
	for _, e := range spiffe.Catalog {
		names = append(names, e.Name)
		if !anyPathExists(e.ExpectedPaths) {
			missing = append(missing, e.Name)
		}
	}
	detail := fmt.Sprintf("%d set up (%s)", len(spiffe.Catalog), strings.Join(names, ", "))
	if len(missing) > 0 {
		return check{name: "programs", ok: true,
			detail: detail + "; not installed here: " + strings.Join(missing, ", ")}
	}
	return check{name: "programs", ok: true, detail: detail}
}

// anyPathExists reports whether any of a catalog entry's expected locations
// resolves on this machine. The paths may use ~ and glob wildcards.
func anyPathExists(paths []string) bool {
	for _, p := range paths {
		matches, err := filepath.Glob(expandHome(p))
		if err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}
