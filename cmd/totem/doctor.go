package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
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
	// notes are extra lines printed under the check, for detail that would
	// make the one-line summary unreadable.
	notes []string
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
		checkKeyBackends(ctx),
		checkDeviceKey(ctx, state),
		checkSocket(state),
		checkCatalog(),
	}
	checks = append(checks, checkToolAnchors()...)

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
		for _, n := range c.notes {
			fmt.Printf("       %s\n", n)
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

// checkKeyBackends reports what enrollment would get on this machine, and what
// stands between it and a better level, without creating anything.
// platform.Probe is the same walk Open takes, so this is the honest preview
// rather than a guess.
func checkKeyBackends(ctx context.Context) check {
	if platform.Probe == nil {
		return check{name: "key storage", detail: "this build cannot keep a device key",
			fix: "Use a build of totem for this operating system."}
	}
	candidates := platform.Probe(ctx)
	if len(candidates) == 0 {
		return check{name: "key storage", detail: "nowhere on this machine can keep a device key",
			fix: "Run 'totem doctor' again after unlocking your login keychain."}
	}
	var chosen *platform.Candidate
	lines := make([]string, 0, len(candidates))
	for i := range candidates {
		c := candidates[i]
		mark := "unavailable"
		if c.Available {
			mark = "usable"
			if chosen == nil {
				chosen = &candidates[i]
			}
		}
		line := fmt.Sprintf("%s (%s, %s)", c.Name, c.Level, mark)
		if c.Reason != "" {
			line += ": " + c.Reason
		}
		lines = append(lines, line)
	}
	if chosen == nil {
		return check{name: "key storage", detail: "nothing here can hold a device key right now", notes: lines,
			fix: "Unlock your login keychain, or check that your secure hardware is reachable."}
	}
	detail := fmt.Sprintf("would use %s (%s)", chosen.Name, chosen.Level)
	if !chosen.Presence {
		detail += ", which cannot ask you to confirm"
	}
	return check{name: "key storage", ok: true, detail: detail, notes: lines}
}

// checkDeviceKey is the check that catches a device that has quietly stopped
// being itself.
//
// It does two separate things, and both are needed. platform.Check really
// re-imports the stored key into the hardware and really takes a signature
// from it, so a machine whose stored blob no longer loads fails here rather
// than at the next exchange; a doctor that only reported the protection level
// would say "hardware, all good" on a machine that can no longer sign at all.
// Then it compares both loaded public halves against the two the issuer
// enrolled, because a re-import that goes subtly wrong does not error. It can
// return a fresh, working key that signs happily and verifies against nothing
// anyone ever enrolled. Only the comparison catches that, and only the issuer
// would catch it otherwise, or nobody would.
func checkDeviceKey(ctx context.Context, state *workloadapi.State) check {
	key, err := platform.Check(ctx, keyLabel(state))
	switch {
	case errors.Is(err, platform.ErrKeyNotFound):
		return check{
			name:   "device key",
			detail: "this device has no key, so it is not set up",
			fix:    "Run the 'totem enroll' command your issuer operator gave you.",
		}
	case errors.Is(err, platform.ErrKeyUnloadable):
		return check{
			name:   "device key",
			detail: "this device's key exists but can no longer be used (" + firstLine(err.Error()) + ")",
			fix:    "This device has to be set up again. Run 'totem uninstall', then the 'totem enroll' command your issuer operator gave you. Do not skip this: nothing this device signs will be accepted until you do.",
		}
	case errors.Is(err, platform.ErrHardwareKeyStranded):
		return check{
			name:   "device key",
			detail: "this device's key lives in secure hardware that is not reachable right now",
			fix:    "Get the secure hardware working again, then run 'totem doctor'. Do NOT re-enroll to get around this: a new setup would land this device at a weaker level than the one it already has.",
		}
	case err != nil:
		return check{
			name:   "device key",
			detail: "this device's key did not check out: " + firstLine(err.Error()),
			fix:    "Run 'totem doctor' again. If it keeps failing, this device has to be set up again with 'totem enroll'.",
		}
	}

	// The key on this machine works. The question left is whether it is the
	// same key the issuer knows about.
	if !state.Enrolled() || len(state.DevicePublicDER) == 0 {
		return check{name: "device key", ok: true,
			detail: fmt.Sprintf("loads and signs, kept in: %s (no setup on record to compare it against)", key.ProtectionLevel())}
	}
	loadedDevice, err := publicKeyDER(key.Public())
	if err != nil {
		return check{name: "device key", detail: "totem could not read this device's key back: " + err.Error(),
			fix: "Run 'totem doctor' again. If it keeps failing, set this device up again with 'totem enroll'."}
	}
	if !bytes.Equal(loadedDevice, state.DevicePublicDER) {
		return check{
			name:   "device key",
			detail: "this machine's key is NOT the one that was set up with your issuer",
			fix:    "This device has to be set up again. Run 'totem uninstall', then the 'totem enroll' command your issuer operator gave you. Everything this device signs is being checked against a key your issuer does not have, so nothing it asks for will be accepted.",
		}
	}

	// The presence half matters just as much and fails more quietly: a
	// mismatch here leaves silent renewals working and every confirmation
	// failing, which reads as a flaky sensor rather than a wrong key.
	loadedPresence := key.PresencePublic()
	switch {
	case loadedPresence == nil && len(state.PresencePublicDER) > 0:
		return check{
			name:   "device key",
			detail: "this device was set up as able to confirm it's you, and now it cannot",
			fix:    "Run 'totem status'. If the secure hardware is reachable, set this device up again with 'totem enroll'; nothing that needs you to confirm will work until then.",
		}
	case loadedPresence != nil && len(state.PresencePublicDER) > 0:
		lp, perr := publicKeyDER(loadedPresence)
		if perr != nil {
			return check{name: "device key", detail: "totem could not read the key that confirms it's you: " + perr.Error(),
				fix: "Set this device up again with 'totem enroll'."}
		}
		if !bytes.Equal(lp, state.PresencePublicDER) {
			return check{
				name:   "device key",
				detail: "the key this device uses to confirm it's you is NOT the one that was set up with your issuer",
				fix:    "This device has to be set up again. Run 'totem uninstall', then the 'totem enroll' command your issuer operator gave you. Silent renewals would keep working and every confirmation would keep failing, which is the confusing failure this check exists to catch.",
			}
		}
	}

	detail := fmt.Sprintf("loads, signs, and matches your issuer's record; kept in: %s", key.ProtectionLevel())
	if loadedPresence == nil {
		detail += "; this device cannot ask you to confirm, which is recorded on its setup"
	}
	return check{name: "device key", ok: true, detail: detail}
}

// keyLabel is the key store label this device's key lives under.
func keyLabel(state *workloadapi.State) string {
	if state != nil && state.KeyLabel != "" {
		return state.KeyLabel
	}
	return platform.DeviceKeyLabel
}

// checkToolAnchors reports each tool's anchor, which docs/totem-design.md
// "Agent (laptop)" asks doctor for by name: whether the program is pinned to a
// hash, or resting on its maker's signature, and whether the program sitting at
// its path right now still matches that pin.
//
// A pinned tool whose hash moved is a refusal, not a warning, so it is reported
// as a failed check with the exact command that resolves it. Decision 2:
// `totem trust <tool>` shows the old and new hash and re-pins.
func checkToolAnchors() []check {
	pins, err := LoadPins()
	if err != nil {
		return []check{{name: "program anchors", detail: err.Error(),
			fix: "Move " + PinsPath() + " out of the way and run 'totem init' again."}}
	}
	out := make([]check, 0, len(spiffe.Catalog))
	for _, entry := range spiffe.Catalog {
		out = append(out, checkOneToolAnchor(entry, pins[entry.Name]))
	}
	return out
}

func checkOneToolAnchor(entry spiffe.CatalogEntry, pin string) check {
	name := "anchor: " + entry.Name
	path := resolveToolPath(entry.ExpectedPaths)
	if path == "" {
		if pin == "" {
			return check{name: name, skipped: true, detail: "not installed here"}
		}
		return check{name: name, skipped: true,
			detail: "pinned to " + shortFingerprint(pin) + ", but not installed here right now"}
	}
	if pin == "" {
		return check{name: name, ok: true,
			detail: "relying on its maker's signature (" + entry.SigningID + "); not pinned to a specific copy",
		}
	}
	sum, err := hashFile(path)
	if err != nil {
		return check{name: name, detail: "cannot read " + path + ": " + err.Error(),
			fix: "Check the permissions on " + path + "."}
	}
	if sum != pin {
		return check{
			name:   name,
			detail: "the copy at " + path + " is not the one totem pinned (pinned " + shortFingerprint(pin) + ", found " + shortFingerprint(sum) + ")",
			fix:    "If you just updated " + entry.Name + ", run 'totem trust " + entry.Name + "' to see both and confirm the new one. If you did not update it, do not confirm it: run 'totem log' and find out what changed it.",
		}
	}
	return check{name: name, ok: true, detail: "pinned to " + shortFingerprint(pin) + " and still matching"}
}

// resolveToolPath returns the first existing path among a catalog entry's
// expected locations, which may contain ~ and glob wildcards.
func resolveToolPath(paths []string) string {
	for _, p := range paths {
		matches, err := filepath.Glob(expandHome(p))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
				return m
			}
		}
	}
	return ""
}

// hashFile is the SHA-256 of a file in hex, which is the form a pin takes.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	names := make([]string, 0, len(spiffe.Catalog))
	for _, e := range spiffe.Catalog {
		names = append(names, e.Name)
	}
	return check{name: "programs", ok: true,
		detail: fmt.Sprintf("%d totem can identify (%s); each one's anchor is below", len(spiffe.Catalog), strings.Join(names, ", "))}
}
