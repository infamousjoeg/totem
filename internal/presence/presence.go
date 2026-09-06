// Package presence holds the presence assertion, the three presence states, the
// per-target presence levels and issuer-side sessions, and the grant model
// (grants, sub-grants, lineage, money ceilings, parked requests) that gate an
// identity becoming a credential.
//
// The one rule, restated for this package: only a present human turns an
// identity into a credential. Everything here is on the issuer side of that
// rule. The laptop's only contribution is a one-shot signature (see Sign); the
// issuer mints the challenge, verifies the signature, records the session,
// holds the grants, and parks what falls outside them.
//
// Files in this package:
//
//   - presence.go: the three states, the three levels, and shipped windows.
//   - encoding.go: the canonical bytes that get signed, and request hashing.
//   - sign.go: the laptop side, calling through platform.Key.
//   - verify.go: the issuer side, with one typed error per rejection.
//   - session.go: in-memory, never-persisted presence sessions.
//   - grant.go: grants, sub-grants, lineage, monotonic narrowing, money.
//   - parked.go: out-of-grant requests parked for a present human.
//
// Standard library only.
package presence

import (
	"strings"
	"time"
)

// State is one of the three presence states, and the credential always says
// which. A longer window is never one of the options.
type State string

const (
	// StatePresent means a human touched the sensor.
	StatePresent State = "present"
	// StateDelegated means a human granted an agent a scope once, with
	// presence, and the agent operates inside it until the grant expires or is
	// revoked.
	StateDelegated State = "delegated"
	// StateNone is a device with no presence capability, recorded as such.
	StateNone State = "none"
)

// Level is one of the three presence levels per target, named in the policy
// file: window (ride-along risk within the window, stated), always (per
// request, assertion bound to a hash of the request), step-up (park and
// approve from another enrolled device). These three names are exactly what
// the user-editable policy file accepts; there is no fourth.
//
// A windowed target that needs a fresh touch for one particular request (a
// second request seconds after an approval, a prompt flood, money above the
// step-up threshold) is not a level. It is a per-request escalation to always
// semantics: see SessionStore.Evaluate's escalate parameter.
type Level string

const (
	// LevelWindow: presence is checked once and then held for a bounded time.
	// Within the window, everything that tool does is authorized, including by
	// an attacker; that is the stated ride-along risk.
	LevelWindow Level = "window"
	// LevelAlways: per request. The assertion is bound to a hash of the
	// request so it cannot be reused, and no session is ever opened.
	LevelAlways Level = "always"
	// LevelStepUp: park and approve from another enrolled device. No touch on
	// the requesting device satisfies it and no session is ever opened; the
	// request goes into a Lot and a present human approves it there, bound to
	// its request hash.
	LevelStepUp Level = "step-up"
)

// MaxWindow is the longest window any target may hold: the shipped claude
// default of one hour. "A longer window is never one of the options" and
// "no global switch": the session store refuses to open anything longer, so no
// policy file, flag, or caller can extend it.
const MaxWindow = time.Hour

// Window is a shipped presence policy for a tool or profile: presence is
// checked once and then held for a bounded time. Windows are issuer-side
// sessions, evaluated on the issuer, never persisted; a restart means every
// tool prompts once. There is no global switch and never a longer window.
type Window struct {
	// Tool is the catalog tool name the window applies to, e.g. "claude" or
	// "aws". A touch must have been given for this tool; a Verified for "gh"
	// cannot open the claude window.
	Tool string
	// Target narrows the window to one target of the tool, e.g. an aws
	// profile name. Empty means the window covers the tool regardless of
	// target. When set, a touch must have been given for exactly this target.
	Target string
	// Group names the session this window draws from. Windows with the same
	// Group share one touch (gh and git share fifteen minutes). Empty means
	// the window is its own group. A member is honored only up to its own
	// Duration, whichever member was touched.
	Group string
	// Duration the presence session is honored for after a touch. Must be
	// positive and at most MaxWindow.
	Duration time.Duration
	// Level is the presence level for the target. LevelAlways binds the
	// assertion to a hash of the request so it cannot be reused; init
	// defaults it on for any profile whose role name contains admin or prod.
	Level Level
}

// SessionKey is the key a touch on this window is recorded under: the Group if
// set, otherwise Tool, or Tool:Target when Target is set.
func (w Window) SessionKey() string {
	if w.Group != "" {
		return w.Group
	}
	if w.Target != "" {
		return w.Tool + ":" + w.Target
	}
	return w.Tool
}

// validDuration reports whether the window is in (0, MaxWindow].
func (w Window) validDuration() bool {
	return w.Duration > 0 && w.Duration <= MaxWindow
}

// Shipped window durations from "Presence windows".
const (
	// ClaudeWindow: presence at session start, one-hour window. Covers the
	// bearer refresh and anything aws or gh do inside Claude Code's bash tool.
	ClaudeWindow = time.Hour
	// AWSWindow: fifteen minutes per named profile, which is also the aws
	// SVID lifetime.
	AWSWindow = 15 * time.Minute
	// GitWindow: gh and git, fifteen minutes, shared.
	GitWindow = 15 * time.Minute
	// GitGroup is the shared session group gh and git draw from.
	GitGroup = "git"
)

// DefaultWindows returns the shipped defaults for the local policy file:
// claude one hour; gh and git fifteen minutes on one shared session. AWS
// profiles are added per profile at init with AWSProfileWindow.
func DefaultWindows() []Window {
	return []Window{
		{Tool: "claude", Duration: ClaudeWindow, Level: LevelWindow},
		{Tool: "gh", Group: GitGroup, Duration: GitWindow, Level: LevelWindow},
		{Tool: "git", Group: GitGroup, Duration: GitWindow, Level: LevelWindow},
	}
}

// AWSProfileWindow is the window init writes for one named aws profile: a
// fifteen-minute window, or LevelAlways when the profile's role name contains
// admin or prod.
func AWSProfileWindow(profile, roleName string) Window {
	w := Window{Tool: "aws", Target: profile, Duration: AWSWindow, Level: LevelWindow}
	if RoleRequiresAlways(roleName) {
		w.Level = LevelAlways
	}
	return w
}

// RoleRequiresAlways reports whether init defaults presence:always for a role:
// any role name containing admin or prod, case-insensitive.
func RoleRequiresAlways(roleName string) bool {
	r := strings.ToLower(roleName)
	return strings.Contains(r, "admin") || strings.Contains(r, "prod")
}
