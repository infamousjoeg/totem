// Package errors defines the typed exit codes and the ~/.totem/last-error JSON
// schema that let a calling harness tell retryable from terminal. Because
// calling tools swallow helper stderr, the file is the contract and the exit
// code is the fast path (docs/totem-design.md "Experience", "Errors are typed
// for machines and plain for humans").
package errors

import "time"

// Exit codes: helpers exit with distinct codes for retryable versus terminal,
// so a harness can branch on the code without parsing the calling tool's prose.
const (
	// ExitOK is a successful exchange.
	ExitOK = 0
	// ExitTerminal is a permanent failure; do not retry.
	ExitTerminal = 1
	// ExitRetryable is a transient failure (for example, issuer unreachable);
	// back off and retry. totem run backs off itself for anything it wraps.
	ExitRetryable = 75
)

// LastErrorPath is the stable file a harness can read. It is ~/.totem/last-error
// (resolve ~ at runtime). The file is the load-bearing signal: a harness reads a
// known path reliably, but cannot rely on aws/gh/git forwarding helper stderr.
const LastErrorPath = "~/.totem/last-error"

// Reason is a machine token naming why an exchange failed or parked. The set is
// closed and documented in the reasons() table below; every call site must use
// one of these constants rather than free text, and Retryable() is the single
// place classification happens so it cannot drift between call sites
// (totem-design-decisions.md entry 37: "~/.totem/last-error JSON is the machine
// error contract").
type Reason string

// The closed set of reason tokens. Adding a new failure mode means adding both
// a constant here and an entry in the reasons() table; TestReasonsTableIsClosed
// enforces that the two never drift apart.
const (
	// ReasonIssuerUnreachable: the issuer could not be reached. Retryable —
	// short outages ride out on existing credential lifetimes per the spec's
	// fail-closed rule, and totem run performs the backoff itself. This is the
	// coffee-shop network-blip case; Write backstops it with a floor
	// (retryFloors) if a record reaches disk with no RetryAfter set, so a
	// harness never gets a bare "retry" with nothing to back off by.
	ReasonIssuerUnreachable Reason = "issuer_unreachable"

	// ReasonPresenceDenied: a human was asked and declined, or the sixty-second
	// prompt timed out. Terminal for this attempt — platform.ErrPresenceDenied
	// documents that a later attempt may succeed, but this attempt must not be
	// retried automatically. A harness MUST NOT auto-retry on this reason: a
	// retry loop on presence denial degenerates into prompt-spamming the
	// human, which is its own denial-of-service against the sensor and the
	// person behind it. A fresh, human-initiated attempt is fine; a harness
	// looping on ExitTerminal/this reason on its own is not.
	ReasonPresenceDenied Reason = "presence_denied"

	// ReasonPresenceUnavailable: this device's protection level has no presence
	// capability at all (platform.ErrPresenceUnavailable). Terminal: it is a
	// permanent property of the device, not a transient condition.
	ReasonPresenceUnavailable Reason = "presence_unavailable"

	// ReasonNotInCatalog: the binary is not a tool totem issues identities for
	// (attest.ErrNotInCatalog). Terminal: this is the default-deny attestation
	// path and needs a catalog or config change, not a retry.
	ReasonNotInCatalog Reason = "not_in_catalog"

	// ReasonSignatureMismatch: the binary's hash, Team ID, or signing identifier
	// does not match its pinned catalog entry (attest.ErrSignatureMismatch).
	// Terminal: attestation failed and needs `totem trust <tool>`, not a retry.
	ReasonSignatureMismatch Reason = "signature_mismatch"

	// ReasonOutOfGrantParked: a delegated agent's request fell outside its
	// grant and was parked for step-up rather than refused. Retryable, by
	// design: "Parking must never look like a terminal failure" — the agent
	// polls ParkedID on a later heartbeat rather than treating this as failed.
	// Write backstops this with a heartbeat-cadence-sized floor (retryFloors)
	// if a record reaches disk with no RetryAfter set.
	ReasonOutOfGrantParked Reason = "out_of_grant_parked"

	// ReasonGrantExpired: the delegated grant lapsed. Terminal: the agent's
	// credentials stop until a human renews the grant with presence: no
	// automatic retry can fix this.
	ReasonGrantExpired Reason = "grant_expired"

	// ReasonSpendCapExceeded: the Claude proxy's per-identity daily spend cap
	// was hit. Retryable: the cap resets at a known time with no human action
	// required. RetryAfter MUST carry the seconds until reset for this reason
	// specifically, because a retryable error with no backoff hint invites a
	// tight loop hammering the cap right back up against itself. Build this
	// reason with SpendCapExceeded (in lasterror.go), not New directly: it
	// makes the backoff hint a required parameter, so a call site that forgets
	// it fails to compile rather than producing a malformed record at runtime.
	ReasonSpendCapExceeded Reason = "spend_cap_exceeded"
)

// classification is the one table mapping every reason to retryable-or-
// terminal, so the fast-path exit code and the last-error JSON's "retryable"
// field can never disagree and can never be set independently at a call site.
var classification = map[Reason]bool{
	ReasonIssuerUnreachable:   true,
	ReasonPresenceDenied:      false,
	ReasonPresenceUnavailable: false,
	ReasonNotInCatalog:        false,
	ReasonSignatureMismatch:   false,
	ReasonOutOfGrantParked:    true,
	ReasonGrantExpired:        false,
	ReasonSpendCapExceeded:    true,
}

// Reasons returns the closed set of documented reason tokens, in declaration
// order, for tests and introspection (e.g. `totem doctor` listing what it
// checks).
func Reasons() []Reason {
	return []Reason{
		ReasonIssuerUnreachable,
		ReasonPresenceDenied,
		ReasonPresenceUnavailable,
		ReasonNotInCatalog,
		ReasonSignatureMismatch,
		ReasonOutOfGrantParked,
		ReasonGrantExpired,
		ReasonSpendCapExceeded,
	}
}

// Known reports whether r is one of the closed set of documented reason
// tokens.
func (r Reason) Known() bool {
	_, ok := classification[r]
	return ok
}

// Retryable reports whether a harness should back off and retry rather than
// treat the failure as terminal. An unrecognized reason (a bug, or a newer
// agent talking to an older harness) fails safe as terminal: an unknown
// failure must never cause a silent retry loop.
func (r Reason) Retryable() bool {
	return classification[r]
}

// ExitCode returns the process exit code a helper should use for r: the fast
// path a harness can branch on without parsing stderr.
func (r Reason) ExitCode() int {
	if r.Retryable() {
		return ExitRetryable
	}
	return ExitTerminal
}

// LastError is the machine-readable record written to LastErrorPath on a
// failed or parked exchange. Exit codes are the fast path; this file is the
// load-bearing contract, since aws/gh/git mostly swallow a credential helper's
// stderr.
type LastError struct {
	// Reason is one of the closed set of machine tokens above, e.g.
	// "issuer_unreachable".
	Reason Reason `json:"reason"`
	// Retryable is true when the harness should back off and retry rather than
	// treat the failure as terminal. Always derived from Reason.Retryable() —
	// use New (in lasterror.go) rather than constructing this by hand, so the
	// two can never disagree.
	Retryable bool `json:"retryable"`
	// RetryAfter is the suggested backoff in seconds before retrying.
	RetryAfter int `json:"retry_after,omitempty"`
	// ParkedID is set when an out-of-grant request was parked for a present
	// human to approve; the long-running agent polls this id across heartbeats
	// rather than blocking, and one parked task never freezes the others.
	ParkedID string `json:"parked_id,omitempty"`
	// Timestamp is when this record was written. A harness that cannot tell a
	// fresh error from a stale one will loop on a failure that was already
	// resolved, so freshness is explicit rather than inferred from mtime: see
	// Fresh.
	Timestamp time.Time `json:"timestamp"`
}

// Fresh reports whether e was written within maxAge of now. Callers pick
// maxAge from their own poll cadence (a heartbeat agent's tick, a shell
// prompt's hook) rather than a hardcoded global, because "stale" is relative to
// how often the reader looks.
func (e *LastError) Fresh(maxAge time.Duration) bool {
	return time.Since(e.Timestamp) <= maxAge
}
