package errors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Option adjusts a LastError built by New.
type Option func(*LastError)

// WithRetryAfter sets the suggested backoff, in seconds, before a retryable
// failure should be retried.
func WithRetryAfter(seconds int) Option {
	return func(e *LastError) { e.RetryAfter = seconds }
}

// WithParkedID marks e as a parked request an agent can poll later, rather
// than a plain failure. Parking must never look like a terminal failure, so
// pass a Reason (ReasonOutOfGrantParked) that classifies as retryable
// alongside this option.
func WithParkedID(id string) Option {
	return func(e *LastError) { e.ParkedID = id }
}

// New builds a LastError for reason, stamping Retryable from the closed
// classification table and Timestamp from the current time, so a call site can
// never set Retryable inconsistently with its Reason and can never forget to
// make freshness explicit. New never panics: this package is the error-
// reporting path, called at the moment something has already gone wrong, and
// its whole job is to get a valid record onto disk and an exit code back to
// main — crashing here destroys the load-bearing signal (~/.totem/last-error)
// at exactly the moment it matters most, and hands the human a Go stack trace
// instead of the plain-language error docs/totem-design.md's Experience
// section calls for.
//
// For ReasonSpendCapExceeded specifically, prefer the dedicated SpendCapExceeded
// constructor over calling New directly: it makes the backoff hint a required
// parameter, so a call site that forgets it fails to compile rather than
// silently producing a retryable error with no backoff hint (which invites a
// caller to spin a tight loop hammering the cap right back up).
func New(reason Reason, opts ...Option) LastError {
	e := LastError{
		Reason:    reason,
		Retryable: reason.Retryable(),
		Timestamp: time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

// minSpendCapRetryAfterSeconds is the floor SpendCapExceeded clamps to when
// given a non-positive retryAfterSeconds. It is a guard against an obviously
// wrong value (a caller's reset-time arithmetic underflowed to zero or
// negative), not a substitute for computing the real reset time: a slightly
// wrong backoff is recoverable, a missing error record is not, so this floor
// exists to keep SpendCapExceeded panic-free rather than to be relied on.
const minSpendCapRetryAfterSeconds = 60

// SpendCapExceeded builds the ReasonSpendCapExceeded LastError and is the only
// constructor for that reason: unlike New, retryAfterSeconds is a required
// positional parameter, not an optional WithRetryAfter, so a call site (the
// Claude proxy's spend-cap check, in particular) that forgets the backoff hint
// fails to compile instead of failing at runtime in this package's one job of
// never failing. If retryAfterSeconds is <= 0, it is clamped to
// minSpendCapRetryAfterSeconds and still recorded — SpendCapExceeded never
// panics, for the same reason New never does.
func SpendCapExceeded(retryAfterSeconds int, opts ...Option) LastError {
	if retryAfterSeconds <= 0 {
		retryAfterSeconds = minSpendCapRetryAfterSeconds
	}
	return New(ReasonSpendCapExceeded, append([]Option{WithRetryAfter(retryAfterSeconds)}, opts...)...)
}

// retryFloors names the minimum RetryAfter, in seconds, Write enforces for a
// retryable record that reaches it with none set. This is the durability-
// boundary half of the invariant: New is deliberately still generic
// (deserialization and round-trip tests both construct a LastError plainly),
// so New(ReasonSpendCapExceeded) with no options is a legitimate way to get a
// zero-value RetryAfter into a live *LastError before it ever reaches Write.
// SpendCapExceeded's own clamp catches that at construction for its one
// reason; this map is the backstop that holds no matter which constructor was
// used, and it also covers the two other retryable reasons — issuer_unreachable
// and out_of_grant_parked — that nothing was guarding before this existed.
//
// Floors differ deliberately rather than sharing one constant, because the
// retry shapes differ:
//   - issuer_unreachable wants a short initial backoff before totem run's own
//     exponential backoff takes over — this is the coffee-shop network blip,
//     not a wait for a scheduled reset.
//   - out_of_grant_parked is resumed on the agent's next heartbeat tick, not
//     retried tightly, so its floor is heartbeat-cadence-sized rather than a
//     short backoff.
//   - spend_cap_exceeded resets at a known wall-clock time; SpendCapExceeded
//     computes a real value in the common path, so genericRetryFloor (below)
//     only guards a caller whose arithmetic underflowed.
//
// PLACEHOLDER values: none of these are measured yet against real totem run
// backoff behavior or a real agent heartbeat interval. Tune the numbers here
// when those exist; the enforcement point (Write) should not need to change.
var retryFloors = map[Reason]int{
	ReasonIssuerUnreachable: 5,
	ReasonOutOfGrantParked:  300,
	ReasonSpendCapExceeded:  minSpendCapRetryAfterSeconds,
}

// genericRetryFloor is used for any retryable reason with no entry in
// retryFloors — most importantly, a reason added to the closed set in the
// future without also adding a tuned floor here. It exists so that gap fails
// safe (some backoff) rather than reintroducing the RetryAfter=0 invitation to
// a tight loop that this whole mechanism is closing.
const genericRetryFloor = 30

// resolvePath expands a leading "~" against the current user's home directory,
// resolved at runtime (never baked in), and returns the absolute path.
func resolvePath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("errors: resolve home directory: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
	}
	return path, nil
}

// Write atomically persists e to LastErrorPath as 0600 JSON: it resolves "~" at
// runtime, creates ~/.totem if needed, writes to a temp file in the same
// directory, and renames it over the target. The rename is what makes this
// atomic — a harness reading LastErrorPath by stat-then-read never observes a
// half-written record, because the file at that path is either the old
// complete record or the new complete one, never a partial write of either.
//
// If e.Timestamp is zero it is stamped with the current time, so a caller can
// never write a record a reader would treat as immediately stale.
//
// Write also enforces, for every retryable record regardless of which
// constructor produced it, that RetryAfter is positive: if e.Retryable is true
// and e.RetryAfter is <= 0, it is set from retryFloors (or genericRetryFloor
// for a reason with no entry there) before the record is persisted. This is
// deliberately not done in New — New is a generic constructor and silently
// rewriting a caller's explicit field there would be its own surprise — but a
// retryable record with no backoff hint must never actually reach disk,
// because that is precisely the shape that invites a harness to spin a tight
// loop against whatever it's retrying. Enforcing it here, at the point a
// record becomes durable, closes every construction path at once rather than
// trusting each one individually.
func Write(e LastError) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Retryable && e.RetryAfter <= 0 {
		if floor, ok := retryFloors[e.Reason]; ok {
			e.RetryAfter = floor
		} else {
			e.RetryAfter = genericRetryFloor
		}
	}

	path, err := resolvePath(LastErrorPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("errors: create %s: %w", dir, err)
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("errors: marshal last-error: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".last-error-*.tmp")
	if err != nil {
		return fmt.Errorf("errors: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Clean up the temp file on any failure path; once Rename succeeds there is
	// nothing left at tmpPath to remove, and the Remove below is a silent no-op.
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("errors: write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("errors: chmod %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("errors: close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("errors: rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}

// Fail writes reason's LastError record to LastErrorPath and returns the exit
// code a helper's main() should os.Exit with, so a single call site both
// satisfies the load-bearing file contract and the fast-path exit code. On a
// write failure it still returns ExitTerminal (never silently ExitOK) along
// with the write error, since a helper that cannot record why it failed must
// not report success.
//
// Fail never panics, under any circumstance. It is typically the last thing
// that runs before the process exits, and a panic here would trade a legible
// error and a working exit-code contract for a bare Go stack trace at the CLI
// boundary — the opposite of what docs/totem-design.md's Experience section
// asks for. For ReasonSpendCapExceeded, use FailSpendCapExceeded instead of
// calling Fail directly, for the same reason SpendCapExceeded exists.
func Fail(reason Reason, opts ...Option) (int, error) {
	e := New(reason, opts...)
	if err := Write(e); err != nil {
		return ExitTerminal, err
	}
	return reason.ExitCode(), nil
}

// FailSpendCapExceeded mirrors Fail for ReasonSpendCapExceeded specifically:
// it builds the record with SpendCapExceeded, so retryAfterSeconds is a
// required parameter a real call site (the Claude proxy's spend-cap check)
// cannot forget and still compile, writes it, and returns the exit code. Like
// Fail, it never panics.
func FailSpendCapExceeded(retryAfterSeconds int, opts ...Option) (int, error) {
	e := SpendCapExceeded(retryAfterSeconds, opts...)
	if err := Write(e); err != nil {
		return ExitTerminal, err
	}
	return e.Reason.ExitCode(), nil
}

// Read loads the current LastError record from LastErrorPath. It returns an
// error satisfying errors.Is(err, os.ErrNotExist) when no helper has ever
// failed — the harness's half of the contract: a known path it can stat and
// parse without depending on the calling tool forwarding stderr.
func Read() (*LastError, error) {
	path, err := resolvePath(LastErrorPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e LastError
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("errors: parse %s: %w", path, err)
	}
	return &e, nil
}
