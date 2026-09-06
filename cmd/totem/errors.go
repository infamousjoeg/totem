package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/infamousjoeg/totem/internal/attest"
	toterrors "github.com/infamousjoeg/totem/internal/errors"
	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// docs/totem-design.md "Experience": errors are typed for machines and plain
// for humans. Calling tools rarely forward a helper's stderr, so
// ~/.totem/last-error is the contract and the exit code is the fast path. A
// long-running agent harness rides out a coffee-shop network blip by branching
// on the exit code and that file; it cannot parse the calling tool's prose.
//
// internal/errors owns both the closed set of machine reasons and the writer.
// A CLI failure that has no token in that closed set (a mistyped issuer link,
// say) is still reported plainly to the human and still exits terminal, but it
// writes no machine record: inventing a token outside the closed set would give
// a harness something it cannot classify, which is worse than silence on a
// failure no harness retries.

// cliError is a failure with everything a person and a harness both need: one
// plain sentence of what happened, one of what to do next, and, when the
// failure is one the machine contract covers, its reason token. No stack trace
// ever crosses the CLI boundary.
type cliError struct {
	// reason is the machine token, or empty when this failure is outside the
	// closed set internal/errors defines.
	reason toterrors.Reason
	// retryAfter is the suggested backoff in seconds, for retryable reasons.
	retryAfter int
	// parkedID is set when a request was parked for a human rather than
	// refused.
	parkedID string
	// what is the one plain sentence a human reads.
	what string
	// fix is the exact next action.
	fix string
	// cause is kept for --verbose and for errors.Is, never printed raw.
	cause error
}

func (e *cliError) Error() string { return e.what }
func (e *cliError) Unwrap() error { return e.cause }

// failf builds a failure that has no machine reason token: it is terminal, and
// it is reported to the human only. A harness never retries a mistyped issuer
// link or a missing argument, so there is nothing here for it to branch on.
func failf(fix, format string, args ...any) *cliError {
	return &cliError{what: fmt.Sprintf(format, args...), fix: fix}
}

// reasonedf builds a failure carrying one of the closed machine reasons, so a
// harness can branch on the exit code and ~/.totem/last-error.
func reasonedf(reason toterrors.Reason, fix, format string, args ...any) *cliError {
	return &cliError{reason: reason, what: fmt.Sprintf(format, args...), fix: fix}
}

// asCLIError turns any error into the shape the CLI reports, classifying the
// typed errors the rest of totem raises so the exit code, the last-error file,
// and the printed text can never disagree.
func asCLIError(err error) *cliError {
	if err == nil {
		return nil
	}
	var ce *cliError
	if errors.As(err, &ce) {
		return ce
	}
	switch {
	case errors.Is(err, workloadapi.ErrIssuerUnreachable):
		return &cliError{reason: toterrors.ReasonIssuerUnreachable, retryAfter: 30, what: err.Error(),
			fix: "Check your network, then run 'totem doctor'. It checks your issuer first."}
	case errors.Is(err, platform.ErrPresenceDenied):
		return &cliError{reason: toterrors.ReasonPresenceDenied, what: "the confirmation was declined or timed out.",
			fix: "Run the command again and approve the prompt within 60 seconds."}
	case errors.Is(err, platform.ErrPresenceUnavailable):
		return &cliError{reason: toterrors.ReasonPresenceUnavailable, what: "this device cannot confirm a person is present.",
			fix: "Use a device that can, or ask your issuer operator to relax this target."}
	case errors.Is(err, attest.ErrNotInCatalog):
		return &cliError{reason: toterrors.ReasonNotInCatalog, what: "that program is not one totem issues identity to.",
			fix: "Run 'totem status' to see which programs totem is set up for."}
	case errors.Is(err, attest.ErrSignatureMismatch):
		return &cliError{reason: toterrors.ReasonSignatureMismatch, what: "that program is not the one totem pinned.",
			fix: "If you just updated it, run 'totem trust <tool>'. If you did not, do not re-pin it."}
	case errors.Is(err, workloadapi.ErrNoState):
		return &cliError{what: "this device is not set up with an issuer yet.",
			fix: "Run the 'totem enroll' command your issuer operator gave you."}
	}
	return &cliError{what: err.Error(), fix: "Run 'totem doctor' to check this machine."}
}

// report prints a failure the way docs/totem-design.md "Experience" requires,
// records it where a harness can find it when the machine contract covers it,
// and returns the exit code: 75 for retryable, 1 for terminal, 0 for success.
func report(err error) int {
	ce := asCLIError(err)
	if ce == nil {
		clearLastError()
		return toterrors.ExitOK
	}
	fmt.Fprintln(os.Stderr, "totem: "+ce.what)
	if ce.fix != "" {
		fmt.Fprintln(os.Stderr, "  "+ce.fix)
	}
	if !ce.reason.Known() {
		return toterrors.ExitTerminal
	}

	var opts []toterrors.Option
	if ce.retryAfter > 0 {
		opts = append(opts, toterrors.WithRetryAfter(ce.retryAfter))
	}
	if ce.parkedID != "" {
		opts = append(opts, toterrors.WithParkedID(ce.parkedID))
	}
	code, werr := toterrors.Fail(ce.reason, opts...)
	if werr != nil {
		fmt.Fprintf(os.Stderr, "  (totem could not write %s, so a harness will not see this: %v)\n", toterrors.LastErrorPath, werr)
	}
	return code
}

// clearLastError removes the machine record after a successful run, so a
// harness reading it never acts on a failure that has since been resolved.
// internal/errors also stamps every record with a timestamp, so a reader that
// misses this still has Fresh() to fall back on.
func clearLastError() { _ = os.Remove(expandHome(toterrors.LastErrorPath)) }
