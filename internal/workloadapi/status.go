package workloadapi

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/infamousjoeg/totem/internal/attest"
	"github.com/infamousjoeg/totem/internal/platform"
)

// The spec's rejection-UX rule: refusals are never silent and never a bare
// permission error. Each typed attestation failure gets its own gRPC code so a
// harness can branch on it, and its own message so a human reading the calling
// tool's output knows what to do next. No SPIFFE vocabulary appears in any of
// these strings; they are the same words docs/totem-design.md "Experience"
// requires of every user-facing surface.
//
//	attest.ErrNotInCatalog       -> PermissionDenied  (the boring default-deny)
//	attest.ErrSignatureMismatch  -> FailedPrecondition (re-pin, deliberately)
//	attest.ErrPIDReused          -> Aborted            (racy, retry is correct)
//	attest.ErrTooManyShellHops   -> OutOfRange         (one hop is the range)
//	attest.ErrInterpreterWrapped -> Unimplemented      (permanent by design)
//	attest.ErrUnsignedAtWritablePath -> Unauthenticated (no credential of its own)
//	ErrIssuerUnreachable         -> Unavailable        (retryable, not terminal)
//	platform.ErrPresenceDenied   -> PermissionDenied   (human said no)
func statusCodeFor(err error) codes.Code {
	switch {
	case errors.Is(err, attest.ErrNotInCatalog):
		return codes.PermissionDenied
	case errors.Is(err, attest.ErrSignatureMismatch):
		return codes.FailedPrecondition
	case errors.Is(err, attest.ErrPIDReused):
		return codes.Aborted
	case errors.Is(err, attest.ErrTooManyShellHops):
		return codes.OutOfRange
	case errors.Is(err, attest.ErrInterpreterWrapped):
		return codes.Unimplemented
	case errors.Is(err, attest.ErrUnsignedAtWritablePath):
		// Unauthenticated rather than PermissionDenied: the caller is not
		// being refused a permission it might otherwise have, it has failed to
		// present anything totem can authenticate it by at all.
		return codes.Unauthenticated
	case errors.Is(err, platform.ErrPresenceDenied):
		return codes.PermissionDenied
	case errors.Is(err, platform.ErrPresenceUnavailable):
		return codes.FailedPrecondition
	case errors.Is(err, ErrIssuerUnreachable), errors.Is(err, ErrAttestorUnavailable), errors.Is(err, ErrSourceUnavailable):
		return codes.Unavailable
	case errors.Is(err, ErrNotEnrolled), errors.Is(err, ErrNoTrustDomain), errors.Is(err, ErrNoDeviceID):
		return codes.FailedPrecondition
	case errors.Is(err, ErrNotUnixConn):
		return codes.Internal
	case errors.Is(err, context.Canceled):
		return codes.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return codes.DeadlineExceeded
	default:
		return codes.Internal
	}
}

// reasonFor is the short machine token recorded in the local log and in
// ~/.totem/last-error. A harness branches on this; a human never reads it.
func reasonFor(err error) string {
	switch {
	case errors.Is(err, attest.ErrNotInCatalog):
		return "not_in_catalog"
	case errors.Is(err, attest.ErrSignatureMismatch):
		return "signature_mismatch"
	case errors.Is(err, attest.ErrPIDReused):
		return "pid_reused"
	case errors.Is(err, attest.ErrTooManyShellHops):
		return "too_many_shell_hops"
	case errors.Is(err, attest.ErrInterpreterWrapped):
		return "interpreter_wrapped"
	case errors.Is(err, attest.ErrUnsignedAtWritablePath):
		return "unsigned_at_writable_path"
	case errors.Is(err, platform.ErrPresenceDenied):
		return "presence_denied"
	case errors.Is(err, platform.ErrPresenceUnavailable):
		return "presence_unavailable"
	case errors.Is(err, ErrIssuerUnreachable):
		return "issuer_unreachable"
	case errors.Is(err, ErrAttestorUnavailable):
		return "attestor_unavailable"
	case errors.Is(err, ErrSourceUnavailable):
		return "issuer_not_configured"
	case errors.Is(err, ErrNotEnrolled), errors.Is(err, ErrNoTrustDomain), errors.Is(err, ErrNoDeviceID):
		return "not_enrolled"
	case err == nil:
		return ""
	default:
		return "internal_error"
	}
}

// Retryable reports whether a harness should back off and try again rather than
// treat the failure as terminal. It is the same split internal/errors encodes
// as ExitRetryable versus ExitTerminal, kept in one place so the exit code, the
// last-error file, and the gRPC status can never disagree.
func Retryable(err error) bool {
	switch {
	case errors.Is(err, ErrIssuerUnreachable), errors.Is(err, attest.ErrPIDReused):
		return true
	default:
		return false
	}
}

// humanRefusal is the sentence a developer sees. It names what happened in
// plain words. ident may be nil when attestation failed before a tool was
// resolved.
func humanRefusal(err error, ident *attest.Identity) string {
	who := "the program that called totem"
	if ident != nil && ident.Tool != "" {
		who = ident.Tool
	}
	switch {
	case errors.Is(err, attest.ErrNotInCatalog):
		return "totem has no identity for " + who + ": it is not one of the programs totem issues credentials to."
	case errors.Is(err, attest.ErrSignatureMismatch):
		if ident == nil {
			return "the program that called totem is not the one totem pinned under that name."
		}
		return "the program at " + binaryOf(ident) + " is not the one totem pinned for " + who + "."
	case errors.Is(err, attest.ErrPIDReused):
		return "the calling process exited while totem was checking it, so nothing was issued."
	case errors.Is(err, attest.ErrTooManyShellHops):
		return who + " reached totem through more than one shell, so totem cannot tell what actually asked."
	case errors.Is(err, attest.ErrInterpreterWrapped):
		return who + " runs as a script under an interpreter, which any program running as you can rewrite, so totem will not identify it."
	case errors.Is(err, attest.ErrUnsignedAtWritablePath):
		return who + " carries no signature totem can trace back to its maker, and it sits somewhere any program running as you could replace it, so totem has no way to know it is still the program you installed."
	case errors.Is(err, platform.ErrPresenceDenied):
		return "the confirmation prompt for " + who + " was declined or timed out."
	case errors.Is(err, platform.ErrPresenceUnavailable):
		return "this device has no way to confirm a person is present, and this target requires one."
	case errors.Is(err, ErrIssuerUnreachable):
		return "totem could not reach your issuer, so it has nothing to hand " + who + "."
	case errors.Is(err, ErrAttestorUnavailable):
		return "this build of totem has no way to identify callers, so it issued nothing."
	case errors.Is(err, ErrSourceUnavailable):
		return "totem is not connected to an issuer yet, so it has no credentials to hand out."
	case errors.Is(err, ErrNotEnrolled), errors.Is(err, ErrNoTrustDomain), errors.Is(err, ErrNoDeviceID):
		return "this device is not enrolled with an issuer yet."
	default:
		return "totem could not complete this request."
	}
}

// fixFor is the exact next action. docs/totem-design.md "Experience": an error
// tells the human what to do next.
func fixFor(err error, ident *attest.Identity) string {
	// When attestation failed before a tool was resolved there is no name to
	// put in the sentence, and a literal placeholder in text a developer reads
	// is worse than a slightly more general instruction.
	tool, named := "that program", false
	if ident != nil && ident.Tool != "" {
		tool, named = ident.Tool, true
	}
	trustCmd := "'totem trust'"
	if named {
		trustCmd = "'totem trust " + tool + "'"
	}
	switch {
	case errors.Is(err, attest.ErrNotInCatalog):
		return "Run 'totem status' to see which programs totem is set up for, and 'totem doctor' to check this machine."
	case errors.Is(err, attest.ErrSignatureMismatch):
		return "If you just updated " + tool + ", run " + trustCmd + " to see the old and new version and confirm it. If you did not update it, do not confirm it: run 'totem log' and check what changed."
	case errors.Is(err, attest.ErrPIDReused):
		return "Run the command again."
	case errors.Is(err, attest.ErrTooManyShellHops):
		return "Call the helper directly instead of through a wrapper script. 'totem doctor' prints the chain totem walked."
	case errors.Is(err, attest.ErrInterpreterWrapped):
		return "Install the native build of " + tool + " and run 'totem init' again. There is no flag that turns this off."
	case errors.Is(err, attest.ErrUnsignedAtWritablePath):
		return "Install the build " + tool + "'s maker signs, or put it somewhere only an administrator can write to, then run 'totem init' again. A locally built or ad-hoc signed copy cannot be identified and there is no flag that turns this off."
	case errors.Is(err, platform.ErrPresenceDenied):
		return "Run the command again and approve the prompt within 60 seconds."
	case errors.Is(err, platform.ErrPresenceUnavailable):
		return "Use a device that can confirm you are present, or ask your issuer operator to relax this target."
	case errors.Is(err, ErrIssuerUnreachable):
		return "Check your network, then run 'totem doctor'. It reports your issuer address and when totem last reached it."
	case errors.Is(err, ErrAttestorUnavailable), errors.Is(err, ErrSourceUnavailable):
		return "Run 'totem doctor' to see what this build is missing."
	case errors.Is(err, ErrNotEnrolled), errors.Is(err, ErrNoTrustDomain), errors.Is(err, ErrNoDeviceID):
		return "Run the 'totem enroll' command your issuer operator gave you."
	default:
		return "Run 'totem log' for the local record of what happened."
	}
}

// binaryOf renders the caller's binary path, or a placeholder when attestation
// never got far enough to resolve one.
func binaryOf(ident *attest.Identity) string {
	if ident != nil && ident.Peer.BinaryPath != "" {
		return ident.Peer.BinaryPath
	}
	return "the calling program"
}

// StatusFromError turns any refusal into the gRPC status a calling tool will
// print. The message is one sentence of what happened plus one sentence of what
// to do, because calling tools rarely forward anything richer.
func StatusFromError(err error, ident *attest.Identity) error {
	if err == nil {
		return nil
	}
	parts := []string{humanRefusal(err, ident)}
	if fix := fixFor(err, ident); fix != "" {
		parts = append(parts, fix)
	}
	return status.Error(statusCodeFor(err), strings.Join(parts, " "))
}
