package workloadapi

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/infamousjoeg/totem/internal/attest"
	"github.com/infamousjoeg/totem/internal/platform"
)

// TestEveryRefusalTellsAHuman guards the spec's rejection-UX rule as text, not
// just as a status code. Every message must be a sentence a person can act on,
// with no placeholders, no stack traces, and no SPIFFE vocabulary.
func TestEveryRefusalTellsAHuman(t *testing.T) {
	all := []error{
		attest.ErrNotInCatalog,
		attest.ErrSignatureMismatch,
		attest.ErrPIDReused,
		attest.ErrTooManyShellHops,
		attest.ErrInterpreterWrapped,
		attest.ErrUnsignedAtWritablePath,
		attest.ErrChainChanged,
		platform.ErrPresenceDenied,
		platform.ErrPresenceUnavailable,
		ErrIssuerUnreachable,
		ErrAttestorUnavailable,
		ErrSourceUnavailable,
		ErrNotEnrolled,
	}
	for _, err := range all {
		// Both with and without a resolved identity: attestation can fail
		// before a tool name exists, and the message has to work either way.
		for _, ident := range []*attest.Identity{nil, {Tool: "claude", Peer: attest.Peer{BinaryPath: "/opt/claude"}}} {
			st, ok := status.FromError(StatusFromError(err, ident))
			if !ok {
				t.Fatalf("%v did not become a gRPC status", err)
			}
			msg := st.Message()
			switch {
			case msg == "":
				t.Errorf("%v produced an empty message", err)
			case strings.Contains(msg, "<tool>"), strings.Contains(msg, "%!"), strings.Contains(msg, "<nil>"):
				t.Errorf("%v produced a message with a placeholder in it: %q", err, msg)
			case strings.Contains(strings.ToLower(msg), "spiffe"),
				strings.Contains(strings.ToLower(msg), "svid"),
				strings.Contains(strings.ToLower(msg), "attest"),
				strings.Contains(strings.ToLower(msg), "workload api"):
				t.Errorf("%v leaked spec vocabulary into user-facing text: %q", err, msg)
			case strings.Contains(msg, " - "), strings.Contains(msg, "—"):
				t.Errorf("%v used a dash where a sentence belongs: %q", err, msg)
			case !strings.Contains(msg, "."):
				t.Errorf("%v is not a sentence: %q", err, msg)
			}
			if st.Code() == codes.OK {
				t.Errorf("%v produced an OK status", err)
			}
		}
	}
}

// TestAttestErrorsGetDistinctCodes is the "distinct gRPC statuses" requirement:
// a harness must be able to branch on the code alone.
func TestAttestErrorsGetDistinctCodes(t *testing.T) {
	seen := map[codes.Code]error{}
	for _, err := range []error{
		attest.ErrNotInCatalog,
		attest.ErrSignatureMismatch,
		attest.ErrPIDReused,
		attest.ErrTooManyShellHops,
		attest.ErrInterpreterWrapped,
		attest.ErrUnsignedAtWritablePath,
		attest.ErrChainChanged,
	} {
		c := statusCodeFor(err)
		if prev, ok := seen[c]; ok {
			t.Errorf("%v and %v share code %v", err, prev, c)
		}
		seen[c] = err
	}
}

// TestWrappedErrorsStillClassify: attest may wrap its sentinels with context,
// and errors.Is has to keep working through that.
func TestWrappedErrorsStillClassify(t *testing.T) {
	wrapped := errors.Join(errors.New("resolving /usr/local/bin/thing"), attest.ErrNotInCatalog)
	if got := statusCodeFor(wrapped); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
	if got := reasonFor(wrapped); got != "not_in_catalog" {
		t.Errorf("reason = %q", got)
	}
}

func TestRetryableClassification(t *testing.T) {
	if !Retryable(ErrIssuerUnreachable) {
		t.Error("an unreachable issuer is retryable")
	}
	for _, err := range []error{attest.ErrNotInCatalog, attest.ErrInterpreterWrapped, platform.ErrPresenceDenied, ErrNotEnrolled} {
		if Retryable(err) {
			t.Errorf("%v must not be retryable", err)
		}
	}
}

// clientTerminalCodes are the status codes a go-spiffe workloadapi.Client
// treats as the END of a watch: handleWatchError returns immediately on these
// and backs off and reconnects on everything else.
//
// Measured against a real client rather than assumed from the names. Probing
// every code a stream might carry:
//
//	Canceled            watch loop terminated, no reconnect
//	InvalidArgument     watch loop terminated, no reconnect
//	Unavailable         reconnected
//	PermissionDenied    reconnected
//	Aborted             reconnected
//	FailedPrecondition  reconnected
//	OutOfRange          reconnected
//	Unauthenticated     reconnected
//	Unimplemented       reconnected
//
// Canceled is the trap, because it is the code whose NAME fits a lifecycle
// event best and whose BEHAVIOUR is the opposite of what a lifecycle event
// needs.
var clientTerminalCodes = map[codes.Code]bool{
	codes.Canceled:        true,
	codes.InvalidArgument: true,
}

// TestRetryableErrorsNeverStallTheClient is the invariant that keeps this
// class of bug from coming back: if totem says an error is retryable, the
// status it sends must be one the client will actually retry.
//
// Getting this wrong is silent in the worst way. The server logs a refusal
// that says "reconnect and carry on", the harness reads retryable and agrees,
// and the client has already torn the watch down for good, so an X509Source
// stops updating and nothing anywhere reports a problem until a credential
// expires.
func TestRetryableErrorsNeverStallTheClient(t *testing.T) {
	retryable := []error{
		ErrIssuerUnreachable,
		attest.ErrPIDReused,
		attest.ErrChainChanged,
	}
	for _, err := range retryable {
		if !Retryable(err) {
			t.Fatalf("%v is in the retryable list but Retryable says otherwise", err)
		}
		code := statusCodeFor(err)
		if clientTerminalCodes[code] {
			t.Errorf("%v is retryable but maps to %v, which a go-spiffe client treats as the end of the watch: "+
				"the stream dies for good and the source silently stops updating", err, code)
		}
	}
}

// TestOnlyDeliberateRefusalsUseTerminalCodes is the other direction. A code
// that stops the client reconnecting is a strong statement, so it belongs only
// where retrying genuinely cannot help.
func TestOnlyDeliberateRefusalsUseTerminalCodes(t *testing.T) {
	for _, err := range []error{
		attest.ErrNotInCatalog,
		attest.ErrSignatureMismatch,
		attest.ErrTooManyShellHops,
		attest.ErrInterpreterWrapped,
		attest.ErrUnsignedAtWritablePath,
		attest.ErrChainChanged,
		ErrIssuerUnreachable,
		ErrSourceUnavailable,
		ErrNotEnrolled,
	} {
		if clientTerminalCodes[statusCodeFor(err)] {
			t.Errorf("%v maps to %v, which permanently stops a client reconnecting; "+
				"that is only correct for a caller that must change something before it can ever succeed", err, statusCodeFor(err))
		}
	}
}

// TestStatusCarriesTheMachineReadableReason: status codes have to be chosen for
// what the client will DO with them, so several distinct refusals necessarily
// share one. The reason token in the status details is where the distinction
// survives, which is what lets a harness branch precisely without totem having
// to pick a code that would strand the caller.
func TestStatusCarriesTheMachineReadableReason(t *testing.T) {
	cases := []struct {
		err    error
		reason string
		retry  string
	}{
		{attest.ErrChainChanged, "CHAIN_CHANGED", "true"},
		{ErrIssuerUnreachable, "ISSUER_UNREACHABLE", "true"},
		{attest.ErrNotInCatalog, "NOT_IN_CATALOG", "false"},
	}
	for _, tc := range cases {
		st, ok := status.FromError(StatusFromError(tc.err, nil))
		if !ok {
			t.Fatalf("%v did not become a status", tc.err)
		}
		var info *errdetails.ErrorInfo
		for _, d := range st.Details() {
			if ei, is := d.(*errdetails.ErrorInfo); is {
				info = ei
			}
		}
		if info == nil {
			t.Errorf("%v carries no machine-readable reason", tc.err)
			continue
		}
		if info.GetReason() != tc.reason {
			t.Errorf("%v reason = %q, want %q", tc.err, info.GetReason(), tc.reason)
		}
		if info.GetDomain() != ErrorDomain {
			t.Errorf("%v domain = %q, want %q", tc.err, info.GetDomain(), ErrorDomain)
		}
		if got := info.GetMetadata()["retryable"]; got != tc.retry {
			t.Errorf("%v retryable = %q, want %q", tc.err, got, tc.retry)
		}
	}

	// Two errors sharing a code must still be told apart by their reason.
	chain, _ := status.FromError(StatusFromError(attest.ErrChainChanged, nil))
	issuer, _ := status.FromError(StatusFromError(ErrIssuerUnreachable, nil))
	if chain.Code() != issuer.Code() {
		t.Skip("these no longer share a code, so there is nothing to disambiguate")
	}
	if reasonOf(t, chain) == reasonOf(t, issuer) {
		t.Error("two different refusals share a code AND a reason; nothing can tell them apart")
	}
}

func reasonOf(t *testing.T, st *status.Status) string {
	t.Helper()
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.GetReason()
		}
	}
	return ""
}
