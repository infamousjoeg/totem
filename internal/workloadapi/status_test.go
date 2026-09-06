package workloadapi

import (
	"errors"
	"strings"
	"testing"

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
