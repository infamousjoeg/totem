package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/infamousjoeg/totem/internal/ca"
	toterrors "github.com/infamousjoeg/totem/internal/errors"
	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
)

// docs/totem-design.md "Experience": "Errors are typed for machines and plain
// for humans", and no stack trace ever crosses a boundary a person reads.
//
// The shape of an error response here was chosen against what the CLIENT
// ACTUALLY DOES with it, measured in cmd/totem rather than inferred from the
// status name. Two measurements decided it:
//
//   - httpIssuerClient.post reads the response body and prints
//     firstLine(body) verbatim inside "your issuer refused this request (%s)".
//     So the FIRST LINE of the body is user-facing prose, not JSON. An issuer
//     that answers with a JSON object shows the person a brace and a key name
//     at the exact moment they need a sentence. The machine-readable half
//     therefore lives in HEADERS, where it cannot pollute what the human reads.
//   - That same client treats EVERY non-2xx status as terminal and retries
//     none of them; only a transport failure becomes the retryable error. So no
//     status code this issuer picks makes the current agent retry. The
//     Totem-Error-Reason and Retry-After headers are still set, because a
//     harness reading ~/.totem/last-error is the thing that needs them, and
//     because an issuer that says "come back in thirty seconds" in a way
//     nothing can read is an issuer that fails silently. This is a real gap on
//     the agent side and is called out in the handover rather than worked
//     around here.

// ErrorReasonHeader carries the machine token from internal/errors' closed set.
const ErrorReasonHeader = "Totem-Error-Reason"

// apiError is one front-door failure: a plain sentence, the next action, the
// status, and the machine token when the closed set has one.
type apiError struct {
	status     int
	reason     toterrors.Reason
	retryAfter int
	what       string
	fix        string
	cause      error
}

func (e *apiError) Error() string { return e.what }
func (e *apiError) Unwrap() error { return e.cause }

// badRequest is the common malformed-input failure.
func badRequest(fix, format string, args ...any) *apiError {
	return &apiError{status: http.StatusBadRequest, what: fmt.Sprintf(format, args...), fix: fix}
}

// writeError renders a failure. The body's first line is the sentence a person
// reads; everything a machine needs is in headers.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	e := classify(err)
	if e.reason.Known() {
		w.Header().Set(ErrorReasonHeader, string(e.reason))
	}
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retryAfter))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(e.status)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	line := e.what
	if e.fix != "" {
		line = strings.TrimSpace(e.what) + " " + strings.TrimSpace(e.fix)
	}
	// One line. The client prints firstLine(body), so a newline in the middle
	// of the sentence is a sentence the person only half reads.
	_, _ = fmt.Fprintln(w, RedactBootstrap(oneLine(line)))
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// classify maps every typed error the issuer raises onto a response. It is one
// switch on purpose: a status chosen at a call site drifts from the status
// chosen at the next one, and a caller cannot branch on a distinction the
// issuer does not make consistently.
func classify(err error) *apiError {
	var e *apiError
	if errors.As(err, &e) {
		if e.status == 0 {
			e.status = http.StatusInternalServerError
		}
		return e
	}
	switch {
	// Enrollment: the device sent something this issuer cannot verify.
	case errors.Is(err, presence.ErrEnrollmentMalformed), errors.Is(err, presence.ErrMalformed):
		return &apiError{status: http.StatusBadRequest, cause: err,
			what: "this device's enrollment was not in a shape the issuer could read.",
			fix:  "Run 'totem enroll' again with the command your issuer operator gave you."}
	case errors.Is(err, presence.ErrUnsupportedVersion):
		return &apiError{status: http.StatusConflict, cause: err,
			what: "this device signed its enrollment in a format the issuer does not understand.",
			fix:  "Upgrade totem, or ask your issuer operator to upgrade the issuer."}
	case errors.Is(err, presence.ErrEnrollmentKeyUnsupported), errors.Is(err, presence.ErrUnsupportedPresenceKey):
		return &apiError{status: http.StatusBadRequest, cause: err,
			what: "this device's key is not one totem uses (it must be ECDSA P-256).",
			fix:  "Run 'totem doctor' on that device."}
	case errors.Is(err, presence.ErrEnrollmentBadSignature), errors.Is(err, presence.ErrBadSignature):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "this device's enrollment did not verify.",
			fix:  "Run 'totem enroll' again. If it keeps failing, tell your issuer operator."}
	case errors.Is(err, presence.ErrEnrollmentNeedsPresence), errors.Is(err, presence.ErrEnrollmentUnexpectedPresence):
		return &apiError{status: http.StatusBadRequest, cause: err,
			what: "this device sent a confirmation that does not match how it is set up.",
			fix:  "Run 'totem doctor' on that device, then enroll again."}
	case errors.Is(err, presence.ErrEnrollmentChallengeSplit):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "the two halves of this enrollment did not come from the same attempt.",
			fix:  "Run 'totem enroll' again, and do not run two enrollments at once."}
	// Challenges. Replayed and expired are TERMINAL for the challenge that was
	// presented and RETRYABLE for the operation: the fix is a new challenge,
	// which is a new enroll run, so the message says that rather than
	// suggesting a bare retry that would fail identically.
	case errors.Is(err, presence.ErrUnknownChallenge), errors.Is(err, presence.ErrChallengeReplayed):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "that request used a one-time value the issuer had already seen.",
			fix:  "Run 'totem enroll' again to start a fresh one."}
	case errors.Is(err, presence.ErrChallengeExpired):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "that request took too long, so the issuer expired it.",
			fix:  "Run 'totem enroll' again and approve the prompt within a minute."}
	case errors.Is(err, presence.ErrTooManyChallenges):
		return &apiError{status: http.StatusTooManyRequests, retryAfter: 30, cause: err,
			what: "this device has too many unanswered requests with the issuer right now.",
			fix:  "Wait half a minute and try again. If it keeps happening, run 'totem status' to see what is asking."}
	// Presence.
	case errors.Is(err, presence.ErrNoPresenceKey), errors.Is(err, policy.ErrPresenceRequired):
		return &apiError{status: http.StatusForbidden, reason: toterrors.ReasonPresenceUnavailable, cause: err,
			what: "this action needs a device that can confirm a person is present, and that one cannot.",
			fix:  "Do it from a device with Touch ID, a TPM PIN, or a security key."}
	case errors.Is(err, presence.ErrPresenceConsumed):
		return &apiError{status: http.StatusForbidden, reason: toterrors.ReasonPresenceDenied, cause: err,
			what: "that confirmation had already been used for something else.",
			fix:  "Run the command again and approve the new prompt."}
	case errors.Is(err, presence.ErrDeviceMismatch), errors.Is(err, presence.ErrToolMismatch),
		errors.Is(err, presence.ErrTargetMismatch), errors.Is(err, presence.ErrRequestHashMismatch),
		errors.Is(err, presence.ErrRequestHashRequired), errors.Is(err, presence.ErrRequestHashUnexpected):
		return &apiError{status: http.StatusForbidden, reason: toterrors.ReasonPresenceDenied, cause: err,
			what: "the confirmation did not match what was being asked for.",
			fix:  "Run the command again, and check the code in the prompt matches the one your terminal printed."}
	// Policy: enrollment, admin, revocation.
	case errors.Is(err, policy.ErrBootstrapInvalid):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "that setup code is not one this issuer is waiting for, or it has expired.",
			fix:  "On the issuer, run 'totem-issuer recover' for a new one."}
	case errors.Is(err, policy.ErrIssuerFingerprint):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "this device pinned a certificate that is not this issuer's, so something answered in between.",
			fix:  "Do not continue. Ask your issuer operator to send you the enroll command again."}
	case errors.Is(err, policy.ErrAlreadyEnrolled):
		return &apiError{status: http.StatusConflict, cause: err,
			what: "this device is already enrolled with this issuer.",
			fix:  "Run 'totem status' on it. To start over, run 'totem uninstall' first."}
	case errors.Is(err, policy.ErrPendingNotFound):
		return &apiError{status: http.StatusNotFound, cause: err,
			what: "there is no device waiting with that code.",
			fix:  "Check the code, or ask the person enrolling to run 'totem enroll' again."}
	case errors.Is(err, policy.ErrPendingExpired):
		return &apiError{status: http.StatusGone, cause: err,
			what: "that approval code has expired.",
			fix:  "Ask the person enrolling to run 'totem enroll' again."}
	case errors.Is(err, policy.ErrNotAdmin):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "only a device marked as an administrator can do that.",
			fix:  "Run it from an administrator device. 'totem devices' shows which ones are."}
	case errors.Is(err, policy.ErrLastAdmin):
		return &apiError{status: http.StatusConflict, cause: err,
			what: "that is the last administrator device, so the issuer will not remove it.",
			fix:  "Make another device an administrator first, with 'totem devices grant-admin'."}
	case errors.Is(err, policy.ErrNotEnrolled), errors.Is(err, policy.ErrDeviceNotFound):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "the issuer does not know that device.",
			fix:  "Enroll it, or run 'totem devices' to see what the issuer does know."}
	case errors.Is(err, policy.ErrDeviceRevoked):
		return &apiError{status: http.StatusForbidden, cause: err,
			what: "that device was revoked.",
			fix:  "Enroll it again if that was not intended."}
	case errors.Is(err, policy.ErrUnsigned), errors.Is(err, policy.ErrWrongSigningShape):
		return &apiError{status: http.StatusBadRequest, cause: err,
			what: "that change did not arrive signed the way the issuer requires.",
			fix:  "Run the command from an enrolled device rather than by hand."}
	case errors.Is(err, policy.ErrCredential):
		return &apiError{status: http.StatusUnauthorized, cause: err,
			what: "the identity presented is not one this issuer recognises.",
			fix:  "Run 'totem status' on that device; it may need to enroll again."}
	// CA states that are "not now" rather than "no".
	case errors.Is(err, ca.ErrNoSigningIntermediate), errors.Is(err, ca.ErrRootOffline):
		return &apiError{status: http.StatusServiceUnavailable, retryAfter: 300,
			reason: toterrors.ReasonIssuerUnreachable, cause: err,
			what: "this issuer cannot sign anything right now.",
			fix:  "Ask your issuer operator to rotate the issuer's intermediate certificate."}
	case errors.Is(err, ca.ErrNotInitialized):
		return &apiError{status: http.StatusServiceUnavailable, retryAfter: 60,
			reason: toterrors.ReasonIssuerUnreachable, cause: err,
			what: "this issuer has not finished being set up.",
			fix:  "Ask your issuer operator to run 'totem-issuer init'."}
	case errors.Is(err, store.ErrChainBroken):
		return &apiError{status: http.StatusServiceUnavailable, cause: err,
			what: "this issuer's records failed their own integrity check, so it refused to answer.",
			fix:  "Tell your issuer operator immediately. Do not restart it; the log is evidence."}
	case errors.Is(err, store.ErrNotFound):
		return &apiError{status: http.StatusNotFound, cause: err,
			what: "the issuer has no record of that.",
			fix:  "Check the identifier and try again."}
	}
	return &apiError{status: http.StatusInternalServerError, cause: err,
		what: "the issuer could not complete that request.",
		fix:  "Ask your issuer operator to check the issuer log for this device."}
}
