// Package errors defines the typed exit codes and the ~/.totem/last-error JSON
// schema that let a calling harness tell retryable from terminal. Because
// calling tools swallow helper stderr, the file is the contract and the exit
// code is the fast path. Scaffold only: types and doc comments, no writer yet.
package errors

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

// LastError is the machine-readable record written to LastErrorPath on a failed
// or parked exchange. It carries reason, retryable, retry_after, and parked_id;
// exit codes are the fast path and this file is the contract.
type LastError struct {
	// Reason is a short machine token for the failure, e.g. "issuer_unreachable".
	Reason string `json:"reason"`
	// Retryable is true when the harness should back off and retry rather than
	// treat the failure as terminal.
	Retryable bool `json:"retryable"`
	// RetryAfter is the suggested backoff in seconds before retrying.
	RetryAfter int `json:"retry_after,omitempty"`
	// ParkedID is set when an out-of-grant request was parked for a present
	// human to approve; the long-running agent polls this id across heartbeats
	// rather than blocking, and one boundary never freezes the other tasks.
	ParkedID string `json:"parked_id,omitempty"`
}
