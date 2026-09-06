package errors

import "testing"

// TestReasonsTableIsClosed guards the spec requirement that reason tokens are
// "a closed, documented set of machine constants... not free text", mapped to
// retryable-or-terminal "in one table so the classification cannot drift
// between call sites". If someone adds a Reason constant without adding it to
// Reasons() and classification, this test catches the drift.
func TestReasonsTableIsClosed(t *testing.T) {
	reasons := Reasons()
	if len(reasons) != len(classification) {
		t.Fatalf("Reasons() has %d entries but classification has %d; every constant must appear in both",
			len(reasons), len(classification))
	}
	seen := make(map[Reason]bool, len(reasons))
	for _, r := range reasons {
		if seen[r] {
			t.Fatalf("Reasons() lists %q more than once", r)
		}
		seen[r] = true
		if !r.Known() {
			t.Fatalf("Reasons() lists %q but classification has no entry for it", r)
		}
	}
}

// TestRetryableClassification pins down the exact table from the brief: fast
// path (exit code) and load-bearing path (last-error JSON) must agree on every
// reason, and this is the one place that agreement is asserted.
func TestRetryableClassification(t *testing.T) {
	cases := []struct {
		reason    Reason
		retryable bool
	}{
		{ReasonIssuerUnreachable, true},
		{ReasonPresenceDenied, false},
		{ReasonPresenceUnavailable, false},
		{ReasonNotInCatalog, false},
		{ReasonSignatureMismatch, false},
		{ReasonOutOfGrantParked, true},
		{ReasonGrantExpired, false},
		{ReasonSpendCapExceeded, true},
	}
	if len(cases) != len(Reasons()) {
		t.Fatalf("test table has %d cases but Reasons() has %d; keep this table in sync with the closed set",
			len(cases), len(Reasons()))
	}
	for _, c := range cases {
		if got := c.reason.Retryable(); got != c.retryable {
			t.Errorf("%s.Retryable() = %v, want %v", c.reason, got, c.retryable)
		}

		wantCode := ExitTerminal
		if c.retryable {
			wantCode = ExitRetryable
		}
		if got := c.reason.ExitCode(); got != wantCode {
			t.Errorf("%s.ExitCode() = %d, want %d", c.reason, got, wantCode)
		}
	}
}

// TestUnknownReasonFailsSafeAsTerminal: an unrecognized token (a bug, or a
// newer agent talking to an older harness) must never be treated as retryable,
// or an unknown failure becomes a silent retry loop.
func TestUnknownReasonFailsSafeAsTerminal(t *testing.T) {
	unknown := Reason("something_nobody_documented")
	if unknown.Known() {
		t.Fatalf("Reason(%q).Known() = true, want false", unknown)
	}
	if unknown.Retryable() {
		t.Fatalf("Reason(%q).Retryable() = true, want false (fail safe as terminal)", unknown)
	}
	if got := unknown.ExitCode(); got != ExitTerminal {
		t.Fatalf("Reason(%q).ExitCode() = %d, want ExitTerminal", unknown, got)
	}
}

// TestExitCodesAreDistinct guards the "fast path: distinct nonzero exit codes"
// requirement directly: OK, terminal, and retryable must all differ.
func TestExitCodesAreDistinct(t *testing.T) {
	codes := map[int]string{
		ExitOK:        "ExitOK",
		ExitTerminal:  "ExitTerminal",
		ExitRetryable: "ExitRetryable",
	}
	if len(codes) != 3 {
		t.Fatalf("exit codes are not pairwise distinct: ExitOK=%d ExitTerminal=%d ExitRetryable=%d",
			ExitOK, ExitTerminal, ExitRetryable)
	}
}
