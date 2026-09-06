package errors

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// withHome points $HOME at a fresh temp directory for the duration of the
// test, so Write/Read exercise the real "~" resolution path without touching
// the developer's actual ~/.totem.
func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// TestWriteCreatesDirectoryAndPermissions covers "resolve ~ at runtime, create
// the directory if needed, write 0600" from the brief, end to end.
func TestWriteCreatesDirectoryAndPermissions(t *testing.T) {
	home := withHome(t)

	e := New(ReasonIssuerUnreachable, WithRetryAfter(30))
	if err := Write(e); err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := filepath.Join(home, ".totem", "last-error")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("last-error mode = %#o, want 0600", mode)
	}

	dirInfo, err := os.Stat(filepath.Join(home, ".totem"))
	if err != nil {
		t.Fatalf("stat ~/.totem: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("~/.totem is not a directory")
	}
}

// TestWriteLeavesNoTempFilesBehind covers the "temp file in the same directory
// then rename" requirement: after a successful Write, nothing but the final
// file should remain in ~/.totem.
func TestWriteLeavesNoTempFilesBehind(t *testing.T) {
	home := withHome(t)

	if err := Write(New(ReasonGrantExpired)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(home, ".totem"))
	if err != nil {
		t.Fatalf("read ~/.totem: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "last-error" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("~/.totem contains %v, want exactly [last-error]", names)
	}
}

// TestWriteAndReadRoundTripEveryReason covers "round-trip every reason" from
// the brief.
func TestWriteAndReadRoundTripEveryReason(t *testing.T) {
	withHome(t)

	for _, reason := range Reasons() {
		reason := reason
		t.Run(string(reason), func(t *testing.T) {
			want := New(reason, WithRetryAfter(42), WithParkedID("parked-123"))
			if err := Write(want); err != nil {
				t.Fatalf("Write: %v", err)
			}

			got, err := Read()
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got.Reason != want.Reason {
				t.Errorf("Reason = %q, want %q", got.Reason, want.Reason)
			}
			if got.Retryable != want.Retryable {
				t.Errorf("Retryable = %v, want %v", got.Retryable, want.Retryable)
			}
			if got.RetryAfter != want.RetryAfter {
				t.Errorf("RetryAfter = %d, want %d", got.RetryAfter, want.RetryAfter)
			}
			if got.ParkedID != want.ParkedID {
				t.Errorf("ParkedID = %q, want %q", got.ParkedID, want.ParkedID)
			}
			if got.Timestamp.IsZero() {
				t.Errorf("Timestamp is zero, want stamped")
			}
		})
	}
}

// TestReadNotExist covers the harness's half of the contract: no helper has
// ever failed yet, and Read must say so via a wrapped os.ErrNotExist rather
// than some ad hoc sentinel.
func TestReadNotExist(t *testing.T) {
	withHome(t)

	_, err := Read()
	if err == nil {
		t.Fatal("Read() = nil error, want os.ErrNotExist on a fresh home")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read() error = %v, want it to satisfy errors.Is(err, os.ErrNotExist)", err)
	}
}

// TestNewStampsRetryableFromTable guards against New ever being able to
// disagree with the classification table: Retryable is always derived, never
// set independently. New never panics (see New's doc comment), so this calls
// it uniformly across every reason with no special-casing required.
func TestNewStampsRetryableFromTable(t *testing.T) {
	for _, reason := range Reasons() {
		e := New(reason)
		if e.Retryable != reason.Retryable() {
			t.Errorf("New(%s).Retryable = %v, want %v", reason, e.Retryable, reason.Retryable())
		}
		if e.Timestamp.IsZero() {
			t.Errorf("New(%s).Timestamp is zero, want stamped", reason)
		}
	}
}

// TestWriteNeverPersistsARetryableRecordWithoutABackoffHint is the property
// the durability boundary enforces, checked generically rather than as a
// hand-enumerated case list so it keeps holding when a ninth reason is added
// to the closed set: for every reason, built the plainest possible way (no
// options at all) and written, the record that actually lands on disk must
// never say "retryable" with RetryAfter <= 0 — because that shape is exactly
// what invites a harness to spin a tight loop against whatever it's retrying,
// whether the retryable reason is a network blip, a parked step-up, or a
// spend cap.
func TestWriteNeverPersistsARetryableRecordWithoutABackoffHint(t *testing.T) {
	withHome(t)

	for _, reason := range Reasons() {
		reason := reason
		t.Run(string(reason), func(t *testing.T) {
			if err := Write(New(reason)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := Read()
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got.Retryable && got.RetryAfter <= 0 {
				t.Fatalf("reason %s is retryable but the record on disk has RetryAfter = %d; "+
					"every retryable record Write persists must carry a positive backoff hint",
					reason, got.RetryAfter)
			}
		})
	}
}

// TestWriteAppliesTheDocumentedPerReasonFloor pins the specific floor values
// in retryFloors (as literals, not by reading the map back) so an accidental
// change to those numbers shows up as a failing test rather than silently
// shipping a different backoff.
func TestWriteAppliesTheDocumentedPerReasonFloor(t *testing.T) {
	withHome(t)

	cases := []struct {
		reason Reason
		want   int
	}{
		{ReasonIssuerUnreachable, 5},
		{ReasonOutOfGrantParked, 300},
		{ReasonSpendCapExceeded, 60},
	}
	for _, c := range cases {
		t.Run(string(c.reason), func(t *testing.T) {
			if err := Write(New(c.reason)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := Read()
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got.RetryAfter != c.want {
				t.Fatalf("RetryAfter = %d, want the documented floor %d", got.RetryAfter, c.want)
			}
		})
	}
}

// TestWriteFallsBackToGenericFloorForAnUnmappedRetryableReason covers "reason
// nine": a hypothetical future retryable reason with no tuned entry in
// retryFloors must still get some positive backoff from Write, not zero. This
// deliberately builds the LastError by hand rather than through New/a real
// Reason constant, since retryFloors already covers every reason in the
// current closed set.
func TestWriteFallsBackToGenericFloorForAnUnmappedRetryableReason(t *testing.T) {
	withHome(t)

	unmapped := Reason("hypothetical_future_reason_not_yet_in_retryFloors")
	if err := Write(LastError{Reason: unmapped, Retryable: true}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.RetryAfter != genericRetryFloor {
		t.Fatalf("RetryAfter = %d, want genericRetryFloor %d", got.RetryAfter, genericRetryFloor)
	}
}

// TestWriteDoesNotOverrideAnExplicitPositiveRetryAfter guards the other
// direction: Write's floor must only kick in when RetryAfter is missing, never
// silently override a caller's real, positive value.
func TestWriteDoesNotOverrideAnExplicitPositiveRetryAfter(t *testing.T) {
	withHome(t)

	if err := Write(New(ReasonIssuerUnreachable, WithRetryAfter(9999))); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.RetryAfter != 9999 {
		t.Fatalf("RetryAfter = %d, want the explicit 9999 untouched", got.RetryAfter)
	}
}

// TestNewNeverPanicsEvenForSpendCapExceededWithoutRetryAfter pins the "New
// never panics" guarantee for exactly the case that used to panic: this
// package is the error-reporting path, and crashing here would destroy the
// ~/.totem/last-error record at the moment it matters most. SpendCapExceeded
// is the constructor real call sites should use (it makes the backoff hint a
// required, compiling-time-enforced parameter); this test documents that
// calling New directly with the "wrong" shape still degrades safely rather
// than crashing.
func TestNewNeverPanicsEvenForSpendCapExceededWithoutRetryAfter(t *testing.T) {
	var e LastError
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("New(ReasonSpendCapExceeded) without WithRetryAfter panicked: %v", r)
			}
		}()
		e = New(ReasonSpendCapExceeded)
	}()
	if e.Reason != ReasonSpendCapExceeded {
		t.Fatalf("Reason = %q, want %q", e.Reason, ReasonSpendCapExceeded)
	}
	if !e.Retryable {
		t.Fatal("Retryable = false, want true")
	}
}

// TestSpendCapExceededSetsRetryAfter covers the intended, compile-enforced
// path: retryAfterSeconds is a required positional parameter, so a call site
// cannot omit it and still build.
func TestSpendCapExceededSetsRetryAfter(t *testing.T) {
	e := SpendCapExceeded(3600)
	if e.Reason != ReasonSpendCapExceeded {
		t.Fatalf("Reason = %q, want %q", e.Reason, ReasonSpendCapExceeded)
	}
	if !e.Retryable {
		t.Fatal("Retryable = false, want true")
	}
	if e.RetryAfter != 3600 {
		t.Fatalf("RetryAfter = %d, want 3600", e.RetryAfter)
	}
}

// TestSpendCapExceededClampsNonPositiveRetryAfter covers the floor: a caller
// whose own reset-time arithmetic underflows to <= 0 must still get a valid,
// non-panicking record with a sane backoff, not a crash and not a useless
// "retry immediately" hint.
func TestSpendCapExceededClampsNonPositiveRetryAfter(t *testing.T) {
	for _, given := range []int{0, -1, -3600} {
		e := SpendCapExceeded(given)
		if e.RetryAfter != minSpendCapRetryAfterSeconds {
			t.Errorf("SpendCapExceeded(%d).RetryAfter = %d, want the floor %d", given, e.RetryAfter, minSpendCapRetryAfterSeconds)
		}
		if !e.Retryable {
			t.Errorf("SpendCapExceeded(%d).Retryable = false, want true", given)
		}
	}
}

// TestFailSpendCapExceededNeverPanicsAndWrites covers FailSpendCapExceeded end
// to end: it writes a valid record and returns the retryable exit code, and
// never panics even when given a non-positive retryAfterSeconds.
func TestFailSpendCapExceededNeverPanicsAndWrites(t *testing.T) {
	withHome(t)

	var code int
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("FailSpendCapExceeded panicked: %v", r)
			}
		}()
		code, err = FailSpendCapExceeded(0)
	}()
	if err != nil {
		t.Fatalf("FailSpendCapExceeded: %v", err)
	}
	if code != ExitRetryable {
		t.Fatalf("FailSpendCapExceeded code = %d, want ExitRetryable", code)
	}

	got, err := Read()
	if err != nil {
		t.Fatalf("Read after FailSpendCapExceeded: %v", err)
	}
	if got.Reason != ReasonSpendCapExceeded {
		t.Fatalf("Reason = %q, want %q", got.Reason, ReasonSpendCapExceeded)
	}
	if got.RetryAfter != minSpendCapRetryAfterSeconds {
		t.Fatalf("RetryAfter = %d, want the floor %d", got.RetryAfter, minSpendCapRetryAfterSeconds)
	}
}

// TestFailReturnsClassifiedExitCode covers the fast path end to end: Fail
// writes the record and returns the same exit code Reason.ExitCode() would.
func TestFailReturnsClassifiedExitCode(t *testing.T) {
	withHome(t)

	code, err := Fail(ReasonOutOfGrantParked, WithParkedID("abc"))
	if err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if code != ExitRetryable {
		t.Fatalf("Fail(ReasonOutOfGrantParked) code = %d, want ExitRetryable (parking must never look terminal)", code)
	}

	got, err := Read()
	if err != nil {
		t.Fatalf("Read after Fail: %v", err)
	}
	if got.ParkedID != "abc" {
		t.Fatalf("ParkedID = %q, want %q", got.ParkedID, "abc")
	}

	code, err = Fail(ReasonSignatureMismatch)
	if err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if code != ExitTerminal {
		t.Fatalf("Fail(ReasonSignatureMismatch) code = %d, want ExitTerminal", code)
	}
}

// TestFresh covers the freshness contract: a harness must be able to tell a
// current failure from a stale one so it does not loop on an already-resolved
// error.
func TestFresh(t *testing.T) {
	cases := []struct {
		name string
		age  time.Duration
		max  time.Duration
		want bool
	}{
		{"well within window", time.Second, time.Minute, true},
		// A tiny margin (not an exact tie) keeps this from being flaky: real
		// wall-clock time elapses between stamping Timestamp and calling Fresh.
		{"just inside the window", 59 * time.Second, time.Minute, true},
		{"just outside the window", 61 * time.Second, time.Minute, false},
		{"an hour old against a minute window", time.Hour, time.Minute, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := LastError{Timestamp: time.Now().Add(-c.age)}
			if got := e.Fresh(c.max); got != c.want {
				t.Errorf("Fresh(%s) with age %s = %v, want %v", c.max, c.age, got, c.want)
			}
		})
	}
}

// TestWriteConcurrentReadsSeeOnlyCompleteRecords is the real atomicity test:
// one goroutine writes continuously while others read continuously, and every
// successful read must parse as a complete, valid record -- never a truncated
// or partially-written one. This is what "write ATOMICALLY... so a harness
// never reads a half-written record" actually buys, and it is only meaningful
// under -race with concurrent readers and writers, not a single-threaded
// round-trip.
func TestWriteConcurrentReadsSeeOnlyCompleteRecords(t *testing.T) {
	home := withHome(t)
	path := filepath.Join(home, ".totem", "last-error")

	const iterations = 200
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			e := New(Reasons()[i%len(Reasons())], WithRetryAfter(i))
			if err := Write(e); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
		}
	}()

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				data, err := os.ReadFile(path)
				if err != nil {
					// Not-yet-created is fine at the very start; anything else
					// (including a torn read) is not.
					if os.IsNotExist(err) {
						continue
					}
					t.Errorf("ReadFile: %v", err)
					return
				}
				var e LastError
				if err := json.Unmarshal(data, &e); err != nil {
					t.Errorf("unmarshal produced invalid JSON, meaning Write is not atomic: %v (data: %q)", err, data)
					return
				}
				if !e.Reason.Known() {
					t.Errorf("read a record with an unknown reason %q, meaning Write is not atomic", e.Reason)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(stop)
	readerWG.Wait()
}
