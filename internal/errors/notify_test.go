package errors

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stubNotify installs replacement hasGUISession/notifyFunc for the duration of
// the test and restores the originals afterward, so these tests never shell
// out to the real osascript/notify-send.
func stubNotify(t *testing.T, gui bool, notify func(ctx context.Context, title, message string) error) {
	t.Helper()
	origGUI, origNotify := hasGUISession, notifyFunc
	hasGUISession = func() bool { return gui }
	notifyFunc = notify
	t.Cleanup(func() {
		hasGUISession = origGUI
		notifyFunc = origNotify
	})
}

// TestNotifyUsesNativeWhenGUIPresent covers the non-headless path: with a GUI
// session and a working native call, the log fallback must not fire.
func TestNotifyUsesNativeWhenGUIPresent(t *testing.T) {
	var called bool
	stubNotify(t, true, func(ctx context.Context, title, message string) error {
		called = true
		if title == "" || message == "" {
			t.Errorf("notifyFunc called with empty title or message: %q / %q", title, message)
		}
		return nil
	})

	var logged []string
	Notify(context.Background(), "totem: presence needed", "claude parked a request", func(line string) {
		logged = append(logged, line)
	})

	if !called {
		t.Error("notifyFunc was not called even though a GUI session was reported")
	}
	if len(logged) != 0 {
		t.Errorf("log fallback fired on a successful native notification: %v", logged)
	}
}

// TestNotifyFallsBackWhenNoGUISession covers the headless case named directly
// in the brief: "write to the structured log and exit cleanly" when there is
// no GUI session, without ever attempting the native call.
func TestNotifyFallsBackWhenNoGUISession(t *testing.T) {
	var nativeCalled bool
	stubNotify(t, false, func(ctx context.Context, title, message string) error {
		nativeCalled = true
		return nil
	})

	var logged []string
	Notify(context.Background(), "totem: grant expiring", "bot's grant expires soon", func(line string) {
		logged = append(logged, line)
	})

	if nativeCalled {
		t.Error("notifyFunc was called despite no GUI session being reported")
	}
	if len(logged) != 1 {
		t.Fatalf("log fallback fired %d times, want 1", len(logged))
	}
	if !strings.Contains(logged[0], "grant expires soon") {
		t.Errorf("fallback line %q does not contain the message", logged[0])
	}
}

// TestNotifyFallsBackWhenNativeCallErrors covers "never fail an exchange
// because a notification could not be shown": a GUI session was reported but
// the native call itself failed (e.g. osascript not authorized), and Notify
// must still fall back to the log rather than surfacing the error to the
// caller (Notify returns nothing to fail with, by design).
func TestNotifyFallsBackWhenNativeCallErrors(t *testing.T) {
	stubNotify(t, true, func(ctx context.Context, title, message string) error {
		return errors.New("boom: no window server")
	})

	var logged []string
	Notify(context.Background(), "title", "message", func(line string) {
		logged = append(logged, line)
	})

	if len(logged) != 1 {
		t.Fatalf("log fallback fired %d times, want 1", len(logged))
	}
	if !strings.Contains(logged[0], "boom: no window server") {
		t.Errorf("fallback line %q does not include the native error", logged[0])
	}
}

// TestNotifyNeverBlocksPastTimeout covers "never block on one": a native call
// that ignores its context and hangs must not be allowed to hang Notify past
// notifyTimeout.
func TestNotifyNeverBlocksPastTimeout(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	stubNotify(t, true, func(ctx context.Context, title, message string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-block:
			return nil
		}
	})

	done := make(chan struct{})
	go func() {
		Notify(context.Background(), "title", "message", func(string) {})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(notifyTimeout + 2*time.Second):
		t.Fatal("Notify did not return within notifyTimeout + margin; it is blocking on a hung native call")
	}
}

// TestNotifyDefaultsLogFuncToSomething covers the nil-logFn convenience path
// so callers are not forced to pass a no-op.
func TestNotifyDefaultsLogFuncToSomething(t *testing.T) {
	stubNotify(t, false, func(ctx context.Context, title, message string) error { return nil })

	// Must not panic with a nil logFn.
	Notify(context.Background(), "title", "message", nil)
}

// TestNotifyParkedAndGrantExpiringMessageContent covers the two concrete
// notifications named in the brief: "an agent parked a request and needs your
// presence" and "your grant expires in 3 days".
func TestNotifyParkedAndGrantExpiringMessageContent(t *testing.T) {
	stubNotify(t, false, func(ctx context.Context, title, message string) error { return nil })

	var logged []string
	logFn := func(line string) { logged = append(logged, line) }

	NotifyParked(context.Background(), "dinner-planner", "parked-42", logFn)
	NotifyGrantExpiring(context.Background(), "dinner-planner", time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), logFn)

	if len(logged) != 2 {
		t.Fatalf("got %d log lines, want 2", len(logged))
	}
	if !strings.Contains(logged[0], "dinner-planner") || !strings.Contains(logged[0], "parked-42") || !strings.Contains(logged[0], "presence") {
		t.Errorf("NotifyParked line missing expected content: %q", logged[0])
	}
	if !strings.Contains(logged[1], "dinner-planner") || !strings.Contains(logged[1], "expires") {
		t.Errorf("NotifyGrantExpiring line missing expected content: %q", logged[1])
	}
}
