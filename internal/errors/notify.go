package errors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// notifyTimeout bounds how long a native notification call is allowed to run.
// The spec is explicit: a refused exchange or pending presence prompt "also
// fires a native notification", but "never fail an exchange because a
// notification could not be shown, and never block on one" — so the call is
// always time-boxed and its result never propagates as an error to the caller.
const notifyTimeout = 3 * time.Second

// LogFunc receives the one-line fallback message when no native notification
// could be shown. The default writes to stderr; a caller with the real
// structured `totem log` writer should pass its own.
type LogFunc func(line string)

func defaultLog(line string) {
	fmt.Fprintln(os.Stderr, line)
}

// hasGUISession is a fast, best-effort pre-check for whether a native
// notification stands a chance of being seen, overridable in tests. On Linux
// over SSH — the spec's example headless case — DISPLAY and WAYLAND_DISPLAY
// are reliably absent, so that is a solid signal. On macOS there is no
// equivalent cheap signal (a launchd daemon with no logged-in GUI user still
// has these unset or set), so darwin optimistically returns true and leaves
// the real test to the notification call itself: an osascript failure there
// still falls through to the log fallback in Notify, so a wrong guess here
// never causes a lost notification to look like success.
var hasGUISession = func() bool {
	switch runtime.GOOS {
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "darwin":
		return true
	default:
		return false
	}
}

// notifyFunc performs the OS-specific native notification call. It is a
// package variable so tests can stub it without shelling out to osascript or
// notify-send.
var notifyFunc = defaultNotify

func defaultNotify(ctx context.Context, title, message string) error {
	switch runtime.GOOS {
	case "darwin":
		return notifyDarwin(ctx, title, message)
	case "linux":
		return notifyLinux(ctx, title, message)
	default:
		return fmt.Errorf("errors: no native notification path on %s", runtime.GOOS)
	}
}

// notifyDarwin shows a macOS notification center banner via osascript. cgo and
// the UserNotifications framework are the eventual richer path, but shelling
// out to the system-installed osascript needs no build tag and no linking.
func notifyDarwin(ctx context.Context, title, message string) error {
	script := fmt.Sprintf("display notification %s with title %s", quoteAppleScript(message), quoteAppleScript(title))
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("osascript: %w: %s", err, out)
	}
	return nil
}

// quoteAppleScript wraps s in AppleScript double quotes, escaping the two
// characters that would otherwise break out of the literal.
func quoteAppleScript(s string) string {
	escaped := ""
	for _, r := range s {
		switch r {
		case '"', '\\':
			escaped += `\` + string(r)
		default:
			escaped += string(r)
		}
	}
	return `"` + escaped + `"`
}

// notifyLinux shows a desktop notification via notify-send, the de facto
// standard on Linux desktops (GNOME, KDE, and everything that implements the
// freedesktop notification spec).
func notifyLinux(ctx context.Context, title, message string) error {
	path, err := exec.LookPath("notify-send")
	if err != nil {
		return fmt.Errorf("errors: notify-send not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, path, title, message)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("notify-send: %w: %s", err, out)
	}
	return nil
}

// Notify shows title/message as a native, user-visible notification (macOS
// notification center, notify-send on Linux). If there is no GUI session to
// show it in, or the native call fails or times out for any reason, Notify
// falls back to logFn (or stderr if nil) and returns — the caller's exchange
// must never fail, and must never block, because a notification could not be
// shown.
func Notify(ctx context.Context, title, message string, logFn LogFunc) {
	if logFn == nil {
		logFn = defaultLog
	}

	if !hasGUISession() {
		logFn(fallbackLine(title, message, "no GUI session"))
		return
	}

	notifyCtx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	if err := notifyFunc(notifyCtx, title, message); err != nil {
		logFn(fallbackLine(title, message, err.Error()))
	}
}

func fallbackLine(title, message, reason string) string {
	return fmt.Sprintf("totem notify (headless fallback, %s): %s: %s", reason, title, message)
}

// NotifyParked shows (or logs the fallback for) the "an agent parked a request
// and needs your presence" notification the spec calls for in the agent
// delegation step-up flow.
func NotifyParked(ctx context.Context, agent, parkedID string, logFn LogFunc) {
	Notify(ctx, "totem: presence needed",
		fmt.Sprintf("%s parked a request (id %s) and needs your presence", agent, parkedID),
		logFn)
}

// NotifyGrantExpiring shows (or logs the fallback for) the "your grant expires
// in 3 days" notification the spec calls for ahead of a delegated grant's
// expiry.
func NotifyGrantExpiring(ctx context.Context, agent string, expires time.Time, logFn LogFunc) {
	Notify(ctx, "totem: grant expiring",
		fmt.Sprintf("%s's grant expires %s", agent, expires.Format(time.RFC3339)),
		logFn)
}
