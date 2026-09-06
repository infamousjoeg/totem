package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The bootstrap code is the highest-privilege value totem ever prints:
// redeeming it makes a device the founding ADMIN, and only admin devices can
// approve enrollments. docs/totem-design.md "Issuer (broker box)" states the
// whole rule in one sentence: "`issuer init` prints a one-time bootstrap code
// (to the terminal if stdout is a TTY, otherwise to a 0600 file, never to
// structured logs; ten-minute expiry, redemption logged with the device
// fingerprint)."
//
// Each clause of that sentence is a separate failure it prevents:
//
//   - TTY or a 0600 file, and nothing in between. `totem-issuer init` inside a
//     container, under systemd, or in a CI job has its stdout captured by
//     something that keeps it: a journal, a log aggregator, a build artifact. A
//     code printed there is a code an attacker reads later from a place nobody
//     thinks of as secret. Detecting the TTY is what decides which of the two
//     paths is safe, so it is a check on the actual file, never a flag the
//     caller passes.
//   - Never to structured logs. The audit log is the one stream this issuer is
//     built to ship off the box (stdout, "with optional syslog or OTLP
//     export"), so it is exactly where the code must never appear. The Event
//     type in audit.go has no field that could carry it, and the redemption
//     event carries the DEVICE FINGERPRINT instead: the thing that says which
//     device used the code without saying what the code was.
//   - Ten minutes. Long enough to paste one command onto a laptop, short enough
//     that a code left on a terminal over lunch has already expired.

// BootstrapCodeTTL is the ten-minute expiry.
const BootstrapCodeTTL = 10 * time.Minute

// BootstrapCodeFile is the name of the 0600 file the code goes to when stdout
// is not a terminal.
const BootstrapCodeFile = "bootstrap-code"

// BootstrapDestination says where a bootstrap code was delivered.
type BootstrapDestination struct {
	// Terminal is true when the code went to the operator's terminal and
	// nowhere else, which is the only path that leaves no copy behind.
	Terminal bool
	// Path is the 0600 file the code was written to when Terminal is false.
	Path string
	// ExpiresAt is when the code stops working.
	ExpiresAt time.Time
}

// String is the line the operator reads. It never contains the code.
func (d BootstrapDestination) String() string {
	if d.Terminal {
		return fmt.Sprintf("The command above is good until %s.", d.ExpiresAt.Local().Format(time.Kitchen))
	}
	return fmt.Sprintf("stdout is not a terminal, so the enroll command was written to %s (readable only by you). It is good until %s.",
		d.Path, d.ExpiresAt.Local().Format(time.Kitchen))
}

// ErrBootstrapSink means the code could not be delivered anywhere safe. It is
// fatal at init: an issuer that generated a founding-admin code and then lost
// it is an issuer nobody can enroll against, and the honest outcome is to say
// so rather than to fall back to printing it somewhere it should not be.
var ErrBootstrapSink = errors.New("server: could not deliver the bootstrap code anywhere safe")

// EmitBootstrap delivers text (the whole enroll command, code included) to the
// terminal when stdout is one, and otherwise to a 0600 file under dir.
//
// stdout is the actual file rather than an io.Writer so the terminal check is a
// property of where the bytes are really going. A caller that hands in a buffer
// gets the file path, which is the safe direction to be wrong in.
func EmitBootstrap(stdout *os.File, dir, text string, expiresAt time.Time) (BootstrapDestination, error) {
	d := BootstrapDestination{ExpiresAt: expiresAt}
	if isTerminal(stdout) {
		if _, err := io.WriteString(stdout, text+"\n"); err != nil {
			return d, fmt.Errorf("%w: %w", ErrBootstrapSink, err)
		}
		d.Terminal = true
		return d, nil
	}
	if dir == "" {
		return d, fmt.Errorf("%w: stdout is not a terminal and no directory was given for the 0600 file", ErrBootstrapSink)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return d, fmt.Errorf("%w: %w", ErrBootstrapSink, err)
	}
	path := filepath.Join(dir, BootstrapCodeFile)
	// Remove first, then create exclusively at 0600. Truncating an existing
	// file would keep whatever mode and owner it already had, which is how a
	// file an attacker pre-created with mode 0666 ends up holding the code.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return d, fmt.Errorf("%w: %w", ErrBootstrapSink, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return d, fmt.Errorf("%w: %w", ErrBootstrapSink, err)
	}
	body := text + "\n\nThis code expires at " + expiresAt.Local().Format(time.RFC1123) + ".\nDelete this file once the first device is enrolled.\n"
	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		return d, fmt.Errorf("%w: %w", ErrBootstrapSink, err)
	}
	if err := f.Close(); err != nil {
		return d, fmt.Errorf("%w: %w", ErrBootstrapSink, err)
	}
	d.Path = path
	return d, nil
}

// isTerminal reports whether f is a character device, which is what a terminal
// is and what a pipe, a file, a socket, and a journal are not.
//
// It stats the real file rather than consulting an environment variable or a
// flag, because the question being asked is "will these bytes be kept
// somewhere", and only the file itself answers that.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// RedactBootstrap is the last line of defence for anything that formats an
// error or a status line containing an enroll command. It replaces the value
// after --code so a code cannot ride out through a message that was never
// meant to carry one.
//
// It is deliberately not the primary control. The primary control is that the
// code is never passed to the audit log at all; this exists because "never
// passed" is a property of today's call sites and this is a property of the
// string.
func RedactBootstrap(s string) string {
	const flag = "--code "
	i := strings.Index(s, flag)
	if i < 0 {
		return s
	}
	rest := s[i+len(flag):]
	end := strings.IndexAny(rest, " \t\n")
	if end < 0 {
		return s[:i+len(flag)] + "[redacted]"
	}
	return s[:i+len(flag)] + "[redacted]" + rest[end:]
}
