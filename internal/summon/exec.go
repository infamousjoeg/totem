package summon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

// MaxValueSize bounds what a provider may return. It is far larger than any
// secret totem holds (the largest is a PEM-encoded GitHub App key) and exists
// so a provider that starts streaming cannot fill the issuer's locked memory.
const MaxValueSize = 64 << 10

// maxStderrCapture bounds what is kept from a failing provider's stderr for
// the error message.
const maxStderrCapture = 4 << 10

// waitDelay is how long Wait lingers after the process is killed before giving
// up on its pipes. A provider that spawned a child holding stdout open must
// not be able to block a resolve forever.
const waitDelay = 2 * time.Second

// runProvider execs the configured Summon provider for ref and returns the
// value in mlocked memory.
//
// The exec is the protocol: the reference is the single argument, the value is
// stdout, diagnostics are stderr, and a non-zero exit is a failure. Around it:
// a clean environment with a fixed PATH, no stdin, a working directory of "/",
// its own process group so a hung provider's children die with it, and a
// timeout after which it is killed rather than waited on.
//
// The reference has already been validated by the caller. Validation happens
// before the reference becomes argv, never after.
func (s *Summoner) runProvider(ctx context.Context, ref Reference) (*secret, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.cfg.Provider.Path, string(ref))
	// A clean environment: the fixed PATH and nothing else. There is no
	// environment variable the issuer reads, and none it passes on.
	cmd.Env = []string{"PATH=" + FixedPATH}
	cmd.Dir = "/"
	cmd.Stdin = nil
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: maxStderrCapture}
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = waitDelay

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("summon: provider stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("summon: starting provider %s: %w", s.cfg.Provider.Path, err)
	}

	// The value is read straight into locked memory. One byte of headroom
	// beyond the limit is how an oversized value is detected without ever
	// buffering it on the heap.
	sec, err := newSecret(MaxValueSize + 1)
	if err != nil {
		_ = cmd.Cancel()
		_ = cmd.Wait()
		return nil, err
	}
	n, readErr := readAll(stdout, sec.buf)
	waitErr := cmd.Wait()

	if waitErr != nil {
		sec.discard()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("summon: provider %s did not return within %s for %q", s.cfg.Provider.Path, s.timeout, ref)
		}
		return nil, fmt.Errorf("summon: provider %s failed for %q: %w%s", s.cfg.Provider.Path, ref, waitErr, stderrSuffix(stderr.String()))
	}
	if readErr != nil {
		sec.discard()
		return nil, fmt.Errorf("summon: reading the value for %q: %w", ref, readErr)
	}
	if n > MaxValueSize {
		sec.discard()
		return nil, errValueTooLarge(ref)
	}
	if n == 0 {
		sec.discard()
		return nil, fmt.Errorf("summon: provider %s returned an empty value for %q", s.cfg.Provider.Path, ref)
	}
	sec.setLen(n)
	return sec, nil
}

// readAll fills buf from r and reports how many bytes arrived. It stops at
// len(buf); the caller sizes buf one byte past the limit so a full buffer
// means the value was too large.
func readAll(r io.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}

// limitedWriter keeps the first remaining bytes and drops the rest, so a
// provider that floods stderr cannot grow the issuer's memory.
type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	if len(p) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.w.Write(p)
	l.remaining -= n
	return len(p), err
}

// stderrSuffix renders a provider's complaint into the error, truncated and
// stripped of control characters so a provider cannot forge log lines or paint
// the terminal with escape sequences.
func stderrSuffix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	const limit = 256
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= limit {
			b.WriteString("...")
			break
		}
		if r == '\n' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return ": " + b.String()
}
