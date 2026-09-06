package summon

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sync"
)

// secret is the backing store for a resolved value: one anonymous mapping,
// mlocked so it is never written to swap, zeroed before it is released. It
// implements "values in mlocked memory, core dumps off, zeroed on replacement"
// from docs/totem-design-decisions.md entry 10.
//
// The memory is mapped rather than allocated on the Go heap on purpose. A heap
// []byte can be copied by the collector, and mlock on a copy that has already
// been moved protects nothing; a mapping's address is stable for its lifetime,
// so the lock and the zeroing apply to the bytes the value actually lives in.
type secret struct {
	mu sync.Mutex
	// buf is the whole mapping. It is nil once the mapping is released.
	buf []byte
	// n is the length of the value inside buf.
	n int
	// refs counts outstanding Values handed to callers.
	refs int
	// cached is true while this secret is the current value for its
	// reference; the cache itself counts as a holder.
	cached bool
	// wiped is true once the bytes have been zeroed.
	wiped bool
}

// secretAllocFn maps and locks size bytes. It is a variable so a test can make
// the lock fail; production never reassigns it, and there is no configuration
// that reaches it.
var secretAllocFn = secretAlloc

// newSecret maps and mlocks size bytes.
func newSecret(size int) (*secret, error) {
	buf, err := secretAllocFn(size)
	if err != nil {
		return nil, err
	}
	return &secret{buf: buf, cached: true}, nil
}

// acquire hands out one reference. It returns a Value whose bytes stay valid
// until that Value is zeroed, the secret is superseded and its retire window
// passes, or the process exits.
func (s *secret) acquire() Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs++
	return &value{s: s}
}

// release drops one caller's reference and frees the mapping if this was the
// last holder of a superseded secret.
func (s *secret) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs > 0 {
		s.refs--
	}
	s.maybeFreeLocked()
}

// retire is called when the cache replaces this secret. The cache stops
// counting as a holder; in-flight callers keep the bytes until they release.
func (s *secret) retire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = false
	s.maybeFreeLocked()
}

// wipe zeroes the bytes whether or not anyone still holds a reference. It is
// what the retire timer calls once the in-flight window has passed: a caller
// that cached a Value across a rotation is then holding a zeroed buffer, which
// is the intended loud failure.
func (s *secret) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wipeLocked()
	s.maybeFreeLocked()
}

func (s *secret) wipeLocked() {
	if s.buf != nil {
		clear(s.buf)
		runtime.KeepAlive(s.buf)
	}
	s.wiped = true
}

// maybeFreeLocked zeroes and unmaps once nothing holds the secret. The mapping
// is kept while a reference is outstanding even after a wipe, so a caller who
// held on reads zeros instead of touching unmapped memory.
func (s *secret) maybeFreeLocked() {
	if s.cached || s.refs > 0 || s.buf == nil {
		return
	}
	s.wipeLocked()
	secretFree(s.buf)
	s.buf = nil
	s.n = 0
}

// bytes returns the value. It is the zero-length slice once the secret has
// been unmapped.
func (s *secret) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf == nil {
		return nil
	}
	return s.buf[:s.n]
}

// sameAs reports whether two secrets hold the same bytes, in constant time so
// the comparison cannot be turned into an oracle for a value it is checking.
// It is used only to detect that a sealed secret changed underneath the
// issuer; neither value is logged, returned, or kept.
func (s *secret) sameAs(other *secret) bool {
	if s == nil || other == nil {
		return false
	}
	a, b := s.bytes(), other.bytes()
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// setLen records how many bytes of the mapping the provider actually wrote.
func (s *secret) setLen(n int) { s.mu.Lock(); s.n = n; s.mu.Unlock() }

// discard drops a secret that was never published to the cache, for example
// when the provider failed after the mapping was made.
func (s *secret) discard() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = false
	s.refs = 0
	s.maybeFreeLocked()
}

// value is one caller's handle on a secret, and is the Value the frozen
// contract describes.
type value struct {
	s    *secret
	once sync.Once
}

// Bytes is the secret material, valid until Zero. Callers must not copy the
// bytes into anything that outlives the call: the next resolve returns a fresh
// value, and this one is zeroed when it is superseded.
func (v *value) Bytes() []byte { return v.s.bytes() }

// Zero releases this handle. The backing memory is zeroed and unmapped once
// nothing holds it, which is immediately when this is the last handle on a
// superseded value.
//
// One nuance stated plainly rather than papered over: a Value is a handle on
// shared memory, so Zero on one handle does not wipe bytes another in-flight
// caller is still reading, and it does not wipe the value the cache is still
// serving. What guarantees the wipe is rotation plus the retire window; Zero
// makes it immediate once the holders are gone. Zero is safe to call more than
// once.
func (v *value) Zero() { v.once.Do(v.s.release) }

// zeroValue is the empty Value returned alongside an error, so a caller that
// ignores the error and calls Bytes gets nothing rather than a nil panic.
type zeroValue struct{}

func (zeroValue) Bytes() []byte { return nil }
func (zeroValue) Zero()         {}

// disableCoreDumpsOnce makes the RLIMIT_CORE change process-wide and once.
var disableCoreDumpsOnce sync.Once
var disableCoreDumpsErr error

// disableCoreDumps sets RLIMIT_CORE to zero for the process, so a crash cannot
// write a core file containing a resolved secret. It is process-wide because
// the limit is; the issuer calls it before the first value is resolved.
func disableCoreDumps() error {
	disableCoreDumpsOnce.Do(func() { disableCoreDumpsErr = setCoreLimitZero() })
	return disableCoreDumpsErr
}

// ErrMemoryLock means a resolved value could not be locked into memory, so it
// could be paged to disk. It is fatal: serving a secret from swappable memory
// while claiming mlocked memory is exactly the control that looks stronger
// than it is.
var ErrMemoryLock = errors.New("summon: cannot lock secret memory")

// errValueTooLarge is returned when a provider writes more than MaxValueSize.
func errValueTooLarge(ref Reference) error {
	return fmt.Errorf("summon: provider returned more than %d bytes for %q", MaxValueSize, ref)
}
