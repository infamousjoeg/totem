package summon

import "io"

// This file compiles only into the test binary. Everything in it exists so a
// refusal can be exercised without running the suite as root, and none of it
// is reachable from a production build: there is no exported constructor, flag
// or config key that reaches any of these.

// newForTest builds a Summoner that accepts trustedUID as an owner on the
// provider chain in addition to root. Production always uses New, which pins
// the trusted uid to root and offers no way to change it.
//
// A test that had to run as root to exercise the ownership check is a test
// that never runs, and an unexercised refusal is a comment rather than a
// control. The refusal itself is still tested through the production path:
// several tests call New and assert that a provider owned by the test user
// rather than root is refused.
func newForTest(cfg Config, trustedUID int) (*Summoner, error) {
	s, err := New(cfg)
	if err != nil {
		return nil, err
	}
	s.trustedUID = trustedUID
	return s, nil
}

// setSecretAlloc replaces the mmap+mlock allocator so a test can make the
// memory lock fail, which is otherwise impossible on a machine with an
// unlimited RLIMIT_MEMLOCK. It returns a function that restores the real one.
func setSecretAlloc(f func(int) ([]byte, error)) func() {
	prev := secretAllocFn
	secretAllocFn = f
	return func() { secretAllocFn = prev }
}

// setWarnSink captures what production writes to stderr, so the file
// provider's unsilenceable warning can be asserted rather than assumed.
func setWarnSink(w io.Writer) func() {
	prev := warnSink
	warnSink = w
	return func() { warnSink = prev }
}

// trustProviderForTest is TrustProvider with a trusted uid, for the same
// reason newForTest exists.
func trustProviderForTest(path string, uid int) (string, error) {
	return trustProvider(path, uid)
}
