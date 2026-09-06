//go:build !unix

package summon

import "fmt"

// secretAlloc refuses on a platform with no mlock. A value this package cannot
// lock into memory is a value it cannot promise anything about, and the issuer
// runs on Linux and macOS.
func secretAlloc(size int) ([]byte, error) {
	return nil, fmt.Errorf("%w: this platform has no supported memory lock", ErrMemoryLock)
}

// secretFree has nothing to unmap, because secretAlloc never returns memory.
func secretFree([]byte) {}

// setCoreLimitZero reports that core dumps cannot be disabled here.
func setCoreLimitZero() error {
	return fmt.Errorf("summon: core dumps cannot be disabled on this platform")
}
