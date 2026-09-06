//go:build unix

package summon

import (
	"fmt"
	"syscall"
)

// secretAlloc maps size bytes of anonymous private memory and locks it into
// RAM. The mapping is off the Go heap so its address is stable, which is what
// makes the lock and the later zeroing apply to the bytes the secret is
// actually stored in.
//
// A failed mlock is an error, not a warning. On Linux, RLIMIT_MEMLOCK can be
// low enough to refuse even one page; the honest outcome there is a resolve
// that fails and names the reason, so the operator raises the limit, rather
// than a secret quietly living in swappable memory.
func secretAlloc(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("summon: refusing to map %d bytes", size)
	}
	buf, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("summon: mapping %d bytes for a secret: %w", size, err)
	}
	if err := syscall.Mlock(buf); err != nil {
		_ = syscall.Munmap(buf)
		return nil, fmt.Errorf("%w: mlock of %d bytes failed: %v (raise RLIMIT_MEMLOCK)", ErrMemoryLock, size, err)
	}
	return buf, nil
}

// secretFree unlocks and unmaps a secret's memory. The caller has already
// zeroed it; unlocking first means the pages are not left locked if unmapping
// somehow fails.
func secretFree(buf []byte) {
	if len(buf) == 0 {
		return
	}
	_ = syscall.Munlock(buf)
	_ = syscall.Munmap(buf)
}

// setCoreLimitZero sets RLIMIT_CORE to zero so a crash cannot write a core
// file holding a resolved secret. The hard limit is left where it is; lowering
// only the soft limit is what an unprivileged process can do, and it is what
// stops the kernel from writing the dump.
func setCoreLimitZero() error {
	var cur syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &cur); err != nil {
		return fmt.Errorf("summon: reading the core dump limit: %w", err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: cur.Max}); err != nil {
		return fmt.Errorf("summon: disabling core dumps: %w", err)
	}
	return nil
}
