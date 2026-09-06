//go:build unix

package workloadapi

import (
	"sync"
	"syscall"
)

// umaskMu serializes the process-wide umask change around socket creation.
// The umask is per process, so two goroutines binding sockets at once would
// otherwise race; the agent binds exactly one, and the lock keeps that true
// even if that ever changes.
var umaskMu sync.Mutex

// withUmask runs fn with the process umask set to mask, restoring it after.
// Binding the socket under a 0177 umask means the kernel creates it at 0600
// directly, so there is no instant at which the socket exists with a looser
// mode.
func withUmask(mask int, fn func() error) error {
	umaskMu.Lock()
	defer umaskMu.Unlock()
	prev := syscall.Umask(mask)
	defer syscall.Umask(prev)
	return fn()
}
