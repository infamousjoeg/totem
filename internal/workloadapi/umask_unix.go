//go:build unix

package workloadapi

// There is deliberately no !unix counterpart to this file.
//
// One existed, a no-op withUmask, and it was misleading: socket.go needs
// syscall.Stat_t for the owner check and syscall.ECONNREFUSED for the
// stale-socket probe, neither of which exists on Windows, so a build that
// selected the fallback could never have linked anyway. A shim that implies a
// portability the package does not have is worse than no shim, because it
// sends the next person looking for the missing piece in the wrong file.
//
// This layer is POSIX-only for v1 by design, and docs/totem-design.md "Scope"
// puts the Windows agent in v1.x. Whoever does that port should know it is not
// three syscalls: go-spiffe reaches a Windows Workload API over a NAMED PIPE,
// not a unix socket (see its addr_windows.go), so the endpoint type changes and
// the 0600-socket security argument has to be rebuilt on pipe ACLs. That is a
// design task, not a shim.

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
