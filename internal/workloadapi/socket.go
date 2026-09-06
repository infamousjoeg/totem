package workloadapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"time"
)

// SocketMode is the mode the Workload API socket must have. The spec is
// explicit: "Standard SPIFFE Workload API on a unix socket, mode 0600."
const SocketMode fs.FileMode = 0o600

// DirMode is the mode of the directory holding the socket and the agent's local
// state. 0700 is what makes socket creation safe: no other user can traverse
// into the directory at any point, so there is no window in which a
// half-created socket is reachable by anyone else.
const DirMode fs.FileMode = 0o700

// ErrSocketInUse means a live totem agent is already listening on the socket
// path. A stale socket file is cleaned up; a live one is never clobbered,
// because doing so would silently take the Workload API away from every tool
// currently holding a stream open on it.
var ErrSocketInUse = errors.New("workloadapi: another totem agent is already listening on this socket")

// DefaultSocketPath is ~/.totem/agent.sock. Clients reach it with
// SPIFFE_ENDPOINT_SOCKET=unix://<path>, which is the standard discovery
// variable every SPIFFE client already reads.
func DefaultSocketPath() string {
	return filepath.Join(homeDir(), ".totem", "agent.sock")
}

// DefaultEndpoint is the DefaultSocketPath as the unix:// URI a SPIFFE client
// expects in SPIFFE_ENDPOINT_SOCKET.
func DefaultEndpoint() string { return "unix://" + DefaultSocketPath() }

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return "."
}

// ListenSocket creates the Workload API socket at path, owned by this user and
// mode 0600, with no window in which it is reachable by anyone else.
//
// Three things make that true. The parent directory is created (or corrected)
// to 0700 first, so nothing inside it is traversable by another user even for
// an instant. The socket itself is bound under a tightened umask, so the kernel
// creates it at 0600 rather than at 0600 after a chmod. The result is then
// re-read from disk and refused unless it really is a socket, really is owned
// by this uid, and really is 0600.
//
// A stale socket left by a crashed agent is removed. A live one is refused.
func ListenSocket(path string) (*net.UnixListener, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("workloadapi: %q is not a usable socket path: %w", path, err)
	}
	if err := ensurePrivateDir(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	if err := clearStaleSocket(abs); err != nil {
		return nil, err
	}

	var lis *net.UnixListener
	err = withUmask(0o177, func() error {
		addr, err := net.ResolveUnixAddr("unix", abs)
		if err != nil {
			return err
		}
		lis, err = net.ListenUnix("unix", addr)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("workloadapi: cannot listen on %s: %w", abs, err)
	}
	lis.SetUnlinkOnClose(true)

	if err := verifySocket(abs); err != nil {
		_ = lis.Close()
		return nil, err
	}
	return lis, nil
}

// ensurePrivateDir makes dir exist at 0700 and owned by this user. A directory
// that is group- or world-accessible is tightened rather than accepted, because
// the directory mode is what closes the socket-creation window.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("workloadapi: cannot create %s: %w", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("workloadapi: cannot inspect %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("workloadapi: %s exists and is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, DirMode); err != nil {
			return fmt.Errorf("workloadapi: %s is readable by other users and cannot be tightened: %w", dir, err)
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("workloadapi: %s is owned by uid %d, not by you (uid %d)", dir, st.Uid, os.Getuid())
	}
	return nil
}

// clearStaleSocket removes a socket file left behind by a crashed agent and
// refuses to touch one a live agent is serving. Liveness is decided by dialing:
// a connection refused means nothing is listening on that inode, anything else
// means something is, and totem stays out of its way.
func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("workloadapi: cannot inspect %s: %w", path, err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("workloadapi: %s already exists and is not a socket; move it out of the way and retry", path)
	}

	conn, derr := net.DialTimeout("unix", path, 500*time.Millisecond)
	if derr == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: %s", ErrSocketInUse, path)
	}
	if !errors.Is(derr, syscall.ECONNREFUSED) && !errors.Is(derr, syscall.ENOENT) {
		// Anything other than "nobody is listening" (a permission error, for
		// instance) means the file is not ours to remove.
		return fmt.Errorf("%w: %s (%v)", ErrSocketInUse, path, derr)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("workloadapi: cannot remove the stale socket at %s: %w", path, err)
	}
	return nil
}

// verifySocket re-reads the socket from disk and fails closed unless it is a
// socket, owned by this uid, at exactly SocketMode. Checking after the fact
// catches a permissive umask, a hostile pre-created path, and any future change
// to how the socket is bound.
func verifySocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("workloadapi: cannot inspect the socket at %s: %w", path, err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("workloadapi: %s is not a socket", path)
	}
	if perm := fi.Mode().Perm(); perm != SocketMode {
		if err := os.Chmod(path, SocketMode); err != nil {
			return fmt.Errorf("workloadapi: the socket at %s is mode %#o, not %#o, and cannot be tightened: %w", path, perm, SocketMode, err)
		}
		if fi, err = os.Lstat(path); err != nil || fi.Mode().Perm() != SocketMode {
			return fmt.Errorf("workloadapi: the socket at %s is mode %#o, not %#o", path, perm, SocketMode)
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("workloadapi: the socket at %s is owned by uid %d, not by you (uid %d)", path, st.Uid, os.Getuid())
	}
	return nil
}
