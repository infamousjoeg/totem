package workloadapi

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenSocketCreatesA0600Socket(t *testing.T) {
	path := testSocketPath(t)
	lis, err := ListenSocket(path)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	defer lis.Close()

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != SocketMode {
		t.Errorf("socket mode = %#o, want %#o", fi.Mode().Perm(), SocketMode)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dir.Mode().Perm()&0o077 != 0 {
		t.Errorf("socket directory mode = %#o; another user can reach the socket path", dir.Mode().Perm())
	}
}

// TestListenSocketClearsAStaleSocket covers the restart case: an agent that
// crashed leaves a socket file behind, and the next start must reclaim it.
func TestListenSocketClearsAStaleSocket(t *testing.T) {
	path := testSocketPath(t)
	first, err := ListenSocket(path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	// Close without unlinking, which is what a crash looks like on disk.
	first.SetUnlinkOnClose(false)
	first.Close()

	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket was not left behind, so this test proves nothing: %v", err)
	}
	second, err := ListenSocket(path)
	if err != nil {
		t.Fatalf("second listen over a stale socket: %v", err)
	}
	second.Close()
}

// TestListenSocketRefusesALiveSocket is the other half: a running agent's
// socket is never clobbered, because doing so silently cuts off every tool
// holding a stream open on it.
func TestListenSocketRefusesALiveSocket(t *testing.T) {
	path := testSocketPath(t)
	live, err := ListenSocket(path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	defer live.Close()

	// Serve accepts so the dial in clearStaleSocket connects.
	go func() {
		for {
			c, err := live.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	time.Sleep(20 * time.Millisecond)

	_, err = ListenSocket(path)
	if !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("err = %v, want ErrSocketInUse", err)
	}
	// The live socket survived the attempt.
	c, derr := net.DialTimeout("unix", path, time.Second)
	if derr != nil {
		t.Fatalf("the live socket was clobbered: %v", derr)
	}
	c.Close()
}

func TestListenSocketRefusesANonSocketPath(t *testing.T) {
	path := testSocketPath(t)
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenSocket(path); err == nil {
		t.Fatal("a regular file at the socket path was accepted")
	}
}

func TestVerifySocketRejectsLoosePermissions(t *testing.T) {
	path := testSocketPath(t)
	lis, err := ListenSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	if err := os.Chmod(path, 0o666); err != nil {
		t.Skipf("cannot chmod the socket on this platform: %v", err)
	}
	// verifySocket tightens what it can and fails closed otherwise; either way
	// the socket must not be left world-writable.
	_ = verifySocket(path)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != SocketMode {
		t.Errorf("socket mode = %#o after verify, want %#o", fi.Mode().Perm(), SocketMode)
	}
}

func TestDefaultEndpointIsAUnixURI(t *testing.T) {
	if got := DefaultEndpoint(); got[:7] != "unix://" {
		t.Errorf("DefaultEndpoint = %q, want a unix:// URI a SPIFFE client can put in SPIFFE_ENDPOINT_SOCKET", got)
	}
}
