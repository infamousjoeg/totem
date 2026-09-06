//go:build unix

package summon

import (
	"context"
	"os"
	"syscall"
	"testing"
)

// Core dumps are off before the first value exists, so a crash cannot write a
// resolved secret to disk.
func TestStartDisablesCoreDumps(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if rl.Cur != 0 {
		t.Fatalf("RLIMIT_CORE soft limit is %d after Start, want 0", rl.Cur)
	}
}
