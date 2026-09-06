package summon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sandbox helper must not be able to hand back a directory that would make
// every hardening test pass vacuously.
func TestSandboxIsItselfSafe(t *testing.T) {
	dir := sandbox(t)
	if err := checkTree(dir, os.Geteuid()); err != nil {
		t.Fatalf("the test sandbox does not satisfy the rules the tests assert: %v", err)
	}
	if err := checkNotPublished(dir); err != nil {
		t.Fatalf("the test sandbox is somewhere the file provider refuses, so its refusals could not be tested honestly: %v", err)
	}
}

func TestCheckTreeAcceptsSafeTree(t *testing.T) {
	dir := sandbox(t)
	sub := filepath.Join(dir, "lib", "summon")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	p := providerScript(t, sub, "provider", "printf x\n")
	if err := checkTree(p, os.Geteuid()); err != nil {
		t.Fatalf("checkTree on a 0755 root-or-owner chain = %v, want nil", err)
	}
}

func TestCheckTreeRefusesRelativePath(t *testing.T) {
	if err := checkTree("relative/provider", os.Geteuid()); !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("checkTree on a relative path = %v, want ErrProviderUnsafe", err)
	}
}

func TestCheckTreeRefusesWritableComponents(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
	}{
		{"group writable", 0o775},
		{"world writable", 0o757},
		{"both", 0o777},
	}
	for _, tc := range cases {
		t.Run("directory "+tc.name, func(t *testing.T) {
			dir := sandbox(t)
			mid := filepath.Join(dir, "lib")
			if err := os.MkdirAll(filepath.Join(mid, "summon"), 0o755); err != nil {
				t.Fatal(err)
			}
			p := providerScript(t, filepath.Join(mid, "summon"), "provider", "printf x\n")
			if err := os.Chmod(mid, tc.mode); err != nil {
				t.Fatal(err)
			}
			err := checkTree(p, os.Geteuid())
			if !errors.Is(err, ErrProviderUnsafe) {
				t.Fatalf("checkTree with a %v directory on the path = %v, want ErrProviderUnsafe", tc.mode, err)
			}
			if !strings.Contains(err.Error(), mid) {
				t.Fatalf("the error must name the offending path %s, got %q", mid, err)
			}
		})
		t.Run("file "+tc.name, func(t *testing.T) {
			dir := sandbox(t)
			p := providerScript(t, dir, "provider", "printf x\n")
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			err := checkTree(p, os.Geteuid())
			if !errors.Is(err, ErrProviderUnsafe) {
				t.Fatalf("checkTree on a %v provider = %v, want ErrProviderUnsafe", tc.mode, err)
			}
			if !strings.Contains(err.Error(), p) {
				t.Fatalf("the error must name the offending path %s, got %q", p, err)
			}
		})
	}
}

// The ownership rule, exercised through the production path: New pins the
// trusted uid to root, and a provider owned by the test user is not root.
func TestCheckTreeRefusesNonRootOwner(t *testing.T) {
	if os.Geteuid() == rootUID {
		t.Skip("running as root: every path in the sandbox is root-owned, so the refusal cannot be provoked this way")
	}
	dir := sandbox(t)
	p := providerScript(t, dir, "provider", "printf x\n")
	err := checkTree(p, rootUID)
	if !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("checkTree on a provider owned by uid %d = %v, want ErrProviderUnsafe", os.Geteuid(), err)
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("the error must say who owns it, got %q", err)
	}
}

// The error should send the operator to the outermost problem, not the
// innermost: chmod on the binary is the wrong fix when its directory is the
// thing anyone can write.
func TestCheckTreeNamesOutermostOffender(t *testing.T) {
	dir := sandbox(t)
	mid := filepath.Join(dir, "lib")
	if err := os.MkdirAll(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	p := providerScript(t, mid, "provider", "printf x\n")
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatal(err)
	}
	err := checkTree(p, os.Geteuid())
	if err == nil || !strings.Contains(err.Error(), mid) || strings.Contains(err.Error(), p) {
		t.Fatalf("want the error to name %s and not %s, got %v", mid, p, err)
	}
}

// A symlink is allowed only if its target chain passes too, so a link cannot
// be used to reach a provider sitting somewhere anyone can rewrite.
func TestCheckTreeFollowsSymlinkTarget(t *testing.T) {
	dir := sandbox(t)
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatal(err)
	}
	p := providerScript(t, real, "provider", "printf x\n")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	err := checkTree(filepath.Join(link, "provider"), os.Geteuid())
	if !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("checkTree through a symlink to a world-writable directory = %v, want ErrProviderUnsafe", err)
	}
	if !strings.Contains(err.Error(), real) {
		t.Fatalf("the error must name the real path %s, got %q", real, err)
	}
	_ = p
}

func TestCheckTreeAcceptsSafeSymlink(t *testing.T) {
	dir := sandbox(t)
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	providerScript(t, real, "provider", "printf x\n")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := checkTree(filepath.Join(link, "provider"), os.Geteuid()); err != nil {
		t.Fatalf("checkTree through a safe symlink = %v, want nil", err)
	}
}

func TestCheckTreeRefusesSymlinkLoop(t *testing.T) {
	dir := sandbox(t)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	if err := checkTree(a, os.Geteuid()); !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("checkTree on a symlink loop = %v, want ErrProviderUnsafe", err)
	}
}

func TestCheckTreeRefusesNonRegularFile(t *testing.T) {
	dir := sandbox(t)
	p := filepath.Join(dir, "fifo")
	if err := makeFIFO(p); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	if err := checkTree(p, os.Geteuid()); !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("checkTree on a FIFO = %v, want ErrProviderUnsafe", err)
	}
}

// This is the check the spec is most insistent about: it is not a start-only
// check. The issuer starts safely, then the provider's directory becomes
// world-writable while it runs, and the very next resolve refuses.
func TestResolveRechecksHardeningOnEveryResolve(t *testing.T) {
	dir := sandbox(t)
	libdir := filepath.Join(dir, "lib")
	if err := os.MkdirAll(libdir, 0o755); err != nil {
		t.Fatal(err)
	}
	provider, _ := echoProvider(t, libdir, "secret-value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	v, err := s.Resolve(ctx, "totem/anthropic")
	if err != nil {
		t.Fatalf("first resolve = %v, want nil", err)
	}
	if string(v.Bytes()) != "secret-value" {
		t.Fatalf("first resolve returned %q", v.Bytes())
	}
	v.Zero()

	if err := os.Chmod(libdir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = s.Resolve(ctx, "totem/anthropic")
	if !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("resolve after the provider directory became world-writable = %v, want ErrProviderUnsafe", err)
	}
	if !strings.Contains(err.Error(), libdir) {
		t.Fatalf("the error must name %s, got %q", libdir, err)
	}
}

// The config file is covered by the same rule as the provider: a config an
// attacker can rewrite is a provider an attacker can choose.
func TestResolveRechecksConfigFile(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := os.Chmod(cfg.Path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = s.Resolve(ctx, "totem/anthropic")
	if !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("resolve with a world-writable config = %v, want ErrProviderUnsafe", err)
	}
	if !strings.Contains(err.Error(), cfg.Path) {
		t.Fatalf("the error must name %s, got %q", cfg.Path, err)
	}
}

// Start refuses before it ever runs the provider.
func TestStartRefusesUnsafeProvider(t *testing.T) {
	dir := sandbox(t)
	provider, calls := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	// The pin is taken while the provider is still safe, exactly as `issuer
	// init` would have done; the binary goes world-writable afterwards.
	if err := os.Chmod(provider, 0o777); err != nil {
		t.Fatal(err)
	}
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("Start with a world-writable provider = %v, want ErrProviderUnsafe", err)
	}
	if n := callCount(t, calls); n != 0 {
		t.Fatalf("the provider ran %d times despite failing its checks", n)
	}
}

// The production constructor requires root ownership with no way to relax it.
func TestProductionStartRequiresRootOwnedProvider(t *testing.T) {
	if os.Geteuid() == rootUID {
		t.Skip("running as root")
	}
	dir := sandbox(t)
	provider, calls := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if !errors.Is(err, ErrProviderUnsafe) {
		t.Fatalf("Start via New with a user-owned provider = %v, want ErrProviderUnsafe", err)
	}
	if n := callCount(t, calls); n != 0 {
		t.Fatalf("the provider ran %d times despite not being root-owned", n)
	}
}
