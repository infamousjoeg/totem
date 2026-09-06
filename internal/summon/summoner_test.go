package summon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRefsAndRef(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	refs := map[string]Reference{
		"ca_passphrase":      "totem/ca-passphrase",
		"anthropic_api_key":  "totem/anthropic",
		"claude_oauth_token": "totem/claude-oauth",
	}
	s, err := startWith(t, dir, provider, refs, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"anthropic_api_key", "ca_passphrase", "claude_oauth_token"}
	if got := s.Refs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Refs() = %v, want %v", got, want)
	}
	ref, err := s.Ref("anthropic_api_key")
	if err != nil || ref != "totem/anthropic" {
		t.Fatalf("Ref(anthropic_api_key) = %q, %v", ref, err)
	}
	if _, err := s.Ref("not_configured"); !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("Ref of an unknown name = %v, want ErrNoSuchReference", err)
	}
}

// Every reference is resolved at start, so a missing secret stops the issuer
// then rather than at the first exchange that needed it.
func TestStartFailsOnAReferenceTheProviderCannotResolve(t *testing.T) {
	dir := sandbox(t)
	provider := providerScript(t, dir, "provider",
		"if [ \"$1\" = totem/present ]; then printf 'v'; else echo 'no such variable' >&2; exit 1; fi\n")
	cfg := testConfig(t, dir, provider, map[string]Reference{
		"present": "totem/present",
		"missing": "totem/missing",
	})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if err == nil {
		t.Fatal("Start should fail when a configured reference cannot be resolved")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("error = %v, want it to name the reference that failed", err)
	}
}

func TestResolveBeforeStart(t *testing.T) {
	dir := sandbox(t)
	provider, calls := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"a": "totem/a"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(context.Background(), "totem/a"); err == nil {
		t.Fatal("Resolve before Start should fail")
	}
	if n := callCount(t, calls); n != 0 {
		t.Fatalf("the provider ran %d times before Start", n)
	}
}

func TestDoubleStartAndDoubleClose(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"a": "totem/a"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err == nil {
		t.Fatal("a second Start should fail")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("a second Close should be a no-op, got %v", err)
	}
}

// Resolves and rotations run concurrently under -race.
func TestConcurrentResolveAndRotate(t *testing.T) {
	dir := sandbox(t)
	provider := countingProvider(t, dir)
	s, err := startWith(t, dir, provider, map[string]Reference{"a": "totem/a", "b": "totem/b"}, func(c *Config) {
		c.RotateEvery = 20 * time.Millisecond
		// Long enough that no forced wipe lands while a reader is using a
		// value; the forced wipe has its own test.
		c.RetireAfter = time.Minute
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	deadline := time.Now().Add(300 * time.Millisecond)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				for _, ref := range []Reference{"totem/a", "totem/b"} {
					v, err := s.Resolve(ctx, ref)
					if err != nil {
						t.Errorf("resolve: %v", err)
						return
					}
					if !strings.HasPrefix(string(v.Bytes()), "value-") {
						t.Errorf("value = %q", v.Bytes())
						v.Zero()
						return
					}
					v.Zero()
				}
			}
		}()
	}
	wg.Wait()
}

// The rule this package exists to enforce, asserted against the source rather
// than trusted: no environment variable the issuer reads directly, no flags,
// no dev mode. A future edit that adds an os.Getenv here fails this test.
func TestPackageReadsNoEnvironmentOrFlags(t *testing.T) {
	forbidden := map[string]string{
		"os.Getenv":      "the issuer must never read a secret or a provider path from the environment",
		"os.LookupEnv":   "the issuer must never read a secret or a provider path from the environment",
		"os.Environ":     "the provider environment is built from nothing, not filtered from the issuer's",
		"syscall.Getenv": "the issuer must never read a secret from the environment",
		"os.ExpandEnv":   "the issuer must never expand the environment into a path or a reference",
		"flag.String":    "there is no key flag and no dev mode",
		"flag.StringVar": "there is no key flag and no dev mode",
		"flag.Parse":     "there is no key flag and no dev mode",
		"os.ReadFile":    "a value reaches memory through the provider path, which reads into locked memory, never through a plain read",
		"os.Args":        "there is no plaintext path from the command line",
		"fmt.Println":    "values must never be printed",
		"fmt.Printf":     "values must never be printed",
		"println":        "values must never be printed",
		"print":          "values must never be printed",
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var called string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok {
					called = pkg.Name + "." + fn.Sel.Name
				}
			case *ast.Ident:
				called = fn.Name
			}
			if why, bad := forbidden[called]; bad {
				t.Errorf("%s calls %s: %s", fset.Position(call.Pos()), called, why)
			}
			return true
		})
	}
}

// There is exactly one way a value enters this package, and it is a provider
// execution. No exported symbol accepts secret material.
func TestNoExportedSymbolAcceptsASecret(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || fn.Type.Params == nil {
				continue
			}
			// Methods on unexported types are not part of the package's
			// surface; limitedWriter.Write is an io.Writer for a provider's
			// stderr, not a way in for a value.
			if fn.Recv != nil && !exportedReceiver(fn.Recv) {
				continue
			}
			for _, p := range fn.Type.Params.List {
				if arr, ok := p.Type.(*ast.ArrayType); ok {
					if id, ok := arr.Elt.(*ast.Ident); ok && id.Name == "byte" {
						t.Errorf("%s: exported %s takes a []byte, which is what a way to inject a value looks like",
							fset.Position(fn.Pos()), fn.Name.Name)
					}
				}
			}
		}
	}
}

// exportedReceiver reports whether a method's receiver type is exported, and
// so whether the method is reachable from outside the package.
func exportedReceiver(recv *ast.FieldList) bool {
	if len(recv.List) == 0 {
		return false
	}
	t := recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.IsExported()
}

// A Config that names no provider, or no config file, is refused at load.
// There is no default that quietly becomes a plaintext path.
func TestConfigValidation(t *testing.T) {
	dir := sandbox(t)
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "no config path",
			cfg:  Config{Provider: Provider{Path: "/x", PinnedHash: strings.Repeat("a", 64)}},
			want: "config path is empty",
		},
		{
			name: "no provider at all",
			cfg:  Config{Path: filepath.Join(dir, "totem.yaml")},
			want: "no provider configured",
		},
		{
			name: "a reference under an empty name",
			cfg: Config{
				Path: filepath.Join(dir, "totem.yaml"),
				File: FileProvider{Dir: dir},
				Refs: map[string]Reference{"": "totem/a"},
			},
			want: "empty name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error saying %q", err, tc.want)
			}
		})
	}
}

// The Value returned alongside an error is empty rather than nil, so a caller
// that ignores the error gets nothing instead of a panic.
func TestErrorReturnsAnEmptyValue(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"a": "totem/a"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Resolve(context.Background(), "-bad-reference")
	if err == nil {
		t.Fatal("expected an error")
	}
	if v == nil {
		t.Fatal("Resolve returned a nil Value alongside its error")
	}
	if len(v.Bytes()) != 0 {
		t.Fatalf("the Value returned with an error has bytes: %q", v.Bytes())
	}
	v.Zero()
}
