package summon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileConfig wires the built-in file provider at dir/secrets.
func fileConfig(t *testing.T, dir string, refs map[string]Secret) Config {
	t.Helper()
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		Path:   writeConfigFile(t, dir),
		File:   FileProvider{Dir: secrets},
		Refs:   refs,
		Logger: discardLogger(),
	}
}

func writeSecret(t *testing.T, dir string, ref Reference, value string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(string(ref)))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileProviderReadsA0600File(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	writeSecret(t, cfg.File.Dir, "totem/anthropic", "sk-ant-secret", 0o600)

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
		t.Fatal(err)
	}
	defer v.Zero()
	if got := string(v.Bytes()); got != "sk-ant-secret" {
		t.Fatalf("value = %q", got)
	}
}

// The refusals are the point of the file provider. Each of these is a way a
// plaintext secret stops being yours alone.
func TestFileProviderRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mode    os.FileMode
		setup   func(t *testing.T, secretsDir, secretPath string)
		want    string
		wantErr error // nil means ErrFileProviderRefused
	}{
		{name: "group readable", mode: 0o640, want: "group or world readable"},
		{name: "world readable", mode: 0o604, want: "group or world readable"},
		{name: "world writable", mode: 0o606, want: "group or world readable"},
		{name: "readable by everyone", mode: 0o644, want: "group or world readable"},
		{
			name: "inside a git worktree",
			mode: 0o600,
			setup: func(t *testing.T, secretsDir, _ string) {
				if err := os.MkdirAll(filepath.Join(secretsDir, ".git"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "git worktree",
		},
		{
			name: "inside a linked git worktree",
			mode: 0o600,
			setup: func(t *testing.T, secretsDir, _ string) {
				if err := os.WriteFile(filepath.Join(secretsDir, ".git"), []byte("gitdir: /elsewhere\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "git worktree",
		},
		{
			name: "under a git worktree further up",
			mode: 0o600,
			setup: func(t *testing.T, secretsDir, _ string) {
				if err := os.MkdirAll(filepath.Join(filepath.Dir(secretsDir), ".git"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "git worktree",
		},
		{
			name: "beside a sync client marker",
			mode: 0o600,
			setup: func(t *testing.T, secretsDir, _ string) {
				if err := os.WriteFile(filepath.Join(secretsDir, ".dropbox"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "synced folder",
		},
		{
			name: "in a group-writable directory",
			mode: 0o600,
			setup: func(t *testing.T, secretsDir, _ string) {
				if err := os.Chmod(secretsDir, 0o770); err != nil {
					t.Fatal(err)
				}
			},
			// The tree check runs first and catches this one, which is
			// why the error is ErrProviderUnsafe: a directory anyone can
			// write is refused before the file inside it is even opened.
			// checkSecretFile has the same rule for the case where a
			// caller reaches it directly; see
			// TestCheckSecretFileRefusesAWritableDirectory.
			want:    "group or world writable",
			wantErr: ErrProviderUnsafe,
		},
		{
			name: "a symlink to a safe file",
			mode: 0o600,
			setup: func(t *testing.T, secretsDir, secretPath string) {
				real := secretPath + ".real"
				if err := os.Rename(secretPath, real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, secretPath); err != nil {
					t.Fatal(err)
				}
			},
			want: "symbolic link",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := sandbox(t)
			cfg := fileConfig(t, dir, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
			p := writeSecret(t, cfg.File.Dir, "totem/anthropic", "sk-ant-secret", tc.mode)
			if tc.setup != nil {
				tc.setup(t, cfg.File.Dir, p)
			}
			s, err := newForTest(cfg, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			wantErr := tc.wantErr
			if wantErr == nil {
				wantErr = ErrFileProviderRefused
			}
			err = s.Start(context.Background())
			if !errors.Is(err, wantErr) {
				t.Fatalf("Start with a secret %s = %v, want %v", tc.name, err, wantErr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to say %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), cfg.File.Dir) {
				t.Fatalf("error = %q, want it to name the path", err)
			}
		})
	}
}

// A folder that syncs to somebody else's storage is refused by name, however
// the vendor decorates it.
func TestFileProviderRefusesSyncedFolderNames(t *testing.T) {
	for _, name := range []string{"Dropbox", "dropbox", "OneDrive - Acme Corp", "Google Drive", "GoogleDrive-someone@example.com", "com~apple~CloudDocs", "Nextcloud"} {
		t.Run(name, func(t *testing.T) {
			dir := sandbox(t)
			synced := filepath.Join(dir, name, "secrets")
			if err := os.MkdirAll(synced, 0o700); err != nil {
				t.Fatal(err)
			}
			cfg := Config{
				Path:   writeConfigFile(t, dir),
				File:   FileProvider{Dir: synced},
				Refs:   map[string]Secret{"anthropic": Rotating("totem/anthropic")},
				Logger: discardLogger(),
			}
			writeSecret(t, synced, "totem/anthropic", "sk-ant-secret", 0o600)
			s, err := newForTest(cfg, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			err = s.Start(context.Background())
			if !errors.Is(err, ErrFileProviderRefused) {
				t.Fatalf("Start with secrets in %s = %v, want ErrFileProviderRefused", name, err)
			}
			if !strings.Contains(err.Error(), "syncs to storage you do not control") {
				t.Fatalf("error = %q, want the synced-folder reason", err)
			}
		})
	}
}

func TestFileProviderMissingSecretIsNoSuchReference(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"anthropic": Rotating("totem/anthropic")})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("Start with a missing secret file = %v, want ErrNoSuchReference", err)
	}
}

func TestFileProviderTrimsOnlyTheEditorsNewline(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
	writeSecret(t, cfg.File.Dir, "totem/a", "sk-ant-secret\n", 0o600)
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Zero()
	if got := string(v.Bytes()); got != "sk-ant-secret" {
		t.Fatalf("value = %q, want the trailing newline gone and nothing else touched", got)
	}
}

func TestFileProviderRefusesAnEmptySecret(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
	writeSecret(t, cfg.File.Dir, "totem/a", "\n", 0o600)
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); !errors.Is(err, ErrFileProviderRefused) {
		t.Fatalf("Start with an empty secret = %v, want ErrFileProviderRefused", err)
	}
}

// A reference cannot climb out of the file provider's directory, because it
// was validated before it became a path.
func TestFileProviderReferenceCannotEscapeItsDirectory(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
	writeSecret(t, cfg.File.Dir, "totem/a", "value", 0o600)
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Resolve(ctx, "../outside"); !errors.Is(err, ErrBadReference) {
		t.Fatalf("Resolve(../outside) = %v, want ErrBadReference", err)
	}
}

// "Logs 'move these' on every start. Not silenceable." The warning goes to
// stderr as well as the logger, so a caller that discards the logger still
// gets it, and it repeats on every single start.
func TestFileProviderWarnsOnEveryStartAndCannotBeSilenced(t *testing.T) {
	dir := sandbox(t)
	var stderr strings.Builder
	restore := setWarnSink(&stderr)
	defer restore()

	for i := 0; i < 3; i++ {
		cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
		writeSecret(t, cfg.File.Dir, "totem/a", "value", 0o600)
		// The most hostile logger a caller can supply: one that throws
		// everything away.
		cfg.Logger = discardLogger()
		s, err := newForTest(cfg, os.Geteuid())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	if n := strings.Count(stderr.String(), "MOVE THESE"); n != 3 {
		t.Fatalf("the warning appeared %d times across 3 starts, want 3:\n%s", n, stderr.String())
	}
	if !strings.Contains(stderr.String(), "cannot be turned off") {
		t.Fatalf("the warning should say it cannot be turned off:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "conceal_summon") {
		t.Fatalf("the warning should name where to move the secrets to:\n%s", stderr.String())
	}
}

// The same warning also reaches the logger, so it lands in the issuer's record
// and not only on a terminal nobody is watching.
func TestFileProviderWarningReachesTheLogger(t *testing.T) {
	dir := sandbox(t)
	restore := setWarnSink(&strings.Builder{})
	defer restore()

	cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
	writeSecret(t, cfg.File.Dir, "totem/a", "value", 0o600)
	var buf logBuffer
	cfg.Logger = buf.logger()
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !strings.Contains(buf.String(), "MOVE THESE") {
		t.Fatalf("the logger did not get the warning:\n%s", buf.String())
	}
}

// An exec provider does not get the file provider's warning: it is not a
// stopgap.
func TestExecProviderDoesNotWarn(t *testing.T) {
	dir := sandbox(t)
	var stderr strings.Builder
	restore := setWarnSink(&stderr)
	defer restore()

	provider, _ := echoProvider(t, dir, "value")
	if _, err := startWith(t, dir, provider, map[string]Secret{"a": Rotating("totem/a")}, nil); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("a real provider should produce no warning, got:\n%s", stderr.String())
	}
}

// The file provider's own directory rule, reached directly: a directory anyone
// in the group can write is a secret anyone in the group can replace.
func TestCheckSecretFileRefusesAWritableDirectory(t *testing.T) {
	dir := sandbox(t)
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	p := writeSecret(t, secrets, "totem/a", "value", 0o600)
	if err := os.Chmod(filepath.Dir(p), 0o770); err != nil {
		t.Fatal(err)
	}
	err := checkSecretFile(secrets, p, os.Geteuid())
	if !errors.Is(err, ErrFileProviderRefused) {
		t.Fatalf("checkSecretFile in a group-writable directory = %v, want ErrFileProviderRefused", err)
	}
	if !strings.Contains(err.Error(), "replace the secret") {
		t.Fatalf("error = %q, want it to say why that is a problem", err)
	}
}

// The ownership rule again, through the file provider: a secret file owned by
// somebody else is refused. Exercised by asking for an owner the file does not
// have, which is what the production path does when it asks for root.
func TestCheckSecretFileRefusesAnotherUsersFile(t *testing.T) {
	if os.Geteuid() == rootUID {
		t.Skip("running as root")
	}
	dir := sandbox(t)
	p := writeSecret(t, dir, "totem/a", "value", 0o600)
	err := checkSecretFile(dir, p, rootUID)
	if !errors.Is(err, ErrFileProviderRefused) {
		t.Fatalf("checkSecretFile on a file owned by uid %d when root was required = %v, want ErrFileProviderRefused", os.Geteuid(), err)
	}
}

func TestFileProviderRefusesAnOversizedSecret(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
	writeSecret(t, cfg.File.Dir, "totem/a", strings.Repeat("x", MaxValueSize+1), 0o600)
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Start with an oversized secret file = %v, want the size refusal", err)
	}
}

func TestFileProviderAcceptsASecretAtTheSizeLimit(t *testing.T) {
	dir := sandbox(t)
	cfg := fileConfig(t, dir, map[string]Secret{"a": Rotating("totem/a")})
	writeSecret(t, cfg.File.Dir, "totem/a", strings.Repeat("x", MaxValueSize), 0o600)
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("a secret exactly at the limit was refused: %v", err)
	}
	defer s.Close()
	v, err := s.Resolve(ctx, "totem/a")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Zero()
	if len(v.Bytes()) != MaxValueSize {
		t.Fatalf("value is %d bytes, want %d", len(v.Bytes()), MaxValueSize)
	}
}

func TestFileProviderNeedsADirectory(t *testing.T) {
	if _, err := readFileSecret("", "totem/a", os.Geteuid()); !errors.Is(err, ErrFileProviderRefused) {
		t.Fatalf("readFileSecret with no directory = %v, want ErrFileProviderRefused", err)
	}
}
