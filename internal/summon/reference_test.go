package summon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestValidateReferenceAccepts(t *testing.T) {
	for _, ref := range []Reference{
		"totem/anthropic",
		"totem/claude-oauth",
		"totem/github-app",
		"totem/ca-passphrase",
		"prod/db/password",
		"a",
		"9lives",
		"team.secrets/db_password-2",
		Reference(strings.Repeat("a", MaxReferenceLen)),
	} {
		if err := validateReference(ref); err != nil {
			t.Errorf("validateReference(%q) = %v, want nil", ref, err)
		}
	}
}

// The negative assertion is the real test here: every one of these would
// otherwise become argv for a provider running as root.
func TestValidateReferenceRefuses(t *testing.T) {
	cases := []struct {
		name string
		ref  Reference
	}{
		{"empty", ""},
		{"leading dash reads as a flag", "-p"},
		{"leading dash on a real name", "-totem/anthropic"},
		{"long flag", "--config=/etc/shadow"},
		{"parent segment", "totem/../../etc/shadow"},
		{"bare parent", ".."},
		{"current dir", "."},
		{"absolute path", "/etc/shadow"},
		{"empty segment", "totem//anthropic"},
		{"trailing separator", "totem/"},
		{"space", "totem/an thropic"},
		{"newline", "totem/anthropic\n"},
		{"carriage return", "totem\ranthropic"},
		{"nul byte", "totem/anthropic\x00"},
		{"shell metacharacter", "totem/anthropic;id"},
		{"backtick", "totem/`id`"},
		{"dollar", "totem/$HOME"},
		{"non-ascii homoglyph", "totem/anthropiс"},
		{"over the length limit", Reference(strings.Repeat("a", MaxReferenceLen+1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReference(tc.ref)
			if !errors.Is(err, ErrBadReference) {
				t.Fatalf("validateReference(%q) = %v, want ErrBadReference", tc.ref, err)
			}
		})
	}
}

// Validation must happen BEFORE the reference becomes argv. A provider that
// records every call proves it: after a refused resolve, the provider has not
// run at all.
func TestResolveValidatesBeforeExec(t *testing.T) {
	dir := sandbox(t)
	provider, calls := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"anthropic": "totem/anthropic"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	before := callCount(t, calls)
	if before != 1 {
		t.Fatalf("start resolved %d references, want 1", before)
	}
	for _, bad := range []Reference{"-p", "totem/../etc/shadow", "totem/anthropic;id", ""} {
		if _, err := s.Resolve(ctx, bad); !errors.Is(err, ErrBadReference) {
			t.Fatalf("Resolve(%q) = %v, want ErrBadReference", bad, err)
		}
	}
	if after := callCount(t, calls); after != before {
		t.Fatalf("the provider ran %d more times for references that should never have reached argv", after-before)
	}
}

// A reference that is well-formed but not configured is refused too, so a bug
// elsewhere in the issuer cannot turn into arbitrary secret retrieval.
func TestResolveRefusesUnconfiguredReference(t *testing.T) {
	dir := sandbox(t)
	provider, calls := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"anthropic": "totem/anthropic"})
	s, err := newForTest(cfg, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	before := callCount(t, calls)
	if _, err := s.Resolve(ctx, "totem/somebody-elses-secret"); !errors.Is(err, ErrNoSuchReference) {
		t.Fatalf("Resolve of an unconfigured reference = %v, want ErrNoSuchReference", err)
	}
	if after := callCount(t, calls); after != before {
		t.Fatal("the provider ran for a reference that is not in the config")
	}
}

// A bad reference in the config fails at load, not at first use.
func TestNewRefusesBadReferenceInConfig(t *testing.T) {
	dir := sandbox(t)
	provider, _ := echoProvider(t, dir, "value")
	cfg := testConfig(t, dir, provider, map[string]Reference{"anthropic": "-totem/anthropic"})
	if _, err := New(cfg); !errors.Is(err, ErrBadReference) {
		t.Fatalf("New with a bad reference = %v, want ErrBadReference", err)
	}
}
