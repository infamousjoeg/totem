package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// TestResolveNames. docs/totem-design.md "Identity model": "Trust domain
// defaults to the issuer hostname given at enroll; IP-only issuers require one
// explicitly." An address is not a name: it changes with the network path, and
// the trust domain is the one string the issuer and every device must agree on
// before an enrollment can finish.
func TestResolveNames(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		url, td         string
		wantURL, wantTD string
		wantErr         string
	}{
		{
			name: "hostname becomes the trust domain",
			url:  "https://issuer.tail1234.ts.net", wantURL: "https://issuer.tail1234.ts.net", wantTD: "issuer.tail1234.ts.net",
		},
		{
			name: "a bare host gets https",
			url:  "issuer.tail1234.ts.net", wantURL: "https://issuer.tail1234.ts.net", wantTD: "issuer.tail1234.ts.net",
		},
		{
			name: "an explicit trust domain wins",
			url:  "https://issuer.ts.net", td: "totem.internal", wantURL: "https://issuer.ts.net", wantTD: "totem.internal",
		},
		{
			name: "an IP-only issuer must be told its name",
			url:  "https://10.0.0.5:8443", wantErr: "needs to be told its name",
		},
		{
			name: "an IP-only issuer with a name is fine",
			url:  "https://10.0.0.5:8443", td: "totem.internal", wantURL: "https://10.0.0.5:8443", wantTD: "totem.internal",
		},
		{
			name: "plain http is refused",
			url:  "http://issuer.ts.net", wantErr: "must start with https",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotTD, err := resolveNames(tc.url, tc.td)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got (%q, %q, %v), want an error containing %q", gotURL, gotTD, err, tc.wantErr)
				}
				var ce *cliError
				if !asCLI(err, &ce) || ce.fix == "" {
					t.Error("every refusal must tell the operator what to do next")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotURL != tc.wantURL || gotTD != tc.wantTD {
				t.Errorf("got (%q, %q), want (%q, %q)", gotURL, gotTD, tc.wantURL, tc.wantTD)
			}
		})
	}
}

func asCLI(err error, out **cliError) bool {
	ce, ok := err.(*cliError)
	if ok {
		*out = ce
	}
	return ok
}

// TestConfigRoundTripAndMode. internal/summon verifies the config file's
// ownership and permissions on EVERY resolve and fails fatally if it is group-
// or world-writable, because "a config an attacker can rewrite is a provider an
// attacker can choose".
func TestConfigRoundTripAndMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := &Config{
		TrustDomain: "issuer.ts.net",
		ExternalURL: "https://issuer.ts.net",
		Listen:      ":8443",
		Secrets:     SecretsConfig{FileProviderDir: dir + "/secrets", Refs: DefaultRefs("totem")},
		Bridges:     map[string]Bridge{"claude": {Enabled: true, Refs: []string{"totem/anthropic"}}},
	}
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("issuer config mode %o is readable or writable by others; summon will refuse to resolve against it", perm)
	}
	back, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if back.TrustDomain != cfg.TrustDomain || back.Listen != cfg.Listen {
		t.Errorf("round trip lost fields: %+v", back)
	}
	if !back.Bridges["claude"].Enabled {
		t.Error("round trip lost the enabled bridge")
	}
}

// TestConfigHoldsReferencesNotValues. "Config holds references": there is no
// plaintext path, no key flag, no environment variable the issuer reads
// directly, and no dev mode.
func TestConfigHoldsReferencesNotValues(t *testing.T) {
	t.Parallel()
	refs := DefaultRefs("totem")
	for _, name := range []string{CAPassphraseRefName, store.DataKeyRefName, store.BackupPassphraseRefName} {
		if refs[name] == "" {
			t.Errorf("the issuer needs a %s reference configured at init, or it fails at first use instead of at start", name)
		}
	}
}

// TestSealingSecretsAreExcludedFromPullRotation. Rotating a value that seals
// material at rest does not re-encrypt anything; it makes the material
// unreadable at whatever hour the rotation interval falls on. Re-encryption is
// a deliberate command, never a timer.
func TestSealingSecretsAreExcludedFromPullRotation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{CAPassphraseRefName, store.DataKeyRefName, store.BackupPassphraseRefName} {
		if got := declare(name, "totem/x"); got.Rotation != summon.Sealing("totem/x").Rotation {
			t.Errorf("%s is declared %v; a value that seals material at rest must not be pull-rotated", name, got.Rotation)
		}
	}
	if got := declare("claude_0", "totem/anthropic"); got.Rotation != summon.Rotating("totem/anthropic").Rotation {
		t.Errorf("a bridge credential is declared %v; it must take part in pull-based rotation", got.Rotation)
	}
}

// TestBridgeRefsAreExactlyWhatTheBridgeNeeds. "Secrets are asked for when a
// bridge needs them": enabling claude must not ask for GitHub's key.
func TestBridgeRefsAreExactlyWhatTheBridgeNeeds(t *testing.T) {
	t.Parallel()
	claude, err := BridgeRefs("totem", "claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(claude) != 2 {
		t.Fatalf("claude needs %v; the spec names an API key and an OAuth token", claude)
	}
	for _, r := range claude {
		if strings.Contains(r, "github") {
			t.Errorf("enabling claude asked for %q", r)
		}
	}
	// AWS is Roles Anywhere: the credential IS the SVID, so there is no
	// operator-provided secret to resolve.
	aws, err := BridgeRefs("totem", "aws")
	if err != nil {
		t.Fatal(err)
	}
	if len(aws) != 0 {
		t.Errorf("the aws bridge asked for secrets (%v); its credential is the SVID itself", aws)
	}
	if _, err := BridgeRefs("totem", "nope"); err == nil {
		t.Fatal("an unknown bridge must be refused, and the message must list the real ones")
	}
}

// TestLoadOnAnUninitialisedDirectorySaysSo.
func TestLoadOnAnUninitialisedDirectorySaysSo(t *testing.T) {
	t.Parallel()
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("loading a config that is not there must fail")
	}
	ce := classify(err)
	if !strings.Contains(ce.fix, "totem-issuer init") {
		t.Errorf("the fix should be the exact next command; got %q", ce.fix)
	}
}

// TestNoStackTraceReachesTheOperator. docs/totem-design.md "Experience": an
// error tells the human what to do next, and no stack trace crosses this
// boundary.
func TestNoStackTraceReachesTheOperator(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		ErrNotInitialized,
		summon.ErrProviderUnsafe,
		store.ErrChainBroken,
	} {
		ce := classify(err)
		if ce.what == "" {
			t.Errorf("%v produced no sentence", err)
		}
		if ce.fix == "" {
			t.Errorf("%v produced no next action", err)
		}
		if strings.Contains(ce.what, "goroutine ") || strings.Contains(ce.what, ".go:") {
			t.Errorf("%v leaked a stack trace: %q", err, ce.what)
		}
	}
}
