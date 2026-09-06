package main

import (
	"errors"
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

// TestAtRestSecretsAreClassifiedAndRequired pins the property the secrets owner
// raised and the build lead asked to have asserted rather than reasoned about.
//
// declare() decides which references are excluded from pull-based rotation by
// switching on the LOGICAL NAME, and that name is an operator-editable key in
// issuer.json. Rename it and the classification silently becomes Rotating, the
// provider's hourly rotation replaces the value that seals material at rest, and
// the issuer runs perfectly until a restart that then fails. internal/summon has
// no name-based special case on its side by design, so the whole protection
// lives in declare(); this is what stops it resting on an unwritten agreement.
func TestAtRestSecretsAreClassifiedAndRequired(t *testing.T) {
	t.Parallel()
	required := RequiredRefs()
	if len(required) != 3 {
		t.Fatalf("RequiredRefs has %d entries (%v); the three at-rest secrets are the CA passphrase, "+
			"the store data key and the backup passphrase", len(required), required)
	}
	sealing := summon.Sealing("totem/x").Rotation
	rotating := summon.Rotating("totem/x").Rotation
	if sealing == rotating {
		t.Fatal("Sealing and Rotating are indistinguishable; this whole test proves nothing")
	}
	for _, name := range required {
		if got := declare(name, "totem/x").Rotation; got != sealing {
			t.Errorf("%s is declared %v; a value that seals material at rest must never be pull-rotated", name, got)
		}
	}
	if got := declare("claude_0", "totem/anthropic").Rotation; got != rotating {
		t.Errorf("a bridge credential is declared %v; it must take part in pull-based rotation", got)
	}
}

// TestRenamingAnAtRestSecretFailsAtStart. Every one of the three, individually,
// because the backup passphrase is the one with no accidental protection: nothing
// resolves it until a restore, which is the worst possible moment to find out,
// with no old value to recover and no working system to recover it from.
func TestRenamingAnAtRestSecretFailsAtStart(t *testing.T) {
	t.Parallel()
	for _, name := range RequiredRefs() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &Config{
				TrustDomain: "issuer.ts.net",
				ExternalURL: "https://issuer.ts.net",
				Listen:      ":8443",
				Secrets:     SecretsConfig{FileProviderDir: dir + "/secrets", Refs: DefaultRefs("totem")},
			}
			// The rename an operator makes while tidying up a config file.
			cfg.Secrets.Refs[name+"_v2"] = cfg.Secrets.Refs[name]
			delete(cfg.Secrets.Refs, name)

			if err := cfg.Validate(); !errors.Is(err, ErrRefMissing) {
				t.Fatalf("a config with %s renamed validated: %v", name, err)
			}
			if err := cfg.Save(dir); err != nil {
				t.Fatal(err)
			}
			_, err := Load(dir)
			if !errors.Is(err, ErrRefMissing) {
				t.Fatalf("loading a config with %s renamed returned %v; it must fail at start, "+
					"before anything is sealed under a value that will then rotate away", name, err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the failure does not name the missing reference: %v", err)
			}
			ce := classify(err)
			if !strings.Contains(ce.fix, "refs") {
				t.Errorf("the fix does not say where to put it back: %q", ce.fix)
			}

			// The second line of defence, which is what made this safe by
			// accident before it was asserted: the renamed entry is now
			// classified Rotating, and the only reason that is not a brick is
			// that resolving it by its canonical name fails.
			if got := declare(name+"_v2", "totem/x").Rotation; got != summon.Rotating("totem/x").Rotation {
				t.Errorf("a renamed at-rest secret classified as %v; the hazard this test exists for is that it does not", got)
			}
			s, err := summon.New(cfg.Summon(dir))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.Ref(name); !errors.Is(err, summon.ErrNoSuchReference) {
				t.Errorf("resolving %s by its canonical name returned %v, want ErrNoSuchReference", name, err)
			}
		})
	}
}

// TestValidateAcceptsTheShippedDefaults, so the check cannot drift into
// rejecting what init itself writes.
func TestValidateAcceptsTheShippedDefaults(t *testing.T) {
	t.Parallel()
	cfg := &Config{Secrets: SecretsConfig{Refs: DefaultRefs("totem")}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("init writes a config its own loader rejects: %v", err)
	}
	// An empty value is as bad as a missing key and must be caught the same way.
	cfg.Secrets.Refs[CAPassphraseRefName] = "   "
	if err := cfg.Validate(); !errors.Is(err, ErrRefMissing) {
		t.Fatalf("a blank reference validated: %v", err)
	}
}

// TestAuditSinkNeverContaminatesACommandsResult pins the ruling that the audit
// stream is a NAMED SINK and stdout is one possible value of it.
//
// The defect this replaces: the invariant was written as "stdout is the audit
// stream", which is true of serve and false of every one-shot command, whose
// stdout belongs to its caller. init writes the enroll command to stdout on
// purpose and a scripted setup captures it, so init emitting a JSON audit
// record there put an unparseable line into two streams at once, a caller's and
// a person's.
//
// It matters past tidiness because the audit stream is itself hash-chained: a
// consumer that has learned to skip unparseable lines will skip a tampered one.
func TestAuditSinkNeverContaminatesACommandsResult(t *testing.T) {
	t.Parallel()
	cfg := &Config{Secrets: SecretsConfig{Refs: DefaultRefs("totem")}}

	if got := auditSink(cfg, longRunning); got != os.Stdout {
		t.Error("serve's audit sink is not stdout; nothing else consumes serve's stdout, so the stream can have it")
	}
	if got := auditSink(cfg, oneShot); got != os.Stderr {
		t.Error("a one-shot command's audit sink is stdout, which is the stream its caller parses. " +
			"init writes the enroll command there deliberately.")
	}

	// Configurable either way, in the shape the syslog and OTLP exports will
	// take. An operator who asks for the contamination gets it, on their head.
	cfg.AuditSink = AuditSinkStdout
	if got := auditSink(cfg, oneShot); got != os.Stdout {
		t.Error("an explicit stdout sink was not honoured")
	}
	cfg.AuditSink = AuditSinkStderr
	if got := auditSink(cfg, longRunning); got != os.Stderr {
		t.Error("an explicit stderr sink was not honoured")
	}
	// Case and whitespace are an operator typing into a config file, not a
	// different intent.
	cfg.AuditSink = "  STDERR "
	if got := auditSink(cfg, longRunning); got != os.Stderr {
		t.Error("a sink written with different case or spacing was not recognised")
	}
	// A typo must not stop an issuer starting; the per-command default is
	// always safe, so an unrecognised value falls back to it rather than
	// refusing.
	cfg.AuditSink = "sylog"
	if got := auditSink(cfg, oneShot); got != os.Stderr {
		t.Error("an unrecognised sink did not fall back to the safe per-command default")
	}
	if got := auditSink(cfg, longRunning); got != os.Stdout {
		t.Error("an unrecognised sink did not fall back to the safe per-command default")
	}
}

// TestEveryCommandDeclaresWhatItsStdoutIsFor. The rule is inherited by having
// to name a kind, so a new command cannot get the default by accident. This
// asserts the one that would be most costly to get wrong is still declared: a
// long-running kind on a command that prints for a caller puts JSON back in the
// caller's stream.
func TestEveryCommandDeclaresWhatItsStdoutIsFor(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	longRunningFiles := map[string]bool{"serve.go": true}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		body := string(src)
		if strings.Contains(body, "openRuntime(ctx, dir, longRunning)") && !longRunningFiles[name] {
			t.Errorf("%s opens the runtime as longRunning. Only serve may: every other command prints a "+
				"result its caller parses, and a longRunning sink puts the audit stream back into it.", name)
		}
		// Nothing may name os.Stdout as an audit sink directly, which is how
		// the rule gets bypassed without anyone choosing to bypass it.
		if strings.Contains(body, "NewAuditLog(os.Stdout") {
			t.Errorf("%s wires the audit log straight to stdout instead of through auditSink()", name)
		}
	}
}
