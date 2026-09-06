package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// docs/totem-design.md "Experience": "`init` on the issuer is a wizard that
// writes the config (trust domain from the hostname, built-in file provider by
// default with its loud warning, secrets asked for per enabled bridge) and
// every question has a flag so headless and scripted setups never block."
//
// FORMAT NOTE FOR THE BUILD LEAD. docs/totem-design.md "Secrets" shows this
// file as YAML. It is written and read here as JSON, because the module has no
// YAML dependency and adding one is the lead's call (go.mod is lead-owned), and
// because a hand-rolled partial YAML parser is worse than a format change: it
// accepts a tab where a space belongs and silently reads a different config
// than the operator wrote. Everything else about the file matches the spec: it
// holds REFERENCES and never values, and its path is handed to internal/summon
// so its ownership and mode are verified at start and on every resolve. Swapping
// the encoding later is confined to Load and Save below.

// ConfigFile is the issuer config file name inside the issuer directory.
const ConfigFile = "issuer.json"

// CAPassphraseRefName is the logical secret name for the passphrase protecting
// intermediate private keys at rest. The name matches the spec's YAML key.
const CAPassphraseRefName = "ca_passphrase"

// Config is the issuer's on-disk configuration. It holds references only.
type Config struct {
	// TrustDomain is the issuer's OWN name, and the one thing here that is
	// never taken from a request. It defaults to the hostname; an IP-only
	// issuer must be given one explicitly, because an address is not a name.
	TrustDomain string `json:"trust_domain"`
	// ExternalURL is how devices reach this issuer. It is what goes in the
	// enroll command, so it must be the address a laptop can dial, not the
	// bind address.
	ExternalURL string `json:"external_url"`
	// Listen is the bind address.
	Listen string `json:"listen"`
	// Secrets configures the Summon provider and the references.
	Secrets SecretsConfig `json:"secrets"`
	// Bridges records which bridges are enabled and what each one needs.
	Bridges map[string]Bridge `json:"bridges,omitempty"`
	// DailyBackup records the operator's answer to the backup question at init,
	// so issuer status can say whether one was ever set up.
	DailyBackup bool `json:"daily_backup"`

	// path is where this config was loaded from. Not serialised; it is the
	// file's own location.
	path string
}

// SecretsConfig mirrors the spec's `secrets:` block.
type SecretsConfig struct {
	// Provider is the Summon-protocol provider binary. Empty selects the
	// built-in file provider, which is the default `issuer init` offers and
	// which warns loudly on every start.
	Provider string `json:"provider,omitempty"`
	// ProviderHash is the hash pinned at init, logged on every resolve and
	// re-pinned only by an explicit trust-provider action.
	ProviderHash string `json:"provider_hash,omitempty"`
	// FileProviderDir is the root the built-in file provider reads under.
	FileProviderDir string `json:"file_provider_dir,omitempty"`
	// Refs maps a logical secret name to its reference.
	Refs map[string]string `json:"refs"`
}

// Bridge is one exchange the issuer will serve.
type Bridge struct {
	Enabled bool     `json:"enabled"`
	Refs    []string `json:"refs,omitempty"`
}

// ErrNotInitialized means there is no config where one was expected.
var ErrNotInitialized = errors.New("this issuer has not been set up yet")

// Load reads the issuer config.
func Load(dir string) (*Config, error) {
	path := filepath.Join(dir, ConfigFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w (looked in %s)", ErrNotInitialized, path)
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("the issuer config at %s could not be read: %w", path, err)
	}
	c.path = path
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the config atomically at 0600.
//
// The mode matters even though the file holds no values: internal/summon
// verifies the config file's ownership and permissions on EVERY resolve and
// fails fatally if it is group- or world-writable, because "a config an
// attacker can rewrite is a provider an attacker can choose".
func (c *Config) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, ConfigFile)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	c.path = path
	return nil
}

// Path is where this config lives.
func (c *Config) Path() string { return c.path }

// Summon builds the resolver config from the issuer config. Every reference the
// issuer needs is registered here so startup fails on a missing reference
// rather than at first use, which for the CA passphrase would mean failing at
// the first rotation, weeks later, at whatever hour the schedule falls on.
func (c *Config) Summon(dir string) summon.Config {
	out := map[string]summon.Secret{}
	for name, ref := range c.Secrets.Refs {
		out[name] = declare(name, summon.Reference(ref))
	}
	cfg := summon.Config{
		Path: filepath.Join(dir, ConfigFile),
		Provider: summon.Provider{
			Path:       c.Secrets.Provider,
			PinnedHash: c.Secrets.ProviderHash,
		},
		File: summon.FileProvider{Dir: c.Secrets.FileProviderDir},
		Refs: out,
	}
	return cfg
}

// RequiredRefs are the logical secret names that MUST be present in every
// issuer config, because each one seals material at rest and the issuer cannot
// come back without it.
//
// They exist as a list rather than as three checks so that declare() and
// Validate cannot drift apart: TestAtRestSecretsAreClassifiedAndRequired walks
// this list for both. Adding an at-rest secret without adding it here fails
// that test rather than shipping a value that quietly pull-rotates.
func RequiredRefs() []string {
	return []string{CAPassphraseRefName, store.DataKeyRefName, store.BackupPassphraseRefName}
}

// Validate refuses a config that is missing any at-rest secret reference.
//
// This closes a hazard the secrets owner raised about declare(). declare()
// decides which references are excluded from pull-based rotation by switching
// on the LOGICAL NAME, and that name is an operator-editable key in this file.
// Rename "ca_passphrase" to anything else and declare() falls through to
// Rotating, the provider's hourly rotation replaces the value that seals the CA
// private keys, and the issuer keeps running perfectly until the next restart,
// at which point the old value is gone and the CA will not open.
//
// In practice a renamed CA passphrase already fails at start, because runtime.go
// resolves it by that exact name and internal/summon answers ErrNoSuchReference,
// and a renamed data key already fails because internal/store checks for its own
// name. But both of those are properties of OTHER packages that happen to agree
// with this one today, nothing asserted them, and one refactor removes them
// silently. The backup passphrase had no such accident at all: nothing resolves
// it until a restore, which is the worst possible moment to discover it, because
// there is no old value to recover and no working system to recover it from.
//
// So the check lives here, at start, where the config is read, and says which
// name is missing.
func (c *Config) Validate() error {
	var missing []string
	for _, name := range RequiredRefs() {
		if strings.TrimSpace(c.Secrets.Refs[name]) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrRefMissing, strings.Join(missing, ", "))
}

// ErrRefMissing means the config does not name a secret the issuer cannot start
// without. It is deliberately fatal at start rather than at first use.
var ErrRefMissing = errors.New("the issuer config is missing a secret reference it cannot start without")

// declare classifies a reference by what its value protects, which is what
// internal/summon needs to know before it will rotate anything.
//
// The distinction is not cosmetic. A value that SEALS material at rest (the
// passphrase over the intermediate private keys, the store's data key, the
// backup passphrase) must be excluded from pull-based rotation, because
// rotating it out from under material that is already encrypted under it does
// not re-encrypt anything: it just makes the material unreadable, at whatever
// hour the rotation interval falls on, with no operator action to correlate it
// with. Re-encryption is a deliberate command (issuer rotate-data-key), never a
// timer. Everything else is a credential a remote service accepts as soon as it
// changes, and rotating those on a pull is the whole point.
func declare(name string, ref summon.Reference) summon.Secret {
	for _, atRest := range RequiredRefs() {
		if name == atRest {
			return summon.Sealing(ref)
		}
	}
	return summon.Rotating(ref)
}

// DefaultRefs are the references every issuer needs regardless of which bridges
// are enabled: the CA passphrase, the store's data key, and the backup
// passphrase.
func DefaultRefs(namespace string) map[string]string {
	ns := strings.TrimSuffix(namespace, "/")
	if ns == "" {
		ns = "totem"
	}
	return map[string]string{
		CAPassphraseRefName:           ns + "/ca-passphrase",
		store.DataKeyRefName:          ns + "/data-key",
		store.BackupPassphraseRefName: ns + "/backup-passphrase",
	}
}

// BridgeRefs is what each bridge needs, from docs/totem-design.md "Secrets".
// "Secrets are asked for when a bridge needs them": `bridges enable claude`
// asks for exactly what claude needs and nothing else.
func BridgeRefs(namespace, bridge string) ([]string, error) {
	ns := strings.TrimSuffix(namespace, "/")
	if ns == "" {
		ns = "totem"
	}
	switch bridge {
	case "claude":
		return []string{ns + "/anthropic", ns + "/claude-oauth"}, nil
	case "aws":
		// The AWS bridge is Roles Anywhere: the credential is the SVID itself,
		// so there is no operator-provided secret to resolve. Enabling it is
		// still a deliberate act, which is why it is listed rather than
		// implicit.
		return nil, nil
	case "github":
		return []string{ns + "/github-app"}, nil
	default:
		return nil, fmt.Errorf("there is no %q bridge. The bridges are: %s", bridge, strings.Join(KnownBridges(), ", "))
	}
}

// KnownBridges lists the bridges this issuer can serve.
func KnownBridges() []string {
	b := []string{"claude", "aws", "github"}
	sort.Strings(b)
	return b
}

// Dirs are the fixed layout under the issuer directory.
func caDir(dir string) string     { return filepath.Join(dir, "ca") }
func tlsDir(dir string) string    { return filepath.Join(dir, "tls") }
func statePath(dir string) string { return filepath.Join(dir, "issuer.db") }
