// Package summon models the Summon provider protocol the issuer speaks
// natively. The laptop holds no durable secrets; the broker holds references,
// and only a Summon provider turns an operator's reference into a value.
//
// The rule this package exists to enforce, from docs/totem-design.md
// "Secrets": there is no plaintext path, no --anthropic-key flag, no
// environment variable the issuer reads directly, and no dev mode. Every value
// arrives by exec'ing a Summon provider (or the built-in file provider, which
// says loudly on every start that it is a stopgap). Tests drive the same exec
// path with a fake provider that exists only while a test runs.
package summon

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

// Reference is an opaque handle to a secret, e.g. "totem/anthropic". The broker
// holds references, never values; only a Summon provider resolves one to a
// value at the moment it is needed.
type Reference string

// Provider is a Summon-protocol provider executable. The issuer speaks the
// provider protocol natively, so every existing provider works unchanged
// (Conceal on a Mac, summon-aws-secrets on a VPS, summon-conjur on Secrets
// Manager). There is no plaintext path, no key flag, no environment variable
// the issuer reads directly, and no dev mode.
//
// The protocol is the whole of Summon's contract: the provider is exec'd with
// the reference as its single argument, writes the value to stdout, writes
// diagnostics to stderr, and exits zero on success. Nothing else is exchanged,
// which is why an unmodified conceal_summon works here.
type Provider struct {
	// Path is the provider binary. It, and every directory in its path, must be
	// root-owned and not group- or world-writable, checked at start and on
	// every resolve, fatal on failure.
	Path string
	// PinnedHash is the provider hash pinned at issuer init, logged on every
	// resolve and re-pinned only with an explicit trust-provider action.
	PinnedHash string
}

// FileProvider configures the built-in file provider: the default `issuer init`
// offers, with its loud warning. It reads a reference as a path under Dir. It
// "refuses world or group readable files, refuses paths inside a git worktree
// or synced folder, and logs 'move these' on every start. Not silenceable."
type FileProvider struct {
	// Dir is the root the reference is resolved under. A reference never
	// escapes it: references are validated before they become a path, and ".."
	// is not a legal segment.
	Dir string
}

// Config maps each secret name the issuer needs to a Reference. Config holds
// references only; values are resolved through the Provider at use and held in
// mlocked memory, with core dumps off and zeroing on replacement.
//
// Nothing in Config is read from the environment. The issuer's config file is
// the only input, and Path names it so its ownership and mode can be verified
// alongside the provider's on every resolve.
type Config struct {
	// Path is the issuer config file this Config was loaded from. It is
	// checked for root ownership and group/world writability at start and on
	// every resolve, because a config an attacker can rewrite is a provider an
	// attacker can choose.
	Path string
	// Provider is the configured Summon provider. An empty Provider.Path
	// selects the built-in file provider.
	Provider Provider
	// File configures the built-in file provider, used only when
	// Provider.Path is empty.
	File FileProvider
	// Refs maps a logical secret name (e.g. "anthropic_api_key") to its
	// Reference (e.g. "totem/anthropic").
	Refs map[string]Reference
	// Timeout bounds a single provider execution. Zero means DefaultTimeout.
	Timeout time.Duration
	// RotateEvery is the pull-based rotation interval. Zero means
	// DefaultRotateEvery, the duration DefaultRotationInterval names.
	RotateEvery time.Duration
	// RetireAfter is how long a superseded value stays readable after an
	// atomic replacement, so an in-flight request finishes against the old
	// value. Past it the old buffer is zeroed whether or not its holder
	// released it, which is the loud failure a caller who cached a Value
	// across a rotation is meant to hit. Zero means DefaultRetireAfter.
	RetireAfter time.Duration
	// Logger receives the per-resolve record (reference, provider path, pinned
	// hash). It never receives a secret value. Nil means slog.Default().
	//
	// Logger cannot silence anything: the file provider's "move these" warning
	// goes to stderr as well, and refusals are returned as errors, not logged
	// and swallowed.
	Logger *slog.Logger
}

// Defaults. DefaultRotateEvery is the duration form of
// DefaultRotationInterval, which the frozen contract states as a string.
const (
	// DefaultTimeout bounds one provider execution. A provider that hangs is a
	// provider that stops the issuer from serving, so it is killed, not waited
	// on.
	DefaultTimeout = 10 * time.Second
	// DefaultRotateEvery is the pull-based rotation interval, one hour.
	DefaultRotateEvery = time.Hour
	// DefaultRetireAfter is the window an in-flight request has to finish
	// against a superseded value before that value is zeroed.
	DefaultRetireAfter = 30 * time.Second
)

// FixedPATH is the PATH the provider is exec'd with. The environment is
// otherwise empty: "clean environment, fixed PATH, timeout". A provider that
// needs configuration reads it from a root-owned file, never from an
// environment variable the issuer would have to pass through.
const FixedPATH = "/usr/bin:/bin:/usr/sbin:/sbin"

// warnSink is where the file provider's unsilenceable warning goes in addition
// to the logger. It is a variable so a test can read what production writes to
// stderr; there is no configuration, flag, or environment variable that
// changes it.
var warnSink io.Writer = os.Stderr

// validate checks a Config without touching the filesystem, so a bad config
// fails at load rather than at first use. Every reference is validated here,
// which is what lets startup "fail on a missing reference rather than at first
// use".
func (c *Config) validate() error {
	if c.Path == "" {
		return fmt.Errorf("summon: config path is empty; the config file must be named so its ownership can be verified")
	}
	if c.Provider.Path == "" && c.File.Dir == "" {
		return fmt.Errorf("summon: no provider configured: set the provider path, or the built-in file provider directory")
	}
	if c.Provider.Path != "" && c.Provider.PinnedHash == "" {
		return fmt.Errorf("%w: no hash pinned for %s; run `totem issuer trust-provider`", ErrProviderUntrusted, c.Provider.Path)
	}
	if c.Provider.Path != "" {
		if err := validatePinnedHash(c.Provider.PinnedHash); err != nil {
			return err
		}
	}
	for name, ref := range c.Refs {
		if name == "" {
			return fmt.Errorf("summon: a reference is configured under an empty name")
		}
		if err := validateReference(ref); err != nil {
			return fmt.Errorf("%w (configured as %q)", err, name)
		}
	}
	return nil
}

func (c *Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

func (c *Config) rotateEvery() time.Duration {
	if c.RotateEvery <= 0 {
		return DefaultRotateEvery
	}
	return c.RotateEvery
}

func (c *Config) retireAfter() time.Duration {
	if c.RetireAfter <= 0 {
		return DefaultRetireAfter
	}
	return c.RetireAfter
}

func (c *Config) logger() *slog.Logger {
	if c.Logger == nil {
		return slog.Default()
	}
	return c.Logger
}
