package summon

import (
	"context"
	"errors"
)

// This file is a FROZEN CONTRACT owned by the build lead. internal/ca and
// internal/store both resolve secrets through it, so its shape is not the
// secrets owner's alone to change. Implementations live in other files in this
// package. Propose changes rather than editing; the lead will make them.

// Resolver turns a Reference into a value by running the configured Summon
// provider. It is the ONLY way a value enters the issuer: there is no plaintext
// path, no key flag, no environment variable the issuer reads directly, and no
// dev mode. Tests use a fake provider that compiles only into the test binary.
type Resolver interface {
	// Resolve runs the provider for ref and returns the value.
	//
	// The hardening is not optional and is not a startup-only check: the config
	// file, the provider binary, and every directory on its path must be
	// root-owned and neither group- nor world-writable, verified at start AND
	// on EVERY resolve, and a failure is fatal and names the offending path.
	// A start-only check would let an attacker who can write the provider
	// directory swap it after the issuer is running, which is the whole attack
	// this check exists to stop.
	//
	// The provider is exec'd with a clean environment and a fixed PATH, under a
	// timeout, and ref is validated against a strict pattern BEFORE it becomes
	// argv. The pinned provider hash is checked and logged on every resolve.
	Resolve(ctx context.Context, ref Reference) (Value, error)

	// Refs returns the logical secret names this resolver is configured for, so
	// startup can fail on a missing reference rather than at first use.
	Refs() []string
}

// Value is a resolved secret. It is held in mlocked memory with core dumps
// disabled and is zeroed on replacement, so it is a type with a lifecycle
// rather than a []byte a caller may keep.
//
// Callers must not copy the bytes into anything that outlives the call. Use
// them and let them go; the next resolve returns a fresh value.
type Value interface {
	// Bytes is the secret material. Valid until Zero.
	Bytes() []byte
	// Zero wipes the backing memory. Safe to call more than once.
	Zero()
}

// Rotation is pull-based, on an interval (default one hour) and on SIGHUP.
// Replacement is atomic, in-flight requests finish against the old value, and
// nothing restarts. A caller that cached a Value across a rotation is holding a
// zeroed buffer, which is the intended failure: it is loud, and it is why
// Resolve is called per use rather than once at start.
const DefaultRotationInterval = "1h"

// Errors are typed because the issuer must fail differently for a
// misconfiguration than for a provider it no longer trusts.
var (
	// ErrProviderUntrusted means the provider binary's hash no longer matches
	// the hash pinned at issuer init. Fatal, and the fix is a deliberate
	// `totem issuer trust-provider`, never an automatic re-pin.
	ErrProviderUntrusted = errors.New("summon: provider hash does not match the pin recorded at init")
	// ErrProviderUnsafe means the provider binary, the config, or a directory
	// on the path is not root-owned or is group- or world-writable. Fatal, and
	// the message names the path.
	ErrProviderUnsafe = errors.New("summon: provider path is not root-owned or is group/world writable")
	// ErrBadReference means a reference failed strict validation and was never
	// passed to the provider.
	ErrBadReference = errors.New("summon: reference name failed validation")
	// ErrNoSuchReference means the config has no entry for the requested
	// logical name.
	ErrNoSuchReference = errors.New("summon: no reference configured for that name")
)
