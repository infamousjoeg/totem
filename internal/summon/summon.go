// Package summon models the Summon provider protocol the issuer speaks
// natively. The laptop holds no durable secrets; the broker holds references,
// and only a Summon provider turns an operator's reference into a value.
// Scaffold only: types and doc comments, no provider execution or hardening
// checks.
package summon

// Reference is an opaque handle to a secret, e.g. "totem/anthropic". The broker
// holds references, never values; only a Summon provider resolves one to a
// value at the moment it is needed.
type Reference string

// Provider is a Summon-protocol provider executable. The issuer speaks the
// provider protocol natively, so every existing provider works unchanged
// (Conceal on a Mac, summon-aws-secrets on a VPS, summon-conjur on Secrets
// Manager). There is no plaintext path, no key flag, no environment variable
// the issuer reads directly, and no dev mode.
type Provider struct {
	// Path is the provider binary. It, and every directory in its path, must be
	// root-owned and not group- or world-writable, checked at start and on
	// every resolve, fatal on failure.
	Path string
	// PinnedHash is the provider hash pinned at issuer init, logged on every
	// resolve and re-pinned only with an explicit trust-provider action.
	PinnedHash string
}

// Config maps each secret name the issuer needs to a Reference. Config holds
// references only; values are resolved through the Provider at use and held in
// mlocked memory, with core dumps off and zeroing on replacement.
type Config struct {
	// Provider is the configured Summon provider.
	Provider Provider
	// Refs maps a logical secret name (e.g. "anthropic_api_key") to its
	// Reference (e.g. "totem/anthropic").
	Refs map[string]Reference
}
