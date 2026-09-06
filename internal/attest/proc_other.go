//go:build !darwin && !linux

package attest

// No attestor on this OS: defaultSystem stays nil and NewWithOptions returns
// an error rather than an attestor that cannot see its peers.
