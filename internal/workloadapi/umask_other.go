//go:build !unix

package workloadapi

// withUmask is a no-op on platforms without a process umask. Those platforms
// are not a v1 target for the agent (docs/totem-design.md "Scope" puts the
// Windows agent in v1.x), and verifySocket still fails closed on a socket that
// is not mode 0600.
func withUmask(_ int, fn func() error) error { return fn() }
