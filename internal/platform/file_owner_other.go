//go:build !unix

package platform

import "io/fs"

// checkKeyFileOwner has no portable owner check on this platform; the
// permission-bits check in checkKeyFile still applies.
func checkKeyFileOwner(string, fs.FileInfo) error { return nil }
