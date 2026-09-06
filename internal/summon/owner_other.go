//go:build !unix

package summon

import (
	"fmt"
	"io/fs"
)

// checkOwner has no way to read a file's owner on this platform, so it
// refuses. The issuer runs on Linux and macOS; reporting "safe" on a platform
// where the ownership rule cannot be evaluated would be a control that looks
// stronger than it is, and this package exists to prevent exactly that.
func checkOwner(p string, _ fs.FileInfo, _ int) error {
	return fmt.Errorf("%w: %s: file ownership cannot be verified on this platform", ErrProviderUnsafe, p)
}
