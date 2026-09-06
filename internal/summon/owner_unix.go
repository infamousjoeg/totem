//go:build unix

package summon

import (
	"fmt"
	"io/fs"
	"syscall"
)

// checkOwner requires a path on the provider chain to be root-owned.
//
// trustedUID is an additional accepted owner and is rootUID in production, so
// the production rule is exactly "root-owned". The test binary passes its own
// uid, because a test that has to run as root to exercise the check is a test
// that never runs, and an unexercised refusal is a comment rather than a
// control. Root is always accepted so that the parents of a test's scratch
// directory (/, /var, /private) still pass.
func checkOwner(p string, fi fs.FileInfo, trustedUID int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: cannot read the owner of this path", ErrProviderUnsafe, p)
	}
	if uid := int(st.Uid); uid != rootUID && uid != trustedUID {
		return fmt.Errorf("%w: %s is owned by uid %d, which is not root", ErrProviderUnsafe, p, uid)
	}
	return nil
}
