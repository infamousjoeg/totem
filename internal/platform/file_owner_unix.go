//go:build unix

package platform

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkKeyFileOwner refuses a key file owned by a different uid than the one
// running the agent. Permissions alone are not enough: a 0600 file owned by
// someone else was written by someone else.
func checkKeyFileOwner(p string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrBadKeyFile, p, st.Uid, os.Geteuid())
	}
	return nil
}
