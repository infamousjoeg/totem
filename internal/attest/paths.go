package attest

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// pathProtected reports whether path, and every directory from it up to the
// root, is owned by none of the untrusted uids and is neither group- nor
// world-writable. That is the spec's "non-user-writable path": a location
// the calling user cannot rewrite, rename into, or replace. Group-writable
// counts as writable regardless of which group, because the caller's group
// memberships are not worth reasoning about. Symlinks are resolved first so
// the check is on the real location. The second return value says why the
// path failed.
func pathProtected(path string, untrusted []uint32) (bool, string) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, fmt.Sprintf("resolving %s: %v", path, err)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return false, "path is not absolute"
	}
	for p := resolved; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return false, fmt.Sprintf("stat %s: %v", p, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return false, "no unix ownership information"
		}
		for _, u := range untrusted {
			if st.Uid == u {
				return false, fmt.Sprintf("%s is owned by uid %d", p, u)
			}
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return false, fmt.Sprintf("%s is group- or world-writable (%s)", p, fi.Mode().Perm())
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Sprintf("%s is a symlink", p)
		}
		if p == "/" || filepath.Dir(p) == p {
			return true, ""
		}
	}
}
