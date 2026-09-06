package summon

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// maxSymlinkHops bounds symlink resolution during a path walk so a link loop
// is an error rather than a hang.
const maxSymlinkHops = 16

// rootUID is the only owner a path on the provider chain may have in
// production. checkTree takes a trusted uid as an argument rather than reading
// one from config: production always passes rootUID, and the only other caller
// is the test binary, which passes its own uid so the walk can reach a scratch
// directory. There is no config key, flag, or environment variable that
// changes it.
const rootUID = 0

// checkTree enforces the hardening rule from docs/totem-design-decisions.md
// entry 10: "config file, provider binary, and every directory in its path
// must be root-owned and not group or world writable... Failure is fatal and
// names the path."
//
// It is called at start AND on every resolve. A start-only check would leave
// an attacker who can write the provider's directory free to swap the binary
// after the issuer is running, which is the whole attack this exists to stop.
//
// The walk is from the filesystem root down to p, checking each component with
// Lstat so a symlink is seen as a symlink rather than silently followed. A
// symlink component is allowed only if the link itself passes the ownership
// check (its permission bits are meaningless on Unix and are not checked), and
// its target chain is then walked under the same rules. That is what lets
// /etc, which is a symlink on macOS, hold the config while still refusing a
// link an attacker planted.
func checkTree(p string, trustedUID int) error {
	if p == "" {
		return fmt.Errorf("%w: empty path", ErrProviderUnsafe)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%w: %s is not an absolute path", ErrProviderUnsafe, p)
	}
	hops := 0
	return checkChain(filepath.Clean(p), trustedUID, &hops)
}

// checkChain checks p's parents first, then p itself, so the error names the
// outermost offending path rather than the innermost. Naming the outermost one
// matters: if /usr/local/lib is world-writable, saying so is the fix, while
// saying the binary is unsafe sends the operator to chmod the wrong file.
func checkChain(p string, trustedUID int, hops *int) error {
	if parent := filepath.Dir(p); parent != p {
		if err := checkChain(parent, trustedUID, hops); err != nil {
			return err
		}
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrProviderUnsafe, p, err)
	}
	if err := checkOwner(p, fi, trustedUID); err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		*hops++
		if *hops > maxSymlinkHops {
			return fmt.Errorf("%w: %s: more than %d symbolic links on the path", ErrProviderUnsafe, p, maxSymlinkHops)
		}
		target, err := os.Readlink(p)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrProviderUnsafe, p, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(p), target)
		}
		return checkChain(filepath.Clean(target), trustedUID, hops)
	}
	if !fi.IsDir() && !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is neither a directory nor a regular file (mode %v)", ErrProviderUnsafe, p, fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is mode %04o, which is group or world writable", ErrProviderUnsafe, p, perm)
	}
	return nil
}
