package summon

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ErrFileProviderRefused means the built-in file provider refused a secret
// file: it was readable by someone else, or it sat somewhere that copies
// itself elsewhere (a git worktree, a synced folder). Fatal, and the message
// names the path and the reason.
var ErrFileProviderRefused = errors.New("summon: the file provider refuses this path")

// fileProviderWarning is logged on EVERY start while the built-in file
// provider is configured, per docs/totem-design.md "Secrets": the file
// provider "logs 'move these' on every start. Not silenceable."
//
// There is deliberately no flag, config key, or log level that turns it off,
// and it goes to stderr as well as the logger so a caller that discards the
// logger still sees it.
const fileProviderWarning = "totem: MOVE THESE. The built-in file provider is in use: your secrets are plaintext files in %s. " +
	"Move them into a real Summon provider (conceal_summon on a Mac, summon-aws-secrets on a VPS, summon-conjur) and set `secrets.provider` in the config. " +
	"This warning cannot be turned off."

// syncedFolderNames are path segments that mean a directory is replicated to
// someone else's storage. Matching is case-insensitive and by prefix, because
// these appear as "OneDrive - Acme" and "GoogleDrive-person@example.com" as
// often as they appear bare.
var syncedFolderNames = []string{
	"dropbox",
	"onedrive",
	"google drive",
	"googledrive",
	"icloud drive",
	"com~apple~clouddocs",
	"mobile documents",
	"box sync",
	"box",
	"nextcloud",
	"owncloud",
	"pcloud drive",
	"creative cloud files",
	"syncthing",
	"megasync",
}

// syncedFolderMarkers are files a sync client leaves in the root of a synced
// tree. A renamed folder still contains them, which is why the name check
// alone is not enough.
var syncedFolderMarkers = []string{
	".dropbox",
	".dropbox.cache",
	".icloud",
	".nextcloudsync.log",
	".csync_journal.db",
	".sync.ffs_db",
}

// readFileSecret is the built-in file provider. It resolves ref as a path
// under dir and reads the value into mlocked memory.
//
// Its refusals are the point of it. It refuses a file anyone else can read,
// because a plaintext secret with a group bit set is a secret the group has.
// It refuses a path inside a git worktree, because the next `git add -A`
// publishes it. It refuses a path inside a synced folder, because the file is
// already somewhere else by the time you read this. And it says "move these"
// on every start, because the file provider is a stopgap and the operator
// should feel it.
func readFileSecret(dir string, ref Reference, trustedUID int) (*secret, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: no directory configured", ErrFileProviderRefused)
	}
	if err := validateReference(ref); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, filepath.FromSlash(string(ref)))
	if err := checkSecretFile(dir, p, trustedUID); err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("summon: reading %q from the file provider: %w", ref, err)
	}
	defer f.Close()
	sec, err := newSecret(MaxValueSize + 1)
	if err != nil {
		return nil, err
	}
	n, err := readAll(f, sec.buf)
	if err != nil {
		sec.discard()
		return nil, fmt.Errorf("summon: reading %q from the file provider: %w", ref, err)
	}
	if n > MaxValueSize {
		sec.discard()
		return nil, errValueTooLarge(ref)
	}
	// A trailing newline is what an editor leaves behind, not part of the
	// secret. Nothing else is trimmed.
	for n > 0 && (sec.buf[n-1] == '\n' || sec.buf[n-1] == '\r') {
		sec.buf[n-1] = 0
		n--
	}
	if n == 0 {
		sec.discard()
		return nil, fmt.Errorf("%w: %s is empty", ErrFileProviderRefused, p)
	}
	sec.setLen(n)
	return sec, nil
}

// checkSecretFile applies every file-provider refusal and names the path it
// refuses.
func checkSecretFile(root, p string, trustedUID int) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s does not exist", ErrNoSuchReference, p)
		}
		return fmt.Errorf("%w: %s: %v", ErrFileProviderRefused, p, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symbolic link; the file provider reads only regular files it can vouch for", ErrFileProviderRefused, p)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrFileProviderRefused, p)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s is mode %04o, which is group or world readable", ErrFileProviderRefused, p, perm)
	}
	if err := checkOwner(p, fi, trustedUID); err != nil {
		return fmt.Errorf("%w: %s is not owned by root or by the issuer", ErrFileProviderRefused, p)
	}
	if err := checkSecretDirs(root, p, trustedUID); err != nil {
		return err
	}
	return checkNotPublished(filepath.Dir(p))
}

// checkSecretDirs checks EVERY directory from the file provider's root down to
// the one holding the secret, not just the immediate parent.
//
// A reference may have several segments ("aws/prod/key" is a legal reference,
// and the spec's own examples look like "totem/anthropic"), so there can be
// directories between the configured root and the secret. The root and its
// ancestors are covered by checkTree at start and on every resolve; the
// immediate parent was covered here. Everything in between was covered by
// neither, which was an inconsistency with the binary provider, whose whole
// path is walked.
//
// It was not exploitable on its own: substituting the secret still had to
// produce a regular, non-symlink, 0600 file owned by root or the issuer, which
// someone who is neither cannot create. But "the other checks happen to catch
// it" is a reason a hole stays closed today, not a reason it was closed, and
// the same argument would have to be re-derived by whoever reads this next.
//
// The walk is outermost-first so the error names the outermost offending
// directory: told that the innermost one is writable, an operator fixes that
// one and leaves the directory that actually let it happen.
//
// This and checkTree in harden.go are a MATCHED PAIR and must stay that way.
// checkTree walks the config file and the provider binary from the filesystem
// root down; this walks the file provider's own directories from its root down
// to the secret. Same rules, same refusal, same message shape. A change to one
// belongs in the other, and the whole reason this function exists is that the
// two were NOT matched: the middle of a multi-segment reference was walked by
// neither.
//
// ONE DELIBERATE DIFFERENCE, recorded so nobody "restores parity" by removing
// it: checkTree permits a symlink component when the link itself is root-owned,
// because /etc is a symlink on macOS and the config legitimately lives under
// it. There is no equivalent case inside a secrets directory, so here a
// symlinked directory is refused outright rather than resolved. That makes
// this walk strictly stricter, never looser, which is the only direction the
// difference is allowed to run.
func checkSecretDirs(root, p string, trustedUID int) error {
	root = filepath.Clean(root)
	var dirs []string
	for d := filepath.Dir(filepath.Clean(p)); ; d = filepath.Dir(d) {
		dirs = append(dirs, d)
		if d == root || d == filepath.Dir(d) {
			break
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		di, err := os.Lstat(d)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrFileProviderRefused, d, err)
		}
		if di.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symbolic link; the file provider will not follow one to a secret", ErrFileProviderRefused, d)
		}
		if !di.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrFileProviderRefused, d)
		}
		if perm := di.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%w: %s is mode %04o, so anyone in the group or on the box can replace the secret in it", ErrFileProviderRefused, d, perm)
		}
		if err := checkOwner(d, di, trustedUID); err != nil {
			return fmt.Errorf("%w: %s is not owned by root or by the issuer", ErrFileProviderRefused, d)
		}
	}
	return nil
}

// checkNotPublished walks up from dir looking for the two ways a plaintext
// file leaves the machine on its own: a git worktree and a synced folder.
func checkNotPublished(dir string) error {
	p := filepath.Clean(dir)
	for {
		if err := checkNotSynced(p); err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
			return fmt.Errorf("%w: %s is inside the git worktree at %s; a secret there is one `git add` from being published", ErrFileProviderRefused, dir, p)
		}
		for _, marker := range syncedFolderMarkers {
			if _, err := os.Lstat(filepath.Join(p, marker)); err == nil {
				return fmt.Errorf("%w: %s is inside the synced folder at %s (%s); the file is already somewhere else", ErrFileProviderRefused, dir, p, marker)
			}
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}

// checkNotSynced refuses a path segment that names a sync client's folder.
func checkNotSynced(p string) error {
	name := strings.ToLower(filepath.Base(p))
	for _, s := range syncedFolderNames {
		if name == s || strings.HasPrefix(name, s+" ") || strings.HasPrefix(name, s+"-") || strings.HasPrefix(name, s+"_") {
			return fmt.Errorf("%w: %s is inside %s, which syncs to storage you do not control", ErrFileProviderRefused, p, filepath.Base(p))
		}
	}
	return nil
}

// warnFileProvider emits the unsilenceable "move these" warning. It runs on
// every start, to the logger and to stderr.
func warnFileProvider(dir string, log *slog.Logger) {
	msg := fmt.Sprintf(fileProviderWarning, dir)
	log.Warn(msg, "provider", "file", "dir", dir)
	_, _ = io.WriteString(warnSink, msg+"\n")
}
