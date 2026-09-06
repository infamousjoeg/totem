package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
)

// cmdUninstall reverses exactly what totem changed, and nothing else.
//
// docs/totem-design.md "Experience": init is reversible; it keeps a manifest of
// every config line it wrote, and uninstall diffs each surface against the
// manifest, restores lines that are unchanged since init, shows any line the
// user edited afterwards and asks, removes the socket and launch agent, and
// offers to revoke the device.
//
// The manifest is the whole authority. There is no blind removal of a directory
// and no pattern matching over the filesystem: if totem did not record making a
// change, uninstall does not touch it.
func cmdUninstall(ctx context.Context, args []string) error {
	fs2 := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs2.SetOutput(os.Stderr)
	dryRun := fs2.Bool("dry-run", false, "show what would be undone without changing anything")
	yes := fs2.Bool("yes", false, "do not ask; assume yes for everything totem itself created")
	force := fs2.Bool("force", false, "also undo changes that were edited after totem made them")
	keepKey := fs2.Bool("keep-key", false, "leave this device's key in place")
	if err := fs2.Parse(args); err != nil {
		return failf("Run 'totem uninstall'.", "could not read those options.")
	}

	manifest, err := LoadManifest("")
	if err != nil {
		return err
	}
	if len(manifest.Changes) == 0 {
		fmt.Println("totem has no record of changing anything on this machine, so there is nothing to undo.")
		fmt.Println("Nothing was removed. That is deliberate: totem only undoes what it recorded doing.")
		return nil
	}

	plan := manifest.Reverse()
	fmt.Println("totem will undo exactly these, newest first:")
	for _, c := range plan {
		fmt.Printf("  %-8s %s\n", c.Kind, describeChange(c))
	}
	fmt.Println()

	if *dryRun {
		fmt.Println("Nothing was changed (--dry-run).")
		return nil
	}
	if !*yes && !confirm("Undo all of this?") {
		fmt.Println("Nothing was changed.")
		return nil
	}

	var edited []Change
	for _, c := range plan {
		status, err := reverseChange(ctx, c, *force, *keepKey)
		switch {
		case errors.Is(err, errChangedSinceTotem):
			edited = append(edited, c)
			fmt.Printf("  kept  %s (you edited this after totem wrote it)\n", describeChange(c))
			continue
		case err != nil:
			fmt.Printf("  !!    %s: %v\n", describeChange(c), err)
			continue
		}
		fmt.Printf("  %-5s %s\n", status, describeChange(c))
		manifest.Remove(c)
	}
	if err := manifest.Save(); err != nil {
		return err
	}

	fmt.Println()
	if len(edited) > 0 {
		fmt.Println("These were left alone because they changed after totem wrote them:")
		for _, c := range edited {
			fmt.Printf("  %s\n", describeChange(c))
		}
		fmt.Println("Look at them, and if you want them gone, run 'totem uninstall --force'.")
	}
	fmt.Println("Your issuer still has a record of this device.")
	fmt.Println("Ask whoever runs it to remove it, so nothing can be issued to it again.")
	clearLastError()
	return nil
}

// errChangedSinceTotem means the thing on disk is not what totem wrote, so
// uninstall refuses to remove it and shows it to the human instead.
var errChangedSinceTotem = errors.New("changed since totem wrote it")

// reverseChange undoes exactly one recorded change.
func reverseChange(ctx context.Context, c Change, force, keepKey bool) (string, error) {
	switch c.Kind {
	case ChangeFile:
		return removeRecordedFile(c, force)
	case ChangeBlock:
		return removeRecordedBlock(c, force)
	case ChangeSocket:
		return removeSocket(c)
	case ChangeLaunchd:
		return removeLaunchAgent(c, force)
	case ChangeSystemd:
		return removeSystemdUnit(c, force)
	case ChangeKey:
		if keepKey {
			return "kept", nil
		}
		return removeDeviceKey(ctx, c)
	case ChangeDir:
		return removeEmptyDir(c)
	default:
		return "", fmt.Errorf("totem does not know how to undo a %q change", c.Kind)
	}
}

// removeRecordedFile removes a file totem created, but only when it still holds
// exactly what totem wrote. A file the user edited afterwards is shown, not
// deleted.
func removeRecordedFile(c Change, force bool) (string, error) {
	data, err := os.ReadFile(c.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "gone", nil
	}
	if err != nil {
		return "", err
	}
	if !force && c.SHA256 != "" && hashBytes(data) != c.SHA256 {
		return "", errChangedSinceTotem
	}
	if err := os.Remove(c.Path); err != nil {
		return "", err
	}
	return "removed", nil
}

// removeRecordedBlock takes totem's marked block back out of a file totem does
// not own, leaving everything around it untouched.
func removeRecordedBlock(c Change, force bool) (string, error) {
	data, err := os.ReadFile(c.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "gone", nil
	}
	if err != nil {
		return "", err
	}
	block, without, found := extractBlock(string(data), c.Marker)
	if !found {
		return "gone", nil
	}
	if !force && c.SHA256 != "" && hashBytes([]byte(block)) != c.SHA256 {
		return "", errChangedSinceTotem
	}
	info, err := os.Stat(c.Path)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(c.Path, []byte(without), mode); err != nil {
		return "", err
	}
	return "restored", nil
}

// removeSocket removes the Workload API socket, and refuses while an agent is
// still serving on it: taking the socket out from under a running agent breaks
// every tool holding a stream open.
func removeSocket(c Change) (string, error) {
	fi, err := os.Lstat(c.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "gone", nil
	}
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return "", errChangedSinceTotem
	}
	if conn, derr := net.DialTimeout("unix", c.Path, 300*time.Millisecond); derr == nil {
		conn.Close()
		return "", errors.New("the agent is still running; stop it first, then run uninstall again")
	}
	if err := os.Remove(c.Path); err != nil {
		return "", err
	}
	return "removed", nil
}

// removeLaunchAgent unloads and removes a macOS launch agent totem installed.
func removeLaunchAgent(c Change, force bool) (string, error) {
	if runtime.GOOS == "darwin" && c.Label != "" {
		target := fmt.Sprintf("gui/%d/%s", os.Getuid(), c.Label)
		// A launch agent that is already unloaded makes bootout fail, which is
		// fine; the file removal below is what actually matters.
		_ = exec.Command("launchctl", "bootout", target).Run()
	}
	if c.Path == "" {
		return "removed", nil
	}
	return removeRecordedFile(Change{Kind: ChangeFile, Path: c.Path, SHA256: c.SHA256}, force)
}

// removeSystemdUnit disables and removes a Linux user unit totem installed.
func removeSystemdUnit(c Change, force bool) (string, error) {
	if runtime.GOOS == "linux" && c.Label != "" {
		_ = exec.Command("systemctl", "--user", "disable", "--now", c.Label).Run()
	}
	if c.Path == "" {
		return "removed", nil
	}
	return removeRecordedFile(Change{Kind: ChangeFile, Path: c.Path, SHA256: c.SHA256}, force)
}

// removeDeviceKey deletes exactly the key totem generated, by label, through
// the platform key store. It never enumerates or clears a key store.
func removeDeviceKey(ctx context.Context, c Change) (string, error) {
	if platform.Open == nil {
		return "", errors.New("this build cannot reach the place the key is kept; remove it by hand")
	}
	store, err := platform.Open(ctx)
	if err != nil {
		return "", err
	}
	if err := store.Delete(ctx, c.Label); err != nil {
		if errors.Is(err, platform.ErrKeyNotFound) {
			return "gone", nil
		}
		return "", err
	}
	return "removed", nil
}

// removeEmptyDir removes a directory totem created, and only when it is empty.
// This is the rule that keeps uninstall from ever being a recursive delete.
func removeEmptyDir(c Change) (string, error) {
	entries, err := os.ReadDir(c.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "gone", nil
	}
	if err != nil {
		return "", err
	}
	if len(entries) > 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return "kept", fmt.Errorf("%s still holds files totem did not create (%s); it was left alone",
			c.Path, strings.Join(names, ", "))
	}
	if err := os.Remove(c.Path); err != nil {
		return "", err
	}
	return "removed", nil
}

func describeChange(c Change) string {
	target := c.Path
	if target == "" {
		target = c.Label
	}
	if c.Describe != "" {
		return fmt.Sprintf("%s (%s)", c.Describe, filepath.Base(target))
	}
	return target
}

func confirm(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}
