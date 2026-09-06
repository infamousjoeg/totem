package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// docs/totem-design.md "Experience": init is reversible. It keeps a manifest of
// every config line it wrote, and `totem uninstall` diffs each surface against
// the manifest, restores lines that are unchanged, shows any line the user
// edited afterwards and asks. Nothing here ever removes a directory blind: the
// manifest is the whole authority on what totem is allowed to undo.

// ChangeKind is the kind of change one manifest entry records.
type ChangeKind string

const (
	// ChangeFile is a file totem created in full.
	ChangeFile ChangeKind = "file"
	// ChangeBlock is a marked block of lines totem added to a file it does
	// not own, such as a shell profile or an aws config.
	ChangeBlock ChangeKind = "block"
	// ChangeSocket is the Workload API socket.
	ChangeSocket ChangeKind = "socket"
	// ChangeLaunchd is a macOS launch agent totem installed.
	ChangeLaunchd ChangeKind = "launchd"
	// ChangeSystemd is a Linux user unit totem installed.
	ChangeSystemd ChangeKind = "systemd"
	// ChangeKey is a device key totem generated in a platform key store.
	ChangeKey ChangeKind = "key"
	// ChangeDir is a directory totem created. It is removed only when empty.
	ChangeDir ChangeKind = "dir"
)

// ManifestVersion is the on-disk format version.
const ManifestVersion = 1

// Change is one reversible thing totem did.
type Change struct {
	// Kind decides how uninstall reverses this change.
	Kind ChangeKind `json:"kind"`
	// Path is the file, socket, directory, or unit file this change touched.
	Path string `json:"path,omitempty"`
	// Label is the launchd label, systemd unit name, or key store label.
	Label string `json:"label,omitempty"`
	// SHA256 is the hex digest of exactly what totem wrote: the file's whole
	// content for ChangeFile, the inserted block for ChangeBlock. Uninstall
	// compares against it to tell "untouched since totem wrote it" from
	// "the user edited this afterwards".
	SHA256 string `json:"sha256,omitempty"`
	// Marker is the comment that brackets a ChangeBlock in a foreign file.
	Marker string `json:"marker,omitempty"`
	// Describe is the one plain sentence uninstall shows for this change.
	Describe string `json:"describe,omitempty"`
	// CreatedAt is when totem made the change.
	CreatedAt time.Time `json:"created_at"`
}

// Manifest is the ordered record of every change totem made. Uninstall replays
// it in reverse, so a directory created first is removed last, after everything
// inside it.
type Manifest struct {
	// Version is ManifestVersion.
	Version int `json:"version"`
	// Changes are in the order they were made.
	Changes []Change `json:"changes"`

	path string
}

// ManifestPath is ~/.totem/manifest.json.
func ManifestPath() string { return filepath.Join(totemDir(), "manifest.json") }

// LoadManifest reads the manifest, returning an empty one when totem has never
// changed anything on this machine.
func LoadManifest(path string) (*Manifest, error) {
	if path == "" {
		path = ManifestPath()
	}
	m := &Manifest{Version: ManifestVersion, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("the record of what totem changed at %s cannot be read: %w", path, err)
	}
	m.path = path
	return m, nil
}

// Save writes the manifest at 0600.
func (m *Manifest) Save() error {
	if m.path == "" {
		m.path = ManifestPath()
	}
	if m.Version == 0 {
		m.Version = ManifestVersion
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, append(data, '\n'), 0o600)
}

// Record appends a change, replacing any earlier entry for the same kind and
// path so a re-run of enroll does not stack duplicates.
func (m *Manifest) Record(c Change) {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	for i, existing := range m.Changes {
		if existing.Kind == c.Kind && existing.Path == c.Path && existing.Label == c.Label {
			m.Changes[i] = c
			return
		}
	}
	m.Changes = append(m.Changes, c)
}

// RecordFile records a file totem created, hashing the exact bytes it wrote.
func (m *Manifest) RecordFile(path string, content []byte, describe string) {
	m.Record(Change{Kind: ChangeFile, Path: path, SHA256: hashBytes(content), Describe: describe})
}

// RecordFileOnDisk records a file totem created by hashing what is on disk now.
// It is for files another part of totem wrote, such as the enrollment record.
func (m *Manifest) RecordFileOnDisk(path, describe string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m.RecordFile(path, data, describe)
	return nil
}

// RecordDir records a directory totem created. Uninstall removes it only when
// it is empty, never recursively.
func (m *Manifest) RecordDir(path, describe string) {
	m.Record(Change{Kind: ChangeDir, Path: path, Describe: describe})
}

// RecordKey records a device key totem generated, so uninstall can offer to
// delete exactly that key and no other.
func (m *Manifest) RecordKey(label, describe string) {
	m.Record(Change{Kind: ChangeKey, Label: label, Describe: describe})
}

// RecordSocket records the Workload API socket.
func (m *Manifest) RecordSocket(path, describe string) {
	m.Record(Change{Kind: ChangeSocket, Path: path, Describe: describe})
}

// RecordBlock records a block of lines totem added to a file it does not own.
// The marker brackets the block so uninstall can find it again even if the
// surrounding file moved, and the hash proves the block itself is untouched.
func (m *Manifest) RecordBlock(path, marker, block, describe string) {
	m.Record(Change{Kind: ChangeBlock, Path: path, Marker: marker, SHA256: hashBytes([]byte(block)), Describe: describe})
}

// Reverse returns the changes in the opposite order to the one they were made
// in, which is the order uninstall applies them: whatever was created last is
// removed first, so a directory recorded before its contents is removed after
// them. Ordering comes from the recorded sequence, not from the timestamps,
// because two changes made in the same microsecond must still unwind in the
// order they were made.
func (m *Manifest) Reverse() []Change {
	out := make([]Change, 0, len(m.Changes))
	for i := len(m.Changes) - 1; i >= 0; i-- {
		out = append(out, m.Changes[i])
	}
	return out
}

// Remove drops a change from the manifest once it has been reversed, so a
// partially completed uninstall can be resumed without redoing work.
func (m *Manifest) Remove(c Change) {
	for i, existing := range m.Changes {
		if existing.Kind == c.Kind && existing.Path == c.Path && existing.Label == c.Label {
			m.Changes = append(m.Changes[:i], m.Changes[i+1:]...)
			return
		}
	}
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// BlockMarkers are the comment lines that bracket a totem-managed block inside
// a file totem does not own.
func BlockMarkers(marker string) (string, string) {
	return "# >>> totem " + marker + " >>>", "# <<< totem " + marker + " <<<"
}

// extractBlock returns the totem-managed block from content, and the content
// with that block removed. found is false when the markers are absent, which
// means the user already took the block out by hand.
func extractBlock(content, marker string) (block, without string, found bool) {
	begin, end := BlockMarkers(marker)
	lines := strings.Split(content, "\n")
	start, stop := -1, -1
	for i, l := range lines {
		switch strings.TrimSpace(l) {
		case begin:
			if start == -1 {
				start = i
			}
		case end:
			if start != -1 && stop == -1 {
				stop = i
			}
		}
	}
	if start == -1 || stop == -1 || stop < start {
		return "", content, false
	}
	block = strings.Join(lines[start:stop+1], "\n")
	remaining := append(append([]string{}, lines[:start]...), lines[stop+1:]...)
	return block, strings.Join(remaining, "\n"), true
}
