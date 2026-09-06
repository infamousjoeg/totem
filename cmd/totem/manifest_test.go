package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func tempManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := LoadManifest(filepath.Join(t.TempDir(), "manifest.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	return m
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	m.RecordDir(dir, "the folder")
	m.RecordKey("totem-device-key", "this device's key")
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}

	back, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(back.Changes))
	}
	if back.Version != ManifestVersion {
		t.Errorf("version = %d, want %d", back.Version, ManifestVersion)
	}
}

func TestManifestOfAMachineTotemNeverTouched(t *testing.T) {
	m, err := LoadManifest(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("a machine totem never touched must not be an error: %v", err)
	}
	if len(m.Changes) != 0 {
		t.Error("an empty manifest must record nothing")
	}
}

func TestRecordIsIdempotent(t *testing.T) {
	m := tempManifest(t)
	m.RecordFile("/tmp/x", []byte("a"), "x")
	m.RecordFile("/tmp/x", []byte("b"), "x")
	if len(m.Changes) != 1 {
		t.Fatalf("re-recording the same path made %d entries, want 1", len(m.Changes))
	}
	if m.Changes[0].SHA256 != hashBytes([]byte("b")) {
		t.Error("re-recording did not update the hash")
	}
}

// TestUninstallRemovesOnlyWhatTotemWrote is the manifest's whole point: a file
// totem created and nobody edited is removed; the same file with one changed
// byte is kept and shown.
func TestUninstallRemovesOnlyWhatTotemWrote(t *testing.T) {
	dir := t.TempDir()
	untouched := filepath.Join(dir, "untouched")
	edited := filepath.Join(dir, "edited")
	content := []byte("totem wrote this\n")
	if err := os.WriteFile(untouched, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(edited, content, 0o600); err != nil {
		t.Fatal(err)
	}

	m := tempManifest(t)
	m.RecordFile(untouched, content, "a file totem wrote")
	m.RecordFile(edited, content, "a file totem wrote")

	if err := os.WriteFile(edited, []byte("the user changed this\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := removeRecordedFile(m.Changes[0], false); err != nil {
		t.Fatalf("removing an untouched file: %v", err)
	}
	if _, err := os.Stat(untouched); !os.IsNotExist(err) {
		t.Error("the untouched file was not removed")
	}

	_, err := removeRecordedFile(m.Changes[1], false)
	if !errors.Is(err, errChangedSinceTotem) {
		t.Fatalf("err = %v, want errChangedSinceTotem", err)
	}
	if _, err := os.Stat(edited); err != nil {
		t.Error("the edited file was removed anyway")
	}

	// --force is the deliberate override, and only that.
	if _, err := removeRecordedFile(m.Changes[1], true); err != nil {
		t.Fatalf("forced removal: %v", err)
	}
}

// TestUninstallNeverRecursivelyDeletes: a directory totem created is removed
// only when empty. Anything the user put inside it keeps the directory alive.
func TestUninstallNeverRecursivelyDeletes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "totem")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Change{Kind: ChangeDir, Path: dir}

	if _, err := removeEmptyDir(c); err == nil {
		t.Fatal("a non-empty directory was removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("the user's file inside was deleted")
	}

	if err := os.Remove(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := removeEmptyDir(c); err != nil {
		t.Fatalf("an empty directory should be removed: %v", err)
	}
}

// TestBlockRoundTrip covers the config-line case: totem adds a marked block to
// a file it does not own, and uninstall takes exactly that block back out.
func TestBlockRoundTrip(t *testing.T) {
	begin, end := BlockMarkers("aws")
	block := begin + "\n[profile totem]\ncredential_process = totem aws\n" + end
	original := "[default]\nregion = us-east-1\n"
	full := original + block + "\n[other]\nx = 1\n"

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatal(err)
	}
	m := tempManifest(t)
	m.RecordBlock(path, "aws", block, "an aws profile pointing at totem")

	if _, err := removeRecordedBlock(m.Changes[0], false); err != nil {
		t.Fatalf("removing the block: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := original + "[other]\nx = 1\n"
	if string(got) != want {
		t.Errorf("file after removing the block:\n%q\nwant:\n%q", got, want)
	}
}

func TestBlockThatTheUserEditedIsKept(t *testing.T) {
	begin, end := BlockMarkers("aws")
	block := begin + "\noriginal\n" + end
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("head\n"+block+"\ntail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := tempManifest(t)
	m.RecordBlock(path, "aws", block, "a block")

	edited := begin + "\nthe user changed this\n" + end
	if err := os.WriteFile(path, []byte("head\n"+edited+"\ntail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := removeRecordedBlock(m.Changes[0], false); !errors.Is(err, errChangedSinceTotem) {
		t.Fatalf("err = %v, want errChangedSinceTotem", err)
	}
}

func TestBlockAlreadyGoneIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("nothing of totem's here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := tempManifest(t)
	m.RecordBlock(path, "aws", "whatever", "a block")
	status, err := removeRecordedBlock(m.Changes[0], false)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if status != "gone" {
		t.Errorf("status = %q, want %q", status, "gone")
	}
}

// TestReverseIsNewestFirst: the directory created first is removed last, after
// everything inside it.
func TestReverseIsNewestFirst(t *testing.T) {
	m := tempManifest(t)
	m.RecordDir("/a", "first")
	m.RecordFile("/a/b", []byte("x"), "second")
	rev := m.Reverse()
	if len(rev) != 2 {
		t.Fatalf("got %d changes", len(rev))
	}
	if rev[0].Path != "/a/b" || rev[1].Path != "/a" {
		t.Errorf("reverse order = %v, %v; want the file before the directory", rev[0].Path, rev[1].Path)
	}
}
