package issuer

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/store"
)

// TestRestoreFromBackupOnAFreshBoxIsUnderTenMinutes is the step-2 gate's item
// 4, and the only one of the six with a real number attached:
// docs/totem-design.md's "Deployment and distribution" release gate is
// "issuer rebuilt from backup on a fresh box in under ten minutes, measured."
// That word -- measured -- is why this is a timed assertion with a logged
// duration, not a smoke test that only checks Restore returned nil.
//
// This drives the real store.DB end to end: a real SQLite file, real
// envelope encryption under a resolved data key, a real populated hash
// chain, a real encrypted-tarball Backup, and a real Restore onto a second,
// independently opened store.DB standing in for a fresh box -- the same
// entry point `totem issuer restore` would call. Only the timing budget
// (ten minutes) is asserted rather than measured against a second
// implementation, because there is no second implementation to compare
// against; the number itself, logged via t.Logf, is the evidence.
func TestRestoreFromBackupOnAFreshBoxIsUnderTenMinutes(t *testing.T) {
	ctx := context.Background()
	clk := newTestClock()

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatalf("generate data key: %v", err)
	}
	resolver := newFakeResolver(map[string][]byte{store.DataKeyRefName: dataKey})

	liveDir := t.TempDir()
	livePath := filepath.Join(liveDir, "state.db")
	db, err := store.Open(ctx, livePath, store.Options{Resolver: resolver, Clock: clk.Now})
	if err != nil {
		t.Fatalf("Open (live): %v", err)
	}

	// Populate a representative live issuer's worth of state -- several
	// enrolled devices and a few hundred chain records -- so backup and
	// restore are not timing an empty file.
	const devices = 5
	for i := 0; i < devices; i++ {
		id := fmt.Sprintf("device-%d", i)
		payload := []byte(fmt.Sprintf(`{"device_id":%q,"admin":false}`, id))
		if err := db.Put(ctx, "enrollments", id, payload); err != nil {
			t.Fatalf("Put(enrollments, %s): %v", id, err)
		}
	}
	const chainRecords = 300
	for i := 0; i < chainRecords; i++ {
		payload := []byte(fmt.Sprintf(`{"seq_hint":%d}`, i))
		if _, err := db.Append(ctx, store.Record{Kind: store.KindIssuance, Payload: payload}); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}

	okBefore, badSeqBefore, err := db.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify (live, before backup): %v", err)
	}
	if !okBefore {
		t.Fatalf("live database's chain does not verify before backup, first bad seq %d", badSeqBefore)
	}

	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		t.Fatalf("generate backup passphrase: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "issuer-backup.tgz")
	if err := db.Backup(ctx, backupPath, passphrase); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close (live): %v", err)
	}

	// "A fresh box": a brand-new, empty store at a different path -- exactly
	// what `issuer init` on replacement hardware produces before restore.
	freshDir := t.TempDir()
	freshPath := filepath.Join(freshDir, "state.db")
	fresh, err := store.Open(ctx, freshPath, store.Options{Resolver: resolver, Clock: clk.Now})
	if err != nil {
		t.Fatalf("Open (fresh box): %v", err)
	}
	defer fresh.Close()

	start := time.Now()
	if err := fresh.Restore(ctx, backupPath, passphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	elapsed := time.Since(start)
	t.Logf("restore from backup onto a fresh box took %s (%d chain records, %d enrollments)", elapsed, chainRecords, devices)
	if elapsed >= 10*time.Minute {
		t.Fatalf("restore took %s, want under the release gate's ten minutes", elapsed)
	}

	okAfter, badSeqAfter, err := fresh.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify (restored): %v", err)
	}
	if !okAfter {
		t.Fatalf("restored database's chain does not verify, first bad seq %d", badSeqAfter)
	}

	// Spot-check the data itself round-tripped, not just the chain's shape.
	for i := 0; i < devices; i++ {
		id := fmt.Sprintf("device-%d", i)
		want := []byte(fmt.Sprintf(`{"device_id":%q,"admin":false}`, id))
		got, err := fresh.Get(ctx, "enrollments", id)
		if err != nil {
			t.Errorf("Get(enrollments, %s) after restore: %v", id, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("restored enrollment %s = %q, want %q", id, got, want)
		}
	}
}

// TestRestoreRefusesAWrongPassphraseWithoutTouchingTheLiveDatabase covers the
// spec's ordering requirement directly: "Only after all of those pass is the
// live file replaced" (backup.go). A wrong passphrase must be refused before
// the live database is touched at all, so the live store keeps working
// exactly as it did before the failed restore attempt.
func TestRestoreRefusesAWrongPassphraseWithoutTouchingTheLiveDatabase(t *testing.T) {
	ctx := context.Background()
	clk := newTestClock()

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatalf("generate data key: %v", err)
	}
	resolver := newFakeResolver(map[string][]byte{store.DataKeyRefName: dataKey})

	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := store.Open(ctx, path, store.Options{Resolver: resolver, Clock: clk.Now})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if err := db.Put(ctx, "enrollments", "device-0", []byte("original")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rightPass := make([]byte, 32)
	rand.Read(rightPass)
	backupPath := filepath.Join(t.TempDir(), "backup.tgz")
	if err := db.Backup(ctx, backupPath, rightPass); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Change the live data after the backup, so a wrongly-successful restore
	// would be detectable: it would silently revert this.
	if err := db.Put(ctx, "enrollments", "device-0", []byte("changed-after-backup")); err != nil {
		t.Fatalf("Put (post-backup change): %v", err)
	}

	wrongPass := make([]byte, 32)
	rand.Read(wrongPass)
	if err := db.Restore(ctx, backupPath, wrongPass); err == nil {
		t.Fatal("Restore with the wrong passphrase succeeded, want a refusal")
	}

	got, err := db.Get(ctx, "enrollments", "device-0")
	if err != nil {
		t.Fatalf("Get after refused restore: %v", err)
	}
	if string(got) != "changed-after-backup" {
		t.Errorf("live data after a refused restore = %q, want the untouched post-backup value %q", got, "changed-after-backup")
	}
}
