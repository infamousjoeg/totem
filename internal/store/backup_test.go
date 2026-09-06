package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testPassphrase = []byte("a-summon-resolved-backup-passphrase")

func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	want := populate(t, d, 50)
	mustPut(t, d, CollectionSecrets, "github.refresh", []byte("ghr_rotating_secret"))
	seedChain(t, d, 120)
	headSeq, headHash, err := d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}

	archive := dir + "/totem-backup.tar.enc"
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// A backup is a file an operator moves off the box; it must not be readable.
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ghr_rotating_secret")) {
		t.Fatal("a secret is readable in the backup file")
	}
	if bytes.Contains(raw, key) {
		t.Fatal("the data key is present in the backup file")
	}

	// Restore onto a fresh box: a brand new database file, same provider.
	fresh := t.TempDir()
	box, err := Open(ctx, fresh+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	if err := box.Restore(ctx, archive, testPassphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	checkAll(t, box, want)
	if got := mustGet(t, box, CollectionSecrets, "github.refresh"); string(got) != "ghr_rotating_secret" {
		t.Fatalf("restored secret = %q", got)
	}
	if ok, bad, err := box.Verify(ctx); !ok || err != nil {
		t.Fatalf("Verify after restore: ok=%v bad=%d err=%v", ok, bad, err)
	}
	seq, hash, err := box.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if seq != headSeq || !bytes.Equal(hash, headHash) {
		t.Fatalf("restored head = %d/%x, want %d/%x", seq, hash, headSeq, headHash)
	}

	// The restored store is live, not read-only: the chain continues from where
	// the backup left off.
	if _, err := box.Append(ctx, Record{Kind: KindIssuance, Payload: []byte("after restore")}); err != nil {
		t.Fatalf("Append after restore: %v", err)
	}
	if ok, _, err := box.Verify(ctx); !ok || err != nil {
		t.Fatalf("Verify after appending to a restored chain: %v", err)
	}
}

// TestRestoreOfAnOlderBackupFailsCleanly is the survivability the spec promises:
// "Restore from an older backup is survivable: devices enrolled after the backup
// fail cleanly and re-enroll" (docs/totem-design-decisions.md #9).
//
// It restores onto a FRESH box, which is both the real procedure after losing a
// machine and the only place an older backup is accepted: restoring one in
// place is refused, because the same missing records that make a later
// enrollment vanish would make a later REVOCATION vanish too. See
// TestRestoreRefusesToUndoARevocation for that half.
//
// The store's share of the promise is that the later device is simply ABSENT,
// so a caller gets ErrNotFound and can tell it to enroll again, rather than a
// stale row that silently still works.
func TestRestoreOfAnOlderBackupFailsCleanly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}

	mustPut(t, d, CollectionEnrollments, "device-before", []byte("enrolled early"))
	if _, err := d.Append(ctx, Record{Kind: KindPolicy, Payload: []byte("approve device-before")}); err != nil {
		t.Fatal(err)
	}
	archive := dir + "/backup.enc"
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}

	// Life goes on after the backup.
	mustPut(t, d, CollectionEnrollments, "device-after", []byte("enrolled later"))
	if _, err := d.Append(ctx, Record{Kind: KindPolicy, Payload: []byte("approve device-after")}); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// The machine is lost. A new box, and the backup is all there is.
	box, err := Open(ctx, t.TempDir()+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()
	if err := box.Restore(ctx, archive, testPassphrase); err != nil {
		t.Fatalf("Restore onto a fresh box: %v", err)
	}

	if got := mustGet(t, box, CollectionEnrollments, "device-before"); string(got) != "enrolled early" {
		t.Fatalf("the earlier device did not survive the restore: %q", got)
	}
	_, err = box.Get(ctx, CollectionEnrollments, "device-after")
	wantErrIs(t, err, ErrNotFound, "a device enrolled after the backup")

	// And the chain is the backup's chain, intact, with no trace of the later
	// records grafted on.
	if ok, bad, err := box.Verify(ctx); !ok || err != nil {
		t.Fatalf("Verify after restoring an older backup: ok=%v bad=%d err=%v", ok, bad, err)
	}
	if seq, _, err := box.Head(ctx); err != nil || seq != 1 {
		t.Fatalf("restored head = %d, want 1", seq)
	}
}

// TestRestoreRefusesBeforeTouchingAnything walks the refusals. Every case must
// leave the live database exactly as it was, because an operator running restore
// has usually just lost a machine.
func TestRestoreRefusesBeforeTouchingAnything(t *testing.T) {
	ctx := context.Background()
	key := testKey(0x11)

	// One good backup, reused by the cases that corrupt a copy of it.
	srcDir := t.TempDir()
	src, err := Open(ctx, srcDir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, src, CollectionEnrollments, "device-01", []byte("from the backup"))
	seedChain(t, src, 5)
	goodArchive := srcDir + "/good.enc"
	if err := src.Backup(ctx, goodArchive, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(goodArchive)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		resolver   func() Options
		archive    func(t *testing.T, dir string) string
		passphrase []byte
		want       error
	}{
		{
			name:       "no resolver at all",
			resolver:   func() Options { return Options{} },
			passphrase: testPassphrase,
			want:       ErrProviderNotConfigured,
		},
		{
			name:       "no Summon provider configured",
			resolver:   func() Options { return Options{Resolver: unconfiguredResolver{}} },
			passphrase: testPassphrase,
			want:       ErrProviderNotConfigured,
		},
		{
			name:       "passphrase below the minimum",
			passphrase: []byte("short"),
			want:       ErrPassphraseTooShort,
		},
		{
			name:       "wrong passphrase",
			passphrase: []byte("the-wrong-summon-resolved-passphrase"),
			want:       ErrBackupMalformed,
		},
		{
			name: "not a totem backup",
			archive: func(t *testing.T, dir string) string {
				return writeArchive(t, dir, bytes.Repeat([]byte("not a backup "), 100))
			},
			want: ErrBackupMalformed,
		},
		{
			name: "header truncated",
			archive: func(t *testing.T, dir string) string {
				return writeArchive(t, dir, good[:backupHeaderLen-1])
			},
			want: ErrBackupMalformed,
		},
		{
			name: "tail truncated",
			archive: func(t *testing.T, dir string) string {
				return writeArchive(t, dir, good[:len(good)-64])
			},
			want: ErrBackupMalformed,
		},
		{
			name: "a ciphertext byte flipped",
			archive: func(t *testing.T, dir string) string {
				bad := bytes.Clone(good)
				bad[len(bad)-20] ^= 0x01
				return writeArchive(t, dir, bad)
			},
			want: ErrBackupMalformed,
		},
		{
			name: "the salt in the header altered",
			archive: func(t *testing.T, dir string) string {
				bad := bytes.Clone(good)
				bad[20] ^= 0xff // inside the salt
				return writeArchive(t, dir, bad)
			},
			want: ErrBackupMalformed,
		},
		{
			name: "the iteration count raised beyond the accepted range",
			archive: func(t *testing.T, dir string) string {
				bad := bytes.Clone(good)
				copy(bad[10:14], be32(uint32(maxIterations+1)))
				return writeArchive(t, dir, bad)
			},
			want: ErrBackupMalformed,
		},
		{
			name: "bytes appended after the final chunk",
			archive: func(t *testing.T, dir string) string {
				return writeArchive(t, dir, append(bytes.Clone(good), 0x00, 0x01, 0x02))
			},
			want: ErrBackupMalformed,
		},
		{
			name: "the provider no longer holds the data key the backup was written under",
			resolver: func() Options {
				return Options{Resolver: newFakeResolver(testKey(0x99))}
			},
			passphrase: testPassphrase,
			want:       ErrDataKeyMismatch,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := Options{Resolver: newFakeResolver(key)}
			if c.resolver != nil {
				opts = c.resolver()
			}
			live, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = live.Close() }()
			mustPut(t, live, CollectionEnrollments, "live-device", []byte("still here"))
			seedChain(t, live, 3)
			live.opts = opts

			archive := goodArchive
			if c.archive != nil {
				archive = c.archive(t, dir)
			}
			pass := c.passphrase
			if pass == nil {
				pass = testPassphrase
			}

			err = live.Restore(ctx, archive, pass)
			wantErrIs(t, err, c.want, "Restore")

			// The live database is untouched: same rows, same chain, still open.
			live.opts = Options{Resolver: newFakeResolver(key), DataKeyRef: DataKeyRefName, Clock: time.Now}
			if got, gerr := live.Get(ctx, CollectionEnrollments, "live-device"); gerr != nil || string(got) != "still here" {
				t.Fatalf("the live database was damaged by a refused restore: %q %v", got, gerr)
			}
			if _, gerr := live.Get(ctx, CollectionEnrollments, "device-01"); gerr == nil {
				t.Fatal("a refused restore still imported rows from the backup")
			}
			if ok, _, verr := live.Verify(ctx); !ok || verr != nil {
				t.Fatalf("the live chain was damaged by a refused restore: %v", verr)
			}
			if seq, _, herr := live.Head(ctx); herr != nil || seq != 3 {
				t.Fatalf("the live chain head moved to %d", seq)
			}
		})
	}
}

func TestRestoreRefusesABackupFromANewerIssuer(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	mustPut(t, d, CollectionEnrollments, "device-01", []byte("x"))
	// A file written by a newer issuer. Migrations are forward-only, so the
	// answer is a refusal that says restore a different backup, not a downgrade.
	execSQL(t, d, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion+3))

	archive := dir + "/newer.enc"
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}
	execSQL(t, d, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))

	err = d.Restore(ctx, archive, testPassphrase)
	wantErrIs(t, err, ErrSchemaAhead, "Restore of a newer backup")
}

func TestRestoreRefusesABackupWithABrokenChain(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	seedChain(t, d, 20)
	// Tamper, then back up the tampered state. Restoring tamper evidence into
	// production and calling it recovery would be worse than refusing.
	execSQL(t, d, `UPDATE chain SET payload = ? WHERE seq = 9`, []byte("widened"))

	archive := dir + "/tampered.enc"
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}
	err = d.Restore(ctx, archive, testPassphrase)
	wantErrIs(t, err, ErrBackupChainBroken, "Restore of a tampered backup")
}

func TestBackupRefusesAShortPassphrase(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	err := d.Backup(ctx, t.TempDir()+"/b.enc", []byte("tooshort"))
	wantErrIs(t, err, ErrPassphraseTooShort, "Backup")
}

func TestBackupLeavesNoPartialFileBehind(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	d, _ := openTestStore(t)
	dst := dir + "/b.enc"
	if err := d.Backup(ctx, dst, testPassphrase); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".partial" {
			t.Fatalf("a partial backup was left behind: %s", e.Name())
		}
	}
	if fi, err := os.Stat(dst); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode is %v, want 0600", fi.Mode().Perm())
	}
}

// TestBackupOfALargeDatabaseSpansChunks pushes past a single AEAD chunk so the
// framing, the per-chunk nonces and the final-chunk flag are exercised for real
// rather than only on a one-chunk file.
func TestBackupOfALargeDatabaseSpansChunks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)
	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	// Several megabytes of rows: comfortably more than one 1 MiB chunk.
	blob := bytes.Repeat([]byte{0x5A}, 64*1024)
	for i := 0; i < 80; i++ {
		mustPut(t, d, CollectionSecrets, fmt.Sprintf("blob-%03d", i), blob)
	}
	archive := dir + "/big.enc"
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	} else if fi.Size() < 3*chunkPlainBytes {
		t.Fatalf("backup is %d bytes; the test is not spanning chunks", fi.Size())
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	fresh, err := Open(ctx, t.TempDir()+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if err := fresh.Restore(ctx, archive, testPassphrase); err != nil {
		t.Fatalf("Restore of a multi-chunk backup: %v", err)
	}
	for i := 0; i < 80; i++ {
		if got := mustGet(t, fresh, CollectionSecrets, fmt.Sprintf("blob-%03d", i)); !bytes.Equal(got, blob) {
			t.Fatalf("blob-%03d did not survive the round trip", i)
		}
	}
}

// TestRestoreOnAFreshBoxMeetsTheTenMinuteGate is a release gate, so it is
// measured rather than asserted in prose: "Ten-minute restore on a fresh box".
//
// It builds an issuer's worth of state, backs it up, and restores it into a
// database that has never seen any of it, timing only the restore, exactly the
// step an operator is waiting on after losing a machine. The restore includes
// key derivation, decryption, extraction, the manifest hash check, schema
// migration, the data key check and a full chain verification.
//
// The default size keeps the everyday suite fast. RELEASE runs set
// TOTEM_RESTORE_GATE_RECORDS to the size the gate is actually claimed at; the
// test logs the variable and the measurement on every run, so the number in CI
// output is always the number that was measured rather than one someone
// remembered.
func TestRestoreOnAFreshBoxMeetsTheTenMinuteGate(t *testing.T) {
	const gate = 10 * time.Minute

	records := 8000
	if v := os.Getenv("TOTEM_RESTORE_GATE_RECORDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("TOTEM_RESTORE_GATE_RECORDS: %v", err)
		}
		records = n
	}
	devices := records / 100
	if devices < 25 {
		devices = 25
	}

	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	want := populate(t, d, devices)
	for i := 0; i < records; i++ {
		if _, err := d.Append(ctx, Record{
			Kind:    KindIssuance,
			Payload: []byte(`{"spiffe_id":"spiffe://issuer.example/device/d1/tool/claude","presence":"present","outcome":"ok"}`),
		}); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	archive := dir + "/gate.enc"
	backupStart := time.Now()
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}
	backupTook := time.Since(backupStart)
	dbSize := statSize(t, d.Path())
	archiveSize := statSize(t, archive)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh box: a new directory, a database that has never held any of this.
	box, err := Open(ctx, t.TempDir()+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = box.Close() }()

	start := time.Now()
	if err := box.Restore(ctx, archive, testPassphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	took := time.Since(start)

	// The restore is only done if the state is actually usable.
	checkAll(t, box, want)
	if ok, bad, err := box.Verify(ctx); !ok || err != nil {
		t.Fatalf("Verify after restore: ok=%v bad=%d err=%v", ok, bad, err)
	}
	if seq, _, err := box.Head(ctx); err != nil || seq != int64(records) {
		t.Fatalf("restored head = %d, want %d", seq, records)
	}

	t.Logf("restore gate: restored %d chain records and %d devices (%d-byte database, %d-byte archive) in %v, against a %v gate; backup took %v. "+
		"Re-run at release scale with TOTEM_RESTORE_GATE_RECORDS=<n> (this run: %d).",
		records, devices, dbSize, archiveSize, took.Round(time.Millisecond), gate,
		backupTook.Round(time.Millisecond), records)
	if took > gate {
		t.Fatalf("restore took %v, over the %v release gate", took, gate)
	}
}

func statSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func writeArchive(t *testing.T, dir string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, "archive.enc")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRestoreRefusesToUndoARevocation is the security property, not the
// mechanism: the reviewer's scenario, run end to end.
//
// A device is revoked AFTER a backup is taken. Restoring that backup would
// remove the revocation record, and because policy rebuilds authority by
// replaying the chain and keeps no separate record of what was revoked, the
// device would be live again. The chain cannot object: every record in the
// older chain is legitimately signed. The store refuses instead.
func TestRestoreRefusesToUndoARevocation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	// A device is enrolled and approved.
	mustPut(t, d, CollectionEnrollments, "device-01", []byte(`{"admin":true}`))
	if _, err := d.Append(ctx, Record{Kind: KindPolicy, Payload: []byte(`{"action":"approve","device":"device-01"}`)}); err != nil {
		t.Fatal(err)
	}
	archive := dir + "/before-the-revoke.enc"
	if err := d.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}

	// Then it is revoked. This is the record an attacker wants gone.
	if _, err := d.Append(ctx, Record{Kind: KindPolicy, Payload: []byte(`{"action":"revoke","device":"device-01"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, CollectionEnrollments, "device-01"); err != nil {
		t.Fatal(err)
	}
	headSeq, headHash, err := d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = d.Restore(ctx, archive, testPassphrase)
	wantErrIs(t, err, ErrBackupIsOlder, "restoring a backup taken before a revocation")
	if !strings.Contains(err.Error(), "revocation") {
		t.Errorf("the refusal should say what is at stake: %v", err)
	}

	// The revocation still stands and the live chain is untouched.
	if _, gerr := d.Get(ctx, CollectionEnrollments, "device-01"); !errors.Is(gerr, ErrNotFound) {
		t.Fatal("the revoked device came back")
	}
	seq, hash, err := d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if seq != headSeq || !bytes.Equal(hash, headHash) {
		t.Fatalf("the live chain moved: %d/%x, want %d/%x", seq, hash, headSeq, headHash)
	}
	if ok, _, verr := d.Verify(ctx); !ok || verr != nil {
		t.Fatalf("the live chain was damaged by a refused restore: %v", verr)
	}
}

// TestRestoreRollbackGate walks the four relationships a backup can have with
// the database it is restored over.
func TestRestoreRollbackGate(t *testing.T) {
	ctx := context.Background()
	key := testKey(0x11)

	cases := []struct {
		name string
		// setup returns the archive to restore and the live store to restore onto.
		setup func(t *testing.T, dir string) (*DB, string)
		want  error
	}{
		{
			name: "onto a fresh box, the case restore exists for",
			setup: func(t *testing.T, dir string) (*DB, string) {
				src, err := Open(ctx, dir+"/src.db", Options{Resolver: newFakeResolver(key)})
				if err != nil {
					t.Fatal(err)
				}
				seedChain(t, src, 10)
				mustPut(t, src, CollectionEnrollments, "device-01", []byte("x"))
				archive := dir + "/a.enc"
				if err := src.Backup(ctx, archive, testPassphrase); err != nil {
					t.Fatal(err)
				}
				_ = src.Close()
				fresh, err := Open(ctx, dir+"/fresh.db", Options{Resolver: newFakeResolver(key)})
				if err != nil {
					t.Fatal(err)
				}
				return fresh, archive
			},
			want: nil,
		},
		{
			name: "onto the exact state it was taken from",
			setup: func(t *testing.T, dir string) (*DB, string) {
				d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
				if err != nil {
					t.Fatal(err)
				}
				seedChain(t, d, 10)
				archive := dir + "/a.enc"
				if err := d.Backup(ctx, archive, testPassphrase); err != nil {
					t.Fatal(err)
				}
				return d, archive
			},
			want: nil,
		},
		{
			name: "older than the live chain",
			setup: func(t *testing.T, dir string) (*DB, string) {
				d, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
				if err != nil {
					t.Fatal(err)
				}
				seedChain(t, d, 10)
				archive := dir + "/a.enc"
				if err := d.Backup(ctx, archive, testPassphrase); err != nil {
					t.Fatal(err)
				}
				seedChain(t, d, 5) // the chain moves on
				return d, archive
			},
			want: ErrBackupIsOlder,
		},
		{
			name: "same length, different history",
			setup: func(t *testing.T, dir string) (*DB, string) {
				// Two independent chains of equal length: a fork, which is a
				// stronger signal than a plain rollback.
				a, err := Open(ctx, dir+"/a.db", Options{Resolver: newFakeResolver(key)})
				if err != nil {
					t.Fatal(err)
				}
				seedChain(t, a, 10)
				archive := dir + "/a.enc"
				if err := a.Backup(ctx, archive, testPassphrase); err != nil {
					t.Fatal(err)
				}
				_ = a.Close()

				b, err := Open(ctx, dir+"/b.db", Options{Resolver: newFakeResolver(key)})
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 10; i++ {
					if _, err := b.Append(ctx, Record{Kind: KindExchange, Payload: []byte("a different history")}); err != nil {
						t.Fatal(err)
					}
				}
				return b, archive
			},
			want: ErrBackupDiverged,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			live, archive := c.setup(t, dir)
			defer func() { _ = live.Close() }()

			beforeSeq, beforeHash, err := live.Head(ctx)
			if err != nil {
				t.Fatal(err)
			}

			err = live.Restore(ctx, archive, testPassphrase)
			if c.want == nil {
				if err != nil {
					t.Fatalf("Restore: %v", err)
				}
				if ok, _, verr := live.Verify(ctx); !ok || verr != nil {
					t.Fatalf("Verify after restore: %v", verr)
				}
				return
			}

			wantErrIs(t, err, c.want, "Restore")
			seq, hash, herr := live.Head(ctx)
			if herr != nil {
				t.Fatal(herr)
			}
			if seq != beforeSeq || !bytes.Equal(hash, beforeHash) {
				t.Fatalf("a refused restore moved the live chain to %d, was %d", seq, beforeSeq)
			}
		})
	}
}

// TestTheEscapeHatchTheRefusalNamesActuallyWorks follows the refusal's own
// instructions. ErrBackupIsOlder tells an operator to restore into a fresh
// directory if the rollback is deliberate; a refusal that names a procedure
// nobody has run is a support incident waiting to happen, so this runs it.
func TestTheEscapeHatchTheRefusalNamesActuallyWorks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := testKey(0x11)

	live, err := Open(ctx, dir+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()

	mustPut(t, live, CollectionEnrollments, "device-01", []byte("from the backup"))
	seedChain(t, live, 4)
	archive := dir + "/older.enc"
	if err := live.Backup(ctx, archive, testPassphrase); err != nil {
		t.Fatal(err)
	}
	seedChain(t, live, 6) // the live chain moves past the backup

	// In place: refused, and the message names the way out.
	err = live.Restore(ctx, archive, testPassphrase)
	wantErrIs(t, err, ErrBackupIsOlder, "an in-place rollback")
	if !strings.Contains(err.Error(), "fresh directory") {
		t.Fatalf("the refusal should name the escape hatch: %v", err)
	}

	// Now do exactly what it says. This is the whole point of the test: the
	// deliberate rollback is possible, it just cannot happen by accident or in
	// silence.
	fresh, err := Open(ctx, t.TempDir()+"/state.db", Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if err := fresh.Restore(ctx, archive, testPassphrase); err != nil {
		t.Fatalf("the procedure the refusal names does not work: %v", err)
	}

	if got := mustGet(t, fresh, CollectionEnrollments, "device-01"); string(got) != "from the backup" {
		t.Fatalf("the rolled-back state is not usable: %q", got)
	}
	if ok, bad, verr := fresh.Verify(ctx); !ok || verr != nil {
		t.Fatalf("Verify after the deliberate rollback: ok=%v bad=%d err=%v", ok, bad, verr)
	}
	if seq, _, herr := fresh.Head(ctx); herr != nil || seq != 4 {
		t.Fatalf("rolled-back head = %d, want 4", seq)
	}
	// And it is a live store, not a museum piece.
	if _, aerr := fresh.Append(ctx, Record{Kind: KindIssuance, Payload: []byte("after the rollback")}); aerr != nil {
		t.Fatalf("Append after the deliberate rollback: %v", aerr)
	}
	if ok, _, verr := fresh.Verify(ctx); !ok || verr != nil {
		t.Fatalf("Verify after appending: %v", verr)
	}
}
