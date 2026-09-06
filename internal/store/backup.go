package store

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupPassphraseRefName is the logical secret name the issuer's Summon config
// maps to the backup passphrase, alongside the names in docs/totem-design.md
// "Secrets". The passphrase is resolved through the provider, never typed, which
// is why MinPassphraseBytes can be a real minimum rather than a human one.
const BackupPassphraseRefName = "backup_passphrase"

// Backup container constants.
const (
	backupMagic     = "TOTEMBKP"
	backupVersion   = 1
	kdfPBKDF2SHA256 = 1

	// pbkdf2Iterations is the work factor written into new backups.
	pbkdf2Iterations = 600_000
	// minIterations and maxIterations bound the value read back OUT of a
	// backup file. The iteration count is attacker-controlled input that
	// directly chooses how much CPU the reader burns, so it is clamped, not
	// trusted.
	minIterations = 100_000
	maxIterations = 10_000_000

	// chunkPlainBytes is the plaintext size of each AEAD chunk.
	chunkPlainBytes = 1 << 20 // 1 MiB
	// gcmOverhead is AES-GCM's tag length.
	gcmOverhead = 16
	// maxChunkCipherBytes bounds a frame length read from the file, so a
	// corrupt or hostile length cannot choose an allocation.
	maxChunkCipherBytes = chunkPlainBytes + gcmOverhead

	// MinPassphraseBytes is the shortest backup passphrase accepted.
	MinPassphraseBytes = 16

	// maxManifestBytes and maxDatabaseBytes bound the tar entries a restore
	// will extract.
	maxManifestBytes = 1 << 20 // 1 MiB
	maxDatabaseBytes = 1 << 33 // 8 GiB

	manifestEntryName = "manifest.json"
	databaseEntryName = "state.db"

	aadBackupV1 = "totem/backup/v1"
)

// ErrBackupMalformed means a backup file is not a totem backup, is truncated,
// or has been altered. It is never worked around.
var ErrBackupMalformed = errors.New("store: backup file is malformed, truncated or not a totem backup")

// ErrBackupChainBroken means the backup's own hash chain does not verify. The
// restore is refused before the live database is touched: restoring tamper
// evidence into production and calling it recovery is worse than refusing.
var ErrBackupChainBroken = errors.New("store: the backup's hash chain does not verify; it will not be restored")

// ErrPassphraseTooShort means the Summon-resolved backup passphrase is shorter
// than MinPassphraseBytes.
var ErrPassphraseTooShort = errors.New("store: backup passphrase is shorter than the minimum")

// ErrBackupIsOlder means the backup's chain head is BEHIND the live chain's, so
// restoring it would roll the issuer back to an earlier state.
//
// This is refused because a rollback is the one attack the hash chain cannot
// see. Every record in an older chain was legitimately admin-signed, so it
// verifies perfectly; what is missing is the records that came after, and among
// those are revocations. Policy rebuilds authority by replaying the chain and
// keeps no separate record of what was revoked, so a chain rolled back past a
// revocation is a revoked device, admin or grant that works again. That would
// defeat the durable revocation the README promises on its first screen.
var ErrBackupIsOlder = errors.New("store: the backup is older than the live chain; restoring it would roll back revocations")

// ErrBackupDiverged means the backup is not an ancestor of the live chain: at
// the sequence where the two should agree, they carry different hashes.
//
// A backup and the database it is restored over should share history. One that
// does not is a different chain, which is a stronger signal than a plain
// rollback: something has been rewritten, or two issuers have been writing
// under one identity.
var ErrBackupDiverged = errors.New("store: the backup is not an ancestor of the live chain")

// manifest is the plaintext-inside-the-encryption description of a backup. It
// exists so a restore can refuse for a stated reason instead of failing partway
// through a database it has already swapped in.
type manifest struct {
	Format        int    `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	CreatedAt     string `json:"created_at"`
	DBSHA256      string `json:"db_sha256"`
	DBBytes       int64  `json:"db_bytes"`
	ChainHeadSeq  int64  `json:"chain_head_seq"`
	ChainHeadHash string `json:"chain_head_hash"`
	DataKeyGen    int64  `json:"data_key_gen"`
	IssuerVersion string `json:"issuer_version,omitempty"`
}

// Backup writes an encrypted tarball of the issuer's state to dst.
//
// It is `totem issuer backup` (docs/totem-design-decisions.md #9): "tarball
// encrypted under a Summon-resolved passphrase". The caller resolves the
// passphrase through the provider and passes the bytes; nothing here reads a
// file, a flag or an environment variable.
//
// The snapshot is taken with SQLite's VACUUM INTO, so it is a consistent
// point-in-time copy rather than a file read out from under live writes, and it
// carries no WAL to reconcile.
func (d *DB) Backup(ctx context.Context, dst string, passphrase []byte) error {
	if len(passphrase) < MinPassphraseBytes {
		return fmt.Errorf("%w: %d bytes, minimum is %d", ErrPassphraseTooShort, len(passphrase), MinPassphraseBytes)
	}
	if dst == "" {
		return fmt.Errorf("store: backup needs a destination path")
	}

	tmpDir, err := os.MkdirTemp(filepath.Dir(d.path), ".totem-backup-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	snapshot := filepath.Join(tmpDir, databaseEntryName)

	m, err := d.snapshot(ctx, snapshot)
	if err != nil {
		return err
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return err
	}

	tmpOut := dst + ".partial"
	out, err := os.OpenFile(tmpOut, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = out.Close()
		_ = os.Remove(tmpOut)
	}

	enc, err := newChunkWriter(out, passphrase)
	if err != nil {
		cleanup()
		return err
	}
	tw := tar.NewWriter(enc)
	if err := writeTarFile(tw, manifestEntryName, int64(len(mj)), m.CreatedAt, bytes.NewReader(mj)); err != nil {
		cleanup()
		return err
	}
	snap, err := os.Open(snapshot)
	if err != nil {
		cleanup()
		return err
	}
	if err := writeTarFile(tw, databaseEntryName, m.DBBytes, m.CreatedAt, snap); err != nil {
		_ = snap.Close()
		cleanup()
		return err
	}
	_ = snap.Close()
	if err := tw.Close(); err != nil {
		cleanup()
		return err
	}
	if err := enc.Close(); err != nil {
		cleanup()
		return err
	}
	// The backup is the thing an operator reaches for after losing a machine.
	// It is fsynced before it is named.
	if err := out.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpOut)
		return err
	}
	if err := os.Rename(tmpOut, dst); err != nil {
		_ = os.Remove(tmpOut)
		return err
	}
	return syncDir(filepath.Dir(dst))
}

// Restore replaces the issuer's state with the contents of an encrypted backup.
//
// What it refuses, and when:
//
//   - No Summon provider configured: ErrProviderNotConfigured, before it has
//     opened the backup file, let alone touched the live database. An operator
//     running restore has usually just lost a machine, and a restore that dies
//     halfway because it cannot reach the provider is worse than one that
//     refuses at the start (store.go, Backup).
//
//   - A passphrase shorter than MinPassphraseBytes, or one that does not
//     decrypt the file: ErrPassphraseTooShort or ErrBackupMalformed, before the
//     live database is touched.
//
//   - A backup written by a newer issuer: ErrSchemaAhead. Migrations are
//     forward-only, so there is no in-place downgrade to attempt.
//
//   - A backup whose database does not match the hash in its own manifest, or
//     whose hash chain does not verify: ErrBackupMalformed or
//     ErrBackupChainBroken.
//
//   - A backup whose data key generation the configured provider cannot open:
//     ErrDataKeyMismatch. This is checked against the extracted copy, so the
//     live database is still intact when it fires.
//
//   - A backup that would move the chain BACKWARDS, or that is not the live
//     chain's own history: ErrBackupIsOlder or ErrBackupDiverged.
//
// Only after all of those pass is the live file replaced, by rename, in one
// step.
//
// On restoring an older backup, carefully, because the obvious reassurance is
// only half true. A device ENROLLED after the backup is simply absent
// afterwards, so it fails cleanly and re-enrolls: that direction fails closed
// and is survivable by design (docs/totem-design-decisions.md #9). But a device,
// admin or grant REVOKED after the backup is also absent afterwards, and that
// direction fails OPEN: the revocation is undone and the subject works again.
// Policy replays the chain to rebuild authority and keeps no separate record of
// what was revoked, so nothing downstream notices.
//
// The hash chain cannot catch this. Every record in an older chain was
// legitimately admin-signed and verifies perfectly; the tampering is in what is
// MISSING, and a chain can only attest to what it contains. So the refusal is
// here instead, comparing the backup's chain head against the live one, which
// is the only place both are in hand at once.
//
// This closes the restore vector. It does not close the other half of the same
// weakness: an attacker with write access to the file who truncates the chain
// AND rewrites the recorded tip leaves no evidence inside the file at all. That
// needs a witness of Head the attacker does not control, kept off the box.
func (d *DB) Restore(ctx context.Context, src string, passphrase []byte) error {
	// Refuse before touching anything. This is the first statement in the
	// function on purpose.
	if err := checkProviderConfigured(d.opts); err != nil {
		return err
	}
	if len(passphrase) < MinPassphraseBytes {
		return fmt.Errorf("%w: %d bytes, minimum is %d", ErrPassphraseTooShort, len(passphrase), MinPassphraseBytes)
	}
	if src == "" {
		return fmt.Errorf("store: restore needs a source path")
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	stagingDir, err := os.MkdirTemp(filepath.Dir(d.path), ".totem-restore-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()

	dec, err := newChunkReader(in, passphrase)
	if err != nil {
		return err
	}
	m, staged, err := extractBackup(dec, stagingDir)
	if err != nil {
		return err
	}

	if m.SchemaVersion > schemaVersion {
		return fmt.Errorf("%w: the backup is at schema version %d, this binary understands %d", ErrSchemaAhead, m.SchemaVersion, schemaVersion)
	}
	sum, size, err := hashFile(staged)
	if err != nil {
		return err
	}
	if size != m.DBBytes || hex.EncodeToString(sum) != m.DBSHA256 {
		return fmt.Errorf("%w: the database in the backup does not match its manifest", ErrBackupMalformed)
	}

	// Prove the staged database is usable BEFORE the live one is replaced: the
	// schema migrates, the configured provider resolves a data key that opens
	// its active generation, and its hash chain verifies.
	staging, err := Open(ctx, staged, d.opts)
	if err != nil {
		return fmt.Errorf("store: the backup will not open with the configured provider: %w", err)
	}
	// Fold the staged WAL back into the file before it is moved: a rename that
	// leaves the sidecars behind would silently drop whatever the checkpoint
	// had not yet written.
	if _, err := staging.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = staging.Close()
		return fmt.Errorf("store: checkpointing the staged database: %w", err)
	}
	ok, badSeq, verr := staging.Verify(ctx)
	if verr != nil && !errors.Is(verr, ErrChainBroken) {
		_ = staging.Close()
		return verr
	}
	if !ok {
		_ = staging.Close()
		return fmt.Errorf("%w: first bad sequence is %d", ErrBackupChainBroken, badSeq)
	}
	// Swap. Everything that could refuse has already refused, except the one
	// question that can only be asked against the live database: is this backup
	// actually a later or equal state of the same chain?
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkNotARollback(ctx, m, staging); err != nil {
		_ = staging.Close()
		return err
	}
	if err := staging.Close(); err != nil {
		return err
	}
	if err := d.sql.Close(); err != nil {
		d.closed = true
		return fmt.Errorf("store: closing the live database before the swap: %w", err)
	}
	d.closed = true

	// The staged file was opened, so it has its own WAL sidecars; they were
	// checkpointed on close, and the live sidecars must not survive the swap.
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(d.path + suffix)
		_ = os.Remove(staged + suffix)
	}
	if err := os.Rename(staged, d.path); err != nil {
		return fmt.Errorf("store: replacing the live database: %w", err)
	}
	if err := syncDir(filepath.Dir(d.path)); err != nil {
		return err
	}

	sqlDB, err := openSQL(ctx, d.path)
	if err != nil {
		return err
	}
	d.sql = sqlDB
	d.closed = false
	if err := d.migrateLocked(ctx); err != nil {
		return err
	}
	return d.ensureActiveGenerationLocked(ctx)
}

// extractBackup reads the tar stream out of dec into dir, accepting exactly the
// two entries a totem backup contains.
//
// Every entry name is compared against a fixed list rather than sanitised, and
// every entry body is length-limited, so nothing in the archive can choose a
// path or an allocation. A tar with an unexpected entry, a duplicate, a
// directory, a symlink or a missing entry is malformed, not tolerated.
func extractBackup(dec io.Reader, dir string) (manifest, string, error) {
	var (
		m      manifest
		gotMan bool
		gotDB  bool
		dbPath = filepath.Join(dir, databaseEntryName)
	)
	tr := tar.NewReader(dec)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, "", fmt.Errorf("%w: %v", ErrBackupMalformed, err)
		}
		if h.Typeflag != tar.TypeReg {
			return m, "", fmt.Errorf("%w: entry %q is not a regular file", ErrBackupMalformed, h.Name)
		}
		switch h.Name {
		case manifestEntryName:
			if gotMan {
				return m, "", fmt.Errorf("%w: duplicate %s", ErrBackupMalformed, manifestEntryName)
			}
			if h.Size < 0 || h.Size > maxManifestBytes {
				return m, "", fmt.Errorf("%w: %s is %d bytes", ErrBackupMalformed, manifestEntryName, h.Size)
			}
			raw, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes+1))
			if err != nil {
				return m, "", fmt.Errorf("%w: %v", ErrBackupMalformed, err)
			}
			if len(raw) > maxManifestBytes {
				return m, "", fmt.Errorf("%w: %s exceeds %d bytes", ErrBackupMalformed, manifestEntryName, maxManifestBytes)
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				return m, "", fmt.Errorf("%w: %s: %v", ErrBackupMalformed, manifestEntryName, err)
			}
			gotMan = true
		case databaseEntryName:
			if gotDB {
				return m, "", fmt.Errorf("%w: duplicate %s", ErrBackupMalformed, databaseEntryName)
			}
			if h.Size < 0 || h.Size > maxDatabaseBytes {
				return m, "", fmt.Errorf("%w: %s is %d bytes", ErrBackupMalformed, databaseEntryName, h.Size)
			}
			f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return m, "", err
			}
			n, err := io.Copy(f, io.LimitReader(tr, maxDatabaseBytes+1))
			if err != nil {
				_ = f.Close()
				return m, "", fmt.Errorf("%w: %v", ErrBackupMalformed, err)
			}
			if n > maxDatabaseBytes {
				_ = f.Close()
				return m, "", fmt.Errorf("%w: %s exceeds %d bytes", ErrBackupMalformed, databaseEntryName, maxDatabaseBytes)
			}
			if err := f.Close(); err != nil {
				return m, "", err
			}
			gotDB = true
		default:
			return m, "", fmt.Errorf("%w: unexpected entry %q", ErrBackupMalformed, h.Name)
		}
	}
	if !gotMan || !gotDB {
		return m, "", fmt.Errorf("%w: the archive is missing %s or %s", ErrBackupMalformed, manifestEntryName, databaseEntryName)
	}
	if m.Format != backupVersion {
		return m, "", fmt.Errorf("%w: manifest format %d, this binary writes %d", ErrBackupMalformed, m.Format, backupVersion)
	}
	return m, dbPath, nil
}

func writeTarFile(tw *tar.Writer, name string, size int64, modTime string, r io.Reader) error {
	t, err := time.Parse(time.RFC3339Nano, modTime)
	if err != nil {
		t = time.Unix(0, 0).UTC()
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o600,
		Size:     size,
		ModTime:  t.UTC(),
		Format:   tar.FormatPAX,
	}); err != nil {
		return err
	}
	n, err := io.Copy(tw, r)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("store: %s changed size while being archived (%d, expected %d)", name, n, size)
	}
	return nil
}

// checkNotARollback refuses a restore that would move the chain backwards, or
// onto a chain that is not the live one's own history.
//
// It runs under the store's lock and re-reads the live head there, so a record
// appended while the backup was being decrypted cannot slip past the check.
//
// The ordinary case, restoring onto a fresh box after losing a machine, has a
// live head of zero and passes without comment. The refusal only fires when the
// database being replaced is ALREADY AHEAD of the backup, which is precisely
// the case where records would be lost, and an operator who genuinely wants
// that can restore into a fresh directory instead, which is the safer procedure
// anyway.
func (d *DB) checkNotARollback(ctx context.Context, m manifest, staging *DB) error {
	liveSeq, liveHash, err := readHead(ctx, d.sql)
	if err != nil {
		return err
	}
	if liveSeq == 0 {
		// An empty chain has nothing to roll back, so this is the fresh box the
		// restore path exists for.
		//
		// It is ALSO exactly what an attacker produces by deleting the database
		// before restoring an old backup, and this check cannot tell the two
		// apart. That is not an oversight to fix here: no check the issuer runs
		// against its own files can distinguish them, because the host holds
		// everything those files are made of. Catching it needs a value the
		// host cannot retract because it has already left the box, which is why
		// the witness is the fleet, and why it lands with the versioned agent
		// protocol rather than here (docs/totem-design.md, "Issuer (broker
		// box)").
		//
		// So: this branch closes the restore vector, not the rollback problem.
		return nil
	}
	backupHash, err := hex.DecodeString(m.ChainHeadHash)
	if err != nil {
		return fmt.Errorf("%w: chain head hash in the manifest: %v", ErrBackupMalformed, err)
	}

	switch {
	case m.ChainHeadSeq < liveSeq:
		return fmt.Errorf("%w: the backup ends at sequence %d, the live chain is at %d, so %d record(s) "+
			"would be discarded; any revocation among them would be undone. Restore into a fresh directory "+
			"if this rollback is deliberate",
			ErrBackupIsOlder, m.ChainHeadSeq, liveSeq, liveSeq-m.ChainHeadSeq)

	case m.ChainHeadSeq == liveSeq:
		if !bytes.Equal(backupHash, liveHash) {
			return fmt.Errorf("%w: both chains end at sequence %d but with different hashes", ErrBackupDiverged, liveSeq)
		}
		return nil

	default:
		// The backup is ahead. That is a legitimate restore, but only if the
		// live chain is genuinely its ancestor: the backup must carry the live
		// head's own hash at the live head's sequence.
		var atLive []byte
		err := staging.sql.QueryRowContext(ctx, `SELECT hash FROM chain WHERE seq = ?`, liveSeq).Scan(&atLive)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: the backup has no record at sequence %d, where the live chain ends",
				ErrBackupDiverged, liveSeq)
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(atLive, liveHash) {
			return fmt.Errorf("%w: at sequence %d the backup carries a different hash than the live chain",
				ErrBackupDiverged, liveSeq)
		}
		return nil
	}
}

// snapshot writes a consistent copy of the database to dst and returns the
// manifest describing it.
//
// SQLite's VACUUM INTO produces a point-in-time copy with no write-ahead log to
// reconcile, which is what makes a backup safe to take from a running issuer.
// The manifest is read under the same lock as the snapshot, so the head
// sequence and the data key generation it records are the ones actually in the
// file.
func (d *DB) snapshot(ctx context.Context, dst string) (manifest, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var m manifest
	if err := d.checkOpen(); err != nil {
		return m, err
	}
	// VACUUM INTO takes an expression, and the driver binds it as a parameter,
	// so the path never becomes SQL text.
	if _, err := d.sql.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return m, fmt.Errorf("store: snapshotting the database: %w", err)
	}
	schemaVer, err := userVersion(ctx, d.sql)
	if err != nil {
		return m, err
	}
	headSeq, headHash, err := readHead(ctx, d.sql)
	if err != nil {
		return m, err
	}
	g, err := activeGeneration(ctx, d.sql)
	if err != nil {
		return m, err
	}
	sum, size, err := hashFile(dst)
	if err != nil {
		return m, err
	}
	return manifest{
		Format:        backupVersion,
		SchemaVersion: schemaVer,
		CreatedAt:     d.opts.Clock().UTC().Format(time.RFC3339Nano),
		DBSHA256:      hex.EncodeToString(sum),
		DBBytes:       size,
		ChainHeadSeq:  headSeq,
		ChainHeadHash: hex.EncodeToString(headHash),
		DataKeyGen:    g.gen,
	}, nil
}

// hashFile returns a file's SHA-256 and its length.
func hashFile(path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), n, nil
}

// syncDir fsyncs a directory so a completed rename survives a power loss.
//
// A failure is not propagated: the rename is atomic either way, and some
// filesystems simply refuse fsync on a directory. This is belt, not braces.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_ = f.Sync()
	return nil
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
