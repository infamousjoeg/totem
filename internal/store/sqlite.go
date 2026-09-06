// Package store's SQLite implementation. See store.go for the frozen contract.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/infamousjoeg/totem/internal/summon"

	_ "modernc.org/sqlite" // pure-Go driver: the issuer container carries no cgo
)

// driverName is modernc.org/sqlite's registered name. It is pure Go, so the
// issuer image needs no C toolchain and cross-compiles for the broker box
// (docs/totem-design-decisions.md #21, "cgo on macOS only").
const driverName = "sqlite"

// DataKeyRefName is the logical secret name the issuer's Summon config maps to
// the store's data key, alongside the names in docs/totem-design.md "Secrets".
const DataKeyRefName = "data_key"

// Options configures Open.
type Options struct {
	// Resolver is how the data key enters the process. It is required: the spec
	// allows no plaintext path, no key flag, no environment variable and no dev
	// mode, so a store with no resolver is not a degraded store, it is an
	// impossible one.
	Resolver summon.Resolver
	// DataKeyRef is the reference Resolver resolves to the raw data key. It
	// defaults to DataKeyRefName.
	DataKeyRef summon.Reference
	// Clock is the time source, injectable for tests. Defaults to time.Now.
	Clock func() time.Time
}

// DB is the SQLite-backed Store and Backup. One file, forward-only migrations
// run on open, rows envelope-encrypted under a Summon-resolved data key.
type DB struct {
	// mu serialises everything. The issuer serves one human and their devices,
	// so contention is not the constraint; a transaction that is never
	// interleaved with another writer is.
	mu   sync.Mutex
	sql  *sql.DB
	path string
	opts Options

	closed bool
}

var (
	_ Store  = (*DB)(nil)
	_ Backup = (*DB)(nil)
)

// Open opens or creates the issuer's state file, runs forward-only migrations,
// and establishes the active data key generation.
//
// It fails rather than degrades in three ways that matter: no Summon resolver
// configured is ErrProviderNotConfigured, a file from a newer issuer is
// ErrSchemaAhead, and a resolved data key that does not match the file's active
// generation is ErrDataKeyMismatch. None of the three is recoverable by
// guessing, so none of them is guessed at.
func Open(ctx context.Context, path string, opts Options) (*DB, error) {
	if opts.DataKeyRef == "" {
		opts.DataKeyRef = summon.Reference(DataKeyRefName)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if err := checkProviderConfigured(opts); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("store: open needs a database path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	sqlDB, err := openSQL(ctx, abs)
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", abs, err)
	}

	d := &DB{sql: sqlDB, path: abs, opts: opts}
	if err := d.Migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	if err := d.ensureActiveGeneration(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// openSQL opens the driver handle with the store's pragmas and one connection.
// WAL would allow concurrent readers, but a single connection removes
// SQLITE_BUSY as a category rather than tuning around it, and the issuer's
// write path is one human's devices.
func openSQL(ctx context.Context, abs string) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsn(abs))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// dsn builds the driver DSN. synchronous=FULL because this file is the record
// of which devices may exist; a fast fsync is not worth an enrollment that
// survives a crash only sometimes.
func dsn(abs string) string {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Set("_txlock", "immediate")
	return "file:" + abs + "?" + q.Encode()
}

// checkProviderConfigured is the single place that decides whether a Summon
// provider is usable, so Open and Restore cannot drift on the question.
func checkProviderConfigured(opts Options) error {
	if opts.Resolver == nil {
		return fmt.Errorf("%w: no resolver", ErrProviderNotConfigured)
	}
	ref := opts.DataKeyRef
	if ref == "" {
		ref = summon.Reference(DataKeyRefName)
	}
	found := false
	for _, name := range opts.Resolver.Refs() {
		if name == string(ref) || name == DataKeyRefName {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: no reference configured for %q", ErrProviderNotConfigured, ref)
	}

	// The data key must be declared as sealing material at rest, and the store
	// refuses to open behind one that is not.
	//
	// This store is the reason that declaration exists. The data key seals rows
	// on disk that Summon has no way to re-seal, so pull-rotating it is not a
	// rotation, it is a delayed brick: the running issuer breaks on its next
	// read, and a restarted one finds every row wrapped under a value nobody
	// kept. Rotating it is a two-part operation instead, RotateDataKey here
	// followed by the provider being told the reseal happened, and refusing the
	// wrong declaration at open is what keeps the two parts from drifting.
	rot, err := opts.Resolver.RotationOf(ref)
	if err != nil {
		return fmt.Errorf("%w: rotation shape of %q: %v", ErrProviderNotConfigured, ref, err)
	}
	if rot != summon.RotationSealsDataAtRest {
		return fmt.Errorf("%w: %q is declared %s, but the store's data key seals every row on disk; "+
			"declare it as sealing material at rest and rotate it with RotateDataKey",
			summon.ErrNotSealing, ref, rot)
	}
	return nil
}

// withDataKey resolves the data key, hands it to fn, and zeroes it afterwards.
//
// It resolves per use rather than caching, which is what the Resolver contract
// requires: "a caller that cached a Value across a rotation is holding a zeroed
// buffer, which is the intended failure" (internal/summon/resolver.go). It also
// means the provider's root-ownership hardening runs on every resolve, which is
// the whole point of that check being per-resolve rather than at start.
func (d *DB) withDataKey(ctx context.Context, fn func(dataKey []byte) error) error {
	if d.opts.Resolver == nil {
		return fmt.Errorf("%w: no resolver", ErrProviderNotConfigured)
	}
	ref := d.opts.DataKeyRef
	if ref == "" {
		ref = summon.Reference(DataKeyRefName)
	}
	v, err := d.opts.Resolver.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("store: resolving the data key: %w", err)
	}
	defer v.Zero()
	return fn(v.Bytes())
}

// generation is one data key generation's metadata. The key itself is never
// part of it.
type generation struct {
	gen  int64
	salt []byte
	kcv  []byte
}

// activeGeneration reads the single active generation.
func activeGeneration(ctx context.Context, q querier) (generation, error) {
	var g generation
	err := q.QueryRowContext(ctx,
		`SELECT gen, salt, kcv FROM data_keys WHERE state = 'active'`).
		Scan(&g.gen, &g.salt, &g.kcv)
	if errors.Is(err, sql.ErrNoRows) {
		return g, fmt.Errorf("store: no active data key generation")
	}
	return g, err
}

// querier is the overlap of *sql.DB and *sql.Tx this package uses, so helpers
// can run either inside or outside a transaction without duplication.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ensureActiveGeneration creates generation 1 on a fresh file, and on an
// existing file proves the resolved data key is the one the file was written
// under before any caller can get a confusing AEAD failure instead.
func (d *DB) ensureActiveGeneration(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ensureActiveGenerationLocked(ctx)
}

func (d *DB) ensureActiveGenerationLocked(ctx context.Context) error {
	var count int
	if err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM data_keys`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return d.withDataKey(ctx, func(dataKey []byte) error {
			salt, err := randomSalt()
			if err != nil {
				return err
			}
			kcv, err := deriveKCV(dataKey, salt, 1)
			if err != nil {
				return err
			}
			_, err = d.sql.ExecContext(ctx,
				`INSERT INTO data_keys (gen, salt, kcv, state, created_at) VALUES (1, ?, ?, 'active', ?)`,
				salt, kcv, d.now())
			return err
		})
	}

	g, err := activeGeneration(ctx, d.sql)
	if err != nil {
		return err
	}
	if err := d.withDataKey(ctx, func(dataKey []byte) error {
		return checkKCV(dataKey, g.salt, g.gen, g.kcv)
	}); err != nil {
		return err
	}
	return d.checkNoMixedGenerations(ctx, g.gen)
}

// checkNoMixedGenerations refuses to serve a file whose rows are split across
// data key generations.
//
// Rotation is one transaction and cannot commit halfway, so this state should
// be unreachable; it is checked anyway because the failure it guards against is
// exactly "a database half-readable under two keys with no record of which row
// is which", and the cost of noticing is one indexed count.
func (d *DB) checkNoMixedGenerations(ctx context.Context, active int64) error {
	var stale int
	if err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM records WHERE gen <> ?`, active).Scan(&stale); err != nil {
		return err
	}
	if stale > 0 {
		return fmt.Errorf("store: %d rows are encrypted under a data key generation other than the active one (%d); "+
			"a rotation did not complete and the file must be restored from backup", stale, active)
	}
	return nil
}

func randomSalt() ([]byte, error) {
	s := make([]byte, saltLen)
	if err := randRead(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (d *DB) now() int64 { return d.opts.Clock().UnixNano() }

// Get returns a row's plaintext, decrypted under the data key Summon resolves.
func (d *DB) Get(ctx context.Context, collection, id string) ([]byte, error) {
	if err := validName("collection", collection, MaxCollectionLen); err != nil {
		return nil, err
	}
	if err := validName("id", id, MaxIDLen); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return nil, err
	}

	var gen int64
	var wrapped, payload []byte
	err := d.sql.QueryRowContext(ctx,
		`SELECT gen, wrapped_key, payload FROM records WHERE collection = ? AND id = ?`,
		collection, id).Scan(&gen, &wrapped, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s/%s", ErrNotFound, collection, id)
	}
	if err != nil {
		return nil, err
	}

	var salt, kcv []byte
	if err := d.sql.QueryRowContext(ctx,
		`SELECT salt, kcv FROM data_keys WHERE gen = ?`, gen).Scan(&salt, &kcv); err != nil {
		return nil, fmt.Errorf("store: row %s/%s names data key generation %d, which is not recorded: %w", collection, id, gen, err)
	}

	var out []byte
	err = d.withDataKey(ctx, func(dataKey []byte) error {
		if err := checkKCV(dataKey, salt, gen, kcv); err != nil {
			return err
		}
		wrapKey, err := deriveWrapKey(dataKey, salt, gen)
		if err != nil {
			return err
		}
		defer zero(wrapKey)
		rowKey, err := open(wrapKey, wrapped, wrapAAD(collection, id, gen))
		if err != nil {
			return fmt.Errorf("store: unwrapping the row key for %s/%s: %w", collection, id, err)
		}
		defer zero(rowKey)
		plaintext, err := open(rowKey, payload, rowAAD(collection, id))
		if err != nil {
			return fmt.Errorf("store: decrypting %s/%s: %w", collection, id, err)
		}
		out = plaintext
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Put writes a row, envelope-encrypted under the active data key generation.
// Writing an existing id replaces it under a fresh row key: a rewritten secret
// never reuses the key that protected its predecessor.
func (d *DB) Put(ctx context.Context, collection, id string, plaintext []byte) error {
	if err := validName("collection", collection, MaxCollectionLen); err != nil {
		return err
	}
	if err := validName("id", id, MaxIDLen); err != nil {
		return err
	}
	if len(plaintext) > MaxValueBytes {
		return fmt.Errorf("%w: %d bytes, limit is %d", ErrValueTooLarge, len(plaintext), MaxValueBytes)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return err
	}

	g, err := activeGeneration(ctx, d.sql)
	if err != nil {
		return err
	}
	var wrapped, sealed []byte
	err = d.withDataKey(ctx, func(dataKey []byte) error {
		if err := checkKCV(dataKey, g.salt, g.gen, g.kcv); err != nil {
			return err
		}
		wrapKey, err := deriveWrapKey(dataKey, g.salt, g.gen)
		if err != nil {
			return err
		}
		defer zero(wrapKey)
		rowKey, err := newRowKey()
		if err != nil {
			return err
		}
		defer zero(rowKey)
		if wrapped, err = seal(wrapKey, rowKey, wrapAAD(collection, id, g.gen)); err != nil {
			return err
		}
		sealed, err = seal(rowKey, plaintext, rowAAD(collection, id))
		return err
	})
	if err != nil {
		return err
	}

	now := d.now()
	_, err = d.sql.ExecContext(ctx,
		`INSERT INTO records (collection, id, gen, wrapped_key, payload, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(collection, id) DO UPDATE SET
		   gen = excluded.gen,
		   wrapped_key = excluded.wrapped_key,
		   payload = excluded.payload,
		   updated_at = excluded.updated_at`,
		collection, id, g.gen, wrapped, sealed, now, now)
	return err
}

// Delete removes a row. Deleting an absent row is ErrNotFound rather than a
// silent success, because "revoke this device" quietly matching nothing is the
// kind of no-op an operator must be told about.
func (d *DB) Delete(ctx context.Context, collection, id string) error {
	if err := validName("collection", collection, MaxCollectionLen); err != nil {
		return err
	}
	if err := validName("id", id, MaxIDLen); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return err
	}
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM records WHERE collection = ? AND id = ?`, collection, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s/%s", ErrNotFound, collection, id)
	}
	return nil
}

// List returns the ids in a collection, sorted. It reads no ciphertext and
// resolves no data key: knowing which devices exist does not require the power
// to read what they are.
func (d *DB) List(ctx context.Context, collection string) ([]string, error) {
	if err := validName("collection", collection, MaxCollectionLen); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return nil, err
	}
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id FROM records WHERE collection = ? ORDER BY id`, collection)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	// Deliberately not preallocated from a count query: the row count is data
	// on disk, and data on disk does not get to size an allocation up front.
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Close releases the database. It is safe to call more than once.
//
// It checkpoints the write-ahead log first, so what is left on disk is one
// self-contained file. Operators move this file: they copy it to another box,
// restore over it, or hand it to a backup tool, and a database whose most
// recent enrollments live only in a sidecar someone forgot to copy is a
// database that loses them.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if _, err := d.sql.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = d.sql.Close()
		return fmt.Errorf("store: checkpointing on close: %w", err)
	}
	return d.sql.Close()
}

// Path is the database file this DB is backed by.
func (d *DB) Path() string { return d.path }

func (d *DB) checkOpen() error {
	if d.closed {
		return fmt.Errorf("store: database is closed")
	}
	return nil
}
