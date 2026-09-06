package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Collections are the logical tables the spec names: "One SQLite file
// (enrollments, policy, revocations, issuance log) plus CA material"
// (docs/totem-design-decisions.md #9), plus grants, which the issuance log and
// the delegation model both reference.
//
// They are collections in one physical `records` table rather than four tables
// because every row is envelope-encrypted end to end. Nothing inside a row is
// indexable or queryable no matter how it is stored, so four tables would buy
// four names and nothing else, while one table lets rotation walk every
// encrypted row in a single statement.
//
// Splitting this into a table per collection WILL look tidier at some point.
// It is not. Read the paragraph above before proposing it: the normalisation
// that separate tables usually buys needs columns to index and join on, and
// there are none here, because the only thing SQLite can see is a ciphertext
// and a key wrapped under a data key it does not hold. What the split would
// actually cost is RotateDataKey, which re-wraps every row in one statement
// inside one transaction, and which is atomic precisely because it is that
// cheap. Four tables make it four statements over four loops, and the first
// person to get that wrong reintroduces the half-rotated database that this
// package is built to make unrepresentable.
//
// The names below are the contract.
const (
	// CollectionEnrollments holds one record per enrolled device: public key,
	// device id, protection level, admin flag, pinned cert.
	CollectionEnrollments = "enrollments"
	// CollectionPolicy holds admin-signed policy records. The signed record is
	// also appended to the hash chain; this collection is the current-state
	// cache the issuer evaluates against.
	CollectionPolicy = "policy"
	// CollectionGrants holds delegation grants: an agent's scope, its sponsor,
	// and its expiry.
	CollectionGrants = "grants"
	// CollectionRevocations holds revocation records, consulted by the live
	// enrollment check every exchange performs.
	CollectionRevocations = "revocations"
	// CollectionSecrets holds the second kind of secret from
	// docs/totem-design-decisions.md #25: material the issuer generates or that
	// rotates on use (GitHub refresh tokens), which cannot live in Summon
	// because Summon providers cannot write.
	CollectionSecrets = "secrets"
)

// Chain record kinds. The spec requires the issuer's own self-issuance be "its
// own logged event type" (docs/totem-design-decisions.md #32), which is why
// KindSelfIssuance is distinct from KindIssuance.
const (
	// KindIssuance is an SVID minted for a device or tool identity.
	KindIssuance = "issuance"
	// KindExchange is a credential exchange against a relying party.
	KindExchange = "exchange"
	// KindPolicy is an admin-signed policy change: enrollment approval,
	// presence policy, grants, admin flags, step-up approvals.
	KindPolicy = "policy"
	// KindSelfIssuance is the issuer issuing to its own identity,
	// spiffe://<td>/issuer, kept distinct so it can never hide inside ordinary
	// issuance volume.
	KindSelfIssuance = "self-issuance"
)

// Size bounds. Every one of these exists so that a value read back off disk, or
// handed in by a caller, can never choose an allocation.
const (
	// MaxCollectionLen bounds a collection name.
	MaxCollectionLen = 64
	// MaxIDLen bounds a record id.
	MaxIDLen = 256
	// MaxKindLen bounds a chain record kind.
	MaxKindLen = 64
	// MaxValueBytes bounds a row plaintext. Rows hold enrollments, grants and
	// rotating secrets, none of which are documents.
	MaxValueBytes = 1 << 22 // 4 MiB
	// MaxPayloadBytes bounds a chain record payload. A log line is a log line.
	MaxPayloadBytes = 1 << 18 // 256 KiB
)

// schemaVersion is the schema this binary writes. A file whose user_version is
// higher was written by a newer issuer: migrations are forward-only, so the
// recovery is restore-from-backup, never an in-place downgrade
// (docs/totem-design-decisions.md #9, "Forward-only schema migrations on
// start").
const schemaVersion = 1

// migration is one forward-only step. Steps are applied in order, each in its
// own transaction with the user_version bump inside it, so an interrupted
// migration either happened or did not.
type migration struct {
	version int
	stmts   []string
}

// migrations is the ordered, append-only list. Never edit a released entry;
// add a new one. Editing an applied migration would silently diverge two
// databases that report the same version.
var migrations = []migration{
	{
		version: 1,
		stmts: []string{
			// data_keys records one row per data key generation. It holds the
			// per-generation HKDF salt and a key check value, never the key.
			`CREATE TABLE data_keys (
				gen        INTEGER PRIMARY KEY,
				salt       BLOB NOT NULL,
				kcv        BLOB NOT NULL,
				state      TEXT NOT NULL CHECK (state IN ('active','retired')),
				created_at INTEGER NOT NULL
			)`,
			// Exactly one generation may be active. A partial rotation is
			// therefore impossible to represent, not merely unlikely.
			`CREATE UNIQUE INDEX data_keys_one_active
				ON data_keys(state) WHERE state = 'active'`,
			// records is every envelope-encrypted row. gen names the data key
			// generation its wrapped_key is sealed under; the foreign key means
			// a row can never point at a generation that was never recorded.
			`CREATE TABLE records (
				collection  TEXT NOT NULL,
				id          TEXT NOT NULL,
				gen         INTEGER NOT NULL REFERENCES data_keys(gen),
				wrapped_key BLOB NOT NULL,
				payload     BLOB NOT NULL,
				created_at  INTEGER NOT NULL,
				updated_at  INTEGER NOT NULL,
				PRIMARY KEY (collection, id)
			) WITHOUT ROWID`,
			// Rotation walks by generation, so it gets an index.
			`CREATE INDEX records_by_gen ON records(gen)`,
			// chain is the one hash chain shared by issuance, exchange and
			// admin-signed policy records. Payloads are audit metadata, not
			// secrets, and are stored in the clear: they are the evidence, and
			// encrypting them would only make the evidence harder to read while
			// protecting a SPIFFE ID that is already on stdout.
			`CREATE TABLE chain (
				seq       INTEGER PRIMARY KEY,
				kind      TEXT NOT NULL,
				at        INTEGER NOT NULL,
				payload   BLOB NOT NULL,
				prev_hash BLOB NOT NULL,
				hash      BLOB NOT NULL
			)`,
			// chain_head is the single-row tip. Appending updates it in the same
			// transaction as the insert, so the recorded tip and the last row
			// cannot drift apart. It also gives Verify a cheap way to notice a
			// chain whose tail was cut off, which a prev-hash walk alone cannot
			// see.
			`CREATE TABLE chain_head (
				id   INTEGER PRIMARY KEY CHECK (id = 1),
				seq  INTEGER NOT NULL,
				hash BLOB NOT NULL
			)`,
			`INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, x'')`,
		},
	},
}

// Migrate runs forward-only migrations. It is called on open and is the only
// path that changes the schema.
//
// A file written by a newer issuer returns ErrSchemaAhead untouched: the spec's
// answer to a downgrade is restore-from-backup, so this must never attempt to
// adapt the file it was handed.
func (d *DB) Migrate(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.migrateLocked(ctx)
}

func (d *DB) migrateLocked(ctx context.Context) error {
	current, err := userVersion(ctx, d.sql)
	if err != nil {
		return err
	}
	if current > schemaVersion {
		return fmt.Errorf("%w: file is at version %d, this binary understands %d", ErrSchemaAhead, current, schemaVersion)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, d.sql, m); err != nil {
			return fmt.Errorf("store: migration to version %d: %w", m.version, err)
		}
	}
	return nil
}

// applyMigration runs one migration's statements and its user_version bump in a
// single transaction.
func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range m.stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	// PRAGMA user_version does not accept a bind parameter; m.version is an int
	// constant from this file, never caller input.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return err
	}
	return tx.Commit()
}

// userVersion reads the schema version SQLite records in the file header.
func userVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// firstLine trims a SQL statement down to something readable in an error.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// validName enforces the shape of a collection, id or kind before it reaches
// SQL, a tar entry name or a log line. Parameters already stop injection; this
// stops the rest: unbounded names, control characters, and path separators that
// would matter the moment a name reaches a filename.
func validName(kindOfName, s string, max int) error {
	if s == "" {
		return fmt.Errorf("%w: %s is empty", ErrBadName, kindOfName)
	}
	if len(s) > max {
		return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrBadName, kindOfName, len(s), max)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':', c == '@':
		default:
			return fmt.Errorf("%w: %s contains a byte that is not allowed (offset %d)", ErrBadName, kindOfName, i)
		}
	}
	if s == "." || s == ".." {
		return fmt.Errorf("%w: %s is a path element", ErrBadName, kindOfName)
	}
	return nil
}
