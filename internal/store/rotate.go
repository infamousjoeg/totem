package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
)

// ErrSameDataKey means RotateDataKey was handed the key the database is already
// using. Rotating to the same key looks like it worked and protects nothing, so
// it is refused rather than performed.
var ErrSameDataKey = errors.New("store: the next data key is the one already in use; rotation would change nothing")

// ErrRotationOrder means the Summon provider is already returning the new data
// key. RotateDataKey needs the OLD key to unwrap the rows it is about to
// re-wrap, so the provider must be updated after this call, never before.
var ErrRotationOrder = errors.New("store: the Summon provider is already returning a key this database was not written under; rotate the store first, then update the provider")

// rotatePageSize bounds how many rows a rotation holds in memory at once. It is
// a constant rather than a row count read from the file, because the number of
// rows on disk does not get to size an allocation.
const rotatePageSize = 500

// RotateDataKey re-encrypts every envelope-encrypted row under a new data key.
//
// It is `totem issuer rotate-data-key` (docs/totem-design-decisions.md #32).
// Losing the old key loses only material a device flow can regenerate, which is
// why this is survivable at all.
//
// Interruption safety, which is the whole difficulty: the entire rotation runs
// in one immediate SQLite transaction, so a crash, a kill, or a lost connection
// leaves the file exactly as it was. There is no half-rotated state to recover
// from, and therefore no window in which the database is half-readable under
// two keys. It is not merely resumable; the interrupted case does not exist.
//
// Three further properties make the failure modes legible rather than silent:
//
//   - Every row records the data key generation its wrapped key belongs to, so
//     a mixed file is detectable at open even though it should be unreachable.
//   - The store refuses to rotate if the provider already returns the new key
//     (ErrRotationOrder), which is the ordering mistake an operator actually
//     makes: rotate the store first, then update the provider.
//   - The store refuses to rotate to the key it already holds (ErrSameDataKey).
//
// The unit that is re-encrypted is each row's wrapped key, not its payload. The
// row's payload key is unchanged, so the payload ciphertext is untouched. That
// is what an envelope is for, and it is what makes an all-or-nothing rotation
// affordable: a rotation moves roughly sixty bytes per row. It gives the
// property rotation is for, that the old data key no longer opens the current
// file. Nothing, including rewriting every payload, can retract a snapshot an
// attacker already decrypted with the old key in hand.
func (d *DB) RotateDataKey(ctx context.Context, next []byte) error {
	if len(next) == 0 {
		return fmt.Errorf("store: rotate needs the next data key")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return err
	}

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	old, err := activeGeneration(ctx, tx)
	if err != nil {
		return err
	}

	// Refuse the two orderings that do not do what the operator thinks. Both
	// checks are on the NEXT key against the CURRENT generation, so neither
	// needs the old key to be resolvable yet.
	if kcv, err := deriveKCV(next, old.salt, old.gen); err != nil {
		return err
	} else if subtle.ConstantTimeCompare(kcv, old.kcv) == 1 {
		return ErrSameDataKey
	}

	var newGen int64
	if err := tx.QueryRowContext(ctx, `SELECT max(gen) FROM data_keys`).Scan(&newGen); err != nil {
		return err
	}
	newGen++
	newSalt, err := randomSalt()
	if err != nil {
		return err
	}
	newKCV, err := deriveKCV(next, newSalt, newGen)
	if err != nil {
		return err
	}
	newWrapKey, err := deriveWrapKey(next, newSalt, newGen)
	if err != nil {
		return err
	}
	defer zero(newWrapKey)

	// The new generation row is inserted BEFORE any record points at it, so the
	// foreign key from records.gen is satisfied at every instant. It goes in
	// retired and is promoted at the end, because the partial unique index
	// permits exactly one active generation and that invariant is what makes a
	// half-rotated file impossible to represent.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO data_keys (gen, salt, kcv, state, created_at) VALUES (?, ?, ?, 'retired', ?)`,
		newGen, newSalt, newKCV, d.now()); err != nil {
		return err
	}

	// Resolve the OLD key through Summon. If the provider has already been
	// moved to the new key, the check value will not match and nothing is
	// touched.
	err = d.withDataKey(ctx, func(dataKey []byte) error {
		if err := checkKCV(dataKey, old.salt, old.gen, old.kcv); err != nil {
			// Distinguish "you rotated the provider first" from "wrong key
			// entirely": if the resolved key is the one being rotated TO, the
			// operator has the order backwards.
			if kcv, kerr := deriveKCV(dataKey, newSalt, newGen); kerr == nil &&
				subtle.ConstantTimeCompare(kcv, newKCV) == 1 {
				return ErrRotationOrder
			}
			return err
		}
		oldWrapKey, derr := deriveWrapKey(dataKey, old.salt, old.gen)
		if derr != nil {
			return derr
		}
		defer zero(oldWrapKey)
		return rewrapAll(ctx, tx, old.gen, newGen, oldWrapKey, newWrapKey)
	})
	if err != nil {
		return err
	}

	// Every row now points at the new generation, so the active flag can move.
	// Retire first, promote second: the partial unique index would reject the
	// other order.
	if _, err := tx.ExecContext(ctx,
		`UPDATE data_keys SET state = 'retired' WHERE gen = ?`, old.gen); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE data_keys SET state = 'active' WHERE gen = ?`, newGen); err != nil {
		return err
	}

	// Belt and braces: prove no row was left behind before committing.
	var remaining int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM records WHERE gen <> ?`, newGen).Scan(&remaining); err != nil {
		return err
	}
	if remaining != 0 {
		return fmt.Errorf("store: rotation would have left %d rows under the old data key; refusing to commit", remaining)
	}
	return tx.Commit()
}

// rewrapAll moves every row from oldGen to newGen, a page at a time.
//
// Each page is fully read before any update runs, because the store holds a
// single connection and a transaction cannot execute while one of its own
// result sets is open. Paging on `gen = oldGen` is self-advancing: rows leave
// the predicate as they are re-wrapped.
func rewrapAll(ctx context.Context, tx *sql.Tx, oldGen, newGen int64, oldWrapKey, newWrapKey []byte) error {
	type row struct {
		collection string
		id         string
		wrapped    []byte
	}
	for {
		page := make([]row, 0, rotatePageSize)
		rows, err := tx.QueryContext(ctx,
			`SELECT collection, id, wrapped_key FROM records WHERE gen = ? ORDER BY collection, id LIMIT ?`,
			oldGen, rotatePageSize)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.collection, &r.id, &r.wrapped); err != nil {
				_ = rows.Close()
				return err
			}
			page = append(page, r)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		for _, r := range page {
			rowKey, err := open(oldWrapKey, r.wrapped, wrapAAD(r.collection, r.id, oldGen))
			if err != nil {
				return fmt.Errorf("store: unwrapping %s/%s during rotation: %w", r.collection, r.id, err)
			}
			rewrapped, err := seal(newWrapKey, rowKey, wrapAAD(r.collection, r.id, newGen))
			zero(rowKey)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE records SET gen = ?, wrapped_key = ? WHERE collection = ? AND id = ?`,
				newGen, rewrapped, r.collection, r.id); err != nil {
				return err
			}
		}
	}
}

// DataKeyGeneration reports the active data key generation. It is recorded in
// backups so a restore can say which key it will need.
func (d *DB) DataKeyGeneration(ctx context.Context) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return 0, err
	}
	g, err := activeGeneration(ctx, d.sql)
	if err != nil {
		return 0, err
	}
	return g.gen, nil
}
