package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ChainBreak says WHERE a chain stopped verifying. It wraps ErrChainBroken, so
// errors.Is still identifies the category and errors.As recovers the sequence.
//
// It exists because Walk reports a break through its error and nothing else: a
// caller handed a bare sentinel would have to parse prose to learn which record
// went bad, and "which record" is the single most useful fact an operator has
// after a compromise. It is also what makes Verify and Walk structurally unable
// to disagree about where a break is, since both read the sequence out of the
// same value.
type ChainBreak struct {
	// Seq is the first sequence that does not verify. For a removed or
	// truncated record it is the sequence that should be there and is not.
	Seq int64
	// Detail says what was wrong, in an operator's words.
	Detail string
}

// Error describes the break and the sequence it happened at.
func (b *ChainBreak) Error() string {
	return fmt.Sprintf("%s at sequence %d: %s", ErrChainBroken.Error(), b.Seq, b.Detail)
}

// Unwrap makes errors.Is(err, ErrChainBroken) true for every break.
func (b *ChainBreak) Unwrap() error { return ErrChainBroken }

func chainBreak(seq int64, format string, args ...any) *ChainBreak {
	return &ChainBreak{Seq: seq, Detail: fmt.Sprintf(format, args...)}
}

// Append adds one record to the hash chain and returns its hash.
//
// Issuance, exchanges, and policy changes share ONE chain, which is the spec's
// explicit requirement and its reason: "Policy is signed by admin devices, not
// by the issuer... the issuer refuses to apply anything unsigned and stores the
// signed records in the same hash chain as issuance... A compromised host can
// mint under the CA (bounded by KMS) but cannot quietly widen a grant or enroll
// a device" (docs/totem-design.md, "Issuer (broker box)"). A second chain for
// policy would reopen exactly that gap.
//
// The sequence number is assigned here and a caller-supplied Seq is ignored: a
// caller that chose its own sequence would be choosing where its record lands
// in the evidence. PrevHash and Hash are likewise computed, never accepted, so
// there is no way to hand the store a record that claims a link it does not
// have.
//
// Record.At IS the caller's when it is set, defaulting to the store clock when
// it is not, because the time an issuance happened is a fact the caller knows
// and the store does not. It is covered by the hash, so a time can be chosen
// once, at the moment of writing, and never revised afterwards without breaking
// the chain.
//
// Append refuses to extend a chain whose recorded tip does not match its last
// row: appending onto a broken chain would launder the break under a run of
// well-formed records.
func (d *DB) Append(ctx context.Context, rec Record) ([]byte, error) {
	if err := validName("kind", rec.Kind, MaxKindLen); err != nil {
		return nil, err
	}
	if len(rec.Payload) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: chain payload is %d bytes, limit is %d", ErrValueTooLarge, len(rec.Payload), MaxPayloadBytes)
	}
	at := rec.At
	if at.IsZero() {
		at = d.opts.Clock()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return nil, err
	}

	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	headSeq, headHash, err := readHead(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := checkTipMatchesLastRow(ctx, tx, headSeq, headHash); err != nil {
		return nil, err
	}

	seq := headSeq + 1
	prev := headHash
	if headSeq == 0 {
		prev = genesisPrevHash()
	}
	payload := rec.Payload
	if payload == nil {
		payload = []byte{}
	}
	hash := recordHash(seq, rec.Kind, at.UnixNano(), payload, prev)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO chain (seq, kind, at, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)`,
		seq, rec.Kind, at.UnixNano(), payload, prev, hash); err != nil {
		return nil, err
	}
	// The tip moves in the same transaction as the row, so the two can never
	// disagree because of a crash.
	if _, err := tx.ExecContext(ctx,
		`UPDATE chain_head SET seq = ?, hash = ? WHERE id = 1`, seq, hash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return hash, nil
}

// readHead returns the recorded tip: sequence 0 and an empty hash on a chain
// that has never been appended to.
func readHead(ctx context.Context, q querier) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := q.QueryRowContext(ctx, `SELECT seq, hash FROM chain_head WHERE id = 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, fmt.Errorf("store: chain_head row is missing; the file is not a totem issuer database or has been tampered with")
	}
	return seq, hash, err
}

// checkTipMatchesLastRow is the O(1) tamper check Append runs before extending.
// A full walk on every append would cost the issuer a linear scan per issuance;
// this catches the two cheap cases, a cut tail and a rewritten tip, and Verify
// remains the authority for the rest.
func checkTipMatchesLastRow(ctx context.Context, q querier, headSeq int64, headHash []byte) error {
	var lastSeq sql.NullInt64
	var lastHash []byte
	err := q.QueryRowContext(ctx,
		`SELECT seq, hash FROM chain ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	if errors.Is(err, sql.ErrNoRows) {
		if headSeq != 0 {
			return chainBreak(1, "the chain is empty but the recorded tip is sequence %d", headSeq)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if lastSeq.Int64 != headSeq || !bytes.Equal(lastHash, headHash) {
		return chainBreak(min64(headSeq, lastSeq.Int64)+1,
			"the recorded tip is sequence %d but the last record is sequence %d; "+
				"records have been removed or rewritten and this must be investigated, not repaired",
			headSeq, lastSeq.Int64)
	}
	return nil
}

// walkChain is the single implementation behind Verify and Walk, so the two can
// never disagree about what a valid chain is.
//
// It re-derives every hash from the record's own stored contents and checks
// each record's prev_hash against its predecessor's derived hash, starting from
// the genesis predecessor (32 zero bytes) or, for a partial walk, from the hash
// of the record immediately before the range. Nothing in the walk trusts a
// stored hash it has not recomputed.
//
// deliver, when non-nil, is called for each record that has passed
// verification, before the next one is read: a caller never sees a record the
// walk has not already checked. An error from deliver stops the walk and is
// returned unchanged, so a caller stopping early does not look like corruption.
//
// It returns the last verified sequence and the error. A break is always a
// *ChainBreak carrying the sequence, so there is no second return value for
// callers to read inconsistently.
func (d *DB) walkChain(ctx context.Context, from int64, deliver func(Record) error) (lastSeq int64, err error) {
	if from < 1 {
		from = 1
	}
	prev, ok, err := prevHashBefore(ctx, d.sql, from)
	if err != nil {
		return 0, err
	}
	if !ok {
		// The record before the range is missing. That is only benign if there
		// is nothing at or after `from` either.
		var present int
		if err := d.sql.QueryRowContext(ctx,
			`SELECT count(*) FROM chain WHERE seq >= ? LIMIT 1`, from).Scan(&present); err != nil {
			return 0, err
		}
		if present > 0 {
			return 0, chainBreak(from-1, "the record is missing but later records exist")
		}
		return 0, nil
	}

	rows, err := d.sql.QueryContext(ctx,
		`SELECT seq, kind, at, payload, prev_hash, hash FROM chain WHERE seq >= ? ORDER BY seq ASC`, from)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	wantSeq := from
	for rows.Next() {
		var (
			r          Record
			atNanos    int64
			storedPrev []byte
			storedHash []byte
		)
		if err := rows.Scan(&r.Seq, &r.Kind, &atNanos, &r.Payload, &storedPrev, &storedHash); err != nil {
			return lastSeq, err
		}
		if r.Seq != wantSeq {
			return lastSeq, chainBreak(wantSeq, "expected this sequence, found %d; a record has been removed or reordered", r.Seq)
		}
		if !bytes.Equal(storedPrev, prev) {
			return lastSeq, chainBreak(r.Seq, "the record does not follow its predecessor")
		}
		if len(storedHash) != sha256.Size {
			return lastSeq, chainBreak(r.Seq, "the record has a %d-byte hash, want %d", len(storedHash), sha256.Size)
		}
		if want := recordHash(r.Seq, r.Kind, atNanos, r.Payload, storedPrev); !bytes.Equal(want, storedHash) {
			return lastSeq, chainBreak(r.Seq, "the record has been rewritten")
		}

		if deliver != nil {
			r.At = time.Unix(0, atNanos).UTC()
			r.PrevHash = bytes.Clone(storedPrev)
			r.Hash = bytes.Clone(storedHash)
			if err := deliver(r); err != nil {
				return lastSeq, err
			}
		}

		prev = storedHash
		lastSeq = r.Seq
		wantSeq++
	}
	if err := rows.Err(); err != nil {
		return lastSeq, err
	}

	// A truncated tail breaks no link, so it is caught here instead: the
	// recorded tip is written in the same transaction as the record it names.
	headSeq, headHash, err := readHead(ctx, d.sql)
	if err != nil {
		return lastSeq, err
	}
	if headSeq != lastSeq && !(lastSeq == 0 && from > 1 && headSeq < from) {
		return lastSeq, chainBreak(min64(headSeq, lastSeq)+1,
			"the recorded tip is sequence %d but the chain ends at sequence %d", headSeq, lastSeq)
	}
	if lastSeq > 0 && !bytes.Equal(headHash, prev) {
		return lastSeq, chainBreak(lastSeq, "the recorded tip hash does not match the last record")
	}
	return lastSeq, nil
}

// prevHashBefore returns the hash the record at seq must name as its
// predecessor: the genesis value for sequence 1, otherwise the preceding
// record's hash. ok is false when that preceding record is absent.
//
// The preceding record's hash is RECOMPUTED from its own contents, not read out
// of its hash column. Trusting the stored hash would make a partial walk a way
// to skip a link: an attacker who edits record N and leaves its hash alone
// would go unnoticed by every walk that starts at N+1, which is precisely the
// walk an incremental reader performs.
func prevHashBefore(ctx context.Context, q querier, seq int64) ([]byte, bool, error) {
	if seq <= 1 {
		return genesisPrevHash(), true, nil
	}
	var (
		kind       string
		atNanos    int64
		payload    []byte
		storedPrev []byte
		storedHash []byte
	)
	err := q.QueryRowContext(ctx,
		`SELECT kind, at, payload, prev_hash, hash FROM chain WHERE seq = ?`, seq-1).
		Scan(&kind, &atNanos, &payload, &storedPrev, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	want := recordHash(seq-1, kind, atNanos, payload, storedPrev)
	if !bytes.Equal(want, storedHash) {
		return nil, false, chainBreak(seq-1, "the record has been rewritten")
	}
	return want, true, nil
}

// Verify walks the chain and reports the first record whose hash does not
// follow from its predecessor.
//
// A broken chain is tamper evidence. Verify reports it and stops; it never
// rewrites a hash, never drops a record, and never "repairs" anything, because
// a chain that can be repaired is not evidence of anything.
//
// It catches four things, in the order a forger would have to defeat them: a
// removed record (sequence numbers are contiguous from 1), a rewritten record
// (its successor's prev_hash no longer matches), a rewritten record whose
// successor was fixed up too (its own hash no longer matches its contents), and
// a truncated tail (the recorded tip names a record that is gone).
//
// The one thing it cannot see alone is a truncation that also rewrites the
// recorded tip, because an attacker holding the file holds both. Detecting that
// needs an off-box witness of the head hash; Head exports the value to witness,
// and the spec does not yet say where it should be kept.
func (d *DB) Verify(ctx context.Context) (bool, int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return false, 0, err
	}
	if _, err := d.walkChain(ctx, 1, nil); err != nil {
		var b *ChainBreak
		if errors.As(err, &b) {
			return false, b.Seq, err
		}
		return false, 0, err
	}
	return true, 0, nil
}

// Walk streams records from seq onward, oldest first, calling fn for each,
// verifying each link as it goes.
//
// A record reaches fn only after its hash has been recomputed from its own
// contents and checked against its predecessor, so a reader never sees bytes
// the walk has not verified. On a break, the valid prefix has already been
// delivered and Walk returns ErrChainBroken: where the chain breaks is the most
// useful fact an operator has.
//
// A partial walk (from > 1) is verified too. Walk reads the hash of the record
// immediately before the range and checks the first delivered record against
// it, so starting in the middle is not a way to skip a link.
//
// fn must not call back into the Store. The walk holds the store's lock and its
// single database connection for its duration, and a re-entrant call would
// deadlock rather than return.
func (d *DB) Walk(ctx context.Context, from int64, fn func(Record) error) error {
	if fn == nil {
		return fmt.Errorf("store: Walk needs a function to call")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return err
	}
	_, err := d.walkChain(ctx, from, fn)
	return err
}

// Head returns the current chain tip: its sequence number and hash. Sequence 0
// with a nil hash means nothing has been appended.
//
// This is the value an operator writes down, publishes, or ships off the box.
// It is the only defence against a truncation that also rewrites the recorded
// tip, which is why it is exported rather than left inside Verify.
func (d *DB) Head(ctx context.Context) (int64, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkOpen(); err != nil {
		return 0, nil, err
	}
	seq, hash, err := readHead(ctx, d.sql)
	if err != nil {
		return 0, nil, err
	}
	if seq == 0 {
		return 0, nil, nil
	}
	return seq, bytes.Clone(hash), nil
}

// min64 is the smaller of two sequence numbers.
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
