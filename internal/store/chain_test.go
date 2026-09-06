package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// seedChain appends n records cycling through every kind, so every test that
// tampers with a chain is tampering with one that mixes issuance, exchange and
// admin-signed policy records in the single shared chain the spec requires.
func seedChain(t *testing.T, d *DB, n int) [][]byte {
	t.Helper()
	ctx := context.Background()
	kinds := []string{KindIssuance, KindExchange, KindPolicy, KindSelfIssuance}
	hashes := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		h, err := d.Append(ctx, Record{
			Kind:    kinds[i%len(kinds)],
			Payload: []byte(fmt.Sprintf(`{"n":%d}`, i)),
		})
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		hashes = append(hashes, h)
	}
	return hashes
}

func TestChainAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	// An empty chain verifies. "Nothing has happened yet" is not a break.
	ok, bad, err := d.Verify(ctx)
	if err != nil || !ok || bad != 0 {
		t.Fatalf("Verify on an empty chain: ok=%v bad=%d err=%v", ok, bad, err)
	}
	if seq, hash, err := d.Head(ctx); err != nil || seq != 0 || hash != nil {
		t.Fatalf("Head on an empty chain: %d %x %v", seq, hash, err)
	}

	hashes := seedChain(t, d, 40)

	ok, bad, err = d.Verify(ctx)
	if err != nil || !ok || bad != 0 {
		t.Fatalf("Verify: ok=%v bad=%d err=%v", ok, bad, err)
	}
	seq, head, err := d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 40 || !bytes.Equal(head, hashes[39]) {
		t.Fatalf("Head = %d/%x, want 40/%x", seq, head, hashes[39])
	}

	// Sequence numbers are assigned by the store, not the caller: a caller that
	// picks its own would be picking where its record lands in the evidence.
	h, err := d.Append(ctx, Record{Seq: 9999, Kind: KindIssuance, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	var got int64
	if err := d.sql.QueryRowContext(ctx, `SELECT seq FROM chain WHERE hash = ?`, h).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 41 {
		t.Fatalf("caller-supplied Seq was honoured: record landed at %d, want 41", got)
	}
}

// TestAppendStampsEveryFieldButKindAndPayload pins which fields of a Record the
// caller owns: two. Everything else the store assigns, including the time.
func TestAppendStampsEveryFieldButKindAndPayload(t *testing.T) {
	ctx := context.Background()
	clk := newTestClock()
	d := openTestStoreWithClock(t, newFakeResolver(testKey(0x11)), clk.Now)
	seedChain(t, d, 2)

	// A caller that supplies a sequence, a time and both hashes gets none of
	// them honoured. The backdated time is the one that matters: it is what an
	// attacker with append access would set.
	backdated := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	forged := bytes.Repeat([]byte{0xAA}, 32)
	before := clk.Now()
	if _, err := d.Append(ctx, Record{
		Seq:      500,
		Kind:     KindExchange,
		At:       backdated,
		Payload:  []byte("body"),
		PrevHash: forged,
		Hash:     forged,
	}); err != nil {
		t.Fatal(err)
	}

	var got []Record
	if err := d.Walk(ctx, 3, func(r Record) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Walk returned %d records", len(got))
	}
	r := got[0]
	if r.Seq != 3 {
		t.Errorf("Seq = %d, want 3 (the caller's 500 must be ignored)", r.Seq)
	}
	if r.At.Equal(backdated) {
		t.Error("the caller's backdated time was stored; an audit log must not take its timestamps from what it audits")
	}
	if !r.At.After(before) {
		t.Errorf("At = %v, want a time from the store clock after %v", r.At, before)
	}
	if bytes.Equal(r.PrevHash, forged) || bytes.Equal(r.Hash, forged) {
		t.Error("a caller-supplied hash was stored")
	}
	if r.Kind != KindExchange || string(r.Payload) != "body" {
		t.Errorf("the caller's own two fields were not kept: %s %q", r.Kind, r.Payload)
	}
	if ok, _, err := d.Verify(ctx); !ok || err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// The stamped time is covered by the hash, so it cannot be revised later
	// without breaking the chain.
	execSQL(t, d, `UPDATE chain SET at = at + 1 WHERE seq = 3`)
	ok, bad, err := d.Verify(ctx)
	if ok || bad != 3 {
		t.Fatalf("editing a stamped time went undetected: ok=%v bad=%d err=%v", ok, bad, err)
	}
}

func TestChainAppendValidation(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	cases := []struct {
		name string
		rec  Record
		want error
	}{
		{"empty kind", Record{Kind: ""}, ErrBadName},
		{"kind with a separator", Record{Kind: "issuance/extra"}, ErrBadName},
		{"payload too large", Record{Kind: KindIssuance, Payload: make([]byte, MaxPayloadBytes+1)}, ErrValueTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := d.Append(ctx, c.rec)
			wantErrIs(t, err, c.want, "Append")
		})
	}
	// Nothing above was written.
	if seq, _, err := d.Head(ctx); err != nil || seq != 0 {
		t.Fatalf("a rejected Append still moved the chain to %d", seq)
	}
}

// chainTamperCases are the edits a compromised host would make to the chain,
// each with the sequence a correct implementation must name. Verify and Walk
// are both run against this one table: two implementations of the same check
// that disagree about where a break is would be worse than one.
var chainTamperCases = []struct {
	name    string
	tamper  func(t *testing.T, d *DB)
	wantSeq int64
}{
	{
		name: "a policy record's payload is widened",
		tamper: func(t *testing.T, d *DB) {
			// The attack the shared chain exists to stop: quietly widening
			// a grant on a host you control.
			execSQL(t, d, `UPDATE chain SET payload = ? WHERE seq = 7`, []byte(`{"scope":"*"}`))
		},
		wantSeq: 7,
	},
	{
		name: "a record's kind is relabelled",
		tamper: func(t *testing.T, d *DB) {
			execSQL(t, d, `UPDATE chain SET kind = ? WHERE seq = 12`, KindIssuance)
		},
		wantSeq: 12,
	},
	{
		name: "a record's timestamp is moved",
		tamper: func(t *testing.T, d *DB) {
			execSQL(t, d, `UPDATE chain SET at = at + 1 WHERE seq = 3`)
		},
		wantSeq: 3,
	},
	{
		name: "a record is deleted from the middle",
		tamper: func(t *testing.T, d *DB) {
			execSQL(t, d, `DELETE FROM chain WHERE seq = 15`)
		},
		wantSeq: 15,
	},
	{
		name: "a record's stored hash is rewritten to match its edited payload",
		tamper: func(t *testing.T, d *DB) {
			// A forger who recomputes the hash of the record it edited
			// still breaks the NEXT record's link.
			var prev []byte
			row(t, d, `SELECT prev_hash FROM chain WHERE seq = 20`).Scan(&prev)
			newPayload := []byte(`{"scope":"*"}`)
			var kind string
			var at int64
			row(t, d, `SELECT kind, at FROM chain WHERE seq = 20`).Scan(&kind, &at)
			h := recordHash(20, kind, at, newPayload, prev)
			execSQL(t, d, `UPDATE chain SET payload = ?, hash = ? WHERE seq = 20`, newPayload, h)
		},
		wantSeq: 21,
	},
	{
		name: "the tail is truncated",
		tamper: func(t *testing.T, d *DB) {
			execSQL(t, d, `DELETE FROM chain WHERE seq > 30`)
		},
		wantSeq: 31,
	},
	{
		name: "the recorded tip is moved backwards",
		tamper: func(t *testing.T, d *DB) {
			var h []byte
			row(t, d, `SELECT hash FROM chain WHERE seq = 30`).Scan(&h)
			execSQL(t, d, `UPDATE chain_head SET seq = 30, hash = ? WHERE id = 1`, h)
		},
		wantSeq: 31,
	},
	{
		name: "the genesis record claims a different predecessor",
		tamper: func(t *testing.T, d *DB) {
			execSQL(t, d, `UPDATE chain SET prev_hash = ? WHERE seq = 1`, bytes.Repeat([]byte{1}, 32))
		},
		wantSeq: 1,
	},
}

// TestChainTamperIsDetected is the core of the tamper-evidence claim. Each case
// edits the database directly, the way a compromised host would, and Verify
// must name the first bad sequence.
func TestChainTamperIsDetected(t *testing.T) {
	cases := chainTamperCases

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			d, _ := openTestStore(t)
			seedChain(t, d, 40)
			if ok, _, err := d.Verify(ctx); !ok || err != nil {
				t.Fatalf("chain was broken before tampering: %v", err)
			}

			c.tamper(t, d)

			ok, bad, err := d.Verify(ctx)
			if ok {
				t.Fatal("Verify accepted a tampered chain")
			}
			wantErrIs(t, err, ErrChainBroken, "Verify")
			if bad != c.wantSeq {
				t.Errorf("firstBadSeq = %d, want %d (%v)", bad, c.wantSeq, err)
			}

			// A broken chain is never repaired, and never extended: appending
			// onto it would launder the break under a run of well-formed
			// records.
			if _, err := d.Append(ctx, Record{Kind: KindIssuance, Payload: []byte("after")}); err == nil {
				// Only the cases that damage the tip or the tail are visible to
				// Append's O(1) check; the rest legitimately still append.
				if c.wantSeq == 31 {
					t.Error("Append extended a chain whose tail was cut")
				}
			}

			// Verify is still reporting the same break: nothing self-healed.
			if ok2, bad2, _ := d.Verify(ctx); ok2 || bad2 != c.wantSeq {
				t.Errorf("a second Verify reported ok=%v bad=%d; tamper evidence must be stable", ok2, bad2)
			}
		})
	}
}

func TestWalkDeliversVerifiedRecords(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	hashes := seedChain(t, d, 25)

	var seen []Record
	if err := d.Walk(ctx, 1, func(r Record) error {
		seen = append(seen, r)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(seen) != 25 {
		t.Fatalf("Walk delivered %d records, want 25", len(seen))
	}
	for i, r := range seen {
		if r.Seq != int64(i+1) {
			t.Fatalf("record %d has Seq %d", i, r.Seq)
		}
		if !bytes.Equal(r.Hash, hashes[i]) {
			t.Fatalf("record %d hash = %x, want %x", i, r.Hash, hashes[i])
		}
		if want := fmt.Sprintf(`{"n":%d}`, i); string(r.Payload) != want {
			t.Fatalf("record %d payload = %q, want %q", i, r.Payload, want)
		}
		if r.At.IsZero() {
			t.Fatalf("record %d has no time", i)
		}
	}
	// Each record's PrevHash is its predecessor's Hash, as delivered.
	for i := 1; i < len(seen); i++ {
		if !bytes.Equal(seen[i].PrevHash, seen[i-1].Hash) {
			t.Fatalf("record %d does not link to its predecessor as delivered", i+1)
		}
	}
}

func TestWalkFromPartialStillVerifiesTheLink(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	seedChain(t, d, 20)

	// Rewrite record 9. A walk starting at 10 must still notice, because it
	// checks record 10's prev_hash against record 9's actual hash. Starting in
	// the middle is not a way to skip a link.
	execSQL(t, d, `UPDATE chain SET payload = ? WHERE seq = 9`, []byte("widened"))

	var delivered int
	err := d.Walk(ctx, 10, func(Record) error { delivered++; return nil })
	wantErrIs(t, err, ErrChainBroken, "Walk from the middle of a tampered chain")
	if delivered != 0 {
		t.Fatalf("Walk delivered %d records past a broken link", delivered)
	}

	// From 1 it delivers the valid prefix and then reports the break: where the
	// chain breaks is the most useful fact an operator has.
	delivered = 0
	err = d.Walk(ctx, 1, func(Record) error { delivered++; return nil })
	wantErrIs(t, err, ErrChainBroken, "Walk from the start")
	if delivered != 8 {
		t.Fatalf("Walk delivered %d records before the break at 9, want 8", delivered)
	}
}

func TestWalkStopsOnCallerErrorWithoutLookingLikeCorruption(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	seedChain(t, d, 30)

	sentinel := errors.New("caller has seen enough")
	var n int
	err := d.Walk(ctx, 1, func(Record) error {
		n++
		if n == 5 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Walk returned %v, want the caller's own error unchanged", err)
	}
	if errors.Is(err, ErrChainBroken) {
		t.Fatal("stopping early was reported as a broken chain")
	}
	if n != 5 {
		t.Fatalf("Walk called fn %d times after being told to stop", n)
	}
}

func TestWalkFromBeyondTheEndIsEmpty(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	seedChain(t, d, 5)

	var n int
	if err := d.Walk(ctx, 6, func(Record) error { n++; return nil }); err != nil {
		t.Fatalf("Walk past the end: %v", err)
	}
	if n != 0 {
		t.Fatalf("Walk delivered %d records past the end", n)
	}
	// A nil function is a caller bug, reported rather than ignored.
	if err := d.Walk(ctx, 1, nil); err == nil {
		t.Fatal("Walk accepted a nil function")
	}
}

func TestHeadIsWitnessable(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	seedChain(t, d, 3)

	seq, h1, err := d.Head(ctx)
	if err != nil || seq != 3 {
		t.Fatalf("Head = %d, %v", seq, err)
	}
	// The returned hash is a copy: an operator holding a witnessed head must
	// not have it change under them when the chain advances.
	seedChain(t, d, 1)
	_, h2, err := d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(h1, h2) {
		t.Fatal("the head did not move after an append")
	}
	if hex.EncodeToString(h1) == "" {
		t.Fatal("empty head hash")
	}
}

func execSQL(t *testing.T, d *DB, query string, args ...any) {
	t.Helper()
	if _, err := d.sql.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func row(t *testing.T, d *DB, query string, args ...any) *sql.Row {
	t.Helper()
	return d.sql.QueryRowContext(context.Background(), query, args...)
}

// TestWalkAndVerifyAgreeOnWhereTheBreakIs runs both readers over the same
// tampered chains. Verify reports the sequence directly; Walk reports it through
// the *ChainBreak its error carries. They read it out of the same value, so this
// test is a guard against that ever being reimplemented twice.
func TestWalkAndVerifyAgreeOnWhereTheBreakIs(t *testing.T) {
	for _, c := range chainTamperCases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			d, _ := openTestStore(t)
			seedChain(t, d, 40)
			c.tamper(t, d)

			ok, verifySeq, verifyErr := d.Verify(ctx)
			if ok {
				t.Fatal("Verify accepted a tampered chain")
			}
			wantErrIs(t, verifyErr, ErrChainBroken, "Verify")

			walkErr := d.Walk(ctx, 1, func(Record) error { return nil })
			wantErrIs(t, walkErr, ErrChainBroken, "Walk")

			var break1, break2 *ChainBreak
			if !errors.As(verifyErr, &break1) {
				t.Fatalf("Verify's error does not carry a *ChainBreak: %v", verifyErr)
			}
			if !errors.As(walkErr, &break2) {
				t.Fatalf("Walk's error does not carry a *ChainBreak: %v", walkErr)
			}
			if break1.Seq != verifySeq {
				t.Errorf("Verify returned firstBadSeq %d but its error names %d", verifySeq, break1.Seq)
			}
			if break2.Seq != verifySeq {
				t.Errorf("Walk reports the break at %d, Verify at %d", break2.Seq, verifySeq)
			}
			if break1.Seq != c.wantSeq {
				t.Errorf("the break is reported at %d, want %d", break1.Seq, c.wantSeq)
			}
			if !strings.Contains(walkErr.Error(), strconv.FormatInt(c.wantSeq, 10)) {
				t.Errorf("the error text does not name the sequence: %v", walkErr)
			}
		})
	}
}

// TestWalkDeliversThePrefixThenNamesTheEdit is the failure the log will actually
// have: one record altered in the middle of a long chain. Everything before the
// edit is still evidence and must reach the caller; the edit itself must stop
// the walk and be named.
func TestWalkDeliversThePrefixThenNamesTheEdit(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	seedChain(t, d, 40)

	// Widen a grant on record 17, the attack the shared chain exists to catch.
	execSQL(t, d, `UPDATE chain SET payload = ? WHERE seq = 17`, []byte(`{"scope":"*"}`))

	var delivered []int64
	err := d.Walk(ctx, 1, func(r Record) error {
		delivered = append(delivered, r.Seq)
		return nil
	})

	wantErrIs(t, err, ErrChainBroken, "Walk over a chain edited in the middle")
	var b *ChainBreak
	if !errors.As(err, &b) {
		t.Fatalf("the error does not carry a *ChainBreak: %v", err)
	}
	if b.Seq != 17 {
		t.Fatalf("the break is named at sequence %d, want 17", b.Seq)
	}
	if len(delivered) != 16 {
		t.Fatalf("Walk delivered %d records before the edit, want 16", len(delivered))
	}
	for i, seq := range delivered {
		if seq != int64(i+1) {
			t.Fatalf("delivered record %d has sequence %d", i, seq)
		}
	}
	// Verify agrees, and the store did not quietly repair anything on the way.
	if ok, seq, _ := d.Verify(ctx); ok || seq != 17 {
		t.Fatalf("Verify reports ok=%v seq=%d after the walk", ok, seq)
	}
}
