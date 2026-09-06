package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
)

func decodeRecords(t *testing.T, s string) []Record {
	t.Helper()
	var out []Record
	dec := json.NewDecoder(strings.NewReader(s))
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("audit line is not JSON: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// TestChainVerifies and TestChainDetectsTampering are the two halves of what a
// hash chain is for. The second is the one that matters: a chain nobody can
// break is a chain nobody has tested.
func TestChainVerifies(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewAuditLog(&buf, nil)
	for i := 0; i < 5; i++ {
		if _, err := l.Log(Event{Kind: ca.EventIssuance, Device: "d1", Outcome: "issued"}); err != nil {
			t.Fatal(err)
		}
	}
	records := decodeRecords(t, buf.String())
	if len(records) != 5 {
		t.Fatalf("got %d records, want 5", len(records))
	}
	if ok, bad := VerifyChain(records); !ok {
		t.Fatalf("a freshly written chain did not verify, first bad seq %d", bad)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewAuditLog(&buf, nil)
	for _, outcome := range []string{"issued", "issued", "refused"} {
		if _, err := l.Log(Event{Kind: ca.EventIssuance, Device: "d1", Outcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	records := decodeRecords(t, buf.String())

	// Rewrite history: turn a refusal into an issuance, the edit an attacker
	// with write access to a log file would actually make.
	records[2].Outcome = "issued"
	ok, bad := VerifyChain(records)
	if ok {
		t.Fatal("an edited record verified")
	}
	if bad != 2 {
		t.Errorf("first bad seq %d, want 2", bad)
	}

	// And removing a line entirely breaks the link, which is the failure mode a
	// per-line signature would miss.
	shortened := append(append([]Record{}, records[0]), records[2])
	if ok, _ := VerifyChain(shortened); ok {
		t.Fatal("a chain with a record removed verified")
	}
}

// TestIssuerSelfIssuanceKeepsItsOwnKind. internal/ca sets the event kind on the
// SVID it returns precisely so a self-issuance can never be logged as a device
// issuance, and this log passes it through rather than deciding the label. An
// auditor counting device issuances must not have to subtract these out.
func TestIssuerSelfIssuanceKeepsItsOwnKind(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewAuditLog(&buf, nil)
	if _, err := l.Log(Event{Kind: ca.EventIssuerSelfIssuance, SpiffeID: "spiffe://td/issuer", Outcome: "issued"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Log(Event{Kind: ca.EventIssuance, SpiffeID: "spiffe://td/device/d/tool/claude", Outcome: "issued"}); err != nil {
		t.Fatal(err)
	}
	records := decodeRecords(t, buf.String())
	if records[0].Kind != ca.EventIssuerSelfIssuance {
		t.Errorf("self-issuance logged as %q", records[0].Kind)
	}
	if records[0].Kind == records[1].Kind {
		t.Fatal("the issuer's own issuance and a device issuance share a kind")
	}
}

// TestPresenceAgeIsAbsentWhenNoPresenceWasInvolved. An auditor reading
// presence_age_s: 0 on a line with no presence would conclude a human touched
// the sensor at exactly the instant of issuance.
func TestPresenceAgeIsAbsentWhenNoPresenceWasInvolved(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewAuditLog(&buf, nil)
	if _, err := l.Log(Event{Kind: ca.EventIssuerSelfIssuance, Outcome: "issued"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Log(Event{Kind: ca.EventIssuance, Presence: presence.StateNone, Outcome: "issued"}); err != nil {
		t.Fatal(err)
	}
	records := decodeRecords(t, buf.String())
	if records[0].PresenceAgeS != nil {
		t.Error("an event with no presence carried a presence age")
	}
	if records[1].PresenceAgeS == nil {
		t.Error("a recorded presence:none event must still carry its age; none is a value, not a gap")
	}
}

// TestConcurrentAppendsKeepTheChainWhole. Two goroutines appending without a
// lock produce two records claiming the same predecessor, which reads
// downstream as tampering. Run under -race.
func TestConcurrentAppendsKeepTheChainWhole(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewAuditLog(&buf, func() time.Time { return time.Unix(0, 0) })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := l.Log(Event{Kind: ca.EventIssuance, Device: "d", Outcome: "issued"}); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	records := decodeRecords(t, buf.String())
	if len(records) != 200 {
		t.Fatalf("got %d records, want 200", len(records))
	}
	if ok, bad := VerifyChain(records); !ok {
		t.Fatalf("concurrent appends broke the chain at seq %d", bad)
	}
}

// TestEventHasNoFreeFormField. A log line the issuer ships off the box is the
// last place a secret should be able to appear, and the way to guarantee that
// is for there to be nowhere to put one. This fails when someone adds a field,
// which is the moment to ask what will end up in it.
func TestEventHasNoFreeFormField(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"Kind": true, "SpiffeID": true, "Device": true, "ToolAnchor": true,
		"Target": true, "Presence": true, "PresenceAge": true, "GrantID": true,
		"Signer": true, "AgentVersion": true, "Outcome": true, "Reason": true,
		// Added deliberately for EventChainHead. Both are public by
		// construction: shipping the hash off the box is the point of emitting
		// it, and the sequence is an ordinal. This test is what made that a
		// considered edit rather than a casual one.
		"ChainSeq": true, "ChainHash": true,
	}
	e := Event{}
	tp := reflect.TypeOf(e)
	for i := 0; i < tp.NumField(); i++ {
		if !want[tp.Field(i).Name] {
			t.Errorf("Event gained field %q. Every field here is written to a stream that leaves the box; "+
				"decide deliberately what can end up in it.", tp.Field(i).Name)
		}
	}
	if tp.NumField() != len(want) {
		t.Errorf("Event has %d fields, expected %d", tp.NumField(), len(want))
	}
}

// TestChainHeadIsStatedWithItsSequenceAndHash. The line exists so a value the
// host cannot later retract has already left the box; it is worth nothing if
// either half is missing or unlabelled.
func TestChainHeadIsStatedWithItsSequenceAndHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	var buf bytes.Buffer
	log := NewAuditLog(&buf, nil)

	// Empty chain first: "the chain is empty" and "the head was not reported"
	// must not look alike to whatever reads the shipped stream.
	if err := LogChainHead(ctx, log, db, ChainHeadAtOpen); err != nil {
		t.Fatal(err)
	}
	records := decodeRecords(t, buf.String())
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Kind != EventChainHead {
		t.Errorf("kind %q, want %q", records[0].Kind, EventChainHead)
	}
	if records[0].ChainSeq == nil {
		t.Fatal("an empty chain reported no sequence at all, so a reader cannot tell it from a line that is not about the chain")
	}
	if records[0].Outcome != string(ChainHeadAtOpen) {
		t.Errorf("outcome %q; a reader comparing two heads needs to know whether a move was a restore or a restart", records[0].Outcome)
	}

	// Now append something and confirm the head moves and is carried whole.
	if _, err := db.Append(ctx, store.Record{Kind: "svid.issued", At: time.Unix(0, 0), Payload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	wantSeq, wantHash, err := db.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := LogChainHead(ctx, log, db, ChainHeadAfterRestore); err != nil {
		t.Fatal(err)
	}
	records = decodeRecords(t, buf.String())
	head := records[len(records)-1]
	if head.ChainSeq == nil || *head.ChainSeq != wantSeq {
		t.Errorf("sequence %v, want %d", head.ChainSeq, wantSeq)
	}
	if head.ChainHash != hex.EncodeToString(wantHash) {
		t.Errorf("hash %q, want %q", head.ChainHash, hex.EncodeToString(wantHash))
	}
	if head.ChainHash == "" {
		t.Fatal("the head carries no hash, which is the only half an off-box reader cannot recompute")
	}
	if head.Outcome != string(ChainHeadAfterRestore) {
		t.Errorf("outcome %q, want %q", head.Outcome, ChainHeadAfterRestore)
	}
	if ok, bad := VerifyChain(records); !ok {
		t.Fatalf("the stdout chain broke at seq %d", bad)
	}
}

// TestChainHeadFieldsAreCoveredByTheRecordHash. The stdout stream is itself
// hash-chained, so a field that is written but not hashed is a field an editor
// of the shipped log can change without breaking a link.
func TestChainHeadFieldsAreCoveredByTheRecordHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	var buf bytes.Buffer
	if err := LogChainHead(ctx, NewAuditLog(&buf, nil), db, ChainHeadAtOpen); err != nil {
		t.Fatal(err)
	}
	records := decodeRecords(t, buf.String())
	if ok, _ := VerifyChain(records); !ok {
		t.Fatal("a freshly written head line does not verify")
	}

	// Rewrite the head an attacker would want to rewrite.
	tampered := append([]Record(nil), records...)
	tampered[0].ChainHash = "deadbeef"
	if ok, bad := VerifyChain(tampered); ok {
		t.Fatal("the chain hash on a head line can be edited without breaking the record's own hash")
	} else if bad != 0 {
		t.Errorf("first bad seq %d, want 0", bad)
	}

	tampered = append([]Record(nil), records...)
	moved := int64(9999)
	tampered[0].ChainSeq = &moved
	if ok, _ := VerifyChain(tampered); ok {
		t.Fatal("the sequence on a head line can be edited without breaking the record's own hash")
	}
}

// TestLogChainHeadReportsAFailureToReadTheHead. Being unable to answer "where
// does my chain end" at open is a real fault in the state file, and swallowing
// it would mean the one line whose absence matters going missing quietly.
func TestLogChainHeadReportsAFailureToReadTheHead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := LogChainHead(ctx, NewAuditLog(&buf, nil), db, ChainHeadAtOpen); err == nil {
		t.Fatal("a store that cannot report its head produced no error")
	}
	if buf.Len() != 0 {
		t.Errorf("a head line was written despite the head being unreadable: %q", buf.String())
	}
}
