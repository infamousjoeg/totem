package server

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/presence"
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
