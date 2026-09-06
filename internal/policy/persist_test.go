package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
)

// snapshot is the comparable admin-signed state of an issuer.
type snapshot struct {
	devices []EnrollmentRecord
	windows []presence.Window
}

func snap(iss *Issuer) snapshot {
	ds := iss.Devices()
	for i := range ds {
		ds[i].LastSeen = time.Time{}
	}
	return snapshot{devices: ds, windows: iss.Windows()}
}

func sameSnapshot(t *testing.T, a, b snapshot) {
	t.Helper()
	aj, _ := json.Marshal(a.devices)
	bj, _ := json.Marshal(b.devices)
	if !bytes.Equal(aj, bj) {
		t.Fatalf("devices differ after reload:\n%s\n%s", aj, bj)
	}
	aj, _ = json.Marshal(a.windows)
	bj, _ = json.Marshal(b.windows)
	if !bytes.Equal(aj, bj) {
		t.Fatalf("windows differ after reload:\n%s\n%s", aj, bj)
	}
}

func TestReloadRebuildsFromChain(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	headless := w.enrolled(founder, "headless", false)
	mustErr(t, w.iss.GrantAdmin(ctx, headless, w.sign(founder, ActionGrantAdmin, headless)), nil)
	laptop := w.enrolled(headless, "laptop", true) // approved without presence
	mustErr(t, w.iss.GrantAdmin(ctx, laptop, w.sign(headless, ActionGrantAdmin, laptop)), nil)
	mustErr(t, w.iss.RevokeAdmin(ctx, founder, w.sign(laptop, ActionRevokeAdmin, founder)), nil)
	spare := w.enrolled(laptop, "spare", true)
	mustErr(t, w.iss.RevokeDevice(ctx, spare, w.sign(laptop, ActionRevoke, spare)), nil)
	ws := []presence.Window{{Tool: "aws", Target: "prod", Level: presence.LevelAlways}}
	mustErr(t, w.iss.SetWindows(ctx, ws, w.sign(headless, ActionPresencePolicy, WindowsSubject(ws))), nil)
	g := presence.NewGrant("cassidy", wideScope(), w.clk.Now())
	root, err := w.iss.Sponsor(ctx, g, w.sign(laptop, ActionGrant, GrantSubject(g)))
	mustErr(t, err, nil)
	// A step-up and a deny land in the chain too.
	cred := w.attest(agentID(laptop, "cassidy"), delegatedClaims(root))
	d, _ := w.iss.Evaluate(ctx, cred, Request{Tool: "aws", Target: "prod", Hash: reqHash("p")})
	mustErr(t, w.iss.ApproveParked(ctx, d.ParkedID, w.sign(laptop, ActionStepUp, d.ParkedID)), nil)
	d2, _ := w.iss.Evaluate(ctx, cred, Request{Tool: "aws", Target: "prod", Hash: reqHash("q")})
	mustErr(t, w.iss.DenyParked(ctx, d2.ParkedID, w.sign(headless, ActionDeny, d2.ParkedID)), nil)
	mustErr(t, w.iss.RevokeGrant(ctx, root.ID, w.sign(laptop, ActionRevokeGrant, root.ID)), nil)

	before := snap(w.iss)
	iss, err := w.reopen()
	mustErr(t, err, nil)
	sameSnapshot(t, before, snap(iss))
	e, _ := iss.Device(laptop)
	if !e.Admin || e.ApprovedBy != headless || e.ApprovedByPresence != presence.StateNone {
		t.Fatalf("laptop after reload %+v", e)
	}
	e, _ = iss.Device(founder)
	if e.Admin || !e.Founding {
		t.Fatalf("founder after reload %+v", e)
	}
	// The reloaded issuer keeps enforcing: last admin now is headless +
	// laptop, so revoking one is fine and the second is refused.
	w.iss = iss
	mustErr(t, iss.RevokeAdmin(ctx, headless, w.sign(laptop, ActionRevokeAdmin, headless)), nil)
	_, err = w.trySign(laptop, ActionRevokeAdmin, laptop)
	mustErr(t, err, ErrLastAdmin)
	// Grant metadata survived (the sponsor is known), even though the
	// registry itself could not be restored.
	if m := iss.state.grants[root.ID]; m == nil || m.sponsor != laptop {
		t.Fatalf("grant meta after reload %+v", m)
	}
}

func TestReloadRefusesTampering(t *testing.T) {
	// Build a world with a founder, a non-admin device, and one admin flag
	// change, then attack the chain in every way a compromised host could.
	build := func(t *testing.T) (*world, string, string) {
		w := newWorld(t)
		founder := w.found("founder", true)
		laptop := w.enrolled(founder, "laptop", true)
		return w, founder, laptop
	}

	t.Run("edited payload breaks the chain", func(t *testing.T) {
		w, _, _ := build(t)
		seq := findSeq(w.st, "policy.approve", 2)
		w.st.tamper(seq, func(b []byte) []byte { return bytes.Replace(b, []byte(`"laptop"`), []byte(`"laptoq"`), 1) }, false)
		_, err := w.reopen()
		mustErr(t, err, store.ErrChainBroken)
	})

	t.Run("rechained edit fails signature verification", func(t *testing.T) {
		w, _, _ := build(t)
		seq := findSeq(w.st, "policy.approve", 2)
		// Flip the approval's recorded subject: the signature was over the
		// old digest.
		w.st.tamper(seq, func(b []byte) []byte {
			var rec signedRecord
			if err := json.Unmarshal(b, &rec); err != nil {
				t.Fatal(err)
			}
			rec.Subject = "AAAA-AAAA-AAAA"
			out, _ := json.Marshal(rec)
			return out
		}, true)
		_, err := w.reopen()
		mustErr(t, err, ErrRecordInvalid)
	})

	t.Run("forged unsigned grant-admin is refused", func(t *testing.T) {
		w, _, laptop := build(t)
		payload, _ := devicePayloadFor(ActionGrantAdmin, laptop)
		forged := signedRecord{Ordinal: 3, Action: ActionGrantAdmin, At: w.clk.Now(), Subject: laptop, Payload: payload, Signer: laptop, SignerPresence: presence.StatePresent}
		body, _ := json.Marshal(forged)
		_, err := w.st.Append(ctxb(), store.Record{Kind: "policy.grant-admin", At: w.clk.Now(), Payload: body})
		mustErr(t, err, nil)
		_, err = w.reopen()
		mustErr(t, err, ErrRecordInvalid)
	})

	t.Run("replayed real signature under a rechained edit is refused", func(t *testing.T) {
		w, founder, laptop := build(t)
		// Take the founder's genuine approval assertion and staple it onto a
		// grant-admin record: bindings (target, digest) do not match.
		seq := findSeq(w.st, "policy.approve", 2)
		var approve signedRecord
		json.Unmarshal(w.st.log[seq-1].Payload, &approve)
		payload, _ := devicePayloadFor(ActionGrantAdmin, laptop)
		forged := signedRecord{Ordinal: 3, Action: ActionGrantAdmin, At: w.clk.Now(), Subject: laptop, Payload: payload, Signer: founder, SignerPresence: presence.StatePresent, Assertion: approve.Assertion}
		body, _ := json.Marshal(forged)
		w.st.Append(ctxb(), store.Record{Kind: "policy.grant-admin", At: w.clk.Now(), Payload: body})
		_, err := w.reopen()
		mustErr(t, err, ErrRecordInvalid)
	})

	t.Run("second founding record is refused", func(t *testing.T) {
		// A host that appends a founding record for its OWN key, complete
		// with genuine self-signatures, is still refused: only the first
		// record may be founding.
		w, _, _ := build(t)
		key := newFakeKey(t, true)
		req := w.enrollRequest(key, "rogue", "ROGUE-CODE", testDomain)
		in := req.Input
		digest, _ := in.Digest()
		deviceID := presence.PreEnrollmentDeviceID(in.DevicePublicKey)
		payload, _ := json.Marshal(enrollmentPayload{Input: inputToJSON(in), Signature: req.Signature, PresenceSignature: req.PresenceSignature, Name: "rogue", Founding: true})
		a := presence.Assertion{Version: presence.EncodingVersion, DeviceID: deviceID, Tool: presence.EnrollmentTool, Target: testDomain, Challenge: in.Challenge, Signature: req.PresenceSignature, RequestHash: digest}
		rec := signedRecord{Ordinal: 3, Action: ActionApprove, At: w.clk.Now(), Subject: "founding", Payload: payload, Signer: deviceID, SignerPresence: presence.StatePresent, Assertion: toJSON(&a)}
		body, _ := json.Marshal(rec)
		w.st.Append(ctxb(), store.Record{Kind: "policy.approve", At: w.clk.Now(), Payload: body})
		_, err := w.reopen()
		if !errors.Is(err, ErrRecordInvalid) || !strings.Contains(err.Error(), "founding") {
			t.Fatalf("rogue founding accepted: %v", err)
		}
	})

	t.Run("presence state cannot be relabelled", func(t *testing.T) {
		w, _, _ := build(t)
		seq := findSeq(w.st, "policy.approve", 2)
		w.st.tamper(seq, func(b []byte) []byte {
			var rec signedRecord
			json.Unmarshal(b, &rec)
			rec.SignerPresence = presence.StateNone
			out, _ := json.Marshal(rec)
			return out
		}, true)
		_, err := w.reopen()
		mustErr(t, err, ErrRecordInvalid)
	})

	t.Run("kind and action must agree", func(t *testing.T) {
		w, _, _ := build(t)
		seq := findSeq(w.st, "policy.approve", 2)
		w.st.mu.Lock()
		w.st.log[seq-1].Kind = "policy.grant-admin"
		w.st.mu.Unlock()
		w.st.tamper(seq, func(b []byte) []byte { return b }, true)
		_, err := w.reopen()
		mustErr(t, err, ErrRecordInvalid)
	})

	t.Run("an audit line cannot pose as policy", func(t *testing.T) {
		w, _, _ := build(t)
		_, err := w.iss.Audit(ctxb(), AuditRecord{SpiffeID: "x", Outcome: "ok"})
		mustErr(t, err, nil)
		iss, err := w.reopen()
		mustErr(t, err, nil)
		if len(iss.Devices()) != 2 {
			t.Fatal("audit line changed device state")
		}
	})
}

// findSeq returns the chain seq of the nth record of kind.
func findSeq(m *memStore, kind string, nth int) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.log {
		if r.Kind == kind {
			n++
			if n == nth {
				return r.Seq
			}
		}
	}
	return 0
}

func TestBootstrapCodeIsStoredNotLogged(t *testing.T) {
	w := newWorld(t)
	code, expires, err := w.iss.IssueBootstrapCode(ctxb())
	mustErr(t, err, nil)
	if !expires.Equal(w.clk.Now().Add(BootstrapTTL)) {
		t.Fatalf("expiry %s", expires)
	}
	// The code appears in the envelope-encrypted row and nowhere in the
	// chain.
	w.st.mu.Lock()
	for _, r := range w.st.log {
		if bytes.Contains(r.Payload, []byte(code)) {
			t.Fatal("bootstrap code reached the chain")
		}
	}
	w.st.mu.Unlock()
	row, err := w.st.Get(ctxb(), collectionBootstrap, bootstrapID)
	mustErr(t, err, nil)
	if !bytes.Contains(row, []byte(code)) {
		t.Fatal("bootstrap code not stored")
	}
	// Expired codes are refused, and refused codes are spent.
	w.clk.Advance(BootstrapTTL + time.Second)
	key := newFakeKey(t, true)
	_, err = w.iss.Enroll(context.Background(), w.enrollRequest(key, "late", code, testDomain), issuerFP)
	mustErr(t, err, ErrBootstrapInvalid)
	_, err = w.st.Get(ctxb(), collectionBootstrap, bootstrapID)
	mustErr(t, err, store.ErrNotFound)
	// Reissuing replaces.
	c1, _, _ := w.iss.IssueBootstrapCode(ctxb())
	c2, _, _ := w.iss.IssueBootstrapCode(ctxb())
	_, err = w.iss.Enroll(context.Background(), w.enrollRequest(key, "old", c1, testDomain), issuerFP)
	mustErr(t, err, ErrBootstrapInvalid)
	// ... and that refusal spent c2 as well: one presented code, one spend.
	_, err = w.iss.Enroll(context.Background(), w.enrollRequest(key, "new", c2, testDomain), issuerFP)
	mustErr(t, err, ErrBootstrapInvalid)
}
