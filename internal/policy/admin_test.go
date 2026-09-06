package policy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
)

func TestFoundingEnrollment(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()

	// No admin yet: an ordinary enrollment is pending, and nobody can approve.
	code, id := w.enroll("first", true)
	if _, err := w.iss.Prepare(id, ActionApprove, code); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("unenrolled device prepared a signature: %v", err)
	}

	bootstrap, _, err := w.iss.IssueBootstrapCode(ctx)
	mustErr(t, err, nil)
	key := newFakeKey(t, true)

	// Wrong code: the hash in the signed input is over the code the device
	// sent, so a mismatch between code and hash is refused before the
	// stored code is consulted, and a wrong code is refused and SPENDS the
	// stored code.
	bad := w.enrollRequest(key, "founder", "AAAA-BBBB-CCCC-DDDD-EEEE", testDomain)
	_, err = w.iss.Enroll(ctx, bad, issuerFP)
	mustErr(t, err, ErrBootstrapInvalid)
	good := w.enrollRequest(key, "founder", bootstrap, testDomain)
	_, err = w.iss.Enroll(ctx, good, issuerFP)
	mustErr(t, err, ErrBootstrapInvalid)

	// Fresh code, but the device pinned a different issuer certificate.
	bootstrap, _, _ = w.iss.IssueBootstrapCode(ctx)
	req := w.enrollRequest(key, "founder", bootstrap, testDomain)
	other := bytes.Repeat([]byte{9}, 32)
	_, err = w.iss.Enroll(ctx, req, other)
	mustErr(t, err, ErrIssuerFingerprint)
	// That attempt spent the challenge: the same request replays.
	_, err = w.iss.Enroll(ctx, req, issuerFP)
	mustErr(t, err, presence.ErrChallengeReplayed)

	// The device signed for a different trust domain than the issuer's:
	// the issuer rebuilds the assertion with its OWN domain as the target
	// (the device sends only signature bytes, never a target), so the
	// signature is simply over the wrong bytes.
	req = w.enrollRequest(key, "founder", bootstrap, "evil.example.test")
	_, err = w.iss.Enroll(ctx, req, issuerFP)
	mustErr(t, err, presence.ErrBadSignature)

	// Correct.
	req = w.enrollRequest(key, "founder", bootstrap, testDomain)
	res, err := w.iss.Enroll(ctx, req, issuerFP)
	mustErr(t, err, nil)
	if !res.Approved || res.Presence != presence.StatePresent {
		t.Fatalf("founding result %+v", res)
	}
	e, err := w.iss.Device(res.DeviceID)
	mustErr(t, err, nil)
	if !e.Admin || !e.Founding || e.ApprovedByPresence != presence.StatePresent || e.ApprovedBy != "" {
		t.Fatalf("founding record %+v", e)
	}
	if !bytes.Equal(e.PresencePublicKey, spki(t, key.PresencePublic())) || bytes.Equal(e.PresencePublicKey, e.PublicKey) {
		t.Fatal("presence key not recorded as the presence half")
	}
	// The code is single-use: redeeming it again is refused.
	key2 := newFakeKey(t, true)
	_, err = w.iss.Enroll(ctx, w.enrollRequest(key2, "again", bootstrap, testDomain), issuerFP)
	mustErr(t, err, ErrBootstrapInvalid)
	// The chain has the founding record.
	kinds := w.st.kinds()
	if kinds[len(kinds)-1] != "policy.approve" {
		t.Fatalf("chain kinds %v", kinds)
	}
}

func TestApproveRules(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)

	code, id := w.enroll("laptop", true)
	if p := w.iss.Pending(); len(p) != 1 || p[0].Code != code || p[0].DeviceID != id {
		t.Fatalf("pending %+v", p)
	}

	// Unsigned is refused.
	_, err := w.iss.Approve(ctx, code, Signature{DeviceID: founder})
	mustErr(t, err, ErrUnsigned)

	// A non-admin (pending, not even enrolled) cannot approve, and cannot
	// even obtain a challenge.
	_, err = w.trySign(id, ActionApprove, code)
	mustErr(t, err, ErrDeviceNotFound)

	// A signature over a DIFFERENT pending code does not approve this one.
	code2, id2 := w.enroll("other", true)
	sig := w.sign(founder, ActionApprove, code2)
	_, err = w.iss.Approve(ctx, code, sig)
	mustErr(t, err, presence.ErrTargetMismatch)
	// ... and that challenge is spent now; the same signature cannot then
	// approve the code it was for either.
	_, err = w.iss.Approve(ctx, code2, sig)
	mustErr(t, err, presence.ErrChallengeReplayed)

	// A window-shaped touch (no request hash) never approves: admin ops are
	// presence:always regardless of windows.
	ts, err := w.iss.Prepare(founder, ActionApprove, code)
	mustErr(t, err, nil)
	in := ts.Input
	in.RequestHash = nil
	a, err := presence.Sign(ctx, w.keys[founder], in)
	mustErr(t, err, nil)
	_, err = w.iss.Approve(ctx, code, Signature{DeviceID: founder, Assertion: a})
	mustErr(t, err, presence.ErrRequestHashRequired)

	// A device-key signature from a device that HAS a presence key is a bad
	// signature, never a none-level approval.
	ts, _ = w.iss.Prepare(founder, ActionApprove, code)
	a, err = SignWithoutPresence(ctx, w.keys[founder], ts.Input)
	mustErr(t, err, nil)
	_, err = w.iss.Approve(ctx, code, Signature{DeviceID: founder, Assertion: a})
	mustErr(t, err, presence.ErrBadSignature)

	// Real approval.
	rec, err := w.approveAs(founder, code)
	mustErr(t, err, nil)
	if rec.Admin || rec.ApprovedBy != founder || rec.ApprovedByPresence != presence.StatePresent || rec.DeviceID != id {
		t.Fatalf("approved record %+v", rec)
	}
	if len(w.iss.Pending()) != 1 {
		t.Fatal("approved enrollment still pending")
	}
	// Approving the same code again: gone.
	_, err = w.approveAs(founder, code)
	mustErr(t, err, ErrPendingNotFound)

	// The new device is not admin: it cannot approve.
	_, err = w.approveAs(id, code2)
	mustErr(t, err, ErrNotAdmin)

	// Codes expire.
	w.clk.Advance(PendingTTL + time.Second)
	_, err = w.approveAs(founder, code2)
	mustErr(t, err, ErrPendingExpired)
	_ = id2
}

func TestNoneLevelAdminApprovesWithoutPresence(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)

	// A none-level device: enrolled with no presence key, State none.
	code, noneID := w.enroll("headless", false)
	rec, err := w.approveAs(founder, code)
	mustErr(t, err, nil)
	if rec.Presence != presence.StateNone || len(rec.PresencePublicKey) != 0 {
		t.Fatalf("none-level record %+v", rec)
	}
	// Make it admin (founder signs, present).
	mustErr(t, w.iss.GrantAdmin(ctx, noneID, w.sign(founder, ActionGrantAdmin, noneID)), nil)

	// It approves the next device, with its device key, and the new
	// enrollment records that no human was present for the approval.
	code2, id2 := w.enroll("laptop", true)
	rec2, err := w.approveAs(noneID, code2)
	mustErr(t, err, nil)
	if rec2.ApprovedBy != noneID || rec2.ApprovedByPresence != presence.StateNone || rec2.Presence != presence.StatePresent {
		t.Fatalf("approval by none-level admin recorded as %+v", rec2)
	}
	_ = id2

	// But a none-level device can never sponsor a grant or approve a
	// parked request: those take a presence.Verified and only presence
	// produces one.
	g := presence.NewGrant("cassidy", wideScope(), w.clk.Now())
	_, err = w.iss.Sponsor(ctx, g, w.sign(noneID, ActionGrant, GrantSubject(g)))
	mustErr(t, err, ErrPresenceRequired)

	// And its device key, presented as if it were a presence key, is
	// refused for the founder: the founder's record has a presence key.
	ts, _ := w.iss.Prepare(founder, ActionRevokeAdmin, noneID)
	a, _ := SignWithoutPresence(ctx, w.keys[founder], ts.Input)
	mustErr(t, w.iss.RevokeAdmin(ctx, noneID, Signature{DeviceID: founder, Assertion: a}), presence.ErrBadSignature)

	// The signature's claimed device must be the signer.
	ts, _ = w.iss.Prepare(noneID, ActionRevokeAdmin, founder)
	a, _ = SignWithoutPresence(ctx, w.keys[noneID], ts.Input)
	mustErr(t, w.iss.RevokeAdmin(ctx, founder, Signature{DeviceID: founder, Assertion: a}), ErrNotEnrolled)
}

func TestLastAdminAndRevocation(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	second := w.enrolled(founder, "second", true)

	// Only one admin: revoke-admin and revoke are refused for it. Prepare
	// refuses before a challenge is minted, so no human is prompted for a
	// doomed change; and a client that skips Prepare is refused at apply.
	_, err := w.trySign(founder, ActionRevokeAdmin, founder)
	mustErr(t, err, ErrLastAdmin)
	_, err = w.trySign(founder, ActionRevoke, founder)
	mustErr(t, err, ErrLastAdmin)
	if w.ver.Outstanding() != 0 {
		t.Fatal("refused Prepare minted a challenge")
	}
	mustErr(t, w.iss.RevokeAdmin(ctx, founder, w.forge(founder, ActionRevokeAdmin, founder)), ErrLastAdmin)
	mustErr(t, w.iss.RevokeDevice(ctx, founder, w.forge(founder, ActionRevoke, founder)), ErrLastAdmin)
	// A non-admin cannot grant admin, revoke, or set policy: refused at
	// Prepare and at apply.
	_, err = w.trySign(second, ActionGrantAdmin, second)
	mustErr(t, err, ErrNotAdmin)
	mustErr(t, w.iss.GrantAdmin(ctx, second, w.forge(second, ActionGrantAdmin, second)), ErrNotAdmin)
	mustErr(t, w.iss.RevokeDevice(ctx, founder, w.forge(second, ActionRevoke, founder)), ErrNotAdmin)
	mustErr(t, w.iss.SetWindows(ctx, presence.DefaultWindows(), w.forge(second, ActionPresencePolicy, WindowsSubject(presence.DefaultWindows()))), ErrNotAdmin)

	// Two admins: now the founder can step down, and then cannot be revoked
	// as "last" but CAN be revoked as a non-admin.
	mustErr(t, w.iss.GrantAdmin(ctx, second, w.sign(founder, ActionGrantAdmin, second)), nil)
	mustErr(t, w.iss.RevokeAdmin(ctx, founder, w.sign(second, ActionRevokeAdmin, founder)), nil)
	e, _ := w.iss.Device(founder)
	if e.Admin {
		t.Fatal("founder still admin")
	}
	// The ex-admin cannot act as admin any more.
	mustErr(t, w.iss.GrantAdmin(ctx, founder, w.forge(founder, ActionGrantAdmin, founder)), ErrNotAdmin)
	// second is now the last admin.
	mustErr(t, w.iss.RevokeAdmin(ctx, second, w.forge(second, ActionRevokeAdmin, second)), ErrLastAdmin)
	// Revoke the founder device entirely.
	mustErr(t, w.iss.RevokeDevice(ctx, founder, w.sign(second, ActionRevoke, founder)), nil)
	e, _ = w.iss.Device(founder)
	if !e.Revoked || e.Live() {
		t.Fatalf("founder not revoked: %+v", e)
	}
	// A revoked device cannot sign anything, not even a challenge.
	_, err = w.iss.Prepare(founder, ActionGrantAdmin, second)
	mustErr(t, err, ErrDeviceRevoked)
	// Nor be granted admin.
	_, err = w.trySign(second, ActionGrantAdmin, founder)
	mustErr(t, err, ErrDeviceRevoked)
	mustErr(t, w.iss.GrantAdmin(ctx, founder, w.forge(second, ActionGrantAdmin, founder)), ErrDeviceRevoked)
	// It can re-enroll (same key) and wait for approval like anyone.
	res, err := w.iss.Enroll(ctx, w.enrollRequest(w.keys[founder], "founder-again", "", testDomain), issuerFP)
	mustErr(t, err, nil)
	if res.Approved {
		t.Fatal("re-enrollment auto-approved")
	}
	devices := w.iss.Devices()
	if len(devices) != 2 {
		t.Fatalf("devices %d", len(devices))
	}
}

func TestPresencePolicySigned(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)

	ws := []presence.Window{
		{Tool: "claude", Duration: time.Hour, Level: presence.LevelWindow},
		{Tool: "aws", Target: "dev", Duration: 15 * time.Minute, Level: presence.LevelWindow},
		{Tool: "aws", Target: "prod", Level: presence.LevelAlways},
		{Tool: "homeassistant", Level: presence.LevelStepUp},
	}
	// Over MaxWindow is refused by policy before any signature.
	bad := append([]presence.Window{{Tool: "gh", Duration: 2 * time.Hour, Level: presence.LevelWindow}}, ws...)
	mustErr(t, w.iss.SetWindows(ctx, bad, Signature{}), ErrPolicyInvalid)
	mustErr(t, w.iss.SetWindows(ctx, []presence.Window{{Tool: "gh", Duration: time.Minute, Level: "forever"}}, Signature{}), ErrPolicyInvalid)
	mustErr(t, w.iss.SetWindows(ctx, ws, Signature{DeviceID: founder}), ErrUnsigned)

	// Signing one policy and submitting another is refused: the subject is
	// the digest of the windows.
	sig := w.sign(founder, ActionPresencePolicy, WindowsSubject(ws[:2]))
	mustErr(t, w.iss.SetWindows(ctx, ws, sig), presence.ErrTargetMismatch)

	mustErr(t, w.iss.SetWindows(ctx, ws, w.sign(founder, ActionPresencePolicy, WindowsSubject(ws))), nil)
	if got := w.iss.Windows(); len(got) != 4 {
		t.Fatalf("windows %+v", got)
	}
	if wnd, ok := w.iss.Window("aws", "prod"); !ok || wnd.Level != presence.LevelAlways {
		t.Fatalf("aws prod window %+v %v", wnd, ok)
	}
	if wnd, ok := w.iss.Window("aws", "unknown"); ok {
		t.Fatalf("aws unknown profile matched %+v", wnd)
	}
	if wnd, ok := w.iss.Window("homeassistant", "lock.front_door#unlock"); !ok || wnd.Level != presence.LevelStepUp {
		t.Fatalf("tool-wide window %+v %v", wnd, ok)
	}
	if _, ok := w.iss.Window("git", ""); ok {
		t.Fatal("dropped tool still has a window")
	}
	kinds := w.st.kinds()
	if kinds[len(kinds)-1] != "policy.presence-policy" {
		t.Fatalf("chain %v", kinds)
	}
}

func TestVerifierSpendsBeforeKeyCheck(t *testing.T) {
	// The none-level signing path relies on presence.Verifier.Verify
	// spending the challenge before it reports ErrNoPresenceKey. Hold the
	// real verifier to that.
	clk := newClock()
	ver := presence.NewVerifier(0, clk.Now)
	key := newFakeKey(t, false)
	ch, err := ver.Mint("dev")
	mustErr(t, err, nil)
	in := presence.SigningInput{DeviceID: "dev", Tool: SigningTool, Target: "x", Challenge: ch, RequestHash: reqHash("r")}
	a, err := SignWithoutPresence(context.Background(), key, in)
	mustErr(t, err, nil)
	exp := presence.Expectation{DeviceID: "dev", Tool: SigningTool, Target: "x", Binding: presence.BindingRequired, RequestHash: in.RequestHash}
	_, err = ver.Verify(a, exp)
	mustErr(t, err, presence.ErrNoPresenceKey)
	_, err = ver.Verify(a, exp)
	mustErr(t, err, presence.ErrChallengeReplayed)
	// And the detached half accepts the device-key signature over exactly
	// those bytes when the device key is passed as the presence key, and
	// refuses another device's key.
	exp.PresenceKey = &key.device.PublicKey
	v, err := presence.VerifyDetached(a, exp, clk.Now())
	mustErr(t, err, nil)
	if !v.Used() {
		t.Fatal("detached proof came back consumable")
	}
	exp.PresenceKey = &newFakeKey(t, false).device.PublicKey
	_, err = presence.VerifyDetached(a, exp, clk.Now())
	mustErr(t, err, presence.ErrBadSignature)
}

func TestConfigRefusesMissingPrimitives(t *testing.T) {
	_, err := New(ctxb(), Config{})
	if err == nil {
		t.Fatal("empty config accepted")
	}
	clk := newClock()
	_, err = New(ctxb(), Config{TrustDomain: "x", Verifier: presence.NewVerifier(0, clk.Now), Sessions: presence.NewSessionStore(clk.Now),
		Grants: presence.NewRegistry(clk.Now), Lot: presence.NewLot(clk.Now, 0, 0), Store: newMemStore(clk.Now),
		Windows: []presence.Window{{Tool: "claude", Duration: 3 * time.Hour, Level: presence.LevelWindow}}})
	mustErr(t, err, ErrPolicyInvalid)
}

var _ store.Store = (*memStore)(nil)

func TestEnrollSpendsOneChallengeForBothSignatures(t *testing.T) {
	// One issuer-minted challenge covers BOTH enrollment signatures (device
	// proof of possession and presence assertion). policy.Enroll hands both
	// to presence.Verifier.Enroll in one call, so the challenge is spent
	// once; verifying the two separately would spend it on the first and
	// fail the second as a replay, a bug that only shows against real
	// hardware. Assert it here against the real verifier.
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	key := newFakeKey(t, true)

	req := w.enrollRequest(key, "laptop", "", testDomain)
	if w.ver.Outstanding() != 1 {
		t.Fatalf("outstanding before enroll %d", w.ver.Outstanding())
	}
	res, err := w.iss.Enroll(ctx, req, issuerFP)
	mustErr(t, err, nil)
	if res.Presence != presence.StatePresent || res.Approved {
		t.Fatalf("enroll result %+v", res)
	}
	if w.ver.Outstanding() != 0 {
		t.Fatalf("challenge not spent exactly once: %d outstanding", w.ver.Outstanding())
	}
	// The same request again is a replay, not a second pending entry.
	_, err = w.iss.Enroll(ctx, req, issuerFP)
	mustErr(t, err, presence.ErrChallengeReplayed)
	if len(w.iss.Pending()) != 1 {
		t.Fatalf("pending %d", len(w.iss.Pending()))
	}

	// A presence assertion signed over a DIFFERENT challenge than the
	// enrollment input is refused as a split, before anything is spent.
	req2 := w.enrollRequest(newFakeKey(t, true), "split", "", testDomain)
	other := w.enrollRequest(newFakeKey(t, true), "donor", "", testDomain)
	split := req2
	split.Input.Challenge = other.Input.Challenge
	_, err = w.iss.Enroll(ctx, split, issuerFP)
	if !errors.Is(err, presence.ErrEnrollmentMalformed) && !errors.Is(err, presence.ErrChallengeReplayed) &&
		!errors.Is(err, presence.ErrUnknownChallenge) && !errors.Is(err, presence.ErrEnrollmentBadSignature) {
		t.Fatalf("split challenge accepted or wrong class: %v", err)
	}
	// And a request whose presence signature is simply over the wrong
	// challenge (device signature intact) is refused, spending the one
	// challenge it named.
	req3 := w.enrollRequest(newFakeKey(t, true), "wrong-presence", "", testDomain)
	req3.PresenceSignature = req.PresenceSignature
	_, err = w.iss.Enroll(ctx, req3, issuerFP)
	mustErr(t, err, presence.ErrBadSignature)
	_, err = w.iss.Enroll(ctx, req3, issuerFP)
	mustErr(t, err, presence.ErrChallengeReplayed)

	// The founder approves the good one; both signatures live in the record
	// and re-verify on reload.
	_, err = w.approveAs(founder, res.Code)
	mustErr(t, err, nil)
	iss, err := w.reopen()
	mustErr(t, err, nil)
	e, err := iss.Device(res.DeviceID)
	mustErr(t, err, nil)
	if e.Presence != presence.StatePresent || !e.Live() {
		t.Fatalf("after reload %+v", e)
	}
}
