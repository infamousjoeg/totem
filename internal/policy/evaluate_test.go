package policy

import (
	"context"
	"crypto/x509"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// touch signs a presence assertion on the requesting device for a tool
// request, the way a bridge would: the issuer mints, the device signs.
func (w *world) touch(deviceID, tool, target string, requestHash []byte) *presence.Assertion {
	w.t.Helper()
	ch, err := w.ver.Mint(deviceID)
	if err != nil {
		w.t.Fatal(err)
	}
	a, err := presence.Sign(context.Background(), w.keys[deviceID], presence.SigningInput{
		DeviceID: deviceID, Tool: tool, Target: target, Challenge: ch, RequestHash: requestHash,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return a
}

func TestRequestCarriesNoIdentity(t *testing.T) {
	// The structural claim: nothing in a request body can name a grant, a
	// device, or a presence state. If a field like that is ever added, this
	// fails and the reviewer has to argue for it.
	rt := reflect.TypeOf(Request{})
	for i := 0; i < rt.NumField(); i++ {
		n := strings.ToLower(rt.Field(i).Name)
		for _, bad := range []string{"grant", "device", "presence", "state", "provenance", "spiffe", "agent"} {
			if strings.Contains(n, bad) {
				t.Fatalf("Request has an identity-shaped field %q", rt.Field(i).Name)
			}
		}
	}
	at := reflect.TypeOf(Attested{})
	for i := 0; i < at.NumField(); i++ {
		if at.Field(i).IsExported() {
			t.Fatalf("Attested has an exported field %q; a caller could set it", at.Field(i).Name)
		}
	}
}

func TestToolPresenceWindows(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	dev := w.enrolled(founder, "laptop", true)
	ws := []presence.Window{
		{Tool: "claude", Duration: time.Hour, Level: presence.LevelWindow},
		{Tool: "aws", Target: "dev", Duration: 15 * time.Minute, Level: presence.LevelWindow},
		{Tool: "aws", Target: "prod", Level: presence.LevelAlways},
		{Tool: "homeassistant", Level: presence.LevelStepUp},
	}
	mustErr(t, w.iss.SetWindows(ctx, ws, w.sign(founder, ActionPresencePolicy, WindowsSubject(ws))), nil)

	claude := w.attest(toolID(dev, "claude"), presentClaims())

	// Default deny for anything without a policy, and for a tool the
	// credential is not for.
	d, err := w.iss.Evaluate(ctx, claude, Request{Tool: "gh"})
	mustErr(t, err, nil)
	if d.Verdict != VerdictDeny {
		t.Fatalf("cross-tool request %+v", d)
	}
	d, _ = w.iss.Evaluate(ctx, w.attest(toolID(dev, "gh"), presentClaims()), Request{Tool: "gh"})
	if d.Verdict != VerdictDeny || !strings.Contains(d.Reason, Default) {
		t.Fatalf("no-policy request %+v", d)
	}

	// Windowed: prompt, then a touch opens the window, then satisfied with
	// an age, then expired.
	d, _ = w.iss.Evaluate(ctx, claude, Request{Tool: "claude"})
	if d.Verdict != VerdictPrompt || d.Binding != presence.BindingNone {
		t.Fatalf("first claude request %+v", d)
	}
	// A touch for the wrong tool does not open it.
	_, err = w.iss.Present(ctx, claude, Request{Tool: "claude"}, w.touch(dev, "gh", "", nil))
	mustErr(t, err, presence.ErrToolMismatch)
	// A touch signed by ANOTHER enrolled device's key does not open it.
	_, err = w.iss.Present(ctx, claude, Request{Tool: "claude"}, w.touch(founder, "claude", "", nil))
	mustErr(t, err, presence.ErrUnknownChallenge)
	// A device-key signature (no human) does not open it.
	ch, _ := w.ver.Mint(dev)
	fake, _ := SignWithoutPresence(ctx, w.keys[dev], presence.SigningInput{DeviceID: dev, Tool: "claude", Challenge: ch})
	_, err = w.iss.Present(ctx, claude, Request{Tool: "claude"}, fake)
	mustErr(t, err, presence.ErrBadSignature)

	d, err = w.iss.Present(ctx, claude, Request{Tool: "claude"}, w.touch(dev, "claude", "", nil))
	mustErr(t, err, nil)
	if d.Verdict != VerdictAllow || d.Presence != presence.StatePresent {
		t.Fatalf("touch %+v", d)
	}
	w.clk.Advance(10 * time.Minute)
	d, _ = w.iss.Evaluate(ctx, claude, Request{Tool: "claude"})
	if d.Verdict != VerdictAllow || d.PresenceAge != 10*time.Minute {
		t.Fatalf("within window %+v", d)
	}
	w.clk.Advance(time.Hour)
	d, _ = w.iss.Evaluate(ctx, claude, Request{Tool: "claude"})
	if d.Verdict != VerdictPrompt {
		t.Fatalf("after window %+v", d)
	}

	// presence:always: never satisfied by a window, needs the bound hash,
	// and a bound touch never opens a window.
	aws := w.attest(toolID(dev, "aws"), presentClaims())
	h := reqHash("sts", "prod", "AssumeRole")
	d, _ = w.iss.Evaluate(ctx, aws, Request{Tool: "aws", Target: "prod", Hash: h})
	if d.Verdict != VerdictPrompt || d.Binding != presence.BindingRequired {
		t.Fatalf("prod %+v", d)
	}
	_, err = w.iss.Present(ctx, aws, Request{Tool: "aws", Target: "prod", Hash: h}, w.touch(dev, "aws", "prod", nil))
	mustErr(t, err, presence.ErrRequestHashRequired)
	_, err = w.iss.Present(ctx, aws, Request{Tool: "aws", Target: "prod", Hash: h}, w.touch(dev, "aws", "prod", reqHash("other")))
	mustErr(t, err, presence.ErrRequestHashMismatch)
	d, err = w.iss.Present(ctx, aws, Request{Tool: "aws", Target: "prod", Hash: h}, w.touch(dev, "aws", "prod", h))
	mustErr(t, err, nil)
	if d.Verdict != VerdictAllow {
		t.Fatalf("bound touch %+v", d)
	}
	d, _ = w.iss.Evaluate(ctx, aws, Request{Tool: "aws", Target: "prod", Hash: h})
	if d.Verdict != VerdictPrompt {
		t.Fatalf("always target held a session: %+v", d)
	}
	// Money above trivial on a windowed target escalates to always.
	_, err = w.iss.Present(ctx, aws, Request{Tool: "aws", Target: "dev"}, w.touch(dev, "aws", "dev", nil))
	mustErr(t, err, nil)
	d, _ = w.iss.Evaluate(ctx, aws, Request{Tool: "aws", Target: "dev"})
	if d.Verdict != VerdictAllow {
		t.Fatalf("dev window %+v", d)
	}
	d, _ = w.iss.Evaluate(ctx, aws, Request{Tool: "aws", Target: "dev", AmountUSD: 6, Hash: h})
	if d.Verdict != VerdictPrompt || d.Binding != presence.BindingRequired {
		t.Fatalf("money on windowed target %+v", d)
	}
	// An amount that is not provably trivial (NaN, infinite, negative)
	// escalates too; it must not slide under the floor by failing a compare.
	for _, amt := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		d, _ = w.iss.Evaluate(ctx, aws, Request{Tool: "aws", Target: "dev", AmountUSD: amt, Hash: h})
		if d.Verdict != VerdictPrompt || d.Binding != presence.BindingRequired {
			t.Fatalf("amount %v on windowed target %+v", amt, d)
		}
	}

	// step-up parks with an id, and a present human on ANOTHER device
	// approves it bound to the request.
	ha := w.attest(toolID(dev, "homeassistant"), presentClaims())
	hh := reqHash("unlock", "front_door")
	d, err = w.iss.Evaluate(ctx, ha, Request{Tool: "homeassistant", Target: "lock.front_door#unlock", Hash: hh, Description: "unlock the front door"})
	mustErr(t, err, nil)
	if d.Verdict != VerdictPark || d.ParkedID == "" {
		t.Fatalf("step-up %+v", d)
	}
	mustErr(t, w.iss.ApproveParked(ctx, d.ParkedID, w.sign(founder, ActionStepUp, d.ParkedID)), nil)
	item, err := w.iss.Consume(ctx, d.ParkedID)
	mustErr(t, err, nil)
	if item.ApprovedBy != founder || item.State != presence.ParkedConsumed {
		t.Fatalf("consumed %+v", item)
	}
	_, err = w.iss.Consume(ctx, d.ParkedID)
	mustErr(t, err, presence.ErrParkedConsumed)

	// A revoked device is denied everything, and its session is gone.
	other := w.enrolled(founder, "spare", true)
	mustErr(t, w.iss.GrantAdmin(ctx, other, w.sign(founder, ActionGrantAdmin, other)), nil)
	mustErr(t, w.iss.RevokeDevice(ctx, dev, w.sign(founder, ActionRevoke, dev)), nil)
	d, _ = w.iss.Evaluate(ctx, aws, Request{Tool: "aws", Target: "dev"})
	if d.Verdict != VerdictDeny {
		t.Fatalf("revoked device %+v", d)
	}
	if w.sess.Len() != 0 {
		t.Fatal("revoked device kept a session")
	}
}

func TestNoneLevelDevice(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	dev := w.enrolled(founder, "server", false)
	ws := []presence.Window{
		{Tool: "gh", Duration: 15 * time.Minute, Level: presence.LevelWindow},
		{Tool: "aws", Target: "prod", Level: presence.LevelAlways},
	}
	mustErr(t, w.iss.SetWindows(ctx, ws, w.sign(founder, ActionPresencePolicy, WindowsSubject(ws))), nil)
	none := Claims{ProtectionLevel: spiffe.ProtectionSoftware, State: presence.StateNone}
	d, _ := w.iss.Evaluate(ctx, w.attest(toolID(dev, "gh"), none), Request{Tool: "gh"})
	if d.Verdict != VerdictAllow || d.Presence != presence.StateNone {
		t.Fatalf("none-level windowed %+v", d)
	}
	d, _ = w.iss.Evaluate(ctx, w.attest(toolID(dev, "aws"), none), Request{Tool: "aws", Target: "prod", Hash: reqHash("x")})
	if d.Verdict != VerdictDeny {
		t.Fatalf("none-level always %+v", d)
	}
	// A present-claiming credential on a none-level device still cannot
	// present a touch: there is no presence key to verify against.
	ch, _ := w.ver.Mint(dev)
	a, _ := SignWithoutPresence(ctx, w.keys[dev], presence.SigningInput{DeviceID: dev, Tool: "gh", Challenge: ch})
	_, err := w.iss.Present(ctx, w.attest(toolID(dev, "gh"), presentClaims()), Request{Tool: "gh"}, a)
	mustErr(t, err, presence.ErrNoPresenceKey)
}

func TestAgentGrantEvaluation(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	box := w.enrolled(founder, "studio", true)

	g := presence.NewGrant("cassidy", wideScope(), w.clk.Now())
	// Signing one grant and submitting another: refused by the registry's
	// own hash check after policy's target check.
	other := presence.NewGrant("cassidy", presence.Scope{ClaudeProxy: true}, w.clk.Now())
	_, err := w.iss.Sponsor(ctx, other, w.sign(founder, ActionGrant, GrantSubject(g)))
	mustErr(t, err, presence.ErrTargetMismatch)
	root, err := w.iss.Sponsor(ctx, g, w.sign(founder, ActionGrant, GrantSubject(g)))
	mustErr(t, err, nil)
	if root.Sponsor != founder || root.Provenance().State != presence.StateDelegated {
		t.Fatalf("root %+v", root)
	}

	// An agent identity with no grant is refused at attest; with a grant
	// for another agent, denied at evaluate.
	_, err = w.tryAttest(agentID(box, "cassidy"), presentClaims())
	mustErr(t, err, ErrCredential)
	ember := w.attest(agentID(box, "ember"), delegatedClaims(root))
	d, _ := w.iss.Evaluate(ctx, ember, Request{Tool: "aws", Target: "dev"})
	if d.Verdict != VerdictDeny {
		t.Fatalf("wrong agent %+v", d)
	}
	// A tool identity carrying a grant is refused at attest.
	_, err = w.tryAttest(toolID(box, "aws"), delegatedClaims(root))
	mustErr(t, err, ErrCredential)

	cassidy := w.attest(agentID(box, "cassidy"), delegatedClaims(root))
	allow := func(req Request) Decision {
		t.Helper()
		d, err := w.iss.Evaluate(ctx, cassidy, req)
		mustErr(t, err, nil)
		if d.Verdict != VerdictAllow || d.Presence != presence.StateDelegated || d.Provenance.GrantID != root.ID {
			t.Fatalf("%+v -> %+v", req, d)
		}
		return d
	}
	park := func(req Request, rev presence.Reversibility) Decision {
		t.Helper()
		d, err := w.iss.Evaluate(ctx, cassidy, req)
		mustErr(t, err, nil)
		if d.Verdict != VerdictPark || d.ParkedID == "" || d.Reversibility != rev {
			t.Fatalf("%+v -> %+v", req, d)
		}
		return d
	}
	allow(Request{Tool: "aws", Target: "dev"})
	allow(Request{Tool: "gh", Target: "infamousjoeg/totem:contents:read"})
	allow(Request{Tool: "claude"})
	allow(Request{Tool: "homeassistant", Target: "sensor.freezer#read"})
	// Entity tiers: same relying party, different entity/action.
	park(Request{Tool: "homeassistant", Target: "lock.front_door#lock", Hash: reqHash("lock"), Reversibility: presence.Reversible}, presence.Reversible)
	park(Request{Tool: "aws", Target: "prod", Hash: reqHash("prod")}, presence.Irreversible)
	park(Request{Tool: "gh", Target: "other/repo:contents:write", Hash: reqHash("gh")}, presence.Irreversible)
	// Parking needs a hash.
	d, _ = w.iss.Evaluate(ctx, cassidy, Request{Tool: "aws", Target: "prod"})
	if d.Verdict != VerdictDeny {
		t.Fatalf("park without hash %+v", d)
	}

	// Money: trivial inside ceilings is delegated and counts; above trivial
	// parks irreversible even though inside the ceiling; over ceiling
	// parks; the day total binds.
	d = allow(Request{Tool: "homeassistant", Target: "sensor.freezer#read", AmountUSD: 4})
	if d.Money != presence.MoneyDelegated {
		t.Fatalf("trivial money %+v", d)
	}
	d = park(Request{Tool: "homeassistant", Target: "sensor.freezer#read", AmountUSD: 6, Hash: reqHash("6"), Reversibility: presence.Reversible}, presence.Irreversible)
	if d.Money != presence.MoneyStepUp {
		t.Fatalf("step-up money %+v", d)
	}
	d = park(Request{Tool: "homeassistant", Target: "sensor.freezer#read", AmountUSD: 25, Hash: reqHash("25")}, presence.Irreversible)
	if d.Money != presence.MoneyOverCeiling {
		t.Fatalf("over ceiling %+v", d)
	}
	for range 24 {
		allow(Request{Tool: "homeassistant", Target: "sensor.freezer#read", AmountUSD: 4})
	}
	d = park(Request{Tool: "homeassistant", Target: "sensor.freezer#read", AmountUSD: 4, Hash: reqHash("101")}, presence.Irreversible)
	if d.Money != presence.MoneyOverCeiling {
		t.Fatalf("daily ceiling %+v", d)
	}

	// Step-up from the morning list: reversible items batch, irreversible
	// never batch, a none-level device cannot approve.
	rev := w.iss.PendingParked(presence.Reversible)
	irr := w.iss.PendingParked(presence.Irreversible)
	if len(rev) != 1 || len(irr) < 3 {
		t.Fatalf("pending rev=%d irr=%d", len(rev), len(irr))
	}
	ids := []string{rev[0].ID, irr[0].ID}
	mustErr(t, w.iss.ApproveBatch(ctx, ids, w.sign(founder, ActionStepUpBatch, BatchSubject(ids))), presence.ErrIrreversibleInBatch)
	ids = []string{rev[0].ID}
	mustErr(t, w.iss.ApproveBatch(ctx, ids, w.sign(founder, ActionStepUpBatch, BatchSubject(ids))), nil)
	headless := w.enrolled(founder, "headless", false)
	mustErr(t, w.iss.ApproveParked(ctx, irr[0].ID, w.sign(headless, ActionStepUp, irr[0].ID)), ErrPresenceRequired)
	mustErr(t, w.iss.DenyParked(ctx, irr[0].ID, w.sign(headless, ActionDeny, irr[0].ID)), nil)
	mustErr(t, w.iss.ApproveParked(ctx, irr[1].ID, w.sign(box, ActionStepUp, irr[1].ID)), nil)
	item, _ := w.iss.Poll(irr[1].ID)
	if item.State != presence.ParkedApproved || item.ApprovedBy != box {
		t.Fatalf("approved %+v", item)
	}

	// Revocation: only admin or sponsor; then everything under it stops.
	spare := w.enrolled(founder, "spare", true)
	mustErr(t, w.iss.RevokeGrant(ctx, root.ID, w.sign(spare, ActionRevokeGrant, root.ID)), ErrNotSponsor)
	mustErr(t, w.iss.RevokeGrant(ctx, root.ID, w.sign(founder, ActionRevokeGrant, root.ID)), nil)
	d, _ = w.iss.Evaluate(ctx, cassidy, Request{Tool: "aws", Target: "dev"})
	if d.Verdict != VerdictDeny || !strings.Contains(d.Reason, "revoked") {
		t.Fatalf("after revoke %+v", d)
	}
}

func TestPresentedGrantIsTheAttestedOne(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	box := w.enrolled(founder, "studio", true)
	g := presence.NewGrant("cassidy", wideScope(), w.clk.Now())
	root, err := w.iss.Sponsor(ctx, g, w.sign(founder, ActionGrant, GrantSubject(g)))
	mustErr(t, err, nil)
	rootCred := w.attest(agentID(box, "cassidy"), delegatedClaims(root))

	sess, err := w.iss.OpenSession(ctx, rootCred, "")
	mustErr(t, err, nil)
	narrow := presence.Scope{Capabilities: []string{"homeassistant/sensor.freezer#read"}}
	child, err := w.iss.Narrow(ctx, rootCred, sess.ID, narrow, time.Time{})
	mustErr(t, err, nil)
	if child.RootID() != root.ID || child.ParentID() != root.ID {
		t.Fatalf("child lineage %+v", child)
	}
	// The session now evaluates under the sub-grant.
	d, _ := w.iss.Evaluate(ctx, rootCred, Request{Tool: "aws", Target: "dev", Hash: reqHash("x"), SessionID: sess.ID})
	if d.Verdict != VerdictPark || d.Provenance.GrantID != child.ID {
		t.Fatalf("narrowed session %+v", d)
	}
	// Without the session, the root credential is still the root grant:
	// narrowing is per session.
	d, _ = w.iss.Evaluate(ctx, rootCred, Request{Tool: "aws", Target: "dev"})
	if d.Verdict != VerdictAllow {
		t.Fatalf("root credential outside session %+v", d)
	}

	// THE attack: a credential minted under the sub-grant tries to walk
	// around narrowing. It cannot name the root in a request (no field), it
	// cannot open a session on the root (ErrNotHolder), it cannot use the
	// root's session (ErrNotHolder: the session's active grant is not its
	// grant or a descendant), and a tool it was narrowed away from parks.
	childCred := w.attest(agentID(box, "cassidy"), delegatedClaims(child))
	_, err = w.iss.OpenSession(ctx, childCred, root.ID)
	mustErr(t, err, presence.ErrNotHolder)
	// Widen the session back to the root with presence, then the child
	// credential cannot ride that session either.
	mustErr(t, func() error {
		_, err := w.iss.Widen(ctx, sess.ID, root.ID, w.sign(founder, ActionWiden, WidenSubject(sess.ID, root.ID)))
		return err
	}(), nil)
	d, err = w.iss.Evaluate(ctx, childCred, Request{Tool: "aws", Target: "dev", SessionID: sess.ID})
	mustErr(t, err, nil)
	if d.Verdict != VerdictDeny || !strings.Contains(d.Reason, presence.ErrNotHolder.Error()) {
		t.Fatalf("child credential on widened session %+v", d)
	}
	d, _ = w.iss.Evaluate(ctx, childCred, Request{Tool: "aws", Target: "dev", Hash: reqHash("y")})
	if d.Verdict != VerdictPark || d.Provenance.GrantID != child.ID {
		t.Fatalf("child credential %+v", d)
	}
	// Another agent's credential cannot use this session.
	emberRoot, _ := w.iss.Sponsor(ctx, presence.NewGrant("ember", wideScope(), w.clk.Now()), w.sign(founder, ActionGrant, GrantSubject(presence.NewGrant("ember", wideScope(), w.clk.Now()))))
	ember := w.attest(agentID(box, "ember"), delegatedClaims(emberRoot))
	_, err = w.iss.Narrow(ctx, ember, sess.ID, narrow, time.Time{})
	mustErr(t, err, ErrNotAgentIdentity)

	// Widening needs presence bound to exactly this widen: a none-level
	// signer is refused, and so is a widen signed for a different target.
	child2, _ := w.iss.Narrow(ctx, rootCred, sess.ID, narrow, time.Time{})
	_ = child2
	headless := w.enrolled(founder, "headless", false)
	_, err = w.iss.Widen(ctx, sess.ID, root.ID, w.sign(headless, ActionWiden, WidenSubject(sess.ID, root.ID)))
	mustErr(t, err, ErrPresenceRequired)
	_, err = w.iss.Widen(ctx, sess.ID, root.ID, w.sign(founder, ActionWiden, WidenSubject(sess.ID, child.ID)))
	mustErr(t, err, presence.ErrTargetMismatch)
}

func TestAttestPeer(t *testing.T) {
	w := newWorld(t)
	// Round trip through a real certificate.
	prov := presence.Provenance{State: presence.StateDelegated, GrantID: "g1", RootID: "g0", Lineage: []string{"g0"}, Sponsor: "dev", SignedAt: w.clk.Now()}
	a := w.attest(agentID("dev", "cassidy"), Claims{ProtectionLevel: spiffe.ProtectionHardware, State: presence.StateDelegated, Provenance: prov})
	if a.GrantID() != "g1" || a.Provenance().RootID != "g0" || !a.Provenance().SignedAt.Equal(w.clk.Now()) || a.ID().Agent != "cassidy" || a.ProtectionLevel() != spiffe.ProtectionHardware {
		t.Fatalf("round trip %+v", a)
	}
	// No extension: presence none, no grant.
	cert := selfSigned(t, "spiffe://td/device/d/tool/claude")
	a2, err := AttestPeer([][]*x509.Certificate{{cert}})
	mustErr(t, err, nil)
	if a2.State() != presence.StateNone || a2.GrantID() != "" {
		t.Fatalf("bare cert %+v", a2)
	}
	// Refusals.
	for _, uri := range []string{"https://td/device/d/tool/claude", "spiffe://td/device/d/other/x", "spiffe://td/device//tool/claude", "spiffe:///device/d/tool/claude"} {
		_, err := AttestPeer([][]*x509.Certificate{{selfSigned(t, uri)}})
		mustErr(t, err, ErrCredential)
	}
	_, err = AttestPeer(nil)
	mustErr(t, err, ErrCredential)
	// Inconsistent claims refused at mint.
	_, err = ProvenanceExtension(Claims{State: presence.StateDelegated})
	mustErr(t, err, ErrCredential)
	_, err = ProvenanceExtension(Claims{State: presence.StatePresent, Provenance: presence.Provenance{GrantID: "g"}})
	mustErr(t, err, ErrCredential)
	_, err = ProvenanceExtension(Claims{State: "always"})
	mustErr(t, err, ErrCredential)
	// A tampered extension body is refused.
	ext, _ := ProvenanceExtension(Claims{State: presence.StateDelegated, Provenance: prov})
	ext.Value = ext.Value[:len(ext.Value)-1]
	_, err = AttestPeer([][]*x509.Certificate{{selfSigned(t, "spiffe://td/device/d/agent/x", ext)}})
	mustErr(t, err, ErrCredential)
}
