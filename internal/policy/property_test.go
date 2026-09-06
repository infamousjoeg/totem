package policy

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
)

// seeded returns the property-test generator for name: a fixed seed by
// default, so a failure names an input that can be replayed, overridable by
// TOTEM_PROPERTY_SEED for replaying a CI failure or hunting with many seeds.
// TOTEM_PROPERTY_ITERS scales the iteration count. The seed is logged on
// every run so a failure is never a rumour.
func seeded(t *testing.T, name string, defaultSeed uint64, defaultIters int) (*rand.Rand, int) {
	t.Helper()
	seed := defaultSeed
	if v := os.Getenv("TOTEM_PROPERTY_SEED"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("TOTEM_PROPERTY_SEED: %v", err)
		}
		seed = n
	}
	iters := defaultIters
	if v := os.Getenv("TOTEM_PROPERTY_ITERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("TOTEM_PROPERTY_ITERS: %v", err)
		}
		iters = n
	}
	t.Logf("%s: seed=%d iters=%d (replay: TOTEM_PROPERTY_SEED=%d TOTEM_PROPERTY_ITERS=%d)", name, seed, iters, seed, iters)
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), iters
}

// Property: verifyOffline gives the same answer as presence.Verifier.Verify
// for every assertion and expectation, on everything except challenge
// state, which the offline half deliberately does not have. The generator
// draws devices, tools, targets, bindings and keys from small universes so
// every mismatch class is hit, and signs with the real presence.Sign or the
// device-key path.
func TestOfflineAgreesWithVerifier(t *testing.T) {
	rng, iters := seeded(t, "offline-agrees", 0x6f66666c696e6521, 600)
	clk := newClock()
	ver := presence.NewVerifier(0, clk.Now)
	keys := []*fakeKey{newFakeKey(t, true), newFakeKey(t, true), newFakeKey(t, false)}
	devices := []string{"a", "b"}
	tools := []string{SigningTool, "claude"}
	targets := []string{"", "approve X", "grant-admin Y"}
	hashes := [][]byte{nil, reqHash("1"), reqHash("2")}
	pick := func(n int) int { return rng.IntN(n) }

	agreed, accepted := 0, 0
	for i := range iters {
		// An assertion the verifier refuses before the spend (malformed,
		// wrong version) leaves its challenge outstanding; on a real issuer
		// those expire on the TTL. Let the clock move so the generator
		// never trips MaxOutstandingChallenges instead of a finding.
		if i%32 == 31 {
			clk.Advance(presence.DefaultChallengeTTL + time.Second)
		}
		signer := keys[pick(len(keys))]
		dev, tool, target, h := devices[pick(2)], tools[pick(2)], targets[pick(3)], hashes[pick(3)]
		ch, err := ver.Mint(dev)
		if err != nil {
			t.Fatal(err)
		}
		in := presence.SigningInput{DeviceID: dev, Tool: tool, Target: target, Challenge: ch, RequestHash: h}
		var a *presence.Assertion
		usePresence := signer.presence != nil && pick(4) != 0
		if usePresence {
			a, err = presence.Sign(context.Background(), signer, in)
		} else {
			a, err = SignWithoutPresence(context.Background(), signer, in)
		}
		if err != nil {
			t.Fatal(err)
		}
		// Sometimes corrupt the signature or a field after signing.
		sigCorrupt := false
		switch pick(8) {
		case 0:
			a.Signature[len(a.Signature)/2] ^= 0x40
			sigCorrupt = true
		case 1:
			a.Target += " "
		case 2:
			a.Version = 2
		}
		// The expectation: which key, and which bindings. Half the time it
		// is exactly what was signed, so acceptances are common enough to
		// mean something; the rest of the time every field is independent.
		expKey := keys[pick(len(keys))]
		exp := presence.Expectation{
			DeviceID: devices[pick(2)], Tool: tools[pick(2)], Target: targets[pick(3)],
			Binding: presence.Binding(pick(2)), RequestHash: hashes[pick(3)],
		}
		if pick(2) == 0 {
			expKey = signer
			exp.DeviceID, exp.Tool, exp.Target, exp.RequestHash = dev, tool, target, h
			exp.Binding = presence.BindingNone
			if len(h) != 0 {
				exp.Binding = presence.BindingRequired
			}
		}
		// Verify against the presence half (nil for the none-level key)
		// through the real verifier, and against the same key offline.
		var ecKey = expKey.presence
		if ecKey != nil {
			exp.PresenceKey = &ecKey.PublicKey
		}
		_, verr := ver.Verify(a, exp)
		if errors.Is(verr, presence.ErrUnknownChallenge) {
			// Challenge state: the challenge was minted for a.DeviceID and
			// the expectation names another device. The verifier refuses on
			// the challenge; offline, with no challenge table, refuses on
			// the device binding. Same outcome, different sentinel, and
			// only when the device really differs.
			if a.DeviceID == exp.DeviceID {
				t.Fatalf("iter %d: unknown challenge for matching device", i)
			}
			oerr := verifyOffline(a, &expKey.device.PublicKey, exp)
			if oerr == nil || (!errors.Is(oerr, presence.ErrDeviceMismatch) && !errors.Is(oerr, presence.ErrUnsupportedVersion)) {
				t.Fatalf("iter %d: offline accepted a cross-device assertion: %v", i, oerr)
			}
			agreed++
			continue
		}
		if errors.Is(verr, presence.ErrNoPresenceKey) {
			// The verifier has no key to check; offline verifies against
			// the device key, which is what the none path does. That is a
			// different question, so compare against the device-key answer.
			oerr := verifyOffline(a, &expKey.device.PublicKey, exp)
			wantOK := !usePresence && !sigCorrupt && signer == expKey && fieldsMatch(a, exp) && a.Version == presence.EncodingVersion
			if (oerr == nil) != wantOK {
				t.Fatalf("iter %d: none path offline=%v want ok=%v", i, oerr, wantOK)
			}
			agreed++
			continue
		}
		// A none-level expectation that was refused before the key check
		// (malformed, version) is compared on the device key; every other
		// case on the presence key the verifier used.
		offlineKey := &expKey.device.PublicKey
		if exp.PresenceKey != nil {
			offlineKey = exp.PresenceKey.(*ecdsa.PublicKey)
		}
		oerr := verifyOffline(a, offlineKey, exp)
		if (verr == nil) != (oerr == nil) {
			t.Fatalf("iter %d: verifier=%v offline=%v", i, verr, oerr)
		}
		if verr != nil && !errors.Is(oerr, rootErr(verr)) {
			t.Fatalf("iter %d: verifier=%v offline=%v (different rejection)", i, verr, oerr)
		}
		if verr == nil {
			accepted++
			if !(usePresence && signer == expKey && fieldsMatch(a, exp)) {
				t.Fatalf("iter %d: accepted a mismatched assertion", i)
			}
		}
		agreed++
	}
	if accepted < 20 {
		t.Fatalf("under-exercised: %d acceptances", accepted)
	}
}

// fieldsMatch is the binding rule, restated independently of both
// implementations.
func fieldsMatch(a *presence.Assertion, exp presence.Expectation) bool {
	if a.DeviceID != exp.DeviceID || a.Tool != exp.Tool || a.Target != exp.Target {
		return false
	}
	switch exp.Binding {
	case presence.BindingNone:
		return len(a.RequestHash) == 0
	default:
		return len(exp.RequestHash) != 0 && len(a.RequestHash) != 0 && string(a.RequestHash) == string(exp.RequestHash)
	}
}

// rootErr strips the wrapping so errors.Is can compare sentinel to sentinel.
func rootErr(err error) error {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return err
		}
		err = u
	}
}

// Property: over a random sequence of admin operations from random signers,
// an operation succeeds if and only if the signer is live and admin (for
// admin actions) and the last-admin rule allows it; the number of live
// admins never reaches zero; every success is one chain record; and the
// issuer rebuilt from the chain agrees with the live one about every device
// after every step.
func TestSigningAuthorityProperty(t *testing.T) {
	rng, iterations := seeded(t, "signing-authority", 0x61646d696e727573, 12)
	for iter := range iterations {
		w := newWorld(t)
		ctx := ctxb()
		var ids []string
		ids = append(ids, w.found("founder", rng.IntN(3) != 0))
		for n := range 3 {
			ids = append(ids, w.enrolled(ids[0], fmt.Sprintf("d%d", n), rng.IntN(4) != 0))
		}
		policyRecords := func() int {
			n := 0
			for _, k := range w.st.kinds() {
				if strings.HasPrefix(k, "policy/") && k != "policy/bootstrap-issued" {
					n++
				}
			}
			return n
		}
		before := policyRecords()
		for step := range 40 {
			signer := ids[rng.IntN(len(ids))]
			subject := ids[rng.IntN(len(ids))]
			action := []Action{ActionGrantAdmin, ActionRevokeAdmin, ActionRevoke}[rng.IntN(3)]
			// Model of what must happen.
			s, _ := w.iss.Device(signer)
			tgt, _ := w.iss.Device(subject)
			admins := 0
			for _, d := range w.iss.Devices() {
				if d.Live() && d.Admin {
					admins++
				}
			}
			var want error
			switch {
			case !s.Live():
				want = ErrDeviceRevoked
			case !s.Admin:
				want = ErrNotAdmin
			case !tgt.Live():
				want = ErrDeviceRevoked
			case (action == ActionRevokeAdmin || action == ActionRevoke) && tgt.Admin && admins == 1:
				want = ErrLastAdmin
			}
			// Half the time skip Prepare's preflight to exercise the apply
			// path's own checks.
			var sig Signature
			var err error
			if rng.IntN(2) == 0 {
				sig, err = w.trySign(signer, action, subject)
				if err != nil {
					if want == nil || !errors.Is(err, want) {
						t.Fatalf("iter %d step %d: prepare %s %s by %s: got %v want %v", iter, step, action, fmtDev(w, subject), fmtDev(w, signer), err, want)
					}
					continue
				}
			} else {
				sig = w.forge(signer, action, subject)
			}
			switch action {
			case ActionGrantAdmin:
				err = w.iss.GrantAdmin(ctx, subject, sig)
			case ActionRevokeAdmin:
				err = w.iss.RevokeAdmin(ctx, subject, sig)
			case ActionRevoke:
				err = w.iss.RevokeDevice(ctx, subject, sig)
			}
			if want == nil && err != nil {
				t.Fatalf("iter %d step %d: %s %s by %s refused: %v", iter, step, action, fmtDev(w, subject), fmtDev(w, signer), err)
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("iter %d step %d: %s %s by %s: got %v want %v", iter, step, action, fmtDev(w, subject), fmtDev(w, signer), err, want)
			}
			// Invariants.
			live := 0
			for _, d := range w.iss.Devices() {
				if d.Live() && d.Admin {
					live++
				}
			}
			if live == 0 {
				t.Fatalf("iter %d step %d: no live admin left", iter, step)
			}
			now := policyRecords()
			if err == nil && now != before+1 {
				t.Fatalf("iter %d step %d: success produced %d records", iter, step, now-before)
			}
			if err != nil && now != before {
				t.Fatalf("iter %d step %d: refusal produced a record", iter, step)
			}
			before = now
		}
		// The chain rebuilds the same state.
		liveSnap := snap(w.iss)
		iss, err := w.reopen()
		if err != nil {
			t.Fatalf("iter %d: reload: %v", iter, err)
		}
		sameSnapshot(t, liveSnap, snap(iss))
	}
}

// Property: a proposal is always within the sanctioned scope, covers every
// covered observation, never includes an uncovered one, and renders the
// ceiling with the floors, over random observations and sanctioned scopes.
func TestProposeProperty(t *testing.T) {
	rng, iters := seeded(t, "propose", 0x70726f706f736521, 300)
	now := newClock().Now()
	profiles := []string{"dev", "staging", "prod", "prod-admin"}
	gh := []string{"a/b:contents:read", "a/b:contents:write", "c/d:pull_requests:write"}
	caps := []string{"homeassistant/sensor.freezer#read", "homeassistant/lock.front_door#unlock", "spotify/playlist#write"}
	sub := func(xs []string) []string {
		var out []string
		for _, x := range xs {
			if rng.IntN(2) == 0 {
				out = append(out, x)
			}
		}
		return out
	}
	for i := range iters {
		sanctioned := presence.Scope{
			AWSProfiles: sub(profiles), GitHubScopes: sub(gh), Capabilities: sub(caps),
			ClaudeProxy: rng.IntN(2) == 0, SpendCapUSD: float64(rng.IntN(100)),
			Money: presence.Money{PerTransactionUSD: float64(rng.IntN(50)), PerDayUSD: float64(rng.IntN(300)), StepUpAboveUSD: float64(rng.IntN(10))},
		}.Normalize()
		var obs []Observation
		for range rng.IntN(30) {
			o := Observation{At: now.Add(time.Duration(rng.IntN(72)) * time.Hour), Agent: "cassidy"}
			switch rng.IntN(4) {
			case 0:
				o.Tool, o.Target = "aws", profiles[rng.IntN(len(profiles))]
			case 1:
				o.Tool, o.Target = "gh", gh[rng.IntN(len(gh))]
			case 2:
				o.Tool = "claude"
				if rng.IntN(2) == 0 {
					o.AmountUSD = float64(rng.IntN(40)) / 4
				}
			default:
				c := caps[rng.IntN(len(caps))]
				o.Tool, o.Target, _ = strings.Cut(c, "/")
				o.Target = strings.TrimPrefix(c, o.Tool+"/")
				if rng.IntN(3) == 0 {
					o.AmountUSD = float64(rng.IntN(60)) / 3
				}
			}
			r := Request{Tool: o.Tool, Target: o.Target, AmountUSD: o.AmountUSD}
			o.Covered = scopeCovers(sanctioned, r) && (o.AmountUSD == 0 || sanctioned.Money.Decide(o.AmountUSD, 0) != presence.MoneyOverCeiling)
			obs = append(obs, o)
		}
		p := Propose("cassidy", sanctioned, obs, now)
		if !p.Proposed.Within(sanctioned) {
			t.Fatalf("iter %d: proposal not within sanctioned:\n%+v\n%+v", i, p.Proposed, sanctioned)
		}
		for _, o := range obs {
			r := Request{Tool: o.Tool, Target: o.Target, AmountUSD: o.AmountUSD}
			cov := scopeCovers(p.Proposed, r)
			if o.Covered && !cov {
				t.Fatalf("iter %d: covered observation %+v not covered by proposal %+v", i, o, p.Proposed)
			}
			if o.Covered && o.AmountUSD > 0 && o.Tool != "claude" && p.Proposed.Money.Decide(o.AmountUSD, 0) == presence.MoneyOverCeiling {
				t.Fatalf("iter %d: observed amount %.2f over proposed ceiling %+v", i, o.AmountUSD, p.Proposed.Money)
			}
			if !o.Covered && cov && !anyCovered(obs, o) {
				t.Fatalf("iter %d: uncovered observation %+v granted by proposal", i, o)
			}
		}
		if p.Proposed.Money.StepUpAboveUSD > presence.TrivialMoneyUSD {
			t.Fatalf("iter %d: step-up threshold above the floor", i)
		}
		out := p.Render()
		for _, must := range []string{"CAN\n", "CANNOT\n", "REDUCTION", "default deny", "kill switch", "raw:"} {
			if !strings.Contains(out, must) {
				t.Fatalf("iter %d: render lacks %q:\n%s", i, must, out)
			}
		}
		if strings.Index(out, "CANNOT") < strings.Index(out, "CAN\n") {
			t.Fatalf("iter %d: ceiling rendered before the grant", i)
		}
		if p.Uncovered > 0 && !strings.Contains(out, "NOT in this proposal") {
			t.Fatalf("iter %d: uncovered requests not called out", i)
		}
	}
}

// anyCovered reports whether some covered observation asks for the same
// capability, which legitimately makes an uncovered money request's
// capability appear in the proposal.
func anyCovered(obs []Observation, o Observation) bool {
	for _, x := range obs {
		if x.Covered && x.Tool == o.Tool && x.Target == o.Target {
			return true
		}
	}
	return false
}

func TestProposeExample(t *testing.T) {
	now := newClock().Now()
	sanctioned := wideScope()
	obs := []Observation{
		{At: now, Tool: "aws", Target: "dev", Covered: true},
		{At: now, Tool: "gh", Target: "infamousjoeg/totem:contents:read", Covered: true},
		{At: now, Tool: "homeassistant", Target: "sensor.freezer#read", Covered: true},
		{At: now, Tool: "homeassistant", Target: "sensor.freezer#read", AmountUSD: 3.5, Covered: true},
		{At: now, Tool: "claude", AmountUSD: 2, Covered: true},
		{At: now, Tool: "aws", Target: "prod", Covered: false},
	}
	p := Propose("cassidy", sanctioned, obs, now)
	if len(p.Proposed.AWSProfiles) != 1 || p.Proposed.AWSProfiles[0] != "dev" || p.Proposed.Money.PerTransactionUSD != 4 || p.Proposed.SpendCapUSD != 2 {
		t.Fatalf("proposed %+v", p.Proposed)
	}
	out := p.Render()
	for _, must := range []string{"aws: dev", "prod-admin", "lock.front_door#unlock", "$5.00", "1 request(s) fell outside", "contents:write"} {
		if !strings.Contains(out, must) {
			t.Fatalf("render lacks %q:\n%s", must, out)
		}
	}
	t.Log("\n" + out)
}

func TestShadowGrantRecordsAndParks(t *testing.T) {
	w := newWorld(t)
	ctx := ctxb()
	founder := w.found("founder", true)
	box := w.enrolled(founder, "studio", true)
	g := presence.NewGrant("cassidy", wideScope(), w.clk.Now())
	root, err := w.iss.Shadow(ctx, g, w.sign(founder, ActionGrant, GrantSubject(g)))
	mustErr(t, err, nil)
	cred := w.attest(agentID(box, "cassidy"), delegatedClaims(root))
	d, _ := w.iss.Evaluate(ctx, cred, Request{Tool: "aws", Target: "dev"})
	if d.Verdict != VerdictAllow || !d.Shadow {
		t.Fatalf("shadow allow %+v", d)
	}
	d, _ = w.iss.Evaluate(ctx, cred, Request{Tool: "aws", Target: "prod", Hash: reqHash("p")})
	if d.Verdict != VerdictPark || !d.Shadow {
		t.Fatalf("shadow park %+v", d)
	}
	// Narrowing inside a shadow still narrows.
	sess, _ := w.iss.OpenSession(ctx, cred, "")
	_, err = w.iss.Narrow(ctx, cred, sess.ID, presence.Scope{}, time.Time{})
	mustErr(t, err, nil)
	d, _ = w.iss.Evaluate(ctx, cred, Request{Tool: "aws", Target: "dev", Hash: reqHash("d"), SessionID: sess.ID})
	if d.Verdict != VerdictPark {
		t.Fatalf("narrowed shadow %+v", d)
	}
	obs := w.iss.Observations(root.ID)
	if len(obs) != 3 || !obs[0].Covered || obs[1].Covered || obs[2].Covered {
		t.Fatalf("observations %+v", obs)
	}
	p := Propose("cassidy", root.Scope, obs, w.clk.Now())
	if p.Uncovered != 2 || len(p.Proposed.AWSProfiles) != 1 {
		t.Fatalf("proposal %+v", p)
	}
}
