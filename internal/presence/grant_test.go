package presence

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"
)

func wideScope() Scope {
	return Scope{
		AWSProfiles:  []string{"dev", "staging"},
		GitHubScopes: []string{"infamousjoeg/totem:contents:write", "infamousjoeg/totem:pull_requests:write"},
		Capabilities: []string{"homeassistant/sensor.freezer#read", "homeassistant/lock.front_door#unlock"},
		ClaudeProxy:  true,
		SpendCapUSD:  50,
		Money:        Money{PerTransactionUSD: 20, PerDayUSD: 100, StepUpAboveUSD: 5},
	}
}

// sponsored returns a registry with one root grant for agent "cassidy" and
// the clock behind it.
func sponsored(t *testing.T) (*clock, *Registry, *Grant) {
	t.Helper()
	clk := newClock()
	reg := NewRegistry(clk.Now)
	g := NewGrant("cassidy", wideScope(), clk.Now())
	root, err := reg.Sponsor(g, verified("mac-studio", clk.Now(), g.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	return clk, reg, root
}

func TestSponsor(t *testing.T) {
	clk := newClock()
	g := NewGrant("cassidy", wideScope(), clk.Now())
	if !g.Until.Equal(clk.At(DefaultGrantDuration)) {
		t.Fatal("NewGrant did not apply the thirty-day default")
	}
	cases := []struct {
		name string
		g    func() Grant
		v    *Verified
		want error
	}{
		{"valid", func() Grant { return g }, verified("mac-studio", clk.Now(), g.Hash()), nil},
		{"hand-built verified", func() Grant { return g }, &Verified{DeviceID: "mac-studio", RequestHash: g.Hash()}, ErrPresenceRequired},
		{"nil verified", func() Grant { return g }, nil, ErrPresenceRequired},
		{"assertion bound to another grant", func() Grant { return g }, verified("mac-studio", clk.Now(), NewGrant("ember", wideScope(), clk.Now()).Hash()), ErrGrantHashMismatch},
		{"unbound window touch", func() Grant { return g }, verified("mac-studio", clk.Now(), nil), ErrGrantHashMismatch},
		{"scope changed after signing", func() Grant {
			h := g
			h.Scope.AWSProfiles = append(slices.Clone(h.Scope.AWSProfiles), "prod")
			return h
		}, verified("mac-studio", clk.Now(), g.Hash()), ErrGrantHashMismatch},
		{"expiry changed after signing", func() Grant {
			h := g
			h.Until = h.Until.Add(time.Hour)
			return h
		}, verified("mac-studio", clk.Now(), g.Hash()), ErrGrantHashMismatch},
		{"no agent", func() Grant {
			h := g
			h.Agent = ""
			return h
		}, verified("mac-studio", clk.Now(), func() []byte { h := g; h.Agent = ""; return h.Hash() }()), ErrGrantInvalid},
		{"already expired", func() Grant {
			h := g
			h.Until = clk.Now()
			return h
		}, verified("mac-studio", clk.Now(), func() []byte { h := g; h.Until = clk.Now(); return h.Hash() }()), ErrGrantInvalid},
		{"caller-supplied lineage", func() Grant {
			h := g
			h.Lineage = []string{"forged-root"}
			return h
		}, verified("mac-studio", clk.Now(), g.Hash()), ErrGrantInvalid},
		{"caller-supplied id", func() Grant {
			h := g
			h.ID = "chosen"
			return h
		}, verified("mac-studio", clk.Now(), g.Hash()), ErrGrantInvalid},
		{"longer than MaxGrantDuration", func() Grant {
			h := g
			h.Until = clk.At(MaxGrantDuration + time.Second)
			return h
		}, verified("mac-studio", clk.Now(), func() []byte { h := g; h.Until = clk.At(MaxGrantDuration + time.Second); return h.Hash() }()), ErrGrantInvalid},
		{"exactly MaxGrantDuration", func() Grant {
			h := g
			h.Until = clk.At(MaxGrantDuration)
			return h
		}, verified("mac-studio", clk.Now(), func() []byte { h := g; h.Until = clk.At(MaxGrantDuration); return h.Hash() }()), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry(clk.Now)
			root, err := reg.Sponsor(tc.g(), tc.v)
			mustErr(t, err, tc.want)
			if tc.want != nil {
				return
			}
			if root.ID == "" || root.Sponsor != "mac-studio" || !root.SignedAt.Equal(clk.Now()) || len(root.Lineage) != 0 {
				t.Fatalf("root fields: %+v", root)
			}
			p := root.Provenance()
			if p.State != StateDelegated || p.GrantID != root.ID || p.RootID != root.ID || p.Sponsor != "mac-studio" {
				t.Fatalf("provenance: %+v", p)
			}
			if _, err := reg.Get(root.ID); err != nil {
				t.Fatal(err)
			}
			if !tc.v.Used() {
				t.Fatal("sponsoring proof not consumed")
			}
			// The same proof cannot sponsor a second grant.
			_, err = reg.Sponsor(tc.g(), tc.v)
			mustErr(t, err, ErrPresenceConsumed)
		})
	}
}

func TestGrantExpiryAndRenewal(t *testing.T) {
	clk, reg, root := sponsored(t)
	if root.RenewalDue(clk.Now()) {
		t.Fatal("renewal due on day one")
	}
	clk.Advance(DefaultGrantDuration - RenewalNotice)
	if !root.RenewalDue(clk.Now()) {
		t.Fatal("renewal not due three days before expiry")
	}
	if _, err := reg.Get(root.ID); err != nil {
		t.Fatal("grant inactive before expiry")
	}
	clk.Advance(RenewalNotice)
	_, err := reg.Get(root.ID)
	mustErr(t, err, ErrGrantExpired)
	_, err = reg.Get("nope")
	mustErr(t, err, ErrGrantNotFound)
}

func TestNarrowInheritsLineageExpirySignedAt(t *testing.T) {
	clk, reg, root := sponsored(t)
	s, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Hour)
	narrow := Scope{AWSProfiles: []string{"dev"}, Money: Money{PerTransactionUSD: 1, PerDayUSD: 1, StepUpAboveUSD: 0}}
	child, err := reg.Narrow(s.ID, narrow, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(child.Lineage, []string{root.ID}) {
		t.Fatalf("lineage %v", child.Lineage)
	}
	if !child.Until.Equal(root.Until) || !child.SignedAt.Equal(root.SignedAt) || child.Sponsor != root.Sponsor || child.Agent != root.Agent {
		t.Fatalf("child did not inherit: %+v", child)
	}
	if !child.DerivedAt.Equal(clk.Now()) {
		t.Fatal("DerivedAt is not the narrowing time")
	}
	if child.RootID() != root.ID || child.ParentID() != root.ID {
		t.Fatal("root/parent ids wrong")
	}
	active, err := reg.Active(s.ID)
	if err != nil || active.ID != child.ID {
		t.Fatalf("session did not move to the child: %v %+v", err, active)
	}
	// Second narrowing chains lineage.
	clk.Advance(time.Minute)
	grand, err := reg.Narrow(s.ID, Scope{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grand.Lineage, []string{root.ID, child.ID}) {
		t.Fatalf("grandchild lineage %v", grand.Lineage)
	}
	p := grand.Provenance()
	if p.RootID != root.ID || !p.SignedAt.Equal(root.SignedAt) || p.State != StateDelegated {
		t.Fatalf("grandchild provenance lost the root: %+v", p)
	}
	// Shorter expiry allowed; later refused.
	if _, err := reg.Narrow(s.ID, Scope{}, root.Until.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err = reg.Narrow(s.ID, Scope{}, root.Until.Add(time.Nanosecond))
	mustErr(t, err, ErrExpiryWidens)
}

func TestNarrowRefusesAddedCapability(t *testing.T) {
	_, reg, root := sponsored(t)
	s, _ := reg.Open(root.ID, root.ID)
	base := wideScope()
	cases := []struct {
		name string
		mut  func(*Scope)
	}{
		{"new aws profile", func(s *Scope) { s.AWSProfiles = append(s.AWSProfiles, "prod") }},
		{"new github scope", func(s *Scope) { s.GitHubScopes = append(s.GitHubScopes, "infamousjoeg/totem:admin") }},
		{"new capability", func(s *Scope) { s.Capabilities = append(s.Capabilities, "homeassistant/alarm#disarm") }},
		{"higher spend cap", func(s *Scope) { s.SpendCapUSD = 51 }},
		{"higher per-transaction", func(s *Scope) { s.Money.PerTransactionUSD = 21 }},
		{"higher per-day", func(s *Scope) { s.Money.PerDayUSD = 101 }},
		{"higher step-up threshold", func(s *Scope) { s.Money.StepUpAboveUSD = 6 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := base
			sc.AWSProfiles = slices.Clone(sc.AWSProfiles)
			sc.GitHubScopes = slices.Clone(sc.GitHubScopes)
			sc.Capabilities = slices.Clone(sc.Capabilities)
			tc.mut(&sc)
			_, err := reg.Narrow(s.ID, sc, time.Time{})
			mustErr(t, err, ErrNotNarrower)
		})
	}
	// Claude proxy on when parent has it off.
	off := base
	off.ClaudeProxy = false
	child, err := reg.Narrow(s.ID, off, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if child.Scope.SpendCapUSD != 0 {
		t.Fatal("spend cap not zeroed with proxy off")
	}
	_, err = reg.Narrow(s.ID, base, time.Time{})
	mustErr(t, err, ErrNotNarrower)
	// Identical scope is allowed (not wider), so a wrapper can pin a
	// sub-identity without changing anything but the id.
	if _, err := reg.Narrow(s.ID, off, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeReachesEveryDescendant(t *testing.T) {
	_, reg, root := sponsored(t)
	s, _ := reg.Open(root.ID, root.ID)
	child, _ := reg.Narrow(s.ID, Scope{AWSProfiles: []string{"dev"}}, time.Time{})
	grand, _ := reg.Narrow(s.ID, Scope{}, time.Time{})
	s2, _ := reg.Open(root.ID, root.ID)
	sibling, _ := reg.Narrow(s2.ID, Scope{GitHubScopes: []string{"infamousjoeg/totem:contents:write"}}, time.Time{})

	reg.Revoke(child.ID)
	for _, id := range []string{child.ID, grand.ID} {
		_, err := reg.Get(id)
		mustErr(t, err, ErrGrantRevoked)
	}
	for _, id := range []string{root.ID, sibling.ID} {
		if _, err := reg.Get(id); err != nil {
			t.Fatalf("revocation of a child hit %s: %v", id, err)
		}
	}
	_, err := reg.Active(s.ID)
	mustErr(t, err, ErrGrantRevoked)
	_, err = reg.Narrow(s.ID, Scope{}, time.Time{})
	mustErr(t, err, ErrGrantRevoked)

	reg.Revoke(root.ID)
	for _, id := range []string{root.ID, sibling.ID} {
		_, err := reg.Get(id)
		mustErr(t, err, ErrGrantRevoked)
	}
	_, err = reg.Open(root.ID, root.ID)
	mustErr(t, err, ErrGrantRevoked)
}

// The structural claim: the narrowest possible grant (empty scope) is still
// attributed to its root, still carries the sponsor's signing time, and is
// still revoked with its root. There is no field on Scope that could have
// opted out.
func TestNarrowingCannotRemoveObservabilityOrRevocability(t *testing.T) {
	_, reg, root := sponsored(t)
	s, _ := reg.Open(root.ID, root.ID)
	floor, err := reg.Narrow(s.ID, Scope{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	p := floor.Provenance()
	if p.RootID != root.ID || p.Sponsor != root.Sponsor || !p.SignedAt.Equal(root.SignedAt) || len(p.Lineage) != 1 {
		t.Fatalf("floor grant lost provenance: %+v", p)
	}
	reg.Revoke(root.ID)
	_, err = reg.Get(floor.ID)
	mustErr(t, err, ErrGrantRevoked)

	// Scope's fields are all capabilities. Enumerate them so adding an
	// observability toggle here would have to be a deliberate act that
	// breaks this test.
	want := []string{"AWSProfiles", "GitHubScopes", "Capabilities", "ClaudeProxy", "SpendCapUSD", "Money"}
	rt := reflect.TypeFor[Scope]()
	var got []string
	for i := range rt.NumField() {
		got = append(got, rt.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Scope fields changed: %v; every field must be a removable capability", got)
	}
}

func TestWidenRequiresFreshBoundPresence(t *testing.T) {
	clk, reg, root := sponsored(t)
	s, _ := reg.Open(root.ID, root.ID)
	child, _ := reg.Narrow(s.ID, Scope{AWSProfiles: []string{"dev"}}, time.Time{})
	grand, _ := reg.Narrow(s.ID, Scope{}, time.Time{})
	narrowedAt := clk.Now()

	// Unconditional: even with zero elapsed time, re-widening without
	// presence is refused. There is no clock condition that makes it safe.
	_, err := reg.Widen(s.ID, child.ID, nil)
	mustErr(t, err, ErrRewidenRequiresPresence)
	// And with presence at the same instant it is allowed (VerifiedAt is
	// not before NarrowedAt), then re-narrowed for the table below.
	if _, err := reg.Widen(s.ID, child.ID, verified("mac-studio", clk.Now(), WidenHash(s.ID, child.ID))); err != nil {
		t.Fatalf("same-instant widen with bound presence refused: %v", err)
	}
	if _, err := reg.Narrow(s.ID, Scope{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Millisecond)

	cases := []struct {
		name string
		to   string
		v    *Verified
		want error
	}{
		{"no presence", child.ID, nil, ErrRewidenRequiresPresence},
		{"hand-built", child.ID, &Verified{DeviceID: "mac-studio", RequestHash: WidenHash(s.ID, child.ID), VerifiedAt: clk.Now()}, ErrRewidenRequiresPresence},
		{"window touch, not bound", child.ID, verified("mac-studio", clk.Now(), nil), ErrRewidenRequiresPresence},
		{"bound to a different widen", child.ID, verified("mac-studio", clk.Now(), WidenHash(s.ID, root.ID)), ErrRewidenRequiresPresence},
		{"bound to another session's widen", child.ID, verified("mac-studio", clk.Now(), WidenHash("other", child.ID)), ErrRewidenRequiresPresence},
		{"assertion predates the narrowing", child.ID, verified("mac-studio", narrowedAt.Add(-time.Second), WidenHash(s.ID, child.ID)), ErrRewidenRequiresPresence},
		{"not an ancestor", grand.ID, verified("mac-studio", clk.Now(), WidenHash(s.ID, grand.ID)), ErrNotAncestor},
		{"unknown grant", "nope", verified("mac-studio", clk.Now(), WidenHash(s.ID, "nope")), ErrNotAncestor},
		{"fresh bound presence", child.ID, verified("mac-studio", clk.Now(), WidenHash(s.ID, child.ID)), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := reg.Session(s.ID)
			g, err := reg.Widen(s.ID, tc.to, tc.v)
			mustErr(t, err, tc.want)
			after, _ := reg.Session(s.ID)
			if tc.want != nil {
				if after.ActiveGrantID != before.ActiveGrantID {
					t.Fatal("refused widen moved the session")
				}
				return
			}
			if g.ID != tc.to || after.ActiveGrantID != tc.to {
				t.Fatalf("widen landed on %s, want %s", after.ActiveGrantID, tc.to)
			}
		})
	}
	// All the way back to the root, with presence, also works; and a widen
	// to a revoked ancestor does not.
	if _, err := reg.Widen(s.ID, root.ID, verified("mac-studio", clk.Now(), WidenHash(s.ID, root.ID))); err != nil {
		t.Fatal(err)
	}
	c2, _ := reg.Narrow(s.ID, Scope{}, time.Time{})
	_ = c2
	reg.Revoke(child.ID)
	if _, err := reg.Narrow(s.ID, Scope{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	_, err = reg.Session("missing")
	mustErr(t, err, ErrSessionNotFound)
	_, err = reg.Widen("missing", root.ID, nil)
	mustErr(t, err, ErrSessionNotFound)
}

// Property test for monotonic narrowing over generated scope sets: for random
// parent P and random subset C of P, C is Within P; for C plus any element
// not in P, or any ceiling raised, Within is false; Within is reflexive and
// transitive along a random chain; and Registry.Narrow agrees with Within on
// every generated case.
func TestNarrowingMonotonicProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x70746d, 0x6e617272))
	universe := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%s-%d", prefix, i)
		}
		return out
	}
	aws, gh, caps := universe("profile", 8), universe("repo", 8), universe("cap", 8)
	pick := func(from []string) []string {
		var out []string
		for _, s := range from {
			if rng.IntN(2) == 0 {
				out = append(out, s)
			}
		}
		rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		return out
	}
	subsetOf := func(of []string) []string { return pick(of) }
	money := func() Money {
		return Money{PerTransactionUSD: rng.Float64() * 100, PerDayUSD: rng.Float64() * 1000, StepUpAboveUSD: rng.Float64() * 10}
	}
	moneyWithin := func(m Money) Money {
		return Money{PerTransactionUSD: m.PerTransactionUSD * rng.Float64(), PerDayUSD: m.PerDayUSD * rng.Float64(), StepUpAboveUSD: m.StepUpAboveUSD * rng.Float64()}
	}
	genParent := func() Scope {
		p := Scope{AWSProfiles: pick(aws), GitHubScopes: pick(gh), Capabilities: pick(caps), ClaudeProxy: rng.IntN(2) == 0, Money: money()}
		if p.ClaudeProxy {
			p.SpendCapUSD = rng.Float64() * 100
		}
		return p
	}
	genChild := func(p Scope) Scope {
		c := Scope{AWSProfiles: subsetOf(p.AWSProfiles), GitHubScopes: subsetOf(p.GitHubScopes), Capabilities: subsetOf(p.Capabilities), Money: moneyWithin(p.Money)}
		if p.ClaudeProxy && rng.IntN(2) == 0 {
			c.ClaudeProxy = true
			c.SpendCapUSD = p.SpendCapUSD * rng.Float64()
		}
		return c
	}
	missing := func(have, from []string) []string {
		var out []string
		for _, s := range from {
			if !slices.Contains(have, s) {
				out = append(out, s)
			}
		}
		return out
	}
	// widenings enumerates every single-axis way to make c wider than p.
	widenings := func(p, c Scope) []Scope {
		var out []Scope
		add := func(mut func(*Scope)) {
			w := c
			w.AWSProfiles = slices.Clone(c.AWSProfiles)
			w.GitHubScopes = slices.Clone(c.GitHubScopes)
			w.Capabilities = slices.Clone(c.Capabilities)
			mut(&w)
			out = append(out, w)
		}
		if m := missing(p.AWSProfiles, aws); len(m) > 0 {
			add(func(s *Scope) { s.AWSProfiles = append(s.AWSProfiles, m[rng.IntN(len(m))]) })
		}
		if m := missing(p.GitHubScopes, gh); len(m) > 0 {
			add(func(s *Scope) { s.GitHubScopes = append(s.GitHubScopes, m[rng.IntN(len(m))]) })
		}
		if m := missing(p.Capabilities, caps); len(m) > 0 {
			add(func(s *Scope) { s.Capabilities = append(s.Capabilities, m[rng.IntN(len(m))]) })
		}
		if !p.ClaudeProxy {
			add(func(s *Scope) { s.ClaudeProxy = true })
		} else {
			add(func(s *Scope) { s.ClaudeProxy = true; s.SpendCapUSD = p.SpendCapUSD + 0.01 })
		}
		add(func(s *Scope) { s.Money.PerTransactionUSD = p.Money.PerTransactionUSD + 0.01 })
		add(func(s *Scope) { s.Money.PerDayUSD = p.Money.PerDayUSD + 0.01 })
		add(func(s *Scope) { s.Money.StepUpAboveUSD = p.Money.StepUpAboveUSD + 0.01 })
		return out
	}

	const iterations = 500
	checked, widened := 0, 0
	for i := range iterations {
		clk := newClock()
		reg := NewRegistry(clk.Now)
		parent := genParent()
		g := NewGrant("agent", parent, clk.Now())
		root, err := reg.Sponsor(g, verified("dev", clk.Now(), g.Hash()))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := reg.Open(root.ID, root.ID)

		// Reflexive.
		if !parent.Within(parent) {
			t.Fatalf("iter %d: Within not reflexive: %+v", i, parent)
		}
		// Random chain of narrowings, each Within its parent and, by
		// transitivity, Within the root.
		cur := parent
		depth := 1 + rng.IntN(4)
		for range depth {
			child := genChild(cur)
			if !child.Within(cur) {
				t.Fatalf("iter %d: subset child not Within parent\nchild %+v\nparent %+v", i, child, cur)
			}
			if !child.Within(parent) {
				t.Fatalf("iter %d: Within not transitive", i)
			}
			if _, err := reg.Narrow(s.ID, child, time.Time{}); err != nil {
				t.Fatalf("iter %d: registry refused a narrower scope: %v", i, err)
			}
			checked++
			// Every single-axis widening of the child past the current
			// parent is refused by both the predicate and the registry.
			for _, w := range widenings(cur, child) {
				if w.Within(cur) {
					t.Fatalf("iter %d: widened scope passed Within\nwide %+v\nparent %+v", i, w, cur)
				}
				if _, err := reg.Narrow(s.ID, w, time.Time{}); !errors.Is(err, ErrNotNarrower) {
					t.Fatalf("iter %d: registry accepted a wider scope: %v", i, err)
				}
				widened++
			}
			cur = child
		}
		// The active grant's scope is Within the root's after the chain.
		active, err := reg.Active(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !active.Scope.Within(root.Scope) {
			t.Fatalf("iter %d: active grant escaped the root ceiling", i)
		}
		if active.RootID() != root.ID || len(active.Lineage) != depth {
			t.Fatalf("iter %d: lineage depth %d, want %d", i, len(active.Lineage), depth)
		}
	}
	if checked < iterations || widened < iterations*3 {
		t.Fatalf("property test under-exercised: %d narrowings, %d widenings", checked, widened)
	}
}

// A session may be opened only on the presented grant or a descendant. A
// caller wrapped in a sub-grant cannot open a fresh session on its root and
// walk around monotonic narrowing. (Reviewer M2, inverted.)
func TestOpenRequiresHolder(t *testing.T) {
	_, reg, root := sponsored(t)
	s, err := reg.Open(root.ID, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	child, _ := reg.Narrow(s.ID, Scope{AWSProfiles: []string{"dev"}}, time.Time{})
	floor, _ := reg.Narrow(s.ID, Scope{}, time.Time{})
	s2, _ := reg.Open(root.ID, root.ID)
	sibling, _ := reg.Narrow(s2.ID, Scope{}, time.Time{})

	cases := []struct {
		name      string
		presented string
		target    string
		want      error
	}{
		{"floor credential opens root", floor.ID, root.ID, ErrNotHolder},
		{"floor credential opens parent", floor.ID, child.ID, ErrNotHolder},
		{"floor credential opens sibling branch", floor.ID, sibling.ID, ErrNotHolder},
		{"child credential opens root", child.ID, root.ID, ErrNotHolder},
		{"floor credential opens itself", floor.ID, floor.ID, nil},
		{"child credential opens its descendant", child.ID, floor.ID, nil},
		{"root credential opens a descendant", root.ID, floor.ID, nil},
		{"root credential opens itself", root.ID, root.ID, nil},
		{"unknown presented", "nope", root.ID, ErrGrantNotFound},
		{"unknown target", root.ID, "nope", ErrGrantNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := reg.Open(tc.presented, tc.target)
			mustErr(t, err, tc.want)
			if tc.want == nil && sess.ActiveGrantID != tc.target {
				t.Fatalf("opened on %s, want %s", sess.ActiveGrantID, tc.target)
			}
		})
	}
	// A revoked presented grant opens nothing, even on itself.
	reg.Revoke(child.ID)
	_, err = reg.Open(floor.ID, floor.ID)
	mustErr(t, err, ErrGrantRevoked)
}

// The widening proof is consumed. (Reviewer M1.)
func TestWidenConsumesProof(t *testing.T) {
	clk, reg, root := sponsored(t)
	s, _ := reg.Open(root.ID, root.ID)
	reg.Narrow(s.ID, Scope{}, time.Time{})
	v := verified("mac-studio", clk.Now(), WidenHash(s.ID, root.ID))
	if _, err := reg.Widen(s.ID, root.ID, v); err != nil {
		t.Fatal(err)
	}
	if !v.Used() {
		t.Fatal("widen did not consume its proof")
	}
	reg.Narrow(s.ID, Scope{}, time.Time{})
	_, err := reg.Widen(s.ID, root.ID, v)
	mustErr(t, err, ErrPresenceConsumed)
	// A refused widen leaves the proof unused.
	fresh := verified("mac-studio", clk.Now(), WidenHash(s.ID, "nope"))
	_, err = reg.Widen(s.ID, "nope", fresh)
	mustErr(t, err, ErrNotAncestor)
	if fresh.Used() {
		t.Fatal("refused widen consumed the proof")
	}
}

func TestScopeNormalize(t *testing.T) {
	s := Scope{
		AWSProfiles:  []string{"b", "a", "b"},
		GitHubScopes: []string{"z", "z"},
		ClaudeProxy:  false,
		SpendCapUSD:  99,
		Money:        Money{PerTransactionUSD: -1, PerDayUSD: math.NaN(), StepUpAboveUSD: 3},
	}
	n := s.Normalize()
	if !reflect.DeepEqual(n.AWSProfiles, []string{"a", "b"}) || !reflect.DeepEqual(n.GitHubScopes, []string{"z"}) || n.Capabilities != nil {
		t.Fatalf("sets: %+v", n)
	}
	if n.SpendCapUSD != 0 {
		t.Fatal("spend cap must be zero when proxy is off")
	}
	if n.Money != (Money{StepUpAboveUSD: 3}) {
		t.Fatalf("money: %+v", n.Money)
	}
	// -0.0 hashes as 0 (L6).
	negZero := NewGrant("x", Scope{Money: Money{PerTransactionUSD: math.Copysign(0, -1)}}, newClock().Now())
	posZero := NewGrant("x", Scope{Money: Money{PerTransactionUSD: 0}}, newClock().Now())
	if string(negZero.Hash()) != string(posZero.Hash()) {
		t.Fatal("-0 and 0 hash differently")
	}
	if !reflect.DeepEqual(s.Normalize(), n) {
		t.Fatal("Normalize is not idempotent")
	}
	// Equal scopes hash equal regardless of order; different scopes do not.
	a := NewGrant("x", Scope{AWSProfiles: []string{"a", "b"}}, newClock().Now())
	b := NewGrant("x", Scope{AWSProfiles: []string{"b", "a", "a"}}, newClock().Now())
	c := NewGrant("x", Scope{AWSProfiles: []string{"ab"}}, newClock().Now())
	if string(a.Hash()) != string(b.Hash()) {
		t.Fatal("equal scopes hashed differently")
	}
	if string(a.Hash()) == string(c.Hash()) {
		t.Fatal("grant hash is not boundary-safe")
	}
}

func TestMoneyDecide(t *testing.T) {
	m := Money{PerTransactionUSD: 50, PerDayUSD: 100, StepUpAboveUSD: 10}
	cases := []struct {
		name       string
		m          Money
		amount     float64
		spentToday float64
		want       MoneyVerdict
	}{
		{"zero is not money", m, 0, 0, MoneyDelegated},
		{"trivial and inside", m, 4.99, 0, MoneyDelegated},
		{"at the trivial floor", m, 5, 0, MoneyDelegated},
		{"above trivial floor even though grant step-up is 10", m, 5.01, 0, MoneyStepUp},
		{"grant step-up lower than floor", Money{PerTransactionUSD: 50, PerDayUSD: 100, StepUpAboveUSD: 1}, 1.01, 0, MoneyStepUp},
		{"above per-transaction", m, 50.01, 0, MoneyOverCeiling},
		{"at per-transaction", m, 50, 0, MoneyStepUp},
		{"per-day exhausted by trivial amount", m, 1, 99.5, MoneyOverCeiling},
		{"per-day exactly reached", m, 1, 99, MoneyDelegated},
		{"negative amount", m, -1, 0, MoneyOverCeiling},
		{"nan", m, math.NaN(), 0, MoneyOverCeiling},
		{"inf", m, math.Inf(1), 0, MoneyOverCeiling},
		{"zero money permits nothing", Money{}, 0.01, 0, MoneyOverCeiling},
		{"zero money refuses a $0 hold", Money{}, 0, 0, MoneyOverCeiling},
		{"NaN step-up cannot lift the floor (M3)", Money{PerTransactionUSD: 1e6, PerDayUSD: 1e6, StepUpAboveUSD: math.NaN()}, 50000, 0, MoneyStepUp},
		{"NaN step-up reads as zero: even $1 steps up", Money{PerTransactionUSD: 1e6, PerDayUSD: 1e6, StepUpAboveUSD: math.NaN()}, 1, 0, MoneyStepUp},
		{"NaN per-transaction permits nothing", Money{PerTransactionUSD: math.NaN(), PerDayUSD: 100, StepUpAboveUSD: 5}, 1, 0, MoneyOverCeiling},
		{"NaN per-day permits nothing", Money{PerTransactionUSD: 50, PerDayUSD: math.NaN(), StepUpAboveUSD: 5}, 1, 0, MoneyOverCeiling},
		{"NaN spent today", m, 1, math.NaN(), MoneyOverCeiling},
		{"negative spent today", m, 1, -1e12, MoneyOverCeiling},
		{"inf spent today", m, 1, math.Inf(1), MoneyOverCeiling},
		{"inf ceilings still floor at trivial", Money{PerTransactionUSD: math.Inf(1), PerDayUSD: math.Inf(1), StepUpAboveUSD: math.Inf(1)}, 6, 0, MoneyStepUp},
		{"inf ceilings, trivial amount delegated", Money{PerTransactionUSD: math.Inf(1), PerDayUSD: math.Inf(1), StepUpAboveUSD: math.Inf(1)}, 4, 0, MoneyDelegated},
		{"huge step-up cannot beat the floor", Money{PerTransactionUSD: 1e6, PerDayUSD: 1e6, StepUpAboveUSD: 1e6}, TrivialMoneyUSD + 0.01, 0, MoneyStepUp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.m.Decide(tc.amount, tc.spentToday); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOpenRequiresActiveGrant(t *testing.T) {
	clk, reg, root := sponsored(t)
	clk.Advance(DefaultGrantDuration)
	_, err := reg.Open(root.ID, root.ID)
	mustErr(t, err, ErrGrantExpired)
	_, err = reg.Open("nope", "nope")
	mustErr(t, err, ErrGrantNotFound)
}
