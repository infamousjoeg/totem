package policy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/infamousjoeg/totem/internal/presence"
)

// Relying parties whose scope lives in a dedicated Scope field. Anything else
// is an entity/action capability "<party>/<target>".
const (
	partyAWS    = "aws"
	partyGitHub = "gh"
	partyGit    = "git"
	partyClaude = "claude"
)

// evaluate decides one request. It reads identity, presence state and grant
// from the Attested credential and the request body for nothing but what is
// being asked.
func (i *Issuer) evaluate(ctx context.Context, a *Attested, req Request) (Decision, error) {
	if a == nil {
		return Decision{}, ErrCredential
	}
	if err := i.requireLiveDevice(a.id.DeviceID); err != nil {
		return deny("device is not a live enrollment: " + err.Error()), nil
	}
	if a.id.Agent != "" {
		return i.evaluateAgent(ctx, a, req)
	}
	return i.evaluateTool(ctx, a, req, nil)
}

func deny(reason string) Decision {
	return Decision{Verdict: VerdictDeny, Reason: reason}
}

// evaluateTool is the interactive-tool path: presence policy plus held
// sessions. assertion, when non-nil, is a fresh touch from the requesting
// device (Present).
func (i *Issuer) evaluateTool(ctx context.Context, a *Attested, req Request, assertion *presence.Assertion) (Decision, error) {
	if req.Tool == "" || req.Tool != a.id.Tool {
		return deny(fmt.Sprintf("credential is for tool %q, request is for %q", a.id.Tool, req.Tool)), nil
	}
	w, ok := i.window(req.Tool, req.Target)
	if !ok {
		return deny(fmt.Sprintf("%s: no presence policy for %s %q", Default, req.Tool, req.Target)), nil
	}
	if a.state == presence.StateDelegated {
		return deny("a delegated credential cannot act as an interactive tool"), nil
	}
	// Money above trivial escalates a windowed target to a per-request
	// touch. Written as "not provably trivial" so a NaN, infinite or
	// negative amount escalates too, the same sense as Money.Decide on the
	// agent path, rather than sliding under the floor by failing a compare.
	escalate := !(req.AmountUSD >= 0 && req.AmountUSD <= presence.TrivialMoneyUSD)
	d := i.cfg.Sessions.Evaluate(a.id.DeviceID, w, escalate)

	// A device with no presence capability: windowed targets work and the
	// credential says none; always is closed to it; step-up parks like
	// anyone else's.
	if a.state == presence.StateNone && !d.Park {
		if w.Level == presence.LevelAlways || escalate {
			return deny("presence:always target is closed to a device with no presence capability"), nil
		}
		return Decision{Verdict: VerdictAllow, Presence: presence.StateNone}, nil
	}

	if d.Park {
		return i.park(ctx, idString(a.id), "", presence.Irreversible, req)
	}
	if d.Satisfied && assertion == nil {
		return Decision{Verdict: VerdictAllow, Presence: presence.StatePresent, PresenceAge: d.Age}, nil
	}
	if assertion == nil {
		return Decision{Verdict: VerdictPrompt, Presence: presence.StatePresent, Binding: d.Binding}, nil
	}

	// A touch was presented: verify it against the ENROLLED presence key
	// with the binding the target's level requires.
	e, err := i.device(a.id.DeviceID)
	if err != nil {
		return Decision{}, err
	}
	presenceKey, _, err := signerKeys(e)
	if err != nil {
		return Decision{}, err
	}
	exp := presence.Expectation{
		DeviceID: a.id.DeviceID, Tool: req.Tool, Target: req.Target, Binding: d.Binding,
	}
	if presenceKey != nil {
		exp.PresenceKey = presenceKey
	}
	if d.Binding == presence.BindingRequired {
		exp.RequestHash = req.Hash
	}
	v, err := i.cfg.Verifier.Verify(assertion, exp)
	if err != nil {
		return Decision{}, err
	}
	if d.Binding == presence.BindingNone {
		if _, err := i.cfg.Sessions.Touch(a.id.DeviceID, w, v); err != nil {
			return Decision{}, err
		}
	}
	return Decision{Verdict: VerdictAllow, Presence: presence.StatePresent, Binding: d.Binding}, nil
}

func (i *Issuer) present(ctx context.Context, a *Attested, req Request, assertion *presence.Assertion) (Decision, error) {
	if a == nil {
		return Decision{}, ErrCredential
	}
	if assertion == nil {
		return Decision{}, presence.ErrPresenceRequired
	}
	if a.id.Agent != "" {
		return Decision{}, fmt.Errorf("%w: an agent identity has no presence to present", ErrNotDelegated)
	}
	if err := i.requireLiveDevice(a.id.DeviceID); err != nil {
		return deny("device is not a live enrollment: " + err.Error()), nil
	}
	return i.evaluateTool(ctx, a, req, assertion)
}

// evaluateAgent is the delegated path: the grant from the credential, or the
// session's active sub-grant; scope, entity tiers and money ceilings;
// anything outside parks.
func (i *Issuer) evaluateAgent(ctx context.Context, a *Attested, req Request) (Decision, error) {
	presented, err := delegated(a)
	if err != nil {
		return deny(err.Error()), nil
	}
	var g *presence.Grant
	if req.SessionID != "" {
		_, g, err = i.sessionFor(a, req.SessionID)
	} else {
		g, err = i.cfg.Grants.Get(presented)
	}
	if err != nil {
		return deny(err.Error()), nil
	}
	if g.Agent != a.id.Agent {
		return deny("grant is for agent " + g.Agent), nil
	}
	root := g.RootID()
	i.state.mu.Lock()
	shadow := i.state.shadows[root]
	i.state.mu.Unlock()
	var sanctioned presence.Scope
	if shadow {
		// The sanctioned scope is the ROOT grant's scope as the registry
		// holds it; policy keeps no copy that could disagree.
		rg, err := i.cfg.Grants.Get(root)
		if err != nil {
			return deny(err.Error()), nil
		}
		sanctioned = rg.Scope
	}

	covered := scopeCovers(g.Scope, req)
	if shadow {
		// Under shadow the sanctioned scope is what actually binds (the
		// sub-grant, if any, still narrows it), and every request is recorded
		// as an observation, covered or not.
		covered = covered && scopeCovers(sanctioned, req)
		i.observe(root, Observation{
			At: i.now(), Agent: a.id.Agent, GrantID: g.ID, Tool: req.Tool, Target: req.Target,
			AmountUSD: req.AmountUSD, Reversibility: reversibility(req), Covered: covered,
		})
	}
	prov := g.Provenance()
	if !covered {
		d, err := i.park(ctx, idString(a.id), g.ID, reversibility(req), req)
		d.Provenance = prov
		d.Shadow = shadow
		return d, err
	}
	dec := Decision{Verdict: VerdictAllow, Presence: presence.StateDelegated, Provenance: prov, Shadow: shadow}
	if req.AmountUSD != 0 {
		i.state.mu.Lock()
		spent := i.state.spendToday(root, i.now(), 0, false)
		dec.Money = g.Scope.Money.Decide(req.AmountUSD, spent)
		if dec.Money == presence.MoneyDelegated {
			i.state.spendToday(root, i.now(), req.AmountUSD, true)
		}
		i.state.mu.Unlock()
		if dec.Money != presence.MoneyDelegated {
			// Money above trivial is always presence, never delegated; it
			// parks irreversible whatever the request said.
			d, err := i.park(ctx, idString(a.id), g.ID, presence.Irreversible, req)
			d.Provenance = prov
			d.Money = dec.Money
			d.Shadow = shadow
			return d, err
		}
	}
	return dec, nil
}

// park records an out-of-grant request and answers "parked, id=X".
func (i *Issuer) park(ctx context.Context, agent, grantID string, rev presence.Reversibility, req Request) (Decision, error) {
	if len(req.Hash) != presence.RequestHashSize {
		return deny("request hash required to park this request"), nil
	}
	desc := req.Description
	if desc == "" {
		desc = req.Tool + " " + req.Target
	}
	id, err := i.cfg.Lot.Park(agent, grantID, rev, desc, req.Hash)
	if err != nil {
		return Decision{}, err
	}
	_, err = i.audit(ctx, AuditRecord{
		Kind: kindParked, SpiffeID: agent, GrantID: grantID, Target: req.Tool + " " + req.Target,
		Outcome: "parked " + id,
	})
	if err != nil {
		return Decision{}, err
	}
	return Decision{
		Verdict: VerdictPark, ParkedID: id, Reversibility: rev,
		Reason: "outside the grant: " + desc,
	}, nil
}

func reversibility(req Request) presence.Reversibility {
	if req.Reversibility == presence.Reversible {
		return presence.Reversible
	}
	return presence.Irreversible
}

// scopeCovers reports whether a scope confers the request, on the capability
// axes only. Money is decided separately by Money.Decide, because a covered
// request can still step up.
func scopeCovers(s presence.Scope, req Request) bool {
	if req.Tool == "" {
		return false
	}
	switch req.Tool {
	case partyAWS:
		return req.Target != "" && slices.Contains(s.AWSProfiles, req.Target)
	case partyGitHub, partyGit:
		return req.Target != "" && slices.Contains(s.GitHubScopes, req.Target)
	case partyClaude:
		return s.ClaudeProxy
	}
	return req.Target != "" && slices.Contains(s.Capabilities, capability(req.Tool, req.Target))
}

// capability renders "<relying-party>/<entity>#<action>" from a tool and a
// target already written "<entity>#<action>".
func capability(party, target string) string {
	if strings.HasPrefix(target, party+"/") {
		return target
	}
	return party + "/" + target
}

func (i *Issuer) observe(root string, o Observation) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	obs := i.state.observations[root]
	if len(obs) >= MaxObservations {
		return
	}
	i.state.observations[root] = append(obs, o)
}
