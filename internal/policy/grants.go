package policy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
)

// sponsor records a root grant. The signature must be from a live enrolled
// device WITH presence: presence.Registry.Sponsor takes a *presence.Verified,
// which only the presence path of verifySignature produces, so a none-level
// device cannot sponsor a grant however it signs. The registry checks the
// bound hash against g.Hash() again itself.
func (i *Issuer) sponsor(ctx context.Context, g presence.Grant, sig Signature) (*presence.Grant, error) {
	return i.sponsorGrant(ctx, g, sig, false)
}

func (i *Issuer) shadow(ctx context.Context, g presence.Grant, sig Signature) (*presence.Grant, error) {
	return i.sponsorGrant(ctx, g, sig, true)
}

func (i *Issuer) sponsorGrant(ctx context.Context, g presence.Grant, sig Signature, shadow bool) (*presence.Grant, error) {
	if g.Agent == "" {
		return nil, fmt.Errorf("%w: no agent", presence.ErrGrantInvalid)
	}
	if err := g.Scope.Validate(); err != nil {
		return nil, err
	}
	subject := grantSubject(g)
	digest := g.Hash()
	_, _, v, err := i.verifySignature(sig, ActionGrant, subject, digest, true)
	if err != nil {
		return nil, err
	}
	root, err := i.cfg.Grants.Sponsor(g, v)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(grantPayload{
		ID: root.ID, Agent: root.Agent, Sponsor: root.Sponsor, Scope: scopeToJSON(root.Scope),
		Until: root.Until, SignedAt: root.SignedAt, Shadow: shadow, Hash: digest,
	})
	if err != nil {
		return nil, err
	}
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.record(ctx, &signedRecord{
		Action: ActionGrant, At: i.now(), Subject: subject, Payload: payload,
		Signer: root.Sponsor, SignerPresence: presence.StatePresent, Assertion: toJSON(sig.Assertion),
	}); err != nil {
		// The grant is registered but unrecorded: revoke it so nothing runs
		// under a grant the chain does not know.
		i.cfg.Grants.Revoke(root.ID)
		return nil, err
	}
	i.state.recordRoot(root.ID, shadow)
	return root, nil
}

// revokeGrant revokes a grant and every sub-grant below it. Admin, or the
// sponsor of the root grant, presence:always.
func (i *Issuer) revokeGrant(ctx context.Context, grantID string, sig Signature) error {
	if grantID == "" {
		return fmt.Errorf("%w: empty grant id", presence.ErrMalformed)
	}
	root := grantID
	if g, err := i.cfg.Grants.Get(grantID); err == nil {
		root = g.RootID()
	}
	if err := i.requireAdminOrSponsor(sig.DeviceID, root); err != nil {
		return err
	}
	digest, err := i.digestFor(ActionRevokeGrant, grantID)
	if err != nil {
		return err
	}
	signer, state, _, err := i.verifySignature(sig, ActionRevokeGrant, grantID, digest, false)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(idPayload{IDs: []string{grantID}})
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.state.requireAdminOrSponsorLocked(i.cfg.Grants, signer.DeviceID, root); err != nil {
		return err
	}
	if err := i.record(ctx, &signedRecord{
		Action: ActionRevokeGrant, At: i.now(), Subject: grantID, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: state, Assertion: toJSON(sig.Assertion),
	}); err != nil {
		return err
	}
	i.cfg.Grants.Revoke(grantID)
	return nil
}

func (i *Issuer) requireAdminOrSponsor(deviceID, rootID string) error {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return i.state.requireAdminOrSponsorLocked(i.cfg.Grants, deviceID, rootID)
}

// requireAdminOrSponsorLocked accepts an admin, or the sponsor the REGISTRY
// records for the root grant. The sponsor is read from the registry and
// nowhere else; a grant the registry no longer serves (expired, revoked,
// unknown) has no sponsor here, so only an admin can act on it.
func (s *state) requireAdminOrSponsorLocked(reg *presence.Registry, deviceID, rootID string) error {
	e, err := s.liveEnrollment(deviceID)
	if err != nil {
		return err
	}
	if e.Admin {
		return nil
	}
	if g, err := reg.Get(rootID); err == nil && g.Sponsor == deviceID {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrNotSponsor, deviceID)
}

// recordRoot remembers a root grant id and its shadow flag, under the lock.
func (s *state) recordRoot(id string, shadow bool) {
	s.roots[id] = struct{}{}
	if shadow {
		s.shadows[id] = true
	}
}

func (i *Issuer) renewalsDue() []presence.Grant {
	now := i.now()
	i.state.mu.Lock()
	ids := make([]string, 0, len(i.state.roots))
	for id := range i.state.roots {
		ids = append(ids, id)
	}
	i.state.mu.Unlock()
	var out []presence.Grant
	for _, id := range ids {
		g, err := i.cfg.Grants.Get(id)
		if err == nil && g.RenewalDue(now) {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Until.Before(out[b].Until) })
	return out
}

// delegated checks that the credential is a delegated agent identity and
// returns its grant id. This is the only source of the presented grant id
// in the package.
func delegated(a *Attested) (string, error) {
	switch {
	case a == nil:
		return "", ErrCredential
	case a.id.Agent == "":
		return "", fmt.Errorf("%w: not an agent identity", ErrNotDelegated)
	case a.state != presence.StateDelegated || a.prov.GrantID == "":
		return "", fmt.Errorf("%w: presence %q", ErrNotDelegated, a.state)
	}
	return a.prov.GrantID, nil
}

// openSession opens an agent session. presentedGrantID is a.GrantID(): the
// attested provenance, read from the certificate the issuer signed. The
// agent named by the grant must be the agent the credential is for.
func (i *Issuer) openSession(ctx context.Context, a *Attested, grantID string) (*presence.AgentSession, error) {
	presented, err := delegated(a)
	if err != nil {
		return nil, err
	}
	if err := i.requireLiveDevice(a.id.DeviceID); err != nil {
		return nil, err
	}
	if grantID == "" {
		grantID = presented
	}
	g, err := i.cfg.Grants.Get(grantID)
	if err != nil {
		return nil, err
	}
	if g.Agent != a.id.Agent {
		return nil, fmt.Errorf("%w: grant is for %s", ErrNotAgentIdentity, g.Agent)
	}
	s, err := i.cfg.Grants.Open(presented, grantID)
	if err != nil {
		return nil, err
	}
	_, err = i.audit(ctx, AuditRecord{
		Kind: kindSession, SpiffeID: idString(a.id), Device: a.id.DeviceID,
		Presence: presence.StateDelegated, GrantID: g.ID, Outcome: "opened " + s.ID,
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// sessionFor returns the session and its active grant for an attested
// agent, refusing a session that belongs to another agent or whose active
// grant is not the presented grant or one of its descendants.
func (i *Issuer) sessionFor(a *Attested, sessionID string) (*presence.AgentSession, *presence.Grant, error) {
	presented, err := delegated(a)
	if err != nil {
		return nil, nil, err
	}
	s, err := i.cfg.Grants.Session(sessionID)
	if err != nil {
		return nil, nil, err
	}
	if s.Agent != a.id.Agent {
		return nil, nil, fmt.Errorf("%w: session is %s's", ErrNotAgentIdentity, s.Agent)
	}
	g, err := i.cfg.Grants.Active(sessionID)
	if err != nil {
		return nil, nil, err
	}
	if g.ID != presented && !slices.Contains(g.Lineage, presented) {
		return nil, nil, presence.ErrNotHolder
	}
	return s, g, nil
}

// narrow derives a sub-grant instantly and logs it under its lineage.
func (i *Issuer) narrow(ctx context.Context, a *Attested, sessionID string, scope presence.Scope, until time.Time) (*presence.Grant, error) {
	if _, _, err := i.sessionFor(a, sessionID); err != nil {
		return nil, err
	}
	child, err := i.cfg.Grants.Narrow(sessionID, scope, until)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(grantPayload{
		ID: child.ID, Agent: child.Agent, Sponsor: child.Sponsor, Scope: scopeToJSON(child.Scope),
		Until: child.Until, SignedAt: child.SignedAt, Lineage: child.Lineage,
	})
	_, err = i.audit(ctx, AuditRecord{
		Kind: kindGrantNarrow, SpiffeID: idString(a.id), Device: a.id.DeviceID,
		Presence: presence.StateDelegated, GrantID: child.ID, Outcome: "narrowed from " + child.ParentID(), Payload: body,
	})
	if err != nil {
		return nil, err
	}
	return child, nil
}

// widen returns a session to an ancestor with fresh presence bound to
// exactly this widen. The registry enforces lineage and freshness; policy
// enforces that the signer is a live enrolled device with presence and
// records the change.
func (i *Issuer) widen(ctx context.Context, sessionID, toGrantID string, sig Signature) (*presence.Grant, error) {
	subject := WidenSubject(sessionID, toGrantID)
	digest, err := i.digestFor(ActionWiden, subject)
	if err != nil {
		return nil, err
	}
	signer, _, v, err := i.verifySignature(sig, ActionWiden, subject, digest, true)
	if err != nil {
		return nil, err
	}
	g, err := i.cfg.Grants.Widen(sessionID, toGrantID, v)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(idPayload{IDs: []string{sessionID, toGrantID}})
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.record(ctx, &signedRecord{
		Action: ActionWiden, At: i.now(), Subject: subject, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: presence.StatePresent, Assertion: toJSON(sig.Assertion),
	}); err != nil {
		return nil, err
	}
	return g, nil
}

// approveParked approves one parked request. Presence is required by the
// Lot itself (it takes a Verified), so a none-level device cannot approve.
func (i *Issuer) approveParked(ctx context.Context, id string, sig Signature) error {
	digest, err := i.digestFor(ActionStepUp, id)
	if err != nil {
		return err
	}
	signer, _, v, err := i.verifySignature(sig, ActionStepUp, id, digest, true)
	if err != nil {
		return err
	}
	if err := i.cfg.Lot.Approve(id, v); err != nil {
		return err
	}
	payload, _ := json.Marshal(idPayload{IDs: []string{id}})
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return i.record(ctx, &signedRecord{
		Action: ActionStepUp, At: i.now(), Subject: id, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: presence.StatePresent, Assertion: toJSON(sig.Assertion),
	})
}

func (i *Issuer) approveBatch(ctx context.Context, ids []string, sig Signature) error {
	subject := batchSubject(ids)
	if subject == "" {
		return fmt.Errorf("%w: empty batch", presence.ErrParkedInvalid)
	}
	digest, err := i.digestFor(ActionStepUpBatch, subject)
	if err != nil {
		return err
	}
	signer, _, v, err := i.verifySignature(sig, ActionStepUpBatch, subject, digest, true)
	if err != nil {
		return err
	}
	if err := i.cfg.Lot.ApproveBatch(ids, v); err != nil {
		return err
	}
	payload, _ := json.Marshal(idPayload{IDs: strings.Split(subject, ",")})
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return i.record(ctx, &signedRecord{
		Action: ActionStepUpBatch, At: i.now(), Subject: subject, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: presence.StatePresent, Assertion: toJSON(sig.Assertion),
	})
}

// denyParked refuses a parked request. Signed, but presence is not required:
// refusing is the safe direction, and a none-level device may say no.
func (i *Issuer) denyParked(ctx context.Context, id string, sig Signature) error {
	digest, err := i.digestFor(ActionDeny, id)
	if err != nil {
		return err
	}
	signer, state, _, err := i.verifySignature(sig, ActionDeny, id, digest, false)
	if err != nil {
		return err
	}
	if err := i.cfg.Lot.Deny(id); err != nil {
		return err
	}
	payload, _ := json.Marshal(idPayload{IDs: []string{id}})
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return i.record(ctx, &signedRecord{
		Action: ActionDeny, At: i.now(), Subject: id, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: state, Assertion: toJSON(sig.Assertion),
	})
}

func (i *Issuer) consume(ctx context.Context, id string) (presence.ParkedRequest, error) {
	item, err := i.cfg.Lot.Consume(id)
	if err != nil {
		return presence.ParkedRequest{}, err
	}
	_, err = i.audit(ctx, AuditRecord{
		Kind: kindParked, SpiffeID: item.Agent, GrantID: item.GrantID, Target: item.Description,
		Presence: presence.StatePresent, Device: item.ApprovedBy, Outcome: "consumed " + id,
	})
	if err != nil {
		return presence.ParkedRequest{}, err
	}
	return item, nil
}

func (i *Issuer) requireLiveDevice(deviceID string) error {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	_, err := i.state.liveEnrollment(deviceID)
	return err
}

func (i *Issuer) observations(root string) []Observation {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return slices.Clone(i.state.observations[root])
}

// spendToday returns the root grant's outward money total for the issuer's
// current day, and adds amount to it when add is true.
func (s *state) spendToday(root string, now time.Time, amount float64, add bool) float64 {
	day := now.UTC().Truncate(24 * time.Hour)
	d, ok := s.spend[root]
	if !ok || !d.day.Equal(day) {
		d = &dailySpend{day: day}
		s.spend[root] = d
	}
	if add {
		d.usd += amount
	}
	return d.usd
}

// equalHash is a constant-time byte comparison.
func equalHash(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
