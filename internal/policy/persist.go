package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/store"
)

// load rebuilds admin-signed state by walking the hash chain. Every policy
// record is re-verified before it is applied: the enrollment signatures
// inside an approve record with presence.VerifyEnrollment and
// presence.VerifyDetached, the signer's assertion with VerifyDetached
// against the key the signer's OWN earlier enrollment record holds, and the signer's
// authority (admin, or sponsor) as it stood at that ordinal. Records are
// replayed in chain order so that authority is what it was, not what it
// became. Store.Walk verifies each link as it goes; a break is
// store.ErrChainBroken and the issuer does not start.
func (i *Issuer) load(ctx context.Context) error {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	i.state.loading = true
	defer func() { i.state.loading = false }()
	err := i.cfg.Store.Walk(ctx, 0, func(r store.Record) error {
		if !strings.HasPrefix(r.Kind, kindPolicyPrefix) || r.Kind == kindPolicyPrefix+"bootstrap-issued" {
			return nil
		}
		var rec signedRecord
		if err := json.Unmarshal(r.Payload, &rec); err != nil {
			return fmt.Errorf("%w: seq %d: %v", ErrRecordInvalid, r.Seq, err)
		}
		if r.Kind != kindPolicyPrefix+string(rec.Action) {
			return fmt.Errorf("%w: seq %d kind %s carries action %s", ErrRecordInvalid, r.Seq, r.Kind, rec.Action)
		}
		if rec.Ordinal != i.state.ordinal+1 {
			return fmt.Errorf("%w: seq %d ordinal %d follows %d", ErrRecordInvalid, r.Seq, rec.Ordinal, i.state.ordinal)
		}
		if err := i.replay(&rec); err != nil {
			return fmt.Errorf("%w: seq %d (%s %s): %v", ErrRecordInvalid, r.Seq, rec.Action, rec.Subject, err)
		}
		i.state.ordinal = rec.Ordinal
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// verifyStored re-verifies a stored record's signature against the signer's
// enrollment as it stands in the replayed state, and checks that the
// recorded presence state is the one the signer's keys allow.
func (i *Issuer) verifyStored(rec *signedRecord, digest []byte) (*EnrollmentRecord, error) {
	signer, err := i.state.liveEnrollment(rec.Signer)
	if err != nil {
		return nil, err
	}
	presenceKey, deviceKey, err := signerKeys(signer)
	if err != nil {
		return nil, err
	}
	exp := presence.Expectation{
		DeviceID: signer.DeviceID, Tool: SigningTool, Target: Target(rec.Action, rec.Subject),
		Binding: presence.BindingRequired, RequestHash: digest,
	}
	switch rec.SignerPresence {
	case presence.StatePresent:
		if presenceKey == nil {
			return nil, errors.New("recorded as present but the signer has no presence key")
		}
		exp.PresenceKey = presenceKey
	case presence.StateNone:
		if presenceKey != nil {
			return nil, errors.New("recorded as none but the signer has a presence key")
		}
		// The recorded none-level signing: the device key stands in for
		// the presence key, exactly as it did when the record was applied.
		exp.PresenceKey = deviceKey
	default:
		return nil, fmt.Errorf("signer presence %q", rec.SignerPresence)
	}
	// Detached: the challenge was minted and spent in a previous process.
	// The Verified comes back consumed; only its verdict is used.
	if _, err := presence.VerifyDetached(rec.Assertion.assertion(), exp, rec.At); err != nil {
		return nil, err
	}
	return signer, nil
}

// replay applies one verified record to the in-memory state.
func (i *Issuer) replay(rec *signedRecord) error {
	switch rec.Action {
	case ActionApprove:
		return i.replayApprove(rec)
	case ActionGrantAdmin, ActionRevokeAdmin, ActionRevoke:
		var p devicePayload
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			return err
		}
		want, _ := devicePayloadFor(rec.Action, rec.Subject)
		if p.DeviceID != rec.Subject || string(want) != string(rec.Payload) {
			return errors.New("payload does not match subject")
		}
		signer, err := i.verifyStored(rec, recordDigest(rec.Action, rec.Subject, rec.Payload))
		if err != nil {
			return err
		}
		if !signer.Admin {
			return ErrNotAdmin
		}
		target, err := i.state.checkAdminChangeLocked(p.DeviceID, p.Admin, p.Revoked)
		if err != nil {
			return err
		}
		if p.Revoked {
			target.Revoked, target.RevokedAt, target.Admin = true, rec.At, false
		} else {
			target.Admin = p.Admin
		}
		return nil
	case ActionPresencePolicy:
		var p windowsPayload
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			return err
		}
		ws := windowsFromJSON(p.Windows)
		if windowsSubject(ws) != rec.Subject {
			return errors.New("windows do not match subject")
		}
		if err := validateWindows(ws); err != nil {
			return err
		}
		signer, err := i.verifyStored(rec, recordDigest(rec.Action, rec.Subject, []byte(rec.Subject)))
		if err != nil {
			return err
		}
		if !signer.Admin {
			return ErrNotAdmin
		}
		i.state.windows = ws
		return nil
	case ActionGrant:
		var p grantPayload
		if err := json.Unmarshal(rec.Payload, &p); err != nil {
			return err
		}
		g := presence.Grant{Agent: p.Agent, Scope: p.Scope.scope(), Until: p.Until}
		if grantSubject(g) != rec.Subject || !equalHash(g.Hash(), p.Hash) {
			return errors.New("grant does not match subject")
		}
		if rec.SignerPresence != presence.StatePresent || rec.Signer != p.Sponsor {
			return errors.New("grant not sponsored with presence by its recorded sponsor")
		}
		if _, err := i.verifyStored(rec, p.Hash); err != nil {
			return err
		}
		i.state.grants[p.ID] = &grantMeta{sponsor: p.Sponsor, shadow: p.Shadow, sanctioned: g.Scope, agent: p.Agent, until: p.Until}
		// presence.Registry has no restore path (Sponsor needs a live
		// Verified and mints its own id), so a restarted issuer cannot put
		// the grant back under its recorded id. If the registry ever grows
		// one, this is where the grant re-enters it; until then a restart
		// means every root grant is re-sponsored with presence.
		if r, ok := any(i.cfg.Grants).(interface{ Restore(presence.Grant) error }); ok {
			if err := r.Restore(presence.Grant{
				ID: p.ID, Agent: p.Agent, Sponsor: p.Sponsor, Scope: g.Scope, Until: p.Until,
				SignedAt: p.SignedAt, DerivedAt: p.SignedAt,
			}); err != nil {
				return err
			}
		}
		return nil
	case ActionRevokeGrant:
		signer, err := i.verifyStored(rec, recordDigest(rec.Action, rec.Subject, []byte(rec.Subject)))
		if err != nil {
			return err
		}
		if err := i.state.requireAdminOrSponsorLocked(signer.DeviceID, rec.Subject); err != nil {
			// The subject may be a sub-grant; its root is unknown after a
			// restart, so accept an admin and otherwise refuse.
			if !signer.Admin {
				return err
			}
		}
		i.cfg.Grants.Revoke(rec.Subject)
		return nil
	case ActionWiden, ActionStepUp, ActionStepUpBatch, ActionDeny:
		// Ephemeral consumers (sessions, the lot) are gone after a restart;
		// the record is verified for the chain's sake and applied to
		// nothing.
		digest, err := i.storedDigest(rec)
		if err != nil {
			return err
		}
		if rec.Action != ActionDeny && rec.SignerPresence != presence.StatePresent {
			return errors.New("step-up recorded without presence")
		}
		_, err = i.verifyStored(rec, digest)
		return err
	}
	return fmt.Errorf("unknown action %q", rec.Action)
}

// storedDigest recomputes the bound value for a record whose binding is a
// presence-package hash rather than a record digest.
func (i *Issuer) storedDigest(rec *signedRecord) ([]byte, error) {
	var p idPayload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return nil, err
	}
	switch rec.Action {
	case ActionWiden:
		if len(p.IDs) != 2 || WidenSubject(p.IDs[0], p.IDs[1]) != rec.Subject {
			return nil, errors.New("widen payload does not match subject")
		}
		return presence.WidenHash(p.IDs[0], p.IDs[1]), nil
	case ActionStepUp:
		// The request hash lived in the lot; it is in the assertion, and the
		// signature is what proves the human bound it. Verify against the
		// assertion's own hash, which VerifyDetached then checks the
		// signature over.
		if len(p.IDs) != 1 || p.IDs[0] != rec.Subject {
			return nil, errors.New("step-up payload does not match subject")
		}
		return rec.Assertion.RequestHash, nil
	case ActionStepUpBatch:
		if batchSubject(p.IDs) != rec.Subject {
			return nil, errors.New("batch payload does not match subject")
		}
		return presence.BatchHash(p.IDs), nil
	case ActionDeny:
		if len(p.IDs) != 1 || p.IDs[0] != rec.Subject {
			return nil, errors.New("deny payload does not match subject")
		}
		return recordDigest(rec.Action, rec.Subject, []byte(rec.Subject)), nil
	}
	return nil, fmt.Errorf("no stored digest for %s", rec.Action)
}

// replayApprove re-proves an enrollment: the device's proof of possession,
// its own presence assertion when it has a presence key, and the approver's
// signature or the founding self-approval.
func (i *Issuer) replayApprove(rec *signedRecord) error {
	var p enrollmentPayload
	if err := json.Unmarshal(rec.Payload, &p); err != nil {
		return err
	}
	in := p.Input.input()
	deviceKey, presenceKey, err := presence.VerifyEnrollment(in, p.Signature)
	if err != nil {
		return err
	}
	_ = deviceKey
	deviceID := presence.PreEnrollmentDeviceID(in.DevicePublicKey)
	digest, err := in.Digest()
	if err != nil {
		return err
	}
	enrolled := &presence.Enrolled{DeviceID: deviceID, State: presence.StateNone}
	switch {
	case presenceKey != nil && len(p.PresenceSignature) == 0:
		return presence.ErrEnrollmentNeedsPresence
	case presenceKey == nil && len(p.PresenceSignature) != 0:
		return presence.ErrEnrollmentUnexpectedPresence
	case presenceKey != nil:
		a := &presence.Assertion{
			Version: presence.EncodingVersion, DeviceID: deviceID, Tool: presence.EnrollmentTool,
			Target: i.cfg.TrustDomain, Challenge: in.Challenge, Signature: p.PresenceSignature, RequestHash: digest,
		}
		if _, err := presence.VerifyDetached(a, presence.Expectation{
			PresenceKey: presenceKey, DeviceID: deviceID, Tool: presence.EnrollmentTool, Target: i.cfg.TrustDomain,
			Binding: presence.BindingRequired, RequestHash: digest,
		}, rec.At); err != nil {
			return fmt.Errorf("device presence assertion: %w", err)
		}
		enrolled.State = presence.StatePresent
	}
	if e, ok := i.state.enrollments[deviceID]; ok && e.Live() {
		return ErrAlreadyEnrolled
	}
	e := enrollmentFrom(in, enrolled, p.Name, rec.At)

	if p.Founding {
		// Founding: self-approved by the bootstrap code, which is bound into
		// the signed input and cannot be re-checked after redemption. The
		// record must say so consistently, and only the first record may be
		// founding.
		if rec.Subject != "founding" || rec.Signer != deviceID || rec.SignerPresence != enrolled.State || len(in.BootstrapCodeHash) == 0 {
			return errors.New("founding record inconsistent")
		}
		if i.state.ordinal != 0 {
			return errors.New("founding record is not the first record")
		}
		e.Admin, e.Founding, e.ApprovedByPresence = true, true, enrolled.State
		i.state.enrollments[deviceID] = e
		return nil
	}
	if len(in.BootstrapCodeHash) != 0 {
		return errors.New("non-founding record binds a bootstrap code")
	}
	code, err := presence.EnrollmentCode(in)
	if err != nil {
		return err
	}
	if code != rec.Subject {
		return errors.New("approval subject is not the enrollment code")
	}
	signer, err := i.verifyStored(rec, recordDigest(ActionApprove, rec.Subject, rec.Payload))
	if err != nil {
		return err
	}
	if !signer.Admin {
		return ErrNotAdmin
	}
	e.ApprovedBy, e.ApprovedByPresence = signer.DeviceID, rec.SignerPresence
	i.state.enrollments[deviceID] = e
	return nil
}
