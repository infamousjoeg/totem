package policy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/store"
)

// issueBootstrapCode mints the one-time code. It is stored envelope-encrypted
// under the store's data key, never logged, and minting replaces any
// outstanding code so a leaked earlier one dies with the new print.
func (i *Issuer) issueBootstrapCode(ctx context.Context) (string, time.Time, error) {
	code, err := randomCode()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := i.now().Add(BootstrapTTL)
	body, err := json.Marshal(bootstrapCode{Code: code, Expires: expires})
	if err != nil {
		return "", time.Time{}, err
	}
	if err := i.cfg.Store.Put(ctx, collectionBootstrap, bootstrapID, body); err != nil {
		return "", time.Time{}, fmt.Errorf("policy: store bootstrap code: %w", err)
	}
	if _, err := i.audit(ctx, AuditRecord{Kind: kindPolicyPrefix + "bootstrap-issued", Outcome: "issued"}); err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// redeemBootstrap checks the code against the stored one and deletes it.
// The code is compared in constant time; the hash in the enrollment input is
// checked by the caller against this same code and the challenge.
func (i *Issuer) redeemBootstrap(ctx context.Context, code string) error {
	body, err := i.cfg.Store.Get(ctx, collectionBootstrap, bootstrapID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrBootstrapInvalid
	}
	if err != nil {
		return fmt.Errorf("policy: read bootstrap code: %w", err)
	}
	var bc bootstrapCode
	if err := json.Unmarshal(body, &bc); err != nil {
		return fmt.Errorf("%w: bootstrap row", ErrRecordInvalid)
	}
	// Whatever the outcome, a presented code is spent: delete before
	// comparing so a wrong guess cannot be followed by a right one.
	if err := i.cfg.Store.Delete(ctx, collectionBootstrap, bootstrapID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("policy: spend bootstrap code: %w", err)
	}
	if !i.now().Before(bc.Expires) {
		return fmt.Errorf("%w: expired", ErrBootstrapInvalid)
	}
	if subtle.ConstantTimeCompare([]byte(bc.Code), []byte(code)) != 1 {
		return ErrBootstrapInvalid
	}
	return nil
}

func (i *Issuer) enrollmentChallenge(spki []byte) ([]byte, error) {
	if len(spki) == 0 {
		return nil, fmt.Errorf("%w: empty device key", presence.ErrEnrollmentMalformed)
	}
	return i.cfg.Verifier.Mint(presence.PreEnrollmentDeviceID(spki))
}

// enroll is the issuer side of totem enroll. The assertion is rebuilt here
// from the issuer's own knowledge: the device id from the key, the tool
// constant, the target from the ISSUER's trust domain, the request hash from
// the input digest. The device supplied only signature bytes. Then one call,
// presence.Verifier.Enroll, spends the challenge once for both signatures.
func (i *Issuer) enroll(ctx context.Context, req EnrollRequest, issuerFingerprint []byte) (*EnrollResult, error) {
	in := req.Input
	in.Version = presence.EncodingVersion
	var a *presence.Assertion
	if len(req.PresenceSignature) != 0 {
		digest, err := in.Digest()
		if err != nil {
			return nil, err
		}
		a = &presence.Assertion{
			Version:     presence.EncodingVersion,
			DeviceID:    presence.PreEnrollmentDeviceID(in.DevicePublicKey),
			Tool:        presence.EnrollmentTool,
			Target:      i.cfg.TrustDomain,
			Challenge:   in.Challenge,
			Signature:   req.PresenceSignature,
			RequestHash: digest,
		}
	}
	enrolled, err := i.cfg.Verifier.Enroll(in, req.Signature, a, i.cfg.TrustDomain)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(in.IssuerFingerprint, issuerFingerprint) != 1 {
		return nil, ErrIssuerFingerprint
	}
	now := i.now()
	i.state.mu.Lock()
	if e, ok := i.state.enrollments[enrolled.DeviceID]; ok && e.Live() {
		i.state.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrAlreadyEnrolled, enrolled.DeviceID)
	}
	i.state.mu.Unlock()

	founding := len(in.BootstrapCodeHash) != 0
	payload, err := json.Marshal(enrollmentPayload{
		Input: inputToJSON(in), Signature: req.Signature, PresenceSignature: req.PresenceSignature,
		Name: req.Name, Founding: founding,
	})
	if err != nil {
		return nil, err
	}
	result := &EnrollResult{DeviceID: enrolled.DeviceID, Presence: enrolled.State}

	if !founding {
		if req.BootstrapCode != "" {
			return nil, fmt.Errorf("%w: code sent but not bound into the enrollment", ErrBootstrapInvalid)
		}
		code, err := presence.EnrollmentCode(in)
		if err != nil {
			return nil, err
		}
		p := &pendingEnrollment{
			PendingEnrollment: PendingEnrollment{
				Code: code, DeviceID: enrolled.DeviceID, Name: req.Name, Hostname: in.Hostname, OS: in.OS,
				ProtectionLevel: in.ProtectionLevel, FirstContact: in.FirstContact, Presence: enrolled.State,
				RequestedAt: now, ExpiresAt: now.Add(PendingTTL),
			},
			payload: payload, enrolled: enrolled, input: in,
		}
		i.state.mu.Lock()
		i.state.pending[code] = p
		i.state.mu.Unlock()
		result.Code = code
		return result, nil
	}

	// Founding device: the bootstrap code is the authorization. The hash in
	// the signed input must be the hash of THIS challenge and the code the
	// device sent, and the code must be the stored, unexpired one.
	if req.BootstrapCode == "" {
		return nil, fmt.Errorf("%w: hash bound but no code sent", ErrBootstrapInvalid)
	}
	if subtle.ConstantTimeCompare(presence.BootstrapCodeHash(in.Challenge, req.BootstrapCode), in.BootstrapCodeHash) != 1 {
		return nil, fmt.Errorf("%w: hash does not match the code", ErrBootstrapInvalid)
	}
	if err := i.redeemBootstrap(ctx, req.BootstrapCode); err != nil {
		return nil, err
	}
	rec := enrollmentFrom(in, enrolled, req.Name, now)
	rec.Admin = true
	rec.Founding = true
	rec.ApprovedByPresence = enrolled.State
	sr := &signedRecord{
		Action: ActionApprove, At: now, Subject: "founding", Payload: payload,
		Signer: enrolled.DeviceID, SignerPresence: enrolled.State,
	}
	if a != nil {
		sr.Assertion = toJSON(a)
	}
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.record(ctx, sr); err != nil {
		return nil, err
	}
	i.state.enrollments[rec.DeviceID] = rec
	result.Approved = true
	return result, nil
}

func enrollmentFrom(in presence.EnrollmentInput, enrolled *presence.Enrolled, name string, now time.Time) *EnrollmentRecord {
	return &EnrollmentRecord{
		DeviceID:          enrolled.DeviceID,
		Name:              name,
		PublicKey:         slices.Clone(in.DevicePublicKey),
		PresencePublicKey: slices.Clone(in.PresencePublicKey),
		ProtectionLevel:   in.ProtectionLevel,
		PinnedCert:        slices.Clone(in.IssuerFingerprint),
		Hostname:          in.Hostname,
		OS:                in.OS,
		FirstContact:      in.FirstContact,
		Presence:          enrolled.State,
		EnrolledAt:        now,
		LastSeen:          now,
	}
}

func (s *state) pendingByCode(code string, now time.Time) (*pendingEnrollment, error) {
	p, ok := s.pending[code]
	if !ok {
		return nil, ErrPendingNotFound
	}
	if !now.Before(p.ExpiresAt) {
		delete(s.pending, code)
		return nil, ErrPendingExpired
	}
	return p, nil
}

func (i *Issuer) pending() []PendingEnrollment {
	now := i.now()
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	var out []PendingEnrollment
	for code, p := range i.state.pending {
		if !now.Before(p.ExpiresAt) {
			delete(i.state.pending, code)
			continue
		}
		out = append(out, p.PendingEnrollment)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].RequestedAt.Before(out[b].RequestedAt) })
	return out
}

// approve applies an admin's signed approval. Order: find the pending
// enrollment (its payload is what the digest covers), verify the signature
// as an admin's presence:always assertion over that digest, then record and
// enroll. The signer's admin flag is checked BEFORE the challenge is spent
// so a non-admin's touch is refused without burning anything, and again
// under the lock before applying, in case it was revoked in between.
func (i *Issuer) approve(ctx context.Context, code string, sig Signature) (*EnrollmentRecord, error) {
	if err := i.requireAdmin(sig.DeviceID); err != nil {
		return nil, err
	}
	digest, err := i.digestFor(ActionApprove, code)
	if err != nil {
		return nil, err
	}
	signer, state, _, err := i.verifySignature(sig, ActionApprove, code, digest, false)
	if err != nil {
		return nil, err
	}
	now := i.now()
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.state.requireAdminLocked(signer.DeviceID); err != nil {
		return nil, err
	}
	p, err := i.state.pendingByCode(code, now)
	if err != nil {
		return nil, err
	}
	if e, ok := i.state.enrollments[p.DeviceID]; ok && e.Live() {
		return nil, fmt.Errorf("%w: %s", ErrAlreadyEnrolled, p.DeviceID)
	}
	rec := enrollmentFrom(p.input, p.enrolled, p.Name, now)
	rec.ApprovedBy = signer.DeviceID
	rec.ApprovedByPresence = state
	sr := &signedRecord{
		Action: ActionApprove, At: now, Subject: code, Payload: p.payload,
		Signer: signer.DeviceID, SignerPresence: state, Assertion: toJSON(sig.Assertion),
	}
	if err := i.record(ctx, sr); err != nil {
		return nil, err
	}
	delete(i.state.pending, code)
	i.state.enrollments[rec.DeviceID] = rec
	out := *rec
	return &out, nil
}

func (i *Issuer) requireAdmin(deviceID string) error {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return i.state.requireAdminLocked(deviceID)
}

func (s *state) requireAdminLocked(deviceID string) error {
	e, err := s.liveEnrollment(deviceID)
	if err != nil {
		return err
	}
	if !e.Admin {
		return fmt.Errorf("%w: %s", ErrNotAdmin, deviceID)
	}
	return nil
}

func (i *Issuer) devices() []EnrollmentRecord {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	out := make([]EnrollmentRecord, 0, len(i.state.enrollments))
	for _, e := range i.state.enrollments {
		out = append(out, *e)
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].EnrolledAt.Equal(out[b].EnrolledAt) {
			return out[a].EnrolledAt.Before(out[b].EnrolledAt)
		}
		return out[a].DeviceID < out[b].DeviceID
	})
	return out
}

func (i *Issuer) device(id string) (*EnrollmentRecord, error) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	e, ok := i.state.enrollments[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrDeviceNotFound, id)
	}
	out := *e
	return &out, nil
}

func (i *Issuer) seen(id string) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if e, ok := i.state.enrollments[id]; ok {
		e.LastSeen = i.now()
	}
}

// setAdmin is grant-admin and revoke-admin: admin only, presence:always,
// last admin refused.
func (i *Issuer) setAdmin(ctx context.Context, deviceID string, admin bool, sig Signature) error {
	action := ActionRevokeAdmin
	if admin {
		action = ActionGrantAdmin
	}
	if err := i.requireAdmin(sig.DeviceID); err != nil {
		return err
	}
	if err := i.checkAdminChange(deviceID, admin, false); err != nil {
		return err
	}
	digest, err := i.digestFor(action, deviceID)
	if err != nil {
		return err
	}
	signer, state, _, err := i.verifySignature(sig, action, deviceID, digest, false)
	if err != nil {
		return err
	}
	payload, _ := devicePayloadFor(action, deviceID)
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.state.requireAdminLocked(signer.DeviceID); err != nil {
		return err
	}
	target, err := i.state.checkAdminChangeLocked(deviceID, admin, false)
	if err != nil {
		return err
	}
	if err := i.record(ctx, &signedRecord{
		Action: action, At: i.now(), Subject: deviceID, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: state, Assertion: toJSON(sig.Assertion),
	}); err != nil {
		return err
	}
	target.Admin = admin
	return nil
}

func (i *Issuer) checkAdminChange(deviceID string, admin, revoke bool) error {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	_, err := i.state.checkAdminChangeLocked(deviceID, admin, revoke)
	return err
}

// checkAdminChangeLocked is the last-admin rule: clearing the admin flag on,
// or revoking, the only live admin is refused.
func (s *state) checkAdminChangeLocked(deviceID string, admin, revoke bool) (*EnrollmentRecord, error) {
	target, err := s.liveEnrollment(deviceID)
	if err != nil {
		return nil, err
	}
	if (revoke || !admin) && target.Admin && s.liveAdmins() <= 1 {
		return nil, fmt.Errorf("%w: %s", ErrLastAdmin, deviceID)
	}
	return target, nil
}

// revokeDevice revokes an enrollment instantly: sessions drop, live checks
// fail. Admin only, presence:always, last admin refused.
func (i *Issuer) revokeDevice(ctx context.Context, deviceID string, sig Signature) error {
	if err := i.requireAdmin(sig.DeviceID); err != nil {
		return err
	}
	if err := i.checkAdminChange(deviceID, false, true); err != nil {
		return err
	}
	digest, err := i.digestFor(ActionRevoke, deviceID)
	if err != nil {
		return err
	}
	signer, state, _, err := i.verifySignature(sig, ActionRevoke, deviceID, digest, false)
	if err != nil {
		return err
	}
	payload, _ := devicePayloadFor(ActionRevoke, deviceID)
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.state.requireAdminLocked(signer.DeviceID); err != nil {
		return err
	}
	target, err := i.state.checkAdminChangeLocked(deviceID, false, true)
	if err != nil {
		return err
	}
	now := i.now()
	if err := i.record(ctx, &signedRecord{
		Action: ActionRevoke, At: now, Subject: deviceID, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: state, Assertion: toJSON(sig.Assertion),
	}); err != nil {
		return err
	}
	target.Revoked = true
	target.RevokedAt = now
	target.Admin = false
	i.cfg.Sessions.Revoke(deviceID)
	return nil
}

// setWindows replaces the presence policy with an admin-signed one.
func (i *Issuer) setWindows(ctx context.Context, windows []presence.Window, sig Signature) error {
	if err := validateWindows(windows); err != nil {
		return err
	}
	if err := i.requireAdmin(sig.DeviceID); err != nil {
		return err
	}
	subject := windowsSubject(windows)
	digest, err := i.digestFor(ActionPresencePolicy, subject)
	if err != nil {
		return err
	}
	signer, state, _, err := i.verifySignature(sig, ActionPresencePolicy, subject, digest, false)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(windowsPayload{Windows: windowsToJSON(windows)})
	if err != nil {
		return err
	}
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if err := i.state.requireAdminLocked(signer.DeviceID); err != nil {
		return err
	}
	if err := i.record(ctx, &signedRecord{
		Action: ActionPresencePolicy, At: i.now(), Subject: subject, Payload: payload,
		Signer: signer.DeviceID, SignerPresence: state, Assertion: toJSON(sig.Assertion),
	}); err != nil {
		return err
	}
	i.state.windows = windowsFromJSON(windowsToJSON(windows))
	return nil
}

func (i *Issuer) windows() []presence.Window {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return slices.Clone(i.state.windows)
}

// window finds the policy for a tool and target: exact tool:target first,
// then the tool-wide window. Neither is Default deny.
func (i *Issuer) window(tool, target string) (presence.Window, bool) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	var wide presence.Window
	found := false
	for _, w := range i.state.windows {
		if w.Tool != tool {
			continue
		}
		if w.Target == target && target != "" {
			return w, true
		}
		if w.Target == "" {
			wide, found = w, true
		}
	}
	return wide, found
}

func protectionLevel(s string) spiffe.ProtectionLevel { return spiffe.ProtectionLevel(s) }

// idString renders a spiffe.ID as its URI.
func idString(id spiffe.ID) string {
	var b strings.Builder
	b.WriteString("spiffe://")
	b.WriteString(id.TrustDomain)
	b.WriteString("/device/")
	b.WriteString(id.DeviceID)
	if id.Agent != "" {
		b.WriteString("/agent/")
		b.WriteString(id.Agent)
	} else {
		b.WriteString("/tool/")
		b.WriteString(id.Tool)
	}
	return b.String()
}
