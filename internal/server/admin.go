package server

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// Device administration. docs/totem-design-decisions.md 32: "Approve,
// grant-admin, revoke-admin, and revoke ignore windows. A `presence: none`
// admin can approve, and the approved enrollment records it."
//
// None of that is decided here. Every one of these endpoints is a two-step
// flow: the device asks what to sign (Prepare, which builds the digest from
// ISSUER state so a signature can only ever authorise what the issuer will
// apply), signs it on its own hardware, and posts the signature back.
// internal/policy checks that the signer is an admin, that the assertion is
// bound to the digest, and that the last admin is not being revoked. This file
// offers no path that skips any of that: there is no unsigned variant of any of
// these four endpoints, which is the only structural guarantee a transport
// layer can actually make about them.

// Assertion is a presence assertion on the wire. It carries the signature and
// the fields the signature was made over, so the issuer can reconstruct the
// canonical bytes and verify them against the ENROLLED presence key. Nothing
// here is trusted as supplied; every field is compared against what the issuer
// already knows before the signature is checked.
type Assertion struct {
	Version     uint8  `json:"version"`
	DeviceID    string `json:"device_id"`
	Tool        string `json:"tool"`
	Target      string `json:"target"`
	Challenge   []byte `json:"challenge"`
	Signature   []byte `json:"signature"`
	RequestHash []byte `json:"request_hash,omitempty"`
}

func (a Assertion) presence() *presence.Assertion {
	return &presence.Assertion{
		Version:     a.Version,
		DeviceID:    a.DeviceID,
		Tool:        a.Tool,
		Target:      a.Target,
		Challenge:   a.Challenge,
		Signature:   a.Signature,
		RequestHash: a.RequestHash,
	}
}

// SignedRequest is one admin operation: the subject it acts on and the
// signature authorising it.
//
// It has no device field, no grant field, and no presence field, and that is
// deliberate rather than incidental. The SIGNER is the attested credential on
// the connection; the assertion's DeviceID is checked against it. A body that
// could name its own signer would let any enrolled device claim to be the
// admin whose key the issuer is about to verify against, which is the same
// class of mistake as taking a grant id from a request body.
type SignedRequest struct {
	// Subject is what the operation acts on: an approval code, or a device id.
	Subject string `json:"subject"`
	// Assertion is the signature over what Prepare returned.
	Assertion Assertion `json:"assertion"`
}

// PrepareRequest asks what to sign for one action.
type PrepareRequest struct {
	Action  policy.Action `json:"action"`
	Subject string        `json:"subject"`
}

// PrepareResponse is the exact signing input, plus the code the human compares
// against the OS prompt.
type PrepareResponse struct {
	Version     uint8  `json:"version"`
	DeviceID    string `json:"device_id"`
	Tool        string `json:"tool"`
	Target      string `json:"target"`
	Challenge   []byte `json:"challenge"`
	RequestHash []byte `json:"request_hash"`
	Code        string `json:"code"`
}

// ChallengeOnlyResponse is a bare signing challenge.
type ChallengeOnlyResponse struct {
	Challenge []byte `json:"challenge"`
	ExpiresIn int    `json:"expires_in"`
}

// DeviceView is one row of `totem devices`: "enrollment, protection level,
// admin flag, and last seen".
type DeviceView struct {
	DeviceID           string                 `json:"device_id"`
	Name               string                 `json:"name,omitempty"`
	Hostname           string                 `json:"hostname,omitempty"`
	OS                 string                 `json:"os,omitempty"`
	ProtectionLevel    spiffe.ProtectionLevel `json:"protection_level"`
	Presence           presence.State         `json:"presence"`
	FirstContact       presence.FirstContact  `json:"first_contact"`
	Admin              bool                   `json:"admin"`
	Founding           bool                   `json:"founding"`
	ApprovedBy         string                 `json:"approved_by,omitempty"`
	ApprovedByPresence presence.State         `json:"approved_by_presence,omitempty"`
	EnrolledAt         time.Time              `json:"enrolled_at"`
	LastSeen           time.Time              `json:"last_seen,omitempty"`
	Revoked            bool                   `json:"revoked,omitempty"`
}

func deviceView(e policy.EnrollmentRecord) DeviceView {
	return DeviceView{
		DeviceID:           e.DeviceID,
		Name:               e.Name,
		Hostname:           e.Hostname,
		OS:                 e.OS,
		ProtectionLevel:    e.ProtectionLevel,
		Presence:           e.Presence,
		FirstContact:       e.FirstContact,
		Admin:              e.Admin,
		Founding:           e.Founding,
		ApprovedBy:         e.ApprovedBy,
		ApprovedByPresence: e.ApprovedByPresence,
		EnrolledAt:         e.EnrolledAt,
		LastSeen:           e.LastSeen,
		Revoked:            e.Revoked,
	}
}

// PendingView is one row of the approval queue.
type PendingView struct {
	Code            string                 `json:"code"`
	DeviceID        string                 `json:"device_id"`
	Name            string                 `json:"name,omitempty"`
	Hostname        string                 `json:"hostname,omitempty"`
	OS              string                 `json:"os,omitempty"`
	ProtectionLevel spiffe.ProtectionLevel `json:"protection_level"`
	Presence        presence.State         `json:"presence"`
	FirstContact    presence.FirstContact  `json:"first_contact"`
	RequestedAt     time.Time              `json:"requested_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
}

// handleDevices lists the enrollment inventory.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, _ *policy.Attested) {
	records := s.cfg.Engine.Devices()
	out := make([]DeviceView, 0, len(records))
	for _, e := range records {
		out = append(out, deviceView(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePending lists enrollments waiting for an admin.
func (s *Server) handlePending(w http.ResponseWriter, r *http.Request, _ *policy.Attested) {
	items := s.cfg.Engine.Pending()
	out := make([]PendingView, 0, len(items))
	for _, p := range items {
		out = append(out, PendingView{
			Code: p.Code, DeviceID: p.DeviceID, Name: p.Name, Hostname: p.Hostname, OS: p.OS,
			ProtectionLevel: p.ProtectionLevel, Presence: p.Presence, FirstContact: p.FirstContact,
			RequestedAt: p.RequestedAt, ExpiresAt: p.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSignChallenge mints a signing challenge for the CALLING device. The
// device id comes from the credential, never from the body.
func (s *Server) handleSignChallenge(w http.ResponseWriter, r *http.Request, a *policy.Attested) {
	challenge, err := s.cfg.Engine.Challenge(a.ID().DeviceID)
	if err != nil {
		s.refuse(w, r, a.ID().DeviceID, err)
		return
	}
	writeJSON(w, http.StatusOK, ChallengeOnlyResponse{
		Challenge: challenge,
		ExpiresIn: int(presence.DefaultChallengeTTL.Seconds()),
	})
}

// handlePrepare returns exactly what the calling device must sign.
func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request, a *policy.Attested) {
	var req PrepareRequest
	if err := decode(r, &req); err != nil {
		s.refuse(w, r, a.ID().DeviceID, err)
		return
	}
	toSign, err := s.cfg.Engine.Prepare(a.ID().DeviceID, req.Action, req.Subject)
	if err != nil {
		s.refuse(w, r, a.ID().DeviceID, err)
		return
	}
	writeJSON(w, http.StatusOK, PrepareResponse{
		Version:     toSign.Input.Version,
		DeviceID:    toSign.Input.DeviceID,
		Tool:        toSign.Input.Tool,
		Target:      toSign.Input.Target,
		Challenge:   toSign.Input.Challenge,
		RequestHash: toSign.Input.RequestHash,
		Code:        toSign.Code,
	})
}

// handleApprove applies an admin's signed approval of a pending enrollment.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, a *policy.Attested) {
	req, sig, ok := s.signed(w, r, a, policy.ActionApprove)
	if !ok {
		return
	}
	rec, err := s.cfg.Engine.Approve(r.Context(), req.Subject, sig)
	if err != nil {
		s.refuse(w, r, a.ID().DeviceID, err)
		return
	}
	s.log(r, Event{
		Kind: "policy/" + string(policy.ActionApprove), Device: rec.DeviceID,
		Signer: a.ID().DeviceID, Presence: rec.ApprovedByPresence,
		Target: policy.Target(policy.ActionApprove, req.Subject), Outcome: "applied",
	})
	writeJSON(w, http.StatusOK, deviceView(*rec))
}

// handleGrantAdmin, handleRevokeAdmin and handleRevokeDevice are the remaining
// three presence:always operations. They differ only in which engine method
// they call and which action they log.
func (s *Server) handleGrantAdmin(w http.ResponseWriter, r *http.Request, a *policy.Attested) {
	s.applyDeviceAction(w, r, a, policy.ActionGrantAdmin, s.cfg.Engine.GrantAdmin)
}

func (s *Server) handleRevokeAdmin(w http.ResponseWriter, r *http.Request, a *policy.Attested) {
	s.applyDeviceAction(w, r, a, policy.ActionRevokeAdmin, s.cfg.Engine.RevokeAdmin)
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request, a *policy.Attested) {
	s.applyDeviceAction(w, r, a, policy.ActionRevoke, s.cfg.Engine.RevokeDevice)
}

func (s *Server) applyDeviceAction(
	w http.ResponseWriter, r *http.Request, a *policy.Attested,
	action policy.Action, apply func(ctx context.Context, deviceID string, sig policy.Signature) error,
) {
	req, sig, ok := s.signed(w, r, a, action)
	if !ok {
		return
	}
	if err := apply(r.Context(), req.Subject, sig); err != nil {
		s.refuse(w, r, a.ID().DeviceID, err)
		return
	}
	s.log(r, Event{
		Kind: "policy/" + string(action), Device: req.Subject, Signer: a.ID().DeviceID,
		Target: policy.Target(action, req.Subject), Outcome: "applied",
	})
	w.WriteHeader(http.StatusNoContent)
}

// signed decodes a signed admin request and rebuilds every field of the
// assertion that the issuer can derive for itself.
//
// THE RULE, and it is the build lead's constraint on the enrollment diagnostic
// generalised: a device-supplied value must not reach the verifier's input at
// all, regardless of what else guards it. presence.Assertion is exactly that
// input, because presence re-encodes it and hashes the result, so anything left
// in it from a request body is a caller-chosen string inside the bytes a
// signature is checked over.
//
// Three of its fields are things the issuer already knows, so the issuer sets
// them and the body cannot:
//
//   - DeviceID is the ATTESTED credential on the connection. A body that could
//     name its own signer would let any enrolled device claim to be the admin
//     whose key is about to be verified against.
//   - Tool is always policy.SigningTool. There is one.
//   - Target is always policy.Target(action, subject): the action is fixed by
//     the endpoint the request arrived at, and the subject is the operand.
//     internal/policy's own comment says "the issuer never accepts a target the
//     signer chose", and until now this handler was accepting one and relying
//     on policy's independent Expectation to disagree with it.
//
// That reliance was safe and is exactly the arrangement this build has found
// three defects in: two things that have to agree, both correct today. The
// safety no longer depends on the second one existing.
//
// Challenge, RequestHash and Signature necessarily come from the body, because
// they ARE the proof. Each is checked against issuer state by internal/policy:
// the challenge must be one it minted for this device, and the request hash
// must equal the digest it computed from its own records.
//
// The cost is a sentinel. A device that signed a different target now fails as
// ErrBadSignature rather than ErrTargetMismatch, because the bytes no longer
// carry what it thought it was signing. That is the same trade the lead ruled
// on for enrollment, and it goes the same way: the invariant is worth more than
// the precise error, and the human-facing message is written from the request
// code the CLI printed either way.
func (s *Server) signed(w http.ResponseWriter, r *http.Request, a *policy.Attested, action policy.Action) (SignedRequest, policy.Signature, bool) {
	var req SignedRequest
	if err := decode(r, &req); err != nil {
		s.refuse(w, r, a.ID().DeviceID, err)
		return req, policy.Signature{}, false
	}
	if req.Subject == "" {
		s.refuse(w, r, a.ID().DeviceID, badRequest(
			"Say which device or code this applies to.", "that request did not say what it applies to."))
		return req, policy.Signature{}, false
	}
	// Refused rather than silently corrected, because a mismatch here is a
	// person running the command from the wrong machine and they need to know
	// that, not to have it quietly rewritten under them.
	if req.Assertion.DeviceID != "" && req.Assertion.DeviceID != a.ID().DeviceID {
		s.refuse(w, r, a.ID().DeviceID, badRequest(
			"Run this from the device that confirmed it, not through another one.",
			"the confirmation came from a different device than the one asking."))
		return req, policy.Signature{}, false
	}

	assertion := req.Assertion.presence()
	assertion.DeviceID = a.ID().DeviceID
	assertion.Tool = policy.SigningTool
	assertion.Target = policy.Target(action, req.Subject)
	return req, policy.Signature{DeviceID: a.ID().DeviceID, Assertion: assertion}, true
}

// CRLView is one signed certificate revocation list, scoped to the
// intermediate that issued the certificates it lists.
type CRLView struct {
	// IssuerSubjectKeyID identifies the intermediate that signed this CRL,
	// which is also the intermediate that issued every serial it lists.
	IssuerSubjectKeyID string `json:"issuer_subject_key_id"`
	// DER is the signed CRL, ready to hand to rolesanywhere ImportCrl/UpdateCrl.
	DER []byte `json:"der"`
	// ThisUpdate and NextUpdate are the CRL's own validity. A relying party
	// still holding a CRL past NextUpdate is failing open.
	ThisUpdate time.Time `json:"this_update"`
	NextUpdate time.Time `json:"next_update"`
}

// handleCRLs publishes one CRL PER INTERMEDIATE, never a merged one.
//
// This shape is not a convenience and must not be collapsed. A CRL is signed by
// the CA that issued the certificates it revokes, and during a rotation overlap
// there are up to three live intermediates. A single list signed by the current
// intermediate is silently IGNORED by a correct verifier for every serial the
// outgoing intermediate issued, so the revocations that matter most during a
// rotation are exactly the ones that stop working, and revocation failing open
// is indistinguishable from nothing having been revoked. The endpoint is
// therefore an array whose length is a property of the schedule, not a
// convenience wrapper around one entry.
func (s *Server) handleCRLs(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CA == nil {
		writeError(w, r, &apiError{
			status: http.StatusServiceUnavailable, retryAfter: 60,
			what: "this issuer has not finished being set up.",
			fix:  "Ask your issuer operator to run 'totem-issuer init'."})
		return
	}
	crls, err := s.cfg.CA.CRLs(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]CRLView, 0, len(crls))
	for _, c := range crls {
		out = append(out, CRLView{
			IssuerSubjectKeyID: hex.EncodeToString(c.IssuerSubjectKeyID),
			DER:                c.DER,
			ThisUpdate:         c.ThisUpdate,
			NextUpdate:         c.NextUpdate,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleBundle publishes what relying parties must trust: the root, or both
// roots during a crossover, plus every intermediate whose validity window
// contains now. It is open, because a trust bundle is public by definition and
// requiring a credential to fetch the thing that verifies credentials is a
// bootstrap loop.
func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CA == nil {
		writeError(w, r, &apiError{
			status: http.StatusServiceUnavailable, retryAfter: 60,
			what: "this issuer has not finished being set up.",
			fix:  "Ask your issuer operator to run 'totem-issuer init'."})
		return
	}
	b, err := s.cfg.CA.Bundle(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	var out []byte
	for _, root := range b.Roots {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	}
	for _, in := range b.Intermediates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: in.Certificate.Raw})...)
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Totem-Bundle-Generated", b.GeneratedAt.UTC().Format(time.RFC3339))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
