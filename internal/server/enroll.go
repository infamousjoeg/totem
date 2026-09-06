package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// docs/totem-design.md "Enrollment" is headless first, browser as a courtesy,
// and the whole flow is two calls: mint a challenge, submit the enrollment.
//
// The single most important property of this file is what it does NOT do. It
// verifies nothing. One enrollment carries TWO signatures over ONE
// issuer-minted challenge, the device half proving possession of the device key
// and the presence half proving a human was there, and presence.Verifier.Enroll
// is the only thing allowed to check them because it is the only thing that
// spends the challenge once for both. Verifying them separately spends the
// challenge on the first, and the second then fails as a replay: a bug that
// passes every test written against a fake and fails against the first real
// Secure Enclave. So this file maps the wire onto presence.EnrollmentInput,
// hands it to internal/policy, and translates the answer.
//
// The other property worth stating: the trust domain used for verification is
// ALWAYS this issuer's own configured value, never the one the device sent. The
// device's asserted name travels as a diagnostic, so a typo in an enroll command
// reads as "this device thinks we are called X and we are called Y" rather than
// as an unexplained signature failure.

// maxBodyBytes caps a request body. Enrollments are a few kilobytes of DER and
// signatures; a megabyte is generous and bounded.
const maxBodyBytes = 1 << 20

// ChallengeRequest mirrors cmd/totem's. See the drift note on EnrollRequest.
type ChallengeRequest struct {
	// DevicePublicDER is the device key's public half, PKIX DER.
	//
	// REQUIRED, and cmd/totem does not send it yet. The issuer mints the
	// enrollment challenge for presence.PreEnrollmentDeviceID(SPKI), so
	// accepting a bare fingerprint would mean minting challenges against an
	// identifier that is a string a caller chose rather than the hash of a real
	// P-256 key. It would also mean this package deriving the device id itself,
	// which is exactly the duplicate-derivation drift the agent's own comment
	// on PreEnrollmentDeviceID warns about. The agent already has these bytes
	// at this point in cmd/totem's enroll; sending them is a one-line change,
	// and it is called out in the handover.
	DevicePublicDER []byte `json:"device_public_der,omitempty"`
	// DeviceFingerprint is presence.PreEnrollmentDeviceID of DevicePublicDER.
	// It is cross-checked against the derived value, never trusted.
	DeviceFingerprint string `json:"device_fingerprint"`
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
}

// ChallengeResponse mirrors cmd/totem's.
type ChallengeResponse struct {
	Challenge []byte `json:"challenge"`
	ExpiresIn int    `json:"expires_in"`
}

// EnrollRequest is what the agent submits.
//
// DRIFT HAZARD, for the build lead. These field names and json tags are a
// hand-kept mirror of cmd/totem's EnrollRequest, because the agent's live in
// package main and cannot be imported. Nothing in the build fails if the two
// drift, and the failure that results is an enrollment whose canonical bytes
// differ by one field and therefore never verifies: the most expensive class of
// bug in this system, and the one internal/presence exists to make impossible
// WITHIN a process. The fix is to move these types to a shared package (an
// internal/wire, say) so agent and issuer encode from one definition. That
// touches cmd/totem, so it is proposed rather than done.
type EnrollRequest struct {
	DevicePublicDER   []byte                 `json:"device_public_der"`
	PresencePublicDER []byte                 `json:"presence_public_der,omitempty"`
	ProtectionLevel   spiffe.ProtectionLevel `json:"protection_level"`
	Hostname          string                 `json:"hostname"`
	OS                string                 `json:"os"`
	DeviceFingerprint string                 `json:"device_fingerprint"`
	// SignedTarget is the issuer NAME this device believes it is joining.
	// DIAGNOSTIC ONLY. It is never what an assertion is verified against; see
	// enrollmentTrustDomain below.
	SignedTarget      string                `json:"signed_target"`
	EncodingVersion   uint8                 `json:"encoding_version"`
	IssuerURL         string                `json:"issuer_url"`
	IssuerFingerprint string                `json:"issuer_fingerprint"`
	FirstContact      presence.FirstContact `json:"first_contact"`
	Challenge         []byte                `json:"challenge"`
	Signature         []byte                `json:"signature"`
	PresenceAssertion []byte                `json:"presence_assertion,omitempty"`
	BootstrapCode     string                `json:"bootstrap_code,omitempty"`
}

// EnrollResponse mirrors cmd/totem's.
type EnrollResponse struct {
	DeviceID     string `json:"device_id"`
	TrustDomain  string `json:"trust_domain"`
	Approved     bool   `json:"approved"`
	ApprovalCode string `json:"approval_code,omitempty"`
	ApprovalURL  string `json:"approval_url,omitempty"`
}

// handleEnrollChallenge mints the one challenge that will cover both
// signatures of one enrollment.
func (s *Server) handleEnrollChallenge(w http.ResponseWriter, r *http.Request) {
	if err := s.checkVersion(r); err != nil {
		s.refuse(w, r, "", err)
		return
	}
	var req ChallengeRequest
	if err := decode(r, &req); err != nil {
		s.refuse(w, r, "", err)
		return
	}
	deviceID, err := deviceIDFor(req.DevicePublicDER, req.DeviceFingerprint)
	if err != nil {
		s.refuse(w, r, req.DeviceFingerprint, err)
		return
	}
	challenge, err := s.cfg.Engine.EnrollmentChallenge(req.DevicePublicDER)
	if err != nil {
		s.refuse(w, r, deviceID, err)
		return
	}
	writeJSON(w, http.StatusOK, ChallengeResponse{
		Challenge: challenge,
		ExpiresIn: int(presence.DefaultChallengeTTL.Seconds()),
	})
}

// handleEnroll submits one enrollment to the policy engine.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if err := s.checkVersion(r); err != nil {
		s.refuse(w, r, "", err)
		return
	}
	var req EnrollRequest
	if err := decode(r, &req); err != nil {
		s.refuse(w, r, "", err)
		return
	}
	deviceID, err := deviceIDFor(req.DevicePublicDER, req.DeviceFingerprint)
	if err != nil {
		s.refuse(w, r, req.DeviceFingerprint, err)
		return
	}
	if err := s.checkAssertedTrustDomain(req.SignedTarget); err != nil {
		s.refuse(w, r, deviceID, err)
		return
	}
	in, err := EnrollmentInput(req)
	if err != nil {
		s.refuse(w, r, deviceID, err)
		return
	}

	// One call, one challenge, both signatures. Nothing above this line
	// verified anything, and nothing below it does either.
	result, err := s.cfg.Engine.Enroll(r.Context(), policy.EnrollRequest{
		Input:             in,
		Signature:         req.Signature,
		PresenceSignature: req.PresenceAssertion,
		BootstrapCode:     req.BootstrapCode,
		Name:              req.Hostname,
	}, s.cfg.Identity.Fingerprint)
	if err != nil {
		s.refuse(w, r, deviceID, err)
		return
	}

	// "Redemption logged with the device fingerprint." The code itself has no
	// field to travel in; the fingerprint says which device spent it, which is
	// what an incident needs.
	if req.BootstrapCode != "" {
		s.log(r, Event{
			Kind:    EventBootstrapRedeemed,
			Device:  result.DeviceID,
			Outcome: "redeemed",
		})
	}
	outcome := "pending"
	if result.Approved {
		outcome = "approved"
	}
	s.log(r, Event{
		Kind:     EventEnrollment,
		Device:   result.DeviceID,
		Target:   s.cfg.TrustDomain,
		Presence: result.Presence,
		Outcome:  outcome,
	})

	resp := EnrollResponse{
		DeviceID:    result.DeviceID,
		TrustDomain: s.cfg.TrustDomain,
		Approved:    result.Approved,
	}
	if !result.Approved {
		resp.ApprovalCode = result.Code
		resp.ApprovalURL = s.approvalURL(result.Code)
	}
	writeJSON(w, http.StatusOK, resp)
}

// EnrollmentInput maps the wire request onto the canonical enrollment input.
//
// It is exported so a conformance test can drive the real
// presence.Verifier.Enroll with exactly what this handler would have produced.
// The mapping mirrors cmd/totem's enrollmentInput field for field, and the
// three fields worth stating are the ones where a wrong mapping is silent:
//
//   - The device id is DERIVED from DevicePublicKey by internal/presence, not
//     taken from DeviceFingerprint. A device does not choose its own identifier.
//   - FirstContact is normalised to the WEAKER path unless it is exactly
//     "fragment". A field that names the weaker path is exactly the field an
//     attacker rewrites, so an unset or unrecognised value must never be signed
//     or recorded as the strong one.
//   - BootstrapCodeHash, never the code. It is salted with this challenge, so a
//     hash from one enrollment gives no dictionary against a still-valid code.
func EnrollmentInput(req EnrollRequest) (presence.EnrollmentInput, error) {
	if req.EncodingVersion != presence.EncodingVersion {
		return presence.EnrollmentInput{}, badRequest(
			"Upgrade totem, or ask your issuer operator to upgrade the issuer.",
			"this device signed its enrollment in format %d and the issuer speaks format %d.",
			req.EncodingVersion, presence.EncodingVersion)
	}
	fp, err := hex.DecodeString(strings.TrimSpace(req.IssuerFingerprint))
	if err != nil || len(fp) != sha256.Size {
		return presence.EnrollmentInput{}, badRequest(
			"Run 'totem enroll' again with the command your issuer operator gave you.",
			"this device did not say which issuer certificate it pinned.")
	}
	in := presence.EnrollmentInput{
		Version:           presence.EncodingVersion,
		Challenge:         req.Challenge,
		IssuerFingerprint: fp,
		DevicePublicKey:   req.DevicePublicDER,
		PresencePublicKey: req.PresencePublicDER,
		ProtectionLevel:   req.ProtectionLevel,
		Hostname:          req.Hostname,
		OS:                req.OS,
		FirstContact:      firstContactOrWeakest(req.FirstContact),
	}
	if req.BootstrapCode != "" {
		in.BootstrapCodeHash = presence.BootstrapCodeHash(req.Challenge, req.BootstrapCode)
	}
	return in, nil
}

// firstContactOrWeakest reads a first-contact value the way it must always be
// read: only the exact fragment value is the strong path, and the zero value,
// the prompt path, and anything unrecognised are all the weak one.
func firstContactOrWeakest(f presence.FirstContact) presence.FirstContact {
	if f.Verified() {
		return presence.FirstContactFragment
	}
	return presence.FirstContactPrompt
}

// checkAssertedTrustDomain compares the name the device says it is joining
// against this issuer's own, purely to produce a better message.
//
// It is NOT a security check and must never be read as one. Verification uses
// the issuer's own trust domain, passed down to presence.Verifier.Enroll, and
// a device that matched here would gain nothing by it. What this buys is the
// difference between "signature did not verify", which sends an operator
// looking at key material, and "this device thinks we are called X and we are
// called Y", which is a typo in an enroll command and a thirty-second fix.
// Without it the mismatch surfaces as presence.ErrBadSignature, because the
// name is under the signature and the issuer reconstructs the signed bytes
// with its own value.
func (s *Server) checkAssertedTrustDomain(asserted string) error {
	if asserted == "" || asserted == s.cfg.TrustDomain {
		return nil
	}
	return badRequest(
		fmt.Sprintf("Enroll again with --trust-domain %s, or ask your issuer operator which name is right.", s.cfg.TrustDomain),
		"this device is trying to join an issuer called %q, and this issuer is called %q.",
		asserted, s.cfg.TrustDomain)
}

// deviceIDFor derives the pre-enrollment device id from the public key and
// cross-checks the fingerprint the device reported. The derived value wins; the
// reported one exists only so a mismatch is a clear message rather than a
// signature failure fifty lines later.
func deviceIDFor(spki []byte, reported string) (string, error) {
	if len(spki) == 0 {
		return "", badRequest(
			"Upgrade totem on that device. This issuer needs a version that sends its key with the request.",
			"this device did not send its key, so the issuer cannot tell which device is asking.")
	}
	derived := presence.PreEnrollmentDeviceID(spki)
	if reported != "" && !strings.EqualFold(reported, derived) {
		return "", badRequest(
			"Run 'totem enroll' again on that device.",
			"this device's key and the identifier it sent do not match.")
	}
	return derived, nil
}

// approvalURL is the browser approval link, or empty for an IP-only issuer.
// docs/totem-design.md: WebAuthn cannot use an IP, so an IP-only issuer gets
// the headless path only, and offering a link that cannot work is worse than
// offering none.
func (s *Server) approvalURL(code string) string {
	if code == "" || s.cfg.ExternalURL == "" || IsIPOnly(s.cfg.ExternalURL) {
		return ""
	}
	return strings.TrimSuffix(s.cfg.ExternalURL, "/") + "/approve/" + code
}

// decode reads a JSON body under the size cap.
func decode(r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return badRequest(
			"Ask your issuer operator whether the issuer is running a version totem understands.",
			"the issuer could not read that request.")
	}
	return nil
}

// writeJSON writes a success body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// refuse logs a turned-away request and writes the error. Every refusal is on
// the audit line: "Refusals are never silent."
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, device string, err error) {
	e := classify(err)
	s.log(r, Event{
		Kind:    EventRefused,
		Device:  device,
		Target:  r.URL.Path,
		Outcome: "refused",
		Reason:  string(e.reason),
	})
	writeError(w, r, e)
}

// log writes one audit line, carrying the agent version the caller reported.
func (s *Server) log(r *http.Request, e Event) {
	if e.AgentVersion == "" && r != nil {
		e.AgentVersion = AgentVersion(r)
	}
	_, _ = s.cfg.Audit.Log(e)
}
