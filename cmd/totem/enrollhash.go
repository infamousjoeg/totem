package main

import "github.com/infamousjoeg/totem/internal/presence"

// enrollmentRequestHash binds every claim an enrollment makes into one value,
// which then rides under the signature as the assertion's request hash and is
// what the human-visible request code is derived from.
//
// Why bind all of it rather than just the challenge. A signature over the
// challenge alone proves only that somebody holding the key was present at
// this moment. It says nothing about WHAT they were agreeing to, so every
// other field in the request is plaintext an active attacker can rewrite while
// the signature still verifies. The fields that matter most are the ones the
// issuer cannot check for itself:
//
//   - ProtectionLevel, because Apple has no third-party key attestation, so a
//     Secure Enclave enrollment is trust-on-first-use and the issuer has no
//     way to tell "hardware" from a rewritten "software". Unbound, it is a
//     lie the issuer would record permanently.
//   - PresencePublicDER, because an enrollment that quietly lost its presence
//     half would verify every future assertion against the wrong key and look
//     healthy doing it. The presence STATE is not a separate field: the key is
//     the state, so the two can never disagree.
//   - FirstContact, because it names the weaker path, and a field that names
//     the weaker path is precisely the field worth rewriting to hide that it
//     was taken.
//   - IssuerFingerprint, because binding what the device pinned lets the
//     issuer refuse an enrollment made against somebody else's certificate,
//     turning a machine-in-the-middle from undetectable into refusable.
//   - BootstrapCode, because redeeming it makes the device the founding ADMIN.
//     Unbound, an attacker who sees one ordinary enrollment can staple a
//     stolen code onto it and promote somebody else's device to admin, with a
//     signature that still verifies because it never covered the code.
//
// Hostname and OS are in because the approval screen shows them: binding them
// makes "what the approver saw" the same thing as "what the device asserted".
//
// The order is fixed and both sides must use it. presence.HashRequest
// length-prefixes and domain-separates every part, so no field boundary can be
// shifted: ("ab","c") and ("a","bc") hash differently, and an empty field is
// distinct from an absent one.
//
// presence.EnrollmentInput is now the canonical encoder for all of this, with
// its own "totem/enrollment" context. enrollmentInput below builds it from a
// request, and it is the only place the mapping lives so the agent and the
// issuer cannot drift.
func enrollmentInput(req EnrollRequest) presence.EnrollmentInput {
	in := presence.EnrollmentInput{
		Version:           presence.EncodingVersion,
		Challenge:         req.Challenge,
		IssuerFingerprint: req.IssuerFingerprintBytes(),
		DevicePublicKey:   req.DevicePublicDER,
		PresencePublicKey: req.PresencePublicDER,
		ProtectionLevel:   req.ProtectionLevel,
		Hostname:          req.Hostname,
		OS:                req.OS,
		// OrWeakest, not a bare cast: an unset value must never be signed as
		// the strong path. presence would refuse an empty value outright, but
		// relying on that would make the safe outcome an accident of the other
		// package's validation rather than a decision made here.
		FirstContact: presence.FirstContact(req.FirstContact.OrWeakest()),
	}
	if req.BootstrapCode != "" {
		// The code itself is never bound, only a hash of it bound to this
		// challenge, so a structure that may end up in a log never carries the
		// value that makes a device the founding admin.
		in.BootstrapCodeHash = presence.BootstrapCodeHash(req.Challenge, req.BootstrapCode)
	}
	return in
}
