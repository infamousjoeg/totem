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
//   - Presence and PresencePublicDER, because an enrollment that quietly lost
//     its presence half would verify every future assertion against the wrong
//     key and look healthy doing it.
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
// This is the interim shape. presence is adding an EnrollmentInput type with
// its own "totem/enrollment" context, and when it lands this whole function is
// replaced by it; the field set here is what that type was specified from.
func enrollmentRequestHash(req EnrollRequest) []byte {
	return presence.HashRequest(
		req.DevicePublicDER,
		req.PresencePublicDER,
		[]byte(req.ProtectionLevel),
		[]byte(req.Presence),
		[]byte(req.Hostname),
		[]byte(req.OS),
		[]byte(req.IssuerURL),
		[]byte(req.IssuerFingerprint),
		[]byte(req.FirstContact),
		[]byte(req.BootstrapCode),
	)
}
