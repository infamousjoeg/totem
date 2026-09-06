package ca

import (
	"encoding/asn1"
	"testing"
)

// placeholderPEN is the private-enterprise number the OID arc uses while totem
// has no registered IANA assignment.
const placeholderPEN = 62733

// TestOIDArcAndItsReleaseGateStayInSync is the ordinary-CI half of the arc
// guard. release_gate.go stops a PLACEHOLDER arc from shipping; this stops the
// two halves from disagreeing, in a normal `go test`, long before anyone
// attempts a release build.
//
// Both directions are mistakes, and both are the same mistake made in one
// commit instead of two:
//
//   - a real PEN recorded but the arc left on the placeholder means the gate
//     opens and the placeholder ships, which is the exact outcome the gate
//     exists to prevent;
//   - the arc changed to a real PEN but the marker left set means the gate
//     stays shut forever and nobody can cut a release.
//
// Registering the PEN and clearing the marker belong in one commit. This test
// is what says so out loud.
func TestOIDArcAndItsReleaseGateStayInSync(t *testing.T) {
	t.Parallel()
	onPlaceholder := OIDProtectionLevel[6] == placeholderPEN
	switch {
	case OIDArcProvisional != "" && !onPlaceholder:
		t.Fatalf("the OID arc has moved off the placeholder PEN but OIDArcProvisional is still set to %q; clear it in the same commit or no release can ever build", OIDArcProvisional)
	case OIDArcProvisional == "" && onPlaceholder:
		t.Fatalf("OIDArcProvisional has been cleared while the arc is still placeholder PEN %d; that opens the release gate on a placeholder, which is what the gate exists to stop", placeholderPEN)
	}
}

// TestOIDArcIsOneCoherentBlock: the four identity extensions must live under a
// single arc and must not collide. They are the only place a relying-party
// trust policy can match on protection level, presence or grant, so a duplicate
// would silently make one fact unreadable and a stray arc would make a fact
// unfindable.
func TestOIDArcIsOneCoherentBlock(t *testing.T) {
	t.Parallel()
	all := map[string]asn1.ObjectIdentifier{
		"OIDProtectionLevel": OIDProtectionLevel,
		"OIDPresenceState":   OIDPresenceState,
		"OIDPresenceAge":     OIDPresenceAge,
		"OIDGrantID":         OIDGrantID,
	}
	arc := OIDProtectionLevel[:7]
	seen := map[string]string{}
	for name, oid := range all {
		if len(oid) != 9 {
			t.Fatalf("%s is %s; every totem extension OID is <arc>.1.<n>", name, oid)
		}
		if !oid[:7].Equal(arc) {
			t.Fatalf("%s sits under %s, not the shared arc %s; one edit must move all four", name, oid[:7], arc)
		}
		if prev, dup := seen[oid.String()]; dup {
			t.Fatalf("%s and %s are both %s; one of these facts would be unreadable", prev, name, oid)
		}
		seen[oid.String()] = name
	}
	if len(seen) != len(all) {
		t.Fatalf("want %d distinct extension OIDs, got %d", len(all), len(seen))
	}
}
