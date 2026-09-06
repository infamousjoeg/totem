package ca

import (
	"crypto/x509"
	"sort"
	"time"
)

// The rotation schedule is DERIVED from the intermediate certificates
// themselves, not stored beside them. Every boundary falls out of NotBefore and
// NotAfter:
//
//	SigningEnd   = NotAfter  - IntermediateRetirementTail
//	SigningStart = max(NotBefore, SigningEnd - IntermediateSigningPeriod)
//
// so a timeline looks like:
//
//	NotBefore ......... SigningStart ......... SigningEnd ......... NotAfter
//	|<-- publication -->|<--  30d signing  -->|<-- retirement  -->|
//	|      overlap      |                     |       tail        |
//	   published,            the ONE cert         still trusted,
//	   not signing           that signs           no longer signing
//
// Deriving rather than storing is deliberate. A separate schedule file can
// disagree with the certificates, and when it does the issuer signs with a key
// whose certificate says something else, which is the failure that is hardest
// to see from the outside. Here the certificate IS the schedule, so a relying
// party validating dates and the issuer choosing a signer are reading the same
// source.
//
// The first intermediate, created at issuer init, has no publication overlap:
// it must sign immediately. The max() in SigningStart handles that without a
// special case, because its NotBefore equals its SigningStart.

// signingEnd is when an intermediate stops signing.
func signingEnd(c *x509.Certificate) time.Time {
	return c.NotAfter.Add(-IntermediateRetirementTail)
}

// signingStart is when an intermediate starts signing.
func signingStart(c *x509.Certificate) time.Time {
	s := signingEnd(c).Add(-IntermediateSigningPeriod)
	if c.NotBefore.After(s) {
		return c.NotBefore
	}
	return s
}

// roleAt reports an intermediate's role at t, and whether it belongs in the
// bundle at all. An intermediate outside [NotBefore, NotAfter) is not in the
// bundle: before, it does not exist yet as far as relying parties go; after, it
// cannot help verify anything.
func roleAt(c *x509.Certificate, t time.Time) (IntermediateRole, bool) {
	if t.Before(c.NotBefore) || !t.Before(c.NotAfter) {
		return "", false
	}
	switch {
	case t.Before(signingStart(c)):
		return RoleNext, true
	case t.Before(signingEnd(c)):
		return RoleCurrent, true
	default:
		return RoleRetiring, true
	}
}

// intermediateWindow builds the certificate validity window for an
// intermediate that starts signing at start.
func intermediateWindow(start time.Time) (notBefore, notAfter time.Time) {
	return start.Add(-IntermediatePublicationOverlap), start.Add(IntermediateSigningPeriod + IntermediateRetirementTail)
}

// firstIntermediateWindow is the window for the intermediate created at issuer
// init, which signs from the moment it exists. It carries no publication
// overlap because there are no relying parties yet to have fetched a bundle
// without it: the overlap protects an existing fleet, and at init there is not
// one.
func firstIntermediateWindow(now time.Time) (notBefore, notAfter time.Time) {
	return now, now.Add(IntermediateSigningPeriod + IntermediateRetirementTail)
}

// buildSchedule evaluates the whole timeline at t. certs may be in any order.
func buildSchedule(certs []*x509.Certificate, t time.Time) *Schedule {
	sorted := append([]*x509.Certificate(nil), certs...)
	sort.Slice(sorted, func(i, j int) bool { return signingStart(sorted[i]).Before(signingStart(sorted[j])) })

	s := &Schedule{At: t}
	for _, c := range sorted {
		role, live := roleAt(c, t)
		if !live {
			continue
		}
		in := Intermediate{Certificate: c, Role: role, SigningStart: signingStart(c), SigningEnd: signingEnd(c)}
		switch role {
		case RoleCurrent:
			cp := in
			s.Current = &cp
		case RoleNext:
			cp := in
			s.Next = &cp
		case RoleRetiring:
			s.Retiring = append(s.Retiring, in)
		}
	}
	if s.Current != nil {
		s.RotateBefore = s.Current.SigningEnd
		s.RotateAfter = s.Current.SigningEnd.Add(-IntermediatePublicationOverlap)
	}
	return s
}

// liveIntermediates returns every intermediate in the bundle at t, in signing
// order, tagged with its role.
func liveIntermediates(certs []*x509.Certificate, t time.Time) []Intermediate {
	sorted := append([]*x509.Certificate(nil), certs...)
	sort.Slice(sorted, func(i, j int) bool { return signingStart(sorted[i]).Before(signingStart(sorted[j])) })

	out := make([]Intermediate, 0, len(sorted))
	for _, c := range sorted {
		role, live := roleAt(c, t)
		if !live {
			continue
		}
		out = append(out, Intermediate{Certificate: c, Role: role, SigningStart: signingStart(c), SigningEnd: signingEnd(c)})
	}
	return out
}
