package server

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The three rules in this package's doc comment are enforced here, over the
// package's own source, because each of them is a property of what the code
// does NOT contain. A comment saying "never verify a signature here" is a
// comment; a test that fails when someone adds one is a control.
//
// These are cheap and blunt on purpose. They will occasionally need updating
// when the package legitimately grows, and that is the point: the update is a
// deliberate edit to a test that states why the rule exists, made by someone
// who has to read the reason before changing it.

// packageFiles returns every non-test .go file in this package, by name, with
// line comments stripped. Doc comments here quote the rules by name, so
// counting them would make every rule look violated by its own explanation.
func packageFiles(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = commentLine.ReplaceAllString(string(data), "")
	}
	if len(out) == 0 {
		t.Fatal("no source found; these tests must run in the package directory")
	}
	return out
}

// packageSource is every non-test file concatenated, comments stripped.
func packageSource(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, src := range packageFiles(t) {
		b.WriteString(src)
		b.WriteByte('\n')
	}
	return b.String()
}

// filesContaining lists the files in which needle appears.
func filesContaining(t *testing.T, needle string) []string {
	t.Helper()
	var out []string
	for name, src := range packageFiles(t) {
		if strings.Contains(src, needle) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

var commentLine = regexp.MustCompile(`(?m)^\s*//.*$`)

// countOutsideComments counts occurrences of needle in code, ignoring line
// comments. Doc comments in this package quote the rules by name, so counting
// them would make every rule look violated by its own explanation.
func countOutsideComments(src, needle string) int {
	return strings.Count(src, needle)
}

// TestServerNeverVerifiesSignatures. Enrollment carries two signatures over one
// challenge, and presence.Verifier.Enroll is the only thing allowed to check
// them, because it is the only thing that spends that challenge once for both.
// A second verification path anywhere in the process spends it on the first
// signature and turns the honest second one into a replay: a defect that passes
// against a fake and fails against the first real Secure Enclave.
func TestServerNeverVerifiesSignatures(t *testing.T) {
	t.Parallel()
	src := packageSource(t)
	for _, forbidden := range []string{
		"ecdsa.Verify",
		"ecdsa.VerifyASN1",
		".Verify(",
		"presence.VerifyEnrollment",
		"Verifier.Enroll",
		"presence.NewVerifier",
	} {
		if n := countOutsideComments(src, forbidden); n != 0 {
			t.Errorf("internal/server contains %q (%d times). This package verifies nothing: "+
				"one challenge covers both enrollment signatures and only presence.Verifier.Enroll, "+
				"called from internal/policy, may spend it.", forbidden, n)
		}
	}
}

// TestAttestPeerCalledExactlyOnce. presentedGrantID must come from the attested
// credential's provenance and never from a request body. policy.Attested has no
// exported fields and exactly one constructor; keeping that constructor to a
// single call site is what makes "the caller cannot supply the shape" a
// property of the code rather than a habit.
func TestAttestPeerCalledExactlyOnce(t *testing.T) {
	t.Parallel()
	src := packageSource(t)
	if n := countOutsideComments(src, "policy.AttestPeer("); n != 1 {
		t.Fatalf("policy.AttestPeer is called %d times; it must be called exactly once, in attest(), "+
			"so every caller identity in this package comes from the TLS layer's own verification result", n)
	}
	// The peer's verified chain is read only where attest() lives. Reading it
	// anywhere else is a second, unaudited way to decide who is calling.
	if got := filesContaining(t, "VerifiedChains"); len(got) != 1 || got[0] != "server.go" {
		t.Fatalf("the peer's verified chain is read in %v; it must be read only in server.go, inside attest()", got)
	}
}

// TestRequestBodiesCarryNoIdentity. The structural half of the same rule: a
// request type with a grant, device, or presence field is a request body that
// can claim one, and presence.Registry.Open refusing the wrong SHAPE is
// worthless against a caller that can supply the shape. An agent narrowed to
// nothing would otherwise name its own root grant and walk around monotonic
// narrowing without presence.
func TestRequestBodiesCarryNoIdentity(t *testing.T) {
	t.Parallel()
	// Every type this package decodes a request body into.
	bodies := []any{
		ChallengeRequest{},
		EnrollRequest{},
		SignedRequest{},
		PrepareRequest{},
	}
	forbidden := []string{"grant", "provenance", "lineage", "sponsor", "admin", "presencestate"}
	for _, body := range bodies {
		tp := reflect.TypeOf(body)
		for i := 0; i < tp.NumField(); i++ {
			name := strings.ToLower(tp.Field(i).Name)
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Errorf("%s has field %s: a request body must never be able to claim identity, "+
						"a grant, or a presence state. Those come from the attested credential.",
						tp.Name(), tp.Field(i).Name)
				}
			}
		}
	}
	// SignedRequest carries an Assertion whose DeviceID is the one identity-ish
	// field on any body. It exists so a mismatch with the attested device is a
	// clear refusal, and signed() overwrites it with the attested value before
	// it reaches the engine. Assert that overwrite is still there.
	if n := countOutsideComments(packageSource(t), "sig.Assertion.DeviceID = a.ID().DeviceID"); n != 1 {
		t.Error("signed() must overwrite the assertion's device id with the attested one, so a body cannot name its own signer")
	}
}

// TestNoTrustDomainIsReadFromARequest. The trust domain an enrollment is
// verified against is always the issuer's own configured value. A device that
// could pick the name it is checked against defeats the whole binding.
func TestNoTrustDomainIsReadFromARequest(t *testing.T) {
	t.Parallel()
	src := packageSource(t)
	// SignedTarget is the device's asserted name. It may be COMPARED (for the
	// diagnostic) and must never be assigned into anything the engine verifies
	// against.
	for _, forbidden := range []string{
		"TrustDomain: req.SignedTarget",
		"TrustDomain = req.SignedTarget",
		"trustDomain: req.SignedTarget",
	} {
		if countOutsideComments(src, forbidden) != 0 {
			t.Errorf("the issuer's trust domain was taken from a request (%q)", forbidden)
		}
	}
	if countOutsideComments(src, "s.cfg.TrustDomain") == 0 {
		t.Error("the configured trust domain is never used; something is reading the name from somewhere else")
	}
}
