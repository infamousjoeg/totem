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

// rawPackageSource is every non-test file concatenated, comments INTACT. It is
// for the rules whose subject is what a comment says.
func rawPackageSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
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
	// SignedRequest carries an Assertion, which IS the verifier's input:
	// presence re-encodes it and hashes the result, so anything left in it from
	// a request body is a caller-chosen string inside the bytes a signature is
	// checked over. Every field the issuer can derive for itself must be
	// overwritten before it reaches the engine, and these are the three.
	src := packageSource(t)
	for _, overwrite := range []string{
		"assertion.DeviceID = a.ID().DeviceID",
		"assertion.Tool = policy.SigningTool",
		"assertion.Target = policy.Target(action, req.Subject)",
	} {
		if n := countOutsideComments(src, overwrite); n != 1 {
			t.Errorf("signed() must set %q exactly once. A field the issuer knows and takes from the body "+
				"instead is a device-supplied value in the verifier's input, safe only for as long as some "+
				"other check keeps disagreeing with it.", overwrite)
		}
	}
}

// TestNoTrustDomainIsReadFromARequest. The trust domain an enrollment is
// verified against is ALWAYS this issuer's own configured value. A device that
// could pick the name it is checked against defeats the whole binding.
//
// The device's asserted name does travel to the policy engine, because a
// mismatch is only legible if the engine can see what the device claimed. The
// rule that keeps that safe is naming: it may be assigned ONLY to a field whose
// name says it is asserted, never to a bare TrustDomain, so a reader skimming a
// use site knows which one is authoritative without consulting a comment. That
// is the build lead's constraint on how the field landed, and this is what
// enforces it.
func TestNoTrustDomainIsReadFromARequest(t *testing.T) {
	t.Parallel()
	src := packageSource(t)

	// A bare TrustDomain field taking the device's value, in any struct. The
	// leading class stops this matching AssertedTrustDomain, which is the one
	// spelling that is allowed.
	bare := regexp.MustCompile(`(^|[^A-Za-z])TrustDomain\s*[:=]\s*req\.SignedTarget`)
	if loc := bare.FindString(src); loc != "" {
		t.Errorf("the issuer's trust domain was taken from a request (%q). Verification uses the configured "+
			"value; a device's asserted name may only be carried in a field that says it is asserted.", strings.TrimSpace(loc))
	}

	// Every use of the device's asserted name must land in an Asserted* field.
	uses := regexp.MustCompile(`([A-Za-z]*)\s*:\s*req\.SignedTarget`).FindAllStringSubmatch(src, -1)
	for _, u := range uses {
		if !strings.HasPrefix(u[1], "Asserted") {
			t.Errorf("req.SignedTarget is assigned to %q; it may only be carried in a field whose name says "+
				"it is asserted, so no use site can be misread as authoritative", u[1])
		}
	}

	if countOutsideComments(src, "s.cfg.TrustDomain") == 0 {
		t.Error("the configured trust domain is never used; something is reading the name from somewhere else")
	}
}

// TestTheAssertedNameIsNeverComparedHere. The detection of a name mismatch
// lives in internal/policy, where the comparison against the configured value
// already happens. This package renders the result and does not repeat the
// check: two places stating the same rule, only one of which anyone watches, is
// the shape this build has repeatedly found to be a defect.
func TestTheAssertedNameIsNeverComparedHere(t *testing.T) {
	t.Parallel()
	src := packageSource(t)
	compare := regexp.MustCompile(`req\.SignedTarget\s*(==|!=)|(==|!=)\s*req\.SignedTarget`)
	if loc := compare.FindString(src); loc != "" {
		t.Errorf("the asserted name is compared in this package (%q). internal/policy detects the mismatch; "+
			"this package only renders it.", strings.TrimSpace(loc))
	}
}

// TestChainHeadIsStatedAndNeverChecked guards an instruction that is easy to
// mistake for an omission.
//
// The head line detects an operator error or a clumsy rollback. It does not
// close the truncation hole, because an attacker who holds the host holds the
// log emitter and can decline to emit or emit a lie. The obvious "improvement"
// is to record the head locally and refuse to start when it goes backwards.
// That must not be built: a witness the host writes for itself is not a
// witness, since the same host that truncated the chain can rewrite the file
// recording where it used to end. It would produce exactly the false
// confidence the honest line is written to avoid, and it would look like a
// closed property to the next reader.
//
// So this asserts the absence: no comparison, no stored previous head, no
// refusal. The real fix is the fleet witness in the versioned agent protocol.
func TestChainHeadIsStatedAndNeverChecked(t *testing.T) {
	t.Parallel()
	src := packageFiles(t)["chainhead.go"]
	if src == "" {
		t.Fatal("chainhead.go is gone; the head line is what puts a value the host cannot retract off the box")
	}

	for _, forbidden := range []struct{ pattern, why string }{
		{"os.ReadFile", "reading a previously recorded head from local disk"},
		{"os.WriteFile", "recording the head locally as a witness against itself"},
		{"store.Store.Get", "stashing the head in the same store it describes"},
		{".Get(", "stashing the head in the same store it describes"},
		{".Put(", "recording the head locally as a witness against itself"},
	} {
		if strings.Contains(src, forbidden.pattern) {
			t.Errorf("chainhead.go contains %q (%s). A witness the host writes for itself is not a witness: "+
				"the host that truncated the chain can rewrite the record of where it ended.",
				forbidden.pattern, forbidden.why)
		}
	}
	// No comparison of one head against another, and no refusal built on one.
	compare := regexp.MustCompile(`(seq|hash)\s*(==|!=|<|>)\s*\w|\w\s*(==|!=|<|>)\s*(seq|hash)\b`)
	if loc := compare.FindString(src); loc != "" {
		t.Errorf("chainhead.go compares a head against something (%q). It states the value and lets it leave "+
			"the box; deciding anything from it locally is the false confidence this avoids.", strings.TrimSpace(loc))
	}
	// And the comment has to say what it is NOT, or a future reader finds this
	// line and concludes the property is covered. Read RAW here: packageFiles
	// strips comments, which is right for every other rule in this file and
	// exactly wrong for one whose subject is the comment.
	whole := rawPackageSource(t)
	for _, required := range []string{"does NOT close", "fleet"} {
		if !strings.Contains(whole, required) {
			t.Errorf("the audit comment no longer says %q. The limits of this line are the reason it is safe "+
				"to have; a reader who takes it for a lock is worse off than one who has nothing.", required)
		}
	}
}
