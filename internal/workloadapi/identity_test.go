package workloadapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/attest"
)

func TestDeriveToolID(t *testing.T) {
	d, err := DeriveTool("issuer.example", "abc123", "claude")
	if err != nil {
		t.Fatalf("DeriveTool: %v", err)
	}
	want := "spiffe://issuer.example/device/abc123/tool/claude"
	if d.String() != want {
		t.Errorf("got %q, want %q", d.String(), want)
	}
	if d.IsAgent() {
		t.Error("a tool identity must not report itself as an agent")
	}
	if d.Model.Tool != "claude" || d.Model.Agent != "" {
		t.Errorf("model = %+v, want Tool set and Agent empty", d.Model)
	}
}

func TestDeriveAgentID(t *testing.T) {
	d, err := DeriveAgent("issuer.example", "abc123", "cassidy")
	if err != nil {
		t.Fatalf("DeriveAgent: %v", err)
	}
	want := "spiffe://issuer.example/device/abc123/agent/cassidy"
	if d.String() != want {
		t.Errorf("got %q, want %q", d.String(), want)
	}
	if !d.IsAgent() {
		t.Error("an agent identity must report itself as one")
	}
}

// TestProtectionLevelNeverReachesThePath is the spec rule stated as a test:
// protection level and presence facts travel as X.509 extensions and JWT
// claims, never as path segments.
func TestProtectionLevelNeverReachesThePath(t *testing.T) {
	d, err := DeriveTool("issuer.example", "abc123", "claude")
	if err != nil {
		t.Fatal(err)
	}
	path := d.ID.Path()
	if segs := strings.Split(strings.TrimPrefix(path, "/"), "/"); len(segs) != 4 {
		t.Fatalf("path %q has %d segments, want exactly device/<id>/tool/<name>", path, len(segs))
	}
	for _, forbidden := range []string{"hardware", "keyring", "software", "presence", "present", "delegated", "none"} {
		if strings.Contains(path, forbidden) {
			t.Errorf("path %q leaks %q; protection and presence facts ride as extensions and claims", path, forbidden)
		}
	}
}

func TestDeriveRequiresEnrollment(t *testing.T) {
	if _, err := DeriveTool("", "abc", "claude"); !errors.Is(err, ErrNoTrustDomain) {
		t.Errorf("missing trust domain: got %v, want ErrNoTrustDomain", err)
	}
	if _, err := DeriveTool("issuer.example", "", "claude"); !errors.Is(err, ErrNoDeviceID) {
		t.Errorf("missing device id: got %v, want ErrNoDeviceID", err)
	}
	if _, err := DeriveTool("issuer.example", "abc", ""); err == nil {
		t.Error("an empty tool name must not derive an identity")
	}
}

func TestDeriveRejectsUnusableTrustDomain(t *testing.T) {
	for _, td := range []string{"Issuer.Example ", "spiffe://a/b", "!!"} {
		if _, err := DeriveTool(td, "abc", "claude"); err == nil {
			t.Errorf("trust domain %q was accepted", td)
		}
	}
}

// TestDeriveAgentFromDedicatedUID is the delegation rule: an agent harness runs
// under a dedicated OS user, so the uid alone decides agent versus tool. No new
// mechanism, and interactive tools under the human's own uid are unaffected.
func TestDeriveAgentFromDedicatedUID(t *testing.T) {
	cfg := IdentityConfig{
		TrustDomain: "issuer.example",
		DeviceID:    "abc123",
		AgentUsers:  map[uint32]string{4711: "cassidy"},
	}
	ident := toolIdentity(t)

	got, err := Derive(cfg, ident)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "spiffe://issuer.example/device/abc123/tool/claude" {
		t.Errorf("a tool under the human's own uid became %q", got)
	}

	ident.Peer.UID = 4711
	got, err = Derive(cfg, ident)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "spiffe://issuer.example/device/abc123/agent/cassidy" {
		t.Errorf("a caller under the agent uid became %q", got)
	}
}

func TestDeriveRefusesUnattestedCaller(t *testing.T) {
	var nilIdent *attest.Identity
	if _, err := Derive(IdentityConfig{TrustDomain: "issuer.example", DeviceID: "a"}, nilIdent); err == nil {
		t.Error("derivation from a caller that did not attest must fail")
	}
}
