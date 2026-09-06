package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/summon"
)

// TestInitProducesTheSpecifiedHierarchy checks the shape of what `issuer init`
// leaves behind: a P-384 self-signed root that can have exactly one CA below
// it, and a P-384 intermediate that can have none.
func TestInitProducesTheSpecifiedHierarchy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Roots) != 1 {
		t.Fatalf("want exactly one root, got %d", len(bundle.Roots))
	}
	root := bundle.Roots[0]
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the root must be self-signed: %v", err)
	}
	if !root.IsCA || root.MaxPathLen != 1 {
		t.Fatalf("root IsCA=%v MaxPathLen=%d, want true/1 so exactly one intermediate tier can exist", root.IsCA, root.MaxPathLen)
	}
	if root.KeyUsage&x509.KeyUsageCRLSign == 0 || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("root must carry certSign and cRLSign")
	}
	assertP384(t, "root", root.PublicKey)

	if len(bundle.Intermediates) != 1 {
		t.Fatalf("want exactly one intermediate at init, got %d", len(bundle.Intermediates))
	}
	inter := bundle.Intermediates[0].Certificate
	if err := inter.CheckSignatureFrom(root); err != nil {
		t.Fatalf("the intermediate must be signed by the root: %v", err)
	}
	if !inter.IsCA || inter.MaxPathLen != 0 || !inter.MaxPathLenZero {
		t.Fatal("the intermediate must be a CA that cannot have another CA below it")
	}
	assertP384(t, "intermediate", inter.PublicKey)
	if inter.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Fatalf("intermediate signed with %s, want ECDSAWithSHA384 to match the P-384 CA key", inter.SignatureAlgorithm)
	}
}

func assertP384(t *testing.T, what string, pub any) {
	t.Helper()
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("%s key is %T, want *ecdsa.PublicKey", what, pub)
	}
	if ec.Curve != elliptic.P384() {
		t.Fatalf("%s key is on %s, want P-384", what, ec.Curve.Params().Name)
	}
}

// TestInitRefusesToOverwriteALiveRoot: regenerating a root over a live one
// invalidates every enrolled device silently.
func TestInitRefusesToOverwriteALiveRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	_, err := Init(ctx, InitParams{Config: Config{
		Dir: ca.dir, Resolver: ca.res, PassphraseRef: "ca_passphrase",
		TrustDomain: testTrustDomain, Now: ca.clk.now,
	}})
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("re-running init: got %v, want ErrAlreadyInitialized", err)
	}
}

func TestOpenBeforeInit(t *testing.T) {
	t.Parallel()
	_, err := Open(context.Background(), Config{
		Dir: t.TempDir(), Resolver: &fakeResolver{pass: "x", rotation: summon.RotationSealsDataAtRest}, PassphraseRef: "ca_passphrase",
		TrustDomain: testTrustDomain,
	})
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("opening an empty directory: got %v, want ErrNotInitialized", err)
	}
}

// TestPassphraseHasNoPathButSummon pins the frozen contract's rule: "there is
// no plaintext path, no key flag, no environment variable the issuer reads
// directly, and no dev mode".
func TestPassphraseHasNoPathButSummon(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	if _, err := Open(ctx, Config{Dir: t.TempDir(), PassphraseRef: "ca_passphrase", TrustDomain: testTrustDomain}); err == nil ||
		!strings.Contains(err.Error(), "Resolver") {
		t.Fatalf("a CA with no resolver must refuse to open, got %v", err)
	}
	if _, err := Open(ctx, Config{Dir: t.TempDir(), Resolver: &fakeResolver{}, TrustDomain: testTrustDomain}); err == nil ||
		!strings.Contains(err.Error(), "PassphraseRef") {
		t.Fatalf("a CA with no passphrase reference must refuse to open, got %v", err)
	}

	ca := newTestCA(t)
	if ca.res.callCount() == 0 {
		t.Fatal("init must have resolved the passphrase through the resolver")
	}

	// A provider that has stopped answering makes rotation fail loudly rather
	// than fall back to anything.
	before := ca.res.callCount()
	ca.res.mu.Lock()
	ca.res.err = summon.ErrProviderUntrusted
	ca.res.mu.Unlock()
	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.RotateAfter.Add(time.Hour))
	if _, err := ca.RotateIntermediate(ctx); !errors.Is(err, summon.ErrProviderUntrusted) {
		t.Fatalf("rotation with an untrusted provider: got %v, want the provider error to propagate", err)
	}
	if ca.res.callCount() <= before {
		t.Fatal("rotation must resolve the passphrase at the moment it needs it, not reuse a cached value")
	}
}

// TestCAKeysAreSealedOnDisk: the key files must not be openable without the
// Summon-resolved passphrase, and must not be group- or world-readable.
func TestCAKeysAreSealedOnDisk(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	matches, err := filepath.Glob(filepath.Join(ca.dir, "*"+keySuffix))
	if err != nil || len(matches) < 2 {
		t.Fatalf("want a sealed key file for the root and the intermediate, got %v (%v)", matches, err)
	}
	for _, p := range matches {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is mode %v, want 0600", filepath.Base(p), info.Mode().Perm())
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "EC PRIVATE KEY") {
			t.Fatalf("%s announces itself as a plain EC private key", filepath.Base(p))
		}
		if _, err := x509.ParseECPrivateKey(raw); err == nil {
			t.Fatalf("%s parsed as a private key without the passphrase", filepath.Base(p))
		}
	}
}

// TestWrongPassphraseCannotOpen: the seal is real, not decoration.
func TestWrongPassphraseCannotOpen(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), Config{
		Dir: ca.dir, Resolver: &fakeResolver{pass: "not the passphrase", rotation: summon.RotationSealsDataAtRest},
		PassphraseRef: "ca_passphrase", TrustDomain: testTrustDomain, Now: ca.clk.now,
	})
	if err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("opening with the wrong passphrase: got %v, want an unseal failure", err)
	}
}

// TestWrongCurveIsRefusedNotDowngraded is the algorithm refusal from the spec.
// Every one of these is a REFUSAL: nothing is minted, and no substitution is
// made, including for the curve that is stronger than the one we require.
func TestWrongCurveIsRefusedNotDowngraded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	edpub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		name string
		key  any
	}{
		{"P-384, stronger than required and still refused", p384.Public()},
		{"P-521", p521.Public()},
		{"P-224, weaker", p224.Public()},
		{"Ed25519, named in the spec as never", edpub},
		{"RSA-2048", rsaKey.Public()},
		{"no key at all", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svid, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: c.key})
			if !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Fatalf("got %v, want ErrUnsupportedAlgorithm", err)
			}
			if svid != nil {
				t.Fatal("a refused algorithm must mint nothing at all; a returned SVID here would be a silent substitution")
			}
			// The issuer's own identity goes through the same gate.
			if _, err := ca.IssueIssuerSVID(ctx, IssuerSVIDRequest{PublicKey: c.key}); !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Fatalf("IssueIssuerSVID got %v, want ErrUnsupportedAlgorithm", err)
			}
		})
	}
}

// TestIssuerIdentityIsDistinguishableInTheLog is the spec sentence "every
// self-issuance logged as a distinct event type", tested as a property of the
// returned value rather than of a convention.
func TestIssuerIdentityIsDistinguishableInTheLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	device, err := ca.IssueSVID(ctx, SVIDRequest{
		ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public(),
		ProtectionLevel: spiffe.ProtectionHardware, Presence: presence.StatePresent,
	})
	if err != nil {
		t.Fatal(err)
	}
	self, err := ca.IssueIssuerSVID(ctx, IssuerSVIDRequest{PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}

	if device.Event != EventIssuance {
		t.Fatalf("device issuance Event = %q, want %q", device.Event, EventIssuance)
	}
	if self.Event != EventIssuerSelfIssuance {
		t.Fatalf("self-issuance Event = %q, want %q", self.Event, EventIssuerSelfIssuance)
	}
	if device.Event == self.Event {
		t.Fatal("a self-issuance must not share an event kind with a device issuance")
	}
	if want := "spiffe://" + testTrustDomain + IssuerPath; self.URI != want {
		t.Fatalf("issuer URI = %q, want %q", self.URI, want)
	}

	// The issuer identity carries no presence and no protection level. Emitting
	// presence:none here would give it the same extension an unattended device
	// credential carries, which is exactly the conflation the distinct event
	// type exists to prevent.
	for _, oid := range []asn1.ObjectIdentifier{OIDProtectionLevel, OIDPresenceState, OIDPresenceAge, OIDGrantID} {
		if hasExt(self.Certificate, oid) {
			t.Fatalf("the issuer's own SVID must not carry %s", oid)
		}
	}
	if !hasExt(device.Certificate, OIDPresenceState) {
		t.Fatal("a device SVID must carry its presence state")
	}

	// And the door is one-way: the issuer identity cannot be minted through
	// IssueSVID, whatever a caller passes.
	for _, id := range []spiffe.ID{
		{TrustDomain: testTrustDomain, Tool: "issuer"},
		{TrustDomain: testTrustDomain, Agent: "issuer"},
	} {
		if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: id, PublicKey: newSVIDKey(t).Public()}); !errors.Is(err, ErrIssuerIdentityReserved) {
			t.Fatalf("IssueSVID(%+v): got %v, want ErrIssuerIdentityReserved", id, err)
		}
	}

	// Both still have to be real certificates.
	bundle, err := ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*SVID{device, self} {
		if err := verifyAgainstBundle(t, s.Certificate, bundle, ca.clk.now()); err != nil {
			t.Fatalf("verifying %s: %v", s.URI, err)
		}
	}
}

func hasExt(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func extValue(t *testing.T, c *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			if e.Critical {
				t.Fatalf("%s is marked critical; a relying party that does not know totem must still be able to verify a totem chain", oid)
			}
			return e.Value
		}
	}
	t.Fatalf("certificate carries no extension %s", oid)
	return nil
}

// TestFactsTravelAsExtensionsNeverInThePath is the identity-model rule:
// "Protection level and presence facts travel as X.509 extensions and JWT
// claims, never in the path."
func TestFactsTravelAsExtensionsNeverInThePath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	svid, err := ca.IssueSVID(ctx, SVIDRequest{
		ID:              deviceID("claude"),
		PublicKey:       newSVIDKey(t).Public(),
		ProtectionLevel: spiffe.ProtectionHardware,
		Presence:        presence.StateDelegated,
		PresenceAge:     90 * time.Second,
		GrantID:         "grant-7",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The URI must round-trip through go-spiffe's own parser, not just through
	// our own string handling.
	if len(svid.Certificate.URIs) != 1 {
		t.Fatalf("want exactly one URI SAN, got %d", len(svid.Certificate.URIs))
	}
	parsed, err := spiffeid.FromURI(svid.Certificate.URIs[0])
	if err != nil {
		t.Fatalf("the URI SAN is not a SPIFFE ID go-spiffe accepts: %v", err)
	}
	if parsed.String() != "spiffe://"+testTrustDomain+"/device/dev-abc123/tool/claude" {
		t.Fatalf("derived ID = %s", parsed.String())
	}
	for _, leaked := range []string{"hardware", "delegated", "grant-7", "presence"} {
		if strings.Contains(parsed.Path(), leaked) {
			t.Fatalf("%q leaked into the identity path %q; these facts belong in extensions", leaked, parsed.Path())
		}
	}

	var s string
	if _, err := asn1.Unmarshal(extValue(t, svid.Certificate, OIDProtectionLevel), &s); err != nil {
		t.Fatal(err)
	}
	if s != string(spiffe.ProtectionHardware) {
		t.Fatalf("protection level extension = %q", s)
	}
	if _, err := asn1.Unmarshal(extValue(t, svid.Certificate, OIDPresenceState), &s); err != nil {
		t.Fatal(err)
	}
	if s != string(presence.StateDelegated) {
		t.Fatalf("presence state extension = %q", s)
	}
	var age int
	if _, err := asn1.Unmarshal(extValue(t, svid.Certificate, OIDPresenceAge), &age); err != nil {
		t.Fatal(err)
	}
	if age != 90 {
		t.Fatalf("presence age extension = %d, want 90", age)
	}
	if _, err := asn1.Unmarshal(extValue(t, svid.Certificate, OIDGrantID), &s); err != nil {
		t.Fatal(err)
	}
	if s != "grant-7" {
		t.Fatalf("grant id extension = %q", s)
	}

	// SVID profile: digitalSignature only, never a CA, never certSign.
	if svid.Certificate.IsCA {
		t.Fatal("an SVID must not be a CA")
	}
	if svid.Certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("SVID KeyUsage = %v, want digitalSignature only", svid.Certificate.KeyUsage)
	}
	// The chain presented is leaf plus the signing intermediate, which is what
	// the AWS bridge helper sends.
	if len(svid.Chain) != 2 || !svid.Chain[0].Equal(svid.Certificate) {
		t.Fatalf("Chain must be leaf then signing intermediate, got %d certs", len(svid.Chain))
	}
	if !svid.Chain[1].IsCA {
		t.Fatal("the second element of the chain must be the signing intermediate")
	}
}

// TestDelegatedIssuanceMustNameItsGrant: a delegated credential that cannot
// name the grant behind it cannot answer "who authorised this".
func TestDelegatedIssuanceMustNameItsGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	_, err := ca.IssueSVID(ctx, SVIDRequest{
		ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public(),
		Presence: presence.StateDelegated,
	})
	if !errors.Is(err, ErrGrantRequired) {
		t.Fatalf("got %v, want ErrGrantRequired", err)
	}
	// presence:none is a legitimate recorded value, not a missing one.
	if _, err := ca.IssueSVID(ctx, SVIDRequest{
		ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public(), Presence: presence.StateNone,
	}); err != nil {
		t.Fatalf("presence:none must be issuable and recorded: %v", err)
	}
}

func TestTTLAndIdentityValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	key := newSVIDKey(t).Public()

	if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: key, TTL: 8 * time.Hour}); !errors.Is(err, ErrTTLTooLong) {
		t.Fatalf("an over-long TTL must be refused, not clamped: got %v", err)
	}
	svid, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if got := svid.NotAfter.Sub(ca.clk.now()); got != DefaultSVIDTTL {
		t.Fatalf("default TTL = %s, want %s", got, DefaultSVIDTTL)
	}
	short, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("aws"), PublicKey: key, TTL: BridgeSVIDTTL})
	if err != nil {
		t.Fatal(err)
	}
	if got := short.NotAfter.Sub(ca.clk.now()); got != BridgeSVIDTTL {
		t.Fatalf("bridge TTL = %s, want %s", got, BridgeSVIDTTL)
	}

	bad := []struct {
		name string
		id   spiffe.ID
		want error
	}{
		{"another trust domain", spiffe.ID{TrustDomain: "someone.else", DeviceID: "d", Tool: "claude"}, ErrTrustDomainMismatch},
		{"no device", spiffe.ID{TrustDomain: testTrustDomain, Tool: "claude"}, ErrInvalidIdentity},
		{"tool and agent both", spiffe.ID{TrustDomain: testTrustDomain, DeviceID: "d", Tool: "claude", Agent: "cassidy"}, ErrInvalidIdentity},
		{"neither tool nor agent", spiffe.ID{TrustDomain: testTrustDomain, DeviceID: "d"}, ErrInvalidIdentity},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: c.id, PublicKey: key}); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	// An agent identity is legal and takes the agent segment.
	agent, err := ca.IssueSVID(ctx, SVIDRequest{
		ID: spiffe.ID{TrustDomain: testTrustDomain, DeviceID: "dev-abc123", Agent: "cassidy"}, PublicKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.URI != "spiffe://"+testTrustDomain+"/device/dev-abc123/agent/cassidy" {
		t.Fatalf("agent URI = %s", agent.URI)
	}
}

// TestRootOfflineBlocksRotation: moving the root key off the box is what makes
// an offline root offline, and rotation then needs a ceremony.
func TestRootOfflineBlocksRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	roots, err := filepath.Glob(filepath.Join(ca.dir, rootPrefix+"*"+keySuffix))
	if err != nil || len(roots) != 1 {
		t.Fatalf("want one root key file, got %v (%v)", roots, err)
	}
	moved := filepath.Join(t.TempDir(), "root.key")
	if err := os.Rename(roots[0], moved); err != nil {
		t.Fatal(err)
	}

	// Steady-state issuance is untouched: it never needs the root.
	if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); err != nil {
		t.Fatalf("an offline root must not affect issuance: %v", err)
	}

	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.RotateAfter.Add(time.Hour))
	if _, err := ca.RotateIntermediate(ctx); !errors.Is(err, ErrRootOffline) {
		t.Fatalf("rotating with the root key absent: got %v, want ErrRootOffline", err)
	}

	// Bring it back for the ceremony and the rotation succeeds.
	if err := os.Rename(moved, roots[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.RotateIntermediate(ctx); err != nil {
		t.Fatalf("rotation with the root present: %v", err)
	}
}

// TestReopenPreservesEverything: an issuer restart must not invalidate
// outstanding credentials or lose the schedule.
func TestReopenPreservesEverything(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	before, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	schedBefore, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed authority must refuse: got %v", err)
	}

	reopened, err := Open(ctx, Config{
		Dir: ca.dir, Resolver: ca.res, PassphraseRef: "ca_passphrase",
		TrustDomain: testTrustDomain, Now: ca.clk.now,
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	schedAfter, err := reopened.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !schedAfter.Current.Certificate.Equal(schedBefore.Current.Certificate) {
		t.Fatal("reopening must find the same signing intermediate; the schedule is derived from the certificates, so it cannot drift across a restart")
	}
	bundle, err := reopened.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstBundle(t, before.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("a credential issued before the restart stopped verifying: %v", err)
	}
	if _, err := reopened.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()}); err != nil {
		t.Fatalf("issuing after a restart: %v", err)
	}
}

// TestConcurrentIssuance exists for -race: issuance, rotation reads and bundle
// reads all touch the same intermediate set.
func TestConcurrentIssuance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)
	key := newSVIDKey(t).Public()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: key}); err != nil {
				errs <- err
			}
			if _, err := ca.Bundle(ctx); err != nil {
				errs <- err
			}
			if _, err := ca.Schedule(ctx); err != nil {
				errs <- err
			}
			if _, err := ca.CRLs(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent use: %v", err)
	}
}

// TestRotateRootPublishesBothRoots: a root rotation must not break the fleet
// that only trusts the old root yet.
func TestRotateRootPublishesBothRoots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	old, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	op, ok := ca.Authority.(RootOperator)
	if !ok {
		t.Fatal("the local authority must implement RootOperator")
	}
	bundle, err := op.RotateRoot(ctx, RootRotationRequest{})
	if err != nil {
		t.Fatalf("RotateRoot: %v", err)
	}
	if len(bundle.Roots) != 2 {
		t.Fatalf("after a root rotation the bundle must publish both roots, got %d", len(bundle.Roots))
	}
	if err := verifyAgainstBundle(t, old.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("a credential issued under the old root stopped verifying after the rotation: %v", err)
	}

	// The next intermediate is signed by the NEW root, and its leaves verify
	// against the same bundle.
	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.RotateAfter.Add(time.Hour))
	if _, err := ca.RotateIntermediate(ctx); err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.Current.SigningEnd.Add(time.Hour))
	fresh, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = ca.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstBundle(t, fresh.Certificate, bundle, ca.clk.now()); err != nil {
		t.Fatalf("a credential from the intermediate signed by the new root does not verify: %v", err)
	}
}
