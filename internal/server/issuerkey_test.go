package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// realStore opens a real SQLite store and returns it with its file path, so a
// test can assert about what actually landed on disk.
func realStore(t *testing.T) (*store.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "issuer.db")
	db, err := store.Open(context.Background(), path, store.Options{
		Resolver: &testProvider{refs: map[summon.Reference][]byte{
			summon.Reference(store.DataKeyRefName): bytes.Repeat([]byte{0x3f}, 32),
		}},
	})
	if err != nil {
		t.Fatalf("opening the real store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

// TestIssuerKeyIsDurableAndStable. Nothing is returned until it is durable: a
// key that was generated and then failed to persist would be used for one
// process lifetime, and the SVIDs minted under it would name a public key
// nothing can prove possession of afterwards.
func TestIssuerKeyIsDurableAndStable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	authority, _, _ := realCA(t)

	first, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := first.Key(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Curve != elliptic.P256() {
		t.Fatalf("the issuer's key is on %s; the spec allows ECDSA P-256 only", k1.Curve.Params().Name)
	}
	// Same process, second call: cached, same key.
	k1again, err := first.Key(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k1again) {
		t.Fatal("two calls in one process returned different keys")
	}
	// A fresh identity over the same store: the key survived, which is the
	// property that matters across a restart.
	second, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := second.Key(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Fatal("the issuer's identity key changed across a reopen; every SVID minted under the old one is now unprovable")
	}
}

// TestIssuerKeyIsNotOnDiskInPlaintext. docs/totem-design-decisions.md 25: the
// issuer's own generated secrets live in SQLite "envelope-encrypted under a data
// key resolved through Summon". This asserts the row is actually encrypted
// rather than merely stored through an API that says it is.
func TestIssuerKeyIsNotOnDiskInPlaintext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, path := realStore(t)
	authority, _, _ := realCA(t)

	identity, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.Key(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, pkcs8) {
		t.Fatal("the issuer's private key is in the database file in plaintext")
	}
	// The private scalar on its own would be just as bad as the whole DER.
	if bytes.Contains(raw, key.D.Bytes()) {
		t.Fatal("the issuer's private scalar is in the database file in plaintext")
	}
}

// TestIssuerSVIDCarriesTheKindInternalCAChose. internal/ca sets the event kind
// on the SVID precisely so a self-issuance can never be recorded as a device
// issuance by a call site that picked the string itself.
func TestIssuerSVIDCarriesTheKindInternalCAChose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	authority, _, _ := realCA(t)
	identity, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}

	var audit bytes.Buffer
	log := NewAuditLog(&audit, nil)
	svid, err := identity.SelfIssue(ctx, log)
	if err != nil {
		t.Fatalf("minting the issuer's own SVID: %v", err)
	}
	if svid.Event != ca.EventIssuerSelfIssuance {
		t.Errorf("the SVID carries kind %q, want %q", svid.Event, ca.EventIssuerSelfIssuance)
	}
	if !strings.HasSuffix(svid.URI, ca.IssuerPath) {
		t.Errorf("the issuer's identity is %q, want a path ending in %q", svid.URI, ca.IssuerPath)
	}
	records := decodeRecords(t, audit.String())
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	if records[0].Kind != ca.EventIssuerSelfIssuance {
		t.Fatalf("the self-issuance was logged as %q; an auditor counting device issuances must not have to subtract these out", records[0].Kind)
	}
	if records[0].Kind == ca.EventIssuance {
		t.Fatal("the issuer's own issuance is indistinguishable from a device issuance in the log")
	}
	// It carries no presence, because the issuer identity has none, and a
	// presence age on this line would read as a human having been involved.
	if records[0].PresenceAgeS != nil {
		t.Error("the issuer's self-issuance carries a presence age")
	}
}

// TestIssuerSVIDBindsTheStoredKey. The certificate must be for the key the
// store holds, or the issuer cannot prove possession of its own identity.
func TestIssuerSVIDBindsTheStoredKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	authority, _, _ := realCA(t)
	identity, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.Key(ctx)
	if err != nil {
		t.Fatal(err)
	}
	svid, err := identity.SVID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := svid.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the issuer's certificate carries a %T", svid.Certificate.PublicKey)
	}
	if !pub.Equal(&key.PublicKey) {
		t.Fatal("the issuer's certificate is for a different key than the one the store holds")
	}
}

// TestAnUnusableStoredKeyIsRefusedNotReplaced. A row that will not parse might
// be corruption or might be a restore from a backup written by something else,
// and quietly minting a fresh identity over the top of either destroys the
// evidence.
func TestAnUnusableStoredKeyIsRefusedNotReplaced(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _ := realStore(t)
	authority, _, _ := realCA(t)

	// A perfectly valid key of the wrong kind is the interesting case: it
	// parses as PKCS8 and is still not something totem will use.
	wrong, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(ctx, store.CollectionSecrets, IssuerKeyID, der); err != nil {
		t.Fatal(err)
	}

	identity, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Key(ctx); !errors.Is(err, ErrIssuerKeyUnusable) {
		t.Fatalf("got %v, want ErrIssuerKeyUnusable", err)
	}
	// And the row is untouched, so whatever it was is still there to look at.
	back, err := db.Get(ctx, store.CollectionSecrets, IssuerKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, der) {
		t.Fatal("the unusable row was overwritten; the evidence is gone")
	}

	// Garbage is refused too, for the same reason.
	if err := db.Put(ctx, store.CollectionSecrets, IssuerKeyID, []byte("not a key")); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewIssuerIdentity(db, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Key(ctx); !errors.Is(err, ErrIssuerKeyUnusable) {
		t.Fatalf("got %v, want ErrIssuerKeyUnusable", err)
	}
}

// TestNewIssuerIdentityRefusesAnIncompleteWiring.
func TestNewIssuerIdentityRefusesAnIncompleteWiring(t *testing.T) {
	t.Parallel()
	db, _ := realStore(t)
	authority, _, _ := realCA(t)
	if _, err := NewIssuerIdentity(nil, authority); !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want ErrConfig", err)
	}
	if _, err := NewIssuerIdentity(db, nil); !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want ErrConfig", err)
	}
}
