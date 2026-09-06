package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/store"
)

// The issuer's own key, the one behind spiffe://<td>/issuer.
//
// docs/totem-design.md: "The issuer has its own tool identity,
// spiffe://<td>/issuer, with no presence, every self-issuance logged as a
// distinct event type, used for the one AWS call it makes: publishing CRLs
// through its own Roles Anywhere profile and a role limited to
// rolesanywhere:ImportCrl and rolesanywhere:UpdateCrl on its own trust anchor."
//
// ca.IssueIssuerSVID takes a public key, so the private half lives outside
// internal/ca, and the docs do not say where. It lives HERE, and it is issuer
// state with the same care as CA material, because of what it is: the only
// credential this box presents to something outside itself. A laptop's device
// key gets a Secure Enclave; this one is on a headless broker with no secure
// element, so the protection available to it is the one the design already
// specifies for exactly this case.
//
// docs/totem-design-decisions.md 25 draws the line and this key falls squarely
// on one side of it: operator-provided secrets are Summon references resolved
// read-only, while "issuer-managed secrets that it generates or that rotate on
// use ... live in SQLite envelope-encrypted under a data key resolved through
// Summon". The issuer generates this key, so it is the second kind, and it goes
// in the store as an envelope-encrypted row rather than in a file beside the CA
// or in a second sealing scheme invented here. Three things follow for free,
// which is the argument for not inventing one: `issuer rotate-data-key`
// re-encrypts it along with everything else, `backup` and `restore` carry it,
// and losing the data key loses only material a re-generation can replace,
// which for this key is true (a new key means a new self-issued SVID, and
// nothing else holds a copy).
//
// It is deliberately NOT sealed under the CA passphrase. That passphrase seals
// material that CANNOT be regenerated, which is why changing it is a ceremony
// with a reseal command behind it; putting a regenerable key under the same
// lock would add a file to that ceremony for no gain and one more way to brick
// a restart.

// IssuerKeyID is the id the issuer's own private key is stored under, in
// store.CollectionSecrets.
const IssuerKeyID = "issuer-identity-key"

// ErrIssuerKeyUnusable means the stored issuer key is not an ECDSA P-256 key.
// It is a refusal rather than a silent regeneration: a key that cannot be
// parsed might be a corrupt row or might be a restore from a backup written by
// something else, and quietly minting a fresh identity over the top of either
// destroys the evidence.
var ErrIssuerKeyUnusable = errors.New("server: the stored issuer identity key is not usable")

// IssuerIdentity holds the issuer's own key and mints its own SVID.
type IssuerIdentity struct {
	mu    sync.Mutex
	store store.Store
	ca    ca.Authority
	key   *ecdsa.PrivateKey
}

// NewIssuerIdentity wires the issuer's own identity to the store it is kept in
// and the CA that signs it.
func NewIssuerIdentity(s store.Store, authority ca.Authority) (*IssuerIdentity, error) {
	if s == nil || authority == nil {
		return nil, fmt.Errorf("%w: the issuer's own identity needs a store and a CA", ErrConfig)
	}
	return &IssuerIdentity{store: s, ca: authority}, nil
}

// Key returns the issuer's own private key, generating and persisting one the
// first time.
//
// Get-then-create rather than create-then-store: a key that was generated and
// then failed to persist would be used for one process lifetime and vanish, and
// the SVIDs minted under it would reference a public key nothing can prove
// possession of afterwards. So nothing is returned until it is durable.
func (i *IssuerIdentity) Key(ctx context.Context) (*ecdsa.PrivateKey, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.key != nil {
		return i.key, nil
	}
	der, err := i.store.Get(ctx, store.CollectionSecrets, IssuerKeyID)
	switch {
	case err == nil:
		key, perr := parseIssuerKey(der)
		if perr != nil {
			return nil, perr
		}
		i.key = key
		return key, nil
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := i.store.Put(ctx, store.CollectionSecrets, IssuerKeyID, pkcs8); err != nil {
		return nil, err
	}
	i.key = key
	return key, nil
}

// SVID mints the issuer's own X.509-SVID.
//
// The returned SVID carries ca.EventIssuerSelfIssuance in its Event field,
// which is passed straight through to the audit line rather than relabelled
// here. internal/ca sets it on the way out precisely so that a self-issuance
// can never be recorded as a device issuance by a call site that picked the
// string itself, and an auditor counting device issuances does not have to
// subtract these out.
func (i *IssuerIdentity) SVID(ctx context.Context) (*ca.SVID, error) {
	key, err := i.Key(ctx)
	if err != nil {
		return nil, err
	}
	return i.ca.IssueIssuerSVID(ctx, ca.IssuerSVIDRequest{PublicKey: &key.PublicKey})
}

// SelfIssue mints the issuer's own SVID and records it on the audit line under
// the kind internal/ca chose.
func (i *IssuerIdentity) SelfIssue(ctx context.Context, log *AuditLog) (*ca.SVID, error) {
	svid, err := i.SVID(ctx)
	if err != nil {
		return nil, err
	}
	if log != nil {
		if _, lerr := log.Log(Event{
			Kind:     svid.Event,
			SpiffeID: svid.URI,
			Outcome:  "issued",
		}); lerr != nil {
			return nil, lerr
		}
	}
	return svid, nil
}

// parseIssuerKey enforces the one algorithm the spec allows.
func parseIssuerKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssuerKeyUnusable, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: it is a %T, and totem uses ECDSA P-256", ErrIssuerKeyUnusable, parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: it is on curve %s, and totem uses ECDSA P-256", ErrIssuerKeyUnusable, key.Curve.Params().Name)
	}
	return key, nil
}
