package ca

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const revocationsFile = "revocations.json"

// revocationState is the durable revocation set plus the per-issuer CRL
// counters. It is one file rather than a table in the issuer's SQLite store
// because it must survive independently of that store: a CA directory restored
// on a fresh box has to be able to publish a CRL before the issuer's database
// is up, and revocation is exactly what an operator reaches for during the
// incident that made them restore.
type revocationState struct {
	// CRLNumbers maps an issuing intermediate's SubjectKeyId to the last CRL
	// number published under it. RFC 5280 requires CRL numbers to increase
	// monotonically per issuer, so this is per-issuer and never reset.
	CRLNumbers map[string]int64 `json:"crl_numbers"`
	// Revoked is the revocation set, each entry scoped to the intermediate that
	// issued the certificate.
	Revoked []revokedEntry `json:"revoked"`
}

type revokedEntry struct {
	// Serial is the revoked certificate's serial, hex.
	Serial string `json:"serial"`
	// IssuerSKID is the SubjectKeyId of the intermediate that issued it,
	// established by chain verification at Revoke, not read off the
	// certificate's own AuthorityKeyId field. A field on the certificate is the
	// certificate's claim about its issuer; a verified chain is proof.
	IssuerSKID string    `json:"issuer_skid"`
	Reason     int       `json:"reason"`
	At         time.Time `json:"at"`
}

func newRevocationState() *revocationState {
	return &revocationState{CRLNumbers: map[string]int64{}}
}

func loadRevocationState(dir string) (*revocationState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, revocationsFile))
	if errors.Is(err, os.ErrNotExist) {
		return newRevocationState(), nil
	}
	if err != nil {
		return nil, err
	}
	var s revocationState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("ca: parsing %s: %w", revocationsFile, err)
	}
	if s.CRLNumbers == nil {
		s.CRLNumbers = map[string]int64{}
	}
	return &s, nil
}

func (s *revocationState) save(dir string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, revocationsFile), raw, 0o600)
}

// Revoke records a revocation, after proving the certificate is one this CA
// issued.
//
// The proof is a chain verification through crypto/x509, not a look at the
// certificate's AuthorityKeyId. A serial number and an AKI are both claims made
// by whoever handed us the certificate; accepting them would let a caller write
// serials this CA never issued into a CRL that relying parties honour, which
// turns the revocation channel into a denial-of-service channel.
//
// Verification runs at the certificate's own NotBefore rather than at now, so
// an already-expired certificate can still be revoked. Revoking an expired
// certificate is usually pointless and occasionally exactly what an incident
// needs, and refusing on expiry would be refusing on a fact that has nothing to
// do with whether we issued it.
func (a *authority) Revoke(ctx context.Context, req RevocationRequest) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if req.Certificate == nil {
		return fmt.Errorf("%w: no certificate", ErrNotOurCertificate)
	}
	issuer, err := a.verifyOurs(req.Certificate)
	if err != nil {
		return err
	}
	at := req.At
	if at.IsZero() {
		at = a.now()
	}
	skid := hex.EncodeToString(issuer.SubjectKeyId)
	serial := req.Certificate.SerialNumber.Text(16)
	for _, e := range a.revs.Revoked {
		if e.Serial == serial && e.IssuerSKID == skid {
			return nil // already revoked; revocation is idempotent
		}
	}
	a.revs.Revoked = append(a.revs.Revoked, revokedEntry{
		Serial:     serial,
		IssuerSKID: skid,
		Reason:     int(req.Reason),
		At:         at.UTC(),
	})
	return a.revs.save(a.dir)
}

// verifyOurs chain-verifies cert against this CA and returns the intermediate
// that actually signed it. Callers hold the lock.
func (a *authority) verifyOurs(cert *x509.Certificate) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	for _, r := range a.roots {
		roots.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, in := range a.inters {
		inter.AddCert(in.cert)
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   cert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotOurCertificate, err)
	}
	// chains[0] is leaf, intermediate, root. A chain of length two would be a
	// certificate the root signed directly, which this CA never does.
	if len(chains[0]) < 3 {
		return nil, fmt.Errorf("%w: it does not chain through one of this CA's intermediates", ErrNotOurCertificate)
	}
	return chains[0][1], nil
}

// CRLs generates one signed CRL per intermediate still in the bundle.
//
// One per issuer, because a CRL is only meaningful for the CA that signed it:
// a verifier checking a certificate issued by the outgoing intermediate looks
// for a CRL signed by that intermediate, and a single merged list signed by the
// current one is silently ignored for every serial the outgoing one issued.
// During an overlap there are up to three live intermediates, so this is not a
// theoretical case; it is the case that occurs every thirty days.
//
// A CRL is produced for an intermediate even when it has revoked nothing. An
// empty CRL is a positive statement that nothing is revoked; a missing one
// leaves the relying party to decide, and the way relying parties decide is by
// failing open.
func (a *authority) CRLs(ctx context.Context) ([]*CRL, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	t := a.now()
	byIssuer := map[string][]x509.RevocationListEntry{}
	for _, e := range a.revs.Revoked {
		serial, ok := new(big.Int).SetString(e.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("ca: %s holds an unparseable serial %q", revocationsFile, e.Serial)
		}
		byIssuer[e.IssuerSKID] = append(byIssuer[e.IssuerSKID], x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: e.At,
			ReasonCode:     e.Reason,
		})
	}

	var out []*CRL
	changed := false
	for _, in := range liveIntermediates(a.intermediateCerts(), t) {
		signer := a.byCert(in.Certificate)
		if signer == nil {
			continue
		}
		skid := hex.EncodeToString(in.Certificate.SubjectKeyId)
		entries := byIssuer[skid]
		sort.Slice(entries, func(i, j int) bool { return entries[i].SerialNumber.Cmp(entries[j].SerialNumber) < 0 })

		a.revs.CRLNumbers[skid]++
		changed = true
		tmpl := &x509.RevocationList{
			SignatureAlgorithm:        caSignatureAlgorithm,
			RevokedCertificateEntries: entries,
			Number:                    big.NewInt(a.revs.CRLNumbers[skid]),
			ThisUpdate:                t,
			NextUpdate:                t.Add(DefaultCRLValidity),
		}
		der, err := x509.CreateRevocationList(cryptoRand, tmpl, signer.cert, signer.key)
		if err != nil {
			return nil, fmt.Errorf("ca: signing a CRL under intermediate %s: %w", skid[:8], err)
		}
		out = append(out, &CRL{
			DER:                der,
			IssuerSubjectKeyID: append([]byte(nil), in.Certificate.SubjectKeyId...),
			ThisUpdate:         tmpl.ThisUpdate,
			NextUpdate:         tmpl.NextUpdate,
		})
	}
	if changed {
		if err := a.revs.save(a.dir); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *authority) byCert(c *x509.Certificate) *loadedIntermediate {
	for _, in := range a.inters {
		if in.cert.Equal(c) {
			return in
		}
	}
	return nil
}
