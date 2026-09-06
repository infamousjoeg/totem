package ca

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

func crlFor(t *testing.T, crls []*CRL, skid []byte) *x509.RevocationList {
	t.Helper()
	for _, c := range crls {
		if hex.EncodeToString(c.IssuerSubjectKeyID) == hex.EncodeToString(skid) {
			parsed, err := x509.ParseRevocationList(c.DER)
			if err != nil {
				t.Fatalf("the CRL this package produced does not parse as a CRL: %v", err)
			}
			return parsed
		}
	}
	t.Fatalf("no CRL published for intermediate %s", hex.EncodeToString(skid)[:8])
	return nil
}

func listsSerial(l *x509.RevocationList, serial *big.Int) bool {
	for _, e := range l.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// TestRevokeThenCRL walks the whole revocation path and checks the CRL with
// crypto/x509's own parser and signature check, not with anything in this
// package. A CRL this package can read and nothing else can is not a CRL.
func TestRevokeThenCRL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	svid, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer := sched.Current.Certificate

	// Before revocation the CRL exists and is empty. An absent CRL leaves the
	// relying party to decide, and relying parties decide by failing open.
	crls, err := ca.CRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	empty := crlFor(t, crls, signer.SubjectKeyId)
	if len(empty.RevokedCertificateEntries) != 0 {
		t.Fatal("nothing is revoked yet")
	}
	if err := empty.CheckSignatureFrom(signer); err != nil {
		t.Fatalf("the CRL must verify under the intermediate that signed it: %v", err)
	}

	if err := ca.Revoke(ctx, RevocationRequest{Certificate: svid.Certificate, Reason: ReasonKeyCompromise}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Revocation is idempotent: an operator running it twice is not an error.
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: svid.Certificate, Reason: ReasonKeyCompromise}); err != nil {
		t.Fatalf("revoking twice: %v", err)
	}

	crls, err = ca.CRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list := crlFor(t, crls, signer.SubjectKeyId)
	if err := list.CheckSignatureFrom(signer); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	if len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("want exactly one entry after revoking one certificate twice, got %d", len(list.RevokedCertificateEntries))
	}
	if !listsSerial(list, svid.Certificate.SerialNumber) {
		t.Fatal("the revoked serial is not on the CRL")
	}
	if got := list.RevokedCertificateEntries[0].ReasonCode; got != int(ReasonKeyCompromise) {
		t.Fatalf("reason code = %d, want %d", got, ReasonKeyCompromise)
	}
	if !list.NextUpdate.Equal(list.ThisUpdate.Add(DefaultCRLValidity)) {
		t.Fatal("NextUpdate must be DefaultCRLValidity after ThisUpdate")
	}

	// CRL numbers increase monotonically per issuer, as RFC 5280 requires, and
	// survive a restart: a counter that resets lets a stale CRL look newer than
	// the current one.
	first := list.Number
	crls, err = ca.CRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second := crlFor(t, crls, signer.SubjectKeyId).Number
	if second.Cmp(first) <= 0 {
		t.Fatalf("CRL number went from %s to %s; it must increase", first, second)
	}
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, Config{Dir: ca.dir, Resolver: ca.res, PassphraseRef: "ca_passphrase", TrustDomain: testTrustDomain, Now: ca.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	crls, err = reopened.CRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after := crlFor(t, crls, signer.SubjectKeyId)
	if after.Number.Cmp(second) <= 0 {
		t.Fatalf("CRL number reset across a restart: %s then %s", second, after.Number)
	}
	if !listsSerial(after, svid.Certificate.SerialNumber) {
		t.Fatal("the revocation did not survive a restart")
	}
}

// TestRevokeRefusesACertificateWeDidNotIssue is the "verify, do not parse"
// rule applied to revocation: a serial number and an AuthorityKeyId are claims
// made by whoever handed us the certificate. Accepting them would turn the
// revocation channel into a way to poison a CRL that relying parties honour.
func TestRevokeRefusesACertificateWeDidNotIssue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	foreign := foreignLeaf(t, ca.clk.now())
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: foreign, Reason: ReasonKeyCompromise}); !errors.Is(err, ErrNotOurCertificate) {
		t.Fatalf("revoking a foreign certificate: got %v, want ErrNotOurCertificate", err)
	}
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: nil}); !errors.Is(err, ErrNotOurCertificate) {
		t.Fatalf("revoking nil: got %v, want ErrNotOurCertificate", err)
	}
	// A certificate that merely CLAIMS one of our serials and our issuer name
	// is still refused, because the chain does not verify.
	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	forged := foreignLeaf(t, ca.clk.now())
	forged.SerialNumber = big.NewInt(1)
	forged.AuthorityKeyId = sched.Current.Certificate.SubjectKeyId
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: forged}); !errors.Is(err, ErrNotOurCertificate) {
		t.Fatalf("revoking on a claimed AuthorityKeyId: got %v, want ErrNotOurCertificate", err)
	}

	crls, err := ca.CRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range crls {
		parsed, err := x509.ParseRevocationList(c.DER)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.RevokedCertificateEntries) != 0 {
			t.Fatal("a refused revocation must not reach a CRL")
		}
	}
}

// TestOneCRLPerLiveIntermediate is the reason CRLs is plural. During an overlap
// there are up to three live intermediates, and a verifier checking a
// certificate issued by the outgoing one looks for a CRL signed by THAT
// intermediate. A single merged list signed by the current one is silently
// ignored for every serial the outgoing one issued, which is revocation not
// working while appearing to.
func TestOneCRLPerLiveIntermediate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	sched, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	outgoing := sched.Current.Certificate

	// A credential from the outgoing intermediate, revoked before the handover.
	ca.clk.set(sched.Current.SigningEnd.Add(-20 * time.Minute))
	old, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.RotateAfter.Add(time.Hour))
	if _, err := ca.RotateIntermediate(ctx); err != nil {
		t.Fatal(err)
	}
	ca.clk.set(sched.Current.SigningEnd.Add(-20 * time.Minute))
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: old.Certificate, Reason: ReasonKeyCompromise}); err != nil {
		t.Fatal(err)
	}

	// Cross the handover and mint one under the incoming intermediate.
	ca.clk.set(sched.Current.SigningEnd.Add(30 * time.Minute))
	after, err := ca.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	incoming := after.Current.Certificate
	fresh, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: fresh.Certificate, Reason: ReasonCessationOfOperation}); err != nil {
		t.Fatal(err)
	}

	crls, err := ca.CRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(crls) != 2 {
		t.Fatalf("two intermediates are live, so there must be two CRLs, got %d", len(crls))
	}

	outList := crlFor(t, crls, outgoing.SubjectKeyId)
	if err := outList.CheckSignatureFrom(outgoing); err != nil {
		t.Fatalf("the outgoing intermediate's CRL must be signed by the outgoing intermediate: %v", err)
	}
	if !listsSerial(outList, old.Certificate.SerialNumber) {
		t.Fatal("the certificate the outgoing intermediate issued is missing from its own CRL; a verifier would treat it as not revoked")
	}
	if listsSerial(outList, fresh.Certificate.SerialNumber) {
		t.Fatal("a serial from the incoming intermediate must not appear on the outgoing intermediate's CRL")
	}

	inList := crlFor(t, crls, incoming.SubjectKeyId)
	if err := inList.CheckSignatureFrom(incoming); err != nil {
		t.Fatalf("the incoming intermediate's CRL signature: %v", err)
	}
	if !listsSerial(inList, fresh.Certificate.SerialNumber) {
		t.Fatal("the certificate the incoming intermediate issued is missing from its own CRL")
	}
	if listsSerial(inList, old.Certificate.SerialNumber) {
		t.Fatal("a serial from the outgoing intermediate must not appear on the incoming intermediate's CRL")
	}
}

// TestRevokeAcceptsAnAlreadyExpiredCertificate: verification runs at the
// certificate's own NotBefore, so expiry does not block a revocation. Whether
// we issued it and whether it has expired are unrelated questions.
func TestRevokeAcceptsAnAlreadyExpiredCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca := newTestCA(t)

	svid, err := ca.IssueSVID(ctx, SVIDRequest{ID: deviceID("claude"), PublicKey: newSVIDKey(t).Public()})
	if err != nil {
		t.Fatal(err)
	}
	ca.clk.advance(2 * time.Hour) // past the leaf's one-hour lifetime
	if err := ca.Revoke(ctx, RevocationRequest{Certificate: svid.Certificate, Reason: ReasonKeyCompromise}); err != nil {
		t.Fatalf("revoking an expired certificate: %v", err)
	}
}
