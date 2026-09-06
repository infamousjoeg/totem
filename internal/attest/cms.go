package attest

// CMS (PKCS#7 SignedData) verification for Mach-O code signatures, in pure Go
// with the standard library only. This is the part that turns "the file says
// it was signed by Team ID X" into "Team ID X's key signed this file": it
// checks the signer's signature over the signed attributes, checks that the
// messageDigest attribute is the hash of the CodeDirectory, and builds the
// certificate chain from the signing certificate to a trusted root. Without
// this step the Team ID and identifier are strings anyone can write.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	// Apple's signed cdhashes attributes: a plist (…9.1) and a DER set (…9.2)
	// listing the cdhash of every CodeDirectory in the signature.
	oidAttrAppleCDHashesPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	oidAttrAppleCDHashesDER   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	oidDigestSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// oidAppleDeveloperIDApplication is the certificate extension Apple puts
	// on a "Developer ID Application" leaf. It is what codesign's designated
	// requirement for Developer ID checks, and what this package requires on
	// the leaf of a vendor-signed catalog binary.
	oidAppleDeveloperIDApplication = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 13}
	// oidAppleCodeSigningCA marks Apple's own "Apple Code Signing
	// Certification Authority" intermediate, the issuer of the "Software
	// Signing" leaves on macOS platform binaries (observed on macOS 26).
	oidAppleCodeSigningCA = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 20}
	// oidAppleSoftwareSigning marks the "macOS Software Signing" leaf itself.
	oidAppleSoftwareSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 22}
)

// isAppleCodeSigningChain reports whether a verified chain is Apple's own
// platform chain: anchored at the embedded Apple Root CA, and passing through
// Apple's code-signing CA (by marker extension) or ending in a leaf that
// carries Apple's software-signing marker. Chain names are not consulted.
//
// Which branch holds the weight, on the real chains pinned under testdata/:
// BOTH known Apple platform leaves carry the software-signing marker 6.22
// (the 2020 "Software Signing" leaf on Command Line Tools binaries and the
// July-2026 macos-26 CI image; the 2026 "macOS Software Signing" leaf on
// macOS 26.6), so the leaf branch is what accepts every known input today.
// The CA branch is reachable but not sole for anything: the 2017 "Apple Code
// Signing Certification Authority" intermediate (the /bin/zsh chain) carries
// 6.2.20, while the 2011 intermediate of the same name (the Command Line
// Tools chain, expiring 2026-10-24 with its leaf) carries no Apple marker at
// all. TestAppleChainMarkerWitnesses pins those facts. If Apple ships a leaf
// without 6.22 under the 2017 CA the second branch carries it; under a CA
// without 6.2.20 nothing does, and that is a new certificate to look at, not
// a case to guess at.
func isAppleCodeSigningChain(chain []*x509.Certificate) bool {
	if len(chain) < 2 {
		return false
	}
	root := chain[len(chain)-1]
	anchored := false
	for _, r := range appleRoots() {
		if bytes.Equal(r.Raw, root.Raw) {
			anchored = true
		}
	}
	if !anchored {
		return false
	}
	if hasExtension(chain[0], oidAppleSoftwareSigning) {
		return true
	}
	for _, c := range chain[1 : len(chain)-1] {
		if hasExtension(c, oidAppleCodeSigningCA) {
			return true
		}
	}
	return false
}

// ASN.1 shapes from RFC 5652, only as much as a code signature needs.
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []cmsAlgorithmIdentifier `asn1:"set"`
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    cmsAlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm cmsAlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// cmsAppleCDHash is one value of the …100.9.2 attribute: the attribute's SET
// holds one SEQUENCE { hashAlgorithm OID, OCTET STRING cdhash } per
// CodeDirectory (observed on macOS 26 platform and Developer ID signatures).
type cmsAppleCDHash struct {
	Algorithm asn1.ObjectIdentifier
	Hash      []byte
}

// cmsResult is a verified CMS signature over a CodeDirectory.
type cmsResult struct {
	// chain is leaf first, trusted root last.
	chain []*x509.Certificate
	// signedAt is the signingTime attribute, zero if absent.
	signedAt time.Time
	// cdHashes are the 20-byte cdhashes the signer vouched for, from Apple's
	// signed cdhashes attribute. Empty when the attribute is absent.
	cdHashes [][]byte
}

// errCMS wraps every CMS verification failure so callers can tell a broken
// signature from a broken file.
var errCMS = errors.New("attest: CMS signature verification failed")

func cmsErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errCMS, fmt.Sprintf(format, a...))
}

// verifyCMS verifies the detached CMS signature cms over the primary
// CodeDirectory blob cd, and chains the signer to one of roots. It returns an
// error unless the signature is valid, the messageDigest matches cd, and the
// chain reaches a root. Certificate validity is judged at the signing time
// the signer asserted (falling back to now), because Apple code signatures
// outlive their certificates by design; see the package TODO on timestamps.
func verifyCMS(cms []byte, cd []byte, roots []*x509.Certificate) (*cmsResult, error) {
	// Apple emits BER with indefinite lengths; normalise to DER first.
	der, err := berToDER(cms)
	if err != nil {
		return nil, cmsErr("normalising BER: %v", err)
	}
	var ci cmsContentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, cmsErr("parsing ContentInfo: %v", err)
	}
	if len(rest) != 0 {
		return nil, cmsErr("trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, cmsErr("content type %v is not SignedData", ci.ContentType)
	}
	var sd cmsSignedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, cmsErr("parsing SignedData: %v", err)
	} else if len(rest) != 0 {
		return nil, cmsErr("trailing data after SignedData")
	}
	if len(sd.SignerInfos) != 1 {
		return nil, cmsErr("expected exactly one signer, found %d", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]

	certs, err := parseCMSCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, err
	}
	signer, err := findSigner(certs, si.SID)
	if err != nil {
		return nil, err
	}

	// Signed attributes are mandatory here: a signature directly over the
	// content would have no messageDigest binding and no signing time.
	if len(si.SignedAttrs.FullBytes) == 0 {
		return nil, cmsErr("signer has no signed attributes")
	}
	attrs, err := parseAttributes(si.SignedAttrs.Bytes)
	if err != nil {
		return nil, err
	}
	res := &cmsResult{}

	// messageDigest must be the digest of the CodeDirectory under the
	// signer's digest algorithm.
	digestHash, ok := hashForDigestOID(si.DigestAlgorithm.Algorithm)
	if !ok {
		return nil, cmsErr("unsupported digest algorithm %v", si.DigestAlgorithm.Algorithm)
	}
	md, ok := attrs[oidAttrMessageDigest.String()]
	if !ok {
		return nil, cmsErr("no messageDigest attribute")
	}
	var mdBytes []byte
	if _, err := asn1.Unmarshal(md, &mdBytes); err != nil {
		return nil, cmsErr("parsing messageDigest: %v", err)
	}
	if !bytes.Equal(mdBytes, sum(digestHash, cd)) {
		return nil, cmsErr("messageDigest does not match the CodeDirectory")
	}
	// RFC 5652 §11.1: when signed attributes are present, contentType MUST
	// be among them and MUST equal the encapsulated content type.
	ct, ok := attrs[oidAttrContentType.String()]
	if !ok {
		return nil, cmsErr("no contentType attribute")
	}
	var ctOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ct, &ctOID); err != nil || !ctOID.Equal(oidData) {
		return nil, cmsErr("contentType attribute is not id-data")
	}
	if st, ok := attrs[oidAttrSigningTime.String()]; ok {
		var t time.Time
		if _, err := asn1.Unmarshal(st, &t); err != nil {
			return nil, cmsErr("parsing signingTime: %v", err)
		}
		res.signedAt = t
	}
	if v, ok := attrs[oidAttrAppleCDHashesDER.String()]; ok {
		for len(v) > 0 {
			var e cmsAppleCDHash
			rest, err := asn1.Unmarshal(v, &e)
			if err != nil {
				return nil, cmsErr("parsing Apple cdhashes attribute: %v", err)
			}
			if len(e.Hash) >= cdHashLen {
				res.cdHashes = append(res.cdHashes, e.Hash[:cdHashLen])
			}
			v = rest
		}
	} else if v, ok := attrs[oidAttrAppleCDHashesPlist.String()]; ok {
		res.cdHashes = cdHashesFromPlist(v)
	}

	// The signature is over the DER of the signed attributes re-tagged as a
	// SET OF (RFC 5652 §5.4): swap the IMPLICIT [0] for the universal SET tag.
	signed := append([]byte(nil), si.SignedAttrs.FullBytes...)
	signed[0] = 0x31
	if err := verifySignature(signer, si.SignatureAlgorithm.Algorithm, digestHash, signed, si.Signature); err != nil {
		return nil, err
	}

	at := res.signedAt
	if at.IsZero() {
		at = time.Now()
	}
	chain, err := buildChain(signer, certs, roots, at)
	if err != nil {
		return nil, err
	}
	if err := checkPathLen(chain); err != nil {
		return nil, err
	}
	res.chain = chain
	return res, nil
}

// parseCMSCertificates splits the [0] IMPLICIT SET OF CertificateChoices.
func parseCMSCertificates(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(b) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(b, &rv)
		if err != nil {
			return nil, cmsErr("parsing certificates: %v", err)
		}
		if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
			c, err := x509.ParseCertificate(rv.FullBytes)
			if err != nil {
				return nil, cmsErr("parsing certificate: %v", err)
			}
			certs = append(certs, c)
		}
		// Other CertificateChoices (attribute certs, OtherCertificateFormat)
		// are skipped; they cannot sign anything here.
		b = rest
	}
	if len(certs) == 0 {
		return nil, cmsErr("no certificates in signature")
	}
	return certs, nil
}

// findSigner resolves the SignerIdentifier to a certificate. Only the
// IssuerAndSerialNumber form is accepted; Apple uses it exclusively.
func findSigner(certs []*x509.Certificate, sid asn1.RawValue) (*x509.Certificate, error) {
	if sid.Class != asn1.ClassUniversal || sid.Tag != asn1.TagSequence {
		return nil, cmsErr("unsupported SignerIdentifier form")
	}
	var ias cmsIssuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil, cmsErr("parsing IssuerAndSerialNumber: %v", err)
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c, nil
		}
	}
	return nil, cmsErr("signer certificate not present in signature")
}

// parseAttributes returns the concatenated DER values of each signed
// attribute, keyed by OID string. Most attributes have exactly one value.
func parseAttributes(b []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	for len(b) > 0 {
		var a cmsAttribute
		rest, err := asn1.Unmarshal(b, &a)
		if err != nil {
			return nil, cmsErr("parsing signed attribute: %v", err)
		}
		if _, dup := out[a.Type.String()]; dup {
			return nil, cmsErr("duplicate signed attribute %v", a.Type)
		}
		out[a.Type.String()] = a.Values.Bytes
		b = rest
	}
	return out, nil
}

// cdHashesFromPlist pulls the <data> elements out of Apple's plist cdhashes
// attribute without a plist parser: each is base64 of a 20-byte cdhash.
func cdHashesFromPlist(der []byte) [][]byte {
	var body []byte
	if _, err := asn1.Unmarshal(der, &body); err != nil {
		return nil
	}
	var out [][]byte
	rest := body
	for {
		i := bytes.Index(rest, []byte("<data>"))
		if i < 0 {
			break
		}
		rest = rest[i+len("<data>"):]
		j := bytes.Index(rest, []byte("</data>"))
		if j < 0 {
			break
		}
		raw := bytes.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
				return -1
			}
			return r
		}, rest[:j])
		h, err := base64.StdEncoding.DecodeString(string(raw))
		if err == nil && len(h) >= cdHashLen {
			out = append(out, h[:cdHashLen])
		}
		rest = rest[j:]
	}
	return out
}

func hashForDigestOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidDigestSHA1):
		return crypto.SHA1, true
	case oid.Equal(oidDigestSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidDigestSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidDigestSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

func sum(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(b)
		return s[:]
	case crypto.SHA256:
		s := sha256.Sum256(b)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(b)
		return s[:]
	}
	return nil
}

// verifySignature checks sig over msg with the signer's public key. The
// signature algorithm may name the hash itself (sha256WithRSAEncryption) or
// defer to the digest algorithm (plain rsaEncryption, which is what Apple's
// codesign emits).
func verifySignature(signer *x509.Certificate, alg asn1.ObjectIdentifier, digest crypto.Hash, msg, sig []byte) error {
	h := digest
	switch {
	case alg.Equal(oidRSAEncryption):
	case alg.Equal(oidSHA1WithRSA):
		h = crypto.SHA1
	case alg.Equal(oidSHA256WithRSA):
		h = crypto.SHA256
	case alg.Equal(oidSHA384WithRSA):
		h = crypto.SHA384
	case alg.Equal(oidSHA512WithRSA):
		h = crypto.SHA512
	case alg.Equal(oidECDSAWithSHA256):
		h = crypto.SHA256
	case alg.Equal(oidECDSAWithSHA384):
		h = crypto.SHA384
	case alg.Equal(oidECDSAWithSHA512):
		h = crypto.SHA512
	default:
		return cmsErr("unsupported signature algorithm %v", alg)
	}
	d := sum(h, msg)
	switch pub := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, h, d, sig); err != nil {
			return cmsErr("signer signature invalid: %v", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, d, sig) {
			return cmsErr("signer signature invalid")
		}
	default:
		return cmsErr("unsupported signer key type %T", signer.PublicKey)
	}
	return nil
}

// buildChain walks issuer links from leaf through certs until it reaches one
// of roots, verifying every signature and every CA flag along the way. Each
// certificate must be valid at time at.
func buildChain(leaf *x509.Certificate, certs, roots []*x509.Certificate, at time.Time) ([]*x509.Certificate, error) {
	if len(roots) == 0 {
		return nil, cmsErr("no trusted roots configured")
	}
	chain := []*x509.Certificate{leaf}
	cur := leaf
	for depth := 0; depth < 8; depth++ {
		if err := checkValidity(cur, at); err != nil {
			return nil, err
		}
		for _, r := range roots {
			if bytes.Equal(r.RawSubject, cur.RawIssuer) {
				if err := checkSignatureFrom(cur, r); err == nil {
					if err := checkValidity(r, at); err != nil {
						return nil, err
					}
					return append(chain, r), nil
				}
			}
		}
		var parent *x509.Certificate
		for _, c := range certs {
			if c == cur || !bytes.Equal(c.RawSubject, cur.RawIssuer) {
				continue
			}
			if !c.BasicConstraintsValid || !c.IsCA {
				continue
			}
			if err := checkSignatureFrom(cur, c); err == nil {
				parent = c
				break
			}
		}
		if parent == nil {
			return nil, cmsErr("no issuer found for %q: chain does not reach a trusted root", cur.Subject.CommonName)
		}
		for _, seen := range chain {
			if seen == parent {
				return nil, cmsErr("certificate chain loops")
			}
		}
		chain = append(chain, parent)
		cur = parent
	}
	return nil, cmsErr("certificate chain too long")
}

// checkPathLen enforces RFC 5280 pathLenConstraint over a built chain (leaf
// first, root last): a CA with a constraint may have at most that many CA
// certificates below it, not counting the leaf.
func checkPathLen(chain []*x509.Certificate) error {
	for i := 1; i < len(chain); i++ {
		ca := chain[i]
		if !ca.BasicConstraintsValid {
			continue
		}
		constrained := ca.MaxPathLen > 0 || (ca.MaxPathLen == 0 && ca.MaxPathLenZero)
		if !constrained {
			continue
		}
		below := i - 1 // CA certificates between this one and the leaf
		if below > ca.MaxPathLen {
			return cmsErr("certificate %q allows %d subordinate CA(s) but %d were used", ca.Subject.CommonName, ca.MaxPathLen, below)
		}
	}
	return nil
}

func checkValidity(c *x509.Certificate, at time.Time) error {
	if at.Before(c.NotBefore) || at.After(c.NotAfter) {
		return cmsErr("certificate %q not valid at %s (valid %s to %s)", c.Subject.CommonName, at.UTC().Format(time.RFC3339), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkSignatureFrom verifies child's signature with parent's key. Go's
// x509 rejects SHA-1 signatures outright; older Apple intermediates carry
// them, so that one case is verified explicitly here rather than refused.
func checkSignatureFrom(child, parent *x509.Certificate) error {
	err := child.CheckSignatureFrom(parent)
	var insecure x509.InsecureAlgorithmError
	if err == nil || !errors.As(err, &insecure) {
		return err
	}
	if child.SignatureAlgorithm != x509.SHA1WithRSA {
		return err
	}
	pub, ok := parent.PublicKey.(*rsa.PublicKey)
	if !ok {
		return err
	}
	d := sha1.Sum(child.RawTBSCertificate)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA1, d[:], child.Signature)
}

// hasExtension reports whether c carries the extension oid.
func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// subjectOU returns the first OU of a certificate subject. Apple puts the
// Team ID there on Developer ID leaves.
func subjectOU(name pkix.Name) string {
	if len(name.OrganizationalUnit) == 0 {
		return ""
	}
	return name.OrganizationalUnit[0]
}
