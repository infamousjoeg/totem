package attest

// A miniature codesign for tests: a throwaway CA shaped like Apple's Developer
// ID chain, and a re-signer that replaces the linker's ad-hoc signature on a
// Go-built Mach-O with a real CodeDirectory plus CMS signature from that CA.
// This is what makes the suite hermetic: fixtures are built and signed on the
// fly, and the attestor is pointed at the test root instead of Apple's.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	root, inter, leaf *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
	leafKey           *ecdsa.PrivateKey
	team              string
}

type testCAOptions struct {
	team        string
	noDevIDMark bool
	// leafOU overrides the OU on the leaf; empty means the team.
	leafOU string
	// parent, when set, issues the leaf under parent's root and
	// intermediate instead of generating a new CA.
	parent *testCA
}

func newTestCA(t testing.TB) *testCA {
	return newTestCAWith(t, testCAOptions{team: "TESTTEAM01"})
}

func newTestCAWith(t testing.TB, o testCAOptions) *testCA {
	t.Helper()
	if o.team == "" {
		o.team = "TESTTEAM01"
	}
	mk := func(tmpl, parent *x509.Certificate, pub any, priv *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now().Add(-time.Hour)
	var root, inter *x509.Certificate
	var rootKey, interKey *ecdsa.PrivateKey
	if o.parent != nil {
		root, inter, rootKey, interKey = o.parent.root, o.parent.inter, o.parent.rootKey, o.parent.interKey
	} else {
		rootKey = key()
		rootTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test Root CA", Organization: []string{"totem tests"}},
			NotBefore:             now,
			NotAfter:              now.Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		root = mk(rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

		interKey = key()
		interTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "Test Developer ID Certification Authority", Organization: []string{"totem tests"}},
			NotBefore:             now,
			NotAfter:              now.Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		inter = mk(interTmpl, root, &interKey.PublicKey, rootKey)
	}

	leafKey := key()
	ou := o.leafOU
	if ou == "" {
		ou = o.team
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:         fmt.Sprintf("Developer ID Application: Test (%s)", o.team),
			OrganizationalUnit: []string{ou},
			Organization:       []string{"Test"},
		},
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if !o.noDevIDMark {
		leafTmpl.ExtraExtensions = []pkix.Extension{{Id: oidAppleDeveloperIDApplication, Critical: true, Value: []byte{0x05, 0x00}}}
	}
	leaf := mk(leafTmpl, inter, &leafKey.PublicKey, interKey)
	return &testCA{root: root, inter: inter, leaf: leaf, rootKey: rootKey, interKey: interKey, leafKey: leafKey, team: o.team}
}

func (c *testCA) roots() []*x509.Certificate { return []*x509.Certificate{c.root} }

// signOptions tune the re-signer for negative tests.
type signOptions struct {
	// adhoc emits a CodeDirectory flagged ad-hoc with no CMS blob.
	adhoc bool
	// team overrides the CodeDirectory team id; empty uses the CA's team.
	team string
	// noTeam leaves the team id out entirely.
	noTeam bool
	// platform sets the CodeDirectory platform byte.
	platform uint8
	// wrongDigest makes the CMS messageDigest cover a different blob.
	wrongDigest bool
	// noSpecial emits no special slots and no requirements blob.
	noSpecial bool
	// rawFlags, when non-zero, overrides the CodeDirectory flags word.
	rawFlags uint32
}

// Mach-O load command layout constants for the re-signer.
const (
	lcSegment64 = 0x19
	machoHeader = 32
	pageShift   = 12
	cdHeaderLen = 88 // CodeDirectory v0x20400
)

// resignMachO replaces the signature on a thin 64-bit Mach-O (as Go's linker
// emits) with one from ca. ident is the signing identifier.
func resignMachO(in []byte, ident string, ca *testCA, o signOptions) ([]byte, error) {
	if len(in) < machoHeader || binary.LittleEndian.Uint32(in) != 0xfeedfacf {
		return nil, errors.New("not a thin 64-bit little-endian mach-o")
	}
	ncmds := binary.LittleEndian.Uint32(in[16:])
	var sigCmdOff, linkeditOff int = -1, -1
	var textOff, textSize uint64
	off := machoHeader
	for i := uint32(0); i < ncmds; i++ {
		cmd := binary.LittleEndian.Uint32(in[off:])
		size := binary.LittleEndian.Uint32(in[off+4:])
		switch cmd {
		case lcCodeSignature:
			sigCmdOff = off
		case lcSegment64:
			name := string(bytes.TrimRight(in[off+8:off+24], "\x00"))
			switch name {
			case "__LINKEDIT":
				linkeditOff = off
			case "__TEXT":
				textOff = binary.LittleEndian.Uint64(in[off+40:])
				textSize = binary.LittleEndian.Uint64(in[off+48:])
			}
		}
		off += int(size)
	}
	if sigCmdOff < 0 || linkeditOff < 0 {
		return nil, errors.New("mach-o lacks LC_CODE_SIGNATURE or __LINKEDIT")
	}
	dataOff := binary.LittleEndian.Uint32(in[sigCmdOff+8:])
	body := append([]byte(nil), in[:dataOff]...)

	team := ca.team
	if o.team != "" {
		team = o.team
	}
	if o.noTeam {
		team = ""
	}
	nCode := (uint64(dataOff) + (1 << pageShift) - 1) >> pageShift
	nSpecial := 2
	if o.noSpecial {
		nSpecial = 0
	}
	identOff := cdHeaderLen
	teamOff := identOff + len(ident) + 1
	hashBase := teamOff
	if team != "" {
		hashBase += len(team) + 1
	}
	hashOff := hashBase + nSpecial*sha256.Size
	cdLen := hashOff + int(nCode)*sha256.Size
	// The final blob size is fixed before hashing (the header carries it and
	// the header is inside the hashed range); the CMS is padded to fit.
	dataSize := uint32(roundUp(12+3*8+cdLen+12+8+8192, 16))

	// Patch the header: LC_CODE_SIGNATURE.datasize, __LINKEDIT filesize/vmsize.
	binary.LittleEndian.PutUint32(body[sigCmdOff+12:], dataSize)
	leFileOff := binary.LittleEndian.Uint64(body[linkeditOff+40:])
	leFileSize := uint64(dataOff) + uint64(dataSize) - leFileOff
	binary.LittleEndian.PutUint64(body[linkeditOff+48:], leFileSize)
	binary.LittleEndian.PutUint64(body[linkeditOff+32:], uint64(roundUp(int(leFileSize), 16384)))

	// Requirements: an empty requirements vector.
	reqs := make([]byte, 12)
	binary.BigEndian.PutUint32(reqs, csMagicRequirements)
	binary.BigEndian.PutUint32(reqs[4:], 12)

	cd := make([]byte, cdLen)
	be := binary.BigEndian
	be.PutUint32(cd[0:], csMagicCodeDirectory)
	be.PutUint32(cd[4:], uint32(cdLen))
	be.PutUint32(cd[8:], 0x20400)
	flags := uint32(0)
	if o.adhoc {
		flags |= cdFlagAdhoc
	}
	if o.rawFlags != 0 {
		flags = o.rawFlags
	}
	be.PutUint32(cd[12:], flags)
	be.PutUint32(cd[16:], uint32(hashOff))
	be.PutUint32(cd[20:], uint32(identOff))
	be.PutUint32(cd[24:], uint32(nSpecial))
	be.PutUint32(cd[28:], uint32(nCode))
	be.PutUint32(cd[32:], dataOff)
	cd[36] = sha256.Size
	cd[37] = csHashTypeSHA256
	cd[38] = o.platform
	cd[39] = pageShift
	if team != "" {
		be.PutUint32(cd[48:], uint32(teamOff))
	}
	be.PutUint64(cd[64:], textOff)
	be.PutUint64(cd[72:], textSize)
	be.PutUint64(cd[80:], 1) // CS_EXECSEG_MAIN_BINARY
	copy(cd[identOff:], ident)
	if team != "" {
		copy(cd[teamOff:], team)
	}
	if !o.noSpecial {
		rh := sha256.Sum256(reqs)
		copy(cd[hashOff-2*sha256.Size:], rh[:]) // special slot 2
	}
	for i := uint64(0); i < nCode; i++ {
		start := i << pageShift
		end := start + (1 << pageShift)
		if end > uint64(dataOff) {
			end = uint64(dataOff)
		}
		h := sha256.Sum256(body[start:end])
		copy(cd[hashOff+int(i)*sha256.Size:], h[:])
	}

	blobs := [][2]any{{uint32(csSlotCodeDirectory), cd}}
	if !o.noSpecial {
		blobs = append(blobs, [2]any{uint32(csSlotRequirements), reqs})
	}
	if !o.adhoc {
		digestOver := cd
		if o.wrongDigest {
			digestOver = reqs
		}
		cms, err := buildCMS(ca, digestOver)
		if err != nil {
			return nil, err
		}
		wrapper := make([]byte, 8+len(cms))
		be.PutUint32(wrapper, csMagicBlobWrapper)
		be.PutUint32(wrapper[4:], uint32(len(wrapper)))
		copy(wrapper[8:], cms)
		blobs = append(blobs, [2]any{uint32(csSlotSignature), wrapper})
	}
	sb := make([]byte, 12+8*len(blobs))
	be.PutUint32(sb, csMagicEmbeddedSignature)
	be.PutUint32(sb[8:], uint32(len(blobs)))
	cur := len(sb)
	for i, b := range blobs {
		be.PutUint32(sb[12+i*8:], b[0].(uint32))
		be.PutUint32(sb[16+i*8:], uint32(cur))
		cur += len(b[1].([]byte))
	}
	be.PutUint32(sb[4:], uint32(cur))
	for _, b := range blobs {
		sb = append(sb, b[1].([]byte)...)
	}
	if len(sb) > int(dataSize) {
		return nil, fmt.Errorf("signature %d bytes exceeds reserved %d", len(sb), dataSize)
	}
	out := append(body, sb...)
	out = append(out, make([]byte, int(dataSize)-len(sb))...)
	return out, nil
}

func roundUp(n, to int) int { return (n + to - 1) / to * to }

// cmsSignedDataOut mirrors cmsSignedData for marshaling.
type cmsSignedDataOut struct {
	Version          int
	DigestAlgorithms []cmsAlgorithmIdentifier `asn1:"set"`
	EncapContentInfo struct {
		ContentType asn1.ObjectIdentifier
	}
	Certificates asn1.RawValue      `asn1:"tag:0"`
	SignerInfos  []cmsSignerInfoOut `asn1:"set"`
}

type cmsSignerInfoOut struct {
	Version            int
	SID                cmsIssuerAndSerial
	DigestAlgorithm    cmsAlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"tag:0"`
	SignatureAlgorithm cmsAlgorithmIdentifier
	Signature          []byte
}

type cmsAttributeOut struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// buildCMS produces a detached SignedData over content signed by ca's leaf.
func buildCMS(ca *testCA, content []byte) ([]byte, error) {
	digest := sha256.Sum256(content)
	mkAttr := func(oid asn1.ObjectIdentifier, v any) (cmsAttributeOut, error) {
		der, err := asn1.Marshal(v)
		if err != nil {
			return cmsAttributeOut{}, err
		}
		return cmsAttributeOut{Type: oid, Values: []asn1.RawValue{{FullBytes: der}}}, nil
	}
	a1, err := mkAttr(oidAttrContentType, oidData)
	if err != nil {
		return nil, err
	}
	a2, err := mkAttr(oidAttrSigningTime, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return nil, err
	}
	a3, err := mkAttr(oidAttrMessageDigest, digest[:])
	if err != nil {
		return nil, err
	}
	attrs := []cmsAttributeOut{a1, a2, a3}
	// Encode as SET OF (what is signed), then retag as [0] IMPLICIT.
	setDER, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, err
	}
	signedDigest := sha256.Sum256(setDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ca.leafKey, signedDigest[:])
	if err != nil {
		return nil, err
	}
	implicit := append([]byte(nil), setDER...)
	implicit[0] = 0xA0

	var certs []byte
	for _, c := range []*x509.Certificate{ca.leaf, ca.inter, ca.root} {
		certs = append(certs, c.Raw...)
	}
	var issuer asn1.RawValue
	if _, err := asn1.Unmarshal(ca.leaf.RawIssuer, &issuer); err != nil {
		return nil, err
	}
	sd := cmsSignedDataOut{
		Version:          1,
		DigestAlgorithms: []cmsAlgorithmIdentifier{{Algorithm: oidDigestSHA256, Parameters: asn1.NullRawValue}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs},
		SignerInfos: []cmsSignerInfoOut{{
			Version:            1,
			SID:                cmsIssuerAndSerial{Issuer: issuer, Serial: ca.leaf.SerialNumber},
			DigestAlgorithm:    cmsAlgorithmIdentifier{Algorithm: oidDigestSHA256, Parameters: asn1.NullRawValue},
			SignedAttrs:        asn1.RawValue{FullBytes: implicit},
			SignatureAlgorithm: cmsAlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
			Signature:          sig,
		}},
	}
	sd.EncapContentInfo.ContentType = oidData
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	// asn1.Marshal emits a RawValue's FullBytes verbatim, ignoring explicit
	// tagging, so the [0] EXPLICIT wrapper is built by hand.
	ci := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}}
	return asn1.Marshal(ci)
}
