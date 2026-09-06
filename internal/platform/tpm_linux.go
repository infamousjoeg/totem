//go:build linux

package platform

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// tpmDevicePaths are tried in order. The in-kernel resource manager (tpmrm0)
// is preferred because it multiplexes transient handles between processes;
// the raw device works but a busy TPM can return TPM_RC_OBJECT_MEMORY.
var tpmDevicePaths = []string{"/dev/tpmrm0", "/dev/tpm0"}

// ekCertNVIndices are the TCG-standard NV indices holding the endorsement key
// certificate: ECC P-256 EK first (matches ECCEKTemplate), RSA-2048 EK second.
const (
	nvIndexEKCertECC tpm2.TPMHandle = 0x01C0000A
	nvIndexEKCertRSA tpm2.TPMHandle = 0x01C00002
)

// TPMStore is the Linux hardware level: an ECDSA P-256 device key created
// inside the TPM 2.0 under the storage root key with FixedTPM and FixedParent
// set, so it cannot be exported or re-parented; the TPM-wrapped private blob
// is kept on disk and is unusable on any other TPM. It carries
// ProtectionHardware and proves residency with the EK/AK/device-key chain the
// design calls for ("TPM enrollment includes standard attestation ... verified
// by the issuer in pure Go").
//
// Presence: a TPM has no human-facing input. The spec's Linux presence types
// (TPM PIN, passkey or FIDO touch, approval from another enrolled device) all
// need a trusted channel to a human that this package does not have and the
// Prompt type does not carry, so Sign with Required=true returns
// ErrPresenceUnavailable and the credential records presence "none". A PIN
// read by the agent from a socket or the environment would be a durable
// secret on the laptop and is not a presence check; it is deliberately not
// implemented.
type TPMStore struct {
	device string
	dir    string
}

// tpmKeyFile is the on-disk record for one TPM key: the TPM2B_PUBLIC and the
// TPM2B_PRIVATE (encrypted by the TPM under the SRK seed). Neither is secret in
// the sense of being usable elsewhere; the private blob only loads into the
// TPM that created it.
type tpmKeyFile struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

// NewTPMStore returns a TPMStore using the first device path that opens and
// answers TPM2_GetCapability, or an error naming what was tried. dir is where
// wrapped key blobs live; empty means <state dir>/tpm.
func NewTPMStore(dir string) (*TPMStore, error) {
	device, reason := tpmProbe()
	if device == "" {
		return nil, fmt.Errorf("platform: %s", reason)
	}
	if dir == "" {
		base, err := stateDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "tpm")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("platform: creating tpm key directory: %w", err)
	}
	return &TPMStore{device: device, dir: dir}, nil
}

// tpmProbe returns the usable device path, or "" and a one-line reason.
func tpmProbe() (string, string) {
	var last string
	for _, p := range tpmDevicePaths {
		if _, err := os.Stat(p); err != nil {
			last = fmt.Sprintf("%s: %v", p, err)
			continue
		}
		t, err := linuxtpm.Open(p)
		if err != nil {
			last = fmt.Sprintf("%s: %v", p, err)
			continue
		}
		_, err = tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(tpm2.TPMPTFamilyIndicator),
			PropertyCount: 1,
		}.Execute(t)
		t.Close()
		if err != nil {
			last = fmt.Sprintf("%s: GetCapability: %v", p, err)
			continue
		}
		return p, ""
	}
	if last == "" {
		last = "no TPM device present"
	}
	return "", "no usable TPM 2.0: " + last
}

func tpmCandidate() Candidate {
	c := Candidate{Name: "tpm", Level: spiffe.ProtectionHardware, Available: true,
		Reason: "presence unavailable: TPM has no human-facing input, credential records presence none"}
	if dev, reason := tpmProbe(); dev == "" {
		c.Available = false
		c.Reason = reason
	}
	return c
}

// ProtectionLevel is ProtectionHardware, queryable before any key exists.
func (s *TPMStore) ProtectionLevel() spiffe.ProtectionLevel {
	return spiffe.ProtectionHardware
}

func (s *TPMStore) path(label string) string   { return filepath.Join(s.dir, label+".tpm") }
func (s *TPMStore) akPath(label string) string { return filepath.Join(s.dir, label+".ak.tpm") }

func (s *TPMStore) open() (transport.TPMCloser, error) {
	t, err := linuxtpm.Open(s.device)
	if err != nil {
		return nil, fmt.Errorf("platform: opening %s: %w", s.device, err)
	}
	return t, nil
}

// deviceKeyTemplate is the device key: ECC P-256, ECDSA/SHA-256, non-restricted
// signing key, FixedTPM+FixedParent (never leaves this TPM), SensitiveDataOrigin
// (the TPM generated it), UserWithAuth with an empty auth value. NoDA is set
// because there is no PIN to brute-force and a lockout would only deny service.
var deviceKeyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
}

// akTemplate is the attestation key: a restricted ECDSA P-256 signing key, so
// its signatures over TPM2_Certify output are only ever over TPM-generated
// attestation structures (the TPM refuses to Sign external data with it).
var akTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		Restricted:          true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
}

// createSRK derives the storage root key (owner hierarchy, TCG ECC SRK
// template). The SRK is deterministic for a given TPM and storage seed, so it
// never needs persisting; every session recreates it and flushes it.
func createSRK(t transport.TPM) (*tpm2.NamedHandle, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("platform: creating SRK: %w", err)
	}
	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	flush := func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	return h, flush, nil
}

// createUnderSRK creates a key from tmpl under the SRK and returns its
// on-disk record without loading it.
func createUnderSRK(t transport.TPM, srk *tpm2.NamedHandle, tmpl tpm2.TPMTPublic) (*tpmKeyFile, error) {
	rsp, err := tpm2.Create{
		ParentHandle: srk,
		InPublic:     tpm2.New2B(tmpl),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("platform: TPM2_Create: %w", err)
	}
	return &tpmKeyFile{
		Public:  tpm2.Marshal(&rsp.OutPublic),
		Private: tpm2.Marshal(&rsp.OutPrivate),
	}, nil
}

// loadUnderSRK loads a stored key blob under the SRK and returns its handle,
// its parsed public area, and a flush func.
func loadUnderSRK(t transport.TPM, srk *tpm2.NamedHandle, rec *tpmKeyFile) (*tpm2.NamedHandle, *tpm2.TPMTPublic, func(), error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](rec.Public)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("platform: decoding stored public: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](rec.Private)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("platform: decoding stored private: %w", err)
	}
	rsp, err := tpm2.Load{ParentHandle: srk, InPrivate: *priv, InPublic: *pub}.Execute(t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("platform: TPM2_Load: %w", err)
	}
	contents, err := pub.Contents()
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
		return nil, nil, nil, fmt.Errorf("platform: stored public has no contents: %w", err)
	}
	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	flush := func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	return h, contents, flush, nil
}

// publicFromRecord converts a stored TPM2B_PUBLIC to a Go *ecdsa.PublicKey.
func publicFromRecord(rec *tpmKeyFile) (*ecdsa.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](rec.Public)
	if err != nil {
		return nil, fmt.Errorf("platform: decoding stored public: %w", err)
	}
	contents, err := pub.Contents()
	if err != nil {
		return nil, err
	}
	return ecdsaFromTPMTPublic(contents)
}

func ecdsaFromTPMTPublic(p *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	parms, err := p.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("platform: TPM key is not ECC: %w", err)
	}
	point, err := p.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("platform: TPM key has no ECC point: %w", err)
	}
	if parms.CurveID != tpm2.TPMECCNistP256 {
		return nil, errors.New("platform: TPM key is not P-256")
	}
	return tpm2.ECDSAPub(parms, point)
}

func (s *TPMStore) readRecord(p string) (*tpmKeyFile, error) {
	if err := checkKeyFile(p); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("platform: reading tpm key record: %w", err)
	}
	var rec tpmKeyFile
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("platform: parsing tpm key record: %w", err)
	}
	return &rec, nil
}

func writeRecord(p string, rec *tpmKeyFile) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrKeyExists
		}
		return fmt.Errorf("platform: creating tpm key record: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(p)
		return fmt.Errorf("platform: writing tpm key record: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return err
	}
	return nil
}

// Generate creates the device key and its attestation key inside the TPM under
// label. It returns ErrKeyExists if label already has a record, so enrollment
// cannot orphan a key the issuer still trusts.
func (s *TPMStore) Generate(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.path(label)); err == nil {
		return nil, ErrKeyExists
	}
	t, err := s.open()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	srk, flushSRK, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flushSRK()
	dev, err := createUnderSRK(t, srk, deviceKeyTemplate)
	if err != nil {
		return nil, err
	}
	ak, err := createUnderSRK(t, srk, akTemplate)
	if err != nil {
		return nil, err
	}
	pub, err := publicFromRecord(dev)
	if err != nil {
		return nil, err
	}
	if err := writeRecord(s.path(label), dev); err != nil {
		return nil, err
	}
	if err := writeRecord(s.akPath(label), ak); err != nil {
		os.Remove(s.path(label))
		return nil, err
	}
	return &tpmKey{store: s, label: label, rec: dev, ak: ak, pub: pub}, nil
}

// Load returns the device key under label, or ErrKeyNotFound. The record file
// is checked for ownership and permissions like any software key file.
func (s *TPMStore) Load(ctx context.Context, label string) (Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	dev, err := s.readRecord(s.path(label))
	if err != nil {
		return nil, err
	}
	ak, err := s.readRecord(s.akPath(label))
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	pub, err := publicFromRecord(dev)
	if err != nil {
		return nil, err
	}
	return &tpmKey{store: s, label: label, rec: dev, ak: ak, pub: pub}, nil
}

// Delete removes the device key and attestation key records. With FixedParent
// and no persistent handle, deleting the wrapped blob is what destroys the
// key: nothing else can ever load it again.
func (s *TPMStore) Delete(ctx context.Context, label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}
	err := os.Remove(s.path(label))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("platform: removing tpm key record: %w", err)
	}
	_ = os.Remove(s.akPath(label))
	return nil
}

// tpmKey is a TPM-resident device key. The private half never leaves the TPM;
// Sign loads the wrapped blob, signs inside the TPM, and flushes.
type tpmKey struct {
	store *TPMStore
	label string
	rec   *tpmKeyFile
	ak    *tpmKeyFile
	pub   *ecdsa.PublicKey
}

// Public returns the public half the issuer enrolled.
func (k *tpmKey) Public() crypto.PublicKey { return k.pub }

// ProtectionLevel is ProtectionHardware.
func (k *tpmKey) ProtectionLevel() spiffe.ProtectionLevel { return spiffe.ProtectionHardware }

// PresencePublic is nil: the TPM key has no companion presence key.
func (k *tpmKey) PresencePublic() crypto.PublicKey { return nil }

// Sign signs SHA-256(challenge) inside the TPM and returns ASN.1 DER. With
// prompt.Required it returns ErrPresenceUnavailable: the TPM cannot ask a
// human anything, and this package will not pretend it did.
func (k *tpmKey) Sign(ctx context.Context, challenge []byte, prompt Prompt) ([]byte, error) {
	if prompt.Required {
		return nil, ErrPresenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t, err := k.store.open()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	srk, flushSRK, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flushSRK()
	h, _, flush, err := loadUnderSRK(t, srk, k.rec)
	if err != nil {
		return nil, err
	}
	defer flush()
	digest := sha256.Sum256(challenge)
	rsp, err := tpm2.Sign{
		KeyHandle: h,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("platform: TPM2_Sign: %w", err)
	}
	return tpmSignatureDER(&rsp.Signature)
}

// tpmSignatureDER converts a TPMT_SIGNATURE (ECDSA) to ASN.1 DER SEQUENCE{r,s}.
func tpmSignatureDER(sig *tpm2.TPMTSignature) ([]byte, error) {
	ecc, err := sig.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("platform: TPM signature is not ECDSA: %w", err)
	}
	var rs struct{ R, S *big.Int }
	rs.R = new(big.Int).SetBytes(ecc.SignatureR.Buffer)
	rs.S = new(big.Int).SetBytes(ecc.SignatureS.Buffer)
	return asn1.Marshal(rs)
}

// TPMAttestation is the residency proof for a TPM device key, in the order the
// issuer verifies it: the EK certificate chains to the TPM vendor root; the AK
// is proven to live on the same TPM as the EK by TPM2_ActivateCredential (the
// issuer's MakeCredential challenge, answered by ActivateCredential below); the
// device key is certified by the AK via TPM2_Certify, binding its Name (a hash
// of its public area including FixedTPM/FixedParent) to the AK's signature.
type TPMAttestation struct {
	// EKPublic is the marshaled TPM2B_PUBLIC of the endorsement key.
	EKPublic []byte
	// EKCertificate is the DER X.509 EK certificate read from NV, or nil when
	// the TPM does not carry one (some virtual TPMs). Without it the issuer can
	// verify the chain's internal consistency but not the vendor root.
	EKCertificate []byte
	// AKPublic is the marshaled TPM2B_PUBLIC of the attestation key.
	AKPublic []byte
	// AKName is the TPM2B_NAME of the AK; the issuer binds its MakeCredential
	// challenge to it.
	AKName []byte
	// CertifyInfo is the marshaled TPM2B_ATTEST from TPM2_Certify of the device
	// key by the AK; its ExtraData is the caller's qualifying data.
	CertifyInfo []byte
	// CertifySignature is the ASN.1 DER ECDSA signature over CertifyInfo by the
	// AK.
	CertifySignature []byte
}

// Attester is implemented by hardware keys that can prove residency. Callers
// (enrollment) type-assert for it; Secure Enclave keys do not implement it
// because Apple silicon has no third-party key attestation outside App Attest.
type Attester interface {
	// Attest produces the attestation chain with qualifyingData (an issuer
	// nonce) bound into the certify statement.
	Attest(ctx context.Context, qualifyingData []byte) (*TPMAttestation, error)
	// ActivateCredential answers the issuer's TPM2_MakeCredential challenge,
	// returning the recovered secret only if the AK and EK are on this TPM.
	ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error)
}

// createEK derives the endorsement key (endorsement hierarchy, TCG ECC EK
// template). Its auth policy is PolicySecret(endorsement), which is why every
// use of it below goes through a policy session.
func createEK(t transport.TPM) (*tpm2.NamedHandle, *tpm2.TPM2BPublic, func(), error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("platform: creating EK: %w", err)
	}
	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	flush := func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	return h, &rsp.OutPublic, flush, nil
}

// ekPolicySession returns a policy session satisfying the EK template's
// PolicySecret(endorsement hierarchy) with the (empty) endorsement auth.
func ekPolicySession() tpm2.Session {
	return tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
		_, err := tpm2.PolicySecret{
			AuthHandle:    tpm2.TPMRHEndorsement,
			PolicySession: handle,
			NonceTPM:      nonceTPM,
		}.Execute(t)
		return err
	})
}

// readEKCertificate reads the EK certificate from NV, ECC index first. A
// missing index is not an error; the certificate is reported as absent.
func readEKCertificate(t transport.TPM) []byte {
	for _, idx := range []tpm2.TPMHandle{nvIndexEKCertECC, nvIndexEKCertRSA} {
		pubRsp, err := tpm2.NVReadPublic{NVIndex: idx}.Execute(t)
		if err != nil {
			continue
		}
		nvPub, err := pubRsp.NVPublic.Contents()
		if err != nil {
			continue
		}
		size := int(nvPub.DataSize)
		out := make([]byte, 0, size)
		const chunk = 512
		ok := true
		for off := 0; off < size; off += chunk {
			n := size - off
			if n > chunk {
				n = chunk
			}
			rsp, err := tpm2.NVRead{
				AuthHandle: tpm2.TPMRHOwner,
				NVIndex:    tpm2.NamedHandle{Handle: idx, Name: pubRsp.NVName},
				Size:       uint16(n),
				Offset:     uint16(off),
			}.Execute(t)
			if err != nil {
				ok = false
				break
			}
			out = append(out, rsp.Data.Buffer...)
		}
		if ok {
			return trimDERTrailer(out)
		}
	}
	return nil
}

// trimDERTrailer strips NV padding after the outer DER SEQUENCE, if any.
func trimDERTrailer(b []byte) []byte {
	if len(b) < 4 || b[0] != 0x30 {
		return b
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return b
	}
	return b[:len(b)-len(rest)]
}

// Attest implements Attester.
func (k *tpmKey) Attest(ctx context.Context, qualifyingData []byte) (*TPMAttestation, error) {
	if k.ak == nil {
		return nil, errors.New("platform: no attestation key record for this device key")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t, err := k.store.open()
	if err != nil {
		return nil, err
	}
	defer t.Close()

	ek, ekPub, flushEK, err := createEK(t)
	if err != nil {
		return nil, err
	}
	defer flushEK()
	_ = ek

	srk, flushSRK, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flushSRK()
	akHandle, _, flushAK, err := loadUnderSRK(t, srk, k.ak)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer flushAK()
	devHandle, _, flushDev, err := loadUnderSRK(t, srk, k.rec)
	if err != nil {
		return nil, fmt.Errorf("loading device key: %w", err)
	}
	defer flushDev()

	rsp, err := tpm2.Certify{
		ObjectHandle:   devHandle,
		SignHandle:     akHandle,
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("platform: TPM2_Certify: %w", err)
	}
	sig, err := tpmSignatureDER(&rsp.Signature)
	if err != nil {
		return nil, err
	}
	return &TPMAttestation{
		EKPublic:         tpm2.Marshal(ekPub),
		EKCertificate:    readEKCertificate(t),
		AKPublic:         k.ak.Public,
		AKName:           tpm2.Marshal(&akHandle.Name),
		CertifyInfo:      tpm2.Marshal(&rsp.CertifyInfo),
		CertifySignature: sig,
	}, nil
}

// ActivateCredential implements Attester. credentialBlob and encryptedSecret
// are the issuer's TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET (marshaled) from
// TPM2_MakeCredential against EKPublic and AKName.
func (k *tpmKey) ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	if k.ak == nil {
		return nil, errors.New("platform: no attestation key record for this device key")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blob, err := tpm2.Unmarshal[tpm2.TPM2BIDObject](credentialBlob)
	if err != nil {
		return nil, fmt.Errorf("platform: decoding credential blob: %w", err)
	}
	secret, err := tpm2.Unmarshal[tpm2.TPM2BEncryptedSecret](encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("platform: decoding encrypted secret: %w", err)
	}
	t, err := k.store.open()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	ek, _, flushEK, err := createEK(t)
	if err != nil {
		return nil, err
	}
	defer flushEK()
	srk, flushSRK, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flushSRK()
	akHandle, _, flushAK, err := loadUnderSRK(t, srk, k.ak)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer flushAK()

	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: akHandle,
		KeyHandle:      tpm2.AuthHandle{Handle: ek.Handle, Name: ek.Name, Auth: ekPolicySession()},
		CredentialBlob: *blob,
		Secret:         *secret,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("platform: TPM2_ActivateCredential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// randomNonce is used by tests and doctor to exercise Attest.
func randomNonce() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
