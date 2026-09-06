package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/fips140"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/summon"
)

// On-disk layout under Config.Dir. Roots and intermediates are named by their
// SubjectKeyId so a directory listing answers "which key signed this" without
// opening anything, and so root rotation adds a file rather than overwriting
// the file the fleet still trusts.
const (
	saltFile    = "salt"
	rootPrefix  = "root-"
	interPrefix = "int-"
	certSuffix  = ".crt"
	keySuffix   = ".key"
)

// authority is the CA. Every method takes the lock: signing, rotating and
// revoking all read and write the same intermediate set, and a rotation racing
// an issuance is exactly the window where a certificate could be signed by a
// key that is being replaced.
type authority struct {
	mu sync.Mutex

	dir             string
	trustDomain     spiffeid.TrustDomain
	resolver        summon.Resolver
	passRef         summon.Reference
	now             func() time.Time
	rootProv        RootProvider
	nameConstraints bool

	salt   []byte
	roots  []*x509.Certificate
	inters []*loadedIntermediate
	revs   *revocationState

	closed bool
}

// loadedIntermediate is an intermediate certificate and its unsealed key.
//
// The key is held in memory for the process lifetime rather than unsealed per
// signature. That is a deliberate trade: unsealing per signature would mean a
// PBKDF2 derivation on the issuance hot path, and the passphrase is resolved
// through Summon at every unseal, so per-signature unsealing would also make
// every SVID depend on the provider being reachable at that instant. An issuer
// whose CA keys are only as available as its secrets provider fails closed far
// more often than the threat model asks for.
type loadedIntermediate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var _ Authority = (*authority)(nil)
var _ RootOperator = (*authority)(nil)

// Init generates the root and the first intermediate at `issuer init`.
//
// It refuses to overwrite existing CA material with ErrAlreadyInitialized.
// Regenerating a root over a live one invalidates every enrolled device at
// once, silently, and the operator finds out when the fleet stops working, so
// it is never something a re-run of a command does by accident.
func Init(ctx context.Context, params InitParams) (Authority, error) {
	a, err := newAuthority(params.Config)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca: creating the CA directory: %w", err)
	}
	existing, err := filepath.Glob(filepath.Join(a.dir, rootPrefix+"*"+certSuffix))
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return nil, ErrAlreadyInitialized
	}

	a.salt = make([]byte, saltLen)
	if _, err := rand.Read(a.salt); err != nil {
		return nil, fmt.Errorf("ca: generating a KDF salt: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(a.dir, saltFile), a.salt, 0o600); err != nil {
		return nil, err
	}

	pass, err := a.passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer pass.Zero()

	now := a.now()
	validity := params.RootValidity
	if validity <= 0 {
		validity = DefaultRootValidity
	}
	subject := params.Subject
	if subject == "" {
		subject = a.trustDomain.Name()
	}

	rootCert, err := a.createRoot(subject, now, validity, pass.Bytes())
	if err != nil {
		return nil, err
	}
	a.roots = []*x509.Certificate{rootCert}

	notBefore, notAfter := firstIntermediateWindow(now)
	if _, err := a.createIntermediate(ctx, subject, notBefore, notAfter, pass.Bytes()); err != nil {
		return nil, err
	}

	a.revs = newRevocationState()
	if err := a.revs.save(a.dir); err != nil {
		return nil, err
	}
	return a, nil
}

// Open loads an existing CA.
func Open(ctx context.Context, cfg Config) (Authority, error) {
	a, err := newAuthority(cfg)
	if err != nil {
		return nil, err
	}
	salt, err := os.ReadFile(filepath.Join(a.dir, saltFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	a.salt = salt

	if err := a.loadRoots(); err != nil {
		return nil, err
	}
	if len(a.roots) == 0 {
		return nil, ErrNotInitialized
	}

	pass, err := a.passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer pass.Zero()
	if err := a.loadIntermediates(pass.Bytes()); err != nil {
		return nil, err
	}
	revs, err := loadRevocationState(a.dir)
	if err != nil {
		return nil, err
	}
	a.revs = revs
	return a, nil
}

func newAuthority(cfg Config) (*authority, error) {
	// RequireFIPS is checked before anything is generated or loaded. "In FIPS
	// mode the issuer refuses non-approved configuration" is a refusal, so it
	// has to happen before a single certificate exists that was minted outside
	// the boundary; checking it at first issuance would leave the root itself
	// on the wrong side of the line.
	if cfg.RequireFIPS && !fips140.Enabled() {
		return nil, fmt.Errorf("%w: build with the FIPS Go crypto module and set GODEBUG=fips140=on", ErrFIPSRequired)
	}
	if cfg.Dir == "" {
		return nil, errors.New("ca: Config.Dir is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("ca: Config.Resolver is required; the CA passphrase has no other path in")
	}
	if cfg.PassphraseRef == "" {
		return nil, errors.New("ca: Config.PassphraseRef is required")
	}
	// Decision 11: the trust domain is validated AS a trust domain. go-spiffe
	// accepts a whole SPIFFE ID here and quietly keeps only its authority, so a
	// value carrying a scheme or a path is refused rather than truncated.
	if strings.Contains(cfg.TrustDomain, "/") {
		return nil, fmt.Errorf("ca: %q is not a trust domain; a trust domain is a name like issuer.example, with no scheme and no path", cfg.TrustDomain)
	}
	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("ca: %q is not a usable trust domain: %w", cfg.TrustDomain, err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	a := &authority{
		dir:         cfg.Dir,
		trustDomain: td,
		resolver:    cfg.Resolver,
		passRef:     cfg.PassphraseRef,
		now:         now,
		rootProv:    cfg.Root,
		// Default ON: the zero value of DisableNameConstraints keeps the
		// constraint, so removing the control is always a deliberate act.
		nameConstraints: !cfg.DisableNameConstraints,
	}
	if a.rootProv == nil {
		a.rootProv = &localRoot{a: a}
	}
	// Before the passphrase is resolved, before the salt is read, before
	// anything on disk is touched: refuse if this passphrase is one that
	// pull-based rotation may replace.
	//
	// It sits in newAuthority rather than in Open because Init is exactly as
	// broken: it CREATES the material sealed under that passphrase, so
	// initialising against a pull-rotated reference produces a CA that can
	// never be opened, from a command that reported success. Both constructors
	// go through here, and nothing else returns an *authority, so there is no
	// path to a CA that skipped the check.
	if err := a.requirePassphraseSealed(); err != nil {
		return nil, err
	}
	return a, nil
}

// passphrase resolves the CA passphrase. It is called at the moment the value
// is needed and the caller zeroes it immediately after, never caching it across
// a rotation: internal/summon is explicit that a cached Value is a zeroed
// buffer after the next rotation, and that the loud failure is the point.
func (a *authority) passphrase(ctx context.Context) (summon.Value, error) {
	v, err := a.resolver.Resolve(ctx, a.passRef)
	if err != nil {
		return nil, fmt.Errorf("ca: resolving the CA passphrase: %w", err)
	}
	return v, nil
}

// --- loading -------------------------------------------------------------

func (a *authority) loadRoots() error {
	paths, err := filepath.Glob(filepath.Join(a.dir, rootPrefix+"*"+certSuffix))
	if err != nil {
		return err
	}
	a.roots = nil
	for _, p := range paths {
		c, err := readCert(p)
		if err != nil {
			return err
		}
		a.roots = append(a.roots, c)
	}
	return nil
}

func (a *authority) loadIntermediates(pass []byte) error {
	paths, err := filepath.Glob(filepath.Join(a.dir, interPrefix+"*"+certSuffix))
	if err != nil {
		return err
	}
	a.inters = nil
	for _, p := range paths {
		c, err := readCert(p)
		if err != nil {
			return err
		}
		key, err := readSealedKey(strings.TrimSuffix(p, certSuffix)+keySuffix, pass, a.salt)
		if err != nil {
			return err
		}
		a.inters = append(a.inters, &loadedIntermediate{cert: c, key: key})
	}
	return nil
}

func (a *authority) intermediateCerts() []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(a.inters))
	for _, in := range a.inters {
		out = append(out, in.cert)
	}
	return out
}

// activeRoot is the root that signs new intermediates: the one with the latest
// NotBefore. Derived rather than recorded, so a root rotation is complete the
// moment the new root's file lands, with no second file to keep in step.
func (a *authority) activeRoot() *x509.Certificate {
	var best *x509.Certificate
	for _, r := range a.roots {
		if best == nil || r.NotBefore.After(best.NotBefore) {
			best = r
		}
	}
	return best
}

// --- CA material creation ------------------------------------------------

func (a *authority) createRoot(subject string, now time.Time, validity time.Duration, pass []byte) (*x509.Certificate, error) {
	key, err := newCAKey()
	if err != nil {
		return nil, fmt.Errorf("ca: generating the root key: %w", err)
	}
	skid, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject + " totem root", Organization: []string{subject}},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// One intermediate CA may follow the root and nothing below that, so
		// the root can never be used to mint a second tier of CAs.
		MaxPathLen:         1,
		SubjectKeyId:       skid,
		SignatureAlgorithm: caSignatureAlgorithm,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("ca: self-signing the root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(a.dir, rootPrefix+hex.EncodeToString(skid))
	if err := writeSealedKey(base+keySuffix, key, pass, a.salt); err != nil {
		return nil, err
	}
	if err := writeCert(base+certSuffix, der); err != nil {
		return nil, err
	}
	return cert, nil
}

// createIntermediate generates an intermediate and has the root sign it. It
// needs the root signer, which is why an offline root turns intermediate
// rotation into a ceremony rather than a cron.
func (a *authority) createIntermediate(ctx context.Context, subject string, notBefore, notAfter time.Time, pass []byte) (*loadedIntermediate, error) {
	rootCert, err := a.rootProv.Certificate(ctx)
	if err != nil {
		return nil, err
	}
	rootSigner, err := a.rootProv.Signer(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireCAKey(rootSigner.Public()); err != nil {
		return nil, err
	}
	key, err := newCAKey()
	if err != nil {
		return nil, fmt.Errorf("ca: generating an intermediate key: %w", err)
	}
	skid, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   subject + " totem intermediate",
			Organization: []string{subject},
			// The signing window is on the certificate as dates; the serial in
			// the OU makes two intermediates distinguishable to a human reading
			// a chain during an overlap, when three of them are live at once.
			OrganizationalUnit: []string{hex.EncodeToString(skid[:4])},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
		SignatureAlgorithm:    caSignatureAlgorithm,
	}
	if a.nameConstraints {
		// The constraint is on the INTERMEDIATE, not the root. It binds
		// everything the intermediate signs, which is every credential totem
		// issues, and backing it out costs one thirty-day rotation. The same
		// constraint on the root would bind the intermediates too, but backing
		// it out would cost a root-rotation ceremony across every relying
		// party's trust anchor, and this control is new enough that it should
		// be reversible at the cheaper tier.
		//
		// Critical, as RFC 5280 requires. A non-critical name constraint is
		// advisory: a verifier is free to ignore it, which would leave the
		// control looking present while doing nothing.
		tmpl.PermittedURIDomains = []string{a.trustDomain.Name()}
		tmpl.PermittedDNSDomainsCritical = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, key.Public(), rootSigner)
	if err != nil {
		return nil, fmt.Errorf("ca: signing an intermediate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(a.dir, interPrefix+hex.EncodeToString(skid))
	if err := writeSealedKey(base+keySuffix, key, pass, a.salt); err != nil {
		return nil, err
	}
	if err := writeCert(base+certSuffix, der); err != nil {
		return nil, err
	}
	in := &loadedIntermediate{cert: cert, key: key}
	a.inters = append(a.inters, in)
	return in, nil
}

// --- Authority -----------------------------------------------------------

// Bundle implements Authority.Bundle: the root plus every intermediate whose
// validity window contains now, so a relying party trusts the next intermediate
// before it signs anything.
func (a *authority) Bundle(ctx context.Context) (*Bundle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	t := a.now()
	return &Bundle{
		Roots:         append([]*x509.Certificate(nil), a.roots...),
		Intermediates: liveIntermediates(a.intermediateCerts(), t),
		GeneratedAt:   t,
	}, nil
}

// Schedule implements Authority.Schedule: the rotation state read off the
// certificates, evaluated against the clock, changing nothing.
func (a *authority) Schedule(ctx context.Context) (*Schedule, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	return buildSchedule(a.intermediateCerts(), a.now()), nil
}

// currentSigner returns the one intermediate signing right now. It is the
// single place "which key signs" is decided, and it fails closed: no signing
// intermediate means no certificate, never a fallback to a retiring one. A
// retiring intermediate signing "just this once" would produce a certificate
// that outlives its issuer, which presents to a relying party as an expired
// chain under a perfectly valid leaf.
func (a *authority) currentSigner(t time.Time) (*loadedIntermediate, error) {
	for _, in := range a.inters {
		if role, live := roleAt(in.cert, t); live && role == RoleCurrent {
			return in, nil
		}
	}
	return nil, ErrNoSigningIntermediate
}

// IssueSVID implements Authority.IssueSVID: an X.509-SVID for a device, tool or
// agent identity, ECDSA P-256 only, refusing the issuer's own identity so that a
// self-issuance cannot be logged as a device issuance.
func (a *authority) IssueSVID(ctx context.Context, req SVIDRequest) (*SVID, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	id, err := a.deriveID(req.ID)
	if err != nil {
		return nil, err
	}
	pub, err := requireSVIDKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	ttl, err := checkTTL(req.TTL)
	if err != nil {
		return nil, err
	}
	if req.Presence == presence.StateDelegated && req.GrantID == "" {
		return nil, ErrGrantRequired
	}

	exts, err := identityExtensions(req)
	if err != nil {
		return nil, err
	}
	return a.mint(id, pub, ttl, exts, EventIssuance)
}

// IssueIssuerSVID implements Authority.IssueIssuerSVID: the issuer's own
// spiffe://<td>/issuer identity, no presence, tagged EventIssuerSelfIssuance.
func (a *authority) IssueIssuerSVID(ctx context.Context, req IssuerSVIDRequest) (*SVID, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	pub, err := requireSVIDKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	ttl, err := checkTTL(req.TTL)
	if err != nil {
		return nil, err
	}
	id, err := spiffeid.FromSegments(a.trustDomain, strings.TrimPrefix(IssuerPath, "/"))
	if err != nil {
		return nil, err
	}
	// No protection level, no presence state, no grant. The issuer's identity
	// has none of those, and emitting presence:none here would put the same
	// extension on it that an unattended device credential carries, which is
	// the conflation the distinct event type exists to prevent.
	return a.mint(id, pub, ttl, nil, EventIssuerSelfIssuance)
}

// mint is the one place a leaf certificate is created. Callers hold the lock.
func (a *authority) mint(id spiffeid.ID, pub *ecdsa.PublicKey, ttl time.Duration, exts []pkix.Extension, event string) (*SVID, error) {
	t := a.now()
	signer, err := a.currentSigner(t)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		return nil, err
	}
	notAfter := t.Add(ttl)
	// A leaf must never outlive the intermediate that signed it: a relying
	// party sees that as an expired chain with a valid leaf, which is the most
	// confusing PKI failure there is. The retirement tail makes this
	// unreachable in normal operation, so this clamp is a belt on top of the
	// braces rather than the mechanism.
	if notAfter.After(signer.cert.NotAfter) {
		notAfter = signer.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id.String()},
		NotBefore:    t,
		NotAfter:     notAfter,
		// digitalSignature only. An X.509-SVID must not carry keyCertSign or
		// cRLSign, and keyEncipherment is meaningless for ECDSA.
		KeyUsage: x509.KeyUsageDigitalSignature,
		// Both directions: an SVID authenticates a client to a relying party
		// and a server to a peer, and totem uses mTLS in both roles.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
		ExtraExtensions:       exts,
		SignatureAlgorithm:    caSignatureAlgorithm,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, pub, signer.key)
	if err != nil {
		return nil, fmt.Errorf("ca: signing an SVID: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &SVID{
		Certificate: leaf,
		Chain:       []*x509.Certificate{leaf, signer.cert},
		ChainDER:    [][]byte{der, signer.cert.Raw},
		URI:         id.String(),
		Event:       event,
		IssuedBy:    append([]byte(nil), signer.cert.SubjectKeyId...),
		NotAfter:    leaf.NotAfter,
	}, nil
}

// deriveID turns the identity model value into a validated SPIFFE ID, in the
// same shape internal/workloadapi derives on the agent side.
func (a *authority) deriveID(id spiffe.ID) (spiffeid.ID, error) {
	// The issuer's own identity has no device segment. An ID with no device
	// whose tool or agent segment is "issuer" is the only expressible reach for
	// spiffe://<td>/issuer through this door, and it gets its own error so the
	// caller is told which method to use.
	if id.DeviceID == "" && (id.Tool == "issuer" || id.Agent == "issuer") {
		return spiffeid.ID{}, ErrIssuerIdentityReserved
	}
	if id.TrustDomain != "" && id.TrustDomain != a.trustDomain.Name() {
		return spiffeid.ID{}, fmt.Errorf("%w: this CA is %s, the request is %s", ErrTrustDomainMismatch, a.trustDomain.Name(), id.TrustDomain)
	}
	if id.DeviceID == "" {
		return spiffeid.ID{}, fmt.Errorf("%w: no device", ErrInvalidIdentity)
	}
	kind, name := "tool", id.Tool
	switch {
	case id.Tool != "" && id.Agent != "":
		return spiffeid.ID{}, fmt.Errorf("%w: an identity is a tool or an agent, never both", ErrInvalidIdentity)
	case id.Tool == "" && id.Agent == "":
		return spiffeid.ID{}, fmt.Errorf("%w: no tool and no agent", ErrInvalidIdentity)
	case id.Agent != "":
		kind, name = "agent", id.Agent
	}
	out, err := spiffeid.FromSegments(a.trustDomain, "device", id.DeviceID, kind, name)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("%w: %v", ErrInvalidIdentity, err)
	}
	return out, nil
}

func checkTTL(ttl time.Duration) (time.Duration, error) {
	if ttl <= 0 {
		return DefaultSVIDTTL, nil
	}
	if ttl > MaxSVIDTTL {
		return 0, fmt.Errorf("%w: asked for %s, maximum is %s", ErrTTLTooLong, ttl, MaxSVIDTTL)
	}
	return ttl, nil
}

// identityExtensions encodes the facts that "travel as X.509 extensions ...
// never in the path". All non-critical: a relying party that does not know
// totem must still be able to verify a totem chain, and a critical extension it
// cannot parse would make every SVID unusable to it.
func identityExtensions(req SVIDRequest) ([]pkix.Extension, error) {
	exts := make([]pkix.Extension, 0, 4)
	add := func(oid asn1.ObjectIdentifier, v any) error {
		b, err := asn1.Marshal(v)
		if err != nil {
			return fmt.Errorf("ca: encoding extension %s: %w", oid, err)
		}
		exts = append(exts, pkix.Extension{Id: oid, Critical: false, Value: b})
		return nil
	}
	utf8 := func(s string) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(s)}
	}
	if req.ProtectionLevel != "" {
		if err := add(OIDProtectionLevel, utf8(string(req.ProtectionLevel))); err != nil {
			return nil, err
		}
	}
	if req.Presence != "" {
		if err := add(OIDPresenceState, utf8(string(req.Presence))); err != nil {
			return nil, err
		}
		// Age rides alongside state because "presence was asserted" and "it was
		// asserted forty minutes ago" are different facts, and a relying party
		// with its own freshness policy needs the second one.
		if err := add(OIDPresenceAge, int(req.PresenceAge/time.Second)); err != nil {
			return nil, err
		}
	}
	if req.GrantID != "" {
		if err := add(OIDGrantID, utf8(req.GrantID)); err != nil {
			return nil, err
		}
	}
	return exts, nil
}

// RotateIntermediate prepares the successor to the current intermediate. See
// the interface godoc for the overlap semantics; the ordering of the checks
// here is the semantics.
func (a *authority) RotateIntermediate(ctx context.Context) (*Schedule, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	t := a.now()
	sched := buildSchedule(a.intermediateCerts(), t)

	var notBefore, notAfter time.Time
	switch {
	case sched.Next != nil:
		// A successor is already published. Rotating again inside the overlap
		// would replace an intermediate that relying parties have already
		// fetched and trusted, and every one of them would reject what the
		// replacement signs until it refetched. Refuse, idempotently, and hand
		// back the schedule that already exists.
		return sched, ErrRotationPending
	case sched.Current == nil:
		// Recovery: nothing is signing, because the signing window closed while
		// nobody rotated. Start a new intermediate now. This is the offline
		// root's failure mode arriving, and the fix must not itself require a
		// window that has already passed.
		notBefore, notAfter = firstIntermediateWindow(t)
	case t.Before(sched.RotateAfter):
		return sched, fmt.Errorf("%w: earliest is %s", ErrRotationTooSoon, sched.RotateAfter.UTC().Format(time.RFC3339))
	default:
		notBefore, notAfter = intermediateWindow(sched.Current.SigningEnd)
	}

	pass, err := a.passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer pass.Zero()

	subject := a.trustDomain.Name()
	if r := a.activeRoot(); r != nil && len(r.Subject.Organization) > 0 {
		subject = r.Subject.Organization[0]
	}
	if _, err := a.createIntermediate(ctx, subject, notBefore, notAfter, pass.Bytes()); err != nil {
		return nil, err
	}
	return buildSchedule(a.intermediateCerts(), t), nil
}

// RotateRoot signs a new root and keeps both published. Deliberate, never
// automatic, and reachable only through RootOperator.
func (a *authority) RotateRoot(ctx context.Context, req RootRotationRequest) (*Bundle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	if _, ok := a.rootProv.(*localRoot); !ok {
		// A KMS root's key is generated inside the KMS by the operator's own
		// tooling; this package will not pretend it can do that. Refusing is
		// honest, and a half-done rotation of a root is the single worst state
		// a PKI can be left in.
		return nil, fmt.Errorf("%w: rotate a KMS-held root with the KMS's own tooling and re-run issuer init against the new key", ErrRootOffline)
	}
	pass, err := a.passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer pass.Zero()

	validity := req.Validity
	if validity <= 0 {
		validity = DefaultRootValidity
	}
	t := a.now()
	old := a.activeRoot()
	subject := a.trustDomain.Name()
	if old != nil && len(old.Subject.Organization) > 0 {
		subject = old.Subject.Organization[0]
	}
	newRoot, err := a.createRoot(subject, t, validity, pass.Bytes())
	if err != nil {
		return nil, err
	}
	a.roots = append(a.roots, newRoot)

	if req.RetireOld && old != nil {
		// Retiring immediately is the operator saying every relying party has
		// already refetched the bundle. Nothing here can verify that claim, so
		// it is never the default.
		kept := a.roots[:0]
		for _, r := range a.roots {
			if r.Equal(old) {
				base := filepath.Join(a.dir, rootPrefix+hex.EncodeToString(r.SubjectKeyId))
				os.Remove(base + certSuffix)
				os.Remove(base + keySuffix)
				continue
			}
			kept = append(kept, r)
		}
		a.roots = kept
	}
	return &Bundle{
		Roots:         append([]*x509.Certificate(nil), a.roots...),
		Intermediates: liveIntermediates(a.intermediateCerts(), t),
		GeneratedAt:   t,
	}, nil
}

// Close implements Authority.Close: it zeroes the intermediate private keys and
// the KDF salt and refuses every later call with ErrClosed.
func (a *authority) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	for _, in := range a.inters {
		if in.key != nil && in.key.D != nil {
			in.key.D.SetInt64(0)
		}
	}
	a.inters = nil
	zero(a.salt)
	return nil
}

// --- local root ----------------------------------------------------------

// localRoot is the "held offline on this box" root: a passphrase-sealed key
// file beside the CA material. Moving that file off the box is what makes the
// root genuinely offline, and Signer then returns ErrRootOffline, which is a
// normal steady state rather than a fault.
type localRoot struct{ a *authority }

// Certificate returns the active root: the one with the latest NotBefore. Always
// available, because the certificate is public and stays in the bundle even when
// the key has been carried off the box.
func (l *localRoot) Certificate(ctx context.Context) (*x509.Certificate, error) {
	if r := l.a.activeRoot(); r != nil {
		return r, nil
	}
	return nil, ErrNotInitialized
}

// Signer unseals the root key from disk. A missing key file is ErrRootOffline,
// which is the normal steady state for a root the operator keeps elsewhere, not
// a fault to alert on.
func (l *localRoot) Signer(ctx context.Context) (crypto.Signer, error) {
	root := l.a.activeRoot()
	if root == nil {
		return nil, ErrNotInitialized
	}
	path := filepath.Join(l.a.dir, rootPrefix+hex.EncodeToString(root.SubjectKeyId)+keySuffix)
	pass, err := l.a.passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer pass.Zero()
	key, err := readSealedKey(path, pass.Bytes(), l.a.salt)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: the root key file is not on this box", ErrRootOffline)
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}
