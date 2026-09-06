package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// docs/totem-design.md "Issuer (broker box)": "Self-signed server cert
// generated at `issuer init`; the printed enroll command embeds its fingerprint
// as a URL FRAGMENT so the agent verifies it with no human comparison.
// Publicly trusted certs are still pinned."
//
// The fragment is the whole point. A fingerprint printed on a separate line is
// a fingerprint a human is asked to compare, and humans do not compare hex;
// they glance, decide it looks right, and paste. In the fragment it is machine
// input: the agent parses it out of the one command it was given and refuses on
// mismatch (cmd/totem, ErrIssuerPinMismatch), and no human is in the loop at
// all.

// ServerCertValidity is how long the self-signed front-door certificate is
// good for.
//
// It is long on purpose, and the reason is the pin rather than the key. Every
// enrolled device has this certificate's fingerprint written into its state and
// trusts nothing else, so replacing it is not a rotation, it is a re-enrollment
// of the entire fleet. A one-year certificate would turn that into an annual
// outage that arrives with no warning and looks, from the laptop, exactly like
// a machine-in-the-middle. The private key sits on the broker box next to the
// CA material, so its exposure is bounded by the same thing the CA's is.
const ServerCertValidity = 10 * 365 * 24 * time.Hour

// Identity is the issuer's front-door TLS identity: the self-signed
// certificate every agent pins, and the fingerprint the enroll command carries.
type Identity struct {
	// Certificate is the TLS certificate served to every caller.
	Certificate tls.Certificate
	// Leaf is the parsed certificate.
	Leaf *x509.Certificate
	// Fingerprint is SHA-256 over the leaf's DER, which is exactly what the
	// agent computes over rawCerts[0] in its VerifyPeerCertificate hook. Any
	// other digest input (the public key, the PEM, the whole chain) would
	// produce a value that never matches and a mismatch that looks like an
	// attack.
	Fingerprint []byte
}

// FingerprintHex is the lowercase hex form that goes in the enroll URL.
func (i *Identity) FingerprintHex() string { return hex.EncodeToString(i.Fingerprint) }

// Errors from the front-door identity.
var (
	// ErrIdentityExists means GenerateIdentity found an existing certificate
	// and refused to overwrite it. Regenerating it silently would invalidate
	// the pin every enrolled device holds, which presents on every laptop as
	// "the issuer presented a different certificate than the enroll link
	// named": indistinguishable from an attack, fleet-wide, with no warning.
	ErrIdentityExists = errors.New("server: front-door certificate already exists; refusing to replace the certificate every enrolled device has pinned")
	// ErrNoIdentity means there is no certificate to load. `issuer init` has
	// not run, or the directory is wrong.
	ErrNoIdentity = errors.New("server: no front-door certificate found; run totem-issuer init")
)

const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

// GenerateIdentity creates the self-signed front-door certificate at
// `issuer init` and writes it under dir: the certificate world-readable, the
// key 0600, the directory 0700.
//
// hosts are the names and addresses agents will dial. Every one of them becomes
// a SAN, because a name that is not in the certificate is a name that cannot be
// used to reach the issuer even though the pin would match: the pin decides
// trust, but the TLS stack still checks the name unless a client explicitly
// opts out, and totem should not require every future client to opt out.
func GenerateIdentity(dir string, hosts []string, now time.Time) (*Identity, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%w: the issuer needs at least one name or address agents can reach it on", ErrConfig)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if _, err := os.Stat(certPath); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrIdentityExists, certPath)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0], Organization: []string{"totem issuer"}},
		NotBefore:             now.Add(-time.Hour).UTC(),
		NotAfter:              now.Add(ServerCertValidity).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	return LoadIdentity(dir)
}

// LoadIdentity reads the front-door certificate written at init.
func LoadIdentity(dir string) (*Identity, error) {
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoIdentity, certPath)
	}
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	sum := sha256.Sum256(leaf.Raw)
	return &Identity{Certificate: pair, Leaf: leaf, Fingerprint: sum[:]}, nil
}

// writeFile writes atomically at the requested mode, so a reader never sees a
// half-written certificate and the key is never briefly world-readable.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// EnrollCommand renders the one command `issuer init` prints and the operator
// pastes on the laptop, with the fingerprint in the fragment.
//
// The code is a flag on the command rather than a second thing to copy, because
// two things to copy is one thing to lose, and the thing people lose is the one
// that is not a URL.
func EnrollCommand(issuerURL, fingerprintHex, bootstrapCode string) string {
	var b strings.Builder
	b.WriteString("totem enroll ")
	b.WriteString(strings.TrimSuffix(issuerURL, "/"))
	b.WriteString("#sha256:")
	b.WriteString(fingerprintHex)
	if bootstrapCode != "" {
		b.WriteString(" --code ")
		b.WriteString(bootstrapCode)
	}
	return b.String()
}

// HostsFor turns an external URL into the SAN list the front-door certificate
// needs, plus any extra names the operator gave.
func HostsFor(externalURL string, extra ...string) ([]string, error) {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	if externalURL != "" {
		u, err := url.Parse(externalURL)
		if err != nil {
			return nil, err
		}
		add(u.Hostname())
	}
	for _, e := range extra {
		add(e)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%w: no hostname or address for the issuer certificate", ErrConfig)
	}
	return hosts, nil
}

// IsIPOnly reports whether an issuer address is reachable only by IP.
// docs/totem-design.md: "A hostname is required for the browser admin path
// (WebAuthn cannot use an IP) ... IP-only issuers get the headless path only",
// and "Trust domain defaults to the issuer hostname given at enroll; IP-only
// issuers require one explicitly."
func IsIPOnly(externalURL string) bool {
	u, err := url.Parse(externalURL)
	if err != nil {
		return false
	}
	return net.ParseIP(u.Hostname()) != nil
}
