package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	toterrors "github.com/infamousjoeg/totem/internal/errors"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// The issuer does not exist yet: it is step 2 of docs/totem-design.md
// "Sequencing". Every network call the agent makes goes through this interface
// so the agent can be built, tested, and reasoned about before the broker
// exists, and so an unreachable issuer is a typed retryable error rather than a
// crash. There is no offline grace for credentials themselves; this interface
// only makes the failure legible, it never fakes success.

// ErrIssuerPinMismatch means the certificate the issuer presented is not the
// one the enroll URL's fingerprint named. Decision 18: the agent verifies and
// refuses on mismatch, and humans never compare hex.
var ErrIssuerPinMismatch = errors.New("the issuer presented a different certificate than the enroll link named")

// IssuerAddr is an issuer URL plus the certificate fingerprint the agent will
// pin, and a record of how that fingerprint was established.
type IssuerAddr struct {
	// URL is the issuer address with the fragment stripped.
	URL string
	// FingerprintHex is the lowercase hex SHA-256 of the issuer's certificate.
	// Empty when the enroll link carried none, in which case a human has to
	// establish it before anything is pinned.
	FingerprintHex string
	// FirstContact is how FingerprintHex was established. It is carried onto
	// the enrollment record and sent to the issuer, so an enrollment made over
	// the weaker path stays visibly weaker forever.
	FirstContact workloadapi.FirstContact
}

// ParseIssuerURL splits an enroll URL into its address and its pinned
// fingerprint. Decision 18 puts the fingerprint in the URL fragment so humans
// never have to compare hex: `totem-issuer init` prints the whole command, the
// agent verifies against the fragment, and refuses on mismatch.
//
// A bare URL is not refused. docs/totem-design.md "Enrollment" step 1 keeps a
// fallback, and a hard refusal would strand anyone whose fragment was eaten by
// a chat client or a copy-paste, and stranded people invent worse workarounds
// than the one they were denied. The fallback is weaker, so it is handled by
// establishIssuer below rather than here, and the path taken is recorded.
func ParseIssuerURL(raw string) (IssuerAddr, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return IssuerAddr{}, failf(
			"Use the whole command your issuer operator gave you, including the part after the # sign.",
			"%q is not a usable issuer address.", raw)
	}
	if u.Scheme != "https" {
		return IssuerAddr{}, failf(
			"Use the whole command your issuer operator gave you. The address starts with https://.",
			"the issuer address must start with https://, and %q does not.", raw)
	}
	if u.Host == "" {
		return IssuerAddr{}, failf(
			"Use the whole command your issuer operator gave you.",
			"the issuer address %q has no host.", raw)
	}
	frag := strings.TrimSpace(u.Fragment)
	u.Fragment = ""
	addr := IssuerAddr{URL: strings.TrimSuffix(u.String(), "#")}
	if frag == "" {
		addr.FirstContact = workloadapi.FirstContactPrompt
		return addr, nil
	}
	fp, err := ParseFingerprint(frag)
	if err != nil {
		return IssuerAddr{}, err
	}
	addr.FingerprintHex = fp
	addr.FirstContact = workloadapi.FirstContactFragment
	return addr, nil
}

// ParseFingerprint normalizes a "sha256:..." fingerprint, accepting the colon
// separated form people paste out of a terminal and a bare hex string, and
// accepting a prefix of at least MinFingerprintPrefix characters so a human
// transcribing from an issuer console does not have to copy all 64.
func ParseFingerprint(raw string) (string, error) {
	fp := strings.ToLower(strings.TrimSpace(raw))
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.NewReplacer(":", "", " ", "", "-", "").Replace(fp)
	if len(fp) != 64 {
		return "", failf(
			"Ask your issuer operator for the full command that 'totem-issuer init' printed, or for the whole line starting with sha256:.",
			"that is not a complete issuer identifier (it should be 64 characters after 'sha256:', and that one is %d).", len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return "", failf(
			"Ask your issuer operator for the full command that 'totem-issuer init' printed.",
			"that issuer identifier has characters totem cannot read.")
	}
	return fp, nil
}

// MinFingerprintPrefix is how much of a fingerprint a human must transcribe
// from the issuer console on the fallback path. Twelve hex characters is 48
// bits, which is the same strength the presence request code settled on, and
// it is short enough that people actually copy it correctly.
const MinFingerprintPrefix = 12

// ParseFingerprintPrefix normalizes a partial fingerprint a human typed. It
// accepts a full one too, because somebody will paste the whole thing.
func ParseFingerprintPrefix(raw string) (string, error) {
	fp := strings.ToLower(strings.TrimSpace(raw))
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.NewReplacer(":", "", " ", "", "-", "").Replace(fp)
	if len(fp) < MinFingerprintPrefix {
		return "", failf(
			fmt.Sprintf("Type at least the first %d characters of the line starting with sha256: on your issuer's console.", MinFingerprintPrefix),
			"that is too short to identify an issuer (totem needs at least %d characters, and that was %d).", MinFingerprintPrefix, len(fp))
	}
	if len(fp) > 64 {
		return "", failf("Copy just the part after 'sha256:'.", "that is longer than an issuer identifier.")
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return "", failf("Copy just the part after 'sha256:'.", "that has characters totem cannot read.")
	}
	return fp, nil
}

// ChallengeRequest asks the issuer for a one-shot value to sign. Nothing
// replayable is ever held on the laptop, so the challenge is issuer-minted and
// used once.
type ChallengeRequest struct {
	DeviceFingerprint string `json:"device_fingerprint"`
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
}

// ChallengeResponse carries the value to sign and how long it is good for.
type ChallengeResponse struct {
	Challenge []byte `json:"challenge"`
	ExpiresIn int    `json:"expires_in"`
}

// EnrollRequest is what the agent submits: BOTH public halves of the device's
// key material, the true protection level, the presence state the device is
// enrolling at, and a presence-gated signature over the issuer's challenge.
//
// Both halves are required, and that is the whole point of the field pair. On
// Apple silicon these are two Secure Enclave keys: a device key with no
// presence access control that signs the silent half-life renewals, and a
// companion key with a user-presence access control that signs presence
// assertions. An enrollment that sent only the device half would look
// completely successful and then fail to verify every presence assertion
// forever, against the wrong key. So PresencePublicDER is either populated or
// the enrollment explicitly says presence "none"; there is no third state.
type EnrollRequest struct {
	// DevicePublicDER is the device key's public half, PKIX DER. The issuer
	// verifies silent renewals against this one.
	DevicePublicDER []byte `json:"device_public_der"`
	// PresencePublicDER is the presence key's public half, PKIX DER. The
	// issuer verifies presence assertions against this one, including the
	// enrollment signature below. It is nil only when Presence is "none".
	PresencePublicDER []byte `json:"presence_public_der,omitempty"`
	// Presence is the presence state this device is enrolling at. A device
	// with no way to check for a human enrolls at "none", recorded and carried
	// on the identity, and exchanges still work; it is never inflated to make
	// an enrollment look better than it is.
	Presence presence.State `json:"presence"`
	// ProtectionLevel is the true assurance of the device key.
	ProtectionLevel spiffe.ProtectionLevel `json:"protection_level"`
	// Hostname and OS are shown to the human approving this device.
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	// DeviceFingerprint is the SHA-256 of DevicePublicDER in hex. It is what
	// the signature below is bound to, and the issuer can recompute it, so the
	// signature cannot be lifted onto a different device's enrollment.
	DeviceFingerprint string `json:"device_fingerprint"`
	// SignedTool and SignedTarget are the other two fields bound into the
	// signature, so the issuer reconstructs the exact signed bytes rather than
	// trusting an encoding the caller supplied.
	SignedTool   string `json:"signed_tool"`
	SignedTarget string `json:"signed_target"`
	// EncodingVersion is the presence encoding version the signature was made
	// under.
	EncodingVersion uint8 `json:"encoding_version"`
	// IssuerURL is the issuer this device believes it enrolled with.
	IssuerURL string `json:"issuer_url"`
	// IssuerFingerprint is the SHA-256 of the certificate this device pinned.
	// Binding it lets the issuer refuse an enrollment made against somebody
	// else's certificate: if what the device pinned is not the issuer's own
	// leaf, something terminated TLS in between and the enrollment is not one
	// the issuer should record.
	IssuerFingerprint string `json:"issuer_fingerprint"`
	// FirstContact is HOW this device established that fingerprint: from the
	// enroll link (or an equivalent operator-supplied value), or from a human
	// reading it off the issuer console. The two paths are not equally strong,
	// so the issuer records which one happened and policy can act on it later.
	// It is under the signature, because a field that names the weaker path is
	// exactly the field an attacker would rewrite to hide that it was taken.
	FirstContact workloadapi.FirstContact `json:"first_contact"`
	// Challenge is the issuer-minted, single-use value that was signed.
	Challenge []byte `json:"challenge"`
	// RequestHash binds everything above into the signature and is what the
	// human-visible request code is derived from. The issuer recomputes it
	// from the fields of this request; see enrollmentRequestHash for the
	// canonical order.
	RequestHash []byte `json:"request_hash"`
	// Signature is over the canonical enrollment signing bytes, from the
	// presence key when the device has one and from the device key when it is
	// enrolling at presence "none".
	Signature []byte `json:"signature"`
	// BootstrapCode is the one-time code from `totem-issuer init`, redeemed by
	// the founding device.
	BootstrapCode string `json:"bootstrap_code,omitempty"`
}

// EnrollResponse is what the issuer records and returns. Approval is a separate
// human step unless this is the founding device redeeming the bootstrap code.
type EnrollResponse struct {
	DeviceID     string `json:"device_id"`
	TrustDomain  string `json:"trust_domain"`
	Approved     bool   `json:"approved"`
	ApprovalCode string `json:"approval_code,omitempty"`
	ApprovalURL  string `json:"approval_url,omitempty"`
}

// IssuerClient is every call the agent makes to the broker. It is small on
// purpose: the laptop asks for a challenge, submits an enrollment, and checks
// reachability. Credential exchange arrives with the bridges in later steps.
type IssuerClient interface {
	// CertificateFingerprint fetches the issuer's certificate and returns its
	// SHA-256 and its PEM. It is the only call made before a pin exists.
	CertificateFingerprint(ctx context.Context) (fingerprint string, certPEM string, err error)
	// Challenge asks for a one-shot value to sign.
	Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResponse, error)
	// Enroll submits the enrollment.
	Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error)
	// Reachable reports whether the issuer answers, which is the first thing
	// `totem doctor` checks.
	Reachable(ctx context.Context) error
	// ServerDate returns the issuer's clock, used for the clock-skew check.
	ServerDate(ctx context.Context) (time.Time, error)
}

// httpIssuerClient talks to the issuer over TLS pinned to the fingerprint from
// the enroll URL. Publicly trusted certificates are still pinned, so the pin is
// the only thing that decides trust here and the system trust store is not
// consulted at all.
type httpIssuerClient struct {
	addr IssuerAddr
	http *http.Client
}

// NewIssuerClient returns a client pinned to addr.FingerprintHex. A zero
// fingerprint is refused rather than silently trusting the system roots.
func NewIssuerClient(addr IssuerAddr) (IssuerClient, error) {
	if addr.FingerprintHex == "" {
		return nil, failf("Run the 'totem enroll' command your issuer operator gave you, including the part after the # sign.",
			"totem will not talk to an issuer it cannot identify.")
	}
	want, err := hex.DecodeString(addr.FingerprintHex)
	if err != nil {
		return nil, failf("Re-run 'totem enroll' with the command your issuer operator gave you.",
			"the pinned issuer identifier is not readable.")
	}
	tlsCfg := &tls.Config{
		// The pin replaces chain validation entirely: totem trusts exactly one
		// certificate, named in the enroll link, and nothing the system trusts.
		InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyPeerCertificate below
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrIssuerPinMismatch
			}
			got := sha256.Sum256(rawCerts[0])
			if !equalBytes(got[:], want) {
				return fmt.Errorf("%w (expected %s, got %s)", ErrIssuerPinMismatch,
					shortFingerprint(addr.FingerprintHex), shortFingerprint(hex.EncodeToString(got[:])))
			}
			return nil
		},
	}
	return &httpIssuerClient{
		addr: addr,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true},
		},
	}, nil
}

// CertificateFingerprint dials the issuer and compares the certificate it
// presents against the pin from the enroll link, refusing on mismatch.
func (c *httpIssuerClient) CertificateFingerprint(ctx context.Context) (string, string, error) {
	u, err := url.Parse(c.addr.URL)
	if err != nil {
		return "", "", err
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the pin below is the whole check
		MinVersion:         tls.VersionTLS12,
	}}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "tcp", host)
	if err != nil {
		return "", "", c.unreachable(err)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", "", failf("Ask your issuer operator to check the issuer is serving over TLS.",
			"your issuer at %s did not present a certificate.", c.addr.URL)
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	got := hex.EncodeToString(sum[:])
	if !equalBytes(sum[:], mustHex(c.addr.FingerprintHex)) {
		return got, "", &cliError{
			what: fmt.Sprintf("the issuer at %s is not the one your enroll link named (link says %s, this one is %s).",
				c.addr.URL, shortFingerprint(c.addr.FingerprintHex), shortFingerprint(got)),
			fix:   "Do not continue. Ask your issuer operator to send you the enroll command again, and if it matches what you used, treat this as a problem worth investigating.",
			cause: ErrIssuerPinMismatch,
		}
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	return got, string(pemBytes), nil
}

// Challenge asks the issuer for a one-shot value to sign.
func (c *httpIssuerClient) Challenge(ctx context.Context, req ChallengeRequest) (*ChallengeResponse, error) {
	var out ChallengeResponse
	if err := c.post(ctx, "/v1/enroll/challenge", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Enroll submits this device to the issuer.
func (c *httpIssuerClient) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.post(ctx, "/v1/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Reachable reports whether the issuer answers and is still the one this
// device pinned.
func (c *httpIssuerClient) Reachable(ctx context.Context) error {
	_, _, err := c.CertificateFingerprint(ctx)
	return err
}

// ServerDate reads the issuer's clock from its response, for the skew check.
func (c *httpIssuerClient) ServerDate(ctx context.Context) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.addr.URL+"/healthz", nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return time.Time{}, c.unreachable(err)
	}
	defer resp.Body.Close()
	d := resp.Header.Get("Date")
	if d == "" {
		return time.Time{}, failf("Skip the clock check; your issuer does not report its time.",
			"your issuer did not report its clock.")
	}
	t, err := http.ParseTime(d)
	if err != nil {
		return time.Time{}, failf("Skip the clock check; your issuer reported a time totem cannot read.",
			"your issuer reported a time totem cannot read.")
	}
	return t, nil
}

// post makes one JSON request over the pinned connection.
func (c *httpIssuerClient) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr.URL+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return c.unreachable(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return failf("Ask your issuer operator to check the issuer log for this device.",
			"your issuer refused this request (%s).", strings.TrimSpace(firstLine(string(data))))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return failf("Ask your issuer operator whether the issuer is running a version totem understands.",
			"your issuer answered in a way totem could not read.")
	}
	return nil
}

// unreachable is the one place a network failure becomes the typed retryable
// error. It names the address and the last successful contact, because a
// harness needs the code and a human needs to know whether this is a blip or a
// box that has been down for a week.
func (c *httpIssuerClient) unreachable(cause error) error {
	last := "never"
	if st, err := workloadapi.LoadState(""); err == nil && !st.LastIssuerContact.IsZero() {
		last = st.LastIssuerContact.Local().Format(time.RFC1123)
	}
	return &cliError{
		reason:     toterrors.ReasonIssuerUnreachable,
		retryAfter: 30,
		what:       fmt.Sprintf("could not reach your issuer at %s (last reached: %s).", c.addr.URL, last),
		fix:        "Check your network and try again. 'totem doctor' checks reachability first.",
		cause:      errors.Join(cause, workloadapi.ErrIssuerUnreachable),
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "no detail"
	}
	return s
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// shortFingerprint renders a fingerprint the way a human can compare at a
// glance without being asked to read 64 hex characters.
func shortFingerprint(hexstr string) string {
	if len(hexstr) < 16 {
		return hexstr
	}
	return hexstr[:8] + "..." + hexstr[len(hexstr)-8:]
}

// parseURLHost returns the hostname of an https URL, or empty when the issuer
// is reachable only by IP. An IP-only issuer requires an explicit trust domain,
// per docs/totem-design.md "Identity model", because an address is not a name.
func parseURLHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	h := u.Hostname()
	if net.ParseIP(h) != nil {
		return "", nil
	}
	return h, nil
}

// observeIssuerCertificate dials the issuer with no pin at all and reports the
// certificate it presented, without trusting it for anything.
//
// It exists ONLY for the fallback path in establishIssuer, where the enroll
// link carried no fingerprint and a human has to establish trust out of band.
// Nothing that comes back from here is trusted until a human has matched it
// against what the issuer console printed; the return value is evidence to be
// checked, not a decision.
func observeIssuerCertificate(ctx context.Context, issuerURL string) (fingerprint, certPEM string, err error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", "", err
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // nothing here is trusted; a human matches it below
		MinVersion:         tls.VersionTLS12,
	}}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "tcp", host)
	if err != nil {
		return "", "", &cliError{
			reason:     toterrors.ReasonIssuerUnreachable,
			retryAfter: 30,
			what:       fmt.Sprintf("could not reach your issuer at %s.", issuerURL),
			fix:        "Check your network and try again.",
			cause:      errors.Join(err, workloadapi.ErrIssuerUnreachable),
		}
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", "", failf("Ask your issuer operator to check the issuer is serving over TLS.",
			"your issuer at %s did not present a certificate.", issuerURL)
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:]), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), nil
}
