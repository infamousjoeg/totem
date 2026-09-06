package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
)

// ProvenanceOID identifies the totem provenance extension on a credential.
// PLACEHOLDER: it sits under the IANA private-enterprise arc with the
// largest arc Go's certificate parser accepts (2^31-1), which no enterprise
// holds, because the project has no Private Enterprise Number yet. Register
// one (free, iana.org/assignments/enterprise-numbers) and replace this
// before any credential leaves a lab; the change re-issues every credential.
var ProvenanceOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2147483647, 1}

// claimsASN1 is the DER body of the extension. Version is bound so a later
// layout cannot be read by an older issuer as something narrower.
type claimsASN1 struct {
	Version  int
	Level    string `asn1:"utf8"`
	State    string `asn1:"utf8"`
	GrantID  string `asn1:"utf8"`
	RootID   string `asn1:"utf8"`
	Lineage  []string
	Sponsor  string `asn1:"utf8"`
	SignedAt int64
}

const claimsVersion = 1

func provenanceExtension(c Claims) (pkix.Extension, error) {
	if err := validateClaims(c); err != nil {
		return pkix.Extension{}, err
	}
	var signedAt int64
	if !c.Provenance.SignedAt.IsZero() {
		signedAt = c.Provenance.SignedAt.UnixNano()
	}
	body, err := asn1.Marshal(claimsASN1{
		Version:  claimsVersion,
		Level:    string(c.ProtectionLevel),
		State:    string(c.State),
		GrantID:  c.Provenance.GrantID,
		RootID:   c.Provenance.RootID,
		Lineage:  c.Provenance.Lineage,
		Sponsor:  c.Provenance.Sponsor,
		SignedAt: signedAt,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("policy: provenance extension: %w", err)
	}
	// Not critical: a verifier that does not know the extension (a relying
	// party's TLS stack) must still accept the chain; the presence facts are
	// for totem and for RPs that match on them.
	return pkix.Extension{Id: ProvenanceOID, Critical: false, Value: body}, nil
}

// validateClaims is the consistency rule between state and grant: delegated
// has a grant, present and none have none. A credential that says delegated
// with nothing to answer "who authorized this" is refused at mint and at
// attest.
func validateClaims(c Claims) error {
	switch c.State {
	case presence.StateDelegated:
		if c.Provenance.GrantID == "" || c.Provenance.RootID == "" {
			return fmt.Errorf("%w: delegated credential without a grant", ErrCredential)
		}
		if c.Provenance.State != presence.StateDelegated {
			return fmt.Errorf("%w: provenance state %q", ErrCredential, c.Provenance.State)
		}
	case presence.StatePresent, presence.StateNone:
		if c.Provenance.GrantID != "" || c.Provenance.RootID != "" || len(c.Provenance.Lineage) != 0 {
			return fmt.Errorf("%w: %s credential carries a grant", ErrCredential, c.State)
		}
	default:
		return fmt.Errorf("%w: presence state %q", ErrCredential, c.State)
	}
	return nil
}

func parseProvenance(ext pkix.Extension) (Claims, error) {
	var body claimsASN1
	rest, err := asn1.Unmarshal(ext.Value, &body)
	if err != nil || len(rest) != 0 {
		return Claims{}, fmt.Errorf("%w: provenance extension malformed", ErrCredential)
	}
	if body.Version != claimsVersion {
		return Claims{}, fmt.Errorf("%w: provenance version %d", ErrCredential, body.Version)
	}
	c := Claims{
		ProtectionLevel: spiffe.ProtectionLevel(body.Level),
		State:           presence.State(body.State),
		Provenance: presence.Provenance{
			GrantID: body.GrantID, RootID: body.RootID, Lineage: body.Lineage, Sponsor: body.Sponsor,
		},
	}
	if body.SignedAt != 0 {
		c.Provenance.SignedAt = time.Unix(0, body.SignedAt).UTC()
	}
	if c.State == presence.StateDelegated {
		c.Provenance.State = presence.StateDelegated
	}
	if err := validateClaims(c); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// attestPeer reads the leaf of the first verified chain. It refuses no chain,
// a leaf with no or several SPIFFE URI SANs, a non-totem path, or claims
// inconsistent with the state.
func attestPeer(chains [][]*x509.Certificate) (*Attested, error) {
	if len(chains) == 0 || len(chains[0]) == 0 || chains[0][0] == nil {
		return nil, fmt.Errorf("%w: no verified chain", ErrCredential)
	}
	leaf := chains[0][0]
	var ids []*url.URL
	for _, u := range leaf.URIs {
		if u != nil && u.Scheme == "spiffe" {
			ids = append(ids, u)
		}
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("%w: %d spiffe URI SANs", ErrCredential, len(ids))
	}
	id, err := parseID(ids[0])
	if err != nil {
		return nil, err
	}
	a := &Attested{id: id, state: presence.StateNone, serial: leaf.SerialNumber.String()}
	found := false
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(ProvenanceOID) {
			continue
		}
		if found {
			return nil, fmt.Errorf("%w: duplicate provenance extension", ErrCredential)
		}
		found = true
		c, err := parseProvenance(ext)
		if err != nil {
			return nil, err
		}
		a.level, a.state, a.prov = c.ProtectionLevel, c.State, c.Provenance
	}
	if id.Agent != "" && a.state != presence.StateDelegated {
		return nil, fmt.Errorf("%w: agent identity with presence %q", ErrCredential, a.state)
	}
	if id.Tool != "" && a.state == presence.StateDelegated {
		return nil, fmt.Errorf("%w: tool identity with a grant", ErrCredential)
	}
	return a, nil
}

// parseID parses spiffe://<td>/device/<id>/(tool|agent)/<name>.
func parseID(u *url.URL) (spiffe.ID, error) {
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Host == "" || len(parts) != 4 || parts[0] != "device" || parts[1] == "" || parts[3] == "" {
		return spiffe.ID{}, fmt.Errorf("%w: %s", ErrCredential, u)
	}
	id := spiffe.ID{TrustDomain: u.Host, DeviceID: parts[1]}
	switch parts[2] {
	case "tool":
		id.Tool = parts[3]
	case "agent":
		id.Agent = parts[3]
	default:
		return spiffe.ID{}, fmt.Errorf("%w: %s", ErrCredential, u)
	}
	return id, nil
}

// attestedFor builds an Attested for tests and for the issuer's own
// self-issuance path, where there is no peer certificate yet. Unexported:
// the exchange handlers get theirs from AttestPeer.
func attestedFor(id spiffe.ID, c Claims) (*Attested, error) {
	if err := validateClaims(c); err != nil {
		return nil, err
	}
	return &Attested{id: id, level: c.ProtectionLevel, state: c.State, prov: presence.Provenance{
		State: c.Provenance.State, GrantID: c.Provenance.GrantID, RootID: c.Provenance.RootID,
		Lineage: slices.Clone(c.Provenance.Lineage), Sponsor: c.Provenance.Sponsor, SignedAt: c.Provenance.SignedAt,
	}}, nil
}
