package workloadapi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/infamousjoeg/totem/internal/attest"
	tspiffe "github.com/infamousjoeg/totem/internal/spiffe"
)

// Errors returned by identity derivation. They are separate from attest's
// errors because they describe agent configuration, not the caller.
var (
	// ErrNoTrustDomain means the agent has no trust domain, which means it has
	// not enrolled. Per docs/totem-design.md "Identity model", the trust domain
	// defaults to the issuer hostname given at enroll, so there is nothing to
	// derive from before that.
	ErrNoTrustDomain = errors.New("workloadapi: no trust domain; device is not enrolled")
	// ErrNoDeviceID means the agent has no device id, which means the issuer
	// has not recorded an enrollment for this machine.
	ErrNoDeviceID = errors.New("workloadapi: no device id; device is not enrolled")
)

// IdentityConfig is everything the derivation needs that does not come from the
// attested caller. It holds no policy: derivation is mechanical.
type IdentityConfig struct {
	// TrustDomain defaults to the issuer hostname given at enroll; IP-only
	// issuers require one explicitly (docs/totem-design.md "Identity model").
	TrustDomain string
	// DeviceID identifies the enrolled device the identity belongs to.
	DeviceID string
	// AgentUsers maps a dedicated OS uid to a long-running agent name. Per
	// docs/totem-design.md "Agents and delegation", the agent harness runs
	// under a dedicated OS user, so the unix attestor already separates on uid
	// and spiffe://<td>/device/<device>/agent/<name> falls out of the existing
	// attestation code. A caller whose uid is absent from this map is an
	// interactive tool under the human's own uid and keeps its tool identity.
	AgentUsers map[uint32]string
}

// Derived is a derived totem identity: the internal model value and the
// validated SPIFFE ID that goes on the wire. There are no registration entries
// as a user-facing concept; every ID in totem is produced here.
type Derived struct {
	// Model is the internal identity model value.
	Model tspiffe.ID
	// ID is the validated SPIFFE ID.
	ID spiffeid.ID
}

// String returns the SPIFFE ID in its URI form, e.g.
// spiffe://example.org/device/abc123/tool/claude.
func (d Derived) String() string { return d.ID.String() }

// IsAgent reports whether this is a long-running agent identity rather than an
// interactive tool identity.
func (d Derived) IsAgent() bool { return d.Model.Agent != "" }

// DeriveTool returns spiffe://<trust-domain>/device/<device-id>/tool/<tool>.
// Protection level and presence facts are deliberately absent: they travel as
// X.509 extensions and JWT claims, never in the path.
func DeriveTool(trustDomain, deviceID, tool string) (Derived, error) {
	return derive(trustDomain, deviceID, "tool", tool)
}

// DeriveAgent returns spiffe://<trust-domain>/device/<device-id>/agent/<name>
// for a long-running agent running under its own dedicated OS user.
func DeriveAgent(trustDomain, deviceID, name string) (Derived, error) {
	return derive(trustDomain, deviceID, "agent", name)
}

// Derive turns an attested caller into its derived SPIFFE ID. A caller running
// under a uid registered in cfg.AgentUsers is a long-running agent and gets an
// agent identity; everything else is an interactive tool under the human's own
// uid and gets a tool identity anchored on the catalog name attest resolved.
func Derive(cfg IdentityConfig, ident *attest.Identity) (Derived, error) {
	if ident == nil {
		return Derived{}, errors.New("workloadapi: cannot derive an identity from a caller that did not attest")
	}
	if name, ok := cfg.AgentUsers[ident.Peer.UID]; ok && name != "" {
		return DeriveAgent(cfg.TrustDomain, cfg.DeviceID, name)
	}
	return DeriveTool(cfg.TrustDomain, cfg.DeviceID, ident.Tool)
}

// derive is the one place a totem SPIFFE ID is built. Keeping it single ensures
// the path shape cannot drift and that nothing but device id and tool or agent
// name ever reaches a path segment.
func derive(trustDomain, deviceID, kind, name string) (Derived, error) {
	if trustDomain == "" {
		return Derived{}, ErrNoTrustDomain
	}
	if deviceID == "" {
		return Derived{}, ErrNoDeviceID
	}
	if name == "" {
		return Derived{}, fmt.Errorf("workloadapi: cannot derive an identity with an empty %s name", kind)
	}
	// go-spiffe accepts a whole SPIFFE ID here and quietly keeps only its
	// authority. Decision 11 wants the trust domain validated as a trust
	// domain, so a value carrying a scheme or a path is refused rather than
	// silently truncated at enroll.
	if strings.Contains(trustDomain, "/") {
		return Derived{}, fmt.Errorf("workloadapi: %q is not a trust domain; a trust domain is a name like issuer.example, with no scheme and no path", trustDomain)
	}
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return Derived{}, fmt.Errorf("workloadapi: %q is not a usable trust domain: %w", trustDomain, err)
	}
	id, err := spiffeid.FromSegments(td, "device", deviceID, kind, name)
	if err != nil {
		return Derived{}, fmt.Errorf("workloadapi: cannot derive an identity for %s %q on device %q: %w", kind, name, deviceID, err)
	}
	model := tspiffe.ID{TrustDomain: td.Name(), DeviceID: deviceID}
	switch kind {
	case "tool":
		model.Tool = name
	case "agent":
		model.Agent = name
	}
	return Derived{Model: model, ID: id}, nil
}
