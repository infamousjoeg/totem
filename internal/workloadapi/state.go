package workloadapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
	tspiffe "github.com/infamousjoeg/totem/internal/spiffe"
)

// On disk the agent keeps only two things, per docs/totem-design.md "Agent
// (laptop)": the enrollment record and the pinned issuer certificate. SVIDs are
// memory only and presence sessions live on the issuer and are never written
// anywhere. State is that enrollment record; RuntimeStatus below is a
// non-secret snapshot for `totem status`, not credential material.

// DefaultStatePath is ~/.totem/state.json.
func DefaultStatePath() string { return filepath.Join(homeDir(), ".totem", "state.json") }

// DefaultRuntimeStatusPath is ~/.totem/agent-status.json.
func DefaultRuntimeStatusPath() string {
	return filepath.Join(homeDir(), ".totem", "agent-status.json")
}

// ErrNoState means the agent has never enrolled on this machine.
var ErrNoState = errors.New("workloadapi: no enrollment record on this device")

// FirstContact records HOW the agent established that the issuer it was
// talking to was the right one, the very first time it spoke to it. There are
// two paths and they are not equally strong, so the enrollment says which one
// was taken and the fact travels to the issuer.
//
// This mirrors what the codebase already does with assurance everywhere else:
// hardware with no presence capability is never refused, it enrolls and is
// recorded as presence "none", and the level rides on the identity so
// downstream policy can act on it. Recording a weaker path is what makes it
// honest to allow the weaker path at all. An issuer operator can ask which
// devices enrolled without a pinned fingerprint, and policy can require the
// stronger path later without anyone having to relitigate what happened.
type FirstContact string

const (
	// FirstContactFragment means the issuer certificate was pinned from the
	// fingerprint the enroll link carried, or from an equivalent fingerprint
	// the operator supplied directly. No human compared anything, which is the
	// whole point of decision 18.
	FirstContactFragment FirstContact = "fragment"
	// FirstContactPrompt means the enroll link carried no fingerprint, so a
	// human had to establish trust out of band. Weaker than the fragment,
	// recorded as such, and never silently upgraded.
	FirstContactPrompt FirstContact = "prompt"
)

// State is the enrollment record the agent persists. It holds no secret: the
// device private key lives in the Secure Enclave, the TPM, the keyring, or a
// separate 0600 file owned by internal/platform, never here.
type State struct {
	// TrustDomain is the enrolled trust domain, defaulted from the issuer
	// hostname given at enroll.
	TrustDomain string `json:"trust_domain"`
	// DeviceID is the identifier the issuer recorded for this device.
	DeviceID string `json:"device_id"`
	// IssuerURL is the issuer address, without the fingerprint fragment.
	IssuerURL string `json:"issuer_url"`
	// IssuerFingerprint is the SHA-256 of the issuer certificate, pinned at
	// enroll. Later connections require that leaf or a successor signed by the
	// issuer's server CA.
	IssuerFingerprint string `json:"issuer_fingerprint"`
	// FirstContact records how that fingerprint was established. It is never
	// rewritten after enrollment: an enrollment made over the weaker path
	// stays visibly weaker.
	FirstContact FirstContact `json:"first_contact,omitempty"`
	// IssuerCertPEM is the pinned issuer certificate itself.
	IssuerCertPEM string `json:"issuer_cert_pem,omitempty"`
	// ProtectionLevel is the true assurance of the device key, recorded at
	// enroll and never inflated.
	ProtectionLevel tspiffe.ProtectionLevel `json:"protection_level"`
	// Presence is the presence state this device enrolled at. A device with no
	// way to check for a human enrolls at "none", recorded and carried; it is
	// never inflated to make an exchange succeed.
	Presence presence.State `json:"presence,omitempty"`
	// DevicePublicDER is the device key's public half as the issuer enrolled
	// it, PKIX DER. It is kept so `totem doctor` can compare the key actually
	// loaded from the key store against the key the issuer knows about.
	//
	// That comparison is not paranoia. A Secure Enclave key is persisted as a
	// wrapped blob and re-imported, and a re-import that goes subtly wrong does
	// not fail: it can hand back a fresh, working key that signs happily and
	// verifies against nothing anyone ever enrolled. "A different key loaded
	// and everything looks fine" is the dangerous case, and this field is what
	// makes it detectable locally instead of at the issuer, or never.
	DevicePublicDER []byte `json:"device_public_der,omitempty"`
	// PresencePublicDER is the presence key's public half as enrolled. Nil
	// only when Presence is "none".
	PresencePublicDER []byte `json:"presence_public_der,omitempty"`
	// KeyLabel is the platform key store label holding the device key.
	KeyLabel string `json:"key_label"`
	// SocketPath is where the agent serves the Workload API.
	SocketPath string `json:"socket_path"`
	// EnrolledAt is when the issuer approved this device.
	EnrolledAt time.Time `json:"enrolled_at"`
	// LastIssuerContact is the last time the agent successfully reached the
	// issuer. "Issuer unreachable" reports it, so a human can tell a blip from
	// a box that has been down for a week.
	LastIssuerContact time.Time `json:"last_issuer_contact,omitempty"`
	// AgentUsers maps a dedicated OS uid to a long-running agent name, which
	// is how an agent identity falls out of the unix attestor for free.
	AgentUsers map[uint32]string `json:"agent_users,omitempty"`
}

// Enrolled reports whether this device has a usable enrollment.
func (s *State) Enrolled() bool {
	return s != nil && s.TrustDomain != "" && s.DeviceID != "" && s.IssuerFingerprint != ""
}

// LoadState reads the enrollment record. A missing file returns ErrNoState,
// which every command turns into "run the totem enroll command your issuer
// operator gave you" rather than a stack trace.
func LoadState(path string) (*State, error) {
	if path == "" {
		path = DefaultStatePath()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoState
	}
	if err != nil {
		return nil, fmt.Errorf("workloadapi: cannot read %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("workloadapi: %s is not readable as an enrollment record: %w", path, err)
	}
	return &s, nil
}

// Save writes the enrollment record at 0600 inside a 0700 directory, atomically
// so a crash mid-write cannot leave a half-parsed enrollment behind.
func (s *State) Save(path string) error {
	if path == "" {
		path = DefaultStatePath()
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}

// RuntimeStatus is what a running agent publishes for `totem status` to read.
// It is a snapshot, not an interface: the CLI cannot fetch its own SVID through
// the Workload API, because `totem` is not a catalog tool and default deny
// applies to it exactly as it does to anything else.
type RuntimeStatus struct {
	// PID of the running agent, so `totem status` can say whether it is up.
	PID int `json:"pid"`
	// StartedAt is when the agent started serving.
	StartedAt time.Time `json:"started_at"`
	// UpdatedAt is when this snapshot was written; a stale file means the
	// agent died without cleaning up.
	UpdatedAt time.Time `json:"updated_at"`
	// SocketPath is the Workload API socket the agent is serving.
	SocketPath string `json:"socket_path"`
	// Endpoint is SocketPath as the unix:// URI clients put in
	// SPIFFE_ENDPOINT_SOCKET.
	Endpoint string `json:"endpoint"`
	// TrustDomain and DeviceID are copied from the enrollment record so
	// `totem status` reads one file for the common case.
	TrustDomain string `json:"trust_domain,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	// ProtectionLevel is the assurance of the device key backing identities.
	ProtectionLevel tspiffe.ProtectionLevel `json:"protection_level,omitempty"`
	// SVIDs is the current SVID per derived identity the agent is serving.
	SVIDs []SVIDStatus `json:"svids,omitempty"`
	// LastIssuerContact is the last successful issuer round trip.
	LastIssuerContact time.Time `json:"last_issuer_contact,omitempty"`
	// LastError is the most recent refusal or failure, so `status` surfaces
	// the log's headline without the human opening `totem log`.
	LastError string `json:"last_error,omitempty"`
	// BinaryPath and BinaryHash identify the totem binary this agent is
	// RUNNING FROM, captured at startup.
	//
	// They exist for one specific, baffling failure. The agent pins its own
	// hash so it can recognise its own helpers. Upgrade totem in place while
	// the agent is running and the helper on disk no longer matches the hash
	// the running agent remembers, so every helper connection fails as an
	// unknown program until the agent restarts. That is correct behaviour and
	// it is completely opaque from the outside: the tool was working, you
	// upgraded, and now it says it does not know what you are. `totem doctor`
	// compares these against what is on disk and says "restart the agent".
	BinaryPath string `json:"binary_path,omitempty"`
	BinaryHash string `json:"binary_hash,omitempty"`
}

// SVIDStatus is one identity's current credential, with no key material.
type SVIDStatus struct {
	// SpiffeID is the derived identity.
	SpiffeID string `json:"spiffe_id"`
	// Tool is the catalog tool it was derived from, when it is a tool
	// identity.
	Tool string `json:"tool,omitempty"`
	// ExpiresAt is when the current SVID stops working.
	ExpiresAt time.Time `json:"expires_at"`
	// RenewsAt is the half-life at which the agent pushes a fresh one.
	RenewsAt time.Time `json:"renews_at"`
}

// LoadRuntimeStatus reads the running agent's snapshot. A missing file means no
// agent is running, which is a normal state and not an error.
func LoadRuntimeStatus(path string) (*RuntimeStatus, error) {
	if path == "" {
		path = DefaultRuntimeStatusPath()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rs RuntimeStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("workloadapi: cannot read the agent status at %s: %w", path, err)
	}
	return &rs, nil
}

// Save writes the runtime snapshot at 0600.
func (r *RuntimeStatus) Save(path string) error {
	if path == "" {
		path = DefaultRuntimeStatusPath()
	}
	r.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}

// writePrivateFile writes data at 0600 inside a 0700 directory, atomically via
// a temp file in the same directory followed by a rename.
func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("workloadapi: cannot write %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
