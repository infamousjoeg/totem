// Package presence holds the presence assertion, the three presence states, and
// the grant and window types that gate an identity becoming a credential.
// Scaffold only: types and doc comments, no signing, verification, or session
// logic.
package presence

import "time"

// State is one of the three presence states, and the credential always says
// which. A longer window is never one of the options.
type State string

const (
	// StatePresent means a human touched the sensor.
	StatePresent State = "present"
	// StateDelegated means a human granted an agent a scope once, with
	// presence, and the agent operates inside it until the grant expires or is
	// revoked.
	StateDelegated State = "delegated"
	// StateNone is a device with no presence capability, recorded as such.
	StateNone State = "none"
)

// Assertion is a one-shot presence assertion: a signature over an issuer
// challenge from a biometric-gated key on the device, bound to the device, the
// tool, and, for sensitive targets, the specific request. Presence state lives
// on the issuer as a short session; the laptop never holds anything replayable.
type Assertion struct {
	// DeviceID is the enrolled device the assertion is bound to.
	DeviceID string
	// Tool is the tool the assertion authorizes.
	Tool string
	// Challenge is the issuer-minted value that was signed.
	Challenge []byte
	// Signature is over the issuer challenge from the biometric-gated key.
	Signature []byte
	// RequestHash binds the assertion to a specific request for presence:always
	// targets, where the assertion cannot be reused.
	RequestHash []byte
}

// Window is a shipped presence policy for a tool or profile: presence is
// checked once and then held for a bounded time. Windows are issuer-side
// sessions, evaluated on the issuer, never persisted; a restart means every
// tool prompts once. There is no global switch and never a longer window.
type Window struct {
	// Tool or profile the window applies to.
	Tool string
	// Duration the presence session is honored for after a touch.
	Duration time.Duration
	// Always, when set, binds the assertion to a hash of the request so it
	// cannot be reused; init defaults this on for any profile whose role name
	// contains admin or prod.
	Always bool
}

// Grant is the presence-signed artifact that lets a long-running agent operate
// without a prompt: which agent, which aws profiles, which GitHub repos and
// scopes, whether Claude via the proxy and under what spend cap, until when.
// The grant lives on the issuer; a hijacked agent gets exactly the grant and
// nothing else, and the human has a dated record of what was authorized.
type Grant struct {
	// ID is referenced by every credential issued under this grant.
	ID string
	// Agent is the agent SPIFFE name the grant is scoped to.
	Agent string
	// AWSProfiles the agent may use inside the grant.
	AWSProfiles []string
	// GitHubScopes (repos and scopes) the agent may use inside the grant.
	GitHubScopes []string
	// ClaudeProxy allows Claude via the proxy under SpendCapUSD when true.
	ClaudeProxy bool
	// SpendCapUSD is the per-identity spend cap that is the runaway-agent fuse.
	SpendCapUSD float64
	// Until is the grant expiry; 30-day default, renewal requires presence, a
	// notification goes out three days before, and if it lapses the agent keeps
	// running but its credentials stop. Revocation is instant.
	Until time.Time
	// SignedAt is the human's signing time, recorded on every delegated
	// credential alongside ID so provenance is legible.
	SignedAt time.Time
}
