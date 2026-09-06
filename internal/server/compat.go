package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/infamousjoeg/totem/internal/version"
)

// docs/totem-design.md "Deployment and distribution": "Compatibility: agent N
// works with issuer N and N+1; issuer refuses agents older than N-1."
//
// Read as a rule the issuer enforces, that is: an agent whose major version is
// the issuer's, or one behind it, is served. Anything older is refused with a
// message naming the fix, and an agent NEWER than the issuer is refused too,
// because "works with issuer N and N+1" says nothing about N-1 and a newer
// agent asking an older issuer for something it does not implement produces a
// worse failure than a clear refusal.

// AgentVersionHeader is how an agent states its version. It is a header rather
// than a body field so it applies to every endpoint including the ones with no
// body, and so the gate can run before anything is decoded.
//
// NOTE FOR THE AGENT: cmd/totem does not send this header today. Until it does,
// the gate cannot distinguish a current agent from an ancient one; see
// CheckAgentVersion for what this issuer does in the meantime and why that is
// the honest behaviour rather than the safe-looking one.
const AgentVersionHeader = "Totem-Agent-Version"

// UnknownAgentVersion is what the audit line records for an agent that did not
// state one. It is a value, not an empty string, so a reader cannot mistake
// "did not say" for "field not implemented".
const UnknownAgentVersion = "unknown"

// ErrAgentTooOld and ErrIssuerTooOld are the two directions of a version
// refusal. They are distinct because the fix is on a different machine in each
// case, and telling a person to upgrade the wrong one costs an afternoon.
var (
	ErrAgentTooOld  = errors.New("server: agent is older than this issuer supports")
	ErrIssuerTooOld = errors.New("server: agent is newer than this issuer")
)

// AgentVersion reads the reported version, or UnknownAgentVersion.
func AgentVersion(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get(AgentVersionHeader))
	if v == "" {
		return UnknownAgentVersion
	}
	return v
}

// CheckAgentVersion applies the compatibility rule.
//
// An agent that reports nothing is served while the ISSUER is itself pre-1.0,
// and refused once it is not. That asymmetry is deliberate. Refusing unknown
// versions today would refuse every existing agent, since cmd/totem does not
// send the header yet, and an issuer that cannot be enrolled against is not a
// safer issuer. Serving unknown versions forever would make the gate
// decorative. Tying it to the issuer's own major version means the rule starts
// being enforced at exactly the release where "agent N-1" first means
// something, and the audit line records "unknown" in the meantime so the gap is
// visible in the log rather than assumed away.
func CheckAgentVersion(issuerVersion, agentVersion string) error {
	issuerMajor, ok := majorOf(issuerVersion)
	if !ok {
		return nil
	}
	if agentVersion == "" || agentVersion == UnknownAgentVersion {
		if issuerMajor == 0 {
			return nil
		}
		return fmt.Errorf("%w: it did not say which version it is", ErrAgentTooOld)
	}
	agentMajor, ok := majorOf(agentVersion)
	if !ok {
		if issuerMajor == 0 {
			return nil
		}
		return fmt.Errorf("%w: %q is not a version this issuer can read", ErrAgentTooOld, agentVersion)
	}
	switch {
	case agentMajor > issuerMajor:
		return fmt.Errorf("%w: agent is %d, issuer is %d", ErrIssuerTooOld, agentMajor, issuerMajor)
	case agentMajor+1 < issuerMajor:
		return fmt.Errorf("%w: agent is %d, issuer is %d", ErrAgentTooOld, agentMajor, issuerMajor)
	default:
		return nil
	}
}

// majorOf parses the leading major version out of a version string, tolerating
// a "v" prefix and any pre-release or build suffix.
func majorOf(v string) (int, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	if v == "" {
		return 0, false
	}
	end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if end == 0 {
		return 0, false
	}
	if end > 0 {
		v = v[:end]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// checkVersion is the handler-side gate. It turns a refusal into the typed
// front-door error with the fix on the right machine.
func (s *Server) checkVersion(r *http.Request) error {
	iv := s.cfg.Version
	if iv == "" {
		iv = version.Version
	}
	err := CheckAgentVersion(iv, AgentVersion(r))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrIssuerTooOld):
		return &apiError{
			status: http.StatusConflict,
			what:   fmt.Sprintf("this totem is newer than your issuer (issuer %s).", iv),
			fix:    "Ask your issuer operator to upgrade the issuer, or use the version of totem that matches it.",
			cause:  err,
		}
	default:
		return &apiError{
			status: http.StatusConflict,
			what:   fmt.Sprintf("this totem is too old for your issuer (issuer %s).", iv),
			fix:    "Upgrade totem: 'brew upgrade totem', or download the current release.",
			cause:  err,
		}
	}
}
