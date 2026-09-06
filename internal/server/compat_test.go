package server

import (
	"errors"
	"testing"
)

// docs/totem-design.md: "agent N works with issuer N and N+1; issuer refuses
// agents older than N-1". The table is the spec, written out, so a change to
// the rule is a change to a table rather than to a chain of conditionals.
func TestCheckAgentVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		issuer, agent string
		want          error
	}{
		{"same major", "2.1.0", "2.0.3", nil},
		{"agent one behind", "2.0.0", "1.9.9", nil},
		{"agent two behind is refused", "3.0.0", "1.0.0", ErrAgentTooOld},
		{"agent newer than issuer is refused", "1.0.0", "2.0.0", ErrIssuerTooOld},
		{"v prefix", "v2.0.0", "v1.0.0", nil},
		{"pre-release issuer serves anything", "0.0.0-dev", "", nil},
		{"pre-release issuer serves an unknown version", "0.0.0-dev", UnknownAgentVersion, nil},
		{"released issuer refuses an unknown version", "1.0.0", UnknownAgentVersion, ErrAgentTooOld},
		{"released issuer refuses an unreadable version", "1.0.0", "not-a-version", ErrAgentTooOld},
		{"an unreadable issuer version disables the gate", "not-a-version", "1.0.0", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAgentVersion(tc.issuer, tc.agent)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("issuer %s, agent %s: got %v, want nil", tc.issuer, tc.agent, err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("issuer %s, agent %s: got %v, want %v", tc.issuer, tc.agent, err, tc.want)
			}
		})
	}
}

// TestPreReleaseGateIsDeliberatelyOpen. Refusing unknown versions today would
// refuse every existing agent, because cmd/totem does not send the header yet,
// and an issuer nobody can enroll against is not a safer issuer. This test
// exists so that when the issuer goes 1.0 the behaviour changes and somebody
// has to have made the agent send its version first.
func TestPreReleaseGateIsDeliberatelyOpen(t *testing.T) {
	t.Parallel()
	if err := CheckAgentVersion("0.0.0-dev", ""); err != nil {
		t.Fatalf("a pre-1.0 issuer must serve an agent that does not state its version: %v", err)
	}
	if err := CheckAgentVersion("1.0.0", ""); err == nil {
		t.Fatal("a released issuer must refuse an agent that does not state its version; " +
			"cmd/totem has to send " + AgentVersionHeader + " before the issuer ships 1.0")
	}
}
