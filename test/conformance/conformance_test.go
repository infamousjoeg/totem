// Package conformance will run the SPIFFE project's go-spiffe client against a
// running totem agent's Workload API socket, proving that anything which already
// speaks SPIFFE works unchanged. Scaffold only: the test is skipped, not
// passing, and no go-spiffe dependency is wired yet.
package conformance

import "testing"

// TestWorkloadAPIConformance will, once the agent serves the Workload API on a
// unix socket (mode 0600), fetch an X509-SVID with go-spiffe's workloadapi
// client and assert the SVID chains to the issuer bundle. It is skipped until
// the agent core exists.
func TestWorkloadAPIConformance(t *testing.T) {
	t.Skip("not yet functional: agent Workload API socket does not exist; " +
		"will fetch an X509-SVID via go-spiffe workloadapi.Client and verify " +
		"it chains to the issuer bundle")
}
