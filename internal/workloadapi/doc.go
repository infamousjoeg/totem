// Package workloadapi serves the standard SPIFFE Workload API on a unix socket
// so that, per docs/totem-design.md "Agent (laptop)", "anything that already
// speaks SPIFFE works unchanged". It is the real service from
// github.com/spiffe/go-spiffe/v2/proto/spiffe/workload, not an approximation:
// a stock go-spiffe workloadapi.Client fetches an X509-SVID from this socket
// and chains it to the issuer bundle without modification.
//
// Three rules shape everything in here.
//
// Attestation is per connection, not per RPC. The listener captures the
// *net.UnixConn before gRPC wraps it, runs attest.Attestor.AttestPeer once,
// and carries the resulting *attest.Identity on the connection for the life of
// that connection. Renewal re-checks the process start time and binary hash on
// that same connection.
//
// Default deny. A caller that does not attest to a catalog tool gets no
// identity. Rejections are legible per the spec's rejection-UX rule: each of
// attest's typed errors maps to its own gRPC status whose message tells a
// developer what to do next, never a bare "permission denied".
//
// Identities are derived, never registered. The SPIFFE ID is
// spiffe://<trust-domain>/device/<device-id>/tool/<tool-name>, or
// .../agent/<name> for a long-running agent. Protection level and presence
// facts ride as X.509 extensions and JWT claims, never as path segments.
package workloadapi
