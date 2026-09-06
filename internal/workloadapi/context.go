package workloadapi

import (
	"context"

	"google.golang.org/grpc/peer"

	"github.com/infamousjoeg/totem/internal/attest"
)

// ConnFromContext returns the attested connection this RPC arrived on. gRPC
// puts the transport auth info on the peer once per connection, so every RPC on
// a connection reads back the same *Conn and therefore the same attestation.
func ConnFromContext(ctx context.Context) (*Conn, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, false
	}
	info, ok := p.AuthInfo.(AuthInfo)
	if !ok || info.Conn == nil {
		return nil, false
	}
	return info.Conn, true
}

// IdentityFromContext returns the catalog identity of the caller on this RPC's
// connection, or the typed attestation error that refused it. It is the single
// entry point every handler uses, so default deny cannot be forgotten in one
// method and honored in another.
func IdentityFromContext(ctx context.Context) (*attest.Identity, error) {
	c, ok := ConnFromContext(ctx)
	if !ok {
		return nil, ErrNotUnixConn
	}
	return c.Identity()
}
