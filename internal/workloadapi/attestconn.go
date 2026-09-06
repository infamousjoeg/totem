package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/infamousjoeg/totem/internal/attest"
)

// ErrAttestorUnavailable means this binary has no attestation backend wired in,
// so no caller can be resolved to a catalog tool. It is a build-time gap, never
// a caller's fault, and it is reported as such rather than as a rejection.
var ErrAttestorUnavailable = errors.New("workloadapi: attestation backend unavailable in this build")

// attestTimeout bounds one attestation. It is generous relative to reading a
// pid's start time and hashing a binary, and short relative to a human noticing
// the agent has stopped answering.
const attestTimeout = 10 * time.Second

// ErrNotUnixConn means something other than a unix socket connection reached
// the listener. totem serves the Workload API on a unix socket only, because
// peer credentials are the whole tool-identity anchor.
var ErrNotUnixConn = errors.New("workloadapi: workload API connections must be unix socket connections")

// Conn is an accepted unix connection whose peer was attested once, before gRPC
// ever saw it. It is the carrier for the spec's "attestation is per connection,
// not per RPC" rule: the *net.UnixConn is captured at Accept, attested there,
// and the resulting identity (or the typed refusal) rides on this value for the
// lifetime of the connection.
//
// Conn also keeps the raw *net.UnixConn so renewal can re-check the process
// start time and binary hash against the same peer, per attest.Attestor.
type Conn struct {
	*net.UnixConn

	attestor attest.Attestor

	mu       sync.Mutex
	identity *attest.Identity
	err      error
}

// Identity returns the identity this connection attested to at accept time, or
// the typed attestation error that refused it. Default deny: a caller that did
// not resolve to a catalog tool gets no identity, and the error is the one
// callers map to a legible gRPC status.
func (c *Conn) Identity() (*attest.Identity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if c.identity == nil {
		return nil, attest.ErrNotInCatalog
	}
	return c.identity, nil
}

// Reattest re-runs attestation on this same connection and confirms the peer
// did not change underneath it. It implements the spec's renewal rule:
// attestation is per connection, but process start time and binary hash are
// re-checked on renewal. A moved start time is a reused pid; a moved hash is a
// binary that changed since totem pinned it. Either way the connection loses
// its identity for good.
func (c *Conn) Reattest(ctx context.Context) (*attest.Identity, error) {
	c.mu.Lock()
	prev, prevErr, attestor, uc := c.identity, c.err, c.attestor, c.UnixConn
	c.mu.Unlock()

	if prevErr != nil {
		return nil, prevErr
	}
	if attestor == nil {
		return nil, ErrAttestorUnavailable
	}

	fresh, err := attestor.AttestPeer(ctx, uc)
	if err == nil && prev != nil {
		switch {
		case fresh.Peer.PID != prev.Peer.PID, !fresh.Peer.StartTime.Equal(prev.Peer.StartTime):
			err = attest.ErrPIDReused
		case fresh.BinaryHash != prev.BinaryHash:
			err = attest.ErrSignatureMismatch
		case fresh.Tool != prev.Tool:
			err = attest.ErrSignatureMismatch
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		// Latch the refusal: once a connection's peer has moved, it never gets
		// its identity back, even if a later check would pass.
		c.err = err
		c.identity = nil
		return nil, err
	}
	c.identity = fresh
	return fresh, nil
}

// Listener wraps a unix listener so every accepted connection is attested
// before gRPC can wrap it. This ordering is load-bearing: gRPC hands handlers a
// context, not a connection, so the *net.UnixConn has to be captured and
// attested here or the peer's pid is unreachable by the time an RPC arrives.
type Listener struct {
	inner    *net.UnixListener
	attestor attest.Attestor
	log      *Logger
}

// NewListener returns a Listener that attests each accepted connection with
// attestor. A nil attestor is accepted: the listener still serves, and every
// connection carries ErrAttestorUnavailable so callers get a legible answer
// instead of a hung socket.
func NewListener(inner *net.UnixListener, attestor attest.Attestor, log *Logger) *Listener {
	return &Listener{inner: inner, attestor: attestor, log: log}
}

// Accept accepts a connection, attests its peer once, and returns a *Conn
// carrying the result. A failed attestation is NOT a closed connection: the
// spec's rejection-UX rule requires the caller to be told what to do, and a
// connection closed at accept time gives a developer nothing but EOF. The
// refusal travels on the connection and is answered as a gRPC status on the
// caller's first RPC.
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	uc, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, ErrNotUnixConn
	}

	c := &Conn{UnixConn: uc, attestor: l.attestor}
	if l.attestor == nil {
		c.err = ErrAttestorUnavailable
		return c, nil
	}
	// Bounded, because attestation runs inline in the accept loop: an attestor
	// that hangs on a wedged /proc read or a stalled code-signature check would
	// otherwise stop the agent answering anyone at all.
	ctx, cancel := context.WithTimeout(context.Background(), attestTimeout)
	defer cancel()
	ident, aerr := l.attestor.AttestPeer(ctx, uc)
	c.identity, c.err = ident, aerr
	if aerr != nil && l.log != nil {
		l.log.Record(Event{Kind: KindRefusal, Reason: reasonFor(aerr), Message: humanRefusal(aerr, nil), Fix: fixFor(aerr, nil)})
	}
	return c, nil
}

// Close closes the underlying listener, which also unlinks the socket file.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr returns the listener's unix address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// AuthInfo is the gRPC transport auth info that carries the attested
// connection into every RPC's context. gRPC stores whatever ServerHandshake
// returns on the peer for the whole connection, which is exactly the lifetime
// attestation is scoped to.
type AuthInfo struct {
	credentials.CommonAuthInfo
	// Conn is the attested connection this RPC arrived on.
	Conn *Conn
}

// AuthType names this transport for gRPC's logging and for any middleware that
// wants to assert it is talking to a totem-attested unix socket.
func (AuthInfo) AuthType() string { return "totem-attested-unix" }

// Credentials returns the grpc.ServerOption transport credentials that move an
// attested *Conn onto each RPC context. It performs no handshake: the security
// boundary is the 0600 unix socket plus peer attestation, not a TLS session.
func Credentials() credentials.TransportCredentials { return attestedCredentials{} }

type attestedCredentials struct{}

// ServerHandshake takes the connection the Listener already attested and
// publishes it as gRPC auth info. It never fails a refused connection: the
// refusal is answered per RPC with a message a developer can act on.
func (attestedCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c, ok := raw.(*Conn)
	if !ok {
		_ = raw.Close()
		return nil, nil, fmt.Errorf("%w: got %T", ErrNotUnixConn, raw)
	}
	return raw, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		Conn:           c,
	}, nil
}

// ClientHandshake is never used: totem only serves the Workload API, it does
// not dial one.
func (attestedCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("workloadapi: totem does not dial a workload API")
}

// Info reports the transport protocol for gRPC's own diagnostics.
func (attestedCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "totem-attested-unix"}
}

// Clone returns a copy; the value is stateless.
func (c attestedCredentials) Clone() credentials.TransportCredentials { return c }

// OverrideServerName is meaningless for a unix socket and is refused.
func (attestedCredentials) OverrideServerName(string) error {
	return errors.New("workloadapi: server name override is meaningless on a unix socket")
}
