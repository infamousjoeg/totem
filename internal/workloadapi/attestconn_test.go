package workloadapi

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/infamousjoeg/totem/internal/attest"
)

// dialPair returns a connected client/server *net.UnixConn pair over a real
// socket, so the listener plumbing is exercised against a real accept rather
// than a mock.
func dialPair(t *testing.T, att attest.Attestor) (*Listener, net.Conn) {
	t.Helper()
	sock := testSocketPath(t)
	raw, err := ListenSocket(sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	lis := NewListener(raw, att, nil)

	client, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return lis, client
}

// TestListenerCapturesUnixConnBeforeGRPC is the plumbing test that matters:
// Accept must hand the attestor the raw *net.UnixConn, because once gRPC wraps
// the listener there is no way back to the peer's pid.
func TestListenerCapturesUnixConnBeforeGRPC(t *testing.T) {
	want := toolIdentity(t)
	att := &fakeAttestor{identity: want}
	lis, _ := dialPair(t, att)

	c, err := lis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	ac, ok := c.(*Conn)
	if !ok {
		t.Fatalf("Accept returned %T, want *Conn", c)
	}
	if ac.UnixConn == nil {
		t.Fatal("the accepted connection did not keep the raw *net.UnixConn")
	}
	if att.callCount() != 1 {
		t.Fatalf("attestor called %d times at accept, want 1", att.callCount())
	}
	got, err := ac.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if got != want {
		t.Errorf("identity = %+v, want %+v", got, want)
	}
}

// TestRefusedConnectionStaysOpen: a failed attestation must not close the
// connection at accept, or the caller sees EOF instead of a message telling it
// what to do.
func TestRefusedConnectionStaysOpen(t *testing.T) {
	lis, _ := dialPair(t, &fakeAttestor{err: attest.ErrNotInCatalog})
	c, err := lis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	ac := c.(*Conn)
	if _, err := ac.Identity(); !errors.Is(err, attest.ErrNotInCatalog) {
		t.Fatalf("Identity err = %v, want ErrNotInCatalog", err)
	}
	if err := ac.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
		t.Fatalf("the refused connection is already closed: %v", err)
	}
}

// TestNilAttestorYieldsLegibleError proves an agent built without an
// attestation backend answers rather than hangs.
func TestNilAttestorYieldsLegibleError(t *testing.T) {
	lis, _ := dialPair(t, nil)
	c, err := lis.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := c.(*Conn).Identity(); !errors.Is(err, ErrAttestorUnavailable) {
		t.Fatalf("err = %v, want ErrAttestorUnavailable", err)
	}
}

// TestReattestDetectsPIDReuse covers the renewal rule: process start time is
// re-read and a moved start time means the pid was reused.
func TestReattestDetectsPIDReuse(t *testing.T) {
	first := toolIdentity(t)
	second := toolIdentity(t)
	second.Peer.StartTime = first.Peer.StartTime.Add(time.Second)

	att := &fakeAttestor{onCall: func(n int) (*attest.Identity, error) {
		if n == 1 {
			return first, nil
		}
		return second, nil
	}}
	lis, _ := dialPair(t, att)
	c, _ := lis.Accept()
	ac := c.(*Conn)

	if _, err := ac.Reattest(context.Background()); !errors.Is(err, attest.ErrPIDReused) {
		t.Fatalf("Reattest err = %v, want ErrPIDReused", err)
	}
	// The refusal latches: the connection never gets its identity back.
	if _, err := ac.Identity(); !errors.Is(err, attest.ErrPIDReused) {
		t.Fatalf("Identity after a failed renewal = %v, want ErrPIDReused", err)
	}
}

// TestReattestDetectsChangedBinary covers the other half of the renewal rule:
// the binary is hash-pinned and a moved hash is a refusal.
func TestReattestDetectsChangedBinary(t *testing.T) {
	first := toolIdentity(t)
	second := toolIdentity(t)
	second.BinaryHash = "deadbeef"

	att := &fakeAttestor{onCall: func(n int) (*attest.Identity, error) {
		if n == 1 {
			return first, nil
		}
		return second, nil
	}}
	lis, _ := dialPair(t, att)
	c, _ := lis.Accept()
	if _, err := c.(*Conn).Reattest(context.Background()); !errors.Is(err, attest.ErrSignatureMismatch) {
		t.Fatalf("Reattest err = %v, want ErrSignatureMismatch", err)
	}
}

func TestReattestAcceptsAnUnchangedPeer(t *testing.T) {
	ident := toolIdentity(t)
	att := &fakeAttestor{identity: ident}
	lis, _ := dialPair(t, att)
	c, _ := lis.Accept()
	got, err := c.(*Conn).Reattest(context.Background())
	if err != nil {
		t.Fatalf("Reattest: %v", err)
	}
	if got != ident {
		t.Error("Reattest returned a different identity for an unchanged peer")
	}
}

// TestCredentialsCarryTheAttestedConn proves the handshake publishes the
// attested connection as gRPC auth info, which is how every RPC on the
// connection reads the same identity from its context.
func TestCredentialsCarryTheAttestedConn(t *testing.T) {
	ident := toolIdentity(t)
	lis, _ := dialPair(t, &fakeAttestor{identity: ident})
	c, _ := lis.Accept()

	creds := Credentials()
	_, info, err := creds.ServerHandshake(c)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	ai, ok := info.(AuthInfo)
	if !ok {
		t.Fatalf("auth info is %T, want AuthInfo", info)
	}
	if ai.Conn == nil {
		t.Fatal("auth info does not carry the attested connection")
	}
	if ai.SecurityLevel != credentials.PrivacyAndIntegrity {
		t.Errorf("security level = %v, want PrivacyAndIntegrity", ai.SecurityLevel)
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: ai})
	got, err := IdentityFromContext(ctx)
	if err != nil {
		t.Fatalf("IdentityFromContext: %v", err)
	}
	if got != ident {
		t.Error("the identity on the context is not the one attested at accept")
	}
}

func TestCredentialsRejectAForeignConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, err := Credentials().ServerHandshake(a); !errors.Is(err, ErrNotUnixConn) {
		t.Fatalf("err = %v, want ErrNotUnixConn", err)
	}
}

func TestIdentityFromContextWithoutPeer(t *testing.T) {
	if _, err := IdentityFromContext(context.Background()); !errors.Is(err, ErrNotUnixConn) {
		t.Fatalf("err = %v, want ErrNotUnixConn", err)
	}
}

func TestListenerLogsRefusals(t *testing.T) {
	dir := t.TempDir()
	logPath := dir + "/log.jsonl"
	lis, _ := dialPair(t, &fakeAttestor{err: attest.ErrNotInCatalog})
	lis.log = NewLogger(logPath)
	if _, err := lis.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
	events, err := ReadEvents(logPath, 0)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 1 || events[0].Reason != "not_in_catalog" {
		t.Fatalf("events = %+v, want one not_in_catalog refusal", events)
	}
	if events[0].Fix == "" {
		t.Error("a logged refusal must carry the fix")
	}
	_ = os.Remove(logPath)
}
