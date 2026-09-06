package main

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/server"
	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// runtime is everything the issuer needs open at once. It exists so init,
// serve, recover and status open the same things in the same order and fail in
// the same place, rather than four call sites each getting the dependency graph
// slightly differently.
//
// The order is not arbitrary. Secrets come first because everything else needs
// a value from them and a provider that fails hardening is fatal; the CA and
// the store both resolve through it; the policy engine reads its signed state
// out of the store and re-verifies it on load. Anything that fails leaves the
// earlier things closed, in reverse.
type runtime struct {
	cfg      *Config
	dir      string
	summoner *summon.Summoner
	ca       ca.Authority
	db       *store.DB
	issuer   *policy.Issuer
	audit    *server.AuditLog
	identity *server.IssuerIdentity
}

func (rt *runtime) Close() {
	if rt == nil {
		return
	}
	if rt.db != nil {
		_ = rt.db.Close()
	}
	if rt.ca != nil {
		_ = rt.ca.Close()
	}
	if rt.summoner != nil {
		_ = rt.summoner.Close()
	}
}

// openSecrets starts the Summon resolver. It is separate because `init` needs
// the resolver BEFORE the CA exists, and because a provider that fails the
// ownership and permission check must stop the command right here with the path
// named, rather than surfacing later as a CA that could not read its passphrase.
func openSecrets(ctx context.Context, cfg *Config, dir string) (*summon.Summoner, error) {
	s, err := summon.New(cfg.Summon(dir))
	if err != nil {
		return nil, err
	}
	if err := s.Start(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// AuditSinkStdout and AuditSinkStderr are the values Config.AuditSink accepts.
// Empty means the default for the command, which is the rule below.
const (
	AuditSinkStdout = "stdout"
	AuditSinkStderr = "stderr"
)

// commandKind says what a command's STDOUT belongs to, which is the only thing
// that decides where the audit stream can go.
type commandKind int

const (
	// oneShot is a command that runs, prints a result, and exits. Its stdout
	// belongs to whoever invoked it: `init` writes the enroll command there on
	// purpose and a scripted setup captures it, `status` prints for a person.
	oneShot commandKind = iota
	// longRunning is `serve`. Nothing else consumes its stdout, so the audit
	// stream can have it.
	longRunning
)

// auditSink returns where the hash-chained audit stream is written.
//
// THE INVARIANT IS THE SINK, NOT STDOUT, and getting that backwards is what
// produced the defect this function exists to fix. The rule used to be written
// as "stdout is the audit stream", which is true of serve and false of every
// one-shot command, because a one-shot command's stdout already belongs to its
// caller. So `init` was emitting a JSON audit record into the same stream a
// scripted setup reads the enroll command from, and into the middle of a
// person's terminal output. init was not the thing that was wrong; the
// invariant was.
//
// The rule, which a new command inherits by having to name its kind:
//
//   - longRunning: stdout, because serve has no other consumer for it.
//   - oneShot: stderr, so stdout carries the command's result and nothing else.
//
// Why it matters beyond tidiness: the audit stream is itself hash-chained, so a
// consumer that has learned to skip unparseable lines is a consumer that will
// skip a TAMPERED one. A stream that never contains a non-JSON line is a stream
// whose reader never needs that habit.
//
// ONE THING THIS DOES NOT DO, stated so nobody infers it. A one-shot command's
// stderr carries its human messages too, so its audit records share a stream
// with prose. That is fine and is not the case the rule is about: a log shipper
// is pointed at the long-running issuer, whose stdout is the audit stream and
// carries nothing else, and a one-shot's audit record is a line for the
// operator running it and for whatever captured that session. Point a shipper
// at a one-shot's stderr and it will see prose. The property being protected is
// that the SHIPPED stream never contains a line its reader must learn to skip,
// because a reader with that habit will skip a tampered one.
//
// Config.AuditSink overrides the default either way, in the same shape the
// syslog and OTLP exports will take. An operator who points a one-shot command
// at stdout gets the contamination back, deliberately and on their own head.
func auditSink(cfg *Config, kind commandKind) io.Writer {
	switch cfg.auditSink() {
	case AuditSinkStdout:
		return os.Stdout
	case AuditSinkStderr:
		return os.Stderr
	}
	if kind == longRunning {
		return os.Stdout
	}
	return os.Stderr
}

// openRuntime opens an issuer that has already been initialised.
func openRuntime(ctx context.Context, dir string, kind commandKind) (*runtime, error) {
	cfg, err := Load(dir)
	if err != nil {
		return nil, err
	}
	rt := &runtime{cfg: cfg, dir: dir, audit: server.NewAuditLog(auditSink(cfg, kind), nil)}

	if rt.summoner, err = openSecrets(ctx, cfg, dir); err != nil {
		return nil, err
	}
	caPassRef, err := rt.summoner.Ref(CAPassphraseRefName)
	if err != nil {
		rt.Close()
		return nil, err
	}
	if rt.ca, err = ca.Open(ctx, ca.Config{
		Dir:           caDir(dir),
		Resolver:      rt.summoner,
		PassphraseRef: caPassRef,
		TrustDomain:   cfg.TrustDomain,
	}); err != nil {
		rt.Close()
		return nil, err
	}
	if rt.db, err = store.Open(ctx, statePath(dir), store.Options{Resolver: rt.summoner}); err != nil {
		rt.Close()
		return nil, err
	}
	if rt.issuer, err = newPolicy(ctx, cfg, rt.db); err != nil {
		rt.Close()
		return nil, err
	}
	// The issuer's own identity key. Created on first open and kept as an
	// envelope-encrypted row, so backup carries it and rotate-data-key
	// re-encrypts it along with everything else. Creating it here rather than
	// at first use means it exists before the first backup rather than after
	// whichever restart happens to need it.
	if rt.identity, err = server.NewIssuerIdentity(rt.db, rt.ca); err != nil {
		rt.Close()
		return nil, err
	}
	if _, err = rt.identity.Key(ctx); err != nil {
		rt.Close()
		return nil, err
	}
	return rt, nil
}

// newPolicy wires the policy engine to the presence primitives.
//
// The presence primitives are constructed HERE, once, and shared. Sessions,
// challenges, grants and parked requests are issuer-side state that "is never
// persisted; a restart means every tool prompts once", so a second SessionStore
// or a second Verifier anywhere in the process would be a second, invisible set
// of windows and a challenge minted by one that the other has never heard of.
func newPolicy(ctx context.Context, cfg *Config, db *store.DB) (*policy.Issuer, error) {
	return policy.New(ctx, policy.Config{
		TrustDomain: cfg.TrustDomain,
		Verifier:    presence.NewVerifier(0, nil),
		Sessions:    presence.NewSessionStore(nil),
		Grants:      presence.NewRegistry(nil),
		Lot:         presence.NewLot(nil, 0, 0),
		Store:       db,
		Windows:     presence.DefaultWindows(),
	})
}

// newServer builds the front door over an open runtime.
func newServer(rt *runtime) (*server.Server, error) {
	identity, err := server.LoadIdentity(tlsDir(rt.dir))
	if err != nil {
		return nil, err
	}
	return server.New(server.Config{
		TrustDomain: rt.cfg.TrustDomain,
		Addr:        rt.cfg.Listen,
		ExternalURL: rt.cfg.ExternalURL,
		Identity:    identity,
		CA:          rt.ca,
		Engine:      rt.issuer,
		Audit:       rt.audit,
	})
}

// issuerDir is the issuer directory a command was pointed at.
func issuerDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("TOTEM_ISSUER_DIR"); v != "" {
		return v
	}
	return DefaultIssuerDir
}

// DefaultIssuerDir is where issuer state lives in the shipped container.
const DefaultIssuerDir = "/var/lib/totem"

// alreadyInitialised reports whether an issuer already exists at dir, so a
// second `init` refuses instead of overwriting a live root and silently
// invalidating every enrolled device at once.
func alreadyInitialised(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ConfigFile))
	return err == nil
}
