package main

import (
	"context"
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

// openRuntime opens an issuer that has already been initialised.
func openRuntime(ctx context.Context, dir string) (*runtime, error) {
	cfg, err := Load(dir)
	if err != nil {
		return nil, err
	}
	rt := &runtime{cfg: cfg, dir: dir, audit: server.NewAuditLog(os.Stdout, nil)}

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
