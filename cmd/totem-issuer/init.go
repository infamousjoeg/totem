package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/server"
	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// docs/totem-design.md "Experience": "Quickstart is fifteen minutes with
// Tailscale already installed ... Run the compose file, run `totem-issuer
// init`, paste one command on the laptop."
//
// So init has exactly one output that matters: the single command the operator
// pastes on the laptop, with the certificate fingerprint in the URL fragment
// and the bootstrap code as a flag. Everything else it prints is context for
// that line.
//
// Every question has a flag. That is not a convenience; a wizard that blocks on
// a prompt inside a container's entrypoint, a systemd unit, or a CI job hangs
// forever with no output, and the operator's only signal is a container that
// never becomes ready. With --yes and the flags below, init never reads stdin.

func cmdInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives (default "+DefaultIssuerDir+", or $TOTEM_ISSUER_DIR)")
	externalURL := fs.String("url", "", "the https address devices will reach this issuer on, e.g. https://issuer.tail1234.ts.net")
	trustDomain := fs.String("trust-domain", "", "the name this issuer is known by (default: the hostname in --url; required when it is an IP)")
	listen := fs.String("listen", ":8443", "the address to bind")
	provider := fs.String("secrets-provider", "", "path to a Summon-protocol provider binary (default: the built-in file provider)")
	fileDir := fs.String("secrets-dir", "", "directory the built-in file provider reads secrets from (default <dir>/secrets)")
	namespace := fs.String("secrets-namespace", "totem", "prefix for the secret references written into the config")
	subject := fs.String("subject", "totem", "organisation name placed on the CA certificates")
	bridges := fs.String("bridges", "", "comma-separated bridges to enable now, e.g. claude,aws")
	dailyBackup := fs.Bool("daily-backup", true, "record that a daily backup should be scheduled")
	yes := fs.Bool("yes", false, "accepted and ignored: init never prompts, so there is nothing to confirm")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer init -h' for the list of options.", "could not read those options.")
	}
	// --yes is accepted and does nothing, deliberately. Every value above has a
	// flag and a default and init never reads stdin, so there is no prompt for
	// it to answer; it exists so a script written against the usual wizard
	// convention does not fail on an unknown flag.
	_ = yes

	dir := issuerDir(*dirFlag)
	if alreadyInitialised(dir) {
		return failf("If you need a new setup code for a device, run 'totem-issuer recover'. Setting up again would invalidate every device already enrolled.",
			"this issuer is already set up in %s.", dir)
	}

	external, td, err := resolveNames(*externalURL, *trustDomain)
	if err != nil {
		return err
	}

	cfg := &Config{
		TrustDomain: td,
		ExternalURL: external,
		Listen:      *listen,
		DailyBackup: *dailyBackup,
		Secrets: SecretsConfig{
			Provider:        *provider,
			FileProviderDir: *fileDir,
			Refs:            DefaultRefs(*namespace),
		},
		Bridges: map[string]Bridge{},
	}
	if cfg.Secrets.Provider == "" && cfg.Secrets.FileProviderDir == "" {
		cfg.Secrets.FileProviderDir = dir + "/secrets"
	}
	if cfg.Secrets.Provider != "" {
		// "Provider hash pinned at `issuer init`, logged on every resolve,
		// re-pinned with `trust-provider`." Pinning here rather than on first
		// resolve is what makes a later change a refusal instead of a silent
		// acceptance of whatever binary is at that path now.
		hash, herr := summon.TrustProvider(cfg.Secrets.Provider)
		if herr != nil {
			return herr
		}
		cfg.Secrets.ProviderHash = hash
	}
	for _, b := range splitList(*bridges) {
		refs, berr := BridgeRefs(*namespace, b)
		if berr != nil {
			return failf("Run 'totem-issuer bridges list' to see the bridges this issuer can serve.", "%v", berr)
		}
		cfg.Bridges[b] = Bridge{Enabled: true, Refs: refs}
		for i, ref := range refs {
			cfg.Secrets.Refs[fmt.Sprintf("%s_%d", b, i)] = ref
		}
	}
	if err := cfg.Save(dir); err != nil {
		return err
	}

	rt := &runtime{cfg: cfg, dir: dir, audit: server.NewAuditLog(os.Stdout, nil)}
	defer rt.Close()

	if rt.summoner, err = openSecrets(ctx, cfg, dir); err != nil {
		return err
	}
	caPassRef, err := rt.summoner.Ref(CAPassphraseRefName)
	if err != nil {
		return err
	}
	if rt.ca, err = ca.Init(ctx, ca.InitParams{
		Config: ca.Config{
			Dir:           caDir(dir),
			Resolver:      rt.summoner,
			PassphraseRef: caPassRef,
			TrustDomain:   td,
		},
		Subject: *subject,
	}); err != nil {
		return err
	}
	if rt.db, err = store.Open(ctx, statePath(dir), store.Options{Resolver: rt.summoner}); err != nil {
		return err
	}
	if rt.issuer, err = newPolicy(ctx, cfg, rt.db); err != nil {
		return err
	}

	// The front-door certificate is generated last of the fallible steps,
	// because its fingerprint is what the enroll command carries and there is
	// no point pinning a certificate for an issuer that could not finish
	// starting.
	hosts, err := server.HostsFor(external)
	if err != nil {
		return err
	}
	identity, err := server.GenerateIdentity(tlsDir(dir), hosts, time.Now())
	if err != nil {
		return err
	}

	code, expires, err := rt.issuer.IssueBootstrapCode(ctx)
	if err != nil {
		return err
	}
	// The audit line records THAT a founding code exists and when it dies. The
	// code itself has no field to travel in; see internal/server/bootstrap.go.
	if _, err := rt.audit.Log(server.Event{
		Kind: server.EventBootstrapIssued, Target: td, Outcome: "issued",
	}); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("This issuer is %s, reachable at %s.\n", td, external)
	fmt.Printf("Its state is in %s.\n", dir)
	if cfg.Secrets.Provider == "" {
		// "The file provider refuses world or group readable files, refuses
		// paths inside a git worktree or synced folder, and logs 'move these'
		// on every start. Not silenceable."
		fmt.Println()
		fmt.Println("Secrets are in plain files on this box, which is the weakest option and is fine for trying totem out.")
		fmt.Printf("  They are in %s. Move them into a real secrets provider before you rely on this.\n", cfg.Secrets.FileProviderDir)
	}
	if server.IsIPOnly(external) {
		fmt.Println()
		fmt.Println("This issuer is reachable only by address, so approvals happen from an enrolled device rather than in a browser.")
	}
	// The enroll command carries the bootstrap code, so it is emitted through
	// EmitBootstrap and NOWHERE else. Printing it here as well would put the
	// founding-admin code on stdout in exactly the captured-output cases the
	// TTY check exists to protect: a container log, a systemd journal, a CI
	// artifact. The preamble is safe to print because it carries nothing.
	fmt.Println()
	fmt.Println("Set up your first device by running this on it:")
	fmt.Println()
	dest, err := server.EmitBootstrap(os.Stdout, dir, "  "+server.EnrollCommand(external, identity.FingerprintHex(), code), expires)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "  "+dest.String())
	fmt.Println("That device becomes this issuer's administrator. Every device after it is approved from one that is already set up.")
	return nil
}

// resolveNames works out the issuer's address and its name.
//
// docs/totem-design.md "Identity model": "Trust domain defaults to the issuer
// hostname given at enroll; IP-only issuers require one explicitly." An address
// is not a name: it changes with the network path, and the trust domain is the
// one string the issuer and every device must agree on before an enrollment can
// finish. Guessing one from an IP would produce a name that stops being true
// the first time the box moves.
func resolveNames(externalURL, trustDomain string) (string, string, error) {
	if externalURL == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			return "", "", failf("Run 'totem-issuer init --url https://<the address devices will use>'.",
				"totem-issuer could not work out what address devices will reach this issuer on.")
		}
		externalURL = "https://" + host
	}
	if !strings.Contains(externalURL, "://") {
		externalURL = "https://" + externalURL
	}
	u, err := url.Parse(externalURL)
	if err != nil || u.Hostname() == "" {
		return "", "", failf("Give the whole address, starting with https://.",
			"%q is not an address devices can reach.", externalURL)
	}
	if u.Scheme != "https" {
		return "", "", failf("Give an https:// address. Devices pin this issuer's certificate, so plain http is never used.",
			"the issuer address must start with https://, and %q does not.", externalURL)
	}
	external := strings.TrimSuffix(u.String(), "/")
	if trustDomain != "" {
		return external, trustDomain, nil
	}
	if server.IsIPOnly(external) {
		return "", "", failf("Run init again with --trust-domain <name>, using the name you want this issuer known by.",
			"this issuer is reachable only by address, so it needs to be told its name.")
	}
	return external, u.Hostname(), nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
