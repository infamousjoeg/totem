package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/infamousjoeg/totem/internal/summon"
)

// docs/totem-design.md "Experience": "Secrets are asked for when a bridge needs
// them. `totem-issuer bridges enable claude` prompts for exactly what that
// bridge needs. `secrets set` is for rotation."
//
// What this command does NOT do is write a secret. docs/totem-design-decisions
// 25: operator-provided secrets are references resolved through Summon,
// READ-ONLY, because "Summon providers can't write". So enabling a bridge
// records which references it needs, then RESOLVES each one to prove it is
// really there, and names the exact command for any that is not. The failure
// this prevents is the one that matters: a bridge that looks enabled at init
// and only discovers its secret is missing at the first exchange, which is the
// first time someone is actually trying to get work done.
//
// SPEC CONFLICT, for the build lead: "Experience" also says `totem secrets set
// <ref>` "prompts on stdin and writes into the configured provider, so
// quickstart and production are the same command", which decision 25 says is
// impossible for a Summon provider. The two can only be reconciled for the
// built-in file provider, which totem itself owns and can write. That is worth
// settling before the Claude bridge lands, because the quickstart depends on it.
func cmdBridges(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return failf("Run 'totem-issuer bridges list', 'bridges enable <name>', or 'bridges disable <name>'.",
			"'bridges' needs to know what to do.")
	}
	switch args[0] {
	case "list":
		return bridgesList(args[1:])
	case "enable":
		return bridgesSet(ctx, args[1:], true)
	case "disable":
		return bridgesSet(ctx, args[1:], false)
	default:
		return failf("Run 'totem-issuer bridges list', 'bridges enable <name>', or 'bridges disable <name>'.",
			"there is no 'bridges %s'.", args[0])
	}
}

func bridgesList(args []string) error {
	fs := flag.NewFlagSet("bridges list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer bridges list -h'.", "could not read those options.")
	}
	cfg, err := Load(issuerDir(*dirFlag))
	if err != nil {
		return err
	}
	names := KnownBridges()
	sort.Strings(names)
	for _, n := range names {
		state := "off"
		if b, ok := cfg.Bridges[n]; ok && b.Enabled {
			state = "on"
		}
		fmt.Printf("  %-8s %s\n", n, state)
	}
	return nil
}

func bridgesSet(ctx context.Context, args []string, enable bool) error {
	fs := flag.NewFlagSet("bridges", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives")
	namespace := fs.String("secrets-namespace", "totem", "prefix for the secret references")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer bridges enable -h'.", "could not read those options.")
	}
	if fs.NArg() != 1 {
		return failf("Name one bridge: "+strings.Join(KnownBridges(), ", "), "which bridge?")
	}
	name := fs.Arg(0)
	dir := issuerDir(*dirFlag)
	cfg, err := Load(dir)
	if err != nil {
		return err
	}
	refs, err := BridgeRefs(*namespace, name)
	if err != nil {
		return failf("Run 'totem-issuer bridges list' to see the bridges this issuer can serve.", "%v", err)
	}
	if cfg.Bridges == nil {
		cfg.Bridges = map[string]Bridge{}
	}
	if !enable {
		delete(cfg.Bridges, name)
		if err := cfg.Save(dir); err != nil {
			return err
		}
		fmt.Printf("The %s bridge is off. Its secrets were left where they are.\n", name)
		return nil
	}

	cfg.Bridges[name] = Bridge{Enabled: true, Refs: refs}
	for i, ref := range refs {
		cfg.Secrets.Refs[fmt.Sprintf("%s_%d", name, i)] = ref
	}
	if err := cfg.Save(dir); err != nil {
		return err
	}

	// Resolve every reference now, so a missing secret is a message here rather
	// than a refused exchange later.
	s, err := openSecrets(ctx, cfg, dir)
	if err != nil {
		return err
	}
	defer s.Close()

	var missing []string
	for _, ref := range refs {
		v, rerr := s.Resolve(ctx, summon.Reference(ref))
		if rerr != nil {
			missing = append(missing, ref)
			continue
		}
		v.Zero()
	}
	if len(missing) > 0 {
		fmt.Printf("The %s bridge is on, but it still needs:\n", name)
		for _, ref := range missing {
			fmt.Printf("  %s   set it with:  totem-issuer secrets set %s\n", ref, ref)
		}
		return nil
	}
	fmt.Printf("The %s bridge is on and every secret it needs is there.\n", name)
	return nil
}
