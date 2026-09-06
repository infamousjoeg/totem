package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/infamousjoeg/totem/internal/server"
)

// status is what an operator runs when something is wrong, so it answers the
// questions in the order they get asked: is this issuer set up, can it sign,
// who can administer it, and what is it waiting on.
func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer status -h'.", "could not read those options.")
	}
	dir := issuerDir(*dirFlag)

	rt, err := openRuntime(ctx, dir)
	if err != nil {
		return err
	}
	defer rt.Close()

	identity, err := server.LoadIdentity(tlsDir(dir))
	if err != nil {
		return err
	}
	fmt.Printf("Name:        %s\n", rt.cfg.TrustDomain)
	fmt.Printf("Address:     %s\n", rt.cfg.ExternalURL)
	fmt.Printf("Certificate: sha256:%s\n", identity.FingerprintHex())

	sched, err := rt.ca.Schedule(ctx)
	if err != nil {
		return err
	}
	switch {
	case sched.Current == nil:
		fmt.Println("Signing:     NOT SIGNING. No intermediate certificate is in its signing window.")
		fmt.Println("             Run 'totem-issuer rotate-intermediate' with the root key present.")
	default:
		fmt.Printf("Signing:     until %s\n", sched.RotateBefore.Local().Format(time.RFC1123))
		if sched.Next == nil && time.Now().After(sched.RotateAfter) {
			fmt.Println("             A successor is due. Run 'totem-issuer rotate-intermediate'.")
		}
	}

	devices := rt.issuer.Devices()
	admins := 0
	for _, d := range devices {
		if d.Admin && !d.Revoked {
			admins++
		}
	}
	fmt.Printf("Devices:     %d enrolled, %d administrator(s)\n", len(devices), admins)
	if pending := rt.issuer.Pending(); len(pending) > 0 {
		fmt.Printf("Waiting:     %d device(s) waiting for approval\n", len(pending))
		for _, p := range pending {
			fmt.Printf("             %s (%s, %s) approve with: totem devices approve %s\n",
				p.Hostname, p.OS, p.ProtectionLevel, p.Code)
		}
	}
	if rt.cfg.Secrets.Provider == "" {
		fmt.Println("Secrets:     plain files on this box. Move them into a real secrets provider.")
	} else {
		fmt.Printf("Secrets:     %s\n", rt.cfg.Secrets.Provider)
	}
	return nil
}
