package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/infamousjoeg/totem/internal/server"
)

// docs/totem-design.md "Issuer (broker box)": "`totem issuer recover` on the
// box prints a new bootstrap code and logs loudly."
//
// Loudly is the requirement, and it is worth being precise about why. This
// command mints a code that makes whatever device redeems it the founding
// ADMIN, which is the one way to get administrative control of an issuer
// without an existing admin device's signature. It exists because the
// alternative, a last-admin lockout with no path back, means restoring from
// backup onto a new box. It has to be run on the box itself, so its only
// authorisation is physical or shell access, and the only defence against
// misuse is that it can never happen quietly: one audit line for the mint, one
// for the redemption with the device fingerprint on it, both in the same
// hash-chained stream everything else is in.
func cmdRecover(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives (default "+DefaultIssuerDir+", or $TOTEM_ISSUER_DIR)")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer recover -h' for the list of options.", "could not read those options.")
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
	code, expires, err := rt.issuer.IssueBootstrapCode(ctx)
	if err != nil {
		return err
	}
	if _, err := rt.audit.Log(server.Event{
		Kind:    server.EventBootstrapIssued,
		Target:  rt.cfg.TrustDomain,
		Outcome: "recover",
	}); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "totem-issuer: a new founding-admin setup code was issued by 'recover' on this box.")
	fmt.Fprintln(os.Stderr, "  Any earlier code is now void. The device that redeems this one becomes an administrator.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Set up a device by running this on it:")
	fmt.Fprintln(os.Stderr)

	dest, err := server.EmitBootstrap(os.Stdout, dir,
		"  "+server.EnrollCommand(rt.cfg.ExternalURL, identity.FingerprintHex(), code), expires)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "  "+dest.String())
	return nil
}
