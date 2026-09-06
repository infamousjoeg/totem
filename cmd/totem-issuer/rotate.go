package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
)

// `totem-issuer rotate-intermediate` prepares the successor to the current
// signing intermediate. It exists as a command because every other place in
// this binary that reports a signing problem names it as the fix, and an error
// message that points at a command which does not exist is worse than one that
// says nothing.
//
// It does NOT make the successor start signing. The clock does that, at
// SigningStart, after the publication overlap has given every relying party
// time to fetch a bundle containing it. That separation is the whole of "with
// overlap": a successor that started signing the moment it was created would be
// rejected by every relying party still holding the previous bundle.
func cmdRotateIntermediate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rotate-intermediate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives (default "+DefaultIssuerDir+", or $TOTEM_ISSUER_DIR)")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer rotate-intermediate -h' for the list of options.", "could not read those options.")
	}
	dir := issuerDir(*dirFlag)

	rt, err := openRuntime(ctx, dir)
	if err != nil {
		return err
	}
	defer rt.Close()

	sched, err := rt.ca.RotateIntermediate(ctx)
	switch {
	case errors.Is(err, ca.ErrRotationPending):
		fmt.Println("Nothing to do. A successor certificate is already published and waiting to start signing.")
		if sched != nil && sched.Next != nil {
			fmt.Printf("  It starts signing at %s.\n", sched.Next.SigningStart.Local().Format(time.RFC1123))
		}
		return nil
	case errors.Is(err, ca.ErrRotationTooSoon):
		if sched != nil {
			return failf(fmt.Sprintf("Run this again after %s.", sched.RotateAfter.Local().Format(time.RFC1123)),
				"it is too early to prepare a successor certificate.")
		}
		return err
	case err != nil:
		return err
	}
	fmt.Println("A successor certificate is prepared and published.")
	if sched.Next != nil {
		fmt.Printf("  It is trusted now and starts signing at %s.\n", sched.Next.SigningStart.Local().Format(time.RFC1123))
	}
	if sched.Current != nil {
		fmt.Printf("  The current one signs until %s.\n", sched.RotateBefore.Local().Format(time.RFC1123))
	}
	return nil
}
