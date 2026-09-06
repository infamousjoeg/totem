// Command totem is the laptop agent: it holds a hardware-bound device key,
// presence-gates signing, and serves the SPIFFE Workload API on a unix socket
// so anything that already speaks SPIFFE works unchanged.
//
// docs/totem-design.md "Experience" sets the rules for everything printed here.
// The command surface fits on one screen. An error tells the human what to do
// next; no stack trace ever reaches this boundary. There is no SPIFFE
// vocabulary in user-facing output: identity, your issuer, verified, confirm
// it's you. The spec terms live in the docs and behind --verbose.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	toterrors "github.com/infamousjoeg/totem/internal/errors"
	"github.com/infamousjoeg/totem/internal/version"
)

const usage = `totem %s

  totem enroll <link>   set this device up with your issuer
  totem status          what this device is, and what it can do right now
  totem doctor          check this machine and print the fix for anything wrong
  totem trust           show the issuer this device is set up to trust
  totem log             what totem refused, asked, or could not do
  totem serve           run the agent (normally started for you at login)
  totem uninstall       undo exactly what totem changed on this machine
  totem version         print the version

Device administration lives under 'totem devices' and agent delegation under
'totem agents'. Both arrive with the issuer.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Printf(usage, version.Version)
		return toterrors.ExitTerminal
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "enroll":
		err = cmdEnroll(ctx, args[1:])
	case "status":
		err = cmdStatus(ctx, args[1:])
	case "doctor":
		err = cmdDoctor(ctx, args[1:])
	case "trust":
		err = cmdTrust(ctx, args[1:])
	case "log":
		err = cmdLog(ctx, args[1:])
	case "serve":
		err = cmdServe(ctx, args[1:])
	case "uninstall":
		err = cmdUninstall(ctx, args[1:])
	case "version", "--version", "-v":
		fmt.Printf("totem %s\n", version.Version)
		return toterrors.ExitOK
	case "help", "--help", "-h":
		fmt.Printf(usage, version.Version)
		return toterrors.ExitOK
	case "init", "run", "devices", "agents":
		err = failf("Run 'totem help' to see what this build does. This command arrives with the issuer.",
			"'totem %s' is not in this build yet.", args[0])
	default:
		fmt.Fprintf(os.Stderr, "totem: there is no 'totem %s' command.\n", args[0])
		fmt.Printf(usage, version.Version)
		return toterrors.ExitTerminal
	}

	return report(err)
}
