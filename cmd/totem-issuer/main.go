// Command totem-issuer is the broker: a headless box, never the laptop, that
// holds the CA and the exchange references and mints short-lived, device- and
// tool-scoped credentials only after a present human.
//
// docs/totem-design.md "Experience" sets the rules for everything printed here.
// Every question the init wizard asks has a flag, so headless and scripted
// setups never block. An error says what to do next. No stack trace reaches
// this boundary, and no SPIFFE vocabulary reaches a person.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/infamousjoeg/totem/internal/version"
)

const usage = `totem-issuer %s

  totem-issuer init       set this issuer up and print the command to enroll the first device
  totem-issuer serve      run the issuer
  totem-issuer status     what this issuer is, and what it is waiting on
  totem-issuer recover    print a new one-time setup code for a founding device
  totem-issuer bridges    enable, disable, and list the exchanges this issuer serves
  totem-issuer version    print the version

Every question 'init' asks has a flag; run 'totem-issuer init -h' for the list.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Printf(usage, version.Version)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "init":
		err = cmdInit(ctx, args[1:])
	case "serve":
		err = cmdServe(ctx, args[1:])
	case "status":
		err = cmdStatus(ctx, args[1:])
	case "recover":
		err = cmdRecover(ctx, args[1:])
	case "bridges":
		err = cmdBridges(ctx, args[1:])
	case "version", "--version", "-v":
		fmt.Printf("totem-issuer %s\n", version.Version)
		return 0
	case "help", "--help", "-h":
		fmt.Printf(usage, version.Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "totem-issuer: there is no 'totem-issuer %s' command.\n", args[0])
		fmt.Fprintf(os.Stderr, "  Run 'totem-issuer help' to see what this build does.\n")
		return 1
	}
	return report(err)
}
