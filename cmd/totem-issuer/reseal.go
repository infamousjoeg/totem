package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/server"
)

// `totem-issuer reseal-ca` is the deliberate path for changing the passphrase
// that seals the CA private keys on disk.
//
// The failure it exists to prevent is quiet and delayed. The CA passphrase is
// resolved through Summon, and Summon's rotation is pull-based. If that value
// is replaced while the issuer is running, nothing breaks: the keys are already
// unsealed in memory. The issuer keeps signing, keeps serving, keeps looking
// healthy, and then fails to open at the next restart with the old value gone
// for good. The reference is excluded from automatic rotation for that reason,
// and the watcher shouts if it changes anyway; this command is what the
// operator runs, either because they meant to change it or because the shouting
// started.
//
// TWO THINGS IT WILL NOT DO.
//
// It does not take either passphrase as a flag. There is no plaintext path and
// no key flag anywhere in totem, and a secret in argv is a secret in `ps`, in
// shell history, and in a process listing any other user on the box can read.
// The NEW value is not an input at all: it is whatever the provider returns
// now, so the operator changes it in the provider first and this command
// catches the CA up. The PREVIOUS value is read from stdin, so it can be piped
// from the provider and never has to be typed.
//
// It does not write anything when the previous value is wrong. internal/ca's
// Reseal rewrites files one at a time, and a directory where some keys are
// under the new passphrase and some under the old opens today and fails at the
// next restart, which is the exact failure this whole mechanism exists to
// remove. So the current value is checked first, the previous value is checked
// against a file before the loop can start on a wrong one, and the result is
// confirmed by asking the real question afterwards: would a restart succeed.
func cmdResealCA(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reseal-ca", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dirFlag := fs.String("dir", "", "where issuer state lives (default "+DefaultIssuerDir+", or $TOTEM_ISSUER_DIR)")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem-issuer reseal-ca -h' for the list of options.", "could not read those options.")
	}
	if fs.NArg() > 0 {
		return failf("Pipe the previous passphrase in on stdin instead: totem-issuer reseal-ca < old-passphrase",
			"reseal-ca takes no passphrase on the command line, because anything in a command line is readable by every other process on this box.")
	}
	dir := issuerDir(*dirFlag)

	rt, err := openRuntime(ctx, dir)
	if err != nil {
		return err
	}
	defer rt.Close()

	op, ok := rt.ca.(ca.PassphraseOperator)
	if !ok {
		return failf("There is nothing to re-seal on this issuer.",
			"this issuer's CA does not seal its keys with a passphrase.")
	}

	// Ask the real question first: does a restart succeed right now. If it
	// does, there is nothing to do, and doing nothing is the correct outcome
	// rather than a re-seal that rewrites every file for no reason.
	switch err := op.VerifyPassphrase(ctx); {
	case err == nil:
		fmt.Println("Nothing to do. The CA material already opens under the passphrase your provider returns, so this issuer will restart.")
		return nil
	case !errors.Is(err, ca.ErrPassphraseChanged):
		return err
	}

	fmt.Fprintln(os.Stderr, "The CA material does not open under the passphrase your provider returns now, so this issuer will not restart until it is re-sealed.")
	previous, err := readPassphrase(os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	defer zero(previous)
	if len(previous) == 0 {
		return failf("Pipe it in: totem-issuer reseal-ca < old-passphrase",
			"re-sealing needs the previous passphrase, and none was given on stdin.")
	}

	if err := op.Reseal(ctx, previous); err != nil {
		if errors.Is(err, ca.ErrPassphraseChanged) {
			return failf(
				"Check that what you piped in is the passphrase the provider returned BEFORE the change, then run reseal-ca again. "+
					"Re-sealing is idempotent, so re-running it with the right value finishes the job.",
				"that is not the passphrase the CA material is sealed under, so nothing further was changed.")
		}
		return err
	}

	// Confirm the property that was actually wanted rather than trusting that
	// the writes added up to it.
	if err := op.VerifyPassphrase(ctx); err != nil {
		return err
	}
	if _, err := rt.audit.Log(server.Event{
		Kind:    server.EventPassphraseChanged,
		Target:  rt.cfg.TrustDomain,
		Outcome: "resealed",
	}); err != nil {
		return err
	}
	fmt.Println("The CA material is re-sealed under the passphrase your provider returns now. This issuer will restart.")
	return nil
}

// readPassphrase reads the previous passphrase from stdin.
//
// NOTE, for the build lead: terminal echo is not disabled, because doing that
// without golang.org/x/term means shelling out to stty, and go.mod is not mine
// to add to. So a passphrase TYPED at a terminal is visible on screen. It is
// never in argv, never in shell history, and never in a process listing, which
// are the exposures that outlast the moment; the screen is the one that does
// not. The prompt says so, and the documented form pipes it in. If x/term is
// acceptable, this becomes three lines and the caveat goes away.
func readPassphrase(in io.Reader, prompt io.Writer) ([]byte, error) {
	if f, ok := in.(*os.File); ok && isTerminalFile(f) {
		fmt.Fprintln(prompt, "Type the PREVIOUS passphrase and press enter. It will be visible on screen;")
		fmt.Fprintln(prompt, "to avoid that, pipe it in instead: totem-issuer reseal-ca < old-passphrase")
		fmt.Fprint(prompt, "Previous passphrase: ")
	}
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if f, ok := in.(*os.File); ok && isTerminalFile(f) {
		fmt.Fprintln(prompt)
	}
	// Only the trailing newline is stripped. A passphrase may legitimately
	// begin or end with a space, and quietly trimming one would turn a correct
	// value into a wrong one with no way to tell.
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// isTerminalFile reports whether f is a character device.
func isTerminalFile(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// zero wipes a passphrase buffer once it is no longer needed.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
