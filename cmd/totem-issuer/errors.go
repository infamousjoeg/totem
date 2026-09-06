package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/policy"
	"github.com/infamousjoeg/totem/internal/server"
	"github.com/infamousjoeg/totem/internal/store"
	"github.com/infamousjoeg/totem/internal/summon"
)

// docs/totem-design.md "Experience": an error tells the human what to do next,
// and no stack trace ever reaches this boundary. The issuer's operator is a
// person at a terminal on a headless box, usually because something already
// went wrong, so every failure here is two lines: what happened, and the exact
// next command.

// cliError is a failure with the sentence and the fix.
type cliError struct {
	what  string
	fix   string
	cause error
}

func (e *cliError) Error() string { return e.what }
func (e *cliError) Unwrap() error { return e.cause }

func failf(fix, format string, args ...any) *cliError {
	return &cliError{what: fmt.Sprintf(format, args...), fix: fix}
}

// classify turns the typed errors the issuer packages raise into the two lines
// a person reads. Every case here exists because the underlying error names a
// condition whose fix is a specific command, and printing the raw error would
// make the operator go and find that command themselves.
func classify(err error) *cliError {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce
	}
	switch {
	case errors.Is(err, ErrNotInitialized), errors.Is(err, ca.ErrNotInitialized), errors.Is(err, server.ErrNoIdentity):
		return failf("Run 'totem-issuer init'.", "this issuer has not been set up yet.")
	case errors.Is(err, ca.ErrAlreadyInitialized), errors.Is(err, server.ErrIdentityExists):
		return failf("If you need a new setup code for a device, run 'totem-issuer recover'. Setting up again would invalidate every device already enrolled.",
			"this issuer is already set up.")
	case errors.Is(err, summon.ErrProviderUnsafe):
		return &cliError{cause: err,
			what: fmt.Sprintf("the secrets provider is not safe to run: %v", err),
			fix:  "Make the provider binary and every directory above it owned by root and not writable by anyone else, then try again."}
	case errors.Is(err, summon.ErrProviderUntrusted):
		return &cliError{cause: err,
			what: "the secrets provider is not the one this issuer pinned.",
			fix:  "If you upgraded it on purpose, run 'totem-issuer trust-provider'. If you did not, stop and find out why it changed."}
	case errors.Is(err, summon.ErrNoSuchReference), errors.Is(err, summon.ErrBadReference):
		return &cliError{cause: err,
			what: fmt.Sprintf("a secret this issuer needs is not configured: %v", err),
			fix:  "Add it with 'totem-issuer secrets set <name>', or check the refs block in the issuer config."}
	case errors.Is(err, store.ErrProviderNotConfigured):
		return failf("Run 'totem-issuer init' first, or point the config at your secrets provider.",
			"this issuer cannot reach its secrets provider, so it will not open its database.")
	case errors.Is(err, store.ErrChainBroken):
		return failf("Do not restart it and do not repair it. The log is evidence. Restore from a backup on a clean box.",
			"this issuer's records failed their own integrity check.")
	case errors.Is(err, store.ErrSchemaAhead):
		return failf("Run the newer issuer, or restore a backup taken by this version.",
			"this issuer's database was written by a newer version of totem-issuer.")
	case errors.Is(err, ca.ErrRootOffline):
		return failf("Bring the root key to this box and run the command again.",
			"the root key is not reachable, and this needs it.")
	case errors.Is(err, ca.ErrNoSigningIntermediate):
		return failf("Run 'totem-issuer rotate-intermediate' with the root key present.",
			"no intermediate certificate is in its signing window, so this issuer cannot sign anything.")
	case errors.Is(err, policy.ErrLastAdmin):
		return failf("Make another device an administrator first.",
			"that is the last administrator device, so the issuer will not remove it.")
	case errors.Is(err, server.ErrBootstrapSink):
		return &cliError{cause: err,
			what: fmt.Sprintf("the setup code could not be written anywhere safe: %v", err),
			fix:  "Run this from a terminal, or make sure the issuer directory is writable and try again."}
	}
	return &cliError{what: err.Error(), fix: "Check the issuer log for more."}
}

// report prints a failure and returns the exit code.
func report(err error) int {
	if err == nil {
		return 0
	}
	ce := classify(err)
	fmt.Fprintln(os.Stderr, "totem-issuer: "+ce.what)
	if ce.fix != "" {
		fmt.Fprintln(os.Stderr, "  "+ce.fix)
	}
	return 1
}
