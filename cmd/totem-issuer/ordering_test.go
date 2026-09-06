package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The ordering inside reseal-ca is load-bearing, and two teammates' packages
// now depend on it being what it is. It cannot be exercised by a unit test,
// because opening a runtime needs a Summon provider that passes the
// root-ownership check, which is fatal by design and has no test seam. So it is
// pinned over the source instead: blunt, and it fails loudly if someone
// reorders the calls, which is the only failure mode that matters here.
//
// What each ordering buys:
//
//   - CanOpen BEFORE ResealCompleted. Adoption retires the old value and wipes
//     it once the retire window passes, so after adopting, internal/summon can
//     no longer give it back and recovery depends entirely on whoever still
//     holds it. Proving the candidate opens the files first means a wrong
//     passphrase is refused while the old value is still recoverable from the
//     person who just typed it.
//   - ResealCompleted BEFORE Reseal. ca.Reseal re-seals under "the passphrase
//     the resolver returns NOW". During a drift alarm internal/summon is
//     deliberately still serving the OLD value, so before adoption every file
//     already opens under the target and there is nothing to do. ca refuses
//     that with ErrPassphraseNotAdopted when a previous value was supplied, but
//     ca has documented one bounded residual: Reseal(ctx, nil) before adoption
//     is still a silent no-op, because the nil-previous case is the legitimate
//     "re-seal whatever memory can reach" call and refusing it would break the
//     idempotent path. This command passes a possibly-empty previous on the
//     offline-root path, so it is exactly the caller that residual would bite
//     if these two calls were ever swapped.

func resealSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("reseal.go")
	if err != nil {
		t.Fatal(err)
	}
	// Strip line comments: the reasoning above and in the command names these
	// calls, and counting the explanation as a call site would make every rule
	// look violated by its own justification.
	return regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(string(data), "")
}

func TestResealAdoptsBeforeItReseals(t *testing.T) {
	t.Parallel()
	src := resealSource(t)

	canOpen := strings.Index(src, "op.CanOpen(")
	adopt := strings.Index(src, "ResealCompleted(")
	reseal := strings.Index(src, "op.Reseal(")

	switch {
	case canOpen < 0:
		t.Fatal("reseal-ca no longer pre-flights with CanOpen, so a wrong passphrase would be discovered " +
			"partway through re-sealing, leaving some keys under one passphrase and some under another")
	case adopt < 0:
		t.Fatal("reseal-ca no longer adopts the new value, so ca.Reseal would re-seal under the value it is " +
			"already sealed under and change nothing")
	case reseal < 0:
		t.Fatal("reseal-ca no longer re-seals anything")
	}

	if canOpen > adopt {
		t.Error("reseal-ca adopts the new value before proving the previous one opens the files. " +
			"Adoption retires the old value, so a wrong passphrase must be refused while it is still recoverable.")
	}
	if adopt > reseal {
		t.Error("reseal-ca re-seals before adopting. Before adoption the resolver is still serving the value " +
			"the files are sealed under, so every file is skipped: with a previous value ca refuses, and with " +
			"the empty previous this command passes on the offline-root path it is a SILENT no-op that reports success.")
	}

	// One call site each. A second Reseal is a second chance to reach it
	// without having adopted.
	if n := strings.Count(src, "op.Reseal("); n != 1 {
		t.Errorf("op.Reseal is called %d times; it must have exactly one call site, after adoption", n)
	}
	if n := strings.Count(src, "ResealCompleted("); n != 1 {
		t.Errorf("ResealCompleted is called %d times; adoption must happen in exactly one place", n)
	}
}

// TestResealReadsThePreviousValueBeforeChangingAnything. An empty stdin must
// change nothing at all, and a wrong value must be refused before either the
// adoption or the first file write.
func TestResealReadsThePreviousValueBeforeChangingAnything(t *testing.T) {
	t.Parallel()
	src := resealSource(t)
	read := strings.Index(src, "readPassphrase(")
	canOpen := strings.Index(src, "op.CanOpen(")
	adopt := strings.Index(src, "ResealCompleted(")

	if read < 0 {
		t.Fatal("reseal-ca no longer reads the previous passphrase from stdin")
	}
	if read > canOpen || read > adopt {
		t.Error("reseal-ca adopts or writes before it has read the previous value. A run with nothing on stdin " +
			"must fail having changed nothing, because after adoption the old value is gone.")
	}
	// And it is never taken from the command line, where it would be readable
	// by every other process on the box.
	if strings.Contains(src, "fs.String(\"previous") || strings.Contains(src, "fs.String(\"passphrase") {
		t.Error("reseal-ca takes a passphrase as a flag")
	}
}
