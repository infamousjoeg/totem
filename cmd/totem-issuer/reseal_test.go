package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestPassphraseIsNeverAcceptedOnTheCommandLine. There is no plaintext path and
// no key flag anywhere in totem, and a secret in argv is a secret in `ps`, in
// shell history, and in a process listing any other user on the box can read.
func TestPassphraseIsNeverAcceptedOnTheCommandLine(t *testing.T) {
	t.Parallel()
	err := cmdResealCA(context.Background(), []string{"--dir", t.TempDir(), "my-old-passphrase"})
	if err == nil {
		t.Fatal("a passphrase given as an argument was accepted")
	}
	ce := classify(err)
	if !strings.Contains(ce.what, "no passphrase on the command line") {
		t.Errorf("the refusal does not say why: %q", ce.what)
	}
	if !strings.Contains(ce.fix, "stdin") {
		t.Errorf("the fix does not point at stdin: %q", ce.fix)
	}
	// And it refuses BEFORE opening anything, so a mistyped invocation on a
	// live issuer does not resolve secrets or touch CA material on its way to
	// the error.
	if strings.Contains(ce.what, "not been set up") {
		t.Error("the argument check ran after the issuer was opened")
	}
}

// TestReadPassphrasePreservesTheValueExactly. A passphrase may legitimately
// begin or end with a space, and quietly trimming one turns a correct value
// into a wrong one with no way to tell which happened.
func TestReadPassphrasePreservesTheValueExactly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"hunter2\n", "hunter2"},
		{"hunter2", "hunter2"},         // no trailing newline, as a pipe often gives
		{"hunter2\r\n", "hunter2"},     // a file written on Windows
		{"  spaces  \n", "  spaces  "}, // preserved on purpose
		{"with spaces inside\n", "with spaces inside"},
		{"\n", ""},
	} {
		got, err := readPassphrase(strings.NewReader(tc.in), &bytes.Buffer{})
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Errorf("readPassphrase(%q) = %q, want %q", tc.in, string(got), tc.want)
		}
	}
}

// TestReadPassphraseDoesNotPromptWhenPiped. A prompt written into a pipe is
// noise in whatever is capturing it, and there is nobody there to read it.
func TestReadPassphraseDoesNotPromptWhenPiped(t *testing.T) {
	t.Parallel()
	var prompt bytes.Buffer
	if _, err := readPassphrase(strings.NewReader("hunter2\n"), &prompt); err != nil {
		t.Fatal(err)
	}
	if prompt.Len() != 0 {
		t.Errorf("a prompt was written to a non-terminal input: %q", prompt.String())
	}
}

// TestZeroWipes. The previous passphrase is wiped once it is no longer needed.
func TestZeroWipes(t *testing.T) {
	t.Parallel()
	b := []byte("hunter2")
	zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d was not wiped", i)
		}
	}
}
