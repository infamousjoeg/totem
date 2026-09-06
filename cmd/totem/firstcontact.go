package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// establishIssuer decides, once, that the machine answering at this address is
// the issuer the operator meant, and reports how it decided.
//
// The strong path is decision 18: `totem-issuer init` prints the whole enroll
// command with the certificate fingerprint in the URL fragment, the agent
// verifies against it, and refuses on mismatch. No human compares hex, which
// is the entire point.
//
// The fallback path exists because docs/totem-design.md "Enrollment" step 1
// keeps it, and because a hard refusal strands anyone whose fragment was eaten
// by a chat client, and stranded people invent worse workarounds than the one
// they were denied. But a prompt a human clicks through is trust-on-first-use
// wearing a costume, so this is not that prompt. totem does not ask "is this
// fingerprint OK?", which invites yes. It asks the human to read the value off
// the issuer's own console and type it, and then TOTEM does the comparison.
// The human transcribes; the machine compares. An attacker terminating TLS
// with their own certificate fails, because the value the operator reads off
// their console will not match what the attacker presented.
//
// Whichever path was taken is returned and recorded, and it is never upgraded
// afterwards.
func establishIssuer(ctx context.Context, addr IssuerAddr, in io.Reader, out io.Writer) (IssuerClient, IssuerAddr, string, error) {
	if addr.FingerprintHex != "" {
		client, err := newIssuerClient(addr)
		if err != nil {
			return nil, addr, "", err
		}
		fp, certPEM, err := client.CertificateFingerprint(ctx)
		if err != nil {
			return nil, addr, "", err
		}
		addr.FingerprintHex = fp
		addr.FirstContact = workloadapi.FirstContactFragment
		fmt.Fprintf(out, "  verified %s\n", addr.URL)
		return client, addr, certPEM, nil
	}

	// Fallback. Nothing is pinned yet and nothing here is trusted until the
	// human's transcription matches.
	observed, certPEM, err := observeIssuerCertificate(ctx, addr.URL)
	if err != nil {
		return nil, addr, "", err
	}

	if !interactive(in) {
		return nil, addr, "", failf(
			"Re-run with the whole command your issuer operator gave you (it ends with #sha256:...), or pass --fingerprint sha256:... with the value from your issuer's console.",
			"this enroll link does not identify your issuer, and there is nobody here to check it.")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "This link does not identify your issuer, so totem cannot check it on its own.")
	fmt.Fprintln(out, "That is a weaker way to set this device up, and totem records that it happened.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  something is answering at:  %s\n", addr.URL)
	fmt.Fprintf(out, "  and it identifies itself as: %s\n", groupFingerprint(observed))
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Go to the machine running your issuer. When 'totem-issuer init' ran there, it")
	fmt.Fprintln(out, "printed a line starting with sha256:. Read it from that screen, not from anything")
	fmt.Fprintln(out, "somebody sent you, and type it here. totem will do the comparing.")
	fmt.Fprintf(out, "  (the first %d characters are enough)\n", MinFingerprintPrefix)
	fmt.Fprintln(out)
	fmt.Fprint(out, "  what your issuer's console says: ")

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return nil, addr, "", failf(
			"Run 'totem enroll' again with the value from your issuer's console, or with the whole command that includes #sha256:...",
			"nothing was typed, so this device was not set up.")
	}
	typed, err := ParseFingerprintPrefix(line)
	if err != nil {
		return nil, addr, "", err
	}

	if !strings.HasPrefix(observed, typed) {
		return nil, addr, "", failf(
			"Do not try again until you know why. Check you read the value off the issuer's own console. If it still does not match, something is sitting between this machine and your issuer, and that is worth taking seriously.",
			"that does not match. Your issuer's console says %s, and the machine answering at %s says %s.",
			groupFingerprint(typed), addr.URL, groupFingerprint(observed[:len(typed)]))
	}

	addr.FingerprintHex = observed
	addr.FirstContact = workloadapi.FirstContactPrompt
	fmt.Fprintln(out, "  matched.")

	client, err := newIssuerClient(addr)
	if err != nil {
		return nil, addr, "", err
	}
	return client, addr, certPEM, nil
}

// interactive reports whether there is a human on the other end of in. A
// headless run must fail with the flag to use rather than block forever on a
// question nobody will answer.
func interactive(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		// A test or a pipe wired directly to a reader: treat it as answerable,
		// because something deliberately supplied it.
		return true
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// groupFingerprint renders hex in short groups so a person transcribing it
// does not lose their place.
func groupFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		b.WriteString(fp[i:end])
	}
	return b.String()
}

// describeFirstContact says, in words a person uses, how this device decided
// its issuer was the right one.
func describeFirstContact(fc workloadapi.FirstContact) string {
	switch fc {
	case workloadapi.FirstContactFragment:
		return "checked automatically from your setup link"
	case workloadapi.FirstContactPrompt:
		return "checked by hand against your issuer's console (weaker, and recorded as such)"
	default:
		return "not recorded"
	}
}
