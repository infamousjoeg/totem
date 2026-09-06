package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// cmdTrust shows the issuer this device is set up to trust, and says plainly
// when the issuer is presenting something different from what was pinned.
// docs/totem-design.md "Experience": totem trust with no argument shows what
// changed and re-pins it.
func cmdTrust(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	printPEM := fs.Bool("pem", false, "print the issuer certificate itself")
	accept := fs.Bool("accept", false, "accept a changed issuer certificate and pin the new one")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem trust'.", "could not read those options.")
	}
	if fs.NArg() > 0 {
		return failf("Run 'totem trust' with no arguments to see your issuer. Pinning individual programs arrives with 'totem init'.",
			"'totem trust %s' is not in this build yet.", fs.Arg(0))
	}

	state, err := workloadapi.LoadState("")
	if err != nil {
		return err
	}
	if !state.Enrolled() {
		return failf("Run the 'totem enroll' command your issuer operator gave you.",
			"this device is not set up with an issuer yet.")
	}

	fmt.Println("Your issuer")
	fmt.Printf("  address:     %s\n", state.IssuerURL)
	fmt.Printf("  verified as: %s\n", shortFingerprint(state.IssuerFingerprint))
	if cert := parsePinnedCert(state.IssuerCertPEM); cert != nil {
		fmt.Printf("  named:       %s\n", cert.Subject.CommonName)
		fmt.Printf("  good until:  %s\n", cert.NotAfter.Local().Format(time.RFC1123))
	}
	if *printPEM {
		fmt.Println()
		fmt.Print(state.IssuerCertPEM)
	}

	client, err := newIssuerClient(IssuerAddr{URL: state.IssuerURL, FingerprintHex: state.IssuerFingerprint})
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	live, livePEM, cerr := client.CertificateFingerprint(cctx)
	if cerr != nil {
		if errors.Is(cerr, ErrIssuerPinMismatch) {
			fmt.Println()
			fmt.Println("Heads up: your issuer is presenting something different from what this device trusts.")
			fmt.Printf("  this device trusts: %s\n", shortFingerprint(state.IssuerFingerprint))
			fmt.Printf("  it is presenting:   %s\n", shortFingerprint(live))
			fmt.Println()
			if !*accept {
				fmt.Println("If your issuer operator told you they replaced it, run 'totem trust --accept'.")
				fmt.Println("If they did not, stop and ask them. Do not accept it.")
				return failf("Ask your issuer operator whether they replaced the issuer certificate before accepting it.",
					"your issuer is not the one this device trusts.")
			}
			state.IssuerFingerprint = live
			state.IssuerCertPEM = livePEM
			if err := state.Save(""); err != nil {
				return err
			}
			fmt.Printf("Accepted. This device now trusts %s.\n", shortFingerprint(live))
			return nil
		}
		fmt.Println()
		fmt.Println("Could not check with your issuer just now: " + asCLIError(cerr).what)
		return nil
	}

	fmt.Println()
	fmt.Println("Checked just now: your issuer is the one this device trusts.")
	state.LastIssuerContact = time.Now().UTC()
	_ = state.Save("")
	return nil
}

// parsePinnedCert decodes the pinned issuer certificate for display. A record
// written by an older build may have no PEM, which is not an error.
func parsePinnedCert(pemStr string) *x509.Certificate {
	if pemStr == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}
