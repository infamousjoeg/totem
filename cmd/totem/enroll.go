package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/workloadapi"
)

// newIssuerClient is a package variable so tests can drive enroll without a
// network. Production always gets the pinned HTTPS client.
var newIssuerClient = NewIssuerClient

// cmdEnroll implements the first step of docs/totem-design.md "Enrollment":
// totem enroll https://issuer#sha256:... fetches the issuer certificate,
// verifies it against the fragment, and refuses on mismatch. Decision 18 puts
// the fingerprint in the fragment precisely so humans never compare hex.
//
// This build accepts no other first contact. There is no trust-on-first-use
// prompt and no skip flag: the fragment is the whole basis for trusting the
// issuer, and an enroll that trusts whatever answers has enrolled nothing.
func cmdEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	code := fs.String("code", "", "the one-time bootstrap code from 'totem-issuer init', for the founding device")
	trustDomain := fs.String("trust-domain", "", "trust domain to use when the issuer is reachable only by IP")
	socket := fs.String("socket", "", "where to serve the workload socket (default ~/.totem/agent.sock)")
	if err := fs.Parse(args); err != nil {
		return failf("Run 'totem enroll <link>' with the command your issuer operator gave you.", "could not read those options.")
	}
	if fs.NArg() != 1 {
		return failf("Run 'totem enroll <link>', using the whole command your issuer operator gave you, including the part after the # sign.",
			"enroll needs the issuer link your issuer operator gave you.")
	}

	addr, err := ParseIssuerURL(fs.Arg(0))
	if err != nil {
		return err
	}
	client, err := newIssuerClient(addr)
	if err != nil {
		return err
	}

	if existing, lerr := workloadapi.LoadState(""); lerr == nil && existing.Enrolled() {
		return failf("If you meant to start over, run 'totem uninstall' first. It will show you exactly what it is about to undo.",
			"this device is already set up with %s.", existing.IssuerURL)
	}

	// Verify the issuer before anything is created. An issuer that cannot be
	// reached or does not match its link must never leave a device key behind.
	fmt.Println("Checking your issuer...")
	fingerprint, certPEM, err := client.CertificateFingerprint(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("  verified %s\n", addr.URL)

	td := *trustDomain
	if td == "" {
		td = hostOf(addr.URL)
	}
	if td == "" {
		return failf("Re-run with --trust-domain <name>, using the name your issuer operator gave you.",
			"your issuer is reachable only by address, so totem needs to be told the name to use.")
	}

	// Ask for the challenge before generating a key, for the same reason: a
	// failure here must not orphan a key the issuer will never know about.
	hostname, _ := os.Hostname()
	challenge, err := client.Challenge(ctx, ChallengeRequest{Hostname: hostname, OS: runtime.GOOS})
	if err != nil {
		return err
	}

	if platform.Open == nil {
		return failf("Run 'totem doctor' to see what this build is missing.",
			"this build of totem cannot create a device key.")
	}
	store, err := platform.Open(ctx)
	if err != nil {
		return failf("Run 'totem doctor' for what this machine can do.",
			"totem could not open a place to keep this device's key: %v", err)
	}

	manifest, err := LoadManifest("")
	if err != nil {
		return err
	}
	manifest.RecordDir(totemDir(), "the folder totem keeps this device's settings in")

	key, err := store.Generate(ctx, platform.DeviceKeyLabel)
	if errors.Is(err, platform.ErrKeyExists) {
		return failf("Run 'totem uninstall' to clear the old setup, then enroll again.",
			"this device already has a key from an earlier setup.")
	}
	if err != nil {
		return failf("Run 'totem doctor' for what this machine can do.",
			"totem could not create this device's key: %v", err)
	}
	manifest.RecordKey(platform.DeviceKeyLabel, "this device's key")

	fmt.Println("Confirm it's you to finish setting this device up.")
	sig, err := key.Sign(ctx, challenge.Challenge, platform.Prompt{
		Required: true,
		Tool:     "totem",
		Target:   addr.URL,
		DeviceID: hostname,
	})
	if err != nil {
		switch {
		case errors.Is(err, platform.ErrPresenceDenied):
			return failf("Run 'totem enroll' again and approve the prompt within 60 seconds.",
				"the confirmation was declined or timed out, so nothing was set up.")
		case errors.Is(err, platform.ErrPresenceUnavailable):
			// A device with no way to confirm a person is present still
			// enrolls; the fact is recorded and carried, never faked.
			fmt.Println("  this device cannot confirm a person is present, so that is recorded as part of its setup.")
		default:
			return failf("Run 'totem doctor' for what this machine can do.",
				"totem could not use this device's key: %v", err)
		}
	}

	pubDER, err := publicKeyDER(key.Public())
	if err != nil {
		return failf("Run 'totem doctor' for what this machine can do.",
			"totem could not read this device's own key back: %v", err)
	}

	resp, err := client.Enroll(ctx, EnrollRequest{
		PublicKeyDER:    pubDER,
		ProtectionLevel: key.ProtectionLevel(),
		Hostname:        hostname,
		OS:              runtime.GOOS,
		Challenge:       challenge.Challenge,
		Signature:       sig,
		BootstrapCode:   *code,
	})
	if err != nil {
		return err
	}
	if resp.TrustDomain != "" {
		td = resp.TrustDomain
	}

	sockPath := *socket
	if sockPath == "" {
		sockPath = workloadapi.DefaultSocketPath()
	}
	state := &workloadapi.State{
		TrustDomain:       td,
		DeviceID:          resp.DeviceID,
		IssuerURL:         addr.URL,
		IssuerFingerprint: fingerprint,
		IssuerCertPEM:     certPEM,
		ProtectionLevel:   key.ProtectionLevel(),
		KeyLabel:          platform.DeviceKeyLabel,
		SocketPath:        sockPath,
		EnrolledAt:        time.Now().UTC(),
		LastIssuerContact: time.Now().UTC(),
	}
	if err := state.Save(""); err != nil {
		return err
	}
	if err := manifest.RecordFileOnDisk(workloadapi.DefaultStatePath(), "this device's settings"); err != nil {
		return err
	}
	manifest.RecordSocket(sockPath, "the socket your tools ask totem for identity on")
	if err := manifest.Save(); err != nil {
		return err
	}
	manifest.RecordFile(ManifestPath(), nil, "the record of what totem changed")

	fmt.Println()
	fmt.Printf("This device is %s.\n", shortFingerprint(hex.EncodeToString(hashPublicKey(pubDER))))
	fmt.Printf("Its key is kept in: %s\n", key.ProtectionLevel())
	if resp.Approved {
		fmt.Println("Your issuer approved it.")
	} else {
		fmt.Println()
		fmt.Println("One step left: someone with a device that is already set up has to approve this one.")
		if resp.ApprovalCode != "" {
			fmt.Printf("  On that device, run:  totem devices approve %s\n", resp.ApprovalCode)
		}
		if resp.ApprovalURL != "" {
			fmt.Printf("  Or approve it here:   %s\n", resp.ApprovalURL)
		}
		fmt.Println("  This device finishes on its own once that happens.")
	}
	fmt.Println()
	fmt.Println("Point your tools at totem with:")
	fmt.Printf("  SPIFFE_ENDPOINT_SOCKET=unix://%s\n", sockPath)
	clearLastError()
	return nil
}

// publicKeyDER encodes the device public key the issuer will enroll. ECDSA
// P-256 only, per docs/totem-design.md "Algorithms and FIPS"; anything else is
// refused here rather than sent to an issuer that will refuse it later.
func publicKeyDER(pub crypto.PublicKey) ([]byte, error) {
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("this device's key is a %T, and totem uses ECDSA P-256", pub)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

func hashPublicKey(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}

// hostOf returns the hostname part of an https URL, which is the default trust
// domain per docs/totem-design.md "Identity model".
func hostOf(raw string) string {
	u, err := parseURLHost(raw)
	if err != nil {
		return ""
	}
	return u
}
