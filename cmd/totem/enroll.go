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
	"github.com/infamousjoeg/totem/internal/presence"
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

	// Both public halves, always. On Apple silicon these are two Secure
	// Enclave keys and the issuer verifies different things against each: the
	// device half for silent renewals, the presence half for assertions.
	// PresencePublic() is nil ONLY when this protection level cannot check for
	// a human at all, and that case is recorded as presence "none" on the
	// enrollment rather than glossed over, because an enrollment that quietly
	// dropped the presence half would verify every future assertion against
	// the wrong key and look fine doing it.
	devicePub, err := publicKeyDER(key.Public())
	if err != nil {
		return failf("Run 'totem doctor' for what this machine can do.",
			"totem could not read this device's own key back: %v", err)
	}
	fingerprintHex := hex.EncodeToString(hashPublicKey(devicePub))

	var presencePub []byte
	presenceState := presence.StateNone
	if pp := key.PresencePublic(); pp != nil {
		presenceState = presence.StatePresent
		if presencePub, err = publicKeyDER(pp); err != nil {
			return failf("Run 'totem doctor' for what this machine can do.",
				"totem could not read the key that confirms it's you: %v", err)
		}
	}

	// The signed bytes go through presence's canonical encoder rather than
	// being the raw challenge. Every signature in totem is domain-separated:
	// a fixed context string plus a version byte plus length-prefixed fields,
	// so a signature made to enroll a device cannot be replayed as a signature
	// made for anything else, and no field boundary can be shifted.
	signing := presence.SigningInput{
		DeviceID:  fingerprintHex,
		Tool:      "totem",
		Target:    addr.URL,
		Challenge: challenge.Challenge,
	}
	if len(challenge.Challenge) != presence.ChallengeSize {
		return failf("Ask your issuer operator whether the issuer is running a version totem understands.",
			"your issuer sent something totem cannot sign safely.")
	}

	var sig []byte
	if presenceState == presence.StatePresent {
		fmt.Println("Confirm it's you to finish setting this device up.")
		assertion, aerr := presence.Sign(ctx, key, signing)
		switch {
		case aerr == nil:
			sig = assertion.Signature
		case errors.Is(aerr, platform.ErrPresenceDenied):
			return failf("Run 'totem enroll' again and approve the prompt within 60 seconds.",
				"the confirmation was declined or timed out, so nothing was set up.")
		case errors.Is(aerr, platform.ErrPresenceUnavailable):
			// The key reported a presence half and then could not use it. That
			// is a contradiction, not a device without a sensor, so it is a
			// refusal rather than a quiet downgrade to presence "none".
			return failf("Run 'totem doctor'. It will say whether this machine's secure hardware is reachable.",
				"this device offered to confirm it's you and then could not.")
		default:
			return failf("Run 'totem doctor' for what this machine can do.",
				"totem could not use this device's key: %v", aerr)
		}
	} else {
		// No presence capability anywhere on this device. It still enrolls and
		// exchanges still work; the level is recorded honestly and travels on
		// every identity, so a target that needs a person present will refuse
		// this device rather than being fooled by it.
		fmt.Println("This device has no way to confirm a person is present, so that is recorded as part of its setup.")
		fmt.Println("Targets that require a person will refuse it. Everything else works.")
		bytes, berr := signing.Bytes()
		if berr != nil {
			return failf("Ask your issuer operator whether the issuer is running a version totem understands.",
				"totem could not prepare this device's enrollment: %v", berr)
		}
		if sig, err = key.Sign(ctx, bytes, platform.Prompt{
			Required: false,
			Tool:     "totem",
			Target:   addr.URL,
			DeviceID: fingerprintHex,
		}); err != nil {
			return failf("Run 'totem doctor' for what this machine can do.",
				"totem could not use this device's key: %v", err)
		}
	}

	resp, err := client.Enroll(ctx, EnrollRequest{
		DevicePublicDER:   devicePub,
		PresencePublicDER: presencePub,
		Presence:          presenceState,
		ProtectionLevel:   key.ProtectionLevel(),
		Hostname:          hostname,
		OS:                runtime.GOOS,
		DeviceFingerprint: fingerprintHex,
		SignedTool:        signing.Tool,
		SignedTarget:      signing.Target,
		EncodingVersion:   presence.EncodingVersion,
		Challenge:         challenge.Challenge,
		Signature:         sig,
		BootstrapCode:     *code,
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
		Presence:          presenceState,
		DevicePublicDER:   devicePub,
		PresencePublicDER: presencePub,
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
	fmt.Printf("This device is %s.\n", shortFingerprint(fingerprintHex))
	fmt.Printf("Its key is kept in: %s\n", key.ProtectionLevel())
	fmt.Printf("Confirming it's you:  %s\n", presenceDescription(presenceState))
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

// presenceDescription says, in words a person uses, what this device can do
// about confirming a human is present. No SPIFFE or spec vocabulary.
func presenceDescription(state presence.State) string {
	if state == presence.StatePresent {
		return "yes, this device can ask you to confirm"
	}
	return "no, this device cannot ask anyone to confirm (recorded on its setup)"
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
