package attest

// Anchor property tests over PINNED REAL certificate chains, not over
// whatever binary the host happens to ship. The chains under testdata/ were
// extracted with `codesign -d --extract-certificates` from:
//
//   apple-zsh-*     /bin/zsh on macOS 26.6.2: the newer "macOS Software
//                   Signing" platform leaf (2026), no OU, no CD team.
//   apple-cltgit-*  Command Line Tools git: the older "Software Signing"
//                   platform leaf (2020, expires 2026-10-24), OU "Apple
//                   Software", CD team 59GAB85EFG. This is the leaf the
//                   July-2026 macos-26 CI image's /bin/zsh carries.
//   apple-claude-*  Claude Code 2.1.261: a Developer ID Application leaf,
//                   OU = Team ID Q6L2SF6YDW.
//
// These run on every OS with no host dependency, and they are what decides
// whether the anchors are right; the host-reading tests are smoke.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// fixtureTime is inside every pinned certificate's validity. The chains are
// judged at this fixed instant, NOT at time.Now(), on purpose: the older
// platform leaf (apple-cltgit-0.der, 2020) and its 2011 intermediate
// (apple-cltgit-1.der) both expire on 2026-10-24. After that date those
// fixtures are expired AND still correct: real binaries signed with them
// keep verifying because production judges validity at the CMS signingTime,
// and the anchor logic these tests exercise does not depend on the date at
// all. Do not "fix" an expired fixture by replacing it or by moving this
// instant forward; the point of pinning it is that it is the certificate the
// July-2026 macos-26 CI image and every Command Line Tools install carry.
var fixtureTime = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func loadChain(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	for i := 0; ; i++ {
		der, err := os.ReadFile(filepath.Join("testdata", fmt.Sprintf("apple-%s-%d.der", name, i)))
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s[%d]: %v", name, i, err)
		}
		chain = append(chain, c)
	}
	if len(chain) < 3 {
		t.Fatalf("fixture %s has %d certificates, want leaf, intermediate, root", name, len(chain))
	}
	return chain
}

// verifiedChain runs the production chain builder over the pinned certs
// against the embedded Apple root, so what the anchor tests see is exactly
// what verifyLoaded would hand them.
func verifiedChain(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	raw := loadChain(t, name)
	chain, err := buildChain(raw[0], raw[1:len(raw)-1], appleRoots(), fixtureTime)
	if err != nil {
		t.Fatalf("%s does not chain to the embedded Apple Root CA: %v", name, err)
	}
	if err := checkPathLen(chain); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return chain
}

func TestPinnedChainsVerifyToEmbeddedAppleRoot(t *testing.T) {
	for _, name := range []string{"zsh", "cltgit", "claude"} {
		chain := verifiedChain(t, name)
		if chain[len(chain)-1].Subject.CommonName != "Apple Root CA" {
			t.Errorf("%s anchored at %q", name, chain[len(chain)-1].Subject.CommonName)
		}
	}
}

// TestPlatformLeafDiscriminator is the fact the fix rests on, checked on
// real bytes: both Apple platform leaves carry the software-signing marker
// and NOT the Developer ID marker; the Developer ID leaf is the reverse.
func TestPlatformLeafDiscriminator(t *testing.T) {
	zsh, clt, claude := loadChain(t, "zsh")[0], loadChain(t, "cltgit")[0], loadChain(t, "claude")[0]
	for name, leaf := range map[string]*x509.Certificate{"zsh": zsh, "cltgit": clt} {
		if hasExtension(leaf, oidAppleDeveloperIDApplication) {
			t.Errorf("%s platform leaf carries the Developer ID marker", name)
		}
		if !hasExtension(leaf, oidAppleSoftwareSigning) {
			t.Errorf("%s platform leaf lacks the software-signing marker", name)
		}
	}
	if !hasExtension(claude, oidAppleDeveloperIDApplication) {
		t.Error("Developer ID leaf lacks its marker")
	}
	if hasExtension(claude, oidAppleSoftwareSigning) {
		t.Error("Developer ID leaf carries Apple's software-signing marker")
	}
	// The two platform conventions differ exactly in the OU, and neither OU
	// is a Team ID.
	if ou := subjectOU(zsh.Subject); ou != "" {
		t.Errorf("newer platform leaf OU %q, want none", ou)
	}
	if ou := subjectOU(clt.Subject); ou != "Apple Software" {
		t.Errorf("older platform leaf OU %q, want Apple Software", ou)
	}
	if ou := subjectOU(claude.Subject); ou != "Q6L2SF6YDW" {
		t.Errorf("Developer ID leaf OU %q, want the Team ID", ou)
	}
}

func TestVendorTeamIDDerivation(t *testing.T) {
	zsh, clt, claude := loadChain(t, "zsh")[0], loadChain(t, "cltgit")[0], loadChain(t, "claude")[0]
	// Newer platform leaf: nothing anywhere.
	if team, ou, err := vendorTeamID(zsh, ""); err != nil || team != "" || ou != "" {
		t.Errorf("zsh: %q %q %v", team, ou, err)
	}
	// Older platform leaf: Apple's team in the CD, prose in the OU, and
	// that disagreement is NOT an error because neither is a vendor Team ID.
	if team, ou, err := vendorTeamID(clt, "59GAB85EFG"); err != nil || team != "" || ou != "Apple Software" {
		t.Errorf("cltgit: %q %q %v", team, ou, err)
	}
	// Developer ID leaf: OU is the Team ID; CD must agree when present.
	if team, ou, err := vendorTeamID(claude, "Q6L2SF6YDW"); err != nil || team != "Q6L2SF6YDW" || ou != "Q6L2SF6YDW" {
		t.Errorf("claude: %q %q %v", team, ou, err)
	}
	if team, _, err := vendorTeamID(claude, ""); err != nil || team != "Q6L2SF6YDW" {
		t.Errorf("claude without CD team: %q %v", team, err)
	}
	if _, _, err := vendorTeamID(claude, "ATTACKER01"); err == nil {
		t.Error("Developer ID leaf with a disagreeing CD team was accepted")
	}
}

func TestIsAppleCodeSigningChainOnPinnedChains(t *testing.T) {
	if !isAppleCodeSigningChain(verifiedChain(t, "zsh")) {
		t.Error("newer platform chain not recognised")
	}
	if !isAppleCodeSigningChain(verifiedChain(t, "cltgit")) {
		t.Error("older platform chain not recognised")
	}
	if isAppleCodeSigningChain(verifiedChain(t, "claude")) {
		t.Error("a Developer ID chain was accepted as Apple's platform chain")
	}
}

// pinnedInspection builds what inspect() would produce for a running process
// whose binary carries the pinned chain, with the kernel facts supplied.
func pinnedInspection(t *testing.T, name, ident, cdTeam string, kernelPlatform bool) *inspection {
	t.Helper()
	chain := verifiedChain(t, name)
	team, ou, err := vendorTeamID(chain[0], cdTeam)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(csValid | csSigned | csHard | csKill)
	if kernelPlatform {
		flags |= csPlatformBinary
	}
	kcsTeam := ""
	if !kernelPlatform {
		kcsTeam = cdTeam // the kernel reports the CD team for non-platform code
	}
	return &inspection{
		sig: &codeSignature{
			Identifier: ident, TeamID: team, CDTeamID: cdTeam, SubjectOU: ou,
			Chain: chain, CDHash: make([]byte, cdHashLen),
		},
		kcs:  &kernelCodeSign{present: true, flags: flags, cdHash: make([]byte, cdHashLen), identity: ident, teamID: kcsTeam},
		hash: strings.Repeat("00", 32),
	}
}

func pinnedAttestor(t *testing.T, rows ...spiffe.CatalogEntry) *attestor {
	t.Helper()
	f := &fakeSystem{procs: map[int32]*process{}, files: map[int32]string{}, calls: map[int32]int{}}
	a, err := newAttestor(f, rows, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var (
	rowZsh    = spiffe.CatalogEntry{Anchor: spiffe.AnchorApplePlatform, Name: "zsh", SigningID: "com.apple.zsh", ExpectedPaths: []string{"/bin/zsh"}}
	rowGit    = spiffe.CatalogEntry{Anchor: spiffe.AnchorApplePlatform, Name: "git", SigningID: "com.apple.git", ExpectedPaths: []string{"/Library/Developer/CommandLineTools/usr/bin/git"}}
	rowClaude = spiffe.Catalog[0]
)

func TestApplePlatformAnchorAcceptsBothRealConventions(t *testing.T) {
	a := pinnedAttestor(t, rowZsh, rowGit)
	// Newer convention: no OU, no CD team, kernel reports no team.
	if err := a.checkCatalogBinary(&a.catalog[0], pinnedInspection(t, "zsh", "com.apple.zsh", "", true), nil); err != nil {
		t.Errorf("newer platform leaf refused: %v", err)
	}
	// Older convention: OU "Apple Software", CD team 59GAB85EFG, and the
	// kernel STILL reports no team for platform code (observed via csops).
	if err := a.checkCatalogBinary(&a.catalog[1], pinnedInspection(t, "cltgit", "com.apple.git", "59GAB85EFG", true), nil); err != nil {
		t.Errorf("older platform leaf refused: %v", err)
	}
}

// TestApplePlatformAnchorRefusesRealDeveloperIDLeaf is the one direction of
// this change with security risk in it: loosening the platform anchor must
// not let a genuine Developer ID binary through, even if the kernel flag
// were somehow set. The chain check is what refuses it.
func TestApplePlatformAnchorRefusesRealDeveloperIDLeaf(t *testing.T) {
	row := spiffe.CatalogEntry{Anchor: spiffe.AnchorApplePlatform, Name: "claude", SigningID: "com.anthropic.claude-code", ExpectedPaths: []string{"/x/claude"}}
	a := pinnedAttestor(t, row)
	for _, kernelPlatform := range []bool{false, true} {
		insp := pinnedInspection(t, "claude", "com.anthropic.claude-code", "Q6L2SF6YDW", kernelPlatform)
		err := a.checkCatalogBinary(&a.catalog[0], insp, nil)
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("kernelPlatform=%v: Developer ID leaf accepted by the platform anchor: %v", kernelPlatform, err)
		}
		if kernelPlatform && !strings.Contains(err.Error(), "code-signing CA") {
			t.Errorf("with the kernel flag forced, the chain check must be the refusal: %v", err)
		}
	}
}

func TestDeveloperIDAnchorOnPinnedChains(t *testing.T) {
	a := pinnedAttestor(t, rowClaude)
	if err := a.checkCatalogBinary(&a.catalog[0], pinnedInspection(t, "claude", "com.anthropic.claude-code", "Q6L2SF6YDW", false), nil); err != nil {
		t.Errorf("real Claude chain refused by the shipped row: %v", err)
	}
	// Both platform leaves under a developer-id row: refused for the real
	// reason, the missing Developer ID marker.
	rowFake := spiffe.CatalogEntry{Name: "fake", TeamID: "59GAB85EFG", SigningID: "com.apple.git", ExpectedPaths: []string{"/x"}}
	b := pinnedAttestor(t, rowFake)
	for _, name := range []string{"zsh", "cltgit"} {
		cdTeam := ""
		if name == "cltgit" {
			cdTeam = "59GAB85EFG"
		}
		err := b.checkCatalogBinary(&b.catalog[0], pinnedInspection(t, name, "com.apple.git", cdTeam, true), nil)
		if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "Developer ID Application") {
			t.Errorf("%s under a developer-id row: %v", name, err)
		}
	}
}

func TestKernelTeamCrossCheckOnPinnedChains(t *testing.T) {
	a := pinnedAttestor(t, rowGit)
	// A non-platform process whose CD names a team the kernel does not
	// report is refused; the platform case above shows the same shape
	// accepted when the kernel flags platform.
	insp := pinnedInspection(t, "cltgit", "com.apple.git", "59GAB85EFG", false)
	insp.kcs.flags |= csPlatformBinary // satisfy the anchor
	insp.kcs.teamID = ""
	insp.kcs.flags &^= csPlatformBinary
	err := a.checkCatalogBinary(&a.catalog[0], insp, nil)
	if err == nil {
		t.Fatal("non-platform process with unreported CD team accepted")
	}
	// And a kernel-reported team that disagrees with the CD is refused.
	insp = pinnedInspection(t, "claude", "com.anthropic.claude-code", "Q6L2SF6YDW", false)
	insp.kcs.teamID = "OTHERTEAM1"
	c := pinnedAttestor(t, rowClaude)
	if err := c.checkCatalogBinary(&c.catalog[0], insp, nil); err == nil || !strings.Contains(err.Error(), "kernel Team ID") {
		t.Errorf("kernel/CD team disagreement not refused: %v", err)
	}
}

// TestAppleChainMarkerWitnesses pins which branch of isAppleCodeSigningChain
// each real chain satisfies, so the comment there stays true: both platform
// leaves carry 6.22; only the 2017 intermediate carries 6.2.20; the 2011
// intermediate carries nothing; the Developer ID intermediate carries 6.2.6
// and neither platform marker.
func TestAppleChainMarkerWitnesses(t *testing.T) {
	zsh, clt, claude := loadChain(t, "zsh"), loadChain(t, "cltgit"), loadChain(t, "claude")
	if !hasExtension(zsh[1], oidAppleCodeSigningCA) {
		t.Error("2017 Apple Code Signing CA lacks 6.2.20; the CA branch has lost its witness")
	}
	if hasExtension(clt[1], oidAppleCodeSigningCA) {
		t.Error("2011 Apple Code Signing CA now carries 6.2.20; update the comment in cms.go")
	}
	if hasExtension(claude[1], oidAppleCodeSigningCA) {
		t.Error("Developer ID CA carries Apple's code-signing CA marker")
	}
	// Leaf branch alone must accept both platform chains: strip the CA
	// marker's effect by checking the leaf directly.
	for name, c := range map[string][]*x509.Certificate{"zsh": zsh, "cltgit": clt} {
		if !hasExtension(c[0], oidAppleSoftwareSigning) {
			t.Errorf("%s leaf lacks 6.22; the leaf branch no longer carries it", name)
		}
	}
	// The CLT chain is accepted by the leaf branch only (its CA has no
	// marker), which is the "reachable but not sole" fact stated in cms.go.
	if !isAppleCodeSigningChain(verifiedChain(t, "cltgit")) {
		t.Error("CLT chain refused although its leaf carries 6.22")
	}
}
