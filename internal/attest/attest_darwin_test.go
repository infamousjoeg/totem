//go:build darwin

package attest

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

type spiffeCatalog = catalogEntryAlias

// --- catalog hit and the mismatches ---------------------------------------

func TestCatalogHitDirect(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	id, err := attestArgv(t, a, fixtures.good, "client", socketArg)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if id.Tool != fixtureTool || id.TeamID != fixtureTeam || id.SigningID != fixtureIdent {
		t.Errorf("identity = %+v", id)
	}
	if id.ShellHops != 0 || len(id.ParentChain) != 1 || id.ParentChain[0] != fixtures.good {
		t.Errorf("chain = %v hops = %d", id.ParentChain, id.ShellHops)
	}
	if id.PathProtected {
		t.Error("a fixture in a temp dir reported as path-protected")
	}
	if id.Peer.BinaryPath != fixtures.good || id.Peer.StartTime.IsZero() || id.Peer.UID != uint32(os.Getuid()) {
		t.Errorf("peer = %+v", id.Peer)
	}
	want, _ := hashFile(fixtures.good)
	if id.BinaryHash != want {
		t.Errorf("hash %s != %s", id.BinaryHash, want)
	}
	// Renewal re-check on a live connection would pass; on a finished one
	// the pid is gone and must be reported as reuse.
	if err := a.Recheck(context.Background(), id); !errors.Is(err, ErrPIDReused) {
		t.Errorf("Recheck after exit = %v, want ErrPIDReused", err)
	}
}

func TestCatalogHitWithMatchingPin(t *testing.T) {
	needFixtures(t)
	h, _ := hashFile(fixtures.good)
	a := fixtureAttestor(t, nil, map[string]string{fixtureTool: h})
	if _, err := attestArgv(t, a, fixtures.good, "client", socketArg); err != nil {
		t.Fatalf("attest with matching pin: %v", err)
	}
}

func TestHashMismatchAgainstPin(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, map[string]string{fixtureTool: strings.Repeat("ab", 32)})
	_, err := attestArgv(t, a, fixtures.good, "client", socketArg)
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("err = %v, want ErrSignatureMismatch mentioning the pin", err)
	}
}

func TestCatalogMiss(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	// A perfectly signed binary outside the expected paths is not the tool.
	elsewhere := filepath.Join(fixtures.dir, "elsewhere")
	if err := copyFile(fixtures.good, elsewhere); err != nil {
		t.Fatal(err)
	}
	_, err := attestArgv(t, a, elsewhere, "client", socketArg)
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v, want ErrNotInCatalog", err)
	}
}

func TestSigningIDMismatch(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	_, err := attestArgv(t, a, fixtures.badIdent, "client", socketArg)
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "signing identifier") {
		t.Fatalf("err = %v, want ErrSignatureMismatch on the signing identifier", err)
	}
}

func TestTeamIDMismatch(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	_, err := attestArgv(t, a, fixtures.otherTeam, "client", socketArg)
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "Team ID") {
		t.Fatalf("err = %v, want ErrSignatureMismatch on the Team ID", err)
	}
}

func TestLeafWithoutDeveloperIDMarkerIsRefused(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	_, err := attestArgv(t, a, fixtures.noDevID, "client", socketArg)
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "Developer ID") {
		t.Fatalf("err = %v, want ErrSignatureMismatch on the Developer ID marker", err)
	}
}

func TestUntrustedChainAtWritablePath(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	_, err := attestArgv(t, a, fixtures.wrongRoot, "client", socketArg)
	if !errors.Is(err, ErrUnsignedAtWritablePath) {
		t.Fatalf("err = %v, want ErrUnsignedAtWritablePath for a chain that reaches no trusted root", err)
	}
}

func TestAdhocAtWritablePath(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	_, err := attestArgv(t, a, fixtures.adhocTool, "client", socketArg)
	if !errors.Is(err, ErrUnsignedAtWritablePath) {
		t.Fatalf("err = %v, want ErrUnsignedAtWritablePath for an ad-hoc binary in a user-owned dir", err)
	}
}

func TestAdhocAtWritablePathEvenWhenPinned(t *testing.T) {
	needFixtures(t)
	h, _ := hashFile(fixtures.adhocTool)
	a := fixtureAttestor(t, nil, map[string]string{fixtureTool: h})
	_, err := attestArgv(t, a, fixtures.adhocTool, "client", socketArg)
	if !errors.Is(err, ErrUnsignedAtWritablePath) {
		t.Fatalf("err = %v, want ErrUnsignedAtWritablePath: a pin does not rescue an ad-hoc binary the user can rewrite", err)
	}
}

// TestSwapAfterExec is the attack proc_pidpath invites: the running process
// is one binary, the file now at its path is another. The kernel cdhash must
// win over the file.
func TestSwapAfterExec(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	victim := filepath.Join(filepath.Dir(fixtures.good), "swap")
	if err := copyFile(fixtures.badIdent, victim); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(victim) })
	swapped := false
	sys := hookSystem{system: darwinSystem{}, beforeInspect: func() {
		if !swapped {
			swapped = true
			// Rename the correctly signed tool over the running (bad) one.
			if err := copyFile(fixtures.good, victim+".new"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(victim+".new", victim); err != nil {
				t.Fatal(err)
			}
		}
	}}
	a.sys = sys
	_, err := attestArgv(t, a, victim, "client", socketArg)
	if err == nil {
		t.Fatal("swap after exec was attested as the tool")
	}
	if !errors.Is(err, ErrSignatureMismatch) && !errors.Is(err, ErrUnsignedAtWritablePath) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "cdhash") {
		t.Fatalf("refusal does not name the kernel cdhash mismatch: %v", err)
	}
}

// --- the parent walk -------------------------------------------------------

func TestOneShellHop(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	// tool -> /bin/sh -> helper(connects). The trailing "; true" keeps sh
	// from exec-optimising the helper into its own pid.
	id, err := attestArgv(t, a, fixtures.good, "run", "/bin/sh", "-c", fixtures.helper+" client "+socketArg+"; true")
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if id.ShellHops != 1 {
		t.Errorf("hops = %d, want 1", id.ShellHops)
	}
	// macOS's /bin/sh re-execs as /bin/bash; the kernel reports the real one.
	if len(id.ParentChain) != 3 || id.ParentChain[0] != fixtures.helper || (id.ParentChain[1] != "/bin/sh" && id.ParentChain[1] != "/bin/bash") || id.ParentChain[2] != fixtures.good {
		t.Errorf("chain = %v", id.ParentChain)
	}
	if id.Peer.BinaryPath != fixtures.helper {
		t.Errorf("peer binary = %s", id.Peer.BinaryPath)
	}
}

func TestHelperWithoutShell(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	id, err := attestArgv(t, a, fixtures.good, "run", fixtures.helper, "client", socketArg)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if id.ShellHops != 0 || len(id.ParentChain) != 2 {
		t.Errorf("chain = %v hops = %d", id.ParentChain, id.ShellHops)
	}
}

func TestTwoShellHopsRefused(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	inner := fixtures.helper + " client " + socketArg + "; true"
	_, err := attestArgv(t, a, fixtures.good, "run", "/bin/sh", "-c", "/bin/zsh -c '"+inner+"'; true")
	if !errors.Is(err, ErrTooManyShellHops) {
		t.Fatalf("err = %v, want ErrTooManyShellHops", err)
	}
}

func TestShellHopMustEndAtCatalogTool(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	// helper -> /bin/sh -> the test binary: the grandparent is not a tool.
	_, err := attestArgv(t, a, "/bin/sh", "-c", fixtures.helper+" client "+socketArg+"; true")
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v, want ErrNotInCatalog", err)
	}
}

// TestShellCopiedOutOfBinIsNotAHop: the kernel will not even launch a copy of
// /bin/zsh from a user-owned directory on this machine, so the copy is
// inspected as if it were the running shell: real kernel facts from a live
// /bin/zsh (platform flags, cdhash, identity), byte-identical Apple-signed
// file at the copied path. Everything a name-matching or signature-only check
// would accept is present; the location rule must still refuse it.
func TestShellCopiedOutOfBinIsNotAHop(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	cmd := exec.Command("/bin/zsh", "-c", "sleep 3; true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()
	real, err := darwinSystem{}.process(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	genuine, err := a.inspect(real)
	if err != nil {
		t.Fatal(err)
	}
	if genuine.kind != kindShell {
		t.Fatalf("live /bin/zsh classified as %d, want shell (kcs %+v)", genuine.kind, genuine.kcs)
	}
	copied := *real
	copied.exePath = fixtures.shellCopy
	insp, err := a.inspect(&copied)
	if err != nil {
		t.Fatal(err)
	}
	if insp.sig == nil || !isAppleCodeSigningChain(insp.sig.Chain) || !insp.kcs.isPlatformBinary() {
		t.Fatalf("test premise broken: copy did not verify as a platform binary (sig %+v, sigErr %v, kernel identity %q)", insp.sig, insp.sigErr, insp.kcs.identity)
	}
	if insp.kind == kindShell {
		t.Fatal("a shell copied out of /bin was accepted as an OS shell hop")
	}
	if insp.kind != kindOther {
		t.Errorf("kind = %d, want other", insp.kind)
	}
}

func TestInterpreterWrappedByName(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	_, err := attestArgv(t, a, fixtures.interp, "client", socketArg)
	if !errors.Is(err, ErrInterpreterWrapped) {
		t.Fatalf("err = %v, want ErrInterpreterWrapped", err)
	}
}

func TestInterpreterWrappedRealPerl(t *testing.T) {
	needFixtures(t)
	perl, err := exec.LookPath("perl")
	if err != nil {
		t.Skip("no perl on PATH; would assert that a perl one-liner connecting to the socket gets ErrInterpreterWrapped")
	}
	a := fixtureAttestor(t, nil, nil)
	script := `use IO::Socket::UNIX; my $s = IO::Socket::UNIX->new(Peer => $ARGV[0]) or die "connect: $!"; print $s "hi"; $s->flush; my $b; sysread($s, $b, 8);`
	_, err = attestArgv(t, a, perl, "-e", script, socketArg)
	if !errors.Is(err, ErrInterpreterWrapped) {
		t.Fatalf("err = %v, want ErrInterpreterWrapped", err)
	}
}

func TestSelfHelperOnlyAtDepthZero(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	// helper -> helper -> tool: the totem binary spawning the totem binary
	// is not a shape the bridges produce.
	_, err := attestArgv(t, a, fixtures.good, "run", fixtures.helper, "run", fixtures.helper, "client", socketArg)
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v, want ErrNotInCatalog", err)
	}
}

// --- pid reuse -------------------------------------------------------------

// hookSystem wraps the real system with test hooks.
type hookSystem struct {
	system
	beforeInspect func()
	onProcess     func(pid int32, p *process, call int) *process
	calls         map[int32]int
}

func (h hookSystem) process(pid int32) (*process, error) {
	p, err := h.system.process(pid)
	if err != nil {
		return nil, err
	}
	if h.onProcess != nil {
		if h.calls == nil {
			return p, nil
		}
		h.calls[pid]++
		return h.onProcess(pid, p, h.calls[pid]), nil
	}
	return p, nil
}

func (h hookSystem) codeSign(pid int32) (*kernelCodeSign, error) {
	if h.beforeInspect != nil {
		h.beforeInspect()
	}
	return h.system.codeSign(pid)
}

// TestPIDReusedDuringInspection simulates the pid being recycled between
// the first read and the re-read: the second read of the connecting pid
// reports a later start time.
func TestPIDReusedDuringInspection(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	var connecting int32
	sys := hookSystem{system: darwinSystem{}, calls: map[int32]int{}}
	sys.onProcess = func(pid int32, p *process, call int) *process {
		if connecting == 0 {
			connecting = pid // the first process read is the connecting pid
		}
		if pid == connecting && call > 1 {
			q := *p
			q.startTime = p.startTime.Add(time.Second)
			return &q
		}
		return p
	}
	a.sys = sys
	_, err := attestArgv(t, a, fixtures.good, "client", socketArg)
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v, want ErrPIDReused", err)
	}
}

// TestPIDReusedOnRecheck covers renewal: the identity was fine, the process
// was replaced, Recheck must refuse.
func TestPIDReusedOnRecheck(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	id, err := attestArgv(t, a, fixtures.good, "client", socketArg)
	if err != nil {
		t.Fatal(err)
	}
	// Point the identity at this test process, which has a different start
	// time from the (now exited) fixture.
	id.Peer.PID = int32(os.Getpid())
	if err := a.Recheck(context.Background(), id); !errors.Is(err, ErrPIDReused) {
		t.Fatalf("Recheck = %v, want ErrPIDReused", err)
	}
}

// --- kernel facts ------------------------------------------------------------

func TestPeerCredentialsFromKernel(t *testing.T) {
	needFixtures(t)
	sys := darwinSystem{}
	self, err := sys.process(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if self.uid != uint32(os.Getuid()) || self.ppid != int32(os.Getppid()) {
		t.Errorf("self = %+v", self)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if self.exePath != exe {
		t.Errorf("exe = %s, want %s", self.exePath, exe)
	}
	if self.uniqueID == 0 || self.pidVersion == 0 || self.startTime.IsZero() {
		t.Errorf("identity counters missing: %+v", self)
	}
	parent, err := sys.process(self.ppid)
	if err != nil {
		t.Skipf("parent %d not readable (%v); would assert parentUniqueID linkage and start-time ordering", self.ppid, err)
	}
	if parent.uniqueID != self.parentUniqueID {
		t.Errorf("parent unique id %d != child's parentUniqueID %d", parent.uniqueID, self.parentUniqueID)
	}
	if parent.startTime.After(self.startTime) {
		t.Errorf("parent started after child")
	}
	k, err := sys.codeSign(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if !k.present || k.flags&csValid == 0 || len(k.cdHash) != cdHashLen {
		t.Errorf("codeSign(self) = %+v", k)
	}
}

func TestPlatformShellIsPlatformInKernel(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 2; true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()
	k, err := darwinSystem{}.codeSign(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if !k.isPlatformBinary() {
		t.Errorf("/bin/sh flags %#x: kernel does not flag it platform", k.flags)
	}
	if k.identity != "com.apple.sh" {
		t.Errorf("identity = %q", k.identity)
	}
	if k.teamID != "" {
		t.Errorf("platform shell has team id %q", k.teamID)
	}
}

// --- anchors -----------------------------------------------------------------

// zshClient is a zsh one-liner that connects to the socket itself, so the
// connecting process is the genuine /bin/zsh platform binary.
const zshClient = `zmodload zsh/net/socket && zsocket ` + socketArg + ` && print -nu $REPLY hi && read -u $REPLY -k 2`

func platformRowAttestor(t *testing.T, anchor spiffe.Anchor, team string) *attestor {
	t.Helper()
	a, err := newAttestor(darwinSystem{}, []spiffe.CatalogEntry{{
		Anchor:        anchor,
		Name:          "zsh",
		TeamID:        team,
		SigningID:     "com.apple.zsh",
		ExpectedPaths: []string{"/bin/zsh"},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestApplePlatformAnchorAcceptsRealShell(t *testing.T) {
	needFixtures(t)
	a := platformRowAttestor(t, spiffe.AnchorApplePlatform, "")
	id, err := attestArgv(t, a, "/bin/zsh", "-c", zshClient)
	if err != nil {
		t.Fatalf("attest /bin/zsh under an apple-platform row: %v", err)
	}
	if id.Tool != "zsh" || id.SigningID != "com.apple.zsh" || id.TeamID != "" || id.ShellHops != 0 {
		t.Errorf("id = %+v", id)
	}
	if !id.PathProtected {
		t.Error("/bin/zsh not reported path-protected")
	}
	if id.Entry.Anchor != spiffe.AnchorApplePlatform {
		t.Errorf("entry anchor = %q", id.Entry.Anchor)
	}
}

func TestDeveloperIDAnchorRefusesPlatformBinary(t *testing.T) {
	needFixtures(t)
	// A developer-id row for /bin/zsh cannot be satisfied: its leaf is
	// Apple's software-signing certificate, not a Developer ID Application
	// certificate, so it has no vendor Team ID at all. An empty Anchor must
	// read as developer-id, and the refusal must name the marker.
	a := platformRowAttestor(t, "", "Q6L2SF6YDW")
	_, err := attestArgv(t, a, "/bin/zsh", "-c", zshClient)
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "Developer ID Application") {
		t.Fatalf("err = %v, want ErrSignatureMismatch naming the Developer ID marker", err)
	}
}

func TestApplePlatformAnchorRefusesVendorBinary(t *testing.T) {
	needFixtures(t)
	a, err := newAttestor(darwinSystem{}, []spiffe.CatalogEntry{{
		Anchor:        spiffe.AnchorApplePlatform,
		Name:          fixtureTool,
		SigningID:     fixtureIdent,
		ExpectedPaths: []string{fixtures.catalog},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.roots = append(fixtures.ca.roots(), appleRoots()...)
	_, err = attestArgv(t, a, fixtures.good, "client", socketArg)
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("err = %v, want ErrSignatureMismatch naming the platform check", err)
	}
}

func TestIsAppleCodeSigningChain(t *testing.T) {
	f, err := os.Open("/bin/zsh")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	sig, err := verifyMachO(f, st.Size(), sliceSelector{}, appleRoots())
	if err != nil {
		t.Fatal(err)
	}
	if !isAppleCodeSigningChain(sig.Chain) {
		t.Error("/bin/zsh chain not recognised as Apple's code-signing chain")
	}
	home, _ := os.UserHomeDir()
	if m, _ := filepath.Glob(filepath.Join(home, ".local/share/claude/versions/*")); len(m) > 0 {
		cf, err := os.Open(m[len(m)-1])
		if err != nil {
			t.Fatal(err)
		}
		defer cf.Close()
		cst, _ := cf.Stat()
		csig, err := verifyMachO(cf, cst.Size(), sliceSelector{}, appleRoots())
		if err != nil {
			t.Fatal(err)
		}
		if isAppleCodeSigningChain(csig.Chain) {
			t.Error("a Developer ID chain was accepted as Apple's platform chain")
		}
	}
	ca := newTestCA(t)
	if isAppleCodeSigningChain([]*x509.Certificate{ca.leaf, ca.inter, ca.root}) {
		t.Error("test chain accepted as Apple's")
	}
}

// TestInspectKeepsSignatureError: a nil sig must come with the reason. A
// running platform shell inspected against a file whose CodeDirectory does
// not match the kernel cdhash gets sigErr set, not silently no signature.
func TestInspectKeepsSignatureError(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	cmd := exec.Command("/bin/zsh", "-c", "sleep 3; true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()
	real, err := darwinSystem{}.process(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	// The kernel says zsh; the file at this path is the (differently
	// signed) fixture, so slice selection by cdhash must fail loudly.
	mismatched := *real
	mismatched.exePath = fixtures.good
	insp, err := a.inspect(&mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if insp.sig != nil || insp.sigErr == nil || !errors.Is(insp.sigErr, errSliceNotFound) {
		t.Fatalf("sig %+v sigErr %v; want nil sig with errSliceNotFound", insp.sig, insp.sigErr)
	}
	// And a walk refusal for a NON-catalog, non-helper path names it (a
	// catalog path reports the same failure through ErrUnsignedAtWritablePath).
	elsewhere := filepath.Join(fixtures.dir, "elsewhere-sigerr")
	if err := copyFile(fixtures.good, elsewhere); err != nil {
		t.Fatal(err)
	}
	hook := hookSystem{system: darwinSystem{}, calls: map[int32]int{}}
	hook.onProcess = func(pid int32, p *process, call int) *process {
		if pid == int32(cmd.Process.Pid) {
			q := *p
			q.exePath = elsewhere
			return &q
		}
		return p
	}
	a.sys = hook
	_, err = a.attest(context.Background(), peerCred{pid: int32(cmd.Process.Pid), uid: real.uid})
	if err == nil || !strings.Contains(err.Error(), "signature:") {
		t.Fatalf("refusal = %v, want the signature failure named", err)
	}
}

// TestSignatureErrorSurvivesCDHashSelection answers the question the cdhash-
// first reorder raises: is a signature failure still reachable, or does every
// bad file now die at slice selection? It is reachable whenever the file IS
// the running code (cdhash matches) but its signature does not verify. Here a
// real process runs a fixture signed by an untrusted root from a non-catalog
// path, and the refusal must name the CMS failure, not a generic miss.
func TestSignatureErrorSurvivesCDHashSelection(t *testing.T) {
	needFixtures(t)
	a := fixtureAttestor(t, nil, nil)
	elsewhere := filepath.Join(fixtures.dir, "elsewhere-wrongroot")
	if err := copyFile(fixtures.wrongRoot, elsewhere); err != nil {
		t.Fatal(err)
	}
	_, err := attestArgv(t, a, elsewhere, "client", socketArg)
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v, want ErrNotInCatalog", err)
	}
	if !strings.Contains(err.Error(), "signature:") || !strings.Contains(err.Error(), "CMS") {
		t.Fatalf("refusal does not name the CMS chain failure: %v", err)
	}
	if strings.Contains(err.Error(), "cdhash") {
		t.Fatalf("refused at slice selection, not at signature verification: %v", err)
	}
}

// TestApplePlatformAnchorAcceptsLiveCLTGit inspects a LIVE Command Line Tools
// git process under the exact row step 5 will ship, using the real kernel
// facts for it (CS_PLATFORM_BINARY set, and csops reporting NO team even
// though the CodeDirectory carries 59GAB85EFG).
func TestApplePlatformAnchorAcceptsLiveCLTGit(t *testing.T) {
	needFixtures(t)
	if _, err := os.Stat(cltGit); err != nil {
		t.Skipf("no Command Line Tools git; would assert a live %s process is a catalog hit under an apple-platform row and that the kernel reports no team for it", cltGit)
	}
	a, err := newAttestor(darwinSystem{}, []spiffe.CatalogEntry{{
		Anchor:        spiffe.AnchorApplePlatform,
		Name:          "git",
		SigningID:     "com.apple.git",
		ExpectedPaths: []string{cltGit},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if out, err := exec.Command(cltGit, "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git init failed (%v: %s); cannot hold a live git process", err, out)
	}
	cmd := exec.Command(cltGit, "-C", repo, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe() // git blocks reading requests until stdin closes
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	time.Sleep(300 * time.Millisecond)
	p, err := darwinSystem{}.process(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if p.exePath != cltGit {
		t.Skipf("live process is %s, not %s (git re-exec'd); premise unavailable", p.exePath, cltGit)
	}
	insp, err := a.inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	if insp.kcs.teamID != "" {
		t.Logf("note: kernel now reports team %q for a platform binary", insp.kcs.teamID)
	}
	if !insp.kcs.isPlatformBinary() {
		t.Fatalf("kernel does not flag CLT git platform (status %#x)", insp.kcs.flags)
	}
	if insp.kind != kindCatalog {
		t.Fatalf("kind = %d, refusal = %v, sigErr = %v; want catalog hit", insp.kind, insp.refusal, insp.sigErr)
	}
	if insp.sig.TeamID != "" || insp.sig.CDTeamID != "59GAB85EFG" {
		t.Errorf("TeamID %q CDTeamID %q", insp.sig.TeamID, insp.sig.CDTeamID)
	}
	if !insp.protectedPath {
		t.Error("CLT git path not reported protected (root-owned /Library/Developer)")
	}
}
