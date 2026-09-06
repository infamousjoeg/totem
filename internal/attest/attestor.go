package attest

// The attestor proper: the parent walk, the catalog match, the pid-reuse
// close, and the policy that turns kernel facts and a verified code signature
// into an Identity or a typed refusal. OS specifics live behind the system
// interface in proc_darwin.go and proc_linux.go; everything in this file is
// portable and is what the hermetic tests exercise.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// maxWalkDepth bounds the parent walk. A helper, one shell, and the tool is
// three; anything past six is not a shape the spec describes.
const maxWalkDepth = 6

// maxBinarySize bounds the executable the attestor will hash and parse. The
// largest catalog binary today (Claude Code) is about 230 MB; a 1 GiB cap
// keeps a crafted file at a writable path from turning one connection into
// unbounded I/O on the shared agent.
const maxBinarySize = 1 << 30

func init() {
	// New is the contract's constructor: the Attestor for this machine, loaded
	// against catalog (nil means spiffe.Catalog) and the hashes `totem init`
	// pinned. See attest.go for the pin semantics.
	New = func(catalog []spiffe.CatalogEntry, pins map[string]string) (Attestor, error) {
		if defaultSystem == nil {
			return nil, errors.New("attest: no attestor implementation for this OS")
		}
		return newAttestor(defaultSystem, catalog, pins)
	}
}

// Rechecker is implemented by the Attestor this package returns. The Workload
// API calls Recheck on renewal: it re-reads the process start time and
// re-walks to the catalog binary, and refuses if either the process or the
// binary is no longer what was attested.
type Rechecker interface {
	Recheck(ctx context.Context, id *Identity) error
}

// peerCred is what the kernel recorded about the connecting process on the
// socket itself, independent of any later lookup by pid.
type peerCred struct {
	pid int32
	uid uint32
	gid uint32
	// pidVersion is the kernel's pid-reuse counter for the peer as captured
	// at connect time (macOS audit token). Zero where unavailable.
	pidVersion int32
}

// process is one process in the walk, as the kernel describes it.
type process struct {
	pid       int32
	ppid      int32
	uid       uint32
	gid       uint32
	startTime time.Time
	// uniqueID and parentUniqueID never repeat for the lifetime of the boot
	// (macOS p_uniqueid). Zero where unavailable.
	uniqueID       uint64
	parentUniqueID uint64
	// pidVersion is the current pid-reuse counter (macOS p_idversion). Zero
	// where unavailable.
	pidVersion int32
	// exePath is the executable path as the kernel resolves it from the
	// process's text vnode, not from argv.
	exePath string
}

// kernelCodeSign is the kernel's view of the code running in a process.
// present is false on platforms without kernel code signing.
type kernelCodeSign struct {
	present  bool
	flags    uint32
	cdHash   []byte
	identity string
	teamID   string
}

// Kernel code-signing status flags (xnu kern/cs_blobs.h). Shared here so the
// portable policy can read them; only darwin ever sets them.
const (
	csValid          = 0x00000001
	csAdhoc          = 0x00000002
	csHard           = 0x00000100
	csKill           = 0x00000200
	csRuntime        = 0x00010000
	csLinkerSigned   = 0x00020000
	csKilled         = 0x01000000
	csPlatformBinary = 0x04000000
	csDebugged       = 0x10000000
	csSigned         = 0x20000000
)

// isPlatformBinary reports whether the kernel itself classifies the process
// as an Apple platform binary. This is the check behind "OS-signed shell":
// the kernel's judgement, not the file name.
func (k *kernelCodeSign) isPlatformBinary() bool {
	return k != nil && k.present && k.flags&csValid != 0 && k.flags&csPlatformBinary != 0
}

// isValid reports whether the kernel still considers the process's code
// valid: signed, pages intact, not killed, never debugged.
func (k *kernelCodeSign) isValid() bool {
	if k == nil || !k.present {
		return false
	}
	if k.flags&csValid == 0 || k.flags&csSigned == 0 {
		return false
	}
	return k.flags&(csKilled|csDebugged) == 0
}

// system is the per-OS kernel interface. Tests substitute it to build
// process trees that cannot be produced on demand (pid reuse mid-walk).
type system interface {
	peer(conn *net.UnixConn) (peerCred, error)
	process(pid int32) (*process, error)
	codeSign(pid int32) (*kernelCodeSign, error)
	// openExecutable opens the running executable for hashing and parsing.
	// On Linux this is /proc/<pid>/exe, the running inode itself; on macOS it
	// is the resolved path, which is why the kernel cdhash cross-check exists.
	openExecutable(p *process) (*os.File, error)
	executable() (string, error)
	uid() uint32
}

// defaultSystem is set by the per-OS file's init.
var defaultSystem system

// errProcessGone means a pid in the walk no longer exists.
var errProcessGone = errors.New("process no longer exists")

// pattern is one expanded expected path.
type pattern struct {
	glob string
	// home is true when the pattern came from a ~ prefix expanded against
	// the AGENT's home directory. Such a pattern is only meaningful when the
	// peer runs as the agent's uid; for any other uid it is not consulted,
	// because matching another user's tool against this user's home would
	// be silently wrong. Rows meant for a dedicated-uid agent use absolute
	// paths.
	home bool
}

// catalogRow is a catalog entry with its expected paths expanded.
type catalogRow struct {
	entry    spiffe.CatalogEntry
	patterns []pattern
}

// attestor implements Attestor and Rechecker.
type attestor struct {
	sys      system
	catalog  []catalogRow
	pins     map[string]string
	roots    []*x509.Certificate
	selfPath string
	selfHash string
}

func newAttestor(sys system, catalog []spiffe.CatalogEntry, pins map[string]string) (*attestor, error) {
	if catalog == nil {
		catalog = spiffe.Catalog
	}
	a := &attestor{sys: sys, roots: appleRoots(), pins: map[string]string{}}
	home, _ := os.UserHomeDir()
	for _, e := range catalog {
		if err := validateEntry(e); err != nil {
			return nil, err
		}
		row := catalogRow{entry: e}
		for _, p := range e.ExpectedPaths {
			isHome := strings.HasPrefix(p, "~/")
			pat := expandPath(p, home)
			row.patterns = append(row.patterns, pattern{glob: pat, home: isHome})
			// The kernel reports real paths; a pattern whose fixed prefix
			// goes through a symlink (/tmp, /var, a symlinked home) is also
			// matched in its resolved form.
			if resolved := resolvePatternPrefix(pat); resolved != pat {
				row.patterns = append(row.patterns, pattern{glob: resolved, home: isHome})
			}
		}
		a.catalog = append(a.catalog, row)
	}
	for tool, h := range pins {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) != sha256.Size*2 {
			return nil, fmt.Errorf("attest: pin for %q is not a hex SHA-256", tool)
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("attest: pin for %q is not hex: %w", tool, err)
		}
		a.pins[tool] = h
	}
	// The agent's own binary is the one caller that may sit between the
	// socket and the tool without being in the catalog: the bridge helpers
	// are `totem` itself. It is recognised by path and hash, never by name.
	if self, err := sys.executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		if h, err := hashFile(self); err == nil {
			a.selfPath = self
			a.selfHash = h
		}
	}
	return a, nil
}

// validateEntry rejects catalog rows that could never be matched safely.
func validateEntry(e spiffe.CatalogEntry) error {
	if e.Name == "" {
		return errors.New("attest: catalog entry with empty name")
	}
	if len(e.ExpectedPaths) == 0 {
		return fmt.Errorf("attest: catalog entry %q has no expected paths", e.Name)
	}
	if e.SigningID == "" {
		return fmt.Errorf("attest: catalog entry %q has no signing identifier (decision 22)", e.Name)
	}
	switch anchorOf(e) {
	case spiffe.AnchorDeveloperID:
		if e.TeamID == "" {
			return fmt.Errorf("attest: catalog entry %q is anchored on a Developer ID but has no Team ID", e.Name)
		}
	case spiffe.AnchorApplePlatform:
		if e.TeamID != "" {
			return fmt.Errorf("attest: catalog entry %q is anchored on an Apple platform signature but names Team ID %q; platform binaries carry none", e.Name, e.TeamID)
		}
	default:
		return fmt.Errorf("attest: catalog entry %q has unknown anchor %q", e.Name, e.Anchor)
	}
	for _, p := range e.ExpectedPaths {
		if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~/") {
			return fmt.Errorf("attest: catalog entry %q expected path %q is not absolute", e.Name, p)
		}
	}
	return nil
}

// anchorOf reads a row's anchor with the contract's default: empty means
// AnchorDeveloperID, the narrower one, so an old row cannot widen.
func anchorOf(e spiffe.CatalogEntry) spiffe.Anchor {
	if e.Anchor == "" {
		return spiffe.AnchorDeveloperID
	}
	return e.Anchor
}

// expandPath resolves a leading ~ against home and cleans the pattern.
func expandPath(p, home string) string {
	if strings.HasPrefix(p, "~/") && home != "" {
		p = filepath.Join(home, p[2:])
	}
	return filepath.Clean(p)
}

// resolvePatternPrefix resolves symlinks in the part of a glob pattern before
// its first metacharacter, leaving the glob itself intact.
func resolvePatternPrefix(pat string) string {
	i := strings.IndexAny(pat, "*?[")
	fixed, rest := pat, ""
	if i >= 0 {
		cut := strings.LastIndex(pat[:i], "/")
		fixed, rest = pat[:cut], pat[cut:]
	}
	if fixed == "" {
		return pat
	}
	resolved, err := filepath.EvalSymlinks(fixed)
	if err != nil {
		return pat
	}
	return resolved + rest
}

// matchCatalog returns the row whose expected paths glob-match path for a
// peer running as peerUID. Patterns expanded from ~ are consulted only when
// the peer is the agent's own uid (see pattern.home); the second result says
// how many were left out, so the refusal can say why.
func (a *attestor) matchCatalog(path string, peerUID uint32) (*catalogRow, int) {
	path = filepath.Clean(path)
	skipped := 0
	sameUser := peerUID == a.sys.uid()
	for i := range a.catalog {
		for _, pat := range a.catalog[i].patterns {
			if pat.home && !sameUser {
				skipped++
				continue
			}
			if ok, err := filepath.Match(pat.glob, path); err == nil && ok {
				return &a.catalog[i], skipped
			}
		}
	}
	return nil, skipped
}

// AttestPeer implements Attestor. The sequence is: read the peer's pid and
// credentials from the socket; read that process's start time and identity
// counters; walk and inspect; then re-read every process's start time after
// inspecting it, and the connecting process's once more at the end. A start
// time that moved is ErrPIDReused.
func (a *attestor) AttestPeer(ctx context.Context, conn *net.UnixConn) (*Identity, error) {
	if conn == nil {
		return nil, errors.New("attest: nil connection")
	}
	pc, err := a.sys.peer(conn)
	if err != nil {
		return nil, err
	}
	return a.attest(ctx, pc)
}

// Recheck implements Rechecker.
func (a *attestor) Recheck(ctx context.Context, id *Identity) error {
	if id == nil {
		return errors.New("attest: nil identity")
	}
	p, err := a.sys.process(id.Peer.PID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPIDReused, err)
	}
	if !p.startTime.Equal(id.Peer.StartTime) {
		return fmt.Errorf("%w: start time moved from %s to %s", ErrPIDReused, id.Peer.StartTime, p.startTime)
	}
	again, err := a.attest(ctx, peerCred{pid: id.Peer.PID, uid: id.Peer.UID, gid: id.Peer.GID})
	if err != nil {
		if errors.Is(err, ErrPIDReused) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		// The connecting process is unchanged, so a walk that no longer
		// reaches the tool means something above it moved: a shell hop or
		// the tool itself exited. Keep the underlying reason visible.
		return fmt.Errorf("%w: %w", ErrChainChanged, err)
	}
	if again.Tool != id.Tool {
		return fmt.Errorf("%w: tool changed from %q to %q", ErrChainChanged, id.Tool, again.Tool)
	}
	if again.BinaryHash != id.BinaryHash {
		return fmt.Errorf("%w: binary hash changed from %s to %s", ErrSignatureMismatch, id.BinaryHash, again.BinaryHash)
	}
	return nil
}

// kind is what a process in the walk turned out to be.
type kind int

const (
	kindOther kind = iota
	kindCatalog
	kindSelf
	kindShell
	kindInterpreter
)

// inspection is the result of looking at one process's binary.
type inspection struct {
	kind          kind
	row           *catalogRow
	sig           *codeSignature
	kcs           *kernelCodeSign
	hash          string
	protectedPath bool
	// refusal is set when the binary sits at a catalog path but fails its
	// checks; it is the ErrSignatureMismatch to return.
	refusal error
	// note carries a reason a catalog match was not attempted, for the
	// ErrNotInCatalog message.
	note string
}

func (a *attestor) attest(ctx context.Context, pc peerCred) (*Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// 1. pid -> start time, before anything else is read about it.
	p0, err := a.sys.process(pc.pid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPIDReused, err)
	}
	if pc.pidVersion != 0 && p0.pidVersion != pc.pidVersion {
		return nil, fmt.Errorf("%w: pid %d version %d at connect, %d now", ErrPIDReused, pc.pid, pc.pidVersion, p0.pidVersion)
	}
	if p0.uid != pc.uid {
		return nil, fmt.Errorf("%w: pid %d is uid %d, socket peer is uid %d", ErrPIDReused, pc.pid, p0.uid, pc.uid)
	}
	peer := Peer{PID: p0.pid, UID: pc.uid, GID: pc.gid, StartTime: p0.startTime, BinaryPath: p0.exePath}

	var chain []string
	hops := 0
	cur := p0
	for depth := 0; depth < maxWalkDepth; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// 2. inspect the binary behind this pid.
		insp, err := a.inspect(cur)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cur.exePath)
		// 3. re-read: the process we inspected must still be the process we
		// read at step 1. This closes the window in which the pid could have
		// been recycled while we were reading its file.
		if err := a.recheck(cur); err != nil {
			return nil, err
		}
		switch insp.kind {
		case kindCatalog:
			id, err := a.identity(insp, cur, peer, chain, hops)
			if err != nil {
				return nil, err
			}
			// 4. the connecting process, one last time, after everything.
			if err := a.recheck(p0); err != nil {
				return nil, err
			}
			return id, nil
		case kindSelf:
			if depth != 0 {
				return nil, fmt.Errorf("%w: totem helper at depth %d in the parent walk", ErrNotInCatalog, depth)
			}
		case kindShell:
			hops++
			if hops > 1 {
				return nil, fmt.Errorf("%w: second shell at %s", ErrTooManyShellHops, cur.exePath)
			}
		case kindInterpreter:
			return nil, fmt.Errorf("%w: %s", ErrInterpreterWrapped, cur.exePath)
		default:
			if insp.refusal != nil {
				return nil, insp.refusal
			}
			if insp.note != "" {
				return nil, fmt.Errorf("%w: %s (%s)", ErrNotInCatalog, cur.exePath, insp.note)
			}
			return nil, fmt.Errorf("%w: %s", ErrNotInCatalog, cur.exePath)
		}
		// Move to the parent. A parent that started after its child, or
		// whose unique id is not the one the child records, is a recycled
		// pid, not a parent.
		if cur.ppid <= 1 {
			return nil, fmt.Errorf("%w: walk reached pid %d without finding a catalog tool", ErrNotInCatalog, cur.ppid)
		}
		parent, err := a.sys.process(cur.ppid)
		if err != nil {
			return nil, fmt.Errorf("%w: parent of %d: %v", ErrNotInCatalog, cur.pid, err)
		}
		if cur.parentUniqueID != 0 && parent.uniqueID != cur.parentUniqueID {
			return nil, fmt.Errorf("%w: pid %d is not the parent that spawned %d", ErrPIDReused, parent.pid, cur.pid)
		}
		if parent.startTime.After(cur.startTime) {
			return nil, fmt.Errorf("%w: pid %d started after its child %d", ErrPIDReused, parent.pid, cur.pid)
		}
		cur = parent
	}
	return nil, fmt.Errorf("%w: parent walk exceeded %d processes", ErrNotInCatalog, maxWalkDepth)
}

// recheck re-reads p and refuses if it is not the same process any more.
func (a *attestor) recheck(p *process) error {
	again, err := a.sys.process(p.pid)
	if err != nil {
		return fmt.Errorf("%w: pid %d: %v", ErrPIDReused, p.pid, err)
	}
	if !again.startTime.Equal(p.startTime) {
		return fmt.Errorf("%w: pid %d start time moved from %s to %s", ErrPIDReused, p.pid, p.startTime, again.startTime)
	}
	if again.uniqueID != p.uniqueID || again.pidVersion != p.pidVersion {
		return fmt.Errorf("%w: pid %d identity counters moved", ErrPIDReused, p.pid)
	}
	if again.exePath != p.exePath {
		return fmt.Errorf("%w: pid %d executable changed from %s to %s", ErrPIDReused, p.pid, p.exePath, again.exePath)
	}
	return nil
}

// inspect classifies one process by its binary. Order matters: a binary at a
// catalog path is judged as a catalog binary and nothing else, so a failed
// signature there is a mismatch, not a fall-through to "maybe it's a shell".
func (a *attestor) inspect(p *process) (*inspection, error) {
	insp := &inspection{}
	kcs, err := a.sys.codeSign(p.pid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotInCatalog, err)
	}
	insp.kcs = kcs

	f, err := a.sys.openExecutable(p)
	if err != nil {
		return nil, fmt.Errorf("%w: opening %s: %v", ErrNotInCatalog, p.exePath, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotInCatalog, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrNotInCatalog, p.exePath)
	}
	// The file is attacker-writable on a real install, so its size is the
	// attacker's too. Bound the work before reading a byte of it.
	if st.Size() > maxBinarySize {
		return nil, fmt.Errorf("%w: %s is %d bytes, over the %d byte bound", ErrNotInCatalog, p.exePath, st.Size(), maxBinarySize)
	}
	// The hash and the page-hash pass below read the whole binary on every
	// attestation, about 0.1 s for a 200 MB Claude Code build. That is per
	// connection, not per RPC, and it is deliberately NOT cached: a cache
	// keyed on path or size or mtime is exactly the staleness an attacker
	// who can write to that path would exploit. Do not add one.
	insp.hash, err = hashReader(f)
	if err != nil {
		return nil, fmt.Errorf("%w: hashing %s: %v", ErrNotInCatalog, p.exePath, err)
	}
	untrusted := []uint32{p.uid, a.sys.uid()}
	insp.protectedPath, _ = pathProtected(p.exePath, untrusted)

	var sig *codeSignature
	var sigErr error
	if kcs.present {
		sel := sliceSelector{kernelCDHash: kcs.cdHash}
		sig, sigErr = verifyMachO(f, st.Size(), sel, a.roots)
		if sigErr == nil {
			insp.sig = sig
		}
	}

	row, skippedHome := a.matchCatalog(p.exePath, p.uid)
	if row != nil {
		insp.row = row
		if err := a.checkCatalogBinary(row, insp, sigErr); err != nil {
			insp.refusal = err
			return insp, nil
		}
		insp.kind = kindCatalog
		return insp, nil
	}
	if skippedHome > 0 {
		insp.note = fmt.Sprintf("%d catalog path(s) under ~ not consulted: peer uid %d is not the agent uid %d, and ~ only expands for the agent's own user", skippedHome, p.uid, a.sys.uid())
	}
	if a.selfPath != "" && p.exePath == a.selfPath && insp.hash == a.selfHash {
		insp.kind = kindSelf
		return insp, nil
	}
	if a.isOSShell(p, insp) {
		insp.kind = kindShell
		return insp, nil
	}
	if isInterpreter(p.exePath, kcs) {
		insp.kind = kindInterpreter
		return insp, nil
	}
	return insp, nil
}

// checkCatalogBinary applies decision 22 (Team ID plus signing identifier),
// decision 2 (hash pin), and the path rule to a binary at a catalog path.
//
// The anchor is the pin when there is one, and always the chain-verified
// vendor signature when the row names a Team ID. A binary with neither a
// verified vendor signature nor a protected path is ErrUnsignedAtWritablePath;
// every other failure is ErrSignatureMismatch with the reason.
func (a *attestor) checkCatalogBinary(row *catalogRow, insp *inspection, sigErr error) error {
	e := row.entry
	pin, pinned := a.pins[e.Name]
	if pinned && pin != insp.hash {
		return fmt.Errorf("%w: %s hash %s does not match the pin %s (run `totem trust %s` if this update is expected)", ErrSignatureMismatch, e.Name, insp.hash, pin, e.Name)
	}
	if !insp.kcs.present {
		// No kernel code signing (Linux): the pin is the only anchor, and the
		// pin is what makes a writable path survivable (a replacement hashes
		// differently).
		if !pinned {
			return fmt.Errorf("%w: %s has no code signature on this platform and no pinned hash", ErrSignatureMismatch, e.Name)
		}
		return nil
	}
	if !insp.kcs.isValid() {
		return fmt.Errorf("%w: %s: kernel code-signing status %#x is not valid", ErrSignatureMismatch, e.Name, insp.kcs.flags)
	}
	sig := insp.sig
	chained := sigErr == nil && !sig.Adhoc && len(sig.Chain) > 0
	if !chained {
		// Nothing chains to a trusted root. Both anchors require a chain, so
		// this is a refusal either way; at a writable path it is the one
		// with its own name.
		if !insp.protectedPath {
			if sigErr != nil {
				return fmt.Errorf("%w: %s: %v", ErrUnsignedAtWritablePath, e.Name, sigErr)
			}
			return fmt.Errorf("%w: %s is ad-hoc signed", ErrUnsignedAtWritablePath, e.Name)
		}
		if sigErr != nil {
			return fmt.Errorf("%w: %s: %v", ErrSignatureMismatch, e.Name, sigErr)
		}
		return fmt.Errorf("%w: %s is ad-hoc signed but the catalog anchors it on %s", ErrSignatureMismatch, e.Name, anchorOf(e))
	}
	if sig.Identifier != e.SigningID {
		return fmt.Errorf("%w: %s signing identifier %q, catalog expects %q", ErrSignatureMismatch, e.Name, sig.Identifier, e.SigningID)
	}
	leaf := sig.leaf()
	switch anchorOf(e) {
	case spiffe.AnchorDeveloperID:
		if sig.TeamID != e.TeamID {
			return fmt.Errorf("%w: %s Team ID %q, catalog expects %q", ErrSignatureMismatch, e.Name, sig.TeamID, e.TeamID)
		}
		if ou := subjectOU(leaf.Subject); ou != e.TeamID {
			return fmt.Errorf("%w: %s signing certificate OU %q is not Team ID %q", ErrSignatureMismatch, e.Name, ou, e.TeamID)
		}
		if !hasExtension(leaf, oidAppleDeveloperIDApplication) {
			return fmt.Errorf("%w: %s signing certificate is not a Developer ID Application certificate", ErrSignatureMismatch, e.Name)
		}
	case spiffe.AnchorApplePlatform:
		// Three independent judgements must agree that this is Apple's own
		// code: the CodeDirectory says platform, the kernel says platform,
		// and the chain runs through Apple's code-signing CA to Apple's root.
		if sig.Platform == 0 {
			return fmt.Errorf("%w: %s CodeDirectory platform byte is zero; not an Apple platform binary", ErrSignatureMismatch, e.Name)
		}
		if !insp.kcs.isPlatformBinary() {
			return fmt.Errorf("%w: %s: kernel does not flag the process as a platform binary (status %#x)", ErrSignatureMismatch, e.Name, insp.kcs.flags)
		}
		if sig.TeamID != "" {
			return fmt.Errorf("%w: %s carries Team ID %q; platform binaries carry none", ErrSignatureMismatch, e.Name, sig.TeamID)
		}
		if !isAppleCodeSigningChain(sig.Chain) {
			return fmt.Errorf("%w: %s signature does not chain through Apple's code-signing CA to Apple Root CA", ErrSignatureMismatch, e.Name)
		}
	}
	// The kernel's own reading of the running code must agree with the
	// signature we verified on disk; the cdhash match already guarantees
	// the same CodeDirectory, this is belt and braces.
	if insp.kcs.identity != "" && insp.kcs.identity != sig.Identifier {
		return fmt.Errorf("%w: kernel identity %q, on-disk %q", ErrSignatureMismatch, insp.kcs.identity, sig.Identifier)
	}
	if insp.kcs.teamID != "" && insp.kcs.teamID != sig.TeamID {
		return fmt.Errorf("%w: kernel Team ID %q, on-disk %q", ErrSignatureMismatch, insp.kcs.teamID, sig.TeamID)
	}
	return nil
}

// identity assembles the Identity for a catalog hit.
func (a *attestor) identity(insp *inspection, tool *process, peer Peer, chain []string, hops int) (*Identity, error) {
	id := &Identity{
		Tool:          insp.row.entry.Name,
		Entry:         insp.row.entry,
		Peer:          peer,
		BinaryHash:    insp.hash,
		ParentChain:   append([]string(nil), chain...),
		ShellHops:     hops,
		PathProtected: insp.protectedPath,
	}
	if insp.sig != nil {
		id.TeamID = insp.sig.TeamID
		id.SigningID = insp.sig.Identifier
	}
	return id, nil
}

// shellIdentifiers are the signing identifiers of the shells macOS ships.
// Membership here is necessary but never sufficient: the kernel must also
// flag the process as a platform binary, the on-disk signature must chain to
// Apple with a platform CodeDirectory, and the path must be protected.
var shellIdentifiers = map[string]bool{
	"com.apple.sh":   true,
	"com.apple.bash": true,
	"com.apple.zsh":  true,
	"com.apple.dash": true,
	"com.apple.ksh":  true,
	"com.apple.tcsh": true,
	"com.apple.csh":  true,
}

// shellBasenames is the Linux fallback, where "OS-signed" can only mean
// "installed by the OS at a root-owned path".
var shellBasenames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "tcsh": true, "csh": true, "fish": true,
}

// isOSShell decides whether a process is the one OS-signed system shell hop
// the spec allows. Named like a shell is not enough; see shellIdentifiers.
func (a *attestor) isOSShell(p *process, insp *inspection) bool {
	dir := filepath.Dir(p.exePath)
	if dir != "/bin" && dir != "/usr/bin" {
		return false
	}
	if !insp.protectedPath {
		return false
	}
	if insp.kcs.present {
		if !insp.kcs.isPlatformBinary() {
			return false
		}
		if !shellIdentifiers[insp.kcs.identity] {
			return false
		}
		if insp.sig == nil || insp.sig.Adhoc || insp.sig.Platform == 0 {
			return false
		}
		return insp.sig.Identifier == insp.kcs.identity
	}
	return shellBasenames[filepath.Base(p.exePath)]
}

var interpreterRE = regexp.MustCompile(`^(node|nodejs|bun|deno|[Pp]ython[0-9.]*|pypy[0-9.]*|[Rr]uby[0-9.]*|perl[0-9.]*|php[0-9.]*|lua[0-9.]*|luajit|tclsh[0-9.]*|wish[0-9.]*|osascript|java|Rscript|julia|elixir|erl|escript)$`)

// isInterpreter recognises the interpreters a script would run under. The
// answer only picks the legible refusal: an interpreter-wrapped caller is
// ErrInterpreterWrapped instead of ErrNotInCatalog. Both are refusals.
func isInterpreter(path string, kcs *kernelCodeSign) bool {
	if interpreterRE.MatchString(filepath.Base(path)) {
		return true
	}
	if kcs != nil && kcs.present {
		switch {
		case strings.HasPrefix(kcs.identity, "org.python."),
			strings.HasPrefix(kcs.identity, "org.nodejs."),
			kcs.identity == "com.apple.osascript",
			kcs.identity == "com.apple.perl",
			kcs.identity == "com.apple.ruby":
			return true
		}
	}
	return false
}

// hashFile is the SHA-256 of the file at path, hex-encoded.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
