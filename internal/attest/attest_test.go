package attest

// Portable tests of the walk and the policy, driven by an in-memory process
// table. They run in "no kernel code signing" mode (what Linux looks like),
// so the anchor is the pin; the signature paths are covered on macOS by the
// real-process tests and by the Apple-signed binaries the OS ships.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

// catalogEntryAlias lets the darwin fixture file name the catalog type
// without a second import block.
type catalogEntryAlias = spiffe.CatalogEntry

type fakeSystem struct {
	procs map[int32]*process
	files map[int32]string
	self  string
	// mutate runs before every process() read and may edit the table.
	mutate func(pid int32, call int)
	calls  map[int32]int
}

func (f *fakeSystem) peer(*net.UnixConn) (peerCred, error) {
	return peerCred{}, errors.New("fake: no sockets")
}

func (f *fakeSystem) process(pid int32) (*process, error) {
	f.calls[pid]++
	if f.mutate != nil {
		f.mutate(pid, f.calls[pid])
	}
	p, ok := f.procs[pid]
	if !ok {
		return nil, errProcessGone
	}
	q := *p
	return &q, nil
}

func (f *fakeSystem) codeSign(int32) (*kernelCodeSign, error) {
	return &kernelCodeSign{present: false}, nil
}

func (f *fakeSystem) openExecutable(p *process) (*os.File, error) {
	return os.Open(f.files[p.pid])
}

func (f *fakeSystem) executable() (string, error) { return f.self, nil }
func (f *fakeSystem) uid() uint32                 { return 501 }

// fakeTree builds a linear chain: pids[0] is the connecting process, each
// next pid is its parent. exes gives each process's path; files gives the
// on-disk file to hash (defaults to a per-process temp file).
type fakeProc struct {
	pid  int32
	exe  string
	file string
}

func newFake(t *testing.T, chain []fakeProc) *fakeSystem {
	t.Helper()
	f := &fakeSystem{procs: map[int32]*process{}, files: map[int32]string{}, calls: map[int32]int{}}
	base := time.Now().Add(-time.Hour)
	for i, fp := range chain {
		ppid := int32(1)
		var puid uint64
		if i+1 < len(chain) {
			ppid = chain[i+1].pid
			puid = uint64(chain[i+1].pid) * 1000
		}
		f.procs[fp.pid] = &process{
			pid: fp.pid, ppid: ppid, uid: 501, gid: 20,
			// Children start after parents.
			startTime:      base.Add(time.Duration(len(chain)-i) * time.Second),
			uniqueID:       uint64(fp.pid) * 1000,
			parentUniqueID: puid,
			exePath:        fp.exe,
		}
		file := fp.file
		if file == "" {
			file = filepath.Join(t.TempDir(), filepath.Base(fp.exe))
			if err := os.WriteFile(file, []byte("binary "+fp.exe), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		f.files[fp.pid] = file
	}
	return f
}

var fakeCatalog = []spiffe.CatalogEntry{{
	Name:          "tool",
	TeamID:        "TESTTEAM01",
	SigningID:     "com.example.tool",
	ExpectedPaths: []string{"/opt/tools/*"},
}}

func fakeAttestor(t *testing.T, f *fakeSystem, pins map[string]string) *attestor {
	t.Helper()
	a, err := newAttestor(f, fakeCatalog, pins)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func pinFor(t *testing.T, f *fakeSystem, pid int32) map[string]string {
	t.Helper()
	h, err := hashFile(f.files[pid])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"tool": h}
}

func TestFakeCatalogHitRequiresPinWithoutCodeSigning(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	a := fakeAttestor(t, f, nil)
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrSignatureMismatch) || !strings.Contains(err.Error(), "no pinned hash") {
		t.Fatalf("err = %v, want ErrSignatureMismatch (no pin, no signature)", err)
	}
	a = fakeAttestor(t, f, pinFor(t, f, 100))
	id, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if err != nil {
		t.Fatal(err)
	}
	if id.Tool != "tool" || id.ShellHops != 0 || id.TeamID != "" || id.SigningID != "" {
		t.Errorf("id = %+v", id)
	}
	if id.Peer.PID != 100 || id.Peer.UID != 501 {
		t.Errorf("peer = %+v", id.Peer)
	}
}

func TestFakePinMismatch(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	a := fakeAttestor(t, f, map[string]string{"tool": strings.Repeat("00", 32)})
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeCatalogMiss(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/usr/local/bin/other"}})
	a := fakeAttestor(t, f, nil)
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeOneShellHop(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 90, exe: "/bin/sh", file: "/bin/sh"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	f.self = "/opt/totem/totem"
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	id, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if err != nil {
		t.Fatal(err)
	}
	if id.ShellHops != 1 || len(id.ParentChain) != 3 || id.ParentChain[1] != "/bin/sh" {
		t.Errorf("id = %+v", id)
	}
}

func TestFakeTwoShellHops(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 90, exe: "/bin/sh", file: "/bin/sh"},
		{pid: 85, exe: "/bin/zsh", file: "/bin/zsh"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrTooManyShellHops) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeShellNamedLikeAShellOutsideBin(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 90, exe: "/Users/x/bin/sh"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v, want ErrNotInCatalog for a shell outside /bin", err)
	}
}

func TestFakeInterpreterWrapped(t *testing.T) {
	for _, exe := range []string{"/usr/bin/python3", "/opt/homebrew/bin/node", "/usr/bin/perl5.34", "/usr/local/bin/ruby3.2"} {
		f := newFake(t, []fakeProc{{pid: 100, exe: exe}, {pid: 80, exe: "/opt/tools/tool"}})
		a := fakeAttestor(t, f, pinFor(t, f, 80))
		_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
		if !errors.Is(err, ErrInterpreterWrapped) {
			t.Errorf("%s: err = %v", exe, err)
		}
	}
}

func TestFakeHelperNotAtDepthZero(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 95, exe: "/opt/totem/totem"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	f.files[95] = f.files[100]
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeWalkEndsAtInit(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/totem/totem"}})
	a := fakeAttestor(t, f, nil)
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrNotInCatalog) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakePIDReusedBeforeRecheck(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	a := fakeAttestor(t, f, pinFor(t, f, 100))
	f.mutate = func(pid int32, call int) {
		if pid == 100 && call == 2 {
			f.procs[100].startTime = f.procs[100].startTime.Add(time.Millisecond)
		}
	}
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakePIDReusedAtFinalRecheck(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	// Reads of 100: (1) initial, (2) recheck after inspect, (3) final.
	f.mutate = func(pid int32, call int) {
		if pid == 100 && call == 3 {
			f.procs[100].uniqueID++
		}
	}
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeParentRecycled(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	// The parent pid now belongs to a process that started after the child.
	f.procs[80].startTime = f.procs[100].startTime.Add(time.Second)
	f.procs[80].uniqueID = 999999
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakePeerUIDMismatch(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	a := fakeAttestor(t, f, pinFor(t, f, 100))
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 502})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakePIDVersionMismatch(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	f.procs[100].pidVersion = 7
	a := fakeAttestor(t, f, pinFor(t, f, 100))
	_, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501, pidVersion: 6})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeProcessGone(t *testing.T) {
	f := newFake(t, nil)
	a := fakeAttestor(t, f, nil)
	_, err := a.attest(context.Background(), peerCred{pid: 4242, uid: 501})
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("err = %v", err)
	}
}

func TestFakeContextCancelled(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	a := fakeAttestor(t, f, pinFor(t, f, 100))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.attest(ctx, peerCred{pid: 100, uid: 501}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// --- constructor and catalog handling ---------------------------------------

func TestNewRejectsBadCatalogAndPins(t *testing.T) {
	f := newFake(t, nil)
	cases := []struct {
		name    string
		catalog []spiffe.CatalogEntry
		pins    map[string]string
	}{
		{"empty name", []spiffe.CatalogEntry{{SigningID: "x", ExpectedPaths: []string{"/a"}}}, nil},
		{"no paths", []spiffe.CatalogEntry{{Name: "t", SigningID: "x"}}, nil},
		{"no signing id", []spiffe.CatalogEntry{{Name: "t", ExpectedPaths: []string{"/a"}}}, nil},
		{"relative path", []spiffe.CatalogEntry{{Name: "t", SigningID: "x", ExpectedPaths: []string{"bin/t"}}}, nil},
		{"short pin", fakeCatalog, map[string]string{"tool": "abcd"}},
		{"non-hex pin", fakeCatalog, map[string]string{"tool": strings.Repeat("zz", 32)}},
	}
	for _, c := range cases {
		if _, err := newAttestor(f, c.catalog, c.pins); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestNewDefaultsToShippedCatalog(t *testing.T) {
	f := newFake(t, nil)
	a, err := newAttestor(f, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.catalog) != len(spiffe.Catalog) || a.catalog[0].entry.Name != "claude" {
		t.Errorf("catalog = %+v", a.catalog)
	}
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(a.catalog[0].patterns[0].glob, home) || !a.catalog[0].patterns[0].home {
		t.Errorf("~ not expanded: %+v", a.catalog[0].patterns[0])
	}
	if row, _ := a.matchCatalog(filepath.Join(home, ".local/share/claude/versions/2.1.261"), 501); row == nil || row.entry.Name != "claude" {
		t.Error("shipped claude glob does not match a versions/ path")
	}
	if row, _ := a.matchCatalog(filepath.Join(home, ".local/share/claude/versions/2.1.261/nested"), 501); row != nil {
		t.Error("glob * crossed a path separator")
	}
	if row, _ := a.matchCatalog("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", 999); row == nil {
		t.Error("homebrew path does not match")
	}
}

func TestNewContractIsWired(t *testing.T) {
	if New == nil {
		t.Fatal("attest.New is nil")
	}
}

func TestPathProtected(t *testing.T) {
	if ok, why := pathProtected("/bin/sh", []uint32{501, uint32(os.Getuid())}); !ok {
		t.Errorf("/bin/sh not protected: %s", why)
	}
	p := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(p, []byte("x"), 0o755)
	if ok, _ := pathProtected(p, []uint32{uint32(os.Getuid())}); ok {
		t.Errorf("%s reported protected", p)
	}
	if ok, why := pathProtected(p, []uint32{0}); ok {
		t.Errorf("temp dir protected against uid 0 only: %s", why)
	}
	if ok, _ := pathProtected("/tmp", nil); ok {
		t.Error("/tmp (world-writable, sticky) reported protected")
	}
	if ok, _ := pathProtected("/definitely/not/here", nil); ok {
		t.Error("missing path reported protected")
	}
}

func TestBERToDER(t *testing.T) {
	// SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "cd" }, INTEGER 5 }
	ber := []byte{
		0x30, 0x80,
		0x24, 0x80, 0x04, 0x02, 'a', 'b', 0x04, 0x02, 'c', 'd', 0x00, 0x00,
		0x02, 0x01, 0x05,
		0x00, 0x00,
		0x00, 0x00, // trailing padding
	}
	der, err := berToDER(ber)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x30, 0x09, 0x04, 0x04, 'a', 'b', 'c', 'd', 0x02, 0x01, 0x05}
	if !bytes.Equal(der, want) {
		t.Fatalf("got % x, want % x", der, want)
	}
	var v struct {
		S []byte
		N int
	}
	if _, err := asn1.Unmarshal(der, &v); err != nil || string(v.S) != "abcd" || v.N != 5 {
		t.Fatalf("decoded %+v, %v", v, err)
	}
	if out, err := berToDER(want); err != nil || !bytes.Equal(out, want) {
		t.Errorf("DER input not returned unchanged: %v", err)
	}
	for _, bad := range [][]byte{{0x30}, {0x30, 0x80, 0x02}, {0x04, 0x80, 0x00, 0x00}, {0x30, 0x02, 0x01}} {
		if _, err := berToDER(bad); err == nil {
			t.Errorf("accepted malformed % x", bad)
		}
	}
}

func TestIsInterpreter(t *testing.T) {
	yes := []string{"/usr/bin/python3", "/opt/homebrew/bin/node", "/usr/bin/perl5.34", "/x/ruby", "/x/Python", "/x/osascript", "/x/bun"}
	no := []string{"/bin/sh", "/opt/tools/tool", "/x/pythonic", "/x/nodeexporter", "/x/git"}
	for _, p := range yes {
		if !isInterpreter(p, nil) {
			t.Errorf("%s not recognised", p)
		}
	}
	for _, p := range no {
		if isInterpreter(p, nil) {
			t.Errorf("%s misrecognised", p)
		}
	}
	if !isInterpreter("/x/whatever", &kernelCodeSign{present: true, identity: "org.python.python"}) {
		t.Error("python signing identity not recognised")
	}
}

func TestFakeHomePatternsOnlyForAgentUID(t *testing.T) {
	home, _ := os.UserHomeDir()
	catalog := []spiffe.CatalogEntry{{
		Name: "tool", TeamID: "TESTTEAM01", SigningID: "com.example.tool",
		ExpectedPaths: []string{"~/tools/*"},
	}}
	exe := filepath.Join(home, "tools", "tool")
	f := newFake(t, []fakeProc{{pid: 100, exe: exe}})
	pins := pinFor(t, f, 100)
	a, err := newAttestor(f, catalog, pins)
	if err != nil {
		t.Fatal(err)
	}
	// Same uid as the agent (the fake's uid() is 501): ~ expands and matches.
	if _, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501}); err != nil {
		t.Fatalf("same-uid peer: %v", err)
	}
	// A different uid: the ~ pattern is not consulted at all, and the
	// refusal says so.
	f.procs[100].uid = 502
	_, err = a.attest(context.Background(), peerCred{pid: 100, uid: 502})
	if !errors.Is(err, ErrNotInCatalog) || !strings.Contains(err.Error(), "under ~ not consulted") {
		t.Fatalf("other-uid peer: %v, want ErrNotInCatalog naming the skipped ~ paths", err)
	}
}

func TestFakeRecheckChainChanged(t *testing.T) {
	f := newFake(t, []fakeProc{
		{pid: 100, exe: "/opt/totem/totem"},
		{pid: 90, exe: "/bin/sh", file: "/bin/sh"},
		{pid: 80, exe: "/opt/tools/tool"},
	})
	a := fakeAttestor(t, f, pinFor(t, f, 80))
	a.selfPath = "/opt/totem/totem"
	a.selfHash, _ = hashFile(f.files[100])
	id, err := a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Recheck(context.Background(), id); err != nil {
		t.Fatalf("Recheck with nothing changed: %v", err)
	}
	// The shell exits; the helper is reparented to init.
	delete(f.procs, 90)
	f.procs[100].ppid = 1
	f.procs[100].parentUniqueID = 0
	err = a.Recheck(context.Background(), id)
	if !errors.Is(err, ErrChainChanged) {
		t.Fatalf("Recheck after the shell exited = %v, want ErrChainChanged", err)
	}
	if errors.Is(err, ErrPIDReused) {
		t.Error("a lifecycle change must not read as pid reuse")
	}
	// The connecting process itself being replaced is still pid reuse.
	f.procs[100].startTime = f.procs[100].startTime.Add(time.Second)
	if err := a.Recheck(context.Background(), id); !errors.Is(err, ErrPIDReused) {
		t.Fatalf("Recheck after replacement = %v, want ErrPIDReused", err)
	}
}

func TestAnchorValidation(t *testing.T) {
	f := newFake(t, nil)
	ok := []spiffe.CatalogEntry{
		{Name: "a", TeamID: "T", SigningID: "s", ExpectedPaths: []string{"/a"}},
		{Anchor: spiffe.AnchorDeveloperID, Name: "b", TeamID: "T", SigningID: "s", ExpectedPaths: []string{"/b"}},
		{Anchor: spiffe.AnchorApplePlatform, Name: "c", SigningID: "com.apple.git", ExpectedPaths: []string{"/usr/bin/git"}},
	}
	if _, err := newAttestor(f, ok, nil); err != nil {
		t.Fatalf("valid rows refused: %v", err)
	}
	bad := []spiffe.CatalogEntry{
		{Name: "no-team-devid", SigningID: "s", ExpectedPaths: []string{"/a"}},
		{Anchor: spiffe.AnchorDeveloperID, Name: "no-team-explicit", SigningID: "s", ExpectedPaths: []string{"/a"}},
		{Anchor: spiffe.AnchorApplePlatform, Name: "platform-with-team", TeamID: "T", SigningID: "s", ExpectedPaths: []string{"/a"}},
		{Anchor: "anchor-apple", Name: "unknown-anchor", SigningID: "s", ExpectedPaths: []string{"/a"}},
	}
	for _, e := range bad {
		if _, err := newAttestor(f, []spiffe.CatalogEntry{e}, nil); err == nil {
			t.Errorf("%s: accepted", e.Name)
		}
	}
}

// craftedCD builds a minimal v0x20400 CodeDirectory header with the given
// page shift, for exercising parse-time bounds.
func craftedCD(pageShift byte) []byte {
	cd := make([]byte, 88+6+32)
	be := func(off int, v uint32) {
		cd[off] = byte(v >> 24)
		cd[off+1] = byte(v >> 16)
		cd[off+2] = byte(v >> 8)
		cd[off+3] = byte(v)
	}
	be(0, csMagicCodeDirectory)
	be(4, uint32(len(cd)))
	be(8, 0x20400)
	be(16, 88+6) // hashOffset
	be(20, 88)   // identOffset
	be(28, 1)    // nCodeSlots
	be(32, 4096) // codeLimit
	cd[36] = 32
	cd[37] = csHashTypeSHA256
	cd[39] = pageShift
	copy(cd[88:], "a.out\x00")
	return cd
}

func TestCodeDirectoryPageShiftIsBounded(t *testing.T) {
	for _, shift := range []byte{0, 1, 11, 17, 28, 40, 63, 255} {
		if _, err := parseCodeDirectory(craftedCD(shift)); err == nil {
			t.Errorf("page shift %d accepted; verifyPages would allocate 1<<%d bytes", shift, shift)
		}
	}
	for _, shift := range []byte{12, 14, 16} {
		if _, err := parseCodeDirectory(craftedCD(shift)); err != nil {
			t.Errorf("page shift %d refused: %v", shift, err)
		}
	}
}

func TestBERDepthIsBounded(t *testing.T) {
	nest := func(depth int) []byte {
		var b []byte
		for i := 0; i < depth; i++ {
			b = append(b, 0x30, 0x80)
		}
		b = append(b, 0x05, 0x00)
		for i := 0; i < depth; i++ {
			b = append(b, 0x00, 0x00)
		}
		return b
	}
	if _, err := berToDER(nest(maxBERDepth - 1)); err != nil {
		t.Fatalf("nesting inside the bound refused: %v", err)
	}
	for _, d := range []int{maxBERDepth + 2, 1000, 100000} {
		if _, err := berToDER(nest(d)); !errors.Is(err, errBERTooDeep) {
			t.Errorf("nesting %d: err = %v, want errBERTooDeep", d, err)
		}
	}
}

func TestCMSRequiresContentTypeAttribute(t *testing.T) {
	// A CMS built by the test signer verifies; the same CMS with its
	// contentType attribute stripped must not.
	ca := newTestCA(t)
	cd := craftedCD(12)
	cms, err := buildCMS(ca, cd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCMS(cms, cd, ca.roots()); err != nil {
		t.Fatalf("intact CMS: %v", err)
	}
	// Locate the contentType attribute OID inside the signed attributes and
	// corrupt its last arc so the attribute is no longer contentType. The
	// signature no longer matches either, but the attribute check runs
	// first and must be the reported failure.
	oid, _ := asn1.Marshal(oidAttrContentType)
	i := bytes.Index(cms, oid)
	if i < 0 {
		t.Fatal("contentType OID not found in CMS")
	}
	broken := append([]byte(nil), cms...)
	broken[i+len(oid)-1] ^= 0x01
	_, err = verifyCMS(broken, cd, ca.roots())
	if err == nil || !strings.Contains(err.Error(), "contentType") {
		t.Fatalf("CMS without contentType: %v, want a contentType refusal", err)
	}
}

func TestChainPathLenConstraint(t *testing.T) {
	// The test intermediate has pathLen 0. Insert a second CA under it and
	// issue the leaf from that; buildChain must refuse the extra level.
	ca := newTestCA(t)
	if err := checkPathLen([]*x509.Certificate{ca.leaf, ca.inter, ca.root}); err != nil {
		t.Fatalf("valid chain refused: %v", err)
	}
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Rogue Sub CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	subDER, err := x509.CreateCertificate(rand.Reader, subTmpl, ca.inter, &subKey.PublicKey, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := x509.ParseCertificate(subDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "leaf", OrganizationalUnit: []string{"X"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, sub, &leafKey.PublicKey, subKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	chain, err := buildChain(leaf, []*x509.Certificate{leaf, sub, ca.inter}, ca.roots(), time.Now())
	if err != nil {
		t.Fatalf("buildChain: %v", err)
	}
	if err := checkPathLen(chain); err == nil {
		t.Fatal("pathLen 0 intermediate with a subordinate CA was accepted")
	}
}

func TestBinarySizeBound(t *testing.T) {
	f := newFake(t, []fakeProc{{pid: 100, exe: "/opt/tools/tool"}})
	a := fakeAttestor(t, f, pinFor(t, f, 100))
	// A sparse file over the bound costs nothing to create and must be
	// refused before it is read.
	big := filepath.Join(t.TempDir(), "huge")
	fh, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(maxBinarySize + 1); err != nil {
		t.Skipf("cannot create a sparse %d byte file here: %v; would assert ErrNotInCatalog naming the size bound", maxBinarySize+1, err)
	}
	fh.Close()
	f.files[100] = big
	_, err = a.attest(context.Background(), peerCred{pid: 100, uid: 501})
	if !errors.Is(err, ErrNotInCatalog) || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("err = %v, want ErrNotInCatalog naming the size bound", err)
	}
}
