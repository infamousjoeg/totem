package attest

// Mach-O code signature parsing in pure Go. This file answers "what does the
// embedded signature on this file claim, and does the file actually match it?"
// It parses the LC_CODE_SIGNATURE SuperBlob, picks the strongest CodeDirectory,
// re-hashes every code page and every sealed special slot against it, and hands
// the CodeDirectory plus the CMS blob to cms.go for signature and chain
// verification. Nothing here shells out and nothing here uses cgo.

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"runtime"
	"time"
)

// Blob magics and slot numbers from xnu's kern/cs_blobs.h. Every value in a
// code signature blob is big-endian.
const (
	csMagicRequirements      = 0xfade0c01
	csMagicCodeDirectory     = 0xfade0c02
	csMagicEmbeddedSignature = 0xfade0cc0
	csMagicBlobWrapper       = 0xfade0b01

	csSlotCodeDirectory   = 0
	csSlotRequirements    = 2
	csSlotAlternateCDs    = 0x1000
	csSlotAlternateCDsMax = 5
	csSlotSignature       = 0x10000

	csHashTypeSHA1            = 1
	csHashTypeSHA256          = 2
	csHashTypeSHA256Truncated = 3
	csHashTypeSHA384          = 4

	// cdFlagAdhoc in CodeDirectory.flags means there is no CMS signature and
	// no signer: the binary vouches for nothing but its own page hashes.
	cdFlagAdhoc = 0x2
	// cdFlagLinkerSigned marks a signature the linker produced automatically
	// (Go's own ld does this on darwin/arm64). Always ad-hoc.
	cdFlagLinkerSigned = 0x20000

	// cdVersionSupportsTeamID is the first CodeDirectory version that carries
	// the teamOffset field.
	cdVersionSupportsTeamID = 0x20200

	lcCodeSignature = 0x1d

	// cdHashLen is the length of a cdhash as the kernel reports it: the
	// leading 20 bytes of the CodeDirectory's hash, whatever the hash type.
	cdHashLen = 20

	// minPageShift and maxPageShift bound CodeDirectory.pageSize: 4 KiB
	// (what codesign and Go's linker emit) up to 64 KiB, comfortably past
	// the 16 KiB the arm64 kernel uses and nowhere near an allocation that
	// matters.
	minPageShift = 12
	maxPageShift = 16
)

// codeSignature is everything the attestor needs from an embedded signature,
// after the file has been checked against it.
type codeSignature struct {
	// Identifier is the signing identifier from the CodeDirectory, for example
	// com.anthropic.claude-code.
	Identifier string
	// TeamID is the Apple Developer Team Identifier, taken from the OU of
	// the chain-verified signing certificate. The CodeDirectory's own team
	// field, when present, must agree with it. Empty for ad-hoc signatures
	// and for Apple platform binaries, whose leaf has no OU.
	TeamID string
	// CDHash is the 20-byte cdhash of the chosen CodeDirectory, exactly as the
	// kernel reports it through csops(CS_OPS_CDHASH).
	CDHash []byte
	// HashType is the CodeDirectory hash type (csHashType*).
	HashType uint8
	// Flags is the CodeDirectory flags word.
	Flags uint32
	// Platform is the CodeDirectory platform identifier; non-zero only for
	// Apple platform binaries.
	Platform uint8
	// Adhoc is true when there is no CMS signature. Nothing about Identifier
	// or TeamID is trustworthy on an ad-hoc signature.
	Adhoc bool
	// Chain is the verified certificate chain, leaf first, ending in the
	// trusted root. Nil when Adhoc.
	Chain []*x509.Certificate
	// SignedAt is the CMS signingTime attribute when present.
	SignedAt time.Time
	// CPU is the architecture of the slice that was checked.
	CPU macho.Cpu
	// Slice is the byte offset of the checked slice inside the file (0 for a
	// thin binary).
	Slice int64
}

// leaf returns the signing certificate.
func (s *codeSignature) leaf() *x509.Certificate {
	if len(s.Chain) == 0 {
		return nil
	}
	return s.Chain[0]
}

// errNoSignature means the Mach-O has no LC_CODE_SIGNATURE at all.
var errNoSignature = errors.New("attest: mach-o has no code signature")

// errSliceNotFound means no slice of a fat binary matched the selector (the
// kernel's cdhash when known, otherwise the host architecture).
var errSliceNotFound = errors.New("attest: no mach-o slice matches the running architecture")

// codeDirectory is a parsed CodeDirectory blob.
type codeDirectory struct {
	raw           []byte
	slot          uint32
	version       uint32
	flags         uint32
	hashOffset    uint32
	identOffset   uint32
	nSpecialSlots uint32
	nCodeSlots    uint32
	codeLimit     uint64
	hashSize      uint8
	hashType      uint8
	platform      uint8
	pageSize      uint8
	teamOffset    uint32
	identifier    string
	teamID        string
}

// hashFunc returns the hash the CodeDirectory uses, or an error for a type
// this package does not accept.
func (cd *codeDirectory) hashFunc() (func() hash.Hash, error) {
	switch cd.hashType {
	case csHashTypeSHA1:
		if cd.hashSize != sha1.Size {
			return nil, fmt.Errorf("attest: CodeDirectory hash size %d does not match SHA-1", cd.hashSize)
		}
		return sha1.New, nil
	case csHashTypeSHA256:
		if cd.hashSize != sha256.Size {
			return nil, fmt.Errorf("attest: CodeDirectory hash size %d does not match SHA-256", cd.hashSize)
		}
		return sha256.New, nil
	case csHashTypeSHA256Truncated:
		if cd.hashSize != 20 {
			return nil, fmt.Errorf("attest: CodeDirectory hash size %d does not match truncated SHA-256", cd.hashSize)
		}
		return func() hash.Hash { return truncatedHash{sha256.New(), 20} }, nil
	case csHashTypeSHA384:
		if cd.hashSize != sha512.Size384 {
			return nil, fmt.Errorf("attest: CodeDirectory hash size %d does not match SHA-384", cd.hashSize)
		}
		return sha512.New384, nil
	}
	return nil, fmt.Errorf("attest: unsupported CodeDirectory hash type %d", cd.hashType)
}

// strength orders hash types so the strongest CodeDirectory is chosen when a
// signature carries several.
func (cd *codeDirectory) strength() int {
	switch cd.hashType {
	case csHashTypeSHA384:
		return 4
	case csHashTypeSHA256:
		return 3
	case csHashTypeSHA256Truncated:
		return 2
	case csHashTypeSHA1:
		return 1
	}
	return 0
}

// truncatedHash adapts a hash to the CS_HASHTYPE_SHA256_TRUNCATED slot width.
type truncatedHash struct {
	hash.Hash
	n int
}

func (t truncatedHash) Sum(b []byte) []byte { return t.Hash.Sum(b)[:len(b)+t.n] }
func (t truncatedHash) Size() int           { return t.n }

// cdHash returns the full digest of the CodeDirectory blob under its own hash
// type. The kernel's cdhash is the first cdHashLen bytes of this.
func (cd *codeDirectory) cdHash() ([]byte, error) {
	hf, err := cd.hashFunc()
	if err != nil {
		return nil, err
	}
	h := hf()
	h.Write(cd.raw)
	return h.Sum(nil), nil
}

// superBlob is a parsed embedded signature: every CodeDirectory it carries,
// the CMS blob, and the sealed blobs the special slots hash.
type superBlob struct {
	cds     []*codeDirectory
	cms     []byte
	special map[uint32][]byte // slot -> whole blob (header included)
}

// parseSuperBlob walks the CSMAGIC_EMBEDDED_SIGNATURE index.
func parseSuperBlob(b []byte) (*superBlob, error) {
	if len(b) < 12 {
		return nil, errors.New("attest: code signature blob too short")
	}
	if binary.BigEndian.Uint32(b) != csMagicEmbeddedSignature {
		return nil, fmt.Errorf("attest: code signature magic %#x is not an embedded signature", binary.BigEndian.Uint32(b))
	}
	length := binary.BigEndian.Uint32(b[4:])
	count := binary.BigEndian.Uint32(b[8:])
	if int(length) > len(b) || length < 12 {
		return nil, errors.New("attest: code signature length exceeds blob")
	}
	b = b[:length]
	if uint64(12)+uint64(count)*8 > uint64(len(b)) {
		return nil, errors.New("attest: code signature index exceeds blob")
	}
	sb := &superBlob{special: map[uint32][]byte{}}
	for i := uint32(0); i < count; i++ {
		typ := binary.BigEndian.Uint32(b[12+i*8:])
		off := binary.BigEndian.Uint32(b[16+i*8:])
		if uint64(off)+8 > uint64(len(b)) {
			return nil, fmt.Errorf("attest: blob %#x offset out of range", typ)
		}
		blen := binary.BigEndian.Uint32(b[off+4:])
		if blen < 8 || uint64(off)+uint64(blen) > uint64(len(b)) {
			return nil, fmt.Errorf("attest: blob %#x length out of range", typ)
		}
		blob := b[off : off+blen]
		magic := binary.BigEndian.Uint32(blob)
		switch {
		case typ == csSlotCodeDirectory || (typ >= csSlotAlternateCDs && typ < csSlotAlternateCDs+csSlotAlternateCDsMax):
			if magic != csMagicCodeDirectory {
				return nil, fmt.Errorf("attest: slot %#x is not a CodeDirectory", typ)
			}
			cd, err := parseCodeDirectory(blob)
			if err != nil {
				return nil, err
			}
			cd.slot = typ
			sb.cds = append(sb.cds, cd)
		case typ == csSlotSignature:
			if magic != csMagicBlobWrapper {
				return nil, errors.New("attest: signature slot is not a blob wrapper")
			}
			sb.cms = blob[8:]
		default:
			// Requirements, entitlements, DER entitlements, launch constraints:
			// anything the CodeDirectory seals in a special slot.
			sb.special[typ] = blob
		}
	}
	if len(sb.cds) == 0 {
		return nil, errors.New("attest: code signature has no CodeDirectory")
	}
	return sb, nil
}

// parseCodeDirectory decodes the fixed header and the identifier and team
// strings. Bounds are checked against the blob's own length field.
func parseCodeDirectory(b []byte) (*codeDirectory, error) {
	if len(b) < 44 {
		return nil, errors.New("attest: CodeDirectory too short")
	}
	be := binary.BigEndian
	cd := &codeDirectory{
		raw:           b,
		version:       be.Uint32(b[8:]),
		flags:         be.Uint32(b[12:]),
		hashOffset:    be.Uint32(b[16:]),
		identOffset:   be.Uint32(b[20:]),
		nSpecialSlots: be.Uint32(b[24:]),
		nCodeSlots:    be.Uint32(b[28:]),
		codeLimit:     uint64(be.Uint32(b[32:])),
		hashSize:      b[36],
		hashType:      b[37],
		platform:      b[38],
		pageSize:      b[39],
	}
	if cd.version >= cdVersionSupportsTeamID {
		if len(b) < 52 {
			return nil, errors.New("attest: CodeDirectory too short for its version")
		}
		cd.teamOffset = be.Uint32(b[48:])
	}
	if cd.version >= 0x20300 {
		if len(b) < 64 {
			return nil, errors.New("attest: CodeDirectory too short for its version")
		}
		if cl64 := be.Uint64(b[56:]); cl64 != 0 {
			cd.codeLimit = cl64
		}
	}
	ident, err := cString(b, cd.identOffset)
	if err != nil {
		return nil, fmt.Errorf("attest: CodeDirectory identifier: %w", err)
	}
	cd.identifier = ident
	if cd.teamOffset != 0 {
		team, err := cString(b, cd.teamOffset)
		if err != nil {
			return nil, fmt.Errorf("attest: CodeDirectory team id: %w", err)
		}
		cd.teamID = team
	}
	if cd.hashSize == 0 {
		return nil, errors.New("attest: CodeDirectory hash size is zero")
	}
	// pageSize is log2 of the page; the kernel accepts 12 (4 KiB) through
	// its own page shift, 14 on arm64. It sizes a buffer in verifyPages, so
	// an unbounded value read from an attacker's file would be an
	// allocation of the attacker's choosing. Bound it here, at parse time.
	if cd.pageSize < minPageShift || cd.pageSize > maxPageShift {
		return nil, fmt.Errorf("attest: CodeDirectory page shift %d outside %d..%d", cd.pageSize, minPageShift, maxPageShift)
	}
	need := uint64(cd.hashOffset) + uint64(cd.nCodeSlots)*uint64(cd.hashSize)
	if uint64(cd.hashOffset) < uint64(cd.nSpecialSlots)*uint64(cd.hashSize) || need > uint64(len(b)) {
		return nil, errors.New("attest: CodeDirectory hash slots out of range")
	}
	return cd, nil
}

// cString reads a NUL-terminated string at off inside b.
func cString(b []byte, off uint32) (string, error) {
	if uint64(off) >= uint64(len(b)) {
		return "", errors.New("offset out of range")
	}
	end := bytes.IndexByte(b[off:], 0)
	if end < 0 {
		return "", errors.New("unterminated string")
	}
	return string(b[off : int(off)+end]), nil
}

// codeSlot returns the recorded hash for code page i.
func (cd *codeDirectory) codeSlot(i uint32) []byte {
	off := cd.hashOffset + i*uint32(cd.hashSize)
	return cd.raw[off : off+uint32(cd.hashSize)]
}

// specialSlot returns the recorded hash for special slot n (1-based, counted
// backwards from hashOffset), or nil when the CodeDirectory has fewer slots.
func (cd *codeDirectory) specialSlot(n uint32) []byte {
	if n == 0 || n > cd.nSpecialSlots {
		return nil
	}
	off := cd.hashOffset - n*uint32(cd.hashSize)
	return cd.raw[off : off+uint32(cd.hashSize)]
}

// verifyPages re-hashes every page of the slice from offset 0 to codeLimit
// and compares against the CodeDirectory. A mismatch means the file on disk
// is not the file the signature was made over, whatever the signature says.
func (cd *codeDirectory) verifyPages(slice io.ReaderAt) error {
	hf, err := cd.hashFunc()
	if err != nil {
		return err
	}
	if cd.pageSize == 0 {
		return errors.New("attest: CodeDirectory with infinite page size is not supported")
	}
	page := uint64(1) << cd.pageSize
	want := (cd.codeLimit + page - 1) / page
	if uint64(cd.nCodeSlots) != want {
		return fmt.Errorf("attest: CodeDirectory has %d code slots for %d pages", cd.nCodeSlots, want)
	}
	buf := make([]byte, page)
	for i := uint32(0); i < cd.nCodeSlots; i++ {
		off := uint64(i) * page
		n := page
		if off+n > cd.codeLimit {
			n = cd.codeLimit - off
		}
		if _, err := slice.ReadAt(buf[:n], int64(off)); err != nil {
			return fmt.Errorf("attest: reading code page %d: %w", i, err)
		}
		h := hf()
		h.Write(buf[:n])
		if !bytes.Equal(h.Sum(nil), cd.codeSlot(i)) {
			return fmt.Errorf("attest: code page %d does not match its CodeDirectory hash", i)
		}
	}
	return nil
}

// verifySpecialSlots checks every special slot whose sealed blob is inside the
// signature itself (requirements, entitlements, launch constraints). Slots that
// seal external files (Info.plist, resources) cannot be checked for a bare
// executable and are not.
func (cd *codeDirectory) verifySpecialSlots(sb *superBlob) error {
	hf, err := cd.hashFunc()
	if err != nil {
		return err
	}
	for slot, blob := range sb.special {
		want := cd.specialSlot(slot)
		if want == nil {
			return fmt.Errorf("attest: sealed blob %#x has no special slot in the CodeDirectory", slot)
		}
		h := hf()
		h.Write(blob)
		if !bytes.Equal(h.Sum(nil), want) {
			return fmt.Errorf("attest: sealed blob %#x does not match its special slot hash", slot)
		}
	}
	// A non-zero requirements slot with no requirements blob is a signature
	// that has been cut apart.
	if want := cd.specialSlot(csSlotRequirements); want != nil {
		if _, ok := sb.special[csSlotRequirements]; !ok && !isZero(want) {
			return errors.New("attest: CodeDirectory seals requirements that are not present")
		}
	}
	return nil
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// sliceSelector chooses which slice of a fat file is the one to trust. When
// the kernel has told us the cdhash of the running process, the slice whose
// CodeDirectory has that cdhash is the running code, by definition. Without
// it, fall back to the host architecture.
type sliceSelector struct {
	kernelCDHash []byte
}

// maxSignatureBlob bounds LC_CODE_SIGNATURE.datasize. A 1 GiB binary at
// 4 KiB pages needs 8 MiB of SHA-256 slots; nothing legitimate is near this.
const maxSignatureBlob = 64 << 20

// loadedSlice is one slice's signature after the cheap, bounded parse and
// before any of the expensive checks. Everything here costs O(signature
// blob) and allocates nothing sized by attacker-chosen fields.
type loadedSlice struct {
	sr      *io.SectionReader
	off     int64
	cpu     macho.Cpu
	dataOff uint32
	sb      *superBlob
	best    *codeDirectory
	primary *codeDirectory
	cdHash  []byte
}

// verifyMachO parses the file at r, selects the slice, checks the file
// against its CodeDirectory, and verifies the CMS signature against roots.
// It returns a fully-checked codeSignature or an error. There is no partial
// success: an unverifiable signature is an error, never a weaker result.
//
// Order matters for robustness, not just correctness: the file at the path
// is attacker-writable on a real install, and the kernel cdhash is what
// rejects a swapped file. So every slice is first parsed cheaply and its
// cdhash computed, the running slice is SELECTED by that cdhash, and only
// then are the page hashes and the CMS signature of that one slice verified.
// A swapped or crafted file is refused before any of its content drives
// allocation or parsing beyond the bounded signature blob.
func verifyMachO(r io.ReaderAt, size int64, sel sliceSelector, roots []*x509.Certificate) (*codeSignature, error) {
	type slice struct {
		off  int64
		size int64
		cpu  macho.Cpu
	}
	var slices []slice
	if ff, err := macho.NewFatFile(r); err == nil {
		for _, a := range ff.Arches {
			slices = append(slices, slice{int64(a.Offset), int64(a.Size), a.Cpu})
		}
	} else {
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, fmt.Errorf("attest: not a mach-o: %w", err)
		}
		slices = append(slices, slice{0, size, f.Cpu})
	}

	var loaded []*loadedSlice
	var lastErr error
	for _, s := range slices {
		sr := io.NewSectionReader(r, s.off, s.size)
		ls, err := loadSlice(sr, s.size)
		if err != nil {
			lastErr = err
			continue
		}
		ls.off, ls.cpu = s.off, s.cpu
		loaded = append(loaded, ls)
	}

	var chosen *loadedSlice
	if sel.kernelCDHash != nil {
		for _, ls := range loaded {
			if bytes.Equal(ls.cdHash, sel.kernelCDHash) {
				chosen = ls
				break
			}
		}
		if chosen == nil {
			if lastErr != nil {
				return nil, fmt.Errorf("%w (no slice matches the kernel cdhash; last error: %v)", errSliceNotFound, lastErr)
			}
			return nil, fmt.Errorf("%w: no slice's cdhash matches the kernel's", errSliceNotFound)
		}
	} else {
		want := hostCPU()
		for _, ls := range loaded {
			if ls.cpu == want {
				chosen = ls
				break
			}
		}
		if chosen == nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errSliceNotFound
		}
	}
	sig, err := verifyLoaded(chosen, roots)
	if err != nil {
		return nil, err
	}
	sig.CPU = chosen.cpu
	sig.Slice = chosen.off
	return sig, nil
}

func hostCPU() macho.Cpu {
	switch runtime.GOARCH {
	case "arm64":
		return macho.CpuArm64
	case "amd64":
		return macho.CpuAmd64
	}
	return 0
}

// loadSlice locates and parses one slice's signature and computes its
// cdhash. This is the bounded, pre-selection part: it reads the load
// commands and at most maxSignatureBlob bytes, and every allocation is sized
// by the blob's own length fields, which are checked against that bound.
func loadSlice(sr *io.SectionReader, size int64) (*loadedSlice, error) {
	f, err := macho.NewFile(sr)
	if err != nil {
		return nil, fmt.Errorf("attest: parsing slice: %w", err)
	}
	defer f.Close()
	var dataOff, dataSize uint32
	found := false
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 16 {
			continue
		}
		if f.ByteOrder.Uint32(raw) == lcCodeSignature {
			dataOff = f.ByteOrder.Uint32(raw[8:])
			dataSize = f.ByteOrder.Uint32(raw[12:])
			found = true
			break
		}
	}
	if !found {
		return nil, errNoSignature
	}
	if int64(dataOff)+int64(dataSize) > size {
		return nil, errors.New("attest: code signature extends past end of slice")
	}
	if dataSize > maxSignatureBlob {
		return nil, fmt.Errorf("attest: code signature of %d bytes exceeds the %d byte bound", dataSize, maxSignatureBlob)
	}
	blob := make([]byte, dataSize)
	if _, err := sr.ReadAt(blob, int64(dataOff)); err != nil {
		return nil, fmt.Errorf("attest: reading code signature: %w", err)
	}
	sb, err := parseSuperBlob(blob)
	if err != nil {
		return nil, err
	}

	// Choose the strongest CodeDirectory, and insist all of them agree on
	// who they claim to be: a signature whose SHA-1 and SHA-256 directories
	// name different identities is not one signature.
	var best, primary *codeDirectory
	for _, cd := range sb.cds {
		if cd.slot == csSlotCodeDirectory {
			primary = cd
		}
		if best == nil || cd.strength() > best.strength() {
			best = cd
		}
		if cd.identifier != sb.cds[0].identifier || cd.teamID != sb.cds[0].teamID {
			return nil, errors.New("attest: CodeDirectories disagree on identifier or team id")
		}
	}
	if primary == nil {
		return nil, errors.New("attest: code signature has no primary CodeDirectory")
	}
	full, err := best.cdHash()
	if err != nil {
		return nil, err
	}
	return &loadedSlice{sr: sr, dataOff: dataOff, sb: sb, best: best, primary: primary, cdHash: full[:cdHashLen]}, nil
}

// verifyLoaded runs the expensive checks on the selected slice: every code
// page, every sealed special slot, and the CMS signature and chain.
func verifyLoaded(ls *loadedSlice, roots []*x509.Certificate) (*codeSignature, error) {
	best, primary, sb := ls.best, ls.primary, ls.sb
	// The CodeDirectory must cover exactly the bytes before the signature:
	// anything less leaves unsigned code in the file.
	if best.codeLimit != uint64(ls.dataOff) {
		return nil, fmt.Errorf("attest: CodeDirectory covers %d bytes but the signature starts at %d", best.codeLimit, ls.dataOff)
	}
	if err := best.verifyPages(ls.sr); err != nil {
		return nil, err
	}
	if err := best.verifySpecialSlots(sb); err != nil {
		return nil, err
	}
	sig := &codeSignature{
		Identifier: best.identifier,
		CDHash:     ls.cdHash,
		HashType:   best.hashType,
		Flags:      best.flags,
		Platform:   best.platform,
	}

	if len(sb.cms) == 0 {
		if best.flags&cdFlagAdhoc == 0 {
			return nil, errors.New("attest: code signature has no CMS blob and is not marked ad-hoc")
		}
		sig.Adhoc = true
		return sig, nil
	}

	// A CMS blob is present: it must verify, and it must bind the
	// CodeDirectory we chose. The primary directory is bound by the CMS
	// messageDigest; an alternate directory is bound only if its cdhash is in
	// the signed cdhashes attribute.
	res, err := verifyCMS(sb.cms, primary.raw, roots)
	if err != nil {
		return nil, err
	}
	if best != primary {
		bound := false
		for _, h := range res.cdHashes {
			if bytes.Equal(h, sig.CDHash) {
				bound = true
			}
		}
		if !bound {
			return nil, errors.New("attest: chosen CodeDirectory is not bound by the CMS signature")
		}
	}
	sig.Chain = res.chain
	sig.SignedAt = res.signedAt
	// The Team ID is the certificate's claim, made under a verified chain;
	// the CodeDirectory string is only allowed to agree with it. The
	// certificate is the thing that chains to the root, so it is the
	// source; the CD string is what the kernel cross-checks against the
	// chain at exec (and kills the process on disagreement), so it is the
	// consistency check.
	sig.TeamID = subjectOU(res.chain[0].Subject)
	if best.teamID != "" && best.teamID != sig.TeamID {
		return nil, fmt.Errorf("attest: CodeDirectory team id %q does not match the signing certificate OU %q", best.teamID, sig.TeamID)
	}
	return sig, nil
}

// digestFor maps a CodeDirectory hash type to the crypto.Hash the CMS layer
// uses to bind it.
func digestFor(hashType uint8) (crypto.Hash, bool) {
	switch hashType {
	case csHashTypeSHA1:
		return crypto.SHA1, true
	case csHashTypeSHA256, csHashTypeSHA256Truncated:
		return crypto.SHA256, true
	case csHashTypeSHA384:
		return crypto.SHA384, true
	}
	return 0, false
}
