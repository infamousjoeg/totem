package store

import (
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// The backup container: a header, then a sequence of independently
// authenticated chunks.
//
//	header (58 bytes, authenticated but not encrypted)
//	  magic       8   "TOTEMBKP"
//	  version     1   1
//	  kdf         1   1 = PBKDF2-HMAC-SHA256
//	  iterations  4   big-endian uint32
//	  salt       32
//	  noncePrefix 4
//	  reserved    8   zero
//
//	frame (repeated)
//	  final       1   1 on the last frame, 0 otherwise
//	  length      4   big-endian uint32, ciphertext length
//	  ciphertext  length bytes
//
// The design is chunked rather than one AEAD over the whole file so that a
// restore never has to hold the entire database in memory to authenticate it,
// and so that no plaintext is ever emitted before the chunk carrying it has
// been authenticated.
//
// Three things stop the obvious attacks on a chunked scheme. Each chunk's nonce
// is the file's random prefix followed by the chunk index, so chunks cannot be
// reordered or replayed between files. Each chunk's additional data carries the
// chunk index and the final-frame flag, so a chunk cannot be moved and the last
// chunk cannot be silently dropped: truncation removes the frame that claims to
// be final, and the reader reports a malformed file rather than a short
// database. Each chunk's additional data also carries a hash of the header, so
// the salt and iteration count are authenticated by every chunk.
const (
	backupHeaderLen = 8 + 1 + 1 + 4 + saltLen + 4 + 8
	noncePrefixLen  = 4
)

// deriveBackupKey turns the Summon-resolved passphrase into the file key.
func deriveBackupKey(passphrase, salt []byte, iterations int) ([]byte, error) {
	if iterations < minIterations || iterations > maxIterations {
		return nil, fmt.Errorf("%w: iteration count %d is outside the accepted range [%d, %d]",
			ErrBackupMalformed, iterations, minIterations, maxIterations)
	}
	// pbkdf2.Key takes the password as a string; this is a conversion, not a
	// copy the caller can reach, and the derived key is what is retained.
	return pbkdf2.Key(sha256.New, string(passphrase), salt, iterations, dataKeyLen)
}

// backupHeader is the parsed container header.
type backupHeader struct {
	iterations  int
	salt        []byte
	noncePrefix []byte
	raw         []byte
}

func (h backupHeader) aad(index uint64, final bool) []byte {
	sum := sha256.Sum256(h.raw)
	out := make([]byte, 0, len(aadBackupV1)+sha256.Size+8+1)
	out = append(out, aadBackupV1...)
	out = append(out, sum[:]...)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], index)
	out = append(out, n[:]...)
	if final {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

// chunkWriter buffers plaintext into fixed-size chunks and seals each one.
type chunkWriter struct {
	w      io.Writer
	gcm    cipher.AEAD
	hdr    backupHeader
	buf    []byte
	index  uint64
	closed bool
	err    error
}

// newChunkWriter writes the container header and returns a writer that seals
// what is written to it.
func newChunkWriter(w io.Writer, passphrase []byte) (*chunkWriter, error) {
	salt := make([]byte, saltLen)
	if err := randRead(salt); err != nil {
		return nil, err
	}
	prefix := make([]byte, noncePrefixLen)
	if err := randRead(prefix); err != nil {
		return nil, err
	}
	raw := make([]byte, 0, backupHeaderLen)
	raw = append(raw, backupMagic...)
	raw = append(raw, backupVersion, kdfPBKDF2SHA256)
	raw = append(raw, be32(uint32(pbkdf2Iterations))...)
	raw = append(raw, salt...)
	raw = append(raw, prefix...)
	raw = append(raw, make([]byte, 8)...)

	key, err := deriveBackupKey(passphrase, salt, pbkdf2Iterations)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	gcm, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	return &chunkWriter{
		w:   w,
		gcm: gcm,
		hdr: backupHeader{iterations: pbkdf2Iterations, salt: salt, noncePrefix: prefix, raw: raw},
		buf: make([]byte, 0, chunkPlainBytes),
	}, nil
}

// Write buffers plaintext, sealing a chunk each time one fills. Callers hand
// over arbitrary slice sizes (the tar writer certainly does), so chunking is
// this writer's job rather than theirs.
func (c *chunkWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	written := 0
	for len(p) > 0 {
		space := chunkPlainBytes - len(c.buf)
		n := min(space, len(p))
		c.buf = append(c.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(c.buf) == chunkPlainBytes {
			if err := c.flush(false); err != nil {
				c.err = err
				return written, err
			}
		}
	}
	return written, nil
}

// Close seals the final chunk. A container always ends with a frame flagged
// final, even when the payload was empty, so an empty file and a truncated one
// are distinguishable.
func (c *chunkWriter) Close() error {
	if c.err != nil {
		return c.err
	}
	if c.closed {
		return nil
	}
	c.closed = true
	return c.flush(true)
}

func (c *chunkWriter) flush(final bool) error {
	nonce := chunkNonce(c.hdr.noncePrefix, c.index)
	ct := c.gcm.Seal(nil, nonce, c.buf, c.hdr.aad(c.index, final))
	frame := make([]byte, 0, 5+len(ct))
	if final {
		frame = append(frame, 1)
	} else {
		frame = append(frame, 0)
	}
	frame = append(frame, be32(uint32(len(ct)))...)
	frame = append(frame, ct...)
	if _, err := c.w.Write(frame); err != nil {
		return err
	}
	c.buf = c.buf[:0]
	c.index++
	return nil
}

// chunkReader authenticates and returns the plaintext of a container.
type chunkReader struct {
	r     io.Reader
	gcm   cipher.AEAD
	hdr   backupHeader
	buf   []byte
	index uint64
	done  bool
	err   error
}

// newChunkReader parses and validates the container header. It does not read
// any chunk, so a file that is not a totem backup is rejected before any
// decryption work happens.
func newChunkReader(r io.Reader, passphrase []byte) (*chunkReader, error) {
	raw := make([]byte, backupHeaderLen)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, fmt.Errorf("%w: header is short", ErrBackupMalformed)
	}
	if string(raw[:8]) != backupMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrBackupMalformed)
	}
	if raw[8] != backupVersion {
		return nil, fmt.Errorf("%w: container version %d, this binary reads %d", ErrBackupMalformed, raw[8], backupVersion)
	}
	if raw[9] != kdfPBKDF2SHA256 {
		return nil, fmt.Errorf("%w: unknown key derivation function %d", ErrBackupMalformed, raw[9])
	}
	iterations := int(binary.BigEndian.Uint32(raw[10:14]))
	salt := raw[14 : 14+saltLen]
	prefix := raw[14+saltLen : 14+saltLen+noncePrefixLen]

	key, err := deriveBackupKey(passphrase, salt, iterations)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	gcm, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	return &chunkReader{
		r:   r,
		gcm: gcm,
		hdr: backupHeader{iterations: iterations, salt: salt, noncePrefix: prefix, raw: raw},
	}, nil
}

// Read returns plaintext from authenticated chunks only. No byte is handed to a
// caller before the chunk carrying it has been verified, so a restore never
// acts on data an attacker could have edited.
func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.done {
			return 0, io.EOF
		}
		if err := c.next(); err != nil {
			c.err = err
			return 0, err
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// next reads and authenticates one frame.
func (c *chunkReader) next() error {
	var head [5]byte
	if _, err := io.ReadFull(c.r, head[:]); err != nil {
		// Running out of frames before one was flagged final IS the truncation
		// case, and it is reported as tampering rather than as a clean EOF.
		return fmt.Errorf("%w: the container ends before a final chunk", ErrBackupMalformed)
	}
	final := head[0] == 1
	if head[0] > 1 {
		return fmt.Errorf("%w: frame flag %d", ErrBackupMalformed, head[0])
	}
	length := binary.BigEndian.Uint32(head[1:])
	// The length comes out of the file, so it is bounded before it sizes an
	// allocation.
	if length < uint32(c.gcm.Overhead()) || length > maxChunkCipherBytes {
		return fmt.Errorf("%w: frame length %d is outside [%d, %d]",
			ErrBackupMalformed, length, c.gcm.Overhead(), maxChunkCipherBytes)
	}
	ct := make([]byte, length)
	if _, err := io.ReadFull(c.r, ct); err != nil {
		return fmt.Errorf("%w: frame body is short", ErrBackupMalformed)
	}
	nonce := chunkNonce(c.hdr.noncePrefix, c.index)
	pt, err := c.gcm.Open(nil, nonce, ct, c.hdr.aad(c.index, final))
	if err != nil {
		return fmt.Errorf("%w: chunk %d does not authenticate (wrong passphrase, or the file was altered)", ErrBackupMalformed, c.index)
	}
	c.buf = pt
	c.index++
	if final {
		c.done = true
		// Anything after the final frame is an attempt to append to an
		// authenticated file, so it is refused rather than ignored.
		var extra [1]byte
		if n, _ := c.r.Read(extra[:]); n > 0 {
			return fmt.Errorf("%w: trailing bytes after the final chunk", ErrBackupMalformed)
		}
	}
	return nil
}

// chunkNonce is the file's random prefix followed by the chunk index. The index
// is unique within a file and the prefix is unique across files, so no key ever
// sees a repeated nonce.
func chunkNonce(prefix []byte, index uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[noncePrefixLen:], index)
	return nonce
}
