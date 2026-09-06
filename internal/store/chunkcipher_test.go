package store

import (
	"bytes"
	"io"
	"testing"
)

// TestChunkCipherRoundTrip covers the sizes where the framing is most likely to
// be wrong: nothing at all, and exactly on a chunk boundary in both directions.
func TestChunkCipherRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one byte", 1},
		{"one byte under a chunk", chunkPlainBytes - 1},
		{"exactly one chunk", chunkPlainBytes},
		{"one byte over a chunk", chunkPlainBytes + 1},
		{"two chunks and a bit", 2*chunkPlainBytes + 77},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plain := make([]byte, c.size)
			for i := range plain {
				plain[i] = byte(i * 7)
			}
			var buf bytes.Buffer
			w, err := newChunkWriter(&buf, testPassphrase)
			if err != nil {
				t.Fatal(err)
			}
			// Written in awkward slices, because the real caller is a tar
			// writer and will not hand over neat chunk-sized pieces.
			for off := 0; off < len(plain); off += 7919 {
				end := min(off+7919, len(plain))
				if _, err := w.Write(plain[off:end]); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close is not idempotent: %v", err)
			}

			r, err := newChunkReader(bytes.NewReader(buf.Bytes()), testPassphrase)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round trip lost data: got %d bytes, want %d", len(got), len(plain))
			}
		})
	}
}

// TestChunkCipherRejectsReorderedChunks proves the per-chunk nonce and the
// index in the additional data are load-bearing: swapping two chunks of a
// container must not decrypt.
func TestChunkCipherRejectsReorderedChunks(t *testing.T) {
	plain := bytes.Repeat([]byte{0xA5}, 3*chunkPlainBytes)
	var buf bytes.Buffer
	w, err := newChunkWriter(&buf, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw := buf.Bytes()
	frame := backupHeaderLen
	frameLen := 5 + chunkPlainBytes + gcmOverhead
	first := bytes.Clone(raw[frame : frame+frameLen])
	second := bytes.Clone(raw[frame+frameLen : frame+2*frameLen])
	swapped := bytes.Clone(raw)
	copy(swapped[frame:], second)
	copy(swapped[frame+frameLen:], first)

	r, err := newChunkReader(bytes.NewReader(swapped), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("reordered chunks decrypted")
	}
}

// TestChunkCipherRejectsAnOversizedFrameLength is the allocation guard: a length
// read out of the file must never size a buffer.
func TestChunkCipherRejectsAnOversizedFrameLength(t *testing.T) {
	var buf bytes.Buffer
	w, err := newChunkWriter(&buf, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("small")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw := bytes.Clone(buf.Bytes())
	// Claim a 4 GiB chunk. Nothing must be allocated on the strength of it.
	copy(raw[backupHeaderLen+1:], be32(0xFFFFFFFF))
	r, err := newChunkReader(bytes.NewReader(raw), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(r)
	wantErrIs(t, err, ErrBackupMalformed, "an oversized frame length")
}

// TestChunkCipherRejectsATruncatedFinalFrame: dropping the last frame removes
// the only frame flagged final, so the reader reports tampering rather than a
// short but plausible file.
func TestChunkCipherRejectsATruncatedFinalFrame(t *testing.T) {
	plain := bytes.Repeat([]byte{0x11}, 2*chunkPlainBytes+10)
	var buf bytes.Buffer
	w, err := newChunkWriter(&buf, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	frameLen := 5 + chunkPlainBytes + gcmOverhead
	truncated := buf.Bytes()[:backupHeaderLen+2*frameLen]
	r, err := newChunkReader(bytes.NewReader(truncated), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(r)
	wantErrIs(t, err, ErrBackupMalformed, "a container with its final frame removed")
}

// TestBackupIterationCountIsBounded pins the clamp on a value that comes out of
// the file and directly decides how much work the reader does.
func TestBackupIterationCountIsBounded(t *testing.T) {
	cases := []struct {
		name  string
		iters int
		ok    bool
	}{
		{"below the floor", minIterations - 1, false},
		{"at the floor", minIterations, true},
		{"what we write", pbkdf2Iterations, true},
		{"above the ceiling", maxIterations + 1, false},
		{"zero", 0, false},
		{"negative", -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := deriveBackupKey(testPassphrase, make([]byte, saltLen), c.iters)
			if c.ok && err != nil {
				t.Fatalf("rejected an acceptable iteration count: %v", err)
			}
			if !c.ok {
				wantErrIs(t, err, ErrBackupMalformed, "deriveBackupKey")
			}
		})
	}
}
