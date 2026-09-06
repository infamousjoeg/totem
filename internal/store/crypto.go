package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// Envelope encryption, the shape the spec forces: "Issuer-managed rotating
// secrets (GitHub refresh tokens, presence session keys) are rows
// envelope-encrypted under a data key resolved through Summon"
// (docs/totem-design.md, "Issuer (broker box)").
//
// Two layers, on purpose:
//
//   - Each row carries its own random 32-byte row key. The row's plaintext is
//     sealed under that row key with AES-256-GCM.
//   - The row key is itself sealed ("wrapped") under a key derived from the
//     Summon-resolved data key.
//
// The data key is NEVER persisted. Only the wrapped row keys are, and a wrapped
// row key is worthless without a live Summon resolve. That is what makes
// `issuer rotate-data-key` cheap enough to be atomic: rotation re-seals ~60
// bytes per row rather than rewriting every payload, so the whole rotation fits
// in one SQLite transaction and can never be observed half-done.
//
// The threat rotation answers is "the old data key leaked". After rotation the
// old key no longer opens the current file, which is the property that matters.
// It cannot un-leak a snapshot an attacker already took with the old key in
// hand; nothing can, and re-encrypting payloads would not change that either.

const (
	// dataKeyLen is the length of the raw data key material a Summon resolve is
	// expected to return, and of every key derived from it.
	dataKeyLen = 32
	// rowKeyLen is the per-row data-encryption key length (AES-256).
	rowKeyLen = 32
	// saltLen is the per-generation HKDF salt length.
	saltLen = 32
	// kcvLen is the stored key check value length. It is a KDF output, not a
	// ciphertext, so it proves the operator resolved the right key without
	// revealing anything usable about it.
	kcvLen = 16
)

// Domain separation strings. Every derived key and every AEAD binding carries a
// distinct, versioned label so that no output of one use can ever be replayed
// into another.
const (
	infoWrapKey  = "totem/store/wrap-key/v1"
	infoKCV      = "totem/store/kcv/v1"
	aadWrapV1    = "totem/store/wrap/v1"
	aadRowV1     = "totem/store/row/v1"
	chainLabelV1 = "totem/chain/v1"
)

// ErrDataKeyMismatch means the data key Summon resolved does not match the key
// the database's active generation was written under.
//
// This exists because of the ordering hazard around `issuer rotate-data-key`:
// the store is rotated to a new key and the provider must then hand back that
// same new key. If the two ever disagree, the operator gets this sentence
// instead of a pile of AEAD authentication failures that look like corruption.
var ErrDataKeyMismatch = errors.New("store: the Summon-resolved data key does not match this database's active data key generation")

// ErrValueTooLarge means a caller offered a row plaintext or a chain payload
// larger than the store accepts. Sizes are bounded on the way in so that no
// value read back off disk can later dictate an allocation.
var ErrValueTooLarge = errors.New("store: value exceeds the maximum size the store accepts")

// ErrBadName means a collection, id or record kind failed validation. Names are
// validated before they reach SQL or a filename, never after.
var ErrBadName = errors.New("store: name failed validation")

// ErrCiphertextMalformed means a stored envelope was too short or otherwise
// structurally invalid. It is reported rather than tolerated: a row that cannot
// be parsed is evidence, not noise.
var ErrCiphertextMalformed = errors.New("store: stored ciphertext is malformed")

// deriveWrapKey turns the raw Summon-resolved data key into the AES key that
// wraps row keys for one generation.
//
// The generation number is inside the HKDF info string, so two generations of
// the same raw key material still produce different wrapping keys and a row
// tagged with the wrong generation fails to unwrap loudly.
func deriveWrapKey(dataKey, salt []byte, gen int64) ([]byte, error) {
	if len(dataKey) == 0 {
		return nil, fmt.Errorf("store: empty data key")
	}
	if len(salt) != saltLen {
		return nil, fmt.Errorf("store: data key salt is %d bytes, want %d", len(salt), saltLen)
	}
	return hkdf.Key(sha256.New, dataKey, salt, fmt.Sprintf("%s|gen=%d", infoWrapKey, gen), dataKeyLen)
}

// deriveKCV computes the key check value stored alongside a generation. It is
// derived from the same inputs as the wrapping key under a different label, so
// knowing it grants nothing.
func deriveKCV(dataKey, salt []byte, gen int64) ([]byte, error) {
	if len(salt) != saltLen {
		return nil, fmt.Errorf("store: data key salt is %d bytes, want %d", len(salt), saltLen)
	}
	return hkdf.Key(sha256.New, dataKey, salt, fmt.Sprintf("%s|gen=%d", infoKCV, gen), kcvLen)
}

// checkKCV compares a freshly derived key check value against the stored one in
// constant time and reports ErrDataKeyMismatch on disagreement.
func checkKCV(dataKey, salt []byte, gen int64, stored []byte) error {
	got, err := deriveKCV(dataKey, salt, gen)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, stored) != 1 {
		return ErrDataKeyMismatch
	}
	return nil
}

// aeadFor builds an AES-256-GCM AEAD for a 32-byte key.
func aeadFor(key []byte) (cipher.AEAD, error) {
	if len(key) != dataKeyLen {
		return nil, fmt.Errorf("store: key is %d bytes, want %d", len(key), dataKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext under key with a fresh random nonce and returns
// nonce||ciphertext. Nonces are random rather than counter-derived because
// nothing here shares a key across enough messages for a 96-bit random nonce to
// be a concern, and a counter would have to be persisted and could be rewound.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Append into a buffer that already holds the nonce so the result is one
	// allocation and the nonce is unambiguously the prefix.
	out := make([]byte, len(nonce), len(nonce)+len(plaintext)+gcm.Overhead())
	copy(out, nonce)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// open reverses seal. It validates the length before slicing, so a truncated or
// hostile row cannot drive a panic or an allocation.
func open(key, box, aad []byte) ([]byte, error) {
	gcm, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	if len(box) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrCiphertextMalformed
	}
	nonce, ct := box[:gcm.NonceSize()], box[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// wrapAAD binds a wrapped row key to the exact place it is stored: collection,
// id and data key generation. An attacker with write access to the file cannot
// move a row's key to another id or replay a pre-rotation key, because the
// binding is authenticated.
func wrapAAD(collection, id string, gen int64) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|gen=%d", aadWrapV1, collection, id, gen))
}

// rowAAD binds a row payload to its collection and id. It deliberately omits
// the generation: rotation re-wraps keys and must not have to rewrite payloads.
func rowAAD(collection, id string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s", aadRowV1, collection, id))
}

// newRowKey returns a fresh random row key.
func newRowKey() ([]byte, error) {
	k := make([]byte, rowKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// zero wipes key material a caller is done with. It mirrors summon.Value.Zero:
// derived keys are held for the length of one call and then destroyed, so a
// caller that keeps one across a Summon rotation is holding a zeroed buffer,
// which is the intended loud failure.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// recordHash computes a record's chain hash.
//
// Every field is length-prefixed with a fixed-width big-endian length and the
// whole thing is domain-separated, so no two distinct records can produce the
// same preimage by shifting bytes across a field boundary. That property is
// what makes the chain evidence rather than decoration: the spec puts issuance,
// exchange AND admin-signed policy records in one chain precisely so "a
// compromised host ... cannot quietly widen a grant or enroll a device"
// (docs/totem-design.md, "Issuer (broker box)").
func recordHash(seq int64, kind string, atUnixNano int64, payload, prevHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte(chainLabelV1))
	var n [8]byte
	writeU64 := func(v uint64) {
		binary.BigEndian.PutUint64(n[:], v)
		h.Write(n[:])
	}
	writeLP := func(b []byte) {
		writeU64(uint64(len(b)))
		h.Write(b)
	}
	writeU64(uint64(seq))
	writeLP([]byte(kind))
	writeU64(uint64(atUnixNano))
	writeLP(payload)
	writeLP(prevHash)
	return h.Sum(nil)
}

// genesisPrevHash is the predecessor of sequence 1: 32 zero bytes. A chain
// whose first record claims any other predecessor is broken at sequence 1.
func genesisPrevHash() []byte { return make([]byte, sha256.Size) }

// randRead fills b with cryptographic randomness. crypto/rand.Read never
// returns a short read and only errors when the OS entropy source is
// unavailable, which is fatal rather than retryable.
func randRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}
