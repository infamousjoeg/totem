package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
)

// Known-answer vectors.
//
// Every value below was produced by an INDEPENDENT implementation (Python's
// cryptography package over OpenSSL, and hashlib) from the formats documented
// in crypto.go and chunkcipher.go, then frozen here. Testing this package's
// encrypt against this package's decrypt would only prove it is self-consistent;
// these prove it is correct, and they pin the on-disk format so a later change
// to it cannot pass unnoticed.
//
// Inputs: data key 000102..1f, salt a0a1..bf, generation 1, collection
// "enrollments", id "device-01".
const (
	katDataKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	katSalt    = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	katWrapKey = "4d9250a6247235d502680a67bab8553611640789cb70a1033e11a38e0c7ee4fe"
	katKCV     = "cc5f6dcf6945f934aa8eaef6402e2f2b"
	katRowKey  = "5a5b58595e5f5c5d52535051565754554a4b48494e4f4c4d4243404146474445"
	katWrapped = "000102030405060708090a0bc3338710f63d4361bb1d914331b341325998b819269eae4d5a29f4d012f3d82918ee1cf54b643456bb278efa6461ba2d"
	katPayload = "0b0a090807060504030201f086b7adb5b14db62031c2196cb7a962a58f7e7165e99cead3c31ae62bdcbd6b6a4252fab8aa4e1679228ab008391918f8d08e28e06fbd7e85582280cb"
	katKATColl = "enrollments"
	katKATID   = "device-01"
	katGen     = 1

	katBackupPassphrase = "a-summon-resolved-backup-passphrase"
	katBackupSalt       = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
	katBackupIterations = 100_000
	katBackupKey        = "a436900d4bf0ea493a4977407cc791985817f56b91f6cd549e6843609d20a591"

	katChainPrev   = "dededededededededededededededededededededededededededededededede"
	katChainHash   = "5470ffab51fb7eb0a44224865913b8319c5edb2dd3915ce7afe1df802c812d06"
	katGenesisHash = "11b3f4702b3e21b38fc13a2609bab065d8686f60901a518ff8e889fa5a96b310"
)

var (
	katPlaintext    = []byte("totem enrollment record, known-answer vector")
	katChainPayload = []byte(`{"spiffe_id":"spiffe://issuer.example/device/d1/tool/claude"}`)
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex vector: %v", err)
	}
	return b
}

// TestKATDerivations pins HKDF-SHA256 key derivation against OpenSSL's answer.
func TestKATDerivations(t *testing.T) {
	dataKey, salt := unhex(t, katDataKey), unhex(t, katSalt)

	cases := []struct {
		name string
		got  func() ([]byte, error)
		want string
	}{
		{"wrap key", func() ([]byte, error) { return deriveWrapKey(dataKey, salt, katGen) }, katWrapKey},
		{"key check value", func() ([]byte, error) { return deriveKCV(dataKey, salt, katGen) }, katKCV},
		{"backup file key", func() ([]byte, error) {
			return deriveBackupKey([]byte(katBackupPassphrase), unhex(t, katBackupSalt), katBackupIterations)
		}, katBackupKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.got()
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if hex.EncodeToString(got) != c.want {
				t.Errorf("got %s, want %s", hex.EncodeToString(got), c.want)
			}
		})
	}
}

// TestKATOpenForeignCiphertext decrypts an envelope this package never
// produced. It proves the nonce framing and the additional-data construction
// match the documented format rather than merely matching seal().
func TestKATOpenForeignCiphertext(t *testing.T) {
	wrapKey, rowKey := unhex(t, katWrapKey), unhex(t, katRowKey)

	gotRowKey, err := open(wrapKey, unhex(t, katWrapped), wrapAAD(katKATColl, katKATID, katGen))
	if err != nil {
		t.Fatalf("unwrapping a foreign wrapped key: %v", err)
	}
	if !bytes.Equal(gotRowKey, rowKey) {
		t.Fatalf("unwrapped row key = %x, want %x", gotRowKey, rowKey)
	}
	gotPlain, err := open(rowKey, unhex(t, katPayload), rowAAD(katKATColl, katKATID))
	if err != nil {
		t.Fatalf("decrypting a foreign payload: %v", err)
	}
	if !bytes.Equal(gotPlain, katPlaintext) {
		t.Fatalf("plaintext = %q, want %q", gotPlain, katPlaintext)
	}
}

// TestKATAADIsLoadBearing proves the additional data actually binds a row to its
// location: the same ciphertext under the same key must not open at a different
// collection, id or generation.
func TestKATAADIsLoadBearing(t *testing.T) {
	wrapKey := unhex(t, katWrapKey)
	box := unhex(t, katWrapped)

	cases := []struct {
		name       string
		collection string
		id         string
		gen        int64
	}{
		{"different collection", "grants", katKATID, katGen},
		{"different id", katKATColl, "device-02", katGen},
		{"different generation", katKATColl, katKATID, katGen + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := open(wrapKey, box, wrapAAD(c.collection, c.id, c.gen)); err == nil {
				t.Fatal("a wrapped key opened under the wrong binding; the AAD is not load-bearing")
			}
		})
	}
}

// TestKATChainHash pins the chain preimage: domain separator, then the sequence,
// a length-prefixed kind, the time, a length-prefixed payload and a
// length-prefixed predecessor hash. If the encoding ever shifts, every existing
// chain becomes unverifiable, so this is a format freeze, not a smoke test.
func TestKATChainHash(t *testing.T) {
	cases := []struct {
		name    string
		seq     int64
		kind    string
		at      int64
		payload []byte
		prev    []byte
		want    string
	}{
		{"mid-chain issuance", 7, KindIssuance, 1757102400123456789, katChainPayload, unhex(t, katChainPrev), katChainHash},
		{"genesis policy record", 1, KindPolicy, 1757102400000000000, []byte("first"), genesisPrevHash(), katGenesisHash},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := recordHash(c.seq, c.kind, c.at, c.payload, c.prev)
			if hex.EncodeToString(got) != c.want {
				t.Errorf("recordHash = %s, want %s", hex.EncodeToString(got), c.want)
			}
		})
	}
}

// TestKATChainHashIsUnambiguous is the reason every field is length-prefixed:
// two different records must never share a preimage just because bytes can be
// shuffled across a field boundary.
func TestKATChainHashIsUnambiguous(t *testing.T) {
	prev := genesisPrevHash()
	a := recordHash(1, "ab", 0, []byte("cd"), prev)
	b := recordHash(1, "a", 0, []byte("bcd"), prev)
	if bytes.Equal(a, b) {
		t.Fatal("two distinct records share a hash preimage; the encoding is ambiguous")
	}
}

// TestKATForeignRowReadsThroughGet inserts a row built entirely by the
// independent implementation and reads it back through the public API. It is
// the end-to-end proof that the store's on-disk envelope is the documented
// format and not merely its own convention.
func TestKATForeignRowReadsThroughGet(t *testing.T) {
	ctx := context.Background()
	d := openTestStoreWith(t, newFakeResolver(unhex(t, katDataKey)))

	// Force generation 1 onto the vector's salt and check value, then insert
	// the foreign row verbatim.
	if _, err := d.sql.ExecContext(ctx,
		`UPDATE data_keys SET salt = ?, kcv = ? WHERE gen = 1`, unhex(t, katSalt), unhex(t, katKCV)); err != nil {
		t.Fatalf("seeding the generation: %v", err)
	}
	if _, err := d.sql.ExecContext(ctx,
		`INSERT INTO records (collection, id, gen, wrapped_key, payload, created_at, updated_at)
		 VALUES (?, ?, 1, ?, ?, 0, 0)`,
		katKATColl, katKATID, unhex(t, katWrapped), unhex(t, katPayload)); err != nil {
		t.Fatalf("inserting the foreign row: %v", err)
	}

	got, err := d.Get(ctx, katKATColl, katKATID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, katPlaintext) {
		t.Fatalf("Get = %q, want %q", got, katPlaintext)
	}
}
