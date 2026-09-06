package presence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/infamousjoeg/totem/internal/spiffe"
)

func spki(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func enrollFixture(t *testing.T) (*fakeKey, EnrollmentInput) {
	t.Helper()
	key := newFakeKey(t)
	fp := sha256.Sum256([]byte("issuer-cert"))
	return key, EnrollmentInput{
		Challenge:         bytes.Repeat([]byte{3}, ChallengeSize),
		IssuerFingerprint: fp[:],
		DevicePublicKey:   spki(t, &key.priv.PublicKey),
		PresencePublicKey: spki(t, &key.priv.PublicKey),
		ProtectionLevel:   spiffe.ProtectionHardware,
		Hostname:          "joes-mac-studio",
		OS:                "macOS 26.1",
		FirstContact:      FirstContactFragment,
	}
}

func TestEnrollmentInputLayoutAndDomain(t *testing.T) {
	_, in := enrollFixture(t)
	in.Version = 1
	got, err := in.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	field := func(b []byte) {
		want = binary.BigEndian.AppendUint32(want, uint32(len(b)))
		want = append(want, b...)
	}
	field([]byte("totem/enrollment"))
	want = append(want, 1)
	field(in.Challenge)
	field(in.IssuerFingerprint)
	field(in.DevicePublicKey)
	field(in.PresencePublicKey)
	field([]byte(in.ProtectionLevel))
	field([]byte(in.Hostname))
	field([]byte(in.OS))
	field([]byte(in.FirstContact))
	field(in.BootstrapCodeHash)
	if !bytes.Equal(got, want) {
		t.Fatal("layout mismatch")
	}
	// Domain separation: an enrollment never encodes like an assertion,
	// even with a shared challenge, and its digest never equals a request
	// hash over the same parts.
	a, _ := SigningInput{Version: 1, DeviceID: "d", Tool: "t", Challenge: in.Challenge}.Bytes()
	if bytes.HasPrefix(got, a[:8]) && bytes.Equal(got[:4], a[:4]) && bytes.Equal(got[4:20], a[4:20]) {
		t.Fatal("enrollment shares the assertion context")
	}
	d, _ := in.Digest()
	if bytes.Equal(d, HashRequest(in.Challenge, in.IssuerFingerprint, in.DevicePublicKey)) {
		t.Fatal("enrollment digest collides with a request hash")
	}
	// First contact cannot be relabelled, and absent vs present bootstrap
	// code differ, without changing the bytes.
	relabel := in
	relabel.FirstContact = FirstContactPrompt
	rb, _ := relabel.Bytes()
	if bytes.Equal(rb, got) {
		t.Fatal("first contact relabel produced identical bytes")
	}
	admin := in
	admin.BootstrapCodeHash = BootstrapCodeHash(in.Challenge, "ABCD-1234")
	ab, _ := admin.Bytes()
	if bytes.Equal(ab, got) || len(ab) != len(got)+sha256.Size {
		t.Fatal("bootstrap code presence not bound")
	}
	// The bootstrap hash is salted by the challenge and empty for no code.
	if BootstrapCodeHash(in.Challenge, "") != nil {
		t.Fatal("empty code produced a hash")
	}
	if bytes.Equal(BootstrapCodeHash(in.Challenge, "X"), BootstrapCodeHash(bytes.Repeat([]byte{4}, ChallengeSize), "X")) {
		t.Fatal("bootstrap hash not salted by challenge")
	}
	if bytes.Equal(BootstrapCodeHash(in.Challenge, "X"), HashRequest(in.Challenge, []byte("X"))) {
		t.Fatal("bootstrap hash shares the request domain")
	}
	// Hostname/OS boundary shift changes the bytes.
	shifted := in
	shifted.Hostname, shifted.OS = in.Hostname+in.OS[:1], in.OS[1:]
	sb, _ := shifted.Bytes()
	if bytes.Equal(sb, got) {
		t.Fatal("boundary shift produced identical bytes")
	}
}

func TestFirstContactZeroValueIsWeaker(t *testing.T) {
	for _, f := range []FirstContact{"", FirstContactPrompt, "verified", "Fragment", "fragment "} {
		if f.Verified() {
			t.Fatalf("%q read as fragment-verified", f)
		}
	}
	if !FirstContactFragment.Verified() {
		t.Fatal("fragment not verified")
	}
	var zero FirstContact
	if zero.Verified() {
		t.Fatal("zero value read as verified")
	}
}

func TestEnrollmentValidate(t *testing.T) {
	_, ok := enrollFixture(t)
	cases := []struct {
		name string
		mut  func(*EnrollmentInput)
		want error
	}{
		{"valid", func(*EnrollmentInput) {}, nil},
		{"no presence key is allowed", func(in *EnrollmentInput) { in.PresencePublicKey = nil }, nil},
		{"short challenge", func(in *EnrollmentInput) { in.Challenge = in.Challenge[:31] }, ErrEnrollmentMalformed},
		{"short fingerprint", func(in *EnrollmentInput) { in.IssuerFingerprint = in.IssuerFingerprint[:31] }, ErrEnrollmentMalformed},
		{"no device key", func(in *EnrollmentInput) { in.DevicePublicKey = nil }, ErrEnrollmentMalformed},
		{"no protection level", func(in *EnrollmentInput) { in.ProtectionLevel = "" }, ErrEnrollmentMalformed},
		{"prompt first contact", func(in *EnrollmentInput) { in.FirstContact = FirstContactPrompt }, nil},
		{"empty first contact", func(in *EnrollmentInput) { in.FirstContact = "" }, ErrEnrollmentMalformed},
		{"unknown first contact", func(in *EnrollmentInput) { in.FirstContact = "trust-me" }, ErrEnrollmentMalformed},
		{"bootstrap code hash", func(in *EnrollmentInput) { in.BootstrapCodeHash = BootstrapCodeHash(in.Challenge, "ABCD-1234") }, nil},
		{"short bootstrap code hash", func(in *EnrollmentInput) { in.BootstrapCodeHash = []byte("ABCD-1234") }, ErrEnrollmentMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ok
			tc.mut(&in)
			_, err := in.Bytes()
			mustErr(t, err, tc.want)
		})
	}
}

func TestEnrollmentSignVerify(t *testing.T) {
	key, in := enrollFixture(t)
	sig, err := SignEnrollment(context.Background(), key, in)
	if err != nil {
		t.Fatal(err)
	}
	if key.lastPrompt.Required {
		t.Fatal("enrollment must not raise a presence prompt")
	}
	in.Version = EncodingVersion
	dev, pres, err := VerifyEnrollment(in, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !dev.Equal(&key.priv.PublicKey) || !pres.Equal(&key.priv.PublicKey) {
		t.Fatal("parsed keys do not match")
	}
	// The code is derived from digest and challenge, and formatted like a
	// request code.
	code, err := EnrollmentCode(in)
	if err != nil || len(code) != RequestCodeLen+2 {
		t.Fatalf("code %q %v", code, err)
	}
	other := in
	other.Hostname = "evil"
	if c2, _ := EnrollmentCode(other); c2 == code {
		t.Fatal("code did not change with a changed field")
	}

	otherKey := newFakeKey(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := []struct {
		name string
		mut  func(*EnrollmentInput, *[]byte)
		want error
	}{
		{"wrong version", func(in *EnrollmentInput, _ *[]byte) { in.Version = 2 }, ErrUnsupportedVersion},
		{"empty signature", func(_ *EnrollmentInput, s *[]byte) { *s = nil }, ErrEnrollmentMalformed},
		{"field altered after signing", func(in *EnrollmentInput, _ *[]byte) { in.ProtectionLevel = spiffe.ProtectionSoftware }, ErrEnrollmentBadSignature},
		{"fingerprint altered after signing", func(in *EnrollmentInput, _ *[]byte) { in.IssuerFingerprint = bytes.Repeat([]byte{9}, 32) }, ErrEnrollmentBadSignature},
		{"first contact relabelled after signing", func(in *EnrollmentInput, _ *[]byte) { in.FirstContact = FirstContactPrompt }, ErrEnrollmentBadSignature},
		{"bootstrap code attached after signing", func(in *EnrollmentInput, _ *[]byte) {
			in.BootstrapCodeHash = BootstrapCodeHash(in.Challenge, "STOLEN")
		}, ErrEnrollmentBadSignature},
		{"key swapped to another device's", func(in *EnrollmentInput, _ *[]byte) { in.DevicePublicKey = spki(t, &otherKey.priv.PublicKey) }, ErrEnrollmentBadSignature},
		{"signature from another key", func(_ *EnrollmentInput, s *[]byte) {
			b, _ := in.Bytes()
			sum := sha256.Sum256(b)
			*s, _ = ecdsa.SignASN1(rand.Reader, otherKey.priv, sum[:])
		}, ErrEnrollmentBadSignature},
		{"device key not P-256", func(in *EnrollmentInput, _ *[]byte) { in.DevicePublicKey = spki(t, &p384.PublicKey) }, ErrEnrollmentKeyUnsupported},
		{"device key not DER", func(in *EnrollmentInput, _ *[]byte) { in.DevicePublicKey = []byte("nope") }, ErrEnrollmentKeyUnsupported},
		{"presence key not P-256", func(in *EnrollmentInput, _ *[]byte) { in.PresencePublicKey = spki(t, &p384.PublicKey) }, ErrEnrollmentKeyUnsupported},
		{"malformed", func(in *EnrollmentInput, _ *[]byte) { in.Challenge = nil }, ErrEnrollmentMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mi, ms := in, append([]byte(nil), sig...)
			tc.mut(&mi, &ms)
			_, _, err := VerifyEnrollment(mi, ms)
			mustErr(t, err, tc.want)
		})
	}
	// No presence key: verifies, presence half nil.
	nopres := in
	nopres.PresencePublicKey = nil
	sig2, _ := SignEnrollment(context.Background(), key, nopres)
	_, pres2, err := VerifyEnrollment(nopres, sig2)
	if err != nil || pres2 != nil {
		t.Fatalf("no-presence enrollment: %v %v", err, pres2)
	}
}
