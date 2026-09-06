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
	"time"

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

// enrollAttempt is one full enrollment from the device side: a minted
// challenge, the input, the device-half signature, and the presence-half
// assertion over the digest.
type enrollAttempt struct {
	key *fakeKey
	in  EnrollmentInput
	sig []byte
	a   *Assertion
}

func makeEnroll(t *testing.T, ver *Verifier, key *fakeKey, presence bool) enrollAttempt {
	t.Helper()
	_, in := enrollFixture(t)
	in.DevicePublicKey = spki(t, &key.priv.PublicKey)
	in.PresencePublicKey = nil
	if presence {
		in.PresencePublicKey = spki(t, &key.priv.PublicKey)
	}
	ch, err := ver.Mint(PreEnrollmentDeviceID(in.DevicePublicKey))
	if err != nil {
		t.Fatal(err)
	}
	in.Challenge = ch
	sig, err := SignEnrollment(context.Background(), key, in)
	if err != nil {
		t.Fatal(err)
	}
	in.Version = EncodingVersion
	att := enrollAttempt{key: key, in: in, sig: sig}
	if presence {
		d, _ := in.Digest()
		att.a, err = Sign(context.Background(), key, SigningInput{
			DeviceID: PreEnrollmentDeviceID(in.DevicePublicKey), Tool: EnrollmentTool, Target: "issuer.example",
			Challenge: ch, RequestHash: d,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return att
}

func TestEnrollOneChallengeBothSignatures(t *testing.T) {
	clk := newClock()
	ver := NewVerifier(0, clk.Now)
	key := newFakeKey(t)
	att := makeEnroll(t, ver, key, true)

	got, err := ver.Enroll(att.in, att.sig, att.a, "issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StatePresent || got.Presence == nil || !got.Presence.Used() || got.PresenceKey == nil {
		t.Fatalf("enrolled: %+v", got)
	}
	if got.DeviceID != PreEnrollmentDeviceID(att.in.DevicePublicKey) || !got.DeviceKey.Equal(&key.priv.PublicKey) {
		t.Fatal("device identity wrong")
	}
	// One spend covered both signatures: presenting either again is a
	// replay, not a fresh use.
	_, err = ver.Enroll(att.in, att.sig, att.a, "issuer.example")
	mustErr(t, err, ErrChallengeReplayed)
	_, err = ver.Verify(att.a, Expectation{PresenceKey: got.PresenceKey, DeviceID: got.DeviceID, Tool: EnrollmentTool, Target: "issuer.example", Binding: BindingRequired, RequestHash: att.a.RequestHash})
	mustErr(t, err, ErrChallengeReplayed)
	if ver.Outstanding() != 0 {
		t.Fatal("challenge still outstanding")
	}
}

func TestEnrollNoneLevelDevice(t *testing.T) {
	clk := newClock()
	ver := NewVerifier(0, clk.Now)
	att := makeEnroll(t, ver, newFakeKey(t), false)
	got, err := ver.Enroll(att.in, att.sig, nil, "issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateNone || got.Presence != nil || got.PresenceKey != nil {
		t.Fatalf("none-level enrolled: %+v", got)
	}
	// The single spend still happened: the device-half signature cannot be
	// replayed to enroll twice.
	_, err = ver.Enroll(att.in, att.sig, nil, "issuer.example")
	mustErr(t, err, ErrChallengeReplayed)
}

func TestEnrollRejections(t *testing.T) {
	clk := newClock()
	other := newFakeKey(t)
	cases := []struct {
		name     string
		presence bool
		mut      func(t *testing.T, ver *Verifier, att *enrollAttempt)
		issuer   string
		want     error
	}{
		{"presence key without assertion", true, func(_ *testing.T, _ *Verifier, att *enrollAttempt) { att.a = nil }, "issuer.example", ErrEnrollmentNeedsPresence},
		{"assertion without presence key", false, func(t *testing.T, ver *Verifier, att *enrollAttempt) {
			d, _ := att.in.Digest()
			att.a, _ = Sign(context.Background(), att.key, SigningInput{DeviceID: PreEnrollmentDeviceID(att.in.DevicePublicKey), Tool: EnrollmentTool, Target: "issuer.example", Challenge: att.in.Challenge, RequestHash: d})
		}, "issuer.example", ErrEnrollmentUnexpectedPresence},
		{"assertion over a second challenge", true, func(t *testing.T, ver *Verifier, att *enrollAttempt) {
			ch2, _ := ver.Mint(PreEnrollmentDeviceID(att.in.DevicePublicKey))
			d, _ := att.in.Digest()
			att.a, _ = Sign(context.Background(), att.key, SigningInput{DeviceID: PreEnrollmentDeviceID(att.in.DevicePublicKey), Tool: EnrollmentTool, Target: "issuer.example", Challenge: ch2, RequestHash: d})
		}, "issuer.example", ErrEnrollmentChallengeSplit},
		{"device signature from another key", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) {
			att.sig, _ = SignEnrollment(context.Background(), other, att.in)
		}, "issuer.example", ErrEnrollmentBadSignature},
		{"presence assertion from another key", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) {
			att.a, _ = Sign(context.Background(), other, att.a.signingInput())
		}, "issuer.example", ErrBadSignature},
		{"assertion names another target", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) {}, "evil.example", ErrTargetMismatch},
		{"assertion bound to another digest", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) {
			in := att.a.signingInput()
			in.RequestHash = HashRequest([]byte("other"))
			att.a, _ = Sign(context.Background(), att.key, in)
		}, "issuer.example", ErrRequestHashMismatch},
		{"unbound assertion", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) {
			in := att.a.signingInput()
			in.RequestHash = nil
			att.a, _ = Sign(context.Background(), att.key, in)
		}, "issuer.example", ErrRequestHashRequired},
		{"unminted challenge", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) {
			att.in.Challenge = bytes.Repeat([]byte{8}, ChallengeSize)
			att.sig, _ = SignEnrollment(context.Background(), att.key, att.in)
			in := att.a.signingInput()
			in.Challenge = att.in.Challenge
			d, _ := att.in.Digest()
			in.RequestHash = d
			att.a, _ = Sign(context.Background(), att.key, in)
		}, "issuer.example", ErrUnknownChallenge},
		{"challenge minted for another device", true, func(t *testing.T, ver *Verifier, att *enrollAttempt) {
			ch, _ := ver.Mint("someone-else")
			att.in.Challenge = ch
			att.sig, _ = SignEnrollment(context.Background(), att.key, att.in)
			in := att.a.signingInput()
			in.Challenge = ch
			d, _ := att.in.Digest()
			in.RequestHash = d
			att.a, _ = Sign(context.Background(), att.key, in)
		}, "issuer.example", ErrUnknownChallenge},
		{"expired", true, func(t *testing.T, ver *Verifier, att *enrollAttempt) { clk.Advance(DefaultChallengeTTL + time.Second) }, "issuer.example", ErrChallengeExpired},
		{"wrong version", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) { att.in.Version = 7 }, "issuer.example", ErrUnsupportedVersion},
		{"empty device signature", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) { att.sig = nil }, "issuer.example", ErrEnrollmentMalformed},
		{"malformed input", true, func(t *testing.T, _ *Verifier, att *enrollAttempt) { att.in.FirstContact = "" }, "issuer.example", ErrEnrollmentMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk.Set(newClock().Now())
			ver := NewVerifier(0, clk.Now)
			att := makeEnroll(t, ver, newFakeKey(t), tc.presence)
			tc.mut(t, ver, &att)
			_, err := ver.Enroll(att.in, att.sig, att.a, tc.issuer)
			mustErr(t, err, tc.want)
		})
	}
}

// The pairing attack a second challenge would invite: device signature from
// one attempt, presence assertion from another. Refused at the challenge
// check before anything is spent, and even the digest alone would refuse it.
func TestEnrollCannotPairAttempts(t *testing.T) {
	clk := newClock()
	ver := NewVerifier(0, clk.Now)
	key := newFakeKey(t)
	first := makeEnroll(t, ver, key, true)
	second := makeEnroll(t, ver, key, true)
	_, err := ver.Enroll(first.in, first.sig, second.a, "issuer.example")
	mustErr(t, err, ErrEnrollmentChallengeSplit)
	if ver.Outstanding() != 2 {
		t.Fatal("a refused pairing spent a challenge")
	}
	// Both attempts remain individually valid.
	if _, err := ver.Enroll(second.in, second.sig, second.a, "issuer.example"); err != nil {
		t.Fatal(err)
	}
}

func TestPreEnrollmentDeviceID(t *testing.T) {
	k := newFakeKey(t)
	id := PreEnrollmentDeviceID(spki(t, &k.priv.PublicKey))
	if len(id) != 64 || id != PreEnrollmentDeviceID(spki(t, &k.priv.PublicKey)) {
		t.Fatalf("id %q", id)
	}
	if id == PreEnrollmentDeviceID(spki(t, &newFakeKey(t).priv.PublicKey)) {
		t.Fatal("two keys share an id")
	}
}
