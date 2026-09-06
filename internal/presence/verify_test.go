package presence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
)

// fixture is one minted challenge, signed by one key, with the matching
// expectation. Tests mutate copies of the assertion or expectation.
type fixture struct {
	clk *clock
	ver *Verifier
	key *fakeKey
	in  SigningInput
	exp Expectation
}

func newFixture(t *testing.T, bound bool) *fixture {
	t.Helper()
	clk := newClock()
	ver := NewVerifier(DefaultChallengeTTL, clk.Now)
	key := newFakeKey(t)
	ch, err := ver.Mint("mac-studio")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		clk: clk, ver: ver, key: key,
		in:  SigningInput{DeviceID: "mac-studio", Tool: "aws", Target: "prod-admin", Challenge: ch},
		exp: Expectation{PresenceKey: key.PresencePublic(), DeviceID: "mac-studio", Tool: "aws", Target: "prod-admin"},
	}
	if bound {
		rh := HashRequest([]byte("sts:AssumeRole"), []byte("arn:aws:iam::123:role/prod-admin"))
		f.in.RequestHash = rh
		f.exp.Binding = BindingRequired
		f.exp.RequestHash = rh
	}
	return f
}

func (f *fixture) sign(t *testing.T) *Assertion {
	t.Helper()
	a, err := Sign(context.Background(), f.key, f.in)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSignBuildsPromptAndAssertion(t *testing.T) {
	f := newFixture(t, true)
	a := f.sign(t)
	p := f.key.lastPrompt
	if !p.Required || p.Tool != "aws" || p.Target != "prod-admin" || p.DeviceID != "mac-studio" {
		t.Fatalf("prompt did not name tool, target, device with presence required: %+v", p)
	}
	if p.RequestCode == "" || p.RequestCode != RequestCode(f.in.Challenge, f.in.RequestHash) {
		t.Fatalf("bound prompt did not carry the request code: %q", p.RequestCode)
	}
	fw := newFixture(t, false)
	fw.sign(t)
	if fw.key.lastPrompt.RequestCode != "" {
		t.Fatal("window touch carried a request code")
	}
	if a.Version != EncodingVersion || a.DeviceID != "mac-studio" || a.Tool != "aws" || a.Target != "prod-admin" {
		t.Fatalf("assertion fields wrong: %+v", a)
	}
	if !bytes.Equal(a.Challenge, f.in.Challenge) || !bytes.Equal(a.RequestHash, f.in.RequestHash) {
		t.Fatal("assertion did not carry challenge and request hash")
	}
	if len(a.Signature) == 0 {
		t.Fatal("no signature")
	}
}

func TestSignPropagatesPlatformErrors(t *testing.T) {
	for _, want := range []error{platform.ErrPresenceDenied, platform.ErrPresenceUnavailable} {
		f := newFixture(t, false)
		f.key.deny = want
		_, err := Sign(context.Background(), f.key, f.in)
		mustErr(t, err, want)
	}
	f := newFixture(t, false)
	f.in.Challenge = nil
	_, err := Sign(context.Background(), f.key, f.in)
	mustErr(t, err, ErrMalformed)
	if f.key.lastPrompt.Required {
		t.Fatal("a malformed input must never reach the sensor")
	}
	_, err = Sign(context.Background(), nil, f.in)
	if err == nil {
		t.Fatal("nil key accepted")
	}
}

func TestVerifyTable(t *testing.T) {
	otherKey := newFakeKey(t)

	type tc struct {
		name  string
		bound bool
		// prepare mutates the fixture (before signing) and/or returns a
		// replacement assertion (after signing). Either may be nil.
		before func(f *fixture)
		after  func(t *testing.T, f *fixture, a *Assertion) *Assertion
		want   error
	}
	cases := []tc{
		{name: "valid window touch"},
		{name: "valid bound to request", bound: true},
		{
			name: "replayed challenge",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				if _, err := f.ver.Verify(a, f.exp); err != nil {
					t.Fatalf("first presentation must succeed: %v", err)
				}
				return a
			},
			want: ErrChallengeReplayed,
		},
		{
			name: "unminted challenge",
			before: func(f *fixture) {
				f.in.Challenge = bytes.Repeat([]byte{7}, ChallengeSize)
			},
			want: ErrUnknownChallenge,
		},
		{
			name: "challenge minted by a different issuer",
			before: func(f *fixture) {
				other := NewVerifier(0, f.clk.Now)
				ch, _ := other.Mint("mac-studio")
				f.in.Challenge = ch
			},
			want: ErrUnknownChallenge,
		},
		{
			name: "challenge minted for another device",
			before: func(f *fixture) {
				ch, _ := f.ver.Mint("work-mbp")
				f.in.Challenge = ch
			},
			want: ErrUnknownChallenge,
		},
		{
			name: "wrong device: prompt named another device",
			before: func(f *fixture) {
				// Challenge minted for mac-studio, issuer expects mac-studio,
				// but the signed record names work-mbp.
				f.in.DeviceID = "work-mbp"
			},
			want: ErrDeviceMismatch,
		},
		{
			name: "wrong device: exchange for a device the challenge was not minted for",
			before: func(f *fixture) {
				f.in.DeviceID = "work-mbp"
				f.exp.DeviceID = "work-mbp"
			},
			want: ErrUnknownChallenge,
		},
		{
			name:   "wrong tool",
			before: func(f *fixture) { f.exp.Tool = "gh" },
			want:   ErrToolMismatch,
		},
		{
			name:   "wrong target",
			before: func(f *fixture) { f.exp.Target = "dev" },
			want:   ErrTargetMismatch,
		},
		{
			name: "expired challenge",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				f.clk.Advance(DefaultChallengeTTL + time.Second)
				return a
			},
			want: ErrChallengeExpired,
		},
		{
			name: "just inside ttl",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				f.clk.Advance(DefaultChallengeTTL)
				return a
			},
		},
		{
			name:  "request hash mismatch on always target",
			bound: true,
			before: func(f *fixture) {
				f.exp.RequestHash = HashRequest([]byte("sts:AssumeRole"), []byte("arn:aws:iam::123:role/prod-admin-elevated"))
			},
			want: ErrRequestHashMismatch,
		},
		{
			name:   "request hash present when not expected",
			before: func(f *fixture) { f.in.RequestHash = HashRequest([]byte("x")) },
			want:   ErrRequestHashUnexpected,
		},
		{
			name:   "request hash absent when required",
			bound:  true,
			before: func(f *fixture) { f.in.RequestHash = nil },
			want:   ErrRequestHashRequired,
		},
		{
			name:   "issuer expectation inconsistent",
			bound:  true,
			before: func(f *fixture) { f.exp.RequestHash = nil },
			want:   ErrExpectation,
		},
		{
			name: "signature over truncated encoding",
			before: func(f *fixture) {
				f.key.mangle = func(b []byte) []byte { return b[:len(b)-1] }
			},
			want: ErrBadSignature,
		},
		{
			name: "signature over extended encoding",
			before: func(f *fixture) {
				f.key.mangle = func(b []byte) []byte { return append(b, 0) }
			},
			want: ErrBadSignature,
		},
		{
			name: "signature over naive concatenation",
			before: func(f *fixture) {
				f.key.mangle = func([]byte) []byte {
					return []byte(f.in.DeviceID + f.in.Tool + f.in.Target + string(f.in.Challenge))
				}
			},
			want: ErrBadSignature,
		},
		{
			name: "boundary shift: signed (aws,prod-admin), presented (awsp,rod-admin)",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				// Move one byte across the tool/target boundary. The
				// naive concatenation is identical; the canonical bytes
				// are not, so the signature must fail.
				shifted := *a
				shifted.Tool = a.Tool + a.Target[:1]
				shifted.Target = a.Target[1:]
				f.exp.Tool = shifted.Tool
				f.exp.Target = shifted.Target
				return &shifted
			},
			want: ErrBadSignature,
		},
		{
			name: "field altered after signing",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				a.Target = "dev"
				f.exp.Target = "dev"
				return a
			},
			want: ErrBadSignature,
		},
		{
			name:   "wrong presence key (another device)",
			before: func(f *fixture) { f.exp.PresenceKey = otherKey.PresencePublic() },
			want:   ErrBadSignature,
		},
		{
			name: "device key passed instead of presence key",
			before: func(f *fixture) {
				// Model the Apple-silicon split: device key != presence key.
				devKey := newFakeKey(t)
				f.exp.PresenceKey = devKey.Public()
			},
			want: ErrBadSignature,
		},
		{
			name:   "nil presence key: level has no presence capability",
			before: func(f *fixture) { f.exp.PresenceKey = nil },
			want:   ErrNoPresenceKey,
		},
		{
			name: "non-P256 presence key",
			before: func(f *fixture) {
				k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				f.exp.PresenceKey = &k.PublicKey
			},
			want: ErrUnsupportedPresenceKey,
		},
		{
			name: "non-ECDSA presence key",
			before: func(f *fixture) {
				f.exp.PresenceKey = ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
			},
			want: ErrUnsupportedPresenceKey,
		},
		{
			name: "unsupported version",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				a.Version = 2
				return a
			},
			want: ErrUnsupportedVersion,
		},
		{
			name: "malformed: short challenge",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				a.Challenge = a.Challenge[:16]
				return a
			},
			want: ErrMalformed,
		},
		{
			name: "malformed: empty signature",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				a.Signature = nil
				return a
			},
			want: ErrMalformed,
		},
		{
			name: "nil assertion",
			after: func(t *testing.T, f *fixture, a *Assertion) *Assertion {
				return nil
			},
			want: ErrMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.bound)
			if tc.before != nil {
				tc.before(f)
			}
			a := f.sign(t)
			if tc.after != nil {
				a = tc.after(t, f, a)
			}
			v, err := f.ver.Verify(a, f.exp)
			mustErr(t, err, tc.want)
			if tc.want != nil {
				if v != nil {
					t.Fatal("rejection returned a Verified")
				}
				return
			}
			if !v.Valid() {
				t.Fatal("Verified not marked valid")
			}
			if v.DeviceID != f.exp.DeviceID || v.Tool != f.exp.Tool || v.Target != f.exp.Target {
				t.Fatalf("Verified bindings wrong: %+v", v)
			}
			if !bytes.Equal(v.RequestHash, f.in.RequestHash) {
				t.Fatal("Verified request hash wrong")
			}
			if !v.VerifiedAt.Equal(f.clk.Now()) {
				t.Fatal("VerifiedAt is not the issuer clock")
			}
		})
	}
}

// Every rejection in the table must be a distinct error value, so an audit
// line can record which. If two collapse, this fails.
func TestRejectionErrorsAreDistinct(t *testing.T) {
	errs := []error{
		ErrMalformed, ErrUnsupportedVersion, ErrUnknownChallenge, ErrChallengeReplayed,
		ErrChallengeExpired, ErrNoPresenceKey, ErrUnsupportedPresenceKey, ErrDeviceMismatch, ErrToolMismatch,
		ErrTargetMismatch, ErrRequestHashRequired, ErrRequestHashUnexpected,
		ErrRequestHashMismatch, ErrBadSignature, ErrExpectation, ErrPresenceRequired,
		ErrPresenceConsumed, ErrTooManyChallenges,
	}
	for i := range errs {
		for j := range errs {
			if i != j && errors.Is(errs[i], errs[j]) {
				t.Fatalf("%v and %v are not distinct", errs[i], errs[j])
			}
		}
	}
}

// A challenge is spent on first presentation regardless of outcome: an
// attacker cannot use a rejected presentation as an oracle and then retry.
func TestFailedVerifySpendsChallenge(t *testing.T) {
	f := newFixture(t, false)
	a := f.sign(t)
	bad := f.exp
	bad.Tool = "other"
	if _, err := f.ver.Verify(a, bad); !errors.Is(err, ErrToolMismatch) {
		t.Fatalf("setup: %v", err)
	}
	_, err := f.ver.Verify(a, f.exp)
	mustErr(t, err, ErrChallengeReplayed)

	// A challenge presented for a device it was not minted for is spent too.
	g := newFixture(t, false)
	b := g.sign(t)
	other := g.exp
	other.DeviceID = "work-mbp"
	if _, err := g.ver.Verify(b, other); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("setup: %v", err)
	}
	_, err = g.ver.Verify(b, g.exp)
	mustErr(t, err, ErrChallengeReplayed)
}

// A malformed assertion is rejected before the challenge lookup, so it does
// not spend anything: the legitimate agent's retry still works.
func TestMalformedDoesNotSpendChallenge(t *testing.T) {
	f := newFixture(t, false)
	a := f.sign(t)
	broken := *a
	broken.Version = 9
	if _, err := f.ver.Verify(&broken, f.exp); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("setup: %v", err)
	}
	if _, err := f.ver.Verify(a, f.exp); err != nil {
		t.Fatalf("challenge was spent by a malformed presentation: %v", err)
	}
}

func TestHandBuiltVerifiedIsInvalid(t *testing.T) {
	v := &Verified{DeviceID: "d", VerifiedAt: time.Now()}
	if v.Valid() {
		t.Fatal("hand-built Verified must not be valid")
	}
	var nilV *Verified
	if nilV.Valid() {
		t.Fatal("nil Verified must not be valid")
	}
}

func TestMintSweepsExpired(t *testing.T) {
	clk := newClock()
	ver := NewVerifier(time.Minute, clk.Now)
	for range 5 {
		if _, err := ver.Mint("dev"); err != nil {
			t.Fatal(err)
		}
	}
	if got := ver.Outstanding(); got != 5 {
		t.Fatalf("outstanding = %d, want 5", got)
	}
	clk.Advance(2 * time.Minute)
	if _, err := ver.Mint("dev"); err != nil {
		t.Fatal(err)
	}
	if got := ver.Outstanding(); got != 1 {
		t.Fatalf("outstanding after sweep = %d, want 1", got)
	}
	if got := len(ver.minted); got != 1 {
		t.Fatalf("minted map holds %d, want 1", got)
	}
	if ver.perDevice["dev"] != 1 {
		t.Fatalf("per-device count %d, want 1", ver.perDevice["dev"])
	}
}

// Outstanding challenges are capped per device; spending, expiry, and other
// devices each release or ignore the slot as they should. (Reviewer L1.)
func TestMintPerDeviceCap(t *testing.T) {
	clk := newClock()
	ver := NewVerifier(time.Minute, clk.Now)
	key := newFakeKey(t)
	var last []byte
	for i := range MaxOutstandingChallenges {
		ch, err := ver.Mint("dev")
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		last = ch
	}
	_, err := ver.Mint("dev")
	mustErr(t, err, ErrTooManyChallenges)
	if _, err := ver.Mint("other"); err != nil {
		t.Fatalf("cap leaked across devices: %v", err)
	}
	// Spending one (even unsuccessfully) frees a slot.
	a, err := Sign(context.Background(), key, SigningInput{DeviceID: "dev", Tool: "t", Challenge: last})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(a, Expectation{PresenceKey: key.PresencePublic(), DeviceID: "dev", Tool: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Mint("dev"); err != nil {
		t.Fatalf("spent challenge did not free its slot: %v", err)
	}
	// Expiry frees them all.
	clk.Advance(2 * time.Minute)
	if _, err := ver.Mint("dev"); err != nil {
		t.Fatalf("expired challenges did not free their slots: %v", err)
	}
	if ver.perDevice["dev"] != 1 {
		t.Fatalf("per-device count %d, want 1", ver.perDevice["dev"])
	}
}

// The request code is 48 bits, challenge-dependent, and formatted for a
// human to compare. (Reviewer H1, inverted.)
func TestRequestCode(t *testing.T) {
	if RequestCodeLen < 12 {
		t.Fatalf("RequestCodeLen = %d; below 48 bits a same-uid grinder collides inside the challenge TTL", RequestCodeLen)
	}
	rh := HashRequest([]byte("sts:AssumeRole"), []byte("prod-admin"))
	c1 := bytes.Repeat([]byte{1}, ChallengeSize)
	c2 := bytes.Repeat([]byte{2}, ChallengeSize)
	code := RequestCode(c1, rh)
	if len(code) != RequestCodeLen+2 || code[4] != '-' || code[9] != '-' {
		t.Fatalf("format: %q", code)
	}
	for i, r := range code {
		if i == 4 || i == 9 {
			continue
		}
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') {
			t.Fatalf("non-hex in code: %q", code)
		}
	}
	if RequestCode(c1, rh) != code {
		t.Fatal("not deterministic")
	}
	if RequestCode(c2, rh) == code {
		t.Fatal("same request under a different challenge produced the same code: precomputable")
	}
	if RequestCode(c1, HashRequest([]byte("sts:AssumeRole"), []byte("dev"))) == code {
		t.Fatal("different request produced the same code")
	}
	if RequestCode(c1, nil) != "" {
		t.Fatal("window touch carried a code")
	}
	// Domain separation: the code is not a prefix of any other hash.
	if strings.HasPrefix(strings.ToUpper(hex.EncodeToString(rh)), code[:4]) && strings.HasPrefix(strings.ToUpper(hex.EncodeToString(rh))[4:], code[5:9]) {
		t.Fatal("code is a prefix of the request hash")
	}
}

// A Verified is single-use across every consumer. (Reviewer M1, inverted.)
func TestVerifiedSingleUse(t *testing.T) {
	clk := newClock()
	v := verified("dev", clk.Now(), nil)
	if v.Used() {
		t.Fatal("fresh proof reads used")
	}
	if err := v.consume(); err != nil {
		t.Fatal(err)
	}
	if !v.Used() {
		t.Fatal("consumed proof reads unused")
	}
	mustErr(t, v.consume(), ErrPresenceConsumed)
	var nilV *Verified
	mustErr(t, nilV.consume(), ErrPresenceRequired)
	mustErr(t, (&Verified{}).consume(), ErrPresenceRequired)
	if nilV.Used() {
		t.Fatal("nil reads used")
	}
}

// Sign passes the full canonical bytes to the platform key, not the bare
// nonce, so the device/tool/target binding is inside the signature.
func TestSignSignsCanonicalBytes(t *testing.T) {
	f := newFixture(t, true)
	var seen []byte
	f.key.mangle = func(b []byte) []byte { seen = b; return b }
	f.sign(t)
	want, _ := SigningInput{
		Version: EncodingVersion, DeviceID: f.in.DeviceID, Tool: f.in.Tool, Target: f.in.Target,
		Challenge: f.in.Challenge, RequestHash: f.in.RequestHash,
	}.Bytes()
	if !bytes.Equal(seen, want) {
		t.Fatal("key was not handed the canonical signing bytes")
	}
	if bytes.Equal(seen, f.in.Challenge) {
		t.Fatal("key was handed the bare nonce")
	}
}
