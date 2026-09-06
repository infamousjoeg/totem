package presence

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestSigningInputBytesLayout(t *testing.T) {
	ch := bytes.Repeat([]byte{0xAA}, ChallengeSize)
	rh := bytes.Repeat([]byte{0xBB}, RequestHashSize)
	in := SigningInput{Version: 1, DeviceID: "dev", Tool: "aws", Target: "prod", Challenge: ch, RequestHash: rh}
	got, err := in.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	field := func(b []byte) {
		want = binary.BigEndian.AppendUint32(want, uint32(len(b)))
		want = append(want, b...)
	}
	field([]byte("totem/presence-assertion"))
	want = append(want, 1)
	field([]byte("dev"))
	field([]byte("aws"))
	field([]byte("prod"))
	field(ch)
	field(rh)
	if !bytes.Equal(got, want) {
		t.Fatalf("layout mismatch\n got %x\nwant %x", got, want)
	}
}

// The canonicalization property: shifting a boundary between fields must
// change the bytes. A naive concatenation would not.
func TestSigningInputBoundaryShift(t *testing.T) {
	ch := bytes.Repeat([]byte{1}, ChallengeSize)
	cases := []struct {
		name string
		a, b SigningInput
	}{
		{"device/tool", SigningInput{DeviceID: "ab", Tool: "c", Challenge: ch}, SigningInput{DeviceID: "a", Tool: "bc", Challenge: ch}},
		{"tool/target", SigningInput{DeviceID: "d", Tool: "awsprod", Target: "", Challenge: ch}, SigningInput{DeviceID: "d", Tool: "aws", Target: "prod", Challenge: ch}},
		// No target/challenge or challenge/request-hash case: those two
		// fields are fixed-length (validated), so a shift across them is
		// structurally impossible, not merely detected.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.a.Version, tc.b.Version = 1, 1
			a, err := tc.a.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			b, err := tc.b.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(a, b) {
				t.Fatalf("boundary shift produced identical bytes: %x", a)
			}
			// And the naive concatenation really would collide, which is
			// the attack the length prefix closes.
			na := tc.a.DeviceID + tc.a.Tool + tc.a.Target + string(tc.a.Challenge)
			nb := tc.b.DeviceID + tc.b.Tool + tc.b.Target + string(tc.b.Challenge)
			if na != nb {
				t.Fatalf("test case is not a real boundary shift: %q vs %q", na, nb)
			}
		})
	}
}

func TestSigningInputValidate(t *testing.T) {
	ch := make([]byte, ChallengeSize)
	ok := SigningInput{Version: 1, DeviceID: "d", Tool: "t", Challenge: ch}
	cases := []struct {
		name string
		mut  func(*SigningInput)
		want error
	}{
		{"valid", func(*SigningInput) {}, nil},
		{"absent request hash", func(in *SigningInput) { in.RequestHash = nil }, nil},
		{"present request hash", func(in *SigningInput) { in.RequestHash = make([]byte, RequestHashSize) }, nil},
		{"empty device", func(in *SigningInput) { in.DeviceID = "" }, ErrMalformed},
		{"empty tool", func(in *SigningInput) { in.Tool = "" }, ErrMalformed},
		{"over-long device", func(in *SigningInput) { in.DeviceID = strings.Repeat("x", maxFieldLen+1) }, ErrMalformed},
		{"over-long target", func(in *SigningInput) { in.Target = strings.Repeat("x", maxFieldLen+1) }, ErrMalformed},
		{"short challenge", func(in *SigningInput) { in.Challenge = ch[:31] }, ErrMalformed},
		{"long challenge", func(in *SigningInput) { in.Challenge = append(ch, 0) }, ErrMalformed},
		{"short request hash", func(in *SigningInput) { in.RequestHash = make([]byte, 31) }, ErrMalformed},
		{"long request hash", func(in *SigningInput) { in.RequestHash = make([]byte, 33) }, ErrMalformed},
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

func TestHashRequestBoundaryAndDomain(t *testing.T) {
	if bytes.Equal(HashRequest([]byte("ab"), []byte("c")), HashRequest([]byte("a"), []byte("bc"))) {
		t.Fatal("HashRequest is not boundary-safe")
	}
	if bytes.Equal(HashRequest([]byte("x")), BatchHash([]string{"x"})) {
		t.Fatal("request and batch hashes share a domain")
	}
	if bytes.Equal(HashRequest([]byte("x")), WidenHash("x", "")) {
		t.Fatal("request and widen hashes share a domain")
	}
	if !bytes.Equal(HashRequest([]byte("a"), []byte("b")), HashRequest([]byte("a"), []byte("b"))) {
		t.Fatal("HashRequest is not deterministic")
	}
	if len(HashRequest()) != RequestHashSize {
		t.Fatal("wrong hash size")
	}
}

func TestBatchHashOrderAndDuplicates(t *testing.T) {
	a := BatchHash([]string{"b", "a", "a"})
	b := BatchHash([]string{"a", "b"})
	if !bytes.Equal(a, b) {
		t.Fatal("BatchHash must be order- and duplicate-insensitive")
	}
	if bytes.Equal(BatchHash([]string{"a", "b"}), BatchHash([]string{"ab"})) {
		t.Fatal("BatchHash is not boundary-safe")
	}
}
