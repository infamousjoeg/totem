package ca

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/infamousjoeg/totem/internal/summon"
)

// The production resolver satisfies what the constructors require. Compile-time,
// because the failure it guards is silent: if *summon.Summoner stopped
// satisfying summon.Resolver, cmd/totem-issuer would break rather than this
// package, and the gate would look fine here while nothing enforced it where it
// matters.
var _ summon.Resolver = (*summon.Summoner)(nil)

const testPass = "a-passphrase-only-summon-knows"

func gateCfg(dir string, rot summon.Rotation, rotErr error) Config {
	return Config{
		Dir:           dir,
		Resolver:      &fakeResolver{pass: testPass, rotation: rot, rotationErr: rotErr},
		PassphraseRef: "ca_passphrase",
		TrustDomain:   testTrustDomain,
		// Injected rather than left to time.Now. Nothing here depends on the
		// wall clock, but a test that reads it can only be reasoned about by
		// arguing that it does not matter, and that argument has to be redone
		// every time the code under it changes.
		Now: newClock(T0).now,
	}
}

// initWith and openWith drive the two constructors through the same gate. Both
// are tested everywhere below, because Init is not the lesser case: it CREATES
// the material sealed under the passphrase, so initialising against a
// pull-rotated reference produces a CA that can never be opened, from a command
// that reported success.
func initWith(t *testing.T, rot summon.Rotation, rotErr error) error {
	t.Helper()
	a, err := Init(context.Background(), InitParams{Config: gateCfg(t.TempDir(), rot, rotErr)})
	if a != nil {
		a.Close()
	}
	return err
}

func openWith(t *testing.T, dir string, rot summon.Rotation, rotErr error) error {
	t.Helper()
	a, err := Open(context.Background(), gateCfg(dir, rot, rotErr))
	if a != nil {
		a.Close()
	}
	return err
}

// initialisedDir returns a real CA directory to reopen.
func initialisedDir(t *testing.T) string {
	t.Helper()
	ca := newTestCA(t)
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	return ca.dir
}

// TestTheSealingGateRefusesBothConstructors is the matrix.
//
// A CA whose private keys on disk are sealed under a pull-rotated value is
// already broken the moment it exists; it just has not noticed. Refusing here
// rather than detecting later means there is no CA in the broken state at all.
func TestTheSealingGateRefusesBothConstructors(t *testing.T) {
	t.Parallel()
	dir := initialisedDir(t)

	cases := []struct {
		name     string
		rot      summon.Rotation
		rotErr   error
		want     error // nil means both constructors must SUCCEED
		contains []string
	}{
		{
			name: "declared Sealing", rot: summon.RotationSealsDataAtRest, want: nil,
		},
		{
			name: "declared pull-rotated", rot: summon.RotationPull, want: summon.ErrNotSealing,
			// The one that means someone will brick this CA, so the message has
			// to name the reference and the fix, not just the fault.
			contains: []string{"ca_passphrase", "summon.Sealing"},
		},
		{
			name: "reference not configured", rotErr: summon.ErrNoSuchReference, want: summon.ErrNoSuchReference,
		},
		{
			name: "no shape at all", rot: summon.RotationUnset, want: ErrRotationShapeUnknown,
			contains: []string{"ca_passphrase"},
		},
		{
			name: "a shape this build has never heard of", rot: summon.Rotation(99), want: ErrRotationShapeUnknown,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, ctor := range []struct {
				what string
				run  func() error
			}{
				{"Init", func() error { return initWith(t, c.rot, c.rotErr) }},
				{"Open", func() error { return openWith(t, dir, c.rot, c.rotErr) }},
			} {
				err := ctor.run()
				if c.want == nil {
					if err != nil {
						t.Fatalf("%s: a passphrase declared Sealing must be accepted: %v", ctor.what, err)
					}
					continue
				}
				if !errors.Is(err, c.want) {
					t.Fatalf("%s: got %v, want %v", ctor.what, err, c.want)
				}
				for _, want := range c.contains {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("%s: the message must contain %q so the operator knows what to change; got %q", ctor.what, want, err)
					}
				}
			}
		})
	}
}

// TestTheTwoRefusalsStayDistinguishable guards the distinction itself.
//
// "Someone declared this reference wrong" and "nobody can tell me what this
// reference is" are different mistakes with different fixes: the first is a
// one-line config change, the second means a resolver was built without going
// through the check that would have caught it. A later edit that collapsed them
// into one error would still pass every test above, because each of those only
// checks its own case. This is the test that notices.
func TestTheTwoRefusalsStayDistinguishable(t *testing.T) {
	t.Parallel()
	dir := initialisedDir(t)

	declaredWrong := openWith(t, dir, summon.RotationPull, nil)
	cannotTell := openWith(t, dir, summon.RotationUnset, nil)
	if declaredWrong == nil || cannotTell == nil {
		t.Fatal("both cases must refuse")
	}
	if declaredWrong.Error() == cannotTell.Error() {
		t.Fatal("the two refusals produced identical messages; the operator cannot tell a misdeclared reference from an unreadable one")
	}
	// And they must not be interchangeable to errors.Is either, or a caller
	// branching on the sentinel would take the wrong branch.
	if errors.Is(declaredWrong, ErrRotationShapeUnknown) {
		t.Fatal("a pull-rotated declaration must not match ErrRotationShapeUnknown")
	}
	if errors.Is(cannotTell, summon.ErrNotSealing) {
		t.Fatal("an undeterminable shape must not match ErrNotSealing")
	}
}

// TestTheGateComparesAgainstTheOneAcceptableShape pins the asymmetry that keeps
// the check correct when summon grows a fourth rotation shape.
//
// Written `rot == RotationPull` the gate admits any new shape by default, and
// that shape would arrive in someone else's package with no reason for them to
// think about this one. Written against RotationSealsDataAtRest it refuses
// everything it does not recognise.
func TestTheGateComparesAgainstTheOneAcceptableShape(t *testing.T) {
	t.Parallel()
	dir := initialisedDir(t)
	for shape := summon.Rotation(0); shape < 12; shape++ {
		openErr := openWith(t, dir, shape, nil)
		initErr := initWith(t, shape, nil)
		if shape == summon.RotationSealsDataAtRest {
			if openErr != nil || initErr != nil {
				t.Fatalf("shape %v must be accepted: open=%v init=%v", shape, openErr, initErr)
			}
			continue
		}
		if openErr == nil || initErr == nil {
			t.Fatalf("shape %v was accepted; only RotationSealsDataAtRest may be: open=%v init=%v", shape, openErr, initErr)
		}
	}
}

// TestTheGateRunsBeforeTheProviderIsEverCalled: the check reads the
// DECLARATION, not a value.
//
// That ordering is what lets it be a startup gate at all. If it needed a
// resolve it could fail for reasons unrelated to the question (a provider that
// is down, hardening that trips), and an operator could not tell "this
// reference is declared wrong" from "the provider is unreachable".
func TestTheGateRunsBeforeTheProviderIsEverCalled(t *testing.T) {
	t.Parallel()
	dir := initialisedDir(t)

	for _, tc := range []struct {
		what string
		run  func(res *fakeResolver) error
	}{
		{"Open", func(res *fakeResolver) error {
			a, err := Open(context.Background(), Config{Dir: dir, Resolver: res, PassphraseRef: "ca_passphrase", TrustDomain: testTrustDomain})
			if a != nil {
				a.Close()
			}
			return err
		}},
		{"Init", func(res *fakeResolver) error {
			a, err := Init(context.Background(), InitParams{Config: Config{Dir: t.TempDir(), Resolver: res, PassphraseRef: "ca_passphrase", TrustDomain: testTrustDomain}})
			if a != nil {
				a.Close()
			}
			return err
		}},
	} {
		res := &fakeResolver{
			pass:     testPass,
			rotation: summon.RotationPull,
			err:      errors.New("the provider must never be reached"),
		}
		if err := tc.run(res); !errors.Is(err, summon.ErrNotSealing) {
			t.Fatalf("%s: got %v, want the rotation-shape refusal", tc.what, err)
		}
		if n := res.callCount(); n != 0 {
			t.Fatalf("%s: the provider was executed %d times; the gate must decide from the declaration alone", tc.what, n)
		}
	}
}
