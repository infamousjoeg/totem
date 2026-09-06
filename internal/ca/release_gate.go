//go:build release

package ca

// This file compiles ONLY into a release build (`go build -tags release`) and
// exists to fail that build while the X.509 extension OID arc is still a
// provisional placeholder. Development builds, tests and `go vet` never see it,
// so it blocks a release without blocking work.
//
// The refusal is at COMPILE time rather than in an init function on purpose. An
// init-time panic produces a release binary that ships, gets installed, and
// then crashes on a customer's box; a compile-time refusal produces no binary
// at all. When the thing being guarded is "an identifier that can never be
// changed again once deployed", not linking is the correct failure.
//
// While OIDArcProvisional is non-empty this array has a negative length, which
// the compiler rejects, and the name below is what the operator reads in the
// error. Setting OIDArcProvisional to "" makes the length zero and the gate
// disappears. See OIDArcProvisional for what to do about it.
var releaseBuildsMustNotCarryAProvisionalOIDArc [0 - len(OIDArcProvisional)]struct{}
