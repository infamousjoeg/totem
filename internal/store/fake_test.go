package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/summon"
)

// fakeResolver is the test-only Summon provider the spec calls for: "Tests use
// a fake provider that compiles only into the test binary"
// (docs/totem-design.md, "Secrets"). It lives in a _test.go file so there is no
// build tag to get wrong and no way for it to reach a release binary.
type fakeResolver struct {
	mu       sync.Mutex
	key      []byte
	refs     []string
	err      error
	resolve  int
	rotation summon.Rotation
}

func newFakeResolver(key []byte) *fakeResolver {
	return &fakeResolver{
		key:      append([]byte(nil), key...),
		refs:     []string{DataKeyRefName},
		rotation: summon.RotationSealsDataAtRest,
	}
}

func (f *fakeResolver) Resolve(_ context.Context, ref summon.Reference) (summon.Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolve++
	if f.err != nil {
		return nil, f.err
	}
	if string(ref) != DataKeyRefName {
		return nil, summon.ErrNoSuchReference
	}
	// A fresh copy per resolve, because the caller zeroes what it is handed.
	// Returning the stored slice would let the first caller destroy the
	// provider's own secret, which is exactly the bug the real Value contract
	// is shaped to prevent.
	return &fakeValue{b: append([]byte(nil), f.key...)}, nil
}

// RotationOf answers the declaration the store insists on. The fake defaults to
// RotationSealsDataAtRest because that is what a correctly configured issuer
// declares for the data key; setRotation exists so a test can prove the store
// refuses the other answers rather than assuming it would.
func (f *fakeResolver) RotationOf(ref summon.Reference) (summon.Rotation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if string(ref) != DataKeyRefName {
		return summon.RotationUnset, summon.ErrNoSuchReference
	}
	return f.rotation, nil
}

// setRotation changes the declared shape, standing in for a misconfigured
// issuer config.
func (f *fakeResolver) setRotation(r summon.Rotation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotation = r
}

func (f *fakeResolver) Refs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.refs...)
}

// setKey moves the provider to a different key, which is what an operator does
// after `issuer rotate-data-key`.
func (f *fakeResolver) setKey(k []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = append([]byte(nil), k...)
}

func (f *fakeResolver) resolves() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resolve
}

type fakeValue struct{ b []byte }

func (v *fakeValue) Bytes() []byte { return v.b }
func (v *fakeValue) Zero() {
	for i := range v.b {
		v.b[i] = 0
	}
}

// unconfiguredResolver has no reference for the data key, which is what a
// half-finished `issuer init` looks like.
type unconfiguredResolver struct{}

func (unconfiguredResolver) Resolve(context.Context, summon.Reference) (summon.Value, error) {
	return nil, summon.ErrNoSuchReference
}
func (unconfiguredResolver) Refs() []string { return []string{"anthropic_api_key"} }
func (unconfiguredResolver) RotationOf(summon.Reference) (summon.Rotation, error) {
	return summon.RotationUnset, summon.ErrNoSuchReference
}

func testKey(b byte) []byte {
	k := make([]byte, dataKeyLen)
	for i := range k {
		k[i] = b ^ byte(i)
	}
	return k
}

// testClock is the seam that replaces a caller-supplied Record.At. It advances
// one millisecond per reading, so a seeded chain gets distinct, ordered,
// reproducible times without the write path ever accepting a time from its
// caller.
type testClock struct {
	mu   sync.Mutex
	next time.Time
}

func newTestClock() *testClock {
	return &testClock{next: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.next
	c.next = c.next.Add(time.Millisecond)
	return t
}

// openTestStore opens a store in a fresh temp directory.
func openTestStore(t *testing.T) (*DB, *fakeResolver) {
	t.Helper()
	r := newFakeResolver(testKey(0x11))
	return openTestStoreWith(t, r), r
}

func openTestStoreWith(t *testing.T, r summon.Resolver) *DB {
	t.Helper()
	dir := t.TempDir()
	d, err := Open(context.Background(), dir+"/state.db", Options{Resolver: r, Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// openTestStoreWithClock is openTestStoreWith plus a caller-controlled clock,
// for the tests that assert on the time the store stamps.
func openTestStoreWithClock(t *testing.T, r summon.Resolver, clock func() time.Time) *DB {
	t.Helper()
	d, err := Open(context.Background(), t.TempDir()+"/state.db", Options{Resolver: r, Clock: clock})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func mustPut(t *testing.T, d *DB, collection, id string, v []byte) {
	t.Helper()
	if err := d.Put(context.Background(), collection, id, v); err != nil {
		t.Fatalf("Put(%s/%s): %v", collection, id, err)
	}
}

func mustGet(t *testing.T, d *DB, collection, id string) []byte {
	t.Helper()
	got, err := d.Get(context.Background(), collection, id)
	if err != nil {
		t.Fatalf("Get(%s/%s): %v", collection, id, err)
	}
	return got
}

func wantErrIs(t *testing.T, err, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}
