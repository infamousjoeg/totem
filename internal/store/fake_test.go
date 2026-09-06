package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/infamousjoeg/totem/internal/summon"
)

// fakeResolver is the test-only Summon provider the spec calls for: "Tests use
// a fake provider that compiles only into the test binary"
// (docs/totem-design.md, "Secrets"). It lives in a _test.go file so there is no
// build tag to get wrong and no way for it to reach a release binary.
type fakeResolver struct {
	mu      sync.Mutex
	key     []byte
	refs    []string
	err     error
	resolve int
}

func newFakeResolver(key []byte) *fakeResolver {
	return &fakeResolver{key: append([]byte(nil), key...), refs: []string{DataKeyRefName}}
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

func testKey(b byte) []byte {
	k := make([]byte, dataKeyLen)
	for i := range k {
		k[i] = b ^ byte(i)
	}
	return k
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
	d, err := Open(context.Background(), dir+"/state.db", Options{Resolver: r})
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
