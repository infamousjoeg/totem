package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/infamousjoeg/totem/internal/summon"
)

func TestRoundTripAndList(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	cases := []struct {
		name       string
		collection string
		id         string
		value      []byte
	}{
		{"enrollment", CollectionEnrollments, "device-01", []byte(`{"protection":"secure-enclave"}`)},
		{"policy record", CollectionPolicy, "presence.aws-prod", []byte(`{"presence":"always"}`)},
		{"grant", CollectionGrants, "grant-7", []byte(`{"scope":"s3:GetObject"}`)},
		{"revocation", CollectionRevocations, "device-02", []byte(`{"at":"2026-09-05T00:00:00Z"}`)},
		{"rotating secret", CollectionSecrets, "github.refresh", []byte("ghr_notarealtoken")},
		{"empty value", CollectionSecrets, "empty", []byte{}},
		{"binary value", CollectionSecrets, "binary", []byte{0x00, 0xff, 0x00, 0xde, 0xad}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustPut(t, d, c.collection, c.id, c.value)
			if got := mustGet(t, d, c.collection, c.id); !bytes.Equal(got, c.value) {
				t.Fatalf("Get = %q, want %q", got, c.value)
			}
		})
	}

	ids, err := d.List(ctx, CollectionSecrets)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"binary", "empty", "github.refresh"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("List = %v, want %v", ids, want)
	}
	// Listing an unused collection is empty, not an error: "no devices are
	// revoked" is a normal answer.
	if ids, err := d.List(ctx, "unused"); err != nil || len(ids) != 0 {
		t.Fatalf("List(unused) = %v, %v; want empty, nil", ids, err)
	}
}

func TestOverwriteUsesAFreshRowKey(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	mustPut(t, d, CollectionSecrets, "github.refresh", []byte("first"))
	var first []byte
	if err := d.sql.QueryRowContext(ctx,
		`SELECT wrapped_key FROM records WHERE collection = ? AND id = ?`,
		CollectionSecrets, "github.refresh").Scan(&first); err != nil {
		t.Fatal(err)
	}

	mustPut(t, d, CollectionSecrets, "github.refresh", []byte("second"))
	var second []byte
	if err := d.sql.QueryRowContext(ctx,
		`SELECT wrapped_key FROM records WHERE collection = ? AND id = ?`,
		CollectionSecrets, "github.refresh").Scan(&second); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("rewriting a rotating secret reused its predecessor's row key")
	}
	if got := mustGet(t, d, CollectionSecrets, "github.refresh"); string(got) != "second" {
		t.Fatalf("Get = %q, want %q", got, "second")
	}
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	_, err := d.Get(ctx, CollectionEnrollments, "never-enrolled")
	wantErrIs(t, err, ErrNotFound, "Get on an absent row")

	// Deleting nothing is reported, not silently successful: "revoke this
	// device" quietly matching nothing is exactly the no-op an operator has to
	// hear about.
	err = d.Delete(ctx, CollectionEnrollments, "never-enrolled")
	wantErrIs(t, err, ErrNotFound, "Delete on an absent row")

	mustPut(t, d, CollectionEnrollments, "device-01", []byte("x"))
	if err := d.Delete(ctx, CollectionEnrollments, "device-01"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = d.Get(ctx, CollectionEnrollments, "device-01")
	wantErrIs(t, err, ErrNotFound, "Get after Delete")
}

func TestNameAndSizeValidation(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	cases := []struct {
		name       string
		collection string
		id         string
		value      []byte
		want       error
	}{
		{"empty collection", "", "id", []byte("v"), ErrBadName},
		{"empty id", CollectionSecrets, "", []byte("v"), ErrBadName},
		{"collection with a path separator", "a/b", "id", []byte("v"), ErrBadName},
		{"id with a path traversal", CollectionSecrets, "..", []byte("v"), ErrBadName},
		{"id with a NUL", CollectionSecrets, "a\x00b", []byte("v"), ErrBadName},
		{"id with a newline", CollectionSecrets, "a\nb", []byte("v"), ErrBadName},
		{"collection too long", strings.Repeat("a", MaxCollectionLen+1), "id", []byte("v"), ErrBadName},
		{"id too long", CollectionSecrets, strings.Repeat("a", MaxIDLen+1), []byte("v"), ErrBadName},
		{"value too large", CollectionSecrets, "big", make([]byte, MaxValueBytes+1), ErrValueTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := d.Put(ctx, c.collection, c.id, c.value)
			wantErrIs(t, err, c.want, "Put")
			// Read paths validate identically, so a name that cannot be written
			// can never be probed for either.
			if !errors.Is(c.want, ErrValueTooLarge) {
				_, gerr := d.Get(ctx, c.collection, c.id)
				wantErrIs(t, gerr, c.want, "Get")
			}
		})
	}

	// The largest accepted value still round-trips, so the bound is a bound and
	// not an off-by-one that rejects legitimate rows.
	big := bytes.Repeat([]byte{0xA5}, MaxValueBytes)
	mustPut(t, d, CollectionSecrets, "at-the-limit", big)
	if got := mustGet(t, d, CollectionSecrets, "at-the-limit"); !bytes.Equal(got, big) {
		t.Fatal("the largest accepted value did not round-trip")
	}
}

func TestOpenRefusesWithoutAProvider(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		resolver summon.Resolver
	}{
		{"no resolver at all", nil},
		{"resolver with no data key reference", unconfiguredResolver{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Open(ctx, t.TempDir()+"/state.db", Options{Resolver: c.resolver})
			wantErrIs(t, err, ErrProviderNotConfigured, "Open")
		})
	}
}

func TestReopenWithTheWrongDataKeyIsRefused(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/state.db"

	r := newFakeResolver(testKey(0x11))
	d, err := Open(ctx, path, Options{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, d, CollectionEnrollments, "device-01", []byte("enrolled"))
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// A provider now handing back a different secret is not a decryption
	// failure to puzzle over; it is one sentence.
	wrong := newFakeResolver(testKey(0x22))
	_, err = Open(ctx, path, Options{Resolver: wrong})
	wantErrIs(t, err, ErrDataKeyMismatch, "Open with the wrong data key")

	// The right key still opens it, so the refusal was about the key and not
	// about damage done on the way past.
	again, err := Open(ctx, path, Options{Resolver: newFakeResolver(testKey(0x11))})
	if err != nil {
		t.Fatalf("reopening with the right key: %v", err)
	}
	defer func() { _ = again.Close() }()
	if got := mustGet(t, again, CollectionEnrollments, "device-01"); string(got) != "enrolled" {
		t.Fatalf("Get = %q", got)
	}
}

func TestSchemaAhead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/state.db"

	r := newFakeResolver(testKey(0x11))
	d, err := Open(ctx, path, Options{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	// Pretend a newer issuer wrote this file.
	if _, err := d.sql.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion+7)); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(ctx, path, Options{Resolver: newFakeResolver(testKey(0x11))})
	wantErrIs(t, err, ErrSchemaAhead, "Open on a newer file")
	if !strings.Contains(err.Error(), fmt.Sprintf("version %d", schemaVersion+7)) {
		t.Errorf("the error should name the version it found: %v", err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	for i := 0; i < 3; i++ {
		if err := d.Migrate(ctx); err != nil {
			t.Fatalf("Migrate #%d: %v", i, err)
		}
	}
	v, err := userVersion(ctx, d.sql)
	if err != nil {
		t.Fatal(err)
	}
	if v != schemaVersion {
		t.Fatalf("user_version = %d, want %d", v, schemaVersion)
	}
}

func TestDataKeyIsResolvedPerUseAndNeverPersisted(t *testing.T) {
	ctx := context.Background()
	d, r := openTestStore(t)

	before := r.resolves()
	mustPut(t, d, CollectionSecrets, "a", []byte("v"))
	mustGet(t, d, CollectionSecrets, "a")
	if r.resolves() <= before+1 {
		t.Fatalf("the data key was resolved %d times across a Put and a Get; the Resolver contract requires per-use resolution",
			r.resolves()-before)
	}

	// List resolves nothing: knowing which devices exist must not require the
	// power to read what they are.
	before = r.resolves()
	if _, err := d.List(ctx, CollectionSecrets); err != nil {
		t.Fatal(err)
	}
	if r.resolves() != before {
		t.Fatal("List resolved the data key")
	}

	// The key itself must appear nowhere in the file.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(readFile(t, d.Path()), testKey(0x11)) {
		t.Fatal("the data key is present in the database file")
	}
}

// readFile reads a whole file for the "this must not appear on disk" checks.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

func TestPlaintextIsNotInTheFile(t *testing.T) {
	d, _ := openTestStore(t)
	secret := []byte("ghr_a_distinctive_refresh_token_value_9f2c")
	mustPut(t, d, CollectionSecrets, "github.refresh", secret)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(readFile(t, d.Path()), secret) {
		t.Fatal("a row's plaintext is readable in the database file")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)

	const workers = 8
	const each = 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				id := fmt.Sprintf("device-%02d-%03d", w, i)
				if err := d.Put(ctx, CollectionEnrollments, id, []byte(id)); err != nil {
					errs <- err
					return
				}
				if got, err := d.Get(ctx, CollectionEnrollments, id); err != nil {
					errs <- err
					return
				} else if string(got) != id {
					errs <- fmt.Errorf("Get(%s) = %q", id, got)
					return
				}
				if _, err := d.Append(ctx, Record{Kind: KindIssuance, Payload: []byte(id)}); err != nil {
					errs <- err
					return
				}
				if _, err := d.List(ctx, CollectionEnrollments); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent use: %v", err)
	}

	ok, bad, err := d.Verify(ctx)
	if err != nil || !ok {
		t.Fatalf("Verify after concurrent appends: ok=%v firstBad=%d err=%v", ok, bad, err)
	}
	ids, err := d.List(ctx, CollectionEnrollments)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != workers*each {
		t.Fatalf("List returned %d ids, want %d", len(ids), workers*each)
	}
}

func TestClosedStoreRefuses(t *testing.T) {
	ctx := context.Background()
	d, _ := openTestStore(t)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close is not idempotent: %v", err)
	}
	if err := d.Put(ctx, CollectionSecrets, "a", []byte("v")); err == nil {
		t.Fatal("Put on a closed store succeeded")
	}
	if _, err := d.Get(ctx, CollectionSecrets, "a"); err == nil {
		t.Fatal("Get on a closed store succeeded")
	}
}
