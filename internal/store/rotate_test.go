package store

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func populate(t *testing.T, d *DB, n int) map[string][]byte {
	t.Helper()
	want := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("device-%05d", i)
		v := []byte(fmt.Sprintf(`{"device":%d,"protection":"tpm"}`, i))
		mustPut(t, d, CollectionEnrollments, id, v)
		want[id] = v
	}
	return want
}

func checkAll(t *testing.T, d *DB, want map[string][]byte) {
	t.Helper()
	for id, v := range want {
		got, err := d.Get(context.Background(), CollectionEnrollments, id)
		if err != nil {
			t.Fatalf("Get(%s) after rotation: %v", id, err)
		}
		if !bytes.Equal(got, v) {
			t.Fatalf("Get(%s) = %q, want %q", id, got, v)
		}
	}
}

func TestRotateDataKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/state.db"

	oldKey, newKey := testKey(0x11), testKey(0x77)
	r := newFakeResolver(oldKey)
	d, err := Open(ctx, path, Options{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	want := populate(t, d, 1200) // more than rotatePageSize, so paging is exercised
	seedChain(t, d, 10)

	gen, err := d.DataKeyGeneration(ctx)
	if err != nil || gen != 1 {
		t.Fatalf("generation before rotation = %d, %v", gen, err)
	}

	if err := d.RotateDataKey(ctx, newKey); err != nil {
		t.Fatalf("RotateDataKey: %v", err)
	}
	// The store is rotated first; the provider follows. That order is the one
	// the code enforces, so the test performs it in the same order.
	r.setKey(newKey)

	if gen, err := d.DataKeyGeneration(ctx); err != nil || gen != 2 {
		t.Fatalf("generation after rotation = %d, %v", gen, err)
	}
	checkAll(t, d, want)

	// Every row moved: none is left tagged with the retired generation.
	var stale int
	row(t, d, `SELECT count(*) FROM records WHERE gen <> 2`).Scan(&stale)
	if stale != 0 {
		t.Fatalf("%d rows are still under the retired generation", stale)
	}
	// Exactly one generation is active.
	var active int
	row(t, d, `SELECT count(*) FROM data_keys WHERE state = 'active'`).Scan(&active)
	if active != 1 {
		t.Fatalf("%d active generations", active)
	}
	// The chain is untouched by rotation: it is evidence, not encrypted state.
	if ok, bad, err := d.Verify(ctx); !ok || err != nil {
		t.Fatalf("Verify after rotation: ok=%v bad=%d err=%v", ok, bad, err)
	}

	// Reopening under the old key is refused, which is the property rotation
	// exists to produce.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(ctx, path, Options{Resolver: newFakeResolver(oldKey)})
	wantErrIs(t, err, ErrDataKeyMismatch, "reopening under the retired key")

	again, err := Open(ctx, path, Options{Resolver: newFakeResolver(newKey)})
	if err != nil {
		t.Fatalf("reopening under the new key: %v", err)
	}
	defer func() { _ = again.Close() }()
	checkAll(t, again, want)
}

func TestRotateRefusesTheWrongOrderAndTheSameKey(t *testing.T) {
	ctx := context.Background()
	oldKey, newKey := testKey(0x11), testKey(0x77)

	t.Run("rotating to the key already in use", func(t *testing.T) {
		d, _ := openTestStore(t)
		populate(t, d, 5)
		err := d.RotateDataKey(ctx, testKey(0x11))
		wantErrIs(t, err, ErrSameDataKey, "RotateDataKey")
	})

	t.Run("provider already moved to the new key", func(t *testing.T) {
		r := newFakeResolver(oldKey)
		d := openTestStoreWith(t, r)
		want := populate(t, d, 5)

		// The operator updated the provider first. Rotation needs the OLD key
		// to unwrap what it is about to re-wrap, so this must refuse rather
		// than half-succeed.
		r.setKey(newKey)
		err := d.RotateDataKey(ctx, newKey)
		wantErrIs(t, err, ErrRotationOrder, "RotateDataKey with the provider ahead")

		// Nothing moved.
		if gen, _ := d.DataKeyGeneration(ctx); gen != 1 {
			t.Fatalf("generation = %d after a refused rotation", gen)
		}
		r.setKey(oldKey)
		checkAll(t, d, want)
	})

	t.Run("empty next key", func(t *testing.T) {
		d, _ := openTestStore(t)
		if err := d.RotateDataKey(ctx, nil); err == nil {
			t.Fatal("RotateDataKey accepted an empty key")
		}
	})
}

// TestRotationIsAtomicUnderCancellation cancels a rotation in flight. The
// invariant asserted holds whether the cancellation lands before, during or
// after the re-wrap loop: the file is never left with rows under two
// generations, because there is no committed state between them.
func TestRotationIsAtomicUnderCancellation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/state.db"
	oldKey, newKey := testKey(0x11), testKey(0x77)

	r := newFakeResolver(oldKey)
	d, err := Open(context.Background(), path, Options{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	want := populate(t, d, 4000)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(2 * time.Millisecond)
		cancel()
	}()
	rotErr := d.RotateDataKey(ctx, newKey)

	// Whatever happened, the file is coherent under exactly one key.
	assertSingleGeneration(t, d)
	if rotErr != nil {
		// Rolled back: everything still reads under the old key.
		checkAll(t, d, want)
		if gen, _ := d.DataKeyGeneration(context.Background()); gen != 1 {
			t.Fatalf("a cancelled rotation still moved the generation to %d", gen)
		}
	} else {
		r.setKey(newKey)
		checkAll(t, d, want)
	}
}

// TestRotationSurvivesSIGKILL is the real interruption test: a child process is
// killed outright partway through a rotation, and the parent then proves the
// file is still fully readable under the old key. A rollback the Go runtime
// performs politely on a cancelled context is not evidence that a crash is
// survivable; a SIGKILL against a live SQLite transaction is.
//
// The kill point is calibrated on this machine rather than guessed: the parent
// times a full rotation over a copy of the same data, then kills the child a
// quarter of the way in. Without that, a fast disk turns the test into a
// no-op that passes.
func TestRotationSurvivesSIGKILL(t *testing.T) {
	if path := os.Getenv("TOTEM_ROTATE_CRASH_CHILD"); path != "" {
		rotateCrashChild(path, os.Getenv("TOTEM_ROTATE_CRASH_MARKER"))
		return
	}
	if testing.Short() {
		t.Skip("spawns a child process")
	}

	rows := 8000
	if v := os.Getenv("TOTEM_ROTATE_CRASH_ROWS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("TOTEM_ROTATE_CRASH_ROWS: %v", err)
		}
		rows = n
	}
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/state.db"
	oldKey := testKey(0x11)

	d, err := Open(ctx, path, Options{Resolver: newFakeResolver(oldKey)})
	if err != nil {
		t.Fatal(err)
	}
	want := populate(t, d, rows)
	seedChain(t, d, 50)
	headSeq, headHash, err := d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	rotateFor := calibrateRotation(t, path, oldKey)
	killAfter := rotateFor / 4
	if killAfter < 20*time.Millisecond {
		killAfter = 20 * time.Millisecond
	}
	t.Logf("a full rotation of %d rows takes %v here; killing the child %v after it starts one", rows, rotateFor, killAfter)

	marker := dir + "/child-started"
	cmd := exec.Command(os.Args[0], "-test.run", "TestRotationSurvivesSIGKILL")
	cmd.Env = append(os.Environ(),
		"TOTEM_ROTATE_CRASH_CHILD="+path,
		"TOTEM_ROTATE_CRASH_MARKER="+marker)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, marker, 30*time.Second)
	time.Sleep(killAfter)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("killing the child: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("the child exited on its own; it was never actually killed mid-rotation")
	}

	// The file is reopened from scratch, exactly as a restarted issuer would.
	again, err := Open(ctx, path, Options{Resolver: newFakeResolver(oldKey)})
	if err != nil {
		t.Fatalf("the database does not open under the old key after a killed rotation: %v", err)
	}
	defer func() { _ = again.Close() }()

	assertSingleGeneration(t, again)
	if gen, _ := again.DataKeyGeneration(ctx); gen != 1 {
		t.Fatalf("a killed rotation committed: generation is %d", gen)
	}
	checkAll(t, again, want)
	if ok, bad, err := again.Verify(ctx); !ok || err != nil {
		t.Fatalf("the chain did not survive: ok=%v bad=%d err=%v", ok, bad, err)
	}
	seq, hash, err := again.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if seq != headSeq || !bytes.Equal(hash, headHash) {
		t.Fatalf("the chain head moved across the crash: %d/%x, want %d/%x", seq, hash, headSeq, headHash)
	}
}

// calibrateRotation times a full rotation over a copy of the database, so the
// kill point is derived from this machine rather than assumed.
func calibrateRotation(t *testing.T, path string, key []byte) time.Duration {
	t.Helper()
	copyPath := t.TempDir() + "/calibration.db"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, src, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(context.Background(), copyPath, Options{Resolver: newFakeResolver(key)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	if err := c.RotateDataKey(context.Background(), testKey(0x77)); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

func waitForFile(t *testing.T, path string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the child never reached %s", path)
}

// rotateCrashChild rotates and waits to be killed. It never returns normally.
func rotateCrashChild(path, marker string) {
	d, err := Open(context.Background(), path, Options{Resolver: newFakeResolver(testKey(0x11))})
	if err != nil {
		fmt.Fprintln(os.Stderr, "child open:", err)
		os.Exit(2)
	}
	if err := os.WriteFile(marker, []byte("go"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "child marker:", err)
		os.Exit(2)
	}
	_ = d.RotateDataKey(context.Background(), testKey(0x77))
	// If the rotation finished before the kill landed, hang: the parent's
	// cmd.Wait() then reports a killed process and the assertions below it run
	// against a committed rotation, which fails loudly instead of passing
	// vacuously.
	select {}
}

func assertSingleGeneration(t *testing.T, d *DB) {
	t.Helper()
	var generations int
	row(t, d, `SELECT count(DISTINCT gen) FROM records`).Scan(&generations)
	if generations > 1 {
		t.Fatalf("rows are split across %d data key generations", generations)
	}
	var active, mismatched int
	row(t, d, `SELECT count(*) FROM data_keys WHERE state = 'active'`).Scan(&active)
	if active != 1 {
		t.Fatalf("%d active generations", active)
	}
	row(t, d, `SELECT count(*) FROM records WHERE gen <> (SELECT gen FROM data_keys WHERE state = 'active')`).Scan(&mismatched)
	if mismatched != 0 {
		t.Fatalf("%d rows are not under the active generation", mismatched)
	}
}

// TestMixedGenerationsAreRefusedAtOpen proves the detection exists even though
// an atomic rotation should make the state unreachable. The point of the check
// is that a database half-readable under two keys is refused loudly rather than
// served with some rows missing.
func TestMixedGenerationsAreRefusedAtOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/state.db"

	d, err := Open(ctx, path, Options{Resolver: newFakeResolver(testKey(0x11))})
	if err != nil {
		t.Fatal(err)
	}
	populate(t, d, 4)
	// Forge the state an interrupted non-atomic rotation would have left.
	execSQL(t, d, `INSERT INTO data_keys (gen, salt, kcv, state, created_at) VALUES (2, ?, ?, 'retired', 0)`,
		make([]byte, saltLen), make([]byte, kcvLen))
	execSQL(t, d, `UPDATE records SET gen = 2 WHERE id = 'device-00001'`)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(ctx, path, Options{Resolver: newFakeResolver(testKey(0x11))})
	if err == nil {
		t.Fatal("a half-rotated database opened")
	}
	if !contains(err.Error(), "restored from backup") {
		t.Errorf("the refusal should tell the operator what to do: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && bytes.Contains([]byte(s), []byte(sub))
}
