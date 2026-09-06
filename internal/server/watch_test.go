package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
	"github.com/infamousjoeg/totem/internal/summon"
)

// These tests drive the REAL internal/ca on an injected clock. A fake authority
// would let me assert that the watcher reacts to a SubjectKeyId I made up,
// which is a fact about my fake. What actually needs proving is that the
// watcher notices the promotion the real CA performs on its own, at the moment
// the real schedule performs it, and that only a real thirty-day schedule can
// demonstrate.

// mutableProvider is the sanctioned test provider, with a value that can change
// underneath the CA the way a pull-based rotation changes it.
type mutableProvider struct {
	mu   sync.Mutex
	refs map[summon.Reference][]byte
}

func (p *mutableProvider) Resolve(_ context.Context, ref summon.Reference) (summon.Value, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.refs[ref]
	if !ok {
		return nil, summon.ErrNoSuchReference
	}
	return testValue(append([]byte(nil), v...)), nil
}

// RotationOf: the CA passphrase seals the CA private keys at rest, so it is
// Sealing. That is the declaration the whole exclusion is keyed on.
func (p *mutableProvider) RotationOf(ref summon.Reference) (summon.Rotation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.refs[ref]; !ok {
		return summon.RotationUnset, summon.ErrNoSuchReference
	}
	if ref == testPassphraseRef {
		return summon.Sealing(ref).Rotation, nil
	}
	return summon.Rotating(ref).Rotation, nil
}

func (p *mutableProvider) Refs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.refs))
	for r := range p.refs {
		out = append(out, string(r))
	}
	return out
}

func (p *mutableProvider) set(ref summon.Reference, v []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refs[ref] = v
}

var _ summon.Resolver = (*mutableProvider)(nil)

const testPassphraseRef = summon.Reference("totem/ca-passphrase")

// realCA initialises a real CA on a clock the test controls.
func realCA(t *testing.T) (ca.Authority, *mutableProvider, *time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &now
	p := &mutableProvider{refs: map[summon.Reference][]byte{
		testPassphraseRef: []byte("the original passphrase"),
	}}
	authority, err := ca.Init(context.Background(), ca.InitParams{
		Config: ca.Config{
			Dir:           filepath.Join(t.TempDir(), "ca"),
			Resolver:      p,
			PassphraseRef: testPassphraseRef,
			TrustDomain:   testTrustDomain,
			Now:           func() time.Time { return *clock },
		},
		Subject: "totem test",
	})
	if err != nil {
		t.Fatalf("initialising the real CA: %v", err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	return authority, p, clock
}

// TestWatcherLogsTheStartupObservationThenThePromotion. An automatic change of
// signing key with no log line is a gap in the chain exactly where an auditor
// reconstructing an incident needs continuity.
func TestWatcherLogsTheStartupObservationThenThePromotion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority, _, clock := realCA(t)

	var audit bytes.Buffer
	w, err := NewWatcher(WatcherConfig{CA: authority, Audit: NewAuditLog(&audit, nil), Warn: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}

	// First poll: an observation, not a promotion. Nothing was promoted.
	w.Poll(ctx)
	records := decodeRecords(t, audit.String())
	if len(records) != 1 {
		t.Fatalf("first poll wrote %d records, want 1", len(records))
	}
	if records[0].Kind != EventIntermediateObserved {
		t.Fatalf("first poll logged %q; a fresh process has nothing to compare against, so it must not claim a promotion", records[0].Kind)
	}
	first := records[0].Target
	if first == "" {
		t.Fatal("the startup line does not say which intermediate was signing")
	}

	// A second poll with nothing changed must be silent, or a five-minute
	// ticker fills the chain with noise and hides the line that matters.
	w.Poll(ctx)
	if got := len(decodeRecords(t, audit.String())); got != 1 {
		t.Fatalf("an unchanged poll wrote another record (%d total)", got)
	}

	// Prepare a successor once the publication overlap opens, then let the
	// clock carry it into its signing window, which is how promotion really
	// happens: on the clock, with no call.
	sched, err := authority.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	*clock = sched.RotateAfter.Add(time.Hour)
	if _, err := authority.RotateIntermediate(ctx); err != nil {
		t.Fatalf("preparing a successor: %v", err)
	}
	sched, err = authority.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sched.Next == nil {
		t.Fatal("no successor was published")
	}
	successor := hex.EncodeToString(sched.Next.Certificate.SubjectKeyId)

	// Still published, not yet signing: nothing to log.
	w.Poll(ctx)
	if got := len(decodeRecords(t, audit.String())); got != 1 {
		t.Fatalf("publishing a successor logged a promotion before it started signing (%d records)", got)
	}

	*clock = sched.Next.SigningStart.Add(time.Minute)
	w.Poll(ctx)

	records = decodeRecords(t, audit.String())
	if len(records) != 2 {
		t.Fatalf("the promotion was not logged (%d records)", len(records))
	}
	promo := records[1]
	if promo.Kind != ca.EventIntermediatePromoted {
		t.Errorf("promotion logged as %q, want %q", promo.Kind, ca.EventIntermediatePromoted)
	}
	if promo.Target != successor {
		t.Errorf("promotion names %q as the new signer, want %q", promo.Target, successor)
	}
	if promo.Signer != first {
		t.Errorf("promotion names %q as the outgoing signer, want %q", promo.Signer, first)
	}
	if ok, bad := VerifyChain(records); !ok {
		t.Fatalf("the audit chain broke at seq %d", bad)
	}
}

// TestWatcherWarnsLoudlyAndRepeatedlyWhenThePassphraseChanges. The keys are
// already unsealed in memory, so a rotation costs a running issuer nothing and
// is invisible until the next restart, when the old value is gone.
func TestWatcherWarnsLoudlyAndRepeatedlyWhenThePassphraseChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority, provider, _ := realCA(t)
	op, ok := authority.(ca.PassphraseOperator)
	if !ok {
		t.Skip("this CA implementation seals nothing")
	}

	var audit, warn bytes.Buffer
	w, err := NewWatcher(WatcherConfig{
		CA: authority, Passphrase: op, Audit: NewAuditLog(&audit, nil), Warn: &warn,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.Poll(ctx) // startup: healthy
	if strings.Contains(warn.String(), "WILL NOT RESTART") {
		t.Fatal("a healthy issuer warned about its passphrase")
	}
	baseline := len(decodeRecords(t, audit.String()))

	// The provider's value changes underneath the running issuer, which is
	// exactly what a pull-based rotation does.
	provider.set(testPassphraseRef, []byte("a rotated passphrase"))

	w.Poll(ctx)
	if !strings.Contains(warn.String(), "WILL NOT RESTART") {
		t.Fatalf("the passphrase changed and the operator was not warned:\n%s", warn.String())
	}
	if !strings.Contains(warn.String(), "reseal-ca") {
		t.Error("the warning does not name the command that fixes it")
	}
	afterFirst := len(decodeRecords(t, audit.String()))
	if afterFirst != baseline+1 {
		t.Fatalf("the change wrote %d records, want 1", afterFirst-baseline)
	}

	// Repeated, every tick, for as long as it is true. A single warning at the
	// moment of rotation is not enough: the operator may not look for weeks.
	w.Poll(ctx)
	w.Poll(ctx)
	if got := len(decodeRecords(t, audit.String())) - afterFirst; got != 2 {
		t.Fatalf("the warning stopped repeating (%d further records over two polls)", got)
	}
	if strings.Count(warn.String(), "WILL NOT RESTART") != 3 {
		t.Errorf("the operator-visible warning was not repeated on every tick:\n%s", warn.String())
	}

	// And re-sealing makes it stop, with the recovery recorded rather than the
	// warnings merely ceasing.
	if err := op.Reseal(ctx, []byte("the original passphrase")); err != nil {
		t.Fatalf("re-sealing under the rotated passphrase: %v", err)
	}
	before := len(decodeRecords(t, audit.String()))
	w.Poll(ctx)
	records := decodeRecords(t, audit.String())
	if len(records) != before+1 {
		t.Fatalf("the recovery was not recorded (%d new records)", len(records)-before)
	}
	if records[len(records)-1].Outcome != "resealed" {
		t.Errorf("recovery recorded as %q, want %q", records[len(records)-1].Outcome, "resealed")
	}
	w.Poll(ctx)
	if got := len(decodeRecords(t, audit.String())); got != before+1 {
		t.Fatalf("the warning kept firing after a successful re-seal (%d records)", got)
	}
	if ok, bad := VerifyChain(decodeRecords(t, audit.String())); !ok {
		t.Fatalf("the audit chain broke at seq %d", bad)
	}
}

// TestWatcherNeverStopsTheIssuer. Both conditions are things to REPORT. An
// issuer that refused to serve because it could not read its rotation schedule
// would turn a warning into the outage the warning exists to prevent.
func TestWatcherNeverStopsTheIssuer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority, _, _ := realCA(t)
	var audit, warn bytes.Buffer
	op, _ := authority.(ca.PassphraseOperator)
	w, err := NewWatcher(WatcherConfig{CA: authority, Passphrase: op, Audit: NewAuditLog(&audit, nil), Warn: &warn})
	if err != nil {
		t.Fatal(err)
	}
	w.Poll(ctx)
	// A closed CA is the harshest thing the watcher can meet.
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	w.Poll(ctx) // must not panic and must not block
	w.Poll(ctx)
}

// syncBuffer is a concurrency-safe sink for the one test where the watcher
// writes from its own goroutine while the test reads. AuditLog serialises its
// own writes, so the unsynchronised half is the reader; a plain bytes.Buffer
// here is a race in the test, not in the log.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestWatcherRunPollsImmediately. The startup observation must be in the chain
// before the first request is served, not one interval later.
func TestWatcherRunPollsImmediately(t *testing.T) {
	t.Parallel()
	authority, _, _ := realCA(t)
	var audit syncBuffer
	w, err := NewWatcher(WatcherConfig{
		CA: authority, Audit: NewAuditLog(&audit, nil), Warn: &syncBuffer{}, Interval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()

	deadline := time.After(5 * time.Second)
	for {
		if len(decodeRecords(t, audit.String())) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not poll before its first tick")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// TestWatcherRefusesAnIncompleteConfig.
func TestWatcherRefusesAnIncompleteConfig(t *testing.T) {
	t.Parallel()
	authority, _, _ := realCA(t)
	if _, err := NewWatcher(WatcherConfig{Audit: NewAuditLog(&bytes.Buffer{}, nil)}); err == nil {
		t.Error("a watcher with no CA was accepted")
	}
	if _, err := NewWatcher(WatcherConfig{CA: authority}); err == nil {
		t.Error("a watcher with no audit log was accepted")
	}
}

// TestResealDoesNothingUntilTheResolverReturnsTheNewValue is the evidence
// behind the ordering `totem-issuer reseal-ca` uses, and behind a note to the
// secrets owner and the build lead.
//
// internal/summon deliberately keeps SERVING the old value for a secret that
// seals material at rest: it is excluded from pull-based rotation, so when the
// provider starts returning something new, summon alarms and carries on with the
// value in use until `ResealCompleted` adopts the new one. Both ca.Reseal and
// ca.VerifyPassphrase ask the resolver "what is the passphrase now". While
// summon is still serving the old value, that answer is the old value, so
// VerifyPassphrase SUCCEEDS and Reseal has nothing to do.
//
// The consequence is that re-sealing before adoption is inert. A reseal-ca that
// ran ca.Reseal first and adopted afterwards would report success having changed
// nothing, and then adopt the new value on top of files still sealed under the
// old one, producing exactly the failed restart it exists to prevent. So the
// command adopts first and re-seals second, and this test is why.
func TestResealDoesNothingUntilTheResolverReturnsTheNewValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority, provider, _ := realCA(t)
	op, ok := authority.(ca.PassphraseOperator)
	if !ok {
		t.Skip("this CA implementation seals nothing")
	}
	const original = "the original passphrase"

	// While the resolver still returns the old value, which is precisely what
	// summon does during a drift alarm:
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("the CA should open under the value in use: %v", err)
	}
	// ...a re-seal is a no-op, and says nothing about whether it did anything.
	// Note it succeeds even with a previous value that is flatly wrong, because
	// every file already opens under what the resolver returned.
	if err := op.Reseal(ctx, []byte("a completely wrong previous value")); err != nil {
		t.Fatalf("Reseal before adoption should be inert, not an error: %v", err)
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("the inert re-seal changed something: %v", err)
	}

	// Now the resolver returns the new value, which is what ResealCompleted
	// does on summon's side. Only from here does Reseal mean anything.
	provider.set(testPassphraseRef, []byte("the adopted passphrase"))
	if err := op.VerifyPassphrase(ctx); !errors.Is(err, ca.ErrPassphraseChanged) {
		t.Fatalf("after adoption the CA must report it will not restart; got %v", err)
	}
	if err := op.Reseal(ctx, []byte(original)); err != nil {
		t.Fatalf("re-sealing after adoption: %v", err)
	}
	if err := op.VerifyPassphrase(ctx); err != nil {
		t.Fatalf("after re-sealing, a restart would still fail: %v", err)
	}

	// And the wrong previous value after adoption is a real refusal, unlike the
	// inert case above. This is the difference the command reports to the
	// operator, and getting it backwards is how a success message hides a brick.
	provider.set(testPassphraseRef, []byte("a third passphrase"))
	if err := op.Reseal(ctx, []byte("still not the right one")); err == nil {
		t.Fatal("re-sealing with a wrong previous value after adoption reported success")
	}
}

// declaringProvider answers RotationOf with whatever the test wants, so the
// question "does my Sealing declaration actually do anything" can be asked by
// taking it away. It is the deliberate counterpart to mutableProvider, which
// answers truthfully; a suite that only ever contains the truthful fake proves
// that the truthful fake agrees with itself.
type declaringProvider struct {
	value    []byte
	rotation summon.Rotation
	err      error
}

func (p *declaringProvider) Resolve(context.Context, summon.Reference) (summon.Value, error) {
	return testValue(append([]byte(nil), p.value...)), nil
}
func (p *declaringProvider) Refs() []string { return []string{string(testPassphraseRef)} }
func (p *declaringProvider) RotationOf(summon.Reference) (summon.Rotation, error) {
	return p.rotation, p.err
}

var _ summon.Resolver = (*declaringProvider)(nil)

// TestCARefusesToOpenUnlessThePassphraseIsDeclaredSealing makes this package's
// Sealing declarations load-bearing rather than incidental.
//
// mutableProvider declares testPassphraseRef as Sealing because in these tests
// that reference genuinely does seal the CA private keys on disk. That is the
// truthful answer, but on its own it is unfalsifiable: every test would pass
// identically if internal/ca ignored the declaration entirely. So this asserts
// the other side, that taking the declaration away STOPS the CA existing. That
// is the last soft edge on the passphrase brick closed: not "the config is
// checked" but "there is no running issuer whose CA passphrase can be
// pull-rotated out from under the key files it sealed".
//
// It also documents the honest answer for a harness with no opinion. An
// undeclared reference is ErrNoSuchReference and the CA refuses, and that
// refusal is correct behaviour rather than an obstacle to route around: a fake
// that declared a shape it does not have would be the shape a future non-test
// caller copies.
func TestCARefusesToOpenUnlessThePassphraseIsDeclaredSealing(t *testing.T) {
	t.Parallel()
	sealing := summon.Sealing(testPassphraseRef).Rotation
	rotating := summon.Rotating(testPassphraseRef).Rotation

	for _, tc := range []struct {
		name     string
		rotation summon.Rotation
		err      error
		want     error
	}{
		{
			name:     "declared pull-rotated",
			rotation: rotating,
			want:     summon.ErrNotSealing,
		},
		{
			name:     "no shape at all",
			rotation: summon.RotationUnset,
			want:     ca.ErrRotationShapeUnknown,
		},
		{
			name: "the resolver has no opinion",
			err:  summon.ErrNoSuchReference,
			want: summon.ErrNoSuchReference,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ca.Init(context.Background(), ca.InitParams{
				Config: ca.Config{
					Dir:           filepath.Join(t.TempDir(), "ca"),
					Resolver:      &declaringProvider{value: []byte("p"), rotation: tc.rotation, err: tc.err},
					PassphraseRef: testPassphraseRef,
					TrustDomain:   testTrustDomain,
				},
				Subject: "totem test",
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("ca.Init with a passphrase %s returned %v, want %v; "+
					"a CA that opens here is a CA whose passphrase can be rotated away from the keys it sealed",
					tc.name, err, tc.want)
			}
		})
	}

	// And the truthful declaration this package actually makes still works, so
	// the check above is a refusal of the wrong shape rather than of everything.
	authority, err := ca.Init(context.Background(), ca.InitParams{
		Config: ca.Config{
			Dir:           filepath.Join(t.TempDir(), "ca"),
			Resolver:      &declaringProvider{value: []byte("p"), rotation: sealing},
			PassphraseRef: testPassphraseRef,
			TrustDomain:   testTrustDomain,
		},
		Subject: "totem test",
	})
	if err != nil {
		t.Fatalf("ca.Init with a correctly declared Sealing passphrase: %v", err)
	}
	_ = authority.Close()
}
