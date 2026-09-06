package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
)

// Two things about a running issuer change with no method call behind them, so
// nothing records them unless something goes looking. This is that something.
//
//  1. INTERMEDIATE PROMOTION HAPPENS ON THE CLOCK. internal/ca advances its own
//     schedule whenever it is asked anything, so a published successor becomes
//     the signing intermediate with no operator action and no call to report.
//     ca.EventIntermediatePromoted exists for exactly this and says why: "Logged
//     because it happens on the clock with no operator action, and an unlogged
//     automatic change of signing key is a gap in the chain." It is a gap in
//     precisely the place an auditor reconstructing an incident needs
//     continuity, because "which key signed this certificate" is the question
//     that stops being answerable.
//
//  2. THE CA PASSPHRASE CAN STOP OPENING THE CA. It is resolved through Summon,
//     and Summon's rotation is pull-based. The keys are already unsealed in
//     memory, so a rotation costs a running issuer nothing and is invisible
//     until the next restart, when the old value is gone and the CA will not
//     open. ca.PassphraseOperator's contract states the requirement on this
//     side of the line: "The issuer is expected to call this on a timer and, on
//     failure, to log loudly and repeatedly that it will NOT restart
//     successfully until `issuer reseal-ca` has been run. A single warning at
//     the moment of rotation is not enough, because the operator who needs to
//     see it may not be looking for weeks."
//
// Both are edge cases that only bite later, which is the argument for watching
// them rather than trusting that the moment will be noticed.

// EventIntermediateObserved records which intermediate was signing when the
// issuer started, or that none was.
//
// It is a SEPARATE kind from ca.EventIntermediatePromoted, deliberately. The
// first poll of a fresh process has nothing to compare against, so calling that
// first observation a promotion would put a promotion in the chain that never
// happened. Suppressing it entirely is worse in the other direction: a
// promotion that occurs while the issuer is down would then never appear
// anywhere, and the chain would show one intermediate signing before a restart
// and a different one after it with nothing in between. So the startup line
// says what it actually is, and an auditor gets the continuity anchor without
// being told a promotion took place.
const EventIntermediateObserved = "ca.intermediate_observed"

// EventPassphraseChanged is the loud, repeated warning that this issuer will
// not restart. It is its own kind because it is not a refusal of anything a
// caller asked for: nothing is failing yet, and that is the point.
const EventPassphraseChanged = "ca.passphrase_changed"

// DefaultWatchInterval is how often the watcher looks.
//
// Five minutes is chosen against the passphrase check rather than the promotion
// one. Promotion boundaries are thirty days apart, so anything under a day
// would do. A passphrase rotation, by contrast, is silent and its warning is
// the only signal an operator gets before a restart that fails, so the delay
// between the rotation and the first warning should be minutes. The cost is a
// key-derivation per sealed file per tick, which for a handful of files every
// five minutes is nothing.
const DefaultWatchInterval = 5 * time.Minute

// WatcherConfig wires the watcher.
type WatcherConfig struct {
	// CA is polled for the rotation schedule.
	CA ca.Authority
	// Passphrase is checked on the same tick. Nil disables that half, which is
	// the right behaviour for a CA implementation that seals nothing rather
	// than a reason to refuse to start.
	Passphrase ca.PassphraseOperator
	// Audit is where both findings are recorded.
	Audit *AuditLog
	// Warn is where the loud, repeated human warning goes. It is separate from
	// Audit because the audit stream is machine-read and hash-chained, and the
	// operator who needs to see this one is reading stderr. Nil discards it,
	// which no production path should do.
	Warn io.Writer
	// Interval between polls. Zero means DefaultWatchInterval.
	Interval time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Watcher records the two changes that happen without being asked for.
type Watcher struct {
	cfg WatcherConfig

	// seen is the SubjectKeyId of the intermediate observed on the last poll.
	// Empty means nothing has been observed yet.
	seen []byte
	// started is whether the first observation has been recorded.
	started bool
	// warned is whether the passphrase warning is currently active, so the
	// recovery is logged once rather than silently.
	warned bool
}

// NewWatcher builds the watcher.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	if cfg.CA == nil {
		return nil, fmt.Errorf("%w: the watcher needs a certificate authority", ErrConfig)
	}
	if cfg.Audit == nil {
		return nil, fmt.Errorf("%w: the watcher needs an audit log", ErrConfig)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultWatchInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Watcher{cfg: cfg}, nil
}

// Run polls until ctx is cancelled. It polls once immediately, so the startup
// observation is in the chain before the first request is served rather than
// one interval later.
func (w *Watcher) Run(ctx context.Context) {
	w.Poll(ctx)
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Poll(ctx)
		}
	}
}

// Poll performs one round. It is exported so a test drives it deterministically
// rather than sleeping, and so `issuer status` can force one.
//
// It never returns an error and never stops the issuer. Both of the things it
// watches are conditions to REPORT: an issuer that refused to serve because it
// could not read its own rotation schedule would turn a warning into the outage
// the warning exists to prevent.
func (w *Watcher) Poll(ctx context.Context) {
	w.pollSchedule(ctx)
	w.pollPassphrase(ctx)
}

// pollSchedule emits a promotion event when the signing intermediate changes.
func (w *Watcher) pollSchedule(ctx context.Context) {
	sched, err := w.cfg.CA.Schedule(ctx)
	if err != nil {
		w.warnf("totem-issuer: could not read the certificate rotation schedule: %v\n", err)
		return
	}

	var current []byte
	if sched.Current != nil {
		current = sched.Current.Certificate.SubjectKeyId
	}

	if !w.started {
		w.started = true
		w.seen = current
		outcome := "signing"
		if current == nil {
			outcome = "none"
			w.warnf("totem-issuer: no intermediate certificate is in its signing window, so this issuer cannot sign anything. Run 'totem-issuer rotate-intermediate' with the root key present.\n")
		}
		w.log(Event{
			Kind:    EventIntermediateObserved,
			Target:  hex.EncodeToString(current),
			Outcome: outcome,
		})
		return
	}

	if bytesEqual(w.seen, current) {
		return
	}
	previous := w.seen
	w.seen = current
	if current == nil {
		// The signing window closed with no successor prepared. This is the
		// fail-closed state ca.ErrNoSigningIntermediate names, and it is a
		// change of signing key in the sense that matters to an auditor: from
		// one key to none.
		w.warnf("totem-issuer: the signing certificate expired and no successor was prepared, so this issuer can no longer sign. Run 'totem-issuer rotate-intermediate' with the root key present.\n")
		w.log(Event{
			Kind:    EventIntermediateObserved,
			Target:  hex.EncodeToString(previous),
			Outcome: "none",
		})
		return
	}
	w.log(Event{
		Kind:    ca.EventIntermediatePromoted,
		Target:  hex.EncodeToString(current),
		Signer:  hex.EncodeToString(previous),
		Outcome: "promoted",
	})
}

// pollPassphrase checks that the CA still opens, and says so loudly and on
// every tick while it does not.
func (w *Watcher) pollPassphrase(ctx context.Context) {
	if w.cfg.Passphrase == nil {
		return
	}
	err := w.cfg.Passphrase.VerifyPassphrase(ctx)
	switch {
	case err == nil:
		if w.warned {
			w.warned = false
			w.log(Event{Kind: EventPassphraseChanged, Outcome: "resealed"})
			w.warnf("totem-issuer: the CA material opens under the current passphrase again. This issuer will restart.\n")
		}
		return
	case errors.Is(err, ca.ErrClosed):
		return
	}

	// Repeated on purpose, every tick, for as long as it is true. The operator
	// who needs to see this may not look for weeks, and the consequence is not
	// visible until a restart that then fails.
	w.warned = true
	w.log(Event{Kind: EventPassphraseChanged, Outcome: "will-not-restart", Reason: "passphrase_changed"})
	w.warnf("totem-issuer: THIS ISSUER WILL NOT RESTART. The CA passphrase the secrets provider returns "+
		"no longer opens the sealed CA material (%v).\n"+
		"  Run 'totem-issuer reseal-ca' with the previous passphrase, before it is gone.\n", err)
}

func (w *Watcher) log(e Event) { _, _ = w.cfg.Audit.Log(e) }

func (w *Watcher) warnf(format string, args ...any) {
	if w.cfg.Warn == nil {
		return
	}
	_, _ = fmt.Fprintf(w.cfg.Warn, format, args...)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
