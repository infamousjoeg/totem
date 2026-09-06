package issuer

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/presence"
)

// TestPresenceWindowSatisfiedWithinDurationThenExpires drives the real
// presence.Verifier and presence.SessionStore through the full lifecycle of
// one window: unsatisfied before any touch, satisfied immediately after a
// real presence-verified touch, still satisfied partway through the window,
// and unsatisfied once the window has elapsed. "The window itself is
// evaluated on the issuer, not the laptop" (session.go) is exactly what this
// exercises: the only thing driving Evaluate's answer is the issuer's own
// clock against a real Verified's real VerifiedAt.
func TestPresenceWindowSatisfiedWithinDurationThenExpires(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	store := presence.NewSessionStore(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "device-1"
	w := presence.Window{Tool: "claude", Duration: time.Hour, Level: presence.LevelWindow}

	if d := store.Evaluate(deviceID, w, false); d.Satisfied {
		t.Fatal("Evaluate before any touch: Satisfied = true, want false")
	}

	verified := touchWindow(t, v, key, deviceID, w.Tool, w.Target)
	if _, err := store.Touch(deviceID, w, verified); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	if d := store.Evaluate(deviceID, w, false); !d.Satisfied {
		t.Fatal("Evaluate immediately after touch: Satisfied = false, want true")
	}

	clk.Advance(59 * time.Minute)
	if d := store.Evaluate(deviceID, w, false); !d.Satisfied {
		t.Fatal("Evaluate at 59 of 60 minutes: Satisfied = false, want true")
	}

	clk.Advance(2 * time.Minute) // total 61 minutes, past the one-hour window
	if d := store.Evaluate(deviceID, w, false); d.Satisfied {
		t.Fatal("Evaluate at 61 of 60 minutes: Satisfied = true, want false")
	}
}

// TestPresenceWindowLevelAlwaysNeverHoldsASession covers a presence:always
// target: no prior touch can ever satisfy it, because Touch itself refuses to
// open a session for LevelAlways at all (ErrLevelHasNoSession) -- the
// assertion must be bound to this specific request every time.
func TestPresenceWindowLevelAlwaysNeverHoldsASession(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	store := presence.NewSessionStore(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "device-1"
	w := presence.Window{Tool: "aws", Target: "prod-admin", Duration: 15 * time.Minute, Level: presence.LevelAlways}

	d := store.Evaluate(deviceID, w, false)
	if d.Satisfied {
		t.Fatal("Evaluate on a presence:always target: Satisfied = true, want false")
	}
	if d.Binding != presence.BindingRequired {
		t.Fatalf("Evaluate on a presence:always target: Binding = %v, want BindingRequired", d.Binding)
	}

	verified := touchWindow(t, v, key, deviceID, w.Tool, w.Target)
	if _, err := store.Touch(deviceID, w, verified); !errors.Is(err, presence.ErrLevelHasNoSession) {
		t.Fatalf("Touch on a presence:always window = %v, want ErrLevelHasNoSession", err)
	}

	// Even after the refused Touch, still never satisfied: LevelAlways holds
	// no session to have opened in the first place.
	if d := store.Evaluate(deviceID, w, false); d.Satisfied {
		t.Fatal("Evaluate after a refused Touch on presence:always: Satisfied = true, want false")
	}
}

// TestPresenceWindowLevelStepUpParksRatherThanPrompting covers the third
// level: Evaluate never asks the requesting device for anything and instead
// flags Park, because "no touch on the requesting device satisfies it"
// (presence.go).
func TestPresenceWindowLevelStepUpParksRatherThanPrompting(t *testing.T) {
	clk := newTestClock()
	store := presence.NewSessionStore(clk.Now)
	w := presence.Window{Tool: "homeassistant", Target: "lock.front_door#unlock", Level: presence.LevelStepUp}

	d := store.Evaluate("device-1", w, false)
	if !d.Park {
		t.Fatal("Evaluate on a step-up target: Park = false, want true")
	}
	if d.Satisfied {
		t.Fatal("Evaluate on a step-up target: Satisfied = true, want false")
	}
	if d.Binding != presence.BindingRequired {
		t.Fatalf("Evaluate on a step-up target: Binding = %v, want BindingRequired", d.Binding)
	}
}

// TestPresenceWindowEscalationBehavesLikeAlwaysForOneRequest covers the
// per-request escalation path (a second request seconds after an approval, a
// prompt-rate ceiling, money above the step-up threshold): even with an open,
// otherwise-satisfying session, escalate=true must still demand a
// request-bound touch and must not be satisfiable by the held session.
func TestPresenceWindowEscalationBehavesLikeAlwaysForOneRequest(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	store := presence.NewSessionStore(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "device-1"
	w := presence.Window{Tool: "claude", Duration: time.Hour, Level: presence.LevelWindow}

	verified := touchWindow(t, v, key, deviceID, w.Tool, w.Target)
	if _, err := store.Touch(deviceID, w, verified); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if d := store.Evaluate(deviceID, w, false); !d.Satisfied {
		t.Fatal("sanity check: the held session should satisfy a normal (non-escalated) evaluation")
	}

	d := store.Evaluate(deviceID, w, true)
	if d.Satisfied {
		t.Fatal("escalated Evaluate: Satisfied = true, want false even with an open session")
	}
	if d.Binding != presence.BindingRequired {
		t.Fatalf("escalated Evaluate: Binding = %v, want BindingRequired", d.Binding)
	}
}

// TestPresenceWindowGroupHonorsEachMembersOwnDuration covers the shared-group
// rule from session.go: "a grouped window never rides a longer sibling's
// touch: the shortest duration in a group is what each member actually
// gets." gh and git share one session; here the longer member (30m) is
// touched, and the shorter member (15m) must stop being satisfied at its own
// 15 minutes even though the underlying session is still alive for the
// longer member.
func TestPresenceWindowGroupHonorsEachMembersOwnDuration(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	store := presence.NewSessionStore(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "device-1"
	const group = "git"
	long := presence.Window{Tool: "gh", Group: group, Duration: 30 * time.Minute, Level: presence.LevelWindow}
	short := presence.Window{Tool: "git", Group: group, Duration: 15 * time.Minute, Level: presence.LevelWindow}

	verified := touchWindow(t, v, key, deviceID, long.Tool, long.Target)
	if _, err := store.Touch(deviceID, long, verified); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	if d := store.Evaluate(deviceID, long, false); !d.Satisfied {
		t.Fatal("immediately after touch, long member: Satisfied = false, want true")
	}
	if d := store.Evaluate(deviceID, short, false); !d.Satisfied {
		t.Fatal("immediately after touch, short member: Satisfied = false, want true")
	}

	clk.Advance(20 * time.Minute) // past short's 15m, within long's 30m
	if d := store.Evaluate(deviceID, long, false); !d.Satisfied {
		t.Fatal("at 20 of 30 minutes, long member: Satisfied = false, want true")
	}
	if d := store.Evaluate(deviceID, short, false); d.Satisfied {
		t.Fatal("at 20 of 15 minutes, short member: Satisfied = true, want false (must not ride the longer sibling's touch)")
	}
}

// TestConcurrentTouchWithSameVerifiedConsumesExactlyOnce is the concurrency
// property for item 2: Verified.consume() documents that "exactly one of two
// racing consumers mutates anything." This drives MaxOutstandingChallenges/2-ish
// concurrent real goroutines at the real SessionStore with the SAME real
// *Verified and asserts exactly one Touch succeeds, every other gets
// ErrPresenceConsumed, and exactly one session is ever recorded -- a
// genuine thread-safety property under -race, not a round trip.
func TestConcurrentTouchWithSameVerifiedConsumesExactlyOnce(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	store := presence.NewSessionStore(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "device-1"
	w := presence.Window{Tool: "claude", Duration: time.Hour, Level: presence.LevelWindow}

	verified := touchWindow(t, v, key, deviceID, w.Tool, w.Target)

	const n = 50
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.Touch(deviceID, w, verified)
		}(i)
	}
	wg.Wait()

	var successes, consumed int
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, presence.ErrPresenceConsumed):
			consumed++
		default:
			t.Fatalf("unexpected Touch error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	if consumed != n-1 {
		t.Fatalf("consumed = %d, want %d", consumed, n-1)
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("store.Len() = %d, want exactly 1 session recorded despite %d racing Touch calls", got, n)
	}
}

// TestConcurrentEvaluateDuringTouchNeverPanicsOrMissesTheTouch races real
// readers (Evaluate) against a real writer (Touch) on the same device and
// window, under -race, and checks the property that matters for a live
// issuer serving multiple tools at once: every Evaluate that runs strictly
// after Touch returns must observe Satisfied, and none may panic or corrupt
// state while racing. It does not assert anything about evaluations
// concurrent with the touch itself, since SessionStore makes no ordering
// promise there -- only that the store is safe to hit from many goroutines
// at once, which is the actual thread-safety property, and that the state is
// coherent once the write has completed.
func TestConcurrentEvaluateDuringTouchNeverPanicsOrMissesTheTouch(t *testing.T) {
	clk := newTestClock()
	v := presence.NewVerifier(0, clk.Now)
	store := presence.NewSessionStore(clk.Now)
	key := newDeviceKey(t)
	const deviceID = "device-1"
	w := presence.Window{Tool: "claude", Duration: time.Hour, Level: presence.LevelWindow}

	verified := touchWindow(t, v, key, deviceID, w.Tool, w.Target)

	const readers = 20
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					store.Evaluate(deviceID, w, false)
				}
			}
		}()
	}

	if _, err := store.Touch(deviceID, w, verified); err != nil {
		close(stop)
		wg.Wait()
		t.Fatalf("Touch: %v", err)
	}
	close(stop)
	wg.Wait()

	if d := store.Evaluate(deviceID, w, false); !d.Satisfied {
		t.Fatal("Evaluate strictly after Touch returned: Satisfied = false, want true")
	}
}
