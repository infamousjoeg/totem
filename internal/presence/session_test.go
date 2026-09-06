package presence

import (
	"testing"
	"time"
)

// touchFor builds a Verified the human would have given for window w on
// device: an unbound touch for w.Tool and w.Target.
func touchFor(device string, w Window, at time.Time) *Verified {
	return verifiedFor(device, w.Tool, w.Target, at, nil)
}

func TestDefaultWindows(t *testing.T) {
	ws := DefaultWindows()
	byTool := map[string]Window{}
	for _, w := range ws {
		if !w.validDuration() {
			t.Fatalf("shipped window %s has duration %s", w.Tool, w.Duration)
		}
		byTool[w.Tool] = w
	}
	if byTool["claude"].Duration != time.Hour {
		t.Fatal("claude window is not one hour")
	}
	if byTool["gh"].SessionKey() != byTool["git"].SessionKey() || byTool["gh"].Duration != 15*time.Minute {
		t.Fatal("gh and git must share one fifteen-minute session")
	}
}

func TestAWSProfileWindowDefaults(t *testing.T) {
	cases := []struct {
		role string
		want Level
	}{
		{"developer", LevelWindow},
		{"ProdAdmin", LevelAlways},
		{"admin-readonly", LevelAlways},
		{"prod-deployer", LevelAlways},
		{"production", LevelAlways},
		{"staging", LevelWindow},
		{"", LevelWindow},
	}
	for _, tc := range cases {
		w := AWSProfileWindow("p", tc.role)
		if w.Level != tc.want {
			t.Errorf("role %q: level %s, want %s", tc.role, w.Level, tc.want)
		}
		if w.Duration != AWSWindow || w.Tool != "aws" || w.Target != "p" || w.SessionKey() != "aws:p" {
			t.Errorf("role %q: %+v", tc.role, w)
		}
	}
	// Two profiles are two sessions.
	if AWSProfileWindow("a", "").SessionKey() == AWSProfileWindow("b", "").SessionKey() {
		t.Fatal("profiles share a session key")
	}
}

func TestSessionWindowLifecycle(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}

	if d := st.Evaluate("dev", w, false); d.Satisfied || d.Binding != BindingNone || d.Park {
		t.Fatalf("fresh store satisfied a window: %+v", d)
	}
	sess, err := st.Touch("dev", w, touchFor("dev", w, clk.Now()))
	mustErr(t, err, nil)
	if !sess.ExpiresAt.Equal(clk.At(time.Hour)) {
		t.Fatalf("expiry %v, want %v", sess.ExpiresAt, clk.At(time.Hour))
	}
	clk.Advance(20 * time.Minute)
	d := st.Evaluate("dev", w, false)
	if !d.Satisfied || d.Age != 20*time.Minute {
		t.Fatalf("mid-window: %+v", d)
	}
	if st.Evaluate("other-device", w, false).Satisfied {
		t.Fatal("session leaked across devices")
	}
	clk.Advance(40 * time.Minute)
	if st.Evaluate("dev", w, false).Satisfied {
		t.Fatal("window honored at its own expiry instant")
	}
	if st.Len() != 0 {
		t.Fatal("expired session not swept")
	}
}

func TestSessionAlwaysNeverSatisfied(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := AWSProfileWindow("prod", "prod-admin")
	// Even with a touch recorded under the same key, always is per request.
	windowed := w
	windowed.Level = LevelWindow
	if _, err := st.Touch("dev", windowed, touchFor("dev", windowed, clk.Now())); err != nil {
		t.Fatal(err)
	}
	d := st.Evaluate("dev", w, false)
	if d.Satisfied || d.Binding != BindingRequired || d.Park {
		t.Fatalf("always target: %+v", d)
	}
	_, err := st.Touch("dev", w, touchFor("dev", w, clk.Now()))
	mustErr(t, err, ErrLevelHasNoSession)
}

// step-up: park and approve from another enrolled device. Never satisfied by
// a held session on the requesting device, never opens one.
func TestSessionStepUpParks(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "aws", Target: "prod-deploy", Duration: AWSWindow, Level: LevelStepUp}
	windowed := w
	windowed.Level = LevelWindow
	if _, err := st.Touch("dev", windowed, touchFor("dev", windowed, clk.Now())); err != nil {
		t.Fatal(err)
	}
	for _, escalate := range []bool{false, true} {
		d := st.Evaluate("dev", w, escalate)
		if d.Satisfied || !d.Park || d.Binding != BindingRequired {
			t.Fatalf("step-up (escalate=%v): %+v", escalate, d)
		}
	}
	_, err := st.Touch("dev", w, touchFor("dev", w, clk.Now()))
	mustErr(t, err, ErrLevelHasNoSession)
}

// Per-request escalation: a windowed target that this once behaves exactly
// as always. The held session does not satisfy it, the assertion must be
// request-bound, and that bound touch cannot refresh the window.
func TestSessionEscalation(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "gh", Group: GitGroup, Duration: GitWindow, Level: LevelWindow}
	if _, err := st.Touch("dev", w, touchFor("dev", w, clk.Now())); err != nil {
		t.Fatal(err)
	}
	if !st.Evaluate("dev", w, false).Satisfied {
		t.Fatal("setup")
	}
	d := st.Evaluate("dev", w, true)
	if d.Satisfied || d.Park || d.Binding != BindingRequired {
		t.Fatalf("escalated evaluation did not behave as always: %+v", d)
	}
	always := w
	always.Level = LevelAlways
	if a := st.Evaluate("dev", always, false); a.Satisfied != d.Satisfied || a.Park != d.Park || a.Binding != d.Binding {
		t.Fatalf("escalated %+v differs from always %+v", d, a)
	}
	// The escalated assertion is request-bound and cannot open a window...
	clk.Advance(5 * time.Minute)
	_, err := st.Touch("dev", w, verifiedFor("dev", "gh", "", clk.Now(), HashRequest([]byte("push --force"))))
	mustErr(t, err, ErrBoundAssertionCannotOpenWindow)
	// ...so the original session is unchanged and still ages normally.
	if d := st.Evaluate("dev", w, false); !d.Satisfied || d.Age != 5*time.Minute {
		t.Fatalf("escalation disturbed the window: %+v", d)
	}
	// Escalation is per request: the next unescalated evaluation is satisfied.
	if !st.Evaluate("dev", w, false).Satisfied {
		t.Fatal("escalation stuck to the window")
	}
}

func TestSessionSharedGroup(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	var gh, git Window
	for _, w := range DefaultWindows() {
		switch w.Tool {
		case "gh":
			gh = w
		case "git":
			git = w
		}
	}
	if _, err := st.Touch("dev", gh, touchFor("dev", gh, clk.Now())); err != nil {
		t.Fatal(err)
	}
	if !st.Evaluate("dev", git, false).Satisfied {
		t.Fatal("git did not share gh's touch")
	}
	claude := Window{Tool: "claude", Duration: ClaudeWindow, Level: LevelWindow}
	if st.Evaluate("dev", claude, false).Satisfied {
		t.Fatal("claude satisfied by a gh touch")
	}
}

// A grouped window is honored only up to its own duration: the shortest
// member of a group is what each member gets, whichever was touched.
// (Reviewer M4, inverted.)
func TestSessionGroupedWindowDoesNotRideLongerSibling(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	long := Window{Tool: "claude", Group: "ide", Duration: time.Hour, Level: LevelWindow}
	short := Window{Tool: "aws", Target: "dev", Group: "ide", Duration: 15 * time.Minute, Level: LevelWindow}
	if _, err := st.Touch("dev", long, touchFor("dev", long, clk.Now())); err != nil {
		t.Fatal(err)
	}
	clk.Advance(14 * time.Minute)
	if !st.Evaluate("dev", short, false).Satisfied {
		t.Fatal("short member not honored inside its own duration")
	}
	clk.Advance(time.Minute)
	if st.Evaluate("dev", short, false).Satisfied {
		t.Fatal("short member rode the long sibling's touch past its own duration")
	}
	if !st.Evaluate("dev", long, false).Satisfied {
		t.Fatal("long member lost its own window")
	}
	// An invalid duration on the evaluated window is never satisfied, even
	// with a live session under the key.
	bad := long
	bad.Duration = MaxWindow + time.Second
	if st.Evaluate("dev", bad, false).Satisfied {
		t.Fatal("over-long window evaluated as satisfied")
	}
	bad.Duration = 0
	if st.Evaluate("dev", bad, false).Satisfied {
		t.Fatal("zero window evaluated as satisfied")
	}
}

func TestSessionTouchRefusals(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	good := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}
	awsDev := Window{Tool: "aws", Target: "dev", Duration: AWSWindow, Level: LevelWindow}
	used := touchFor("dev", good, clk.Now())
	if err := used.consume(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		device string
		w      Window
		v      *Verified
		want   error
	}{
		{"longer than MaxWindow", "dev", Window{Tool: "claude", Duration: MaxWindow + time.Second, Level: LevelWindow}, verifiedFor("dev", "claude", "", clk.Now(), nil), ErrInvalidWindow},
		{"zero duration", "dev", Window{Tool: "claude", Level: LevelWindow}, verifiedFor("dev", "claude", "", clk.Now(), nil), ErrInvalidWindow},
		{"negative duration", "dev", Window{Tool: "claude", Duration: -time.Minute, Level: LevelWindow}, verifiedFor("dev", "claude", "", clk.Now(), nil), ErrInvalidWindow},
		{"request-bound assertion", "dev", good, verifiedFor("dev", "claude", "", clk.Now(), HashRequest([]byte("x"))), ErrBoundAssertionCannotOpenWindow},
		{"hand-built verified", "dev", good, &Verified{DeviceID: "dev", Tool: "claude", VerifiedAt: clk.Now()}, ErrPresenceRequired},
		{"nil verified", "dev", good, nil, ErrPresenceRequired},
		{"already used verified", "dev", good, used, ErrPresenceConsumed},
		{"other device's touch", "dev", good, verifiedFor("work-mbp", "claude", "", clk.Now(), nil), ErrDeviceMismatch},
		{"touch given for another tool (M1)", "dev", good, verifiedFor("dev", "gh", "", clk.Now(), nil), ErrToolMismatch},
		{"touch given for another profile (M1)", "dev", awsDev, verifiedFor("dev", "aws", "prod", clk.Now(), nil), ErrTargetMismatch},
		{"touch for the tool with no target", "dev", awsDev, verifiedFor("dev", "aws", "", clk.Now(), nil), ErrTargetMismatch},
		{"exactly MaxWindow", "dev", Window{Tool: "claude", Duration: MaxWindow, Level: LevelWindow}, verifiedFor("dev", "claude", "", clk.Now(), nil), nil},
		{"tool window ignores the touch's target", "dev", good, verifiedFor("dev", "claude", "api.anthropic.com", clk.Now(), nil), nil},
		{"profile window with matching target", "dev", awsDev, verifiedFor("dev", "aws", "dev", clk.Now(), nil), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fresh := NewSessionStore(clk.Now)
			_, err := fresh.Touch(tc.device, tc.w, tc.v)
			mustErr(t, err, tc.want)
			if tc.want != nil {
				if fresh.Evaluate(tc.device, tc.w, false).Satisfied {
					t.Fatal("refused touch still opened a session")
				}
				if tc.v != nil && tc.v != used && tc.v.Used() {
					t.Fatal("refused touch consumed the proof")
				}
				return
			}
			if !tc.v.Used() {
				t.Fatal("successful touch did not consume the proof")
			}
		})
	}
	_ = st
}

// One Verified opens exactly one window. (Reviewer M1, inverted.)
func TestSessionOneTouchOneWindow(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	gh := Window{Tool: "gh", Group: GitGroup, Duration: GitWindow, Level: LevelWindow}
	git := Window{Tool: "git", Group: GitGroup, Duration: GitWindow, Level: LevelWindow}
	v := touchFor("dev", gh, clk.Now())
	if _, err := st.Touch("dev", gh, v); err != nil {
		t.Fatal(err)
	}
	// Same proof, a second window (even one it would otherwise match).
	_, err := st.Touch("dev", gh, v)
	mustErr(t, err, ErrPresenceConsumed)
	// git shares gh's group so it is satisfied by the touch, but it cannot be
	// opened with the gh proof either: the proof is spent and the tool
	// differs.
	_, err = st.Touch("dev", git, v)
	if err == nil {
		t.Fatal("spent gh proof opened the git window")
	}
	if !st.Evaluate("dev", git, false).Satisfied {
		t.Fatal("group sharing broken")
	}
}

func TestSessionRevoke(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	claude := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}
	gh := Window{Tool: "gh", Group: GitGroup, Duration: GitWindow, Level: LevelWindow}
	for _, dev := range []string{"a", "b"} {
		for _, w := range []Window{claude, gh} {
			if _, err := st.Touch(dev, w, touchFor(dev, w, clk.Now())); err != nil {
				t.Fatal(err)
			}
		}
	}
	st.Revoke("a")
	if st.Evaluate("a", claude, false).Satisfied || st.Evaluate("a", gh, false).Satisfied {
		t.Fatal("revoked device still holds a session")
	}
	if !st.Evaluate("b", claude, false).Satisfied {
		t.Fatal("revocation hit the wrong device")
	}
	if st.Len() != 2 {
		t.Fatalf("len = %d, want 2", st.Len())
	}
}

// A new store is empty: this is what "an issuer restart means every tool
// prompts once" reduces to. There is no load path to test because there is
// none.
func TestSessionStoreStartsEmpty(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}
	if _, err := st.Touch("dev", w, touchFor("dev", w, clk.Now())); err != nil {
		t.Fatal(err)
	}
	restarted := NewSessionStore(clk.Now)
	if restarted.Evaluate("dev", w, false).Satisfied || restarted.Len() != 0 {
		t.Fatal("a new store carried a session")
	}
}
