package presence

import (
	"testing"
	"time"
)

func TestDefaultWindows(t *testing.T) {
	ws := DefaultWindows()
	byTool := map[string]Window{}
	for _, w := range ws {
		if w.Duration <= 0 || w.Duration > MaxWindow {
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
		if w.Duration != AWSWindow || w.Tool != "aws:p" {
			t.Errorf("role %q: %+v", tc.role, w)
		}
	}
}

func TestSessionWindowLifecycle(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}

	if d := st.Evaluate("dev", w, false); d.Satisfied || d.Binding != BindingNone || d.Park {
		t.Fatalf("fresh store satisfied a window: %+v", d)
	}
	sess, err := st.Touch("dev", w, verified("dev", clk.Now(), nil))
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
	if _, err := st.Touch("dev", Window{Tool: w.Tool, Duration: AWSWindow, Level: LevelWindow}, verified("dev", clk.Now(), nil)); err != nil {
		t.Fatal(err)
	}
	d := st.Evaluate("dev", w, false)
	if d.Satisfied || d.Binding != BindingRequired || d.Park {
		t.Fatalf("always target: %+v", d)
	}
	_, err := st.Touch("dev", w, verified("dev", clk.Now(), nil))
	mustErr(t, err, ErrLevelHasNoSession)
}

// step-up: park and approve from another enrolled device. Never satisfied by
// a held session on the requesting device, never opens one.
func TestSessionStepUpParks(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "aws:prod-deploy", Duration: AWSWindow, Level: LevelStepUp}
	if _, err := st.Touch("dev", Window{Tool: w.Tool, Duration: AWSWindow, Level: LevelWindow}, verified("dev", clk.Now(), nil)); err != nil {
		t.Fatal(err)
	}
	for _, escalate := range []bool{false, true} {
		d := st.Evaluate("dev", w, escalate)
		if d.Satisfied || !d.Park || d.Binding != BindingRequired {
			t.Fatalf("step-up (escalate=%v): %+v", escalate, d)
		}
	}
	_, err := st.Touch("dev", w, verified("dev", clk.Now(), nil))
	mustErr(t, err, ErrLevelHasNoSession)
}

// Per-request escalation: a windowed target that this once behaves exactly
// as always. The held session does not satisfy it, the assertion must be
// request-bound, and that bound touch cannot refresh the window.
func TestSessionEscalation(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	w := Window{Tool: "gh", Group: GitGroup, Duration: GitWindow, Level: LevelWindow}
	if _, err := st.Touch("dev", w, verified("dev", clk.Now(), nil)); err != nil {
		t.Fatal(err)
	}
	if !st.Evaluate("dev", w, false).Satisfied {
		t.Fatal("setup")
	}
	d := st.Evaluate("dev", w, true)
	if d.Satisfied || d.Park || d.Binding != BindingRequired {
		t.Fatalf("escalated evaluation did not behave as always: %+v", d)
	}
	always := Window{Tool: w.Tool, Group: w.Group, Duration: w.Duration, Level: LevelAlways}
	if a := st.Evaluate("dev", always, false); a.Satisfied != d.Satisfied || a.Park != d.Park || a.Binding != d.Binding {
		t.Fatalf("escalated %+v differs from always %+v", d, a)
	}
	// The escalated assertion is request-bound and cannot open a window...
	clk.Advance(10 * time.Minute)
	_, err := st.Touch("dev", w, verified("dev", clk.Now(), HashRequest([]byte("push --force"))))
	mustErr(t, err, ErrBoundAssertionCannotOpenWindow)
	// ...so the original session is unchanged and still ages normally.
	if d := st.Evaluate("dev", w, false); !d.Satisfied || d.Age != 10*time.Minute {
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
	if _, err := st.Touch("dev", gh, verified("dev", clk.Now(), nil)); err != nil {
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

func TestSessionTouchRefusals(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	good := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}
	cases := []struct {
		name   string
		device string
		w      Window
		v      *Verified
		want   error
	}{
		{"longer than MaxWindow", "dev", Window{Tool: "claude", Duration: MaxWindow + time.Second, Level: LevelWindow}, verified("dev", clk.Now(), nil), ErrInvalidWindow},
		{"zero duration", "dev", Window{Tool: "claude", Level: LevelWindow}, verified("dev", clk.Now(), nil), ErrInvalidWindow},
		{"negative duration", "dev", Window{Tool: "claude", Duration: -time.Minute, Level: LevelWindow}, verified("dev", clk.Now(), nil), ErrInvalidWindow},
		{"request-bound assertion", "dev", good, verified("dev", clk.Now(), HashRequest([]byte("x"))), ErrBoundAssertionCannotOpenWindow},
		{"hand-built verified", "dev", good, &Verified{DeviceID: "dev", VerifiedAt: clk.Now()}, ErrPresenceRequired},
		{"nil verified", "dev", good, nil, ErrPresenceRequired},
		{"other device's touch", "dev", good, verified("work-mbp", clk.Now(), nil), ErrDeviceMismatch},
		{"exactly MaxWindow", "dev", Window{Tool: "claude", Duration: MaxWindow, Level: LevelWindow}, verified("dev", clk.Now(), nil), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := st.Touch(tc.device, tc.w, tc.v)
			mustErr(t, err, tc.want)
			if tc.want != nil && st.Evaluate(tc.device, tc.w, false).Satisfied {
				t.Fatal("refused touch still opened a session")
			}
		})
	}
}

func TestSessionRevoke(t *testing.T) {
	clk := newClock()
	st := NewSessionStore(clk.Now)
	claude := Window{Tool: "claude", Duration: time.Hour, Level: LevelWindow}
	gh := Window{Tool: "gh", Group: GitGroup, Duration: GitWindow, Level: LevelWindow}
	for _, dev := range []string{"a", "b"} {
		for _, w := range []Window{claude, gh} {
			if _, err := st.Touch(dev, w, verified(dev, clk.Now(), nil)); err != nil {
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
	if _, err := st.Touch("dev", w, verified("dev", clk.Now(), nil)); err != nil {
		t.Fatal(err)
	}
	restarted := NewSessionStore(clk.Now)
	if restarted.Evaluate("dev", w, false).Satisfied || restarted.Len() != 0 {
		t.Fatal("a new store carried a session")
	}
}
