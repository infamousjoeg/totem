package presence

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Session errors.
var (
	// ErrInvalidWindow: a window with a non-positive duration or one longer
	// than MaxWindow. "A longer window is never one of the options."
	ErrInvalidWindow = errors.New("presence: window duration invalid or longer than MaxWindow")
	// ErrLevelHasNoSession: presence:always and step-up targets never open a
	// session; touching one is an issuer bug.
	ErrLevelHasNoSession = errors.New("presence: always and step-up targets hold no session")
	// ErrBoundAssertionCannotOpenWindow: a request-bound assertion authorizes
	// one request and is never reusable, so it cannot open a window.
	ErrBoundAssertionCannotOpenWindow = errors.New("presence: request-bound assertion cannot open a window")
)

// Session is one held presence window on the issuer: a human touched the
// sensor for this device and session key at TouchedAt, and that touch is
// honored until ExpiresAt.
type Session struct {
	// DeviceID the touch happened on.
	DeviceID string
	// Key is the window's SessionKey (tool, profile, or shared group).
	Key string
	// TouchedAt is the verified presence time.
	TouchedAt time.Time
	// ExpiresAt is TouchedAt plus the window duration.
	ExpiresAt time.Time
}

// Decision is the issuer's answer to "does this request need a fresh touch".
type Decision struct {
	// Satisfied is true when a held session covers the request and no prompt
	// is needed.
	Satisfied bool
	// Park is true for a LevelStepUp target: no assertion from the requesting
	// device satisfies it. The issuer parks the request in a Lot and a human
	// approves it from another enrolled device.
	Park bool
	// Binding says what an assertion, if one is needed, must carry.
	Binding Binding
	// Session is the covering session when Satisfied.
	Session Session
	// Age is how old the covering presence is at evaluation, recorded on the
	// audit line as the presence age.
	Age time.Duration
}

// SessionStore holds presence sessions on the issuer, in memory only. It has
// no serialization path on purpose: sessions are never persisted, an issuer
// restart means every tool prompts once, and there is nothing on disk to
// steal or replay. There is no global switch and no way to open a window
// longer than MaxWindow.
type SessionStore struct {
	mu       sync.Mutex
	now      func() time.Time
	sessions map[sessionKey]Session
}

type sessionKey struct {
	device string
	key    string
}

// NewSessionStore returns an empty store on the given clock (nil means
// time.Now). A new store is the only way sessions come into being after a
// restart.
func NewSessionStore(now func() time.Time) *SessionStore {
	if now == nil {
		now = time.Now
	}
	return &SessionStore{now: now, sessions: make(map[sessionKey]Session)}
}

// Evaluate decides whether a held session satisfies a request on window w for
// deviceID. LevelWindow is satisfied by an unexpired session; LevelAlways
// never is (BindingRequired); LevelStepUp never is and sets Park. escalate is
// the per-request escalation for a windowed target that this once needs a
// fresh touch (a second request seconds after an approval, a prompt rate over
// the target's ceiling, money above the step-up threshold): the single
// evaluation behaves exactly as LevelAlways, so the assertion is bound to the
// request hash, the held session cannot satisfy it, and, being request-bound,
// the resulting touch cannot open or refresh a window. escalate has no effect
// on LevelAlways or LevelStepUp, which are already stricter.
func (s *SessionStore) Evaluate(deviceID string, w Window, escalate bool) Decision {
	d := Decision{Binding: BindingNone}
	switch {
	case w.Level == LevelStepUp:
		d.Park = true
		d.Binding = BindingRequired
		return d
	case w.Level == LevelAlways || escalate:
		d.Binding = BindingRequired
		return d
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sessionKey{device: deviceID, key: w.SessionKey()}
	sess, ok := s.sessions[k]
	if !ok {
		return d
	}
	if !now.Before(sess.ExpiresAt) {
		delete(s.sessions, k)
		return d
	}
	d.Satisfied = true
	d.Session = sess
	d.Age = now.Sub(sess.TouchedAt)
	return d
}

// Touch records a verified presence on window w for deviceID and returns the
// session opened. It refuses an invalid or over-long window, an always or
// step-up window (neither holds a session), a request-bound assertion, a
// hand-built Verified, or a Verified from another device.
func (s *SessionStore) Touch(deviceID string, w Window, v *Verified) (Session, error) {
	if !v.Valid() {
		return Session{}, ErrPresenceRequired
	}
	if w.Duration <= 0 || w.Duration > MaxWindow {
		return Session{}, fmt.Errorf("%w: %s", ErrInvalidWindow, w.Duration)
	}
	if w.Level == LevelAlways || w.Level == LevelStepUp {
		return Session{}, fmt.Errorf("%w: %s", ErrLevelHasNoSession, w.Level)
	}
	if len(v.RequestHash) != 0 {
		return Session{}, ErrBoundAssertionCannotOpenWindow
	}
	if v.DeviceID != deviceID {
		return Session{}, ErrDeviceMismatch
	}
	sess := Session{
		DeviceID:  deviceID,
		Key:       w.SessionKey(),
		TouchedAt: v.VerifiedAt,
		ExpiresAt: v.VerifiedAt.Add(w.Duration),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionKey{device: deviceID, key: sess.Key}] = sess
	return sess, nil
}

// Revoke drops every session for deviceID. Revocation is instant: the next
// request from that device prompts, or fails if the device is no longer
// enrolled.
func (s *SessionStore) Revoke(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.sessions {
		if k.device == deviceID {
			delete(s.sessions, k)
		}
	}
}

// Len reports how many unexpired sessions are held, sweeping expired ones.
func (s *SessionStore) Len() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	return len(s.sessions)
}
