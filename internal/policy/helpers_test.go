package policy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/platform"
	"github.com/infamousjoeg/totem/internal/presence"
	"github.com/infamousjoeg/totem/internal/spiffe"
	"github.com/infamousjoeg/totem/internal/store"
)

const testDomain = "issuer.example.test"

var issuerFP = func() []byte { s := sha256.Sum256([]byte("issuer-leaf")); return s[:] }()

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// memStore is an in-memory store.Store with a real hash chain, so Append
// and Verify behave like the contract says and a tampered payload breaks
// the chain. Like the real store it STAMPS Record.At from its own clock on
// Append and ignores the caller's value: a fake that honoured a caller's
// timestamp would pass tests that mean nothing against the real thing.
type memStore struct {
	mu   sync.Mutex
	now  func() time.Time
	rows map[string]map[string][]byte
	log  []store.Record
}

func newMemStore(now func() time.Time) *memStore {
	return &memStore{now: now, rows: make(map[string]map[string][]byte)}
}

func (m *memStore) Migrate(context.Context) error { return nil }
func (m *memStore) Get(_ context.Context, c, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.rows[c][id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(v), nil
}
func (m *memStore) Put(_ context.Context, c, id string, v []byte) error {
	if err := validName(c); err != nil {
		return err
	}
	if err := validName(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[c] == nil {
		m.rows[c] = make(map[string][]byte)
	}
	m.rows[c][id] = bytes.Clone(v)
	return nil
}
func (m *memStore) Delete(_ context.Context, c, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[c][id]; !ok {
		return store.ErrNotFound
	}
	delete(m.rows[c], id)
	return nil
}
func (m *memStore) List(_ context.Context, c string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id := range m.rows[c] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
func (m *memStore) RotateDataKey(context.Context, []byte) error { return nil }
func chainHash(prev []byte, r store.Record) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte(r.Kind))
	h.Write([]byte(r.At.UTC().Format(time.RFC3339Nano)))
	h.Write(r.Payload)
	return h.Sum(nil)
}

// validName mirrors the real store's name rule (store/schema.go validName)
// so a kind or id policy writes is refused here the way SQLite and the
// backup tarball would refuse it, instead of passing an in-memory fake and
// failing at the seam.
func validName(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > 128 {
		return fmt.Errorf("%w: %q", store.ErrBadName, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':', c == '@':
		default:
			return fmt.Errorf("%w: %q offset %d", store.ErrBadName, s, i)
		}
	}
	return nil
}

func (m *memStore) Append(_ context.Context, r store.Record) ([]byte, error) {
	if err := validName(r.Kind); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev []byte
	if n := len(m.log); n > 0 {
		prev = m.log[n-1].Hash
	}
	r.Seq = int64(len(m.log) + 1)
	r.At = m.now()
	r.PrevHash = prev
	r.Hash = chainHash(prev, r)
	m.log = append(m.log, r)
	return bytes.Clone(r.Hash), nil
}
func (m *memStore) Verify(context.Context) (bool, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev []byte
	for _, r := range m.log {
		if !bytes.Equal(r.PrevHash, prev) || !bytes.Equal(r.Hash, chainHash(prev, r)) {
			return false, r.Seq, nil
		}
		prev = r.Hash
	}
	return true, 0, nil
}
func (m *memStore) Walk(_ context.Context, from int64, fn func(store.Record) error) error {
	m.mu.Lock()
	log := append([]store.Record(nil), m.log...)
	m.mu.Unlock()
	var prev []byte
	for _, r := range log {
		if !bytes.Equal(r.PrevHash, prev) || !bytes.Equal(r.Hash, chainHash(prev, r)) {
			return store.ErrChainBroken
		}
		prev = r.Hash
		if r.Seq < from {
			continue
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}
func (m *memStore) Head(context.Context) (int64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.log) == 0 {
		return 0, nil, nil
	}
	last := m.log[len(m.log)-1]
	return last.Seq, bytes.Clone(last.Hash), nil
}
func (m *memStore) Close() error { return nil }

// tamper rewrites the payload of chain record seq in place, and if rechain
// is set recomputes every later hash so the chain reads as intact.
func (m *memStore) tamper(seq int64, edit func([]byte) []byte, rechain bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log[seq-1].Payload = edit(m.log[seq-1].Payload)
	if !rechain {
		return
	}
	var prev []byte
	for i := range m.log {
		m.log[i].PrevHash = prev
		m.log[i].Hash = chainHash(prev, m.log[i])
		prev = m.log[i].Hash
	}
}

// kinds returns the chain kinds in order.
func (m *memStore) kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.log))
	for i, r := range m.log {
		out[i] = r.Kind
	}
	return out
}

// fakeKey models a device honestly: on Apple silicon the device half and
// the presence half are two keys. presence nil is a none-level device.
type fakeKey struct {
	device, presence *ecdsa.PrivateKey
	level            spiffe.ProtectionLevel
	deny             error
	prompts          int
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newFakeKey(t *testing.T, withPresence bool) *fakeKey {
	t.Helper()
	k := &fakeKey{device: p256(t), level: spiffe.ProtectionHardware}
	if withPresence {
		k.presence = p256(t)
	} else {
		k.level = spiffe.ProtectionSoftware
	}
	return k
}

func (k *fakeKey) Public() crypto.PublicKey { return &k.device.PublicKey }
func (k *fakeKey) PresencePublic() crypto.PublicKey {
	if k.presence == nil {
		return nil
	}
	return &k.presence.PublicKey
}
func (k *fakeKey) Sign(_ context.Context, challenge []byte, prompt platform.Prompt) ([]byte, error) {
	sum := sha256.Sum256(challenge)
	if !prompt.Required {
		return ecdsa.SignASN1(rand.Reader, k.device, sum[:])
	}
	if k.presence == nil {
		return nil, platform.ErrPresenceUnavailable
	}
	if k.deny != nil {
		return nil, k.deny
	}
	k.prompts++
	return ecdsa.SignASN1(rand.Reader, k.presence, sum[:])
}
func (k *fakeKey) ProtectionLevel() spiffe.ProtectionLevel { return k.level }

func spki(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	if pub == nil {
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// world is one issuer with its primitives and store.
type world struct {
	t     *testing.T
	clk   *clock
	st    *memStore
	ver   *presence.Verifier
	sess  *presence.SessionStore
	reg   *presence.Registry
	lot   *presence.Lot
	iss   *Issuer
	keys  map[string]*fakeKey
	names map[string]string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, clk: newClock(), keys: map[string]*fakeKey{}, names: map[string]string{}}
	w.st = newMemStore(w.clk.Now)
	w.ver = presence.NewVerifier(0, w.clk.Now)
	w.sess = presence.NewSessionStore(w.clk.Now)
	w.reg = presence.NewRegistry(w.clk.Now)
	w.lot = presence.NewLot(w.clk.Now, 0, 0)
	w.iss = w.open()
	return w
}

func (w *world) open() *Issuer {
	w.t.Helper()
	iss, err := New(context.Background(), Config{
		TrustDomain: testDomain, Verifier: w.ver, Sessions: w.sess, Grants: w.reg, Lot: w.lot,
		Store: w.st, Now: w.clk.Now,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return iss
}

// reopen builds a fresh issuer on the same store, as a restart would.
func (w *world) reopen() (*Issuer, error) {
	w.ver = presence.NewVerifier(0, w.clk.Now)
	w.sess = presence.NewSessionStore(w.clk.Now)
	w.reg = presence.NewRegistry(w.clk.Now)
	w.lot = presence.NewLot(w.clk.Now, 0, 0)
	return New(context.Background(), Config{
		TrustDomain: testDomain, Verifier: w.ver, Sessions: w.sess, Grants: w.reg, Lot: w.lot,
		Store: w.st, Now: w.clk.Now,
	})
}

// enrollRequest does what the agent does at `totem enroll`: one challenge,
// the device proof of possession, and (with a presence key) a presence
// assertion over the digest, signed for the trust domain the device was
// told. Both go through presence's real signing functions.
func (w *world) enrollRequest(key *fakeKey, name, code, target string) EnrollRequest {
	w.t.Helper()
	devicePub := spki(w.t, key.Public())
	ch, err := w.iss.EnrollmentChallenge(devicePub)
	if err != nil {
		w.t.Fatal(err)
	}
	in := presence.EnrollmentInput{
		Version:   presence.EncodingVersion,
		Challenge: ch, IssuerFingerprint: issuerFP, DevicePublicKey: devicePub,
		PresencePublicKey: spki(w.t, key.PresencePublic()), ProtectionLevel: key.level,
		Hostname: name + ".local", OS: "macOS", FirstContact: presence.FirstContactFragment,
	}
	if code != "" {
		in.BootstrapCodeHash = presence.BootstrapCodeHash(ch, code)
	}
	sig, err := presence.SignEnrollment(context.Background(), key, in)
	if err != nil {
		w.t.Fatal(err)
	}
	req := EnrollRequest{Input: in, Signature: sig, BootstrapCode: code, Name: name}
	if key.presence != nil {
		digest, _ := in.Digest()
		a, err := presence.Sign(context.Background(), key, presence.SigningInput{
			DeviceID: presence.PreEnrollmentDeviceID(devicePub), Tool: presence.EnrollmentTool,
			Target: target, Challenge: ch, RequestHash: digest,
		})
		if err != nil {
			w.t.Fatal(err)
		}
		req.PresenceSignature = a.Signature
	}
	return req
}

// found enrolls the founding admin with a fresh bootstrap code.
func (w *world) found(name string, withPresence bool) string {
	w.t.Helper()
	code, _, err := w.iss.IssueBootstrapCode(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	key := newFakeKey(w.t, withPresence)
	res, err := w.iss.Enroll(context.Background(), w.enrollRequest(key, name, code, testDomain), issuerFP)
	if err != nil {
		w.t.Fatal(err)
	}
	if !res.Approved {
		w.t.Fatal("founding device not approved")
	}
	w.keys[res.DeviceID] = key
	w.names[res.DeviceID] = name
	return res.DeviceID
}

// enroll enrolls a device and returns its pending code and id.
func (w *world) enroll(name string, withPresence bool) (code, deviceID string) {
	w.t.Helper()
	key := newFakeKey(w.t, withPresence)
	res, err := w.iss.Enroll(context.Background(), w.enrollRequest(key, name, "", testDomain), issuerFP)
	if err != nil {
		w.t.Fatal(err)
	}
	if res.Approved {
		w.t.Fatal("non-founding device approved without an admin")
	}
	w.keys[res.DeviceID] = key
	w.names[res.DeviceID] = name
	return res.Code, res.DeviceID
}

// sign is the device side of a signed record: Prepare, then presence.Sign
// (or the device-key path for a none-level device).
func (w *world) sign(deviceID string, action Action, subject string) Signature {
	w.t.Helper()
	sig, err := w.trySign(deviceID, action, subject)
	if err != nil {
		w.t.Fatalf("sign %s %s as %s: %v", action, subject, w.names[deviceID], err)
	}
	return sig
}

func (w *world) trySign(deviceID string, action Action, subject string) (Signature, error) {
	ts, err := w.iss.Prepare(deviceID, action, subject)
	if err != nil {
		return Signature{}, err
	}
	key := w.keys[deviceID]
	var a *presence.Assertion
	if key.presence != nil {
		a, err = presence.Sign(context.Background(), key, ts.Input)
	} else {
		a, err = SignWithoutPresence(context.Background(), key, ts.Input)
	}
	if err != nil {
		return Signature{}, err
	}
	return Signature{DeviceID: deviceID, Assertion: a}, nil
}

// forge builds a signature WITHOUT Prepare's preflight, the way a modified
// client would: it mints its own challenge and signs the right bytes for
// the action. It exists to prove the apply path refuses on its own.
func (w *world) forge(deviceID string, action Action, subject string) Signature {
	w.t.Helper()
	digest, err := w.iss.digestFor(action, subject)
	if err != nil {
		w.t.Fatal(err)
	}
	ch, err := w.ver.Mint(deviceID)
	if err != nil {
		w.t.Fatal(err)
	}
	in := presence.SigningInput{DeviceID: deviceID, Tool: SigningTool, Target: Target(action, subject), Challenge: ch, RequestHash: digest}
	key := w.keys[deviceID]
	var a *presence.Assertion
	if key.presence != nil {
		a, err = presence.Sign(context.Background(), key, in)
	} else {
		a, err = SignWithoutPresence(context.Background(), key, in)
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return Signature{DeviceID: deviceID, Assertion: a}
}

// approveAs has admin approve the pending code.
func (w *world) approveAs(admin, code string) (*EnrollmentRecord, error) {
	w.t.Helper()
	sig, err := w.trySign(admin, ActionApprove, code)
	if err != nil {
		return nil, err
	}
	return w.iss.Approve(context.Background(), code, sig)
}

// enrolled enrolls and approves a device in one go.
func (w *world) enrolled(admin, name string, withPresence bool) string {
	w.t.Helper()
	code, id := w.enroll(name, withPresence)
	if _, err := w.approveAs(admin, code); err != nil {
		w.t.Fatal(err)
	}
	return id
}

// attest builds an Attested the way the exchange handler would, through a
// self-signed certificate and AttestPeer, so the provenance extension is
// exercised on every path.
func (w *world) attest(id spiffe.ID, c Claims) *Attested {
	w.t.Helper()
	a, err := w.tryAttest(id, c)
	if err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *world) tryAttest(id spiffe.ID, c Claims) (*Attested, error) {
	ext, err := ProvenanceExtension(c)
	if err != nil {
		return nil, err
	}
	cert := selfSigned(w.t, idString(id), ext)
	return AttestPeer([][]*x509.Certificate{{cert}})
}

func toolID(device, tool string) spiffe.ID {
	return spiffe.ID{TrustDomain: testDomain, DeviceID: device, Tool: tool}
}

func agentID(device, agent string) spiffe.ID {
	return spiffe.ID{TrustDomain: testDomain, DeviceID: device, Agent: agent}
}

func delegatedClaims(g *presence.Grant) Claims {
	return Claims{ProtectionLevel: spiffe.ProtectionHardware, State: presence.StateDelegated, Provenance: g.Provenance()}
}

func presentClaims() Claims {
	return Claims{ProtectionLevel: spiffe.ProtectionHardware, State: presence.StatePresent}
}

func mustErr(t *testing.T, got, want error) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("unexpected error: %v", got)
		}
		return
	}
	if !errors.Is(got, want) {
		t.Fatalf("got error %v, want %v", got, want)
	}
}

func wideScope() presence.Scope {
	return presence.Scope{
		AWSProfiles:  []string{"dev", "staging", "prod-admin"},
		GitHubScopes: []string{"infamousjoeg/totem:contents:write", "infamousjoeg/totem:contents:read"},
		Capabilities: []string{"homeassistant/sensor.freezer#read", "homeassistant/lock.front_door#unlock"},
		ClaudeProxy:  true,
		SpendCapUSD:  50,
		Money:        presence.Money{PerTransactionUSD: 20, PerDayUSD: 100, StepUpAboveUSD: 5},
	}
}

func reqHash(parts ...string) []byte {
	b := make([][]byte, len(parts))
	for i, p := range parts {
		b[i] = []byte(p)
	}
	return presence.HashRequest(b...)
}

func ctxb() context.Context { return context.Background() }

func fmtDev(w *world, id string) string { return fmt.Sprintf("%s(%s)", w.names[id], id[:6]) }
