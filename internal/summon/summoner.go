package summon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Summoner is the Resolver implementation: the one path a secret takes into
// the issuer. It execs the configured Summon provider (or reads the built-in
// file provider), holds what comes back in mlocked memory, re-checks the
// hardening on every resolve, and rotates on an interval and on SIGHUP.
//
// There is no constructor, option, or field that lets a caller put a value in
// by hand. That absence is the package's entire purpose: a convenience seam
// for injecting a secret is the thing this exists to prevent.
type Summoner struct {
	cfg         Config
	timeout     time.Duration
	rotateEvery time.Duration
	retireAfter time.Duration
	log         *slog.Logger

	// trustedUID is an extra accepted owner for the provider chain, alongside
	// root. It is rootUID in production and is set to anything else only by
	// the test binary, so that the ownership refusal can be exercised by a
	// test that does not run as root.
	trustedUID int

	// byName maps a logical secret name to its Secret; known is the set of
	// references this Summoner will resolve at all. A reference that is not
	// configured is refused rather than passed through to the provider.
	// nameOf goes back the other way so an alarm can name the secret the way
	// the operator's config does.
	byName map[string]Secret
	known  map[Reference]bool
	nameOf map[Reference]string
	// sealed is the set of references declared RotationSealsDataAtRest. They
	// are resolved at start and compared on every rotation cycle, but never
	// replaced by one.
	sealed map[Reference]bool

	mu       sync.Mutex
	rotateMu sync.Mutex
	started  bool
	closed   bool
	fatal    error
	cache    map[Reference]*secret
	// drift holds the sealed references whose provider value no longer matches
	// the value the issuer's on-disk material is sealed under.
	drift    map[Reference]bool
	timers   map[uint64]*time.Timer
	timerSeq uint64

	stop chan struct{}
	hup  chan os.Signal
	wg   sync.WaitGroup
}

// Summoner implements the frozen Resolver contract.
var _ Resolver = (*Summoner)(nil)

// New validates a Config and returns a Summoner that has not touched the
// filesystem yet. Every configured reference is validated here, so a bad
// reference or a missing pin fails at config load rather than at first use.
func New(cfg Config) (*Summoner, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Summoner{
		cfg:         cfg,
		timeout:     cfg.timeout(),
		rotateEvery: cfg.rotateEvery(),
		retireAfter: cfg.retireAfter(),
		log:         cfg.logger(),
		trustedUID:  rootUID,
		byName:      make(map[string]Secret, len(cfg.Refs)),
		known:       make(map[Reference]bool, len(cfg.Refs)),
		nameOf:      make(map[Reference]string, len(cfg.Refs)),
		sealed:      make(map[Reference]bool),
		cache:       make(map[Reference]*secret, len(cfg.Refs)),
		drift:       make(map[Reference]bool),
		timers:      make(map[uint64]*time.Timer),
		stop:        make(chan struct{}),
	}
	for name, sec := range cfg.Refs {
		s.byName[name] = sec
		s.known[sec.Ref] = true
		s.nameOf[sec.Ref] = name
		if sec.Rotation == RotationSealsDataAtRest {
			s.sealed[sec.Ref] = true
		}
	}
	return s, nil
}

// Start runs the start-time half of the hardening, resolves every configured
// reference once, and begins rotation.
//
// The order matters. Core dumps are disabled before any value exists, so there
// is no window in which a crash could write one out. The config file and the
// provider chain are checked before the provider is run. The pin is verified
// before the provider is exec'd, not after. And every reference is resolved
// here, so a missing secret stops the issuer at start rather than at the first
// exchange that needed it.
func (s *Summoner) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("summon: already started")
	}
	if s.closed {
		return fmt.Errorf("summon: closed")
	}
	if err := disableCoreDumps(); err != nil {
		return err
	}
	if err := s.checkHardening(); err != nil {
		return err
	}
	hash, err := s.verifyPin()
	if err != nil {
		return err
	}
	if s.usesFileProvider() {
		warnFileProvider(s.cfg.File.Dir, s.log)
	}
	s.log.Info("summon: provider trusted",
		"provider", s.providerName(),
		"provider_sha256", hash,
		"references", len(s.known),
		"rotate_every", s.rotateEvery.String())

	for name, decl := range s.byName {
		sec, err := s.fetch(ctx, decl.Ref)
		if err != nil {
			s.wipeAllLocked()
			return fmt.Errorf("summon: resolving %s at start: %w", name, err)
		}
		s.cache[decl.Ref] = sec
	}
	// SIGHUP is registered here rather than inside the loop goroutine, so
	// that by the time Start returns the signal is already being caught. A
	// HUP that arrived in the gap would otherwise hit the default action and
	// kill the issuer.
	s.hup = make(chan os.Signal, 1)
	signal.Notify(s.hup, syscall.SIGHUP)
	s.started = true
	s.wg.Add(1)
	go s.run(ctx)
	return nil
}

// Resolve returns the current value for ref.
//
// It runs the full hardening on EVERY call, not only when it has to exec the
// provider: the config file, the provider binary and every directory on its
// path are re-checked, and the pinned hash is re-verified and logged. That is
// the point of the rule. A start-only check would let an attacker who can
// write the provider's directory swap the binary while the issuer runs, and a
// cached value served without re-checking would hide the swap until the next
// rotation.
//
// A hardening failure is fatal: the Summoner wipes every value it holds and
// every later Resolve returns the same error, so the issuer cannot keep
// serving secrets that were resolved by a provider it no longer trusts.
//
// ref is the configured Reference, not the logical name; use Ref to go from
// one to the other. A reference that is not in the config is refused with
// ErrNoSuchReference rather than passed to the provider, so a bug elsewhere in
// the issuer cannot turn into arbitrary secret retrieval.
func (s *Summoner) Resolve(ctx context.Context, ref Reference) (Value, error) {
	if err := validateReference(ref); err != nil {
		return zeroValue{}, err
	}
	if err := s.checkState(ref); err != nil {
		return zeroValue{}, err
	}
	// The path and pin checks read the filesystem and hash the provider, so
	// they run without the value lock held: a resolve must not be able to
	// stall every other resolve for the length of a stat storm.
	if err := s.checkHardening(); err != nil {
		s.poison(err)
		return zeroValue{}, err
	}
	hash, err := s.verifyPin()
	if err != nil {
		s.poison(err)
		return zeroValue{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fatal != nil {
		return zeroValue{}, s.fatal
	}
	if s.closed {
		return zeroValue{}, fmt.Errorf("summon: closed")
	}
	sec, cached := s.cache[ref]
	if !cached {
		sec, err = s.fetch(ctx, ref)
		if err != nil {
			return zeroValue{}, err
		}
		s.cache[ref] = sec
	}
	s.log.Info("summon: resolve",
		"reference", string(ref),
		"provider", s.providerName(),
		"provider_sha256", hash,
		"cached", cached)
	if s.drift[ref] {
		// Every single resolve, not once: the operator has to be able to see
		// this from whatever they happen to be looking at, and the window in
		// which the value in use is still in memory is the only window in
		// which the fix is cheap.
		s.log.Error(sealAlarm(s.nameOf[ref], ref))
	}
	return sec.acquire(), nil
}

// checkState reports whether this Summoner will serve ref at all, before any
// filesystem work is done for it.
func (s *Summoner) checkState(ref Reference) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fatal != nil {
		return s.fatal
	}
	if !s.started {
		return fmt.Errorf("summon: Start has not been called")
	}
	if s.closed {
		return fmt.Errorf("summon: closed")
	}
	if !s.known[ref] {
		return fmt.Errorf("%w: %q", ErrNoSuchReference, ref)
	}
	return nil
}

// Refs returns the logical secret names this resolver is configured for,
// sorted, so startup can fail on a missing reference rather than at first use.
func (s *Summoner) Refs() []string {
	names := make([]string, 0, len(s.byName))
	for name := range s.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Ref returns the Reference configured under a logical name, or
// ErrNoSuchReference. It is how a caller that knows it needs the CA passphrase
// gets the reference to resolve without holding the config itself.
func (s *Summoner) Ref(name string) (Reference, error) {
	decl, ok := s.byName[name]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNoSuchReference, name)
	}
	return decl.Ref, nil
}

// Err reports the fatal error that stopped this Summoner, if any. The issuer
// treats a non-nil Err as terminal: it holds no usable secrets any more.
func (s *Summoner) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatal
}

// Rotate re-resolves every configured reference now. It is what the interval
// and SIGHUP both call.
//
// Replacement is atomic per reference: the new value is fully resolved before
// the old one is swapped out, so a request either sees the old value or the
// new one and never an empty slot, and nothing restarts. The superseded value
// stays readable for RetireAfter so an in-flight request finishes against it,
// and is then zeroed whether or not its holder released it.
//
// A provider failure during rotation keeps the old value and logs: a
// transient failure to reach the secrets backend must not take the issuer's
// existing credentials away. A hardening or pin failure is different and is
// fatal, because it means the provider that produced those values is no longer
// one to trust.
func (s *Summoner) Rotate(ctx context.Context) error {
	// One rotation at a time: the interval and a SIGHUP can arrive together,
	// and two rotations racing would each retire the other's value.
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()

	s.mu.Lock()
	if s.fatal != nil {
		err := s.fatal
		s.mu.Unlock()
		return err
	}
	if !s.started || s.closed {
		s.mu.Unlock()
		return fmt.Errorf("summon: not running")
	}
	names := make(map[string]Secret, len(s.byName))
	for name, decl := range s.byName {
		names[name] = decl
	}
	s.mu.Unlock()

	if err := s.checkHardening(); err != nil {
		s.poison(err)
		return err
	}
	if _, err := s.verifyPin(); err != nil {
		s.poison(err)
		return err
	}

	var firstErr error
	for name, decl := range names {
		if decl.Rotation == RotationSealsDataAtRest {
			// Not replaced, checked. See checkSealed.
			s.checkSealed(ctx, name, decl.Ref)
			continue
		}
		// The provider runs with no lock held, so resolves keep being served
		// from the current values for as long as rotation takes.
		sec, err := s.fetch(ctx, decl.Ref)
		if err != nil {
			s.log.Error("summon: rotation kept the previous value", "name", name, "reference", string(decl.Ref), "error", err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.mu.Lock()
		if s.closed || s.fatal != nil {
			s.mu.Unlock()
			sec.discard()
			return firstErr
		}
		old := s.cache[decl.Ref]
		s.cache[decl.Ref] = sec
		s.retireLocked(old)
		s.mu.Unlock()
		s.log.Info("summon: rotated", "name", name, "reference", string(decl.Ref))
	}
	return firstErr
}

// checkSealed compares what the provider returns now for a sealed reference
// with the value the issuer is running on, and REPLACES NOTHING.
//
// This is the detector for the failure that made the exclusion necessary. The
// value seals material on disk. If it is replaced, the running process is fine
// because that material is already open in memory, and the next start fails
// against files sealed under a value that is by then unreachable. The operator
// sees a CA that will not open and has no reason to connect it to a rotation
// weeks earlier.
//
// So the cycle that would have replaced the value instead asks whether it
// changed, and shouts if it did. The alarm is raised while the value in use is
// still in memory, which is the difference between an inconvenience and a lost
// CA: at that moment both halves of a re-seal are still available.
//
// A provider that cannot be reached is a warning, not an alarm and not a fatal
// error: not knowing whether the value changed is a different thing from
// knowing that it did.
func (s *Summoner) checkSealed(ctx context.Context, name string, ref Reference) {
	probe, err := s.fetch(ctx, ref)
	if err != nil {
		s.log.Warn("summon: could not check a sealed secret for drift",
			"name", name, "reference", string(ref), "error", err.Error())
		return
	}
	s.mu.Lock()
	cur, ok := s.cache[ref]
	same := ok && cur.sameAs(probe)
	if same {
		delete(s.drift, ref)
	} else {
		s.drift[ref] = true
	}
	s.mu.Unlock()
	// The probe never becomes a served value and never outlives this check.
	probe.discard()

	if same {
		s.log.Debug("summon: sealed secret unchanged", "name", name, "reference", string(ref))
		return
	}
	s.log.Error(sealAlarm(name, ref))
}

// sealAlarm is the one wording for the drift alarm, so the rotation cycle and
// every resolve say the same thing. It names the secret and the fix and
// carries no part of either value.
func sealAlarm(name string, ref Reference) string {
	if name == "" {
		name = string(ref)
	}
	return "summon: SEALED SECRET CHANGED: the provider now returns a different value for " + name +
		" (" + string(ref) + "), but the material this issuer keeps on disk is still sealed under the value in use. " +
		"THIS ISSUER WILL NOT RESTART until that material is re-sealed. Re-seal it now, while the value in use is still in memory " +
		"(for the CA passphrase: `totem issuer reseal-ca`), then confirm the reseal so the new value is adopted. " +
		"Until then the old value is being served and nothing has been replaced."
}

// Drifted returns the logical names of sealed secrets whose provider value no
// longer matches the value in use, sorted. `issuer status` and `doctor` surface
// it, so the alarm is visible to someone who is looking rather than only to
// someone reading logs.
func (s *Summoner) Drifted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.drift))
	for ref := range s.drift {
		if n, ok := s.nameOf[ref]; ok {
			names = append(names, n)
		} else {
			names = append(names, string(ref))
		}
	}
	sort.Strings(names)
	return names
}

// ResealCompleted adopts the provider's current value for a sealed secret and
// clears its alarm. It is the second half of rotating a value that seals
// material at rest, and it is called only after the FIRST half has actually
// happened: the material on disk has been re-sealed under the new value.
//
// Nothing calls this on its own. An automatic adoption would be the very
// rotation this exclusion exists to prevent, just with extra steps: it would
// leave the running process fine and the next start broken. It exists so that
// `totem issuer reseal-ca`, having re-sealed the CA key files, can tell this
// package the world changed underneath it.
//
// Calling it without having re-sealed anything is how you brick the issuer by
// hand. The refusal it cannot make for you is the one where you have not.
func (s *Summoner) ResealCompleted(ctx context.Context, name string) error {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()

	s.mu.Lock()
	if s.fatal != nil {
		err := s.fatal
		s.mu.Unlock()
		return err
	}
	if !s.started || s.closed {
		s.mu.Unlock()
		return fmt.Errorf("summon: not running")
	}
	decl, ok := s.byName[name]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %q", ErrNoSuchReference, name)
	}
	if decl.Rotation != RotationSealsDataAtRest {
		s.mu.Unlock()
		return fmt.Errorf("summon: %q is declared %s, not a secret that seals material at rest; it rotates on its own and needs no reseal", name, decl.Rotation)
	}
	wasDrifted := s.drift[decl.Ref]
	s.mu.Unlock()

	if err := s.checkHardening(); err != nil {
		s.poison(err)
		return err
	}
	if _, err := s.verifyPin(); err != nil {
		s.poison(err)
		return err
	}
	sec, err := s.fetch(ctx, decl.Ref)
	if err != nil {
		return fmt.Errorf("summon: resolving %s after a reseal: %w", name, err)
	}
	s.mu.Lock()
	if s.closed || s.fatal != nil {
		s.mu.Unlock()
		sec.discard()
		return fmt.Errorf("summon: not running")
	}
	old := s.cache[decl.Ref]
	s.cache[decl.Ref] = sec
	delete(s.drift, decl.Ref)
	s.retireLocked(old)
	s.mu.Unlock()
	s.log.Warn("summon: reseal confirmed, the new value is now in use",
		"name", name, "reference", string(decl.Ref), "was_drifted", wasDrifted)
	return nil
}

// Close stops rotation and zeroes every value this Summoner holds.
func (s *Summoner) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.hup != nil {
		signal.Stop(s.hup)
	}
	close(s.stop)
	s.wipeAllLocked()
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// run is the rotation loop: pull-based on an interval, and on SIGHUP.
func (s *Summoner) run(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.rotateEvery)
	defer ticker.Stop()
	hup := s.hup
	defer signal.Stop(hup)
	for {
		select {
		case <-s.stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.rotateFromLoop(ctx, "interval")
		case <-hup:
			s.rotateFromLoop(ctx, "SIGHUP")
		}
	}
}

func (s *Summoner) rotateFromLoop(ctx context.Context, cause string) {
	rctx, cancel := context.WithTimeout(ctx, s.timeout*time.Duration(len(s.byName)+1))
	defer cancel()
	if err := s.Rotate(rctx); err != nil {
		s.log.Error("summon: rotation failed", "cause", cause, "error", err.Error())
		return
	}
	s.log.Info("summon: rotation complete", "cause", cause)
}

// checkHardeningLocked re-runs the path rules on the config file and the
// provider. It is called at start, on every resolve, and before every
// rotation.
func (s *Summoner) checkHardening() error {
	if err := checkTree(s.cfg.Path, s.trustedUID); err != nil {
		return err
	}
	if s.usesFileProvider() {
		// The file provider's directory holds the issuer's own files rather
		// than system binaries, so it may be owned by the issuer as well as by
		// root. It still may not be group- or world-writable: a directory
		// anyone can write is a secret anyone can replace.
		return checkTree(s.cfg.File.Dir, os.Geteuid())
	}
	return checkTree(s.cfg.Provider.Path, s.trustedUID)
}

// verifyPinLocked hashes the provider binary and compares it with the hash
// pinned at issuer init, returning the hash so the caller can log it.
//
// A mismatch is ErrProviderUntrusted and never a re-pin. Re-pinning on
// mismatch would make the pin a record of whatever binary is there now, which
// is precisely what an attacker who replaced it is counting on. The fix is a
// deliberate `totem issuer trust-provider`.
//
// The hash is recomputed on every resolve rather than remembered from start,
// which is what makes it a check rather than a memory. A residual race
// remains and is worth stating plainly: the binary is hashed and then exec'd
// as two operations, so a swap in between is not caught by this check. The
// path rules are what close that window, by requiring that only root can write
// the directory the binary sits in.
func (s *Summoner) verifyPin() (string, error) {
	if s.usesFileProvider() {
		return "", nil
	}
	hash, err := hashFile(s.cfg.Provider.Path)
	if err != nil {
		return "", err
	}
	if !equalHash(hash, s.cfg.Provider.PinnedHash) {
		return "", fmt.Errorf("%w: %s hashes to %s, pinned %s; run `totem issuer trust-provider` if you changed it on purpose",
			ErrProviderUntrusted, s.cfg.Provider.Path, hash, s.cfg.Provider.PinnedHash)
	}
	return hash, nil
}

// fetchLocked runs whichever provider is configured.
func (s *Summoner) fetch(ctx context.Context, ref Reference) (*secret, error) {
	if s.usesFileProvider() {
		return readFileSecret(s.cfg.File.Dir, ref, os.Geteuid())
	}
	return s.runProvider(ctx, ref)
}

// retireLocked drops the cache's hold on a superseded value and schedules the
// forced wipe that ends the in-flight window.
func (s *Summoner) retireLocked(old *secret) {
	if old == nil {
		return
	}
	old.retire()
	s.timerSeq++
	id := s.timerSeq
	s.timers[id] = time.AfterFunc(s.retireAfter, func() {
		old.wipe()
		s.mu.Lock()
		delete(s.timers, id)
		s.mu.Unlock()
	})
}

// poison takes the lock and records a fatal hardening failure.
func (s *Summoner) poison(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poisonLocked(err)
}

// poisonLocked records a fatal hardening failure and destroys every value the
// Summoner holds. Once poisoned, every Resolve returns the same error: a
// provider that failed its checks must not keep serving from the values it
// produced before it failed them.
func (s *Summoner) poisonLocked(err error) {
	if s.fatal == nil {
		s.fatal = err
		s.log.Error("summon: refusing to serve secrets", "error", err.Error())
	}
	s.wipeAllLocked()
}

// wipeAllLocked zeroes every cached value immediately.
func (s *Summoner) wipeAllLocked() {
	for ref, sec := range s.cache {
		sec.retire()
		sec.wipe()
		delete(s.cache, ref)
	}
	for id, t := range s.timers {
		t.Stop()
		delete(s.timers, id)
	}
}

func (s *Summoner) usesFileProvider() bool { return s.cfg.Provider.Path == "" }

func (s *Summoner) providerName() string {
	if s.usesFileProvider() {
		return "file:" + s.cfg.File.Dir
	}
	return s.cfg.Provider.Path
}
