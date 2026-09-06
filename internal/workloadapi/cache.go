package workloadapi

import (
	"context"
	"sync"
	"time"
)

// svidCache holds the current X509-SVID per derived identity so that several
// open streams for the same identity share one issuer round trip, and so that
// renewal happens at half-life rather than on expiry.
//
// There is no offline grace: an entry past its expiry is dropped, never served.
// If the issuer is unreachable when a renewal comes due, the caller gets the
// retryable ErrIssuerUnreachable and no credential.
type svidCache struct {
	src   Source
	clock func() time.Time

	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	// fetching serializes concurrent renewals of the same identity so N open
	// streams cause one issuer call, not N. It is held across the network call
	// and therefore cannot also guard reads of svid, which `totem status` makes
	// while a fetch is in flight.
	fetching sync.Mutex
	// svid is guarded by svidCache.mu, not by fetching, so a status read never
	// blocks on the issuer and never races a renewal.
	svid *X509SVID
}

func newSVIDCache(src Source, clock func() time.Time) *svidCache {
	if src == nil {
		src = unavailableSource{}
	}
	if clock == nil {
		clock = time.Now
	}
	return &svidCache{src: src, clock: clock, entries: map[string]*cacheEntry{}}
}

func (c *svidCache) entryFor(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		e = &cacheEntry{}
		c.entries[key] = e
	}
	return e
}

// get returns a usable SVID for id, renewing it at the issuer when the cached
// one has passed its half-life or expired. It never returns an expired SVID.
func (c *svidCache) get(ctx context.Context, id Derived) (*X509SVID, error) {
	key := id.String()
	e := c.entryFor(key)

	e.fetching.Lock()
	defer e.fetching.Unlock()

	now := c.clock()
	if s := c.load(e); s != nil && now.Before(s.RenewAt()) {
		return s, nil
	}

	fresh, err := c.src.FetchX509SVID(ctx, id)
	if err != nil {
		// A still-valid cached SVID covers a blip between half-life and
		// expiry; that is renewal headroom the issuer minted, not offline
		// grace. Past expiry there is nothing to serve.
		if s := c.load(e); s != nil && now.Before(s.ExpiresAt) {
			return s, nil
		}
		c.store(e, nil)
		return nil, err
	}
	c.store(e, fresh)
	return fresh, nil
}

// load and store are the only readers and writers of an entry's SVID, both
// under svidCache.mu, so a status snapshot taken during a renewal sees either
// the old SVID or the new one and never a torn read.
func (c *svidCache) load(e *cacheEntry) *X509SVID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return e.svid
}

func (c *svidCache) store(e *cacheEntry, s *X509SVID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.svid = s
}

// current returns the cached SVID for id without contacting the issuer. It is
// what `totem status` reads through the runtime status file; it never triggers
// a fetch and never blocks on the network.
func (c *svidCache) current(id string) *X509SVID {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return nil
	}
	return e.svid
}

// waitForRenewal blocks until svid reaches its half-life, the context ends, or
// the maximum idle interval elapses. It is what makes the X509-SVID stream a
// push: the server sleeps here and writes the next SVID when it has one, and
// the client never polls.
func (c *svidCache) waitForRenewal(ctx context.Context, svid *X509SVID) error {
	const maxWait = 5 * time.Minute
	wait := maxWait
	if svid != nil {
		if d := svid.RenewAt().Sub(c.clock()); d < wait {
			wait = d
		}
	}
	if wait <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
