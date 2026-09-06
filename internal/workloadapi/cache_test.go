package workloadapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCacheRenewsAtHalfLife(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.lifetime = time.Hour

	now := time.Now()
	clock := func() time.Time { return now }
	c := newSVIDCache(src, clock)

	id, err := DeriveTool(testTrustDomain, testDeviceID, testTool)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := c.get(ctx, id); err != nil {
		t.Fatal(err)
	}
	if src.fetchCount() != 1 {
		t.Fatalf("fetches = %d, want 1", src.fetchCount())
	}

	// Just before half-life: still the cached SVID, no issuer call.
	now = now.Add(29 * time.Minute)
	if _, err := c.get(ctx, id); err != nil {
		t.Fatal(err)
	}
	if src.fetchCount() != 1 {
		t.Errorf("fetches = %d before half-life, want 1", src.fetchCount())
	}

	// Past half-life: renewed.
	now = now.Add(2 * time.Minute)
	if _, err := c.get(ctx, id); err != nil {
		t.Fatal(err)
	}
	if src.fetchCount() != 2 {
		t.Errorf("fetches = %d past half-life, want 2", src.fetchCount())
	}
}

// TestCacheHasNoOfflineGraceForExpiredCredentials is the spec rule: there is no
// offline grace window; an unreachable issuer is a clear error and nothing else.
func TestCacheHasNoOfflineGraceForExpiredCredentials(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.lifetime = time.Hour

	now := time.Now()
	c := newSVIDCache(src, func() time.Time { return now })
	id, _ := DeriveTool(testTrustDomain, testDeviceID, testTool)
	ctx := context.Background()

	if _, err := c.get(ctx, id); err != nil {
		t.Fatal(err)
	}

	src.setErr(ErrIssuerUnreachable)

	// Between half-life and expiry the issuer already granted headroom, so the
	// unexpired SVID still serves.
	now = now.Add(45 * time.Minute)
	if _, err := c.get(ctx, id); err != nil {
		t.Fatalf("an unexpired SVID must survive a blip: %v", err)
	}

	// Past expiry there is nothing to serve, and the error is the retryable one.
	now = now.Add(20 * time.Minute)
	_, err := c.get(ctx, id)
	if !errors.Is(err, ErrIssuerUnreachable) {
		t.Fatalf("err = %v, want ErrIssuerUnreachable", err)
	}
	if c.current(id.String()) != nil {
		t.Error("an expired SVID was kept in the cache")
	}
}

func TestRenewAtIsTheHalfLife(t *testing.T) {
	issued := time.Unix(1000, 0)
	s := &X509SVID{IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)}
	if got, want := s.RenewAt(), issued.Add(30*time.Minute); !got.Equal(want) {
		t.Errorf("RenewAt = %v, want %v", got, want)
	}
	var nilSVID *X509SVID
	if !nilSVID.RenewAt().IsZero() {
		t.Error("a nil SVID has no renewal time")
	}
}

// TestStatusSnapshotDoesNotRaceARenewal guards the split between the fetch lock
// and the field lock: `totem status` reads the current SVID while a renewal is
// in flight, and must never block on the issuer or see a torn value.
func TestStatusSnapshotDoesNotRaceARenewal(t *testing.T) {
	ca := newTestCA(t)
	src := newFakeSource(ca)
	src.lifetime = 2 * time.Millisecond // renew on essentially every call
	c := newSVIDCache(src, time.Now)
	id, err := DeriveTool(testTrustDomain, testDeviceID, testTool)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = c.get(ctx, id)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = c.current(id.String())
				}
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}
