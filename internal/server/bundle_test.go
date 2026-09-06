package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/infamousjoeg/totem/internal/ca"
)

// serverWithCA builds a front door over a real certificate authority.
func serverWithCA(t *testing.T, authority ca.Authority) *Server {
	t.Helper()
	id, err := GenerateIdentity(t.TempDir(), []string{testTrustDomain}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		TrustDomain: testTrustDomain,
		ExternalURL: "https://" + testTrustDomain,
		Identity:    id,
		CA:          authority,
		Engine:      &fakeEngine{},
		Audit:       NewAuditLog(&bytes.Buffer{}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// TestCRLsAreOnePerIntermediateAndNeverMerged.
//
// A CRL is signed by the CA that issued the certificates it revokes. During a
// rotation overlap there are up to three live intermediates, and a single list
// signed by the current one is silently IGNORED by a correct verifier for every
// serial the outgoing one issued. That means the revocations that matter most,
// the ones outstanding across a rotation, are exactly the ones that stop
// working, and revocation failing open is indistinguishable from nothing having
// been revoked. So the count is a property of the schedule, and this test
// asserts it stays that way.
func TestCRLsAreOnePerIntermediateAndNeverMerged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority, _, clock := realCA(t)
	s := serverWithCA(t, authority)

	read := func() []CRLView {
		t.Helper()
		w := get(t, s, "/v1/crls")
		if w.Code != http.StatusOK {
			t.Fatalf("GET /v1/crls: %d %s", w.Code, w.Body.String())
		}
		var out []CRLView
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	liveIntermediates := func() int {
		t.Helper()
		b, err := authority.Bundle(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return len(b.Intermediates)
	}

	first := read()
	if len(first) != liveIntermediates() {
		t.Fatalf("got %d CRLs for %d live intermediates", len(first), liveIntermediates())
	}
	if len(first) != 1 {
		t.Fatalf("a freshly initialised CA has %d live intermediates, want 1", len(first))
	}

	// Open the overlap: two intermediates are live and both must publish.
	sched, err := authority.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	*clock = sched.RotateAfter.Add(time.Hour)
	if _, err := authority.RotateIntermediate(ctx); err != nil {
		t.Fatalf("preparing a successor: %v", err)
	}

	during := read()
	if n := liveIntermediates(); len(during) != n {
		t.Fatalf("during the overlap: got %d CRLs for %d live intermediates; a merged list would be silently ignored "+
			"for every serial the other intermediate issued", len(during), n)
	}
	if len(during) < 2 {
		t.Fatalf("the overlap produced %d CRLs; the successor is published and must publish its own", len(during))
	}
	seen := map[string]bool{}
	for _, c := range during {
		if c.IssuerSubjectKeyID == "" {
			t.Error("a CRL does not say which intermediate signed it, so a verifier cannot scope it")
		}
		if seen[c.IssuerSubjectKeyID] {
			t.Errorf("two CRLs claim the same signing intermediate %s", c.IssuerSubjectKeyID)
		}
		seen[c.IssuerSubjectKeyID] = true
		if len(c.DER) == 0 {
			t.Error("a CRL carries no signed bytes")
		}
		if !c.NextUpdate.After(c.ThisUpdate) {
			t.Errorf("CRL %s has NextUpdate %s at or before ThisUpdate %s; a relying party past NextUpdate fails open",
				c.IssuerSubjectKeyID, c.NextUpdate, c.ThisUpdate)
		}
	}
}

// TestBundlePublishesCurrentPlusNext. "A bundle that contains only the signing
// intermediate is a bug, not an optimisation": a relying party that fetched
// during the overlap must already trust the intermediate about to sign, or a
// rotation is an outage.
func TestBundlePublishesCurrentPlusNext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	authority, _, clock := realCA(t)
	s := serverWithCA(t, authority)

	count := func() int {
		t.Helper()
		w := get(t, s, "/v1/bundle")
		if w.Code != http.StatusOK {
			t.Fatalf("GET /v1/bundle: %d %s", w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
			t.Errorf("bundle content type %q", ct)
		}
		if w.Header().Get("Totem-Bundle-Generated") == "" {
			t.Error("the bundle does not say when its roles were evaluated, so a client cannot tell how stale a cache is")
		}
		n := 0
		rest := w.Body.Bytes()
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return n
			}
			if block.Type != "CERTIFICATE" {
				t.Fatalf("the bundle contains a %q block", block.Type)
			}
			n++
		}
	}

	before := count()
	if before < 2 {
		t.Fatalf("a fresh bundle has %d certificates, want at least a root and an intermediate", before)
	}

	sched, err := authority.Schedule(ctx)
	if err != nil {
		t.Fatal(err)
	}
	*clock = sched.RotateAfter.Add(time.Hour)
	if _, err := authority.RotateIntermediate(ctx); err != nil {
		t.Fatal(err)
	}
	if after := count(); after != before+1 {
		t.Fatalf("after preparing a successor the bundle has %d certificates, want %d; "+
			"a relying party that fetched during the overlap must already trust the one about to sign", after, before+1)
	}
}

// TestBundleAndCRLsAreOpen. Requiring a credential to fetch the thing that
// verifies credentials is a bootstrap loop.
func TestBundleAndCRLsAreOpen(t *testing.T) {
	t.Parallel()
	authority, _, _ := realCA(t)
	s := serverWithCA(t, authority)
	for _, path := range []string{"/v1/bundle", "/v1/crls"} {
		if w := get(t, s, path); w.Code != http.StatusOK {
			t.Errorf("%s with no credential: %d", path, w.Code)
		}
	}
}

// TestBundleBeforeInitIsRetryableNotTerminal. An issuer still starting up is
// "not yet", and a client told "no" permanently gives up on something that is
// about to work.
func TestBundleBeforeInitIsRetryableNotTerminal(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t, &fakeEngine{}) // no CA wired
	for _, path := range []string{"/v1/bundle", "/v1/crls"} {
		w := get(t, s, path)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: got %d, want 503", path, w.Code)
		}
		if w.Header().Get("Retry-After") == "" {
			t.Errorf("%s: a 'not yet' answer must say when to come back", path)
		}
	}
}

// TestTTLRefusalNamesTheActualLimit. internal/ca refuses rather than clamps,
// because a caller that asked for eight hours and quietly got one discovers it
// during an outage. A refusal that does not say the limit leaves the caller
// guessing, and it will guess in the direction that fails later.
func TestTTLRefusalNamesTheActualLimit(t *testing.T) {
	t.Parallel()
	e := classify(fmt.Errorf("minting: %w", ca.ErrTTLTooLong))
	if e.status != http.StatusBadRequest {
		t.Errorf("status %d, want 400: asking for an impossible lifetime is a caller bug, not a transient one", e.status)
	}
	limit := ca.MaxSVIDTTL.String()
	if !strings.Contains(e.what, limit) {
		t.Errorf("the refusal does not name the limit %s: %q", limit, e.what)
	}
	if !strings.Contains(e.fix, limit) {
		t.Errorf("the fix does not name the limit %s: %q", limit, e.fix)
	}
	if strings.Contains(strings.ToLower(e.what), "clamp") || strings.Contains(strings.ToLower(e.fix), "shorten") &&
		!strings.Contains(e.fix, "does not shorten") {
		t.Error("the message implies the issuer might shorten a credential instead of refusing")
	}
}
