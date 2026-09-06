package workloadapi

import (
	"context"
	"errors"
	"time"
)

// Errors a Source raises. They are typed because internal/errors branches on
// them: an unreachable issuer is retryable and a harness should back off and
// try again, while an unenrolled device is terminal until a human enrolls it.
// There is no offline grace for credentials themselves, so neither error ever
// results in a cached SVID being served past its life.
var (
	// ErrIssuerUnreachable is the retryable one. docs/totem-design.md
	// "Experience": "Issuer unreachable" includes the issuer address and when
	// it was last reached, and a harness branches on the exit code and
	// ~/.totem/last-error rather than on the calling tool's prose.
	ErrIssuerUnreachable = errors.New("workloadapi: issuer unreachable")
	// ErrNotEnrolled means the device has no enrollment, so there is no
	// identity to derive and nothing to ask the issuer for.
	ErrNotEnrolled = errors.New("workloadapi: device is not enrolled")
	// ErrSourceUnavailable means no credential source is wired into this
	// agent at all. It is the honest state of the agent before the issuer
	// exists, and it is reported as an unavailable service rather than as a
	// rejection of the caller.
	ErrSourceUnavailable = errors.New("workloadapi: no credential source configured")
)

// X509SVID is one X509-SVID exactly as the Workload API puts it on the wire.
// The field encodings are the proto's, not a convenience shape: a stock
// go-spiffe client hands X509Svid and X509SvidKey straight to
// x509svid.ParseRaw, which requires a concatenated DER chain with the leaf
// first and an unencrypted PKCS#8 DER key.
type X509SVID struct {
	// ID is the derived SPIFFE ID this SVID belongs to.
	ID string
	// CertChainDER is the ASN.1 DER encoded certificate chain, concatenated
	// with no padding, leaf first.
	CertChainDER []byte
	// KeyPKCS8DER is the ASN.1 DER encoded PKCS#8 private key, unencrypted.
	// ECDSA P-256, per docs/totem-design.md "Algorithms and FIPS".
	KeyPKCS8DER []byte
	// BundleDER is the ASN.1 DER encoded X.509 bundle for the trust domain,
	// which is what the SVID must chain to.
	BundleDER []byte
	// Hint is the optional operator guidance string; totem leaves it empty.
	Hint string
	// IssuedAt is when the issuer minted this SVID.
	IssuedAt time.Time
	// ExpiresAt is when it stops being usable. The device identity is one
	// hour, per docs/totem-design.md "Agent (laptop)".
	ExpiresAt time.Time
}

// RenewAt is the half-life of this SVID, which is when the agent renews it. The
// spec sets a one-hour device SVID lifetime with renewal at half-life, so a
// client holding an X509-SVID stream is pushed a fresh SVID roughly every
// thirty minutes and never polls for one.
func (s *X509SVID) RenewAt() time.Time {
	if s == nil || s.ExpiresAt.IsZero() {
		return time.Time{}
	}
	start := s.IssuedAt
	if start.IsZero() || !start.Before(s.ExpiresAt) {
		return s.ExpiresAt
	}
	return start.Add(s.ExpiresAt.Sub(start) / 2)
}

// JWTSVID is one JWT-SVID in JWS Compact Serialization, with the metadata the
// Workload API returns alongside it.
type JWTSVID struct {
	// ID is the derived SPIFFE ID this token was minted for.
	ID string
	// Token is the encoded JWT using JWS Compact Serialization.
	Token string
	// Hint is the optional operator guidance string; totem leaves it empty.
	Hint string
	// ExpiresAt is the token expiry. Five minutes for the Octo STS profile,
	// per decision 11.
	ExpiresAt time.Time
}

// Source is where credentials come from. In v1 the only implementation is the
// issuer client: the laptop holds no durable credential material, so every
// method here is a call to the broker and every one of them can fail with
// ErrIssuerUnreachable. The interface exists so the Workload API server can be
// built, tested, and conformance-checked before the issuer does.
//
// Nothing in this interface takes an attestation result. Attestation happens
// once per connection at accept time and produces the derived identity that is
// passed in here; a Source never re-decides who the caller is.
type Source interface {
	// FetchX509SVID returns the current X509-SVID for a derived identity,
	// minting or renewing it at the issuer as needed.
	FetchX509SVID(ctx context.Context, id Derived) (*X509SVID, error)
	// FetchJWTSVID returns a JWT-SVID for a derived identity and audience.
	FetchJWTSVID(ctx context.Context, id Derived, audience []string) (*JWTSVID, error)
	// X509Bundles returns the ASN.1 DER X.509 bundles the workload should
	// trust, keyed by the SPIFFE ID of the trust domain they belong to.
	X509Bundles(ctx context.Context) (map[string][]byte, error)
	// JWTBundles returns the JWKS documents the workload should trust for
	// JWT-SVID validation, keyed by the SPIFFE ID of the trust domain.
	JWTBundles(ctx context.Context) (map[string][]byte, error)
}

// unavailableSource is the Source an agent has before it is connected to an
// issuer. It fails every call with ErrSourceUnavailable rather than being nil,
// so the server has one code path and no handler has to nil-check.
type unavailableSource struct{}

func (unavailableSource) FetchX509SVID(context.Context, Derived) (*X509SVID, error) {
	return nil, ErrSourceUnavailable
}

func (unavailableSource) FetchJWTSVID(context.Context, Derived, []string) (*JWTSVID, error) {
	return nil, ErrSourceUnavailable
}

func (unavailableSource) X509Bundles(context.Context) (map[string][]byte, error) {
	return nil, ErrSourceUnavailable
}

func (unavailableSource) JWTBundles(context.Context) (map[string][]byte, error) {
	return nil, ErrSourceUnavailable
}
