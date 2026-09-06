package workloadapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// JWT-SVID validation is done locally, against the JWKS documents the source
// publishes, because the agent already holds the keys and the issuer should not
// be a round trip in a validation path. Only ECDSA is accepted: ES256 for
// SVIDs, with ES384 tolerated for a CA-signed token, per
// docs/totem-design.md "Algorithms and FIPS" (P-256 for SVIDs, P-384 for the
// CA, no Ed25519).

var (
	errMalformedToken = errors.New("it is not in the three-part form an identity token has")
	errUnknownKey     = errors.New("it was signed by a key this device does not trust")
	errBadSignature   = errors.New("its signature does not match")
	errExpired        = errors.New("it has expired")
	errNotYetValid    = errors.New("it is not valid yet")
	errWrongAudience  = errors.New("it was not issued for that audience")
	errNoSubject      = errors.New("it carries no identity")
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// validateJWTSVID checks a JWT-SVID against an audience using the JWKS bundles
// keyed by trust domain SPIFFE ID, and returns the token's SPIFFE ID and its
// claims. now is passed in so the check is testable and so clock handling lives
// in one place.
func validateJWTSVID(token, audience string, bundles map[string][]byte, now time.Time) (string, *structpb.Struct, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, errMalformedToken
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, errMalformedToken
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, errMalformedToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, errMalformedToken
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return "", nil, errMalformedToken
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return "", nil, errMalformedToken
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", nil, errNoSubject
	}
	id, err := spiffeid.FromString(sub)
	if err != nil {
		return "", nil, errNoSubject
	}

	jwks, ok := bundles[id.TrustDomain().IDString()]
	if !ok {
		return "", nil, errUnknownKey
	}
	key, err := publicKeyFromJWKS(jwks, hdr.Kid)
	if err != nil {
		return "", nil, err
	}
	if err := verifyES(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return "", nil, err
	}

	if err := checkTime(claims, now); err != nil {
		return "", nil, err
	}
	if !audienceContains(claims["aud"], audience) {
		return "", nil, errWrongAudience
	}

	st, err := structpb.NewStruct(claims)
	if err != nil {
		return "", nil, fmt.Errorf("its claims could not be read back: %w", err)
	}
	return id.String(), st, nil
}

// jwk is the subset of a JSON Web Key totem accepts: an EC public key on an
// approved curve.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// publicKeyFromJWKS finds the signing key in a JWKS document. An empty kid
// matches a single-key bundle, which is what a freshly rotated issuer publishes.
func publicKeyFromJWKS(doc []byte, kid string) (*ecdsa.PublicKey, error) {
	var set jwks
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, errUnknownKey
	}
	for _, k := range set.Keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		if k.Kty != "EC" {
			continue
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			continue
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			continue
		}
		return pub, nil
	}
	return nil, errUnknownKey
}

// verifyES verifies a JWS ES256 or ES384 signature, which is the fixed-width
// r||s form, not ASN.1 DER.
func verifyES(alg string, key *ecdsa.PublicKey, signed, sig []byte) error {
	var digest []byte
	var size int
	switch alg {
	case "ES256":
		d := sha256.Sum256(signed)
		digest, size = d[:], 32
	case "ES384":
		d := sha512.Sum384(signed)
		digest, size = d[:], 48
	default:
		return fmt.Errorf("it was signed with %q, which totem does not accept", alg)
	}
	if len(sig) != 2*size {
		return errBadSignature
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(key, digest, r, s) {
		return errBadSignature
	}
	return nil
}

// checkTime enforces exp and nbf with no skew allowance. Clock skew is a
// `totem doctor` check with a fix, not something silently absorbed here.
func checkTime(claims map[string]any, now time.Time) error {
	if exp, ok := numericDate(claims["exp"]); ok && !now.Before(exp) {
		return errExpired
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Before(nbf) {
		return errNotYetValid
	}
	return nil
}

// numericDate reads a JWT NumericDate claim, which json unmarshals as float64.
func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	sec, frac := int64(f), f-float64(int64(f))
	return time.Unix(sec, int64(frac*float64(time.Second))).UTC(), true
}

// audienceContains handles both shapes the aud claim takes: a single string or
// an array of them.
func audienceContains(v any, want string) bool {
	switch aud := v.(type) {
	case string:
		return aud == want
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
