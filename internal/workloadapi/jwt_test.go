package workloadapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// signJWT mints an ES256 JWT-SVID the way the issuer will, so validation is
// tested against a real token rather than a fixture.
func signJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k1"})
	body, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwksFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.PublicKey.X.FillBytes(x)
	key.PublicKey.Y.FillBytes(y)
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}}})
	return doc
}

func TestValidateJWTSVID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundles := map[string][]byte{"spiffe://" + testTrustDomain: jwksFor(t, key)}
	now := time.Unix(1_700_000_000, 0).UTC()
	sub := "spiffe://" + testTrustDomain + "/device/" + testDeviceID + "/tool/claude"

	token := signJWT(t, key, map[string]any{
		"sub": sub,
		"aud": []any{"https://octo-sts.example"},
		"exp": float64(now.Add(5 * time.Minute).Unix()),
	})

	id, claims, err := validateJWTSVID(token, "https://octo-sts.example", bundles, now)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id != sub {
		t.Errorf("id = %q, want %q", id, sub)
	}
	if claims == nil || claims.Fields["sub"].GetStringValue() != sub {
		t.Error("claims were not returned")
	}
}

func TestValidateJWTSVIDRejections(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundles := map[string][]byte{"spiffe://" + testTrustDomain: jwksFor(t, key)}
	now := time.Unix(1_700_000_000, 0).UTC()
	sub := "spiffe://" + testTrustDomain + "/device/d/tool/claude"

	good := map[string]any{"sub": sub, "aud": []any{"aud1"}, "exp": float64(now.Add(time.Minute).Unix())}

	t.Run("wrong audience", func(t *testing.T) {
		tok := signJWT(t, key, good)
		if _, _, err := validateJWTSVID(tok, "aud2", bundles, now); err == nil {
			t.Error("a token for another audience was accepted")
		}
	})
	t.Run("expired", func(t *testing.T) {
		expired := map[string]any{"sub": sub, "aud": []any{"aud1"}, "exp": float64(now.Add(-time.Minute).Unix())}
		tok := signJWT(t, key, expired)
		if _, _, err := validateJWTSVID(tok, "aud1", bundles, now); err == nil {
			t.Error("an expired token was accepted")
		}
	})
	t.Run("foreign key", func(t *testing.T) {
		tok := signJWT(t, other, good)
		if _, _, err := validateJWTSVID(tok, "aud1", bundles, now); err == nil {
			t.Error("a token signed by an untrusted key was accepted")
		}
	})
	t.Run("unknown trust domain", func(t *testing.T) {
		tok := signJWT(t, key, map[string]any{"sub": "spiffe://elsewhere.example/x", "aud": []any{"aud1"}})
		if _, _, err := validateJWTSVID(tok, "aud1", bundles, now); err == nil {
			t.Error("a token from an unknown trust domain was accepted")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, _, err := validateJWTSVID("not.a.token", "aud1", bundles, now); err == nil {
			t.Error("a malformed token was accepted")
		}
	})
}
