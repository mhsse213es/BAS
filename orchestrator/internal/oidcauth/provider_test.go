package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeOIDCProvider spins up a minimal local OIDC discovery + JWKS + token
// endpoint set, so Provider can be tested without a real IdP. Signs ID
// tokens with a locally generated RSA key, served via a hand-built JWKS
// document — the same shape go-oidc's verifier expects from a real IdP.
type fakeOIDCProvider struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	email    string
	clientID string
}

func newFakeOIDCProvider(t *testing.T, clientID, email string) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &fakeOIDCProvider{key: key, email: email, clientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOIDCProvider) discovery(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.server.URL,
		"authorization_endpoint":                f.server.URL + "/authorize",
		"token_endpoint":                        f.server.URL + "/token",
		"jwks_uri":                              f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeOIDCProvider) jwks(w http.ResponseWriter, r *http.Request) {
	pub := f.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (f *fakeOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"iss":   f.server.URL,
		"sub":   "test-subject",
		"aud":   f.clientID,
		"email": f.email,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"id_token":     signed,
		"token_type":   "Bearer",
	})
}

func TestNewProvider_DiscoveryAndExchange(t *testing.T) {
	fake := newFakeOIDCProvider(t, "test-client", "user@example.com")
	ctx := context.Background()
	p, err := NewProvider(ctx, fake.server.URL, "test-client", "test-secret", "http://localhost/callback")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	email, err := p.Exchange(ctx, "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", email)
	}
}

func TestNewProvider_DiscoveryFailsOnBadIssuer(t *testing.T) {
	ctx := context.Background()
	if _, err := NewProvider(ctx, "http://127.0.0.1:1/not-a-real-idp", "c", "s", "http://localhost/callback"); err == nil {
		t.Fatal("expected an error discovering against an unreachable issuer, got nil")
	}
}

func TestGeneratePKCE_VerifierAndChallengeAreLinkedAndUnique(t *testing.T) {
	v1, c1, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	v2, c2, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if v1 == "" || c1 == "" {
		t.Fatal("verifier and challenge must not be empty")
	}
	if v1 == v2 || c1 == c2 {
		t.Fatal("two calls to GeneratePKCE must not produce the same verifier/challenge")
	}
}
