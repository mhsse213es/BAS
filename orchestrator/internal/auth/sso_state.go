package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SSOStateClaims is the signed payload carried through the OIDC "state"
// parameter — the browser round-trips it opaquely to the IdP and back, so it
// must be tamper-evident (HMAC-signed, reusing the same JWT mechanism the
// platform's own login tokens use) and short-lived. It carries the raw PKCE
// code_verifier (not a hash — the token-exchange step must present the
// verifier in cleartext to the IdP; only the derived code_challenge, sent in
// the initial authorization request, is a hash). Carrying the raw verifier
// inside a signed token is safe here: state's threat model is tamper
// evidence via the browser round-trip, not confidentiality from the
// browser completing its own legitimate login.
type SSOStateClaims struct {
	TenantID     string `json:"tenant_id"`
	CodeVerifier string `json:"code_verifier"`
	jwt.RegisteredClaims
}

// GenerateSSOState creates a signed, short-lived state token binding one
// login attempt to one tenant and one PKCE code verifier.
func GenerateSSOState(tenantID, codeVerifier, secret string, ttl time.Duration) (string, error) {
	claims := SSOStateClaims{
		TenantID:     tenantID,
		CodeVerifier: codeVerifier,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// ValidateSSOState parses and validates a state token, returning its claims.
func ValidateSSOState(tokenStr, secret string) (*SSOStateClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &SSOStateClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*SSOStateClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid state claims")
	}
	return claims, nil
}
