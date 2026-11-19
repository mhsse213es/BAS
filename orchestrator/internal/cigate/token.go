// Package cigate lets a CI pipeline start one validation run and read back its verdict (REQ-057).
//
// A CI pipeline authenticates with a dedicated bearer token, not a user session. The token is shown once when it is
// created; only its SHA-256 is stored. A CI token opens the /api/ci routes and nothing else.
package cigate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TokenPrefix marks a CI token. The auth middleware uses it to tell a CI token from a user session JWT.
const TokenPrefix = "bas_ci_"

// NewToken returns a new random CI token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return TokenPrefix + hex.EncodeToString(b), nil
}

// HashToken is the stored form of a token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// IsCIToken reports whether a bearer credential has the CI token shape.
func IsCIToken(credential string) bool {
	return strings.HasPrefix(credential, TokenPrefix) && len(credential) == len(TokenPrefix)+64
}
