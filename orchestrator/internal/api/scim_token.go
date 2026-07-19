package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// generateSCIMToken returns a fresh, high-entropy bearer token — shown to
// the admin in cleartext exactly once (creation/rotation response), never
// stored or returned again.
func generateSCIMToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashSCIMToken hashes a presented bearer token for storage/lookup. A
// fast hash (not bcrypt/PBKDF2) is appropriate here: the token is already
// high-entropy random data, not a human-chosen password, so brute-force
// resistance from a slow hash buys nothing — the hash exists purely to
// protect the live credential at rest.
func hashSCIMToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
