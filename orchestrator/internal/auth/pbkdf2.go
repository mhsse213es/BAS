package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Prefix  = "$pbkdf2-sha256$"
	pbkdf2KeyLen  = 32 // 256-bit derived key
	pbkdf2SaltLen = 32 // 256-bit salt
)

// pbkdf2Hash produces a self-describing PBKDF2-HMAC-SHA256 hash:
//
//	$pbkdf2-sha256$<iterations>$<base64-salt>$<base64-dk>
//
// All random bytes come from crypto/rand. FIPS 140-3 approved.
func pbkdf2Hash(password string, iters int) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pbkdf2: salt generation failed: %w", err)
	}
	dk := pbkdf2.Key([]byte(password), salt, iters, pbkdf2KeyLen, sha256.New)
	result := fmt.Sprintf("%s%d$%s$%s",
		pbkdf2Prefix,
		iters,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	)
	// Best-effort: zero key material before GC can observe these slices.
	for i := range dk {
		dk[i] = 0
	}
	for i := range salt {
		salt[i] = 0
	}
	return result, nil
}

// pbkdf2Verify checks password against a stored PBKDF2 hash.
// Uses constant-time comparison to prevent timing attacks.
func pbkdf2Verify(password, hash string) (bool, error) {
	body := strings.TrimPrefix(hash, pbkdf2Prefix)
	parts := strings.SplitN(body, "$", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("pbkdf2: malformed hash (expected 3 fields, got %d)", len(parts))
	}

	iters, err := strconv.Atoi(parts[0])
	if err != nil || iters <= 0 {
		return false, fmt.Errorf("pbkdf2: invalid iteration count %q", parts[0])
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("pbkdf2: invalid salt encoding: %w", err)
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("pbkdf2: invalid dk encoding: %w", err)
	}

	candidate := pbkdf2.Key([]byte(password), salt, iters, pbkdf2KeyLen, sha256.New)
	eq := subtle.ConstantTimeCompare(candidate, expected) == 1
	// Best-effort memory hygiene: zero derived key material.
	for i := range candidate {
		candidate[i] = 0
	}
	for i := range expected {
		expected[i] = 0
	}
	for i := range salt {
		salt[i] = 0
	}
	return eq, nil
}

func isPBKDF2Hash(hash string) bool {
	return strings.HasPrefix(hash, pbkdf2Prefix)
}

// pbkdf2ParseIterations extracts the iteration count from a PBKDF2 hash.
// Returns 0 if the hash is malformed or not a PBKDF2 hash.
func pbkdf2ParseIterations(hash string) int {
	if !isPBKDF2Hash(hash) {
		return 0
	}
	body := strings.TrimPrefix(hash, pbkdf2Prefix)
	i := strings.IndexByte(body, '$')
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(body[:i])
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
