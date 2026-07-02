package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
)

// DefaultIterations is the default PBKDF2 iteration count.
// NIST SP 800-132 recommends ≥310000 for PBKDF2-HMAC-SHA256 (2023 guidance).
const DefaultIterations = 310000

// minIterations is enforced at runtime to prevent weak configurations.
const minIterations = 310000

var iterations = DefaultIterations

// SetIterations overrides the PBKDF2 iteration count. Call once at startup
// from config, before any HashPassword calls. Panics if n < minIterations to
// prevent accidental weakening.
func SetIterations(n int) {
	if n < minIterations {
		panic(fmt.Sprintf("auth: PBKDF2 iteration count %d is below the minimum %d", n, minIterations))
	}
	iterations = n
}

// HashPassword returns a PBKDF2-HMAC-SHA256 hash in self-describing format:
//
//	$pbkdf2-sha256$<iterations>$<base64-salt>$<base64-dk>
//
// All randomness comes from crypto/rand. FIPS 140-3 approved algorithm.
func HashPassword(password string) (string, error) {
	return pbkdf2Hash(password, iterations)
}

// VerifyPassword verifies password against a stored hash.
// Supports PBKDF2 (current) and bcrypt (legacy transition).
//
// Returns:
//
//	ok          — true if the password matches
//	needsRehash — true if the hash uses the legacy bcrypt algorithm and
//	              should be replaced with PBKDF2 on the next successful login
//	err         — non-nil if the hash format is unrecognized or verification failed
func VerifyPassword(password, hash string) (ok bool, needsRehash bool, err error) {
	switch {
	case isPBKDF2Hash(hash):
		ok, err = pbkdf2Verify(password, hash)
		return ok, false, err

	case isBcryptHash(hash):
		ok, err = bcryptVerify(password, hash)
		if err != nil {
			return false, false, err
		}
		// Migration flag: upgrade this hash to PBKDF2 on successful login.
		return ok, ok, nil

	default:
		return false, false, errors.New("auth: unrecognized password hash format")
	}
}

// NeedsRehash reports whether hash was produced by the legacy bcrypt algorithm
// and should be replaced with PBKDF2 on the next successful login.
func NeedsRehash(hash string) bool {
	return isBcryptHash(hash)
}

// CryptoSelfTest verifies the password subsystem is operational.
// Intended to be called once at server startup; fatal if any check fails.
//
// Verifies:
//   - crypto/rand is readable
//   - PBKDF2-HMAC-SHA256 hashing produces a valid hash
//   - hash verification succeeds for the correct password
//   - hash verification fails for a wrong password
//   - fresh PBKDF2 hash is NOT flagged for rehash
func CryptoSelfTest() error {
	// Verify crypto/rand is readable.
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return fmt.Errorf("crypto self-test: crypto/rand unavailable: %w", err)
	}

	const pw = "audspect-fips-selftest-probe"
	h, err := HashPassword(pw)
	if err != nil {
		return fmt.Errorf("crypto self-test: HashPassword failed: %w", err)
	}

	ok, rehash, err := VerifyPassword(pw, h)
	if err != nil {
		return fmt.Errorf("crypto self-test: VerifyPassword returned error: %w", err)
	}
	if !ok {
		return fmt.Errorf("crypto self-test: VerifyPassword returned false for correct password")
	}
	if rehash {
		return fmt.Errorf("crypto self-test: fresh PBKDF2 hash incorrectly flagged for rehash")
	}

	wrong, _, _ := VerifyPassword("wrong-password", h)
	if wrong {
		return fmt.Errorf("crypto self-test: VerifyPassword returned true for wrong password")
	}

	log.Println("[+] Crypto self-test passed (PBKDF2-HMAC-SHA256, crypto/rand)")
	return nil
}
