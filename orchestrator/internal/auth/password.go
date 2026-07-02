package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
// from config, before any HashPassword calls. Panics below minIterations to
// prevent accidental weakening.
func SetIterations(n int) {
	if n < minIterations {
		panic(fmt.Sprintf("auth: PBKDF2 iteration count %d is below the minimum %d", n, minIterations))
	}
	iterations = n
}

// GetIterations returns the currently configured PBKDF2 iteration count.
func GetIterations() int {
	return iterations
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
//	ok           — true if the password matches
//	needsUpgrade — true when the match succeeded but the hash should be
//	               replaced: bcrypt (algorithm migration) or PBKDF2 with a
//	               lower iteration count than the current configuration
//	err          — non-nil if the hash format is unrecognized or verification failed
func VerifyPassword(password, hash string) (ok bool, needsUpgrade bool, err error) {
	switch {
	case isPBKDF2Hash(hash):
		ok, err = pbkdf2Verify(password, hash)
		return ok, ok && NeedsUpgrade(hash), err

	case isBcryptHash(hash):
		ok, err = bcryptVerify(password, hash)
		if err != nil {
			return false, false, err
		}
		return ok, ok && NeedsUpgrade(hash), nil

	default:
		return false, false, errors.New("auth: unrecognized password hash format")
	}
}

// NeedsUpgrade reports whether a hash should be replaced on the next successful login.
//
// Returns true for:
//   - any bcrypt hash (algorithm migration to PBKDF2)
//   - PBKDF2 hashes whose stored iteration count is below the current configuration
//     (enables transparent re-hashing when the config iteration count is increased)
func NeedsUpgrade(hash string) bool {
	if isBcryptHash(hash) {
		return true
	}
	if isPBKDF2Hash(hash) {
		return pbkdf2ParseIterations(hash) < iterations
	}
	return false
}

// CryptoSelfTest verifies the cryptographic subsystem is fully operational.
// Call once at server startup; treat a non-nil return as fatal.
//
// Verifies: SHA-256 (known-answer), HMAC-SHA256, RSA-2048 sign/verify,
// PBKDF2-HMAC-SHA256, crypto/rand entropy, constant-time compare.
func CryptoSelfTest() error {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"SHA-256 KAT", sha256SelfTest},
		{"HMAC-SHA256", hmacSelfTest},
		{"RSA sign/verify", rsaSelfTest},
		{"crypto/rand", randSelfTest},
		{"PBKDF2-HMAC-SHA256", pbkdf2SelfTest},
		{"constant-time compare", ctCompareSelfTest},
	}
	for _, c := range checks {
		if err := c.fn(); err != nil {
			return fmt.Errorf("crypto self-test [%s]: %w", c.name, err)
		}
	}
	log.Printf("[+] Crypto self-test passed (SHA-256, HMAC-SHA256, RSA-2048, PBKDF2-HMAC-SHA256, crypto/rand, CT-compare)")
	return nil
}

// sha256SelfTest uses a known-answer test to verify the SHA-256 implementation.
func sha256SelfTest() error {
	// SHA-256("") is a well-known constant; any deviation indicates a broken implementation.
	const expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h := sha256.Sum256([]byte(""))
	if hex.EncodeToString(h[:]) != expected {
		return errors.New("SHA-256 known-answer test failed")
	}
	return nil
}

func hmacSelfTest() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	const msg = "audspect-hmac-probe"
	mac1 := hmac.New(sha256.New, key)
	mac1.Write([]byte(msg))
	sum1 := mac1.Sum(nil)
	mac2 := hmac.New(sha256.New, key)
	mac2.Write([]byte(msg))
	if !hmac.Equal(sum1, mac2.Sum(nil)) {
		return errors.New("HMAC reproducibility check failed")
	}
	mac3 := hmac.New(sha256.New, key)
	mac3.Write([]byte(msg + "x"))
	if hmac.Equal(sum1, mac3.Sum(nil)) {
		return errors.New("HMAC produced identical output for different inputs")
	}
	return nil
}

func rsaSelfTest() error {
	// 2048-bit key for test speed; production scenario/license signing uses RSA-4096.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("key generation: %w", err)
	}
	digest := sha256.Sum256([]byte("audspect-rsa-selftest"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	bad := sha256.Sum256([]byte("wrong"))
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, bad[:], sig) == nil {
		return errors.New("RSA accepted signature for wrong digest")
	}
	return nil
}

func randSelfTest() error {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("read failed: %w", err)
	}
	for _, b := range buf {
		if b != 0 {
			return nil
		}
	}
	return errors.New("crypto/rand returned all zeros — possible entropy failure")
}

func pbkdf2SelfTest() error {
	const pw = "audspect-fips-selftest-probe"
	h, err := HashPassword(pw)
	if err != nil {
		return fmt.Errorf("HashPassword: %w", err)
	}
	ok, upgrade, err := VerifyPassword(pw, h)
	if err != nil {
		return fmt.Errorf("VerifyPassword: %w", err)
	}
	if !ok {
		return errors.New("correct password rejected")
	}
	if upgrade {
		return errors.New("fresh PBKDF2 hash incorrectly flagged for upgrade")
	}
	if wrong, _, _ := VerifyPassword("wrong", h); wrong {
		return errors.New("wrong password accepted")
	}
	return nil
}

func ctCompareSelfTest() error {
	a := []byte("audspect-ct-probe-value")
	b := []byte("audspect-ct-probe-value")
	c := []byte("audspect-ct-probe-XXXXX")
	if subtle.ConstantTimeCompare(a, b) != 1 {
		return errors.New("equal slices returned not-equal")
	}
	if subtle.ConstantTimeCompare(a, c) != 0 {
		return errors.New("different slices returned equal")
	}
	return nil
}
