// Package auth — bcrypt_legacy.go
//
// Read-only bcrypt support for transparent migration. New passwords are never
// hashed with bcrypt; this file exists only to verify existing DB hashes during
// the transition period and is intentionally kept minimal.
package auth

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcryptVerify checks password against a stored bcrypt hash.
// Returns (true, nil) on match, (false, nil) on mismatch, (false, err) on error.
func bcryptVerify(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// isBcryptHash reports whether hash looks like a bcrypt hash ($2a$, $2b$, $2y$).
func isBcryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") ||
		strings.HasPrefix(hash, "$2b$") ||
		strings.HasPrefix(hash, "$2y$")
}
