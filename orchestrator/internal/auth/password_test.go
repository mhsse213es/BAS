package auth

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// ── HashPassword / VerifyPassword ─────────────────────────────────────────────

func TestHashAndVerify_PBKDF2(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !isPBKDF2Hash(h) {
		t.Fatalf("expected PBKDF2 hash prefix, got %q", h)
	}

	ok, needsUpgrade, err := VerifyPassword("hunter2", h)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for correct password")
	}
	if needsUpgrade {
		t.Error("fresh PBKDF2 hash must not require upgrade")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	h, _ := HashPassword("correct")
	ok, _, err := VerifyPassword("wrong", h)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("expected ok=false for wrong password")
	}
}

func TestHashPassword_Unique(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("two hashes of the same password must differ (different salts)")
	}
}

func TestHashPassword_Format(t *testing.T) {
	h, _ := HashPassword("password")
	if !strings.HasPrefix(h, "$pbkdf2-sha256$") {
		t.Fatalf("unexpected hash format: %q", h)
	}
	// Must have 4 fields: prefix+iter, salt, dk when split on $
	// Format: $pbkdf2-sha256$<iter>$<salt>$<dk>
	parts := strings.Split(strings.TrimPrefix(h, "$pbkdf2-sha256$"), "$")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts after prefix, got %d: %v", len(parts), parts)
	}
}

// ── bcrypt legacy migration ───────────────────────────────────────────────────

func TestVerify_BcryptLegacy_CorrectPassword(t *testing.T) {
	raw, err := bcrypt.GenerateFromPassword([]byte("legacy"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.Generate: %v", err)
	}
	hash := string(raw)

	ok, needsUpgrade, err := VerifyPassword("legacy", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for correct bcrypt password")
	}
	if !needsUpgrade {
		t.Error("bcrypt hash must be flagged for upgrade")
	}
}

func TestVerify_BcryptLegacy_WrongPassword(t *testing.T) {
	raw, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	ok, needsUpgrade, err := VerifyPassword("wrong", string(raw))
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("expected ok=false for wrong password")
	}
	if needsUpgrade {
		t.Error("failed bcrypt verify must not flag for upgrade")
	}
}

func TestNeedsUpgrade(t *testing.T) {
	// bcrypt must always need upgrade.
	raw, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	if !NeedsUpgrade(string(raw)) {
		t.Error("bcrypt hash must need upgrade")
	}

	// Fresh PBKDF2 at current iterations must not need upgrade.
	h, _ := HashPassword("x")
	if NeedsUpgrade(h) {
		t.Error("current PBKDF2 hash must not need upgrade")
	}

	// PBKDF2 hash with lower iteration count (injected manually) must need upgrade.
	lowIter := strings.Replace(h, fmt.Sprintf("$pbkdf2-sha256$%d$", iterations), "$pbkdf2-sha256$1$", 1)
	if !NeedsUpgrade(lowIter) {
		t.Error("low-iteration PBKDF2 hash must need upgrade")
	}
}

// ── Edge-case passwords ───────────────────────────────────────────────────────

func TestEmptyPassword(t *testing.T) {
	h, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword empty: %v", err)
	}
	ok, _, err := VerifyPassword("", h)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("empty password must verify against its own hash")
	}
	if wrong, _, _ := VerifyPassword("x", h); wrong {
		t.Error("non-empty password must not match empty-password hash")
	}
}

func TestVeryLongPassword(t *testing.T) {
	pw := strings.Repeat("A", 1024)
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword 1KB: %v", err)
	}
	ok, _, err := VerifyPassword(pw, h)
	if err != nil {
		t.Fatalf("VerifyPassword 1KB: %v", err)
	}
	if !ok {
		t.Error("1KB password must verify")
	}
}

func TestInvalidIterationCount(t *testing.T) {
	// Craft a hash with iteration count "0" — must return error, not panic.
	badHash := "$pbkdf2-sha256$0$AAAA$AAAA"
	_, _, err := VerifyPassword("pw", badHash)
	if err == nil {
		t.Error("expected error for zero iteration count in stored hash")
	}
}

// ── Unknown hash format ───────────────────────────────────────────────────────

func TestVerify_UnknownFormat(t *testing.T) {
	_, _, err := VerifyPassword("pw", "sha1:deadbeef")
	if err == nil {
		t.Error("expected error for unrecognized hash format")
	}
}

// ── CryptoSelfTest ────────────────────────────────────────────────────────────

func TestCryptoSelfTest(t *testing.T) {
	if err := CryptoSelfTest(); err != nil {
		t.Fatalf("CryptoSelfTest: %v", err)
	}
}

// ── PBKDF2 tamper-resistance ──────────────────────────────────────────────────

func TestVerify_TamperedHash(t *testing.T) {
	h, _ := HashPassword("pw")
	// Corrupt the last character of the derived key portion.
	corrupted := h[:len(h)-1] + "X"
	ok, _, err := VerifyPassword("pw", corrupted)
	if err != nil && strings.Contains(err.Error(), "encoding") {
		t.Skip("corruption produced base64 decode error — acceptable")
	}
	if ok {
		t.Error("tampered hash must not verify")
	}
}
