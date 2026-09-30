package config

import (
	"strings"
	"testing"
)

// TestLoad_JWTSecretMinLength verifies the JWT secret entropy guard: a short
// secret is rejected at load, a >=32-char secret is accepted.
func TestLoad_JWTSecretMinLength(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")

	t.Setenv("JWT_SECRET", "too-short")
	if _, err := Load("/nonexistent-config.json"); err == nil {
		t.Error("expected error for short jwt_secret")
	} else if !strings.Contains(err.Error(), "jwt_secret too short") {
		t.Errorf("unexpected error: %v", err)
	}

	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	if _, err := Load("/nonexistent-config.json"); err != nil {
		t.Errorf("32-char secret should be accepted, got: %v", err)
	}
}

func TestLoad_JWTSecretRequired(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db")
	t.Setenv("JWT_SECRET", "")
	if _, err := Load("/nonexistent-config.json"); err == nil {
		t.Error("expected error for missing jwt_secret")
	}
}
