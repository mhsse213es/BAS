package main

import (
	"context"
	"os"
	"testing"
)

// TestCheckCANotSilentlyRotated_AllowsFreshInstall confirms a genuine
// fresh install (no existing agent_certificates rows) is never blocked,
// even though caKeyExistedBefore is false (a CA was just generated).
func TestCheckCANotSilentlyRotated_AllowsFreshInstall(t *testing.T) {
	if err := checkCANotSilentlyRotated(context.Background(), sharedDB.Pool, false); err != nil {
		t.Errorf("expected fresh install (no existing certs) to be allowed, got: %v", err)
	}
}

// TestCheckCANotSilentlyRotated_BlocksSilentRegenerationWithExistingCerts
// is the core safety property: a fresh CA generation (caKeyExistedBefore
// = false) with EXISTING valid agent_certificates rows must be refused.
func TestCheckCANotSilentlyRotated_BlocksSilentRegenerationWithExistingCerts(t *testing.T) {
	ctx := context.Background()
	// Seed a valid, non-revoked, non-expired agent_certificates row --
	// evidence a fleet was previously enrolled under a CA that's now gone.
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year')`,
		"test-serial-lockout-check", "abc123deadbeef01")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-lockout-check")

	os.Unsetenv("BAS_CONFIRM_NEW_CA") // ensure the override is NOT set for this test
	if err := checkCANotSilentlyRotated(ctx, sharedDB.Pool, false); err == nil {
		t.Fatal("expected an error when a fresh CA is generated but valid agent_certificates rows already exist")
	}
}

// TestCheckCANotSilentlyRotated_OverrideAllowsIntentionalRotation confirms
// the escape hatch for a genuine, intentional CA rotation/reset.
func TestCheckCANotSilentlyRotated_OverrideAllowsIntentionalRotation(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year')`,
		"test-serial-override-check", "abc123deadbeef02")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-override-check")

	t.Setenv("BAS_CONFIRM_NEW_CA", "true")
	if err := checkCANotSilentlyRotated(ctx, sharedDB.Pool, false); err != nil {
		t.Errorf("expected BAS_CONFIRM_NEW_CA=true to allow intentional rotation, got: %v", err)
	}
}

// TestCheckCANotSilentlyRotated_SkipsCheckWhenCAAlreadyExisted confirms
// the normal, every-day restart case (CA file was present, nothing was
// regenerated) is never blocked, regardless of what's in agent_certificates.
func TestCheckCANotSilentlyRotated_SkipsCheckWhenCAAlreadyExisted(t *testing.T) {
	if err := checkCANotSilentlyRotated(context.Background(), sharedDB.Pool, true); err != nil {
		t.Errorf("expected caKeyExistedBefore=true to skip the check entirely, got: %v", err)
	}
}
