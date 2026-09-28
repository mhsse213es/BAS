package main

import (
	"context"
	"os"
	"testing"
)

// TestCheckSigningKeyNotSilentlyRotated_AllowsFreshInstall mirrors
// TestCheckCANotSilentlyRotated_AllowsFreshInstall: a genuine fresh
// install (no existing agent_certificates rows carrying a
// command_signing_key_id) is never blocked, even though
// signingKeyExistedBefore is false (a key was just generated).
func TestCheckSigningKeyNotSilentlyRotated_AllowsFreshInstall(t *testing.T) {
	if err := checkSigningKeyNotSilentlyRotated(context.Background(), sharedDB.Pool, false); err != nil {
		t.Errorf("expected fresh install (no existing signing-trust rows) to be allowed, got: %v", err)
	}
}

// TestCheckSigningKeyNotSilentlyRotated_BlocksSilentRegenerationWithExistingTrust
// is the core safety property: a fresh signing key generation
// (signingKeyExistedBefore = false) with an EXISTING agent_certificates
// row that already recorded trust in a (now-gone) signing key must be
// refused -- exactly like the CA's equivalent check, and for the same
// reason: agents enrolled under the old key would silently reject every
// command the new key signs, with no indication why, unless the operator
// is warned at startup instead.
func TestCheckSigningKeyNotSilentlyRotated_BlocksSilentRegenerationWithExistingTrust(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at, command_signing_key_id)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year', $3)`,
		"test-serial-signing-lockout-check", "abc123deadbeef01", "command-signing-key-deadbeef")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-signing-lockout-check")

	os.Unsetenv("BAS_CONFIRM_NEW_SIGNING_KEY")
	if err := checkSigningKeyNotSilentlyRotated(ctx, sharedDB.Pool, false); err == nil {
		t.Fatal("expected an error when a fresh signing key is generated but a row already records trust in a different key")
	}
}

// TestCheckSigningKeyNotSilentlyRotated_OverrideAllowsIntentionalRotation
// confirms the escape hatch for a genuine, intentional key rotation/reset.
func TestCheckSigningKeyNotSilentlyRotated_OverrideAllowsIntentionalRotation(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at, command_signing_key_id)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year', $3)`,
		"test-serial-signing-override-check", "abc123deadbeef02", "command-signing-key-deadbeef")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-signing-override-check")

	t.Setenv("BAS_CONFIRM_NEW_SIGNING_KEY", "true")
	if err := checkSigningKeyNotSilentlyRotated(ctx, sharedDB.Pool, false); err != nil {
		t.Errorf("expected BAS_CONFIRM_NEW_SIGNING_KEY=true to allow intentional rotation, got: %v", err)
	}
}

// TestCheckSigningKeyNotSilentlyRotated_SkipsCheckWhenKeyAlreadyExisted
// confirms the normal, every-day restart case (signing key file was
// present, nothing was regenerated) is never blocked.
func TestCheckSigningKeyNotSilentlyRotated_SkipsCheckWhenKeyAlreadyExisted(t *testing.T) {
	if err := checkSigningKeyNotSilentlyRotated(context.Background(), sharedDB.Pool, true); err != nil {
		t.Errorf("expected signingKeyExistedBefore=true to skip the check entirely, got: %v", err)
	}
}

// TestCheckSigningKeyNotSilentlyRotated_IgnoresRowsWithNoRecordedTrust
// confirms a pre-this-plan agent_certificates row (command_signing_key_id
// IS NULL, since it predates this column) is correctly NOT treated as
// evidence of prior signing-key trust -- it never trusted any signing key
// at all, so there's nothing to silently invalidate.
func TestCheckSigningKeyNotSilentlyRotated_IgnoresRowsWithNoRecordedTrust(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year')`,
		"test-serial-signing-null-check", "abc123deadbeef03")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-signing-null-check")

	os.Unsetenv("BAS_CONFIRM_NEW_SIGNING_KEY")
	if err := checkSigningKeyNotSilentlyRotated(ctx, sharedDB.Pool, false); err != nil {
		t.Errorf("expected a row with no recorded signing-key trust to be ignored, got: %v", err)
	}
}
