package license

import (
	"testing"
	"time"
)

func mustLicense(expiresAt string) *License {
	return &License{Customer: "Acme Corp", ExpiresAt: expiresAt}
}

func TestEvaluate_Valid_WellBeforeExpiry(t *testing.T) {
	lic := mustLicense("2026-08-20")
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateValid {
		t.Errorf("state = %q, want %q", info.State, StateValid)
	}
	if info.DaysRemaining != 0 {
		t.Errorf("DaysRemaining = %d, want 0 for a Valid license", info.DaysRemaining)
	}
}

func TestEvaluate_Valid_JustBeforeExpiryInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	// expiresAt for 2026-08-14 is 2026-08-14T23:59:59Z — one second before that is still Valid.
	now := time.Date(2026, 8, 14, 23, 59, 58, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateValid {
		t.Errorf("state = %q, want %q", info.State, StateValid)
	}
}

func TestEvaluate_Grace_ExactlyAtExpiryInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 14, 23, 59, 59, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateGrace {
		t.Errorf("state = %q, want %q (expiresAt is inclusive-lower-bound of grace)", info.State, StateGrace)
	}
}

func TestEvaluate_Grace_MidWindow(t *testing.T) {
	lic := mustLicense("2026-08-14")
	// lockoutAt = 2026-08-14T23:59:59Z + 5*24h = 2026-08-19T23:59:59Z
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateGrace {
		t.Errorf("state = %q, want %q", info.State, StateGrace)
	}
	if info.DaysRemaining < 1 || info.DaysRemaining > 5 {
		t.Errorf("DaysRemaining = %d, want a value in [1,5] mid-grace", info.DaysRemaining)
	}
}

func TestEvaluate_Grace_JustBeforeLockoutInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 19, 23, 59, 58, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateGrace {
		t.Errorf("state = %q, want %q", info.State, StateGrace)
	}
}

func TestEvaluate_Locked_ExactlyAtLockoutInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateLocked {
		t.Errorf("state = %q, want %q (lockoutAt is inclusive-lower-bound of locked)", info.State, StateLocked)
	}
}

func TestEvaluate_Locked_WellPastLockout(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateLocked {
		t.Errorf("state = %q, want %q", info.State, StateLocked)
	}
	if info.DaysRemaining != 0 {
		t.Errorf("DaysRemaining = %d, want 0 once Locked", info.DaysRemaining)
	}
}

func TestEvaluate_InvalidExpiryDate(t *testing.T) {
	lic := mustLicense("not-a-date")
	_, err := Evaluate(lic, time.Now())
	if err == nil {
		t.Fatal("expected an error for a malformed ExpiresAt date")
	}
}

func TestEvaluate_ExpiresAtAndLockoutAtFields(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantExpires := time.Date(2026, 8, 14, 23, 59, 59, 0, time.UTC)
	wantLockout := time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC)
	if !info.ExpiresAt.Equal(wantExpires) {
		t.Errorf("ExpiresAt = %v, want %v", info.ExpiresAt, wantExpires)
	}
	if !info.LockoutAt.Equal(wantLockout) {
		t.Errorf("LockoutAt = %v, want %v", info.LockoutAt, wantLockout)
	}
}
