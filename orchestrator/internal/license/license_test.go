package license

import (
	"testing"
	"time"
)

// Check() with PublicKeyPEM still at its dev-mode placeholder always
// returns nil regardless of expiry — this test only exercises the
// production code path indirectly via Evaluate, since Check() itself
// requires a real signed .lic file on disk to test the signature branch
// meaningfully (out of scope here — Check()'s signature verification is
// unchanged by this task). This task's regression coverage is: Status()
// must agree with Evaluate() for the same three boundary cases Task 1
// already covers for Evaluate directly.
func TestStatus_Valid(t *testing.T) {
	if got := Status("2099-01-01"); got != "valid" {
		t.Errorf("Status = %q, want %q", got, "valid")
	}
}

func TestStatus_Expired(t *testing.T) {
	if got := Status("2000-01-01"); got != "expired" {
		t.Errorf("Status = %q, want %q", got, "expired")
	}
}

func TestStatus_ExpiringSoon(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format("2006-01-02")
	if got := Status(soon); got != "expiring_soon" {
		t.Errorf("Status(%q) = %q, want %q", soon, got, "expiring_soon")
	}
}

func TestStatus_UnknownOnBadDate(t *testing.T) {
	if got := Status("garbage"); got != "unknown" {
		t.Errorf("Status = %q, want %q", got, "unknown")
	}
}
