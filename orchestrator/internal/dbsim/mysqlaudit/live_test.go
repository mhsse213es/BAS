package mysqlaudit

import (
	"context"
	"os"
	"testing"
)

// TestLiveHarnessEvidenceCovered runs only on the lab host. It is skipped unless
// DBSIM_HARNESS_LIVE=1 and the three lab paths are set. It must report covered.
func TestLiveHarnessEvidenceCovered(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	cfg := LabConfig{
		PasswordFile: os.Getenv("DBSIM_HARNESS_PW"),
		Addr:         os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:    os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	ev, err := Evidence(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	if ev.AuditCoverage != "covered" {
		t.Fatalf("want covered, got %q", ev.AuditCoverage)
	}
}
