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

// TestLiveAuthEvent03 runs test 03 on the lab host. It needs the same DBSIM_HARNESS_*
// variables and DBSIM_HARNESS_RUN (a run ID: letters, digits, hyphens). It must PASS.
func TestLiveAuthEvent03(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	cfg := LabConfig{
		PasswordFile: os.Getenv("DBSIM_HARNESS_PW"),
		Addr:         os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:    os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	res, why, err := RunAuthEvent(context.Background(), cfg, os.Getenv("DBSIM_HARNESS_RUN"))
	if err != nil {
		t.Fatalf("RunAuthEvent: %v", err)
	}
	t.Logf("result=%s reason=%s", res, why)
	if res != "PASS" {
		t.Fatalf("test 03 must PASS on the lab, got %s (%s)", res, why)
	}
}

// TestLiveFailedLogin04 runs test 04 on the lab host. Same variables as test 03, with
// DBSIM_HARNESS_RUN up to 22 letters or digits. It must PASS.
func TestLiveFailedLogin04(t *testing.T) {
	if os.Getenv("DBSIM_HARNESS_LIVE") != "1" {
		t.Skip("live lab check: set DBSIM_HARNESS_LIVE=1 on the lab host")
	}
	cfg := LabConfig{
		PasswordFile: os.Getenv("DBSIM_HARNESS_PW"),
		Addr:         os.Getenv("DBSIM_HARNESS_ADDR"),
		AuditFile:    os.Getenv("DBSIM_HARNESS_AUDIT"),
	}
	res, why, err := RunFailedLogin(context.Background(), cfg, os.Getenv("DBSIM_HARNESS_RUN"))
	if err != nil {
		t.Fatalf("RunFailedLogin: %v", err)
	}
	t.Logf("result=%s reason=%s", res, why)
	if res != "PASS" {
		t.Fatalf("test 04 must PASS on the lab, got %s (%s)", res, why)
	}
}
