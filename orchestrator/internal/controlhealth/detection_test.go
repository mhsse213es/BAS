package controlhealth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/verification"
)

// seedVerificationRecord gives each row its own (run_id, expectation_id)
// pair -- verification_history's idx_verif_active_one unique index allows at
// most one active row per that pair, so distinct pairs per row let a test
// seed multiple simultaneously-active records.
func seedVerificationRecord(t *testing.T, pool *pgxpool.Pool, id, techID, result, workflowState string, active bool, verifiedAt time.Time) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO verification_history
			(id, run_id, expectation_id, profile_name, profile_version, technique_id, domain, provider, result, workflow_state, verification_source, verified_by, verified_at, active)
		VALUES ($1, $2, $3, 'ch-profile', 1, $4, 'endpoint', 'test', $5, $6, $7, 'tester', $8, $9)`,
		id, id+"-run", id+"-exp", techID, result, workflowState, verification.SourceAPI, verifiedAt, active)
}

func TestLoadDetectionEvidence_OnlyApprovedActiveCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		now := time.Now().UTC()
		seedVerificationRecord(t, pool, "ch-vh-1", "T1566", verification.ResultDetected, verification.StateApproved, true, now)
		seedVerificationRecord(t, pool, "ch-vh-2", "T1003", verification.ResultNotDetected, verification.StateApproved, true, now)
		seedVerificationRecord(t, pool, "ch-vh-3", "T1078", verification.ResultDetected, verification.StatePending, true, now)   // not Approved
		seedVerificationRecord(t, pool, "ch-vh-4", "T1046", verification.ResultDetected, verification.StateApproved, false, now) // not active

		since := now.Add(-24 * time.Hour)
		got, err := loadDetectionEvidence(ctx, pool, since)
		if err != nil {
			t.Fatalf("loadDetectionEvidence: %v", err)
		}
		seen := map[string]string{}
		for _, r := range got {
			seen[r.TechniqueID] = r.Verdict
		}
		if seen["T1566"] != "pass" {
			t.Errorf("T1566 verdict = %q, want pass", seen["T1566"])
		}
		if seen["T1003"] != "fail" {
			t.Errorf("T1003 verdict = %q, want fail", seen["T1003"])
		}
		if _, ok := seen["T1078"]; ok {
			t.Error("Pending (not Approved) record must be excluded, but T1078 was returned")
		}
		if _, ok := seen["T1046"]; ok {
			t.Error("inactive record must be excluded, but T1046 was returned")
		}
	})
}
