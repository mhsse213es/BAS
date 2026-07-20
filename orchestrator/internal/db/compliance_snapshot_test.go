package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestGetFleetComplianceScores_PicksWorstAgentCoherently(t *testing.T) {
	ctx := context.Background()
	const fw = "TEST_FLEET_FW"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM compliance_snapshots WHERE framework_id = $1`, fw)
	})

	// Agent A: worse score (40%), but higher raw pass count.
	if err := db.UpsertComplianceSnapshot(ctx, sharedDB.Pool, db.ComplianceSnapshot{
		AgentID: "test-agent-a", FrameworkID: fw,
		CompliancePct: 40, CoveragePct: 80,
		TotalControls: 20, TestableControls: 20, TestedControls: 10,
		PassingControls: 4, FailingControls: 6, ManualControls: 0,
	}); err != nil {
		t.Fatalf("seed agent-a: %v", err)
	}

	// Agent B: better score (90%), fewer tested controls.
	if err := db.UpsertComplianceSnapshot(ctx, sharedDB.Pool, db.ComplianceSnapshot{
		AgentID: "test-agent-b", FrameworkID: fw,
		CompliancePct: 90, CoveragePct: 50,
		TotalControls: 20, TestableControls: 20, TestedControls: 10,
		PassingControls: 9, FailingControls: 1, ManualControls: 0,
	}); err != nil {
		t.Fatalf("seed agent-b: %v", err)
	}

	snaps, err := db.GetFleetComplianceScores(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("GetFleetComplianceScores: %v", err)
	}

	var got *db.ComplianceSnapshot
	for i := range snaps {
		if snaps[i].FrameworkID == fw {
			got = &snaps[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("no snapshot returned for framework %s", fw)
	}

	if got.AgentID != "test-agent-a" {
		t.Errorf("AgentID = %q, want the worst-scoring agent test-agent-a", got.AgentID)
	}
	if got.CompliancePct != 40 {
		t.Errorf("CompliancePct = %v, want 40 (agent-a's real score)", got.CompliancePct)
	}
	// These must belong to agent-a specifically -- NOT summed across both agents
	// (the old MIN()/SUM() blend would have produced PassingControls=13, FailingControls=7).
	if got.PassingControls != 4 {
		t.Errorf("PassingControls = %d, want 4 (agent-a's own count, not summed across agents)", got.PassingControls)
	}
	if got.FailingControls != 6 {
		t.Errorf("FailingControls = %d, want 6 (agent-a's own count, not summed across agents)", got.FailingControls)
	}
	if got.EnrolledAgentCount != 2 {
		t.Errorf("EnrolledAgentCount = %d, want 2", got.EnrolledAgentCount)
	}
}
