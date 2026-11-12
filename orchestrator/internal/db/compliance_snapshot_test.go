package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// The fleet headline for a framework is the agent with the most completed runs, because that agent carries the most
// evidence. An agent tested in only a handful of runs must not set the fleet's compliance figure.
func TestGetFleetComplianceScores_PicksTheMostTestedAgentCoherently(t *testing.T) {
	ctx := context.Background()
	const fw = "TEST_FLEET_FW"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM compliance_snapshots WHERE framework_id = $1`, fw)
	})

	// Agent A: worst score (40%) but only 5 runs of evidence.
	if err := db.UpsertComplianceSnapshot(ctx, sharedDB.Pool, db.ComplianceSnapshot{
		AgentID: "test-agent-a", FrameworkID: fw, RunCount: 5,
		CompliancePct: 40, CoveragePct: 80,
		TotalControls: 20, TestableControls: 20, TestedControls: 10,
		PassingControls: 4, FailingControls: 6, ManualControls: 0,
	}); err != nil {
		t.Fatalf("seed agent-a: %v", err)
	}

	// Agent B: better score (90%) and 134 runs of evidence.
	if err := db.UpsertComplianceSnapshot(ctx, sharedDB.Pool, db.ComplianceSnapshot{
		AgentID: "test-agent-b", FrameworkID: fw, RunCount: 134,
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

	if got.AgentID != "test-agent-b" {
		t.Errorf("AgentID = %q, want the most-tested agent test-agent-b", got.AgentID)
	}
	if got.CompliancePct != 90 {
		t.Errorf("CompliancePct = %v, want 90 (agent-b's real score)", got.CompliancePct)
	}
	// These must belong to agent-b specifically, not summed across both agents.
	if got.PassingControls != 9 {
		t.Errorf("PassingControls = %d, want 9 (agent-b's own count, not summed across agents)", got.PassingControls)
	}
	if got.FailingControls != 1 {
		t.Errorf("FailingControls = %d, want 1 (agent-b's own count, not summed across agents)", got.FailingControls)
	}
	if got.EnrolledAgentCount != 2 {
		t.Errorf("EnrolledAgentCount = %d, want 2", got.EnrolledAgentCount)
	}
}
