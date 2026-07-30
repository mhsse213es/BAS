package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestCompliance_EmptyAgentID_ReturnsFleetScores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.UpsertComplianceSnapshot(ctx, pool, db.ComplianceSnapshot{
			AgentID: "agent-1", FrameworkID: "ISO_27001_2022", RunCount: 3,
			CompliancePct: 75.0, CoveragePct: 80.0, TotalControls: 10,
		}); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}

		got, err := Compliance(ctx, pool, "")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if len(got) != 1 || got[0].FrameworkID != "ISO_27001_2022" {
			t.Fatalf("Compliance(\"\") = %+v, want 1 row for ISO_27001_2022", got)
		}
	})
}

func TestCompliance_WithAgentID_ReturnsThatAgentsScores(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.UpsertComplianceSnapshot(ctx, pool, db.ComplianceSnapshot{
			AgentID: "agent-compliance-test", FrameworkID: "PCI_DSS_V4", RunCount: 2,
			CompliancePct: 60.0, CoveragePct: 70.0, TotalControls: 40,
		}); err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}

		got, err := Compliance(ctx, pool, "agent-compliance-test")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if len(got) != 1 || got[0].AgentID != "agent-compliance-test" {
			t.Fatalf("Compliance(agent-compliance-test) = %+v, want 1 row for that agent", got)
		}
	})
}
