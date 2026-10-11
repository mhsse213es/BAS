package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwevidence"
)

func TestWriteRWCapabilityResults_RoundTripAndUpsertNoDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		runID := "test-run-upsert"

		results := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: controlval.VerdictFail, Reason: "allowed"},
			{Capability: rwevidence.CapabilityRecovery, TechniqueID: "T1490", Verdict: controlval.VerdictPass, Reason: "survived"},
		}
		if err := db.WriteRWCapabilityResults(ctx, pool, runID, "action-1", results); err != nil {
			t.Fatalf("first write: %v", err)
		}

		rows, err := db.RWCapabilityCoverage(ctx, pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2", len(rows))
		}

		// Retry: same run/action/capability -- must overwrite, not duplicate.
		retried := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: controlval.VerdictPass, Reason: "blocked on retry"},
		}
		if err := db.WriteRWCapabilityResults(ctx, pool, runID, "action-1", retried); err != nil {
			t.Fatalf("retry write: %v", err)
		}
		rows, err = db.RWCapabilityCoverage(ctx, pool, runID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("after retry, got %d rows, want 2 (upsert, not a duplicate)", len(rows))
		}
	})
}

func TestSummarizeRWCoverage_DistinguishesEvaluatedNotApplicableAndNotTestedReasons(t *testing.T) {
	rows := []db.RWCoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 3},
		{Capability: "recovery", Verdict: "FAIL", Count: 1},
		{Capability: "containment", Verdict: "SKIPPED", SkipReason: "not_applicable", Count: 2},
		{Capability: "data_protection", Verdict: "SKIPPED", SkipReason: "not_tested", SpecificReason: "technique_not_mapped", Count: 10},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "not_tested", SpecificReason: "gate_not_confirmed", Count: 1},
	}
	s := db.SummarizeRWCoverage(rows)
	if s.Evaluated != 4 { // PASS(3) + FAIL(1)
		t.Errorf("evaluated = %d, want 4", s.Evaluated)
	}
	if s.NotApplicable != 2 {
		t.Errorf("notApplicable = %d, want 2", s.NotApplicable)
	}
	if s.NotTestedByReason["technique_not_mapped"] != 10 {
		t.Errorf("not_tested/technique_not_mapped = %d, want 10", s.NotTestedByReason["technique_not_mapped"])
	}
	if s.NotTestedByReason["gate_not_confirmed"] != 1 {
		t.Errorf("not_tested/gate_not_confirmed = %d, want 1", s.NotTestedByReason["gate_not_confirmed"])
	}
}

func TestWriteRWCapabilityResults_RejectsInvalidSkipPair(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		bad := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: controlval.VerdictFail, SkipReason: controlval.SkipInsufficientEvidence},
		}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, "test-run-invalid", "action-1", bad); err == nil {
			t.Fatal("expected an error -- FAIL must never carry a SkipReason, application code must reject this before it reaches the DB")
		}
	})
}
