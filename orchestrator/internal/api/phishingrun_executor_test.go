package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
)

func TestExecutePhishingRun_UnregisteredScenario_NoRowInserted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure schema: %v", err)
		}
		_, err := ExecutePhishingRun(ctx, pool, PhishingRunExecutorEnv{}, PhishingRunRequest{ScenarioID: "PH-BEC-002"})
		if err == nil {
			t.Fatal("want an error for an unregistered scenario id")
		}
		runs, _ := db.ListPhishingRuns(ctx, pool, 10)
		if len(runs) != 0 {
			t.Errorf("rows inserted = %d, want 0 (an unregistered scenario must never create a row)", len(runs))
		}
	})
}

func TestExecutePhishingRun_MissingParams_StatusFailed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure schema: %v", err)
		}
		env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider(nil)}
		run, err := ExecutePhishingRun(ctx, pool, env, PhishingRunRequest{ScenarioID: "PH-DET-002"})
		if err == nil {
			t.Fatal("want an error for missing executionId/targetId")
		}
		if run.Status != phishingrun.StatusFailed {
			t.Errorf("Status = %q, want failed", run.Status)
		}
	})
}

func TestExecutePhishingRun_PHDET002_EndToEnd_Completed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("ensure schema: %v", err)
		}
		env := PhishingRunExecutorEnv{ReportTicketProvider: phishbridge.NewFixtureReportTicketProvider([]phishbridge.ReportTicketEvidence{{
			ExecutionID: "exec-1", TargetID: "target-1", TicketCreated: true, Timestamp: time.Now(),
		}})}
		run, err := ExecutePhishingRun(ctx, pool, env, PhishingRunRequest{
			ScenarioID: "PH-DET-002", Parameters: map[string]any{"executionId": "exec-1", "targetId": "target-1"}, InitiatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("ExecutePhishingRun: %v", err)
		}
		if run.Status != phishingrun.StatusCompleted {
			t.Fatalf("Status = %q, want completed", run.Status)
		}

		persisted, err := db.GetPhishingRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("GetPhishingRun: %v", err)
		}
		var outcome phishval.Outcome
		if err := json.Unmarshal(persisted.Result, &outcome); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if outcome.Response.Verdict != phishval.VerdictPass {
			t.Errorf("Response.Verdict = %q, want pass", outcome.Response.Verdict)
		}
	})
}
