package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestBasReadinessInput_ComputesPassRateAndTechCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-a1', 'ER-HOST-1')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-run-1', 'er-scn-1', 'ER Test Run', 'er-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"technique":{"id":"T1059","name":"PowerShell","tactic":"execution"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"},
				{"technique":{"id":"T1003","name":"OS Credential Dumping","tactic":"credential-access"},"result":"fail","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"},
				{"technique":{"id":"T1078","name":"Valid Accounts","tactic":"defense-evasion"},"result":"skipped","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(ctx, "er-a1")
		got := h.basReadinessInput(time.Now().UTC().Add(time.Hour), all)
		if !got.Collected {
			t.Fatal("expected Collected=true")
		}
		if got.PassRate != 50 {
			t.Errorf("PassRate = %.1f, want 50 (1 pass, 1 fail, skipped excluded)", got.PassRate)
		}
		if got.TechniquesTested != 2 {
			t.Errorf("TechniquesTested = %d, want 2", got.TechniquesTested)
		}
	})
}

func TestBasReadinessInput_NoResults_NotCollected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(context.Background(), "no-such-agent-ever")
		got := h.basReadinessInput(time.Now().UTC(), all)
		if got.Collected {
			t.Error("expected Collected=false for an agent with no results")
		}
	})
}

func TestPostureCheckInput_WeightedScoreAndCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pc-a1', 'ER-PC-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pc-run', 'windows-security-config', 'Posture Run', 'er-pc-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"checkId":"windows-firewall-enabled","technique":{"id":"T1562.004"},"result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"},
				{"checkId":"windows-bitlocker-enabled","technique":{"id":""},"result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"},
				{"checkId":"windows-guest-account-disabled","technique":{"id":"T1078"},"result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx

		all := h.aggregateAgentResults(context.Background(), "er-pc-a1")
		got := h.securityConfigInput(context.Background(), "er-pc-a1", now.Add(time.Hour), all)
		if !got.Collected {
			t.Fatal("expected Collected=true")
		}
		if got.Total != 2 || got.Passed != 1 || got.Failed != 1 {
			t.Errorf("Total/Passed/Failed = %d/%d/%d, want 2/1/1", got.Total, got.Passed, got.Failed)
		}
		if got.Score != 50 {
			t.Errorf("Score = %d, want 50 (equal weight, 1 of 2 passed)", got.Score)
		}
		if len(got.Findings) != 1 || got.Findings[0].ID != "windows-bitlocker-enabled" {
			t.Errorf("Findings = %+v, want exactly windows-bitlocker-enabled", got.Findings)
		}

		gotIdentity := h.identityInput(context.Background(), "er-pc-a1", now.Add(time.Hour), all)
		if !gotIdentity.Collected || gotIdentity.Total != 1 || gotIdentity.Passed != 1 {
			t.Errorf("identity input = %+v, want Collected=true Total=1 Passed=1", gotIdentity)
		}
	})
}

func TestPostureCheckInput_UnmappedCheckID_Skipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pc-a2', 'ER-PC-HOST-2')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pc-run-2', 'custom', 'Unmapped Run', 'er-pc-a2', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"no-such-check","result":"fail","executedAt":"`+now.Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx

		all := h.aggregateAgentResults(context.Background(), "er-pc-a2")
		got := h.securityConfigInput(context.Background(), "er-pc-a2", now.Add(time.Hour), all)
		if got.Collected {
			t.Error("expected Collected=false -- the only result has an unmapped check_id")
		}
	})
}

func TestPostureCheckInput_NoResults_NotCollected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx

		all := h.aggregateAgentResults(context.Background(), "no-such-agent-ever-pc")
		got := h.securityConfigInput(context.Background(), "no-such-agent-ever-pc", time.Now().UTC(), all)
		if got.Collected {
			t.Error("expected Collected=false for an agent with no results")
		}
	})
}

func TestPostureCheckInput_HistoricalAsOf_LatestPerCheckBeforeCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-pc-a3', 'ER-PC-HOST-3')`)
		early := time.Now().UTC().Add(-48 * time.Hour)
		late := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-pc-run-3', 'windows-security-config', 'Regression Run', 'er-pc-a3', 'completed', $1::jsonb, NOW())`,
			`[
				{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"`+early.Format(time.RFC3339)+`"},
				{"checkId":"windows-firewall-enabled","result":"fail","executedAt":"`+late.Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx

		all := h.aggregateAgentResults(context.Background(), "er-pc-a3")

		asOfEarly := early.Add(time.Minute)
		gotEarly := h.securityConfigInput(context.Background(), "er-pc-a3", asOfEarly, all)
		if gotEarly.Failed != 0 || gotEarly.Passed != 1 {
			t.Errorf("as-of just after the early pass: Passed/Failed = %d/%d, want 1/0", gotEarly.Passed, gotEarly.Failed)
		}

		asOfLate := late.Add(time.Minute)
		gotLate := h.securityConfigInput(context.Background(), "er-pc-a3", asOfLate, all)
		if gotLate.Failed != 1 || gotLate.Passed != 0 {
			t.Errorf("as-of after the later fail: Passed/Failed = %d/%d, want 0/1", gotLate.Passed, gotLate.Failed)
		}
		if gotLate.Findings[0].LastPassed == nil {
			t.Error("LastPassed should be set to the early pass's timestamp, not nil")
		}
	})
}

func TestFilterByAsOf_ExcludesFutureResults(t *testing.T) {
	now := time.Now().UTC()
	all := []models.SimulationResult{{ExecutedAt: now}}
	got := filterByAsOf(all, now.Add(-24*time.Hour))
	if len(got) != 0 {
		t.Errorf("got %d results, want 0 (fixture result is at 'now', cutoff is 24h before)", len(got))
	}
}
