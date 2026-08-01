package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

func TestFilterByAsOf_ExcludesFutureResults(t *testing.T) {
	now := time.Now().UTC()
	all := []models.SimulationResult{{ExecutedAt: now}}
	got := filterByAsOf(all, now.Add(-24*time.Hour))
	if len(got) != 0 {
		t.Errorf("got %d results, want 0 (fixture result is at 'now', cutoff is 24h before)", len(got))
	}
}
