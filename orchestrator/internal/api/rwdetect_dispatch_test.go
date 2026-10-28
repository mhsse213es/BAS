package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// recordingConnector is a detectverify.Connector stand-in that records every
// query it receives and returns a fixed verdict.
type recordingConnector struct {
	verdict string
	calls   int
}

func (c *recordingConnector) Verify(_ context.Context, _ detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	c.calls++
	return detectverify.VerifyResult{Verdict: c.verdict}, nil
}

func (c *recordingConnector) TestConnection(context.Context) error { return nil }

// seedRansomwareStep dispatches one ransomware-scoped step and submits its
// result. executedAt is the agent's timestamp, or the zero value to exercise
// the orchestrator fallback.
func seedRansomwareStep(t *testing.T, h *Handler, pool *pgxpool.Pool, runID, agentID string, executedAt time.Time) {
	t.Helper()
	stepName := "VSS Shadow Copy Enumeration (lab)"
	taskID := scenario.TaskID("T1490", stepName)
	seedRunRow(t, pool, runID, "akira-kill-chain", agentID, "running")
	if _, err := pool.Exec(context.Background(), `UPDATE agents SET hostname='WS-RW', ip_address='10.0.0.20' WHERE agent_id=$1`, agentID); err != nil {
		t.Fatal(err)
	}
	meta := map[string]scenario.StepMeta{taskID: {TechniqueID: "T1490", Name: stepName, Framework: "custom"}}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta=$2 WHERE id=$1`, runID, raw); err != nil {
		t.Fatal(err)
	}
	result := scenario.ExecResult{TaskID: taskID, ExitCode: 0, Stdout: "EXEC enumeration completed"}
	if !executedAt.IsZero() {
		result.ExecutedAt = executedAt
	}
	submitResultOK(t, h, scenario.RawRunResult{
		RunID: runID, ScenarioID: "akira-kill-chain", AgentID: agentID,
		Results: []scenario.ExecResult{result},
	})
}

func detectionRow(t *testing.T, pool *pgxpool.Pool, runID string) (verdict, reason string) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT verdict, reason FROM rw_capability_results WHERE run_id=$1 AND capability='detection'`, runID).
		Scan(&verdict, &reason)
	if err != nil {
		t.Fatalf("read detection row for %s: %v", runID, err)
	}
	return verdict, reason
}

func TestRWDetection_NoConnectorConfiguredStaysNotTested(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rwdet-none"
		seedRansomwareStep(t, h, pool, runID, "agent-rwdet-none", time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC))

		verdict, _ := detectionRow(t, pool, runID)
		if verdict != "SKIPPED" {
			t.Fatalf("verdict = %q, want SKIPPED when no connector is configured", verdict)
		}
	})
}

func TestRWDetection_ConfiguredConnectorVerifiesWithProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		conn := &recordingConnector{verdict: detectverify.VerdictDetected}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithDetectionConnector(conn)
		runID := "rwdet-detected"
		seedRansomwareStep(t, h, pool, runID, "agent-rwdet-detected", time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC))

		if conn.calls != 1 {
			t.Fatalf("connector queried %d times, want 1", conn.calls)
		}
		verdict, reason := detectionRow(t, pool, runID)
		if verdict != "PASS" {
			t.Fatalf("verdict = %q, want PASS for a detected verdict", verdict)
		}
		for _, want := range []string{"WS-RW", "10.0.0.20", "2026-10-28T09:00:00Z", "time source=step execution timestamp"} {
			if !strings.Contains(reason, want) {
				t.Fatalf("reason %q missing provenance %q", reason, want)
			}
		}
	})
}

func TestRWDetection_FallbackTimestampIsNeverQueriedAsEventTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		conn := &recordingConnector{verdict: detectverify.VerdictDetected}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithDetectionConnector(conn)
		runID := "rwdet-fallback"
		seedRansomwareStep(t, h, pool, runID, "agent-rwdet-fallback", time.Time{})

		if conn.calls != 0 {
			t.Fatal("a submission-time fallback must never drive a connector query")
		}
		verdict, reason := detectionRow(t, pool, runID)
		if verdict != "SKIPPED" {
			t.Fatalf("verdict = %q, want SKIPPED (inconclusive)", verdict)
		}
		if !strings.Contains(reason, "fallback") {
			t.Fatalf("reason %q must say the timestamp was a fallback", reason)
		}
	})
}
