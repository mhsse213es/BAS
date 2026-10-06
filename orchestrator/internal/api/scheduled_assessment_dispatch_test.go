package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchScheduledAssessmentTarget_PostureMode_CreatesScenarioRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('sa-disp-1', 'SA-DISP-HOST', 'windows')`)

		eng := scenario.NewEngine(t.TempDir())
		eng.SetVerifier(testutil.DevVerifier())
		eng.AttachRegistry(contentregistry.New(sharedDB.Pool, testutil.DevVerifier()))
		registerFixtureScenario(t, eng, "fixture-check")
		h := New(pool, ws.NewHub(), eng, "")
		fake := startFakeAgent(t, h.hub, "sa-disp-1")
		defer fake.Disconnect(t)

		payload, _ := json.Marshal(scheduledAssessmentPayload{ScenarioID: "fixture-scenario", Mode: "posture"})
		job := jobs.Job{ID: "job-1", Type: "scheduled_assessment", CreatedBy: "sched-1", Payload: payload}
		target := jobs.JobTarget{ID: "target-1", JobID: "job-1", AgentID: "sa-disp-1"}

		runID, err := h.dispatchScheduledAssessmentTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchScheduledAssessmentTarget: %v", err)
		}
		if runID == "" {
			t.Fatal("got empty runID")
		}

		var scenarioID, agentID, status string
		if err := pool.QueryRow(context.Background(),
			`SELECT scenario_id, agent_id, status FROM scenario_runs WHERE id=$1`, runID,
		).Scan(&scenarioID, &agentID, &status); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if scenarioID != "fixture-scenario" || agentID != "sa-disp-1" {
			t.Errorf("scenario_runs row: scenarioId=%q agentId=%q, want fixture-scenario/sa-disp-1", scenarioID, agentID)
		}

		state, _, terminal := h.scheduledAssessmentTargetStatus(context.Background(), "scheduled_assessment", runID)
		if terminal {
			t.Errorf("status: terminal = true immediately after dispatch, want false (run just started)")
		}
		if state != jobs.TargetStateDispatched {
			t.Errorf("status: state = %q, want %q", state, jobs.TargetStateDispatched)
		}
	})
}

func TestDispatchScheduledAssessmentTarget_UnknownScenario_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		payload, _ := json.Marshal(scheduledAssessmentPayload{ScenarioID: "does-not-exist", Mode: "posture"})
		job := jobs.Job{ID: "job-2", Type: "scheduled_assessment", Payload: payload}
		target := jobs.JobTarget{ID: "target-2", JobID: "job-2", AgentID: "no-such-agent"}

		if _, err := h.dispatchScheduledAssessmentTarget(context.Background(), job, target); err == nil {
			t.Error("got nil error for an unknown scenarioId, want an error")
		}
	})
}
