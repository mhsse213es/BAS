package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchBasRevalidationTarget_Dispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('bv-t1', 'BV-T1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-bv-t1', 'enable_windows_firewall', 'bv-t1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "bv-t1")

		h := New(pool, hub, eng, "")

		payload, _ := json.Marshal(basRevalidationPayload{
			RequestID: "rr-bv-t1", AgentID: "bv-t1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082",
		})
		job := jobs.Job{ID: "job-bv1", Type: "bas_revalidation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-bv1", JobID: "job-bv1", AgentID: "bv-t1"}

		refID, err := h.dispatchBasRevalidationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBasRevalidationTarget: %v", err)
		}
		if refID == "" {
			t.Fatal("refID is empty")
		}
		var status, runID, requestID string
		if err := pool.QueryRow(context.Background(),
			`SELECT status, run_id, request_id FROM technique_verification_runs WHERE id=$1`, refID,
		).Scan(&status, &runID, &requestID); err != nil {
			t.Fatalf("query technique_verification_runs: %v", err)
		}
		if status != "dispatched" || runID == "" {
			t.Errorf("status=%q runID=%q, want status=dispatched and a non-empty runID", status, runID)
		}
		if requestID != "rr-bv-t1" {
			t.Errorf("request_id = %q, want rr-bv-t1", requestID)
		}
	})
}

func TestDispatchBasRevalidationTarget_AgentNotConnected_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('bv-t2', 'BV-T2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-bv-t2', 'enable_windows_firewall', 'bv-t2', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")

		h := New(pool, ws.NewHub(), eng, "") // no fake agent connected

		payload, _ := json.Marshal(basRevalidationPayload{
			RequestID: "rr-bv-t2", AgentID: "bv-t2", CheckID: "windows-firewall-enabled", TechniqueID: "T1082",
		})
		job := jobs.Job{ID: "job-bv2", Type: "bas_revalidation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-bv2", JobID: "job-bv2", AgentID: "bv-t2"}

		if _, err := h.dispatchBasRevalidationTarget(context.Background(), job, target); err == nil {
			t.Fatal("expected an error, agent not connected")
		}

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM technique_verification_runs WHERE request_id='rr-bv-t2'`).Scan(&status)
		if status != "error" {
			t.Errorf("status = %q, want error", status)
		}
	})
}

func TestBasRevalidationTargetStatus_MapsCheckResultToTargetState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('bv-t3', 'BV-T3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-bv-t3', 'enable_windows_firewall', 'bv-t3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		cases := []struct {
			status       string
			wantState    string
			wantTerminal bool
		}{
			{"pass", jobs.TargetStateCompleted, true},
			{"fail", jobs.TargetStateFailed, true},
			{"error", jobs.TargetStateFailed, true},
			{"blocked", jobs.TargetStateFailed, true},
			{"skipped", jobs.TargetStateFailed, true},
			{"requested", jobs.TargetStateDispatched, false},
			{"dispatched", jobs.TargetStateDispatched, false},
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		for i, c := range cases {
			id := "tvr-bv-t3-" + string(rune('a'+i))
			mustExecAPI(t, pool, `
				INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
				VALUES ($1, 'rr-bv-t3', 'bv-t3', 'windows-firewall-enabled', 'T1082', $2, 'user-1')`, id, c.status)

			state, _, terminal := h.basRevalidationTargetStatus(context.Background(), "bas_revalidation", id)
			if state != c.wantState || terminal != c.wantTerminal {
				t.Errorf("status=%q: state=%q terminal=%v, want state=%q terminal=%v", c.status, state, terminal, c.wantState, c.wantTerminal)
			}
		}
	})
}
