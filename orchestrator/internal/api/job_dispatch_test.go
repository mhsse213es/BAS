package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/remediation"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestDispatchBatchRemediationTarget_Dispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-t1', 'JB-T1', 'windows')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "jb-t1")

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, hub, eng, "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job := jobs.Job{ID: "job-1", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-1", JobID: "job-1", AgentID: "jb-t1"}

		refID, err := h.dispatchBatchRemediationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBatchRemediationTarget: %v", err)
		}
		if refID == "" {
			t.Fatal("refID is empty")
		}
		var status, fixRunID string
		if err := pool.QueryRow(context.Background(), `SELECT status, fix_run_id FROM remediation_requests WHERE id=$1`, refID).Scan(&status, &fixRunID); err != nil {
			t.Fatalf("query remediation_requests: %v", err)
		}
		if status != remediation.StatusDispatched || fixRunID == "" {
			t.Errorf("status=%q fixRunID=%q, want status=dispatched and a non-empty fixRunID", status, fixRunID)
		}
	})
}

func TestDispatchBatchRemediationTarget_AlreadyCompliant_MarksCompletedWithoutDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-t2', 'JB-T2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('jb-t2-run', 'windows-security-config', 'Posture Run', 'jb-t2', 'completed', $1::jsonb, NOW())`,
			`[{"checkId":"windows-firewall-enabled","result":"pass","executedAt":"2026-08-03T00:00:00Z"}]`)
		eng := scenario.NewEngine(t.TempDir())
		hub := ws.NewHub()

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, hub, eng, "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job := jobs.Job{ID: "job-2", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-2", JobID: "job-2", AgentID: "jb-t2"}

		refID, err := h.dispatchBatchRemediationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBatchRemediationTarget: %v", err)
		}
		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM remediation_requests WHERE id=$1`, refID).Scan(&status); err != nil {
			t.Fatalf("query remediation_requests: %v", err)
		}
		if status != remediation.StatusCompleted {
			t.Errorf("status = %q, want completed (already compliant, no dispatch needed)", status)
		}
	})
}

func TestDispatchBatchRemediationTarget_ContinuousValidation_PersistsFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-cv1', 'JB-CV1', 'windows')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "jb-cv1")

		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, hub, eng, "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(batchRemediationPayload{RemediationID: "enable_windows_firewall", Reason: "test", ContinuousValidation: true})
		job := jobs.Job{ID: "job-cv1", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-cv1", JobID: "job-cv1", AgentID: "jb-cv1"}

		refID, err := h.dispatchBatchRemediationTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchBatchRemediationTarget: %v", err)
		}
		var flag bool
		if err := pool.QueryRow(context.Background(), `SELECT continuous_validation FROM remediation_requests WHERE id=$1`, refID).Scan(&flag); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !flag {
			t.Error("continuous_validation = false, want true")
		}
	})
}

func TestDispatchJobTarget_RoutesByJobType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jt-r1', 'JT-R1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-jt-r1', 'enable_windows_firewall', 'jt-r1', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		eng := scenario.NewEngine(t.TempDir())
		registerFixtureScenario(t, eng, "windows-firewall-enabled")
		hub := ws.NewHub()
		startFakeAgent(t, hub, "jt-r1")

		h := New(pool, hub, eng, "")

		payload, _ := json.Marshal(basRevalidationPayload{
			RequestID: "rr-jt-r1", AgentID: "jt-r1", CheckID: "windows-firewall-enabled", TechniqueID: "T1082",
		})
		job := jobs.Job{ID: "job-jt1", Type: "bas_revalidation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-jt1", JobID: "job-jt1", AgentID: "jt-r1"}

		refID, err := h.dispatchJobTarget(context.Background(), job, target)
		if err != nil {
			t.Fatalf("dispatchJobTarget: %v", err)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM technique_verification_runs WHERE id=$1`, refID).Scan(&status)
		if status != "dispatched" {
			t.Errorf("status = %q, want dispatched (should have routed to dispatchBasRevalidationTarget)", status)
		}

		state, _, terminal := h.statusForJobTarget(context.Background(), "bas_revalidation", refID)
		if terminal {
			t.Error("terminal = true, want false (status is still 'dispatched')")
		}
		if state != jobs.TargetStateDispatched {
			t.Errorf("state = %q, want dispatched", state)
		}
	})
}

func TestDispatchJobTarget_UnknownType_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		job := jobs.Job{ID: "job-unk", Type: "does_not_exist", Payload: []byte(`{}`), CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-unk", JobID: "job-unk", AgentID: "agent-unk"}
		if _, err := h.dispatchJobTarget(context.Background(), job, target); err == nil {
			t.Fatal("expected an error for an unknown job type")
		}
	})
}

func TestDispatchBatchRemediationTarget_UnknownRemediationID_Errors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('jb-t4', 'JB-T4', 'windows')`)
		cat, err := remediation.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithRemediationCatalog(cat)

		payload, _ := json.Marshal(map[string]string{"remediationId": "does_not_exist", "reason": "test"})
		job := jobs.Job{ID: "job-4", Type: "batch_remediation", Payload: payload, CreatedBy: "user-1"}
		target := jobs.JobTarget{ID: "target-4", JobID: "job-4", AgentID: "jb-t4"}

		if _, err := h.dispatchBatchRemediationTarget(context.Background(), job, target); err == nil {
			t.Fatal("expected an error for an unknown remediationId")
		}
	})
}

func TestBatchRemediationTargetStatus_MapsRemediationStatusToTargetState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jb-t3', 'JB-T3')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-jb-t3', 'enable_windows_firewall', 'jb-t3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		state, errText, terminal := h.batchRemediationTargetStatus(context.Background(), "batch_remediation", "rr-jb-t3")
		if state != jobs.TargetStateCompleted || !terminal || errText != "" {
			t.Errorf("state=%q terminal=%v errText=%q, want completed/true/empty", state, terminal, errText)
		}
	})
}

func TestBatchRemediationTargetStatus_StillRunningIsNotTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('jb-t5', 'JB-T5')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-jb-t5', 'enable_windows_firewall', 'jb-t5', 'windows-firewall-enabled', 1, 'verifying', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		state, _, terminal := h.batchRemediationTargetStatus(context.Background(), "batch_remediation", "rr-jb-t5")
		if terminal {
			t.Errorf("terminal = true, want false (status is still 'verifying')")
		}
		if state != jobs.TargetStateDispatched {
			t.Errorf("state = %q, want dispatched (still in progress)", state)
		}
	})
}
