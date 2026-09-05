package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runAdversaryTemplateReq(id string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return withURLParam(httptest.NewRequest(http.MethodPost, "/api/adversary-templates/"+id+"/run", bytes.NewReader(b)), "id", id)
}

func TestRunAdversaryTemplate_MultipleAgentIDs_DispatchesToEach(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalLiveScenario(t, "apt29-kill-chain")
		h := New(pool, ws.NewHub(), engine, "")
		a1, a2 := "rat-multi-agent-1", "rat-multi-agent-2"
		seedActiveAgent(t, pool, a1, "Windows")
		seedActiveAgent(t, pool, a2, "Windows")
		fake1 := startFakeAgent(t, h.hub, a1)
		defer fake1.Disconnect(t)
		fake2 := startFakeAgent(t, h.hub, a2)
		defer fake2.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"agentIds": []string{a1, a2}, "mode": "telemetry", "useBas": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Dispatched []struct {
				AgentID string `json:"agentId"`
				Source  string `json:"source"`
				RunID   string `json:"runId"`
			} `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Dispatched) != 2 {
			t.Fatalf("dispatched = %+v, want exactly 2 entries (one per agent)", out.Dispatched)
		}
		seen := map[string]bool{}
		for _, d := range out.Dispatched {
			if d.RunID == "" {
				t.Errorf("entry %+v missing runId", d)
			}
			seen[d.AgentID] = true
		}
		if !seen[a1] || !seen[a2] {
			t.Fatalf("dispatched agentIds = %+v, want both %s and %s", out.Dispatched, a1, a2)
		}
	})
}

func TestRunAdversaryTemplate_GroupIDs_ResolvesToMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, engine := minimalLiveScenario(t, "apt29-kill-chain")
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, "").WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		var groupID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO agent_groups (name) VALUES ('RAT Group Test') RETURNING id`).Scan(&groupID); err != nil {
			t.Fatalf("insert group: %v", err)
		}
		a1, a2 := "rat-group-agent-1", "rat-group-agent-2"
		for _, aid := range []string{a1, a2} {
			if _, err := pool.Exec(ctx,
				`INSERT INTO agents (agent_id, hostname, os_version, state, group_id) VALUES ($1,'h','Windows','active',$2)`,
				aid, groupID); err != nil {
				t.Fatalf("seed grouped agent %s: %v", aid, err)
			}
		}
		fake1 := startFakeAgent(t, h.hub, a1)
		defer fake1.Disconnect(t)
		fake2 := startFakeAgent(t, h.hub, a2)
		defer fake2.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"groupIds": []int64{groupID}, "mode": "telemetry", "useBas": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Dispatched []struct {
				AgentID string `json:"agentId"`
			} `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Dispatched) != 2 {
			t.Fatalf("dispatched = %+v, want exactly 2 entries (one per group member)", out.Dispatched)
		}
	})
}

func TestRunAdversaryTemplate_NoTargets_400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalLiveScenario(t, "apt29-kill-chain")
		h := New(pool, ws.NewHub(), engine, "")
		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"mode": "telemetry", "useBas": true,
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (no agentId/agentIds/groupIds given), body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestRunAdversaryTemplate_DuplicateAgentAcrossFields_NotDoubleDispatched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalLiveScenario(t, "apt29-kill-chain")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "rat-dedup-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		// Same agent named both via legacy agentId AND the new agentIds list --
		// must dedupe to a single dispatch, not run it twice.
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"agentId": agentID, "agentIds": []string{agentID}, "mode": "telemetry", "useBas": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Dispatched []struct {
				AgentID string `json:"agentId"`
			} `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Dispatched) != 1 {
			t.Fatalf("dispatched = %+v, want exactly 1 entry (deduped), not one per field", out.Dispatched)
		}
	})
}

// TestRunAdversaryTemplate_ExecutionPolicyFiltersStep uses the built-in
// "apt29-quick" template, whose BASScenarioID is "apt29-kill-chain" — a
// scenario is registered under that exact ID so the template's BAS branch
// resolves it via h.engine.Get, without needing a real ART store or Caldera.
func TestRunAdversaryTemplate_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "user-step", TechniqueID: "T1059", Framework: "custom", Command: "echo user",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		_, engine := minimalLiveScenario(t, "apt29-kill-chain", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "rat-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"agentId": agentID, "mode": "telemetry", "useBas": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var out struct {
			Dispatched []struct {
				Source string `json:"source"`
				RunID  string `json:"runId"`
			} `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Dispatched) != 1 || out.Dispatched[0].RunID == "" {
			t.Fatalf("out = %+v, want exactly 1 dispatched entry with a runId", out)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id=$1`, out.Dispatched[0].RunID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("query policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(skipped) != 1 || skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("policy_skipped_results = %+v, want 1 policy-privilege skip", skipped)
		}
	})
}

// TestRunAdversaryTemplate_ARTBranchDoesNotDependOnSelectiveScenario proves
// the ART branch synthesizes its own ad-hoc scenario instead of loading a
// standalone "art-selective" catalog entry (which no longer exists — the
// operator-facing "Selective" scenarios were removed, only Full Sweep
// remains there). No scenario named "art-selective" is registered in this
// test's engine at all; the old code path would skip with "art-selective
// scenario not loaded" here, the new one reaches real ART step-building and
// fails there instead (no ART store configured in this test), proving the
// dependency on the catalog entry is gone.
func TestRunAdversaryTemplate_ARTBranchDoesNotDependOnSelectiveScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalLiveScenario(t, "apt29-kill-chain")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "rat-art-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"agentId": agentID, "mode": "telemetry", "useArt": true,
		}))
		// No ART store is configured in this test, so the ART branch is
		// expected to fail past dispatch (asserted below) -- what matters
		// here is WHERE it fails, not that it fully succeeds.

		var out struct {
			Skipped []struct {
				Source string `json:"source"`
				Reason string `json:"reason"`
			} `json:"skipped"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		var artResult *struct {
			Source string `json:"source"`
			Reason string `json:"reason"`
		}
		for i := range out.Skipped {
			if out.Skipped[i].Source == "art" {
				artResult = &out.Skipped[i]
			}
		}
		if artResult == nil {
			t.Fatalf("out = %+v, want an art-source skip entry", out)
		}
		if artResult.Reason == "art-selective scenario not loaded" {
			t.Fatalf("art skip reason = %q, still depends on the removed art-selective scenario", artResult.Reason)
		}
	})
}
