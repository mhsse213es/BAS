package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatchRun_AgentStateGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-agentstate")
		h := New(pool, ws.NewHub(), engine, "")
		for _, state := range []string{"restricted", "quarantined", "retired"} {
			agentID := "dr-agent-state-" + state
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h',$2)`, agentID, state); err != nil {
				t.Fatalf("seed agent: %v", err)
			}
			runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
			if err != nil {
				t.Fatalf("state=%s: unexpected error %v", state, err)
			}
			if runID != "" || skip != "agent "+state {
				t.Fatalf("state=%s: runID=%q skip=%q, want empty runID and skip=%q", state, runID, skip, "agent "+state)
			}
			var count int
			pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM scenario_runs WHERE agent_id=$1`, agentID).Scan(&count)
			if count != 0 {
				t.Fatalf("state=%s: run row created despite gate", state)
			}
		}
	})
}

func TestDispatchRun_OSMismatch_LiveBlocksPostureProceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		live, liveEngine := minimalLiveScenario(t, "dr-osmismatch-live")
		live.SupportedOS = []string{"linux"}
		if err := liveEngine.Save(live); err != nil {
			t.Fatalf("re-save: %v", err)
		}
		hLive := New(pool, ws.NewHub(), liveEngine, "")
		agentID := "dr-agent-osmismatch"
		seedActiveAgent(t, pool, agentID, "Windows Server 2022")

		runID, skip, err := hLive.dispatchRun(context.Background(), live, agentID, dispatchOpts{Mode: "telemetry", ConfirmLive: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if runID != "" || skip != "os mismatch" {
			t.Fatalf("live: runID=%q skip=%q, want empty runID and skip=os mismatch", runID, skip)
		}

		posture, postureEngine := minimalPostureScenario(t, "dr-osmismatch-posture")
		posture.SupportedOS = []string{"linux"}
		if err := postureEngine.Save(posture); err != nil {
			t.Fatalf("re-save posture: %v", err)
		}
		hPosture := New(pool, ws.NewHub(), postureEngine, "")
		fake := startFakeAgent(t, hPosture.hub, agentID)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := hPosture.dispatchRun(context.Background(), posture, agentID, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("posture: runID=%q skip=%q err=%v, want a real runID with no skip", runID2, skip2, err2)
		}
	})
}

func TestDispatchRun_ConcurrencyGuard_BusyAndStaleCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-busy")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-busy"
		seedActiveAgent(t, pool, agentID, "Windows")

		// Fresh, non-stale running run blocks a new dispatch.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at) VALUES ('run-fresh',$1,$2,'x','running',NOW())`,
			sc.ID, agentID); err != nil {
			t.Fatalf("seed fresh running run: %v", err)
		}
		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || skip != "agent busy" {
			t.Fatalf("fresh busy: runID=%q skip=%q err=%v, want skip=agent busy", runID, skip, err)
		}

		// Replace with a stale running run (agent hasn't heartbeated recently)
		// and confirm it gets freed to 'partial' and the new dispatch proceeds.
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET id='run-stale', started_at = NOW() - interval '3 hours' WHERE id='run-fresh'`); err != nil {
			t.Fatalf("age the run: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("age the agent: %v", err)
		}
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("after stale cleanup: runID=%q skip=%q err=%v, want a real new runID", runID2, skip2, err2)
		}
		if runID2 == "run-stale" {
			t.Fatal("dispatch reused the stale run's id instead of creating a new one")
		}

		var staleStatus string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, completed_at FROM scenario_runs WHERE id='run-stale'`).Scan(&staleStatus, &completedAt); err != nil {
			t.Fatalf("read stale run: %v", err)
		}
		if staleStatus != "partial" || completedAt == nil {
			t.Fatalf("stale run status=%q completedAt=%v, want partial with a completedAt set", staleStatus, completedAt)
		}
	})
}

func TestDispatchRun_IdempotentRetryAfterOfflineFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-retry-offline")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-retry"
		seedActiveAgent(t, pool, agentID, "Windows")

		runID1, skip1, err1 := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err1 != nil || runID1 != "" || skip1 != "offline" {
			t.Fatalf("first dispatch (no agent connected): runID=%q skip=%q err=%v, want offline", runID1, skip1, err1)
		}
		var firstStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs ORDER BY started_at DESC LIMIT 1`).Scan(&firstStatus)
		if firstStatus != "failed" {
			t.Fatalf("first run status = %q, want failed", firstStatus)
		}

		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("retry after connecting: runID=%q skip=%q err=%v, want a real new runID (not blocked by the failed prior run)", runID2, skip2, err2)
		}
	})
}

func TestDispatchRun_PostureDispatch_SuccessAndOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-posture-outcomes")
		h := New(pool, ws.NewHub(), engine, "")

		offlineAgent := "dr-agent-posture-offline"
		seedActiveAgent(t, pool, offlineAgent, "Windows")
		runID, skip, err := h.dispatchRun(context.Background(), sc, offlineAgent, dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || skip != "offline" {
			t.Fatalf("offline: runID=%q skip=%q err=%v", runID, skip, err)
		}

		onlineAgent := "dr-agent-posture-online"
		seedActiveAgent(t, pool, onlineAgent, "Windows")
		fake := startFakeAgent(t, h.hub, onlineAgent)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, onlineAgent, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("online: runID=%q skip=%q err=%v", runID2, skip2, err2)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, runID2).Scan(&status)
		if status != "running" {
			t.Fatalf("online dispatch left status=%q, want running", status)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != "command_simulate" {
			t.Fatalf("message type = %q, want command_simulate", env.Type)
		}
		var data struct {
			ScenarioID string `json:"scenarioId"`
			RunID      string `json:"runId"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode data: %v", err)
		}
		if data.ScenarioID != sc.ID || data.RunID != runID2 {
			t.Fatalf("data = %+v, want scenarioId=%s runId=%s", data, sc.ID, runID2)
		}
	})
}

func TestDispatchRun_LiveDispatch_SuccessAndOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "dr-live-outcomes",
			scenario.Step{Name: "s1", TechniqueID: "T1059", Framework: "custom", Command: "echo s1"},
			scenario.Step{Name: "s2", TechniqueID: "T1059", Framework: "custom", Command: "echo s2"},
		)
		h := New(pool, ws.NewHub(), engine, "")

		offlineAgent := "dr-agent-live-offline"
		seedActiveAgent(t, pool, offlineAgent, "Windows")
		runID, skip, err := h.dispatchRun(context.Background(), sc, offlineAgent, dispatchOpts{Mode: "telemetry"})
		if err != nil || runID != "" || skip != "offline" {
			t.Fatalf("offline: runID=%q skip=%q err=%v", runID, skip, err)
		}

		onlineAgent := "dr-agent-live-online"
		seedActiveAgent(t, pool, onlineAgent, "Windows")
		fake := startFakeAgent(t, h.hub, onlineAgent)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, onlineAgent, dispatchOpts{Mode: "telemetry"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("online: runID=%q skip=%q err=%v", runID2, skip2, err2)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != "command_scenario" {
			t.Fatalf("message type = %q, want command_scenario", env.Type)
		}
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode ScenarioCommand: %v", err)
		}
		if cmd.RunID != runID2 || cmd.ScenarioID != sc.ID || cmd.Mode != "telemetry" {
			t.Fatalf("cmd = %+v, want runId=%s scenarioId=%s mode=telemetry", cmd, runID2, sc.ID)
		}
		if len(cmd.Steps) != 2 || cmd.Steps[0].Name != "s1" || cmd.Steps[1].Name != "s2" {
			t.Fatalf("cmd.Steps = %+v, want 2 steps [s1, s2] in order", cmd.Steps)
		}
	})
}

func TestDispatchRun_DisconnectImmediatelyBeforeDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-disconnect")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-disconnect"
		seedActiveAgent(t, pool, agentID, "Windows")

		fake := startFakeAgent(t, h.hub, agentID)
		fake.Disconnect(t) // blocks until the hub has actually removed it

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || skip != "offline" {
			t.Fatalf("post-disconnect dispatch: runID=%q skip=%q err=%v, want offline", runID, skip, err)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs ORDER BY started_at DESC LIMIT 1`).Scan(&status)
		if status != "failed" {
			t.Fatalf("run status = %q, want failed (must not stay running against a dead connection)", status)
		}
	})
}

func TestDispatchRun_LabOnlyStepFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mixed := []scenario.Step{
			{Name: "normal-1", TechniqueID: "T1059", Framework: "custom", Command: "echo n1"},
			{Name: "lab-1", TechniqueID: "T1059", Framework: "custom", Command: "echo l1", Fidelity: "lab-only"},
			{Name: "normal-2", TechniqueID: "T1059", Framework: "custom", Command: "echo n2"},
			{Name: "lab-2", TechniqueID: "T1059", Framework: "custom", Command: "echo l2", Fidelity: "lab-only"},
		}
		sc, engine := minimalLiveScenario(t, "dr-mixed-fidelity", mixed...)
		h := New(pool, ws.NewHub(), engine, "")

		telemetryAgent := "dr-agent-mixed-telemetry"
		seedActiveAgent(t, pool, telemetryAgent, "Windows")
		fakeT := startFakeAgent(t, h.hub, telemetryAgent)
		defer fakeT.Disconnect(t)
		_, skip, err := h.dispatchRun(context.Background(), sc, telemetryAgent, dispatchOpts{Mode: "telemetry"})
		if err != nil || skip != "" {
			t.Fatalf("telemetry dispatch: skip=%q err=%v", skip, err)
		}
		envT := fakeT.WaitForMessage(t, 2*time.Second)
		var cmdT scenario.ScenarioCommand
		_ = json.Unmarshal(envT.Data, &cmdT)
		if len(cmdT.Steps) != 2 || cmdT.Steps[0].Name != "normal-1" || cmdT.Steps[1].Name != "normal-2" {
			t.Fatalf("telemetry steps = %+v, want [normal-1, normal-2] in original order", cmdT.Steps)
		}

		labAgent := "dr-agent-mixed-lab"
		seedActiveAgent(t, pool, labAgent, "Windows")
		fakeL := startFakeAgent(t, h.hub, labAgent)
		defer fakeL.Disconnect(t)
		_, skipL, errL := h.dispatchRun(context.Background(), sc, labAgent, dispatchOpts{Mode: "lab"})
		if errL != nil || skipL != "" {
			t.Fatalf("lab dispatch: skip=%q err=%v", skipL, errL)
		}
		envL := fakeL.WaitForMessage(t, 2*time.Second)
		var cmdL scenario.ScenarioCommand
		_ = json.Unmarshal(envL.Data, &cmdL)
		if len(cmdL.Steps) != 4 {
			t.Fatalf("lab steps = %+v, want all 4 in original order", cmdL.Steps)
		}
		wantOrder := []string{"normal-1", "lab-1", "normal-2", "lab-2"}
		for i, name := range wantOrder {
			if cmdL.Steps[i].Name != name {
				t.Fatalf("lab step[%d] = %q, want %q (order not preserved)", i, cmdL.Steps[i].Name, name)
			}
		}
	})
}

func TestDispatchRun_AllLabOnlyStepsInTelemetryMode_BuildFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		allLab := []scenario.Step{
			{Name: "lab-only-1", TechniqueID: "T1059", Framework: "custom", Command: "echo l1", Fidelity: "lab-only"},
		}
		sc, engine := minimalLiveScenario(t, "dr-all-lab", allLab...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-all-lab"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry"})
		if err == nil {
			t.Fatal("expected a genuine build error, got nil")
		}
		if runID != "" || skip != "" {
			t.Fatalf("runID=%q skip=%q, want both empty when err is set", runID, skip)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs ORDER BY started_at DESC LIMIT 1`).Scan(&status)
		if status != "failed" {
			t.Fatalf("run status = %q, want failed", status)
		}
	})
}

func TestDispatchRun_VariantExpansionInvariants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "base-1", TechniqueID: "T1059", Framework: "custom", Command: "echo b1", Executor: "powershell"},
			{Name: "base-2", TechniqueID: "T1059", Framework: "custom", Command: "echo b2", Executor: "powershell"},
		}
		sc, engine := minimalLiveScenario(t, "dr-variant", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-variant"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry", VariantDepth: scenario.VariantDepthQuick})
		if err != nil || skip != "" {
			t.Fatalf("variant dispatch: skip=%q err=%v", skip, err)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		_ = json.Unmarshal(env.Data, &cmd)
		if len(cmd.Steps) <= len(steps) {
			t.Fatalf("expanded step count = %d, want more than the base %d", len(cmd.Steps), len(steps))
		}

		var metaRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT step_meta FROM scenario_runs WHERE id=$1`, runID).Scan(&metaRaw); err != nil {
			t.Fatalf("read step_meta: %v", err)
		}
		var meta map[string]scenario.StepMeta
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			t.Fatalf("decode step_meta: %v", err)
		}
		if len(meta) != len(cmd.Steps) {
			t.Fatalf("step_meta has %d entries, want %d (one per delivered step)", len(meta), len(cmd.Steps))
		}
		for taskID, m := range meta {
			if m.BaseTaskID == "" {
				continue // a base step itself
			}
			if _, ok := meta[m.BaseTaskID]; !ok {
				t.Fatalf("variant step %s has BaseTaskID %q which is not a key in step_meta (orphaned variant)", taskID, m.BaseTaskID)
			}
		}
	})
}

func TestDispatchRun_NoVariantExpansion_IdentityTransform(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "only-step", TechniqueID: "T1059", Framework: "custom", Command: "echo x"},
		}
		sc, engine := minimalLiveScenario(t, "dr-no-variant", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-no-variant"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		_, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry"})
		if err != nil || skip != "" {
			t.Fatalf("dispatch: skip=%q err=%v", skip, err)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		_ = json.Unmarshal(env.Data, &cmd)
		if len(cmd.Steps) != 1 {
			t.Fatalf("step count = %d, want 1 (no variant expansion requested)", len(cmd.Steps))
		}
	})
}

func TestDispatchRun_DBInsertFailure_ClosedPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-closedpool")
		closedPool, err := pgxpool.New(context.Background(), sharedDB.Pool.Config().ConnString())
		if err != nil {
			t.Fatalf("new pool: %v", err)
		}
		closedPool.Close()
		h := New(closedPool, ws.NewHub(), engine, "")

		runID, skip, err2 := h.dispatchRun(context.Background(), sc, "dr-agent-closedpool", dispatchOpts{Mode: "posture"})
		if err2 == nil {
			t.Fatal("expected a genuine error against a closed pool, got nil")
		}
		if runID != "" || skip != "" {
			t.Fatalf("runID=%q skip=%q, want both empty when err is set", runID, skip)
		}
	})
}
