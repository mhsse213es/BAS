package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// fakeDeviceSource answers containment queries with a fixed vendor status.
type fakeDeviceSource struct {
	status string
	reads  int
}

func (f *fakeDeviceSource) ResolveDevice(context.Context, string) (string, error) {
	return "device-ws-rw", nil
}

func (f *fakeDeviceSource) DeviceContainmentStatus(context.Context, string) (string, error) {
	f.reads++
	return f.status, nil
}

// seedContainmentStep dispatches one T1486 step in a ransomware scenario and
// submits its result.
func seedContainmentStep(t *testing.T, h *Handler, pool *pgxpool.Pool, runID, agentID string) {
	t.Helper()
	stepName := "Ransomware Payload Simulation (lab)"
	taskID := scenario.TaskID("T1486", stepName)
	seedRunRow(t, pool, runID, "akira-kill-chain", agentID, "running")
	if _, err := pool.Exec(context.Background(), `UPDATE agents SET hostname='WS-RW', ip_address='10.0.0.20' WHERE agent_id=$1`, agentID); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]scenario.StepMeta{taskID: {TechniqueID: "T1486", Name: stepName, Framework: "custom"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE scenario_runs SET step_meta=$2 WHERE id=$1`, runID, raw); err != nil {
		t.Fatal(err)
	}
	submitResultOK(t, h, scenario.RawRunResult{
		RunID: runID, ScenarioID: "akira-kill-chain", AgentID: agentID,
		Results: []scenario.ExecResult{{
			TaskID: taskID, ExitCode: 0, Stdout: "EXEC payload simulation completed",
			ExecutedAt: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC),
		}},
	})
}

func containmentRow(t *testing.T, pool *pgxpool.Pool, runID string) string {
	t.Helper()
	var verdict string
	if err := pool.QueryRow(context.Background(),
		`SELECT verdict FROM rw_capability_results WHERE run_id=$1 AND capability='containment'`, runID).Scan(&verdict); err != nil {
		t.Fatalf("read containment row for %s: %v", runID, err)
	}
	return verdict
}

func TestRWContainment_NoDeviceSourceConfiguredStaysNotTested(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "rwcontain-none"
		seedContainmentStep(t, h, pool, runID, "agent-rwcontain-none")
		if v := containmentRow(t, pool, runID); v != "SKIPPED" {
			t.Fatalf("verdict = %q, want SKIPPED when no device source is configured", v)
		}
	})
}

func TestRWContainment_ContainedVendorStatusPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		src := &fakeDeviceSource{status: "contained"}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithContainmentDevices(src)
		runID := "rwcontain-contained"
		seedContainmentStep(t, h, pool, runID, "agent-rwcontain-contained")
		if src.reads != 1 {
			t.Fatalf("vendor status read %d times, want 1", src.reads)
		}
		if v := containmentRow(t, pool, runID); v != "PASS" {
			t.Fatalf("verdict = %q, want PASS for a contained device", v)
		}
	})
}

