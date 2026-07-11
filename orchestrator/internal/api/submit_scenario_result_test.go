package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubmitScenarioResult_MissingRunID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body := []byte(`{"scenarioId":"s1","agentId":"a1"}`)
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestSubmitScenarioResult_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body := []byte(`{not valid json`)
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// An unknown runId matches zero rows in the UPDATE, which pgx does not
// surface as an error, so the handler proceeds through the rest of the
// function and returns 200. This test locks down that no-op-accept behavior
// explicitly, so a future change to add existence-checking is a deliberate,
// visible diff against this test rather than an unnoticed behavior change.
func TestSubmitScenarioResult_UnknownRunID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body := rawResultBody(t, scenario.RawRunResult{RunID: "does-not-exist", ScenarioID: "whatever", AgentID: "whoever"})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("unknown runId: status = %d, want 200 (no-op accept), body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestSubmitScenarioResult_REPLACENotAppend(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "replace-run", "sc-missing", "agent-replace", "running")

		first := rawResultBody(t, scenario.RawRunResult{
			RunID: "replace-run", ScenarioID: "sc-missing", AgentID: "agent-replace",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: first"}},
		})
		rec1 := httptest.NewRecorder()
		h.SubmitScenarioResult(rec1, validSubmitResultReq("", first))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first submit: status = %d", rec1.Code)
		}

		second := rawResultBody(t, scenario.RawRunResult{
			RunID: "replace-run", ScenarioID: "sc-missing", AgentID: "agent-replace",
			Results: []scenario.ExecResult{
				{TaskID: "t1", ExitCode: 0, Stdout: "FAIL: second-a"},
				{TaskID: "t2", ExitCode: 0, Stdout: "PASS: second-b"},
			},
		})
		rec2 := httptest.NewRecorder()
		h.SubmitScenarioResult(rec2, validSubmitResultReq("", second))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second submit: status = %d", rec2.Code)
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "replace-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("results has %d entries, want 2 (REPLACE, not append)", len(results))
		}
		foundSecondA := false
		for _, r := range results {
			if r.Details == "second-a" {
				foundSecondA = true
			}
			if r.Details == "first" {
				t.Fatalf("results still contains the first submission's content: %+v", results)
			}
		}
		if !foundSecondA {
			t.Fatalf("results = %+v, want the second submission's content present", results)
		}
	})
}

func TestSubmitScenarioResult_LateSubmissionHealsPartialToCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "heal-run", "sc-heal", "agent-heal", "partial")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "heal-run", ScenarioID: "sc-heal", AgentID: "agent-heal",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: late but complete"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, "heal-run").Scan(&status); err != nil {
			t.Fatalf("read status: %v", err)
		}
		if status != "completed" {
			t.Fatalf("status = %q, want completed (late valid submission heals a partial run)", status)
		}
	})
}

func TestSubmitScenarioResult_PartialFlag_SetsPartialStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "partial-flag-run", "sc-partial-flag", "agent-partial-flag", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "partial-flag-run", ScenarioID: "sc-partial-flag", AgentID: "agent-partial-flag", Partial: true,
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: incomplete run"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(), `SELECT status, completed_at FROM scenario_runs WHERE id=$1`, "partial-flag-run").Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "partial" {
			t.Fatalf("status = %q, want partial", status)
		}
		if completedAt == nil {
			t.Fatal("completed_at = nil, want set even for a partial submission")
		}
	})
}

func TestSubmitScenarioResult_ResultsInterpretedViaSteps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-interp", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		seedRunRow(t, pool, "interp-run", sc.ID, "agent-interp", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "interp-run", ScenarioID: sc.ID, AgentID: "agent-interp",
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "interp-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 1 || results[0].Technique.ID != "T1059" || results[0].Result != models.ResultPass {
			t.Fatalf("results = %+v, want one T1059 pass result derived via scenario.Interpret", results)
		}
	})
}

func TestSubmitScenarioResult_ChecksTakePriorityOverResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "checks-run", "sc-checks", "agent-checks", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "checks-run", ScenarioID: "sc-checks", AgentID: "agent-checks",
			Results: []scenario.ExecResult{{TaskID: "should-be-ignored", ExitCode: 0, Stdout: "PASS: ignored"}},
			Checks: []scenario.SimCheckResult{{
				ID: "chk-1", TechniqueID: "T1218", TechniqueName: "Signed Binary Proxy",
				Tactic: "defense-evasion", Result: "pass", Severity: "High",
			}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "checks-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 1 || results[0].ID != "chk-1" || results[0].Technique.ID != "T1218" {
			t.Fatalf("results = %+v, want exactly the Checks entry (Results must be ignored when Checks is present)", results)
		}
	})
}

func TestSubmitScenarioResult_UnknownTaskIDFallsBackToCustom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-unknown-task", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		seedRunRow(t, pool, "unknown-task-run", sc.ID, "agent-unknown-task", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "unknown-task-run", ScenarioID: sc.ID, AgentID: "agent-unknown-task",
			Results: []scenario.ExecResult{{TaskID: "not-in-scenario-or-step-meta", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "unknown-task-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 1 || results[0].Framework != "custom" {
			t.Fatalf("results = %+v, want one result with Framework=custom fallback", results)
		}
	})
}
