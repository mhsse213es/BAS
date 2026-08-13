package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// submitResultOK submits raw with valid (bypass) auth and asserts 200.
func submitResultOK(t *testing.T, h *Handler, raw scenario.RawRunResult) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.SubmitScenarioResult(rec, validSubmitResultReq("", rawResultBody(t, raw)))
	if rec.Code != http.StatusOK {
		t.Fatalf("submit result: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// readRunResults decodes the run's persisted results column.
func readRunResults(t *testing.T, pool *pgxpool.Pool, runID string) []models.SimulationResult {
	t.Helper()
	var resultsRaw []byte
	if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, runID).Scan(&resultsRaw); err != nil {
		t.Fatalf("read results: %v", err)
	}
	var results []models.SimulationResult
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	return results
}

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

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "replace-run", ScenarioID: "sc-missing", AgentID: "agent-replace",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: first"}},
		})
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "replace-run", ScenarioID: "sc-missing", AgentID: "agent-replace",
			Results: []scenario.ExecResult{
				{TaskID: "t1", ExitCode: 0, Stdout: "FAIL: second-a"},
				{TaskID: "t2", ExitCode: 0, Stdout: "PASS: second-b"},
			},
		})

		results := readRunResults(t, pool, "replace-run")
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

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "heal-run", ScenarioID: "sc-heal", AgentID: "agent-heal",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: late but complete"}},
		})

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

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "partial-flag-run", ScenarioID: "sc-partial-flag", AgentID: "agent-partial-flag", Partial: true,
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: incomplete run"}},
		})

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

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "interp-run", ScenarioID: sc.ID, AgentID: "agent-interp",
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "PASS: ok"}},
		})

		results := readRunResults(t, pool, "interp-run")
		if len(results) != 1 || results[0].Technique.ID != "T1059" || results[0].Result != models.ResultPass {
			t.Fatalf("results = %+v, want one T1059 pass result derived via scenario.Interpret", results)
		}
	})
}

func TestSubmitScenarioResult_MergesPolicySkippedResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-submit-merge")
		h := New(pool, ws.NewHub(), engine, "")
		runID := "run-merge-test"
		agentID := "agent-merge-test"
		seedRunRow(t, pool, runID, sc.ID, agentID, "running")

		policySkipped := []models.SimulationResult{
			{ID: "policy-skip-1", Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege,
				Technique: models.AttackTechnique{ID: "T1548"}},
		}
		skippedJSON, _ := json.Marshal(policySkipped)
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET policy_skipped_results = $1 WHERE id = $2`, skippedJSON, runID,
		); err != nil {
			t.Fatalf("seed policy_skipped_results: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: "real-1", Stdout: "the operation completed successfully", ExitCode: 0}},
		})

		results := readRunResults(t, pool, runID)
		if len(results) != 2 {
			t.Fatalf("results = %d entries, want 2 (1 real + 1 policy-skipped): %+v", len(results), results)
		}
		var sawPolicySkip bool
		for _, r := range results {
			if r.SkipReason == models.SkipReasonPolicyPrivilege {
				sawPolicySkip = true
			}
		}
		if !sawPolicySkip {
			t.Fatalf("results = %+v, missing the policy-skipped entry", results)
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

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "checks-run", ScenarioID: "sc-checks", AgentID: "agent-checks",
			Results: []scenario.ExecResult{{TaskID: "should-be-ignored", ExitCode: 0, Stdout: "PASS: ignored"}},
			Checks: []scenario.SimCheckResult{{
				ID: "chk-1", TechniqueID: "T1218", TechniqueName: "Signed Binary Proxy",
				Tactic: "defense-evasion", Result: "pass", Severity: "High",
			}},
		})

		results := readRunResults(t, pool, "checks-run")
		if len(results) != 1 || results[0].ID != "chk-1" || results[0].Technique.ID != "T1218" {
			t.Fatalf("results = %+v, want exactly the Checks entry (Results must be ignored when Checks is present)", results)
		}
	})
}

// The Checks path derives a severity when the agent omits one: first from the
// technique's tactic, then falling back to "Medium". This is the handler's own
// derivation (not a called subsystem), so it's in scope.
func TestSubmitScenarioResult_ChecksSeverityFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "sev-fallback-run", "sc-sev-fallback", "agent-sev-fallback", "running")

		// chk-default: no severity, no tactic → must default to "Medium".
		// chk-tactic:  no severity, but a tactic → must derive a non-empty
		//              severity from the tactic (not the "Medium" default).
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "sev-fallback-run", ScenarioID: "sc-sev-fallback", AgentID: "agent-sev-fallback",
			Checks: []scenario.SimCheckResult{
				{ID: "chk-default", TechniqueID: "T1059", TechniqueName: "x", Result: "pass"},
				{ID: "chk-tactic", TechniqueID: "T1003", TechniqueName: "y", Tactic: "credential-access", Result: "pass"},
			},
		})

		results := readRunResults(t, pool, "sev-fallback-run")
		byID := map[string]models.SimulationResult{}
		for _, r := range results {
			byID[r.ID] = r
		}
		if got := byID["chk-default"].Severity; got != "Medium" {
			t.Fatalf("chk-default severity = %q, want Medium (no severity, no tactic)", got)
		}
		got := byID["chk-tactic"].Severity
		if got == "" || got == "Medium" {
			t.Fatalf("chk-tactic severity = %q, want a non-empty tactic-derived value distinct from the Medium default", got)
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

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "unknown-task-run", ScenarioID: sc.ID, AgentID: "agent-unknown-task",
			Results: []scenario.ExecResult{{TaskID: "not-in-scenario-or-step-meta", ExitCode: 0, Stdout: "PASS: ok"}},
		})

		results := readRunResults(t, pool, "unknown-task-run")
		if len(results) != 1 || results[0].Framework != "custom" {
			t.Fatalf("results = %+v, want one result with Framework=custom fallback", results)
		}
	})
}

func TestSubmitScenarioResult_ScoreComputedWhenResultsNonEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "score-run", "sc-score", "agent-score", "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "score-run", ScenarioID: "sc-score", AgentID: "agent-score",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "score-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		var score models.Score
		if err := json.Unmarshal(scoreRaw, &score); err != nil {
			t.Fatalf("decode score: %v", err)
		}
		if score.Trend != "Baseline" {
			t.Fatalf("trend = %q, want Baseline (no prior run)", score.Trend)
		}
		if score.TotalTechniques != 1 {
			t.Fatalf("totalTechniques = %d, want 1", score.TotalTechniques)
		}
	})
}

func TestSubmitScenarioResult_ScoreSkippedWhenResultsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "score-empty-run", "sc-score-empty", "agent-score-empty", "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "score-empty-run", ScenarioID: "sc-score-empty", AgentID: "agent-score-empty",
			Partial: true, Results: []scenario.ExecResult{},
		})

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "score-empty-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		if len(scoreRaw) != 0 {
			t.Fatalf("score = %s, want untouched/NULL (no results to score)", scoreRaw)
		}
	})
}

func TestSubmitScenarioResult_PrevScorePickedFromSameScenarioAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		priorScore := models.Score{Trend: "Baseline", TacticBreakdown: map[string]models.TacticScore{}, CriticalFailures: []models.CriticalFailure{}}
		priorScoreJSON, _ := json.Marshal(priorScore)
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-prev','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at, score)
			 VALUES ('prev-run','sc-prev','agent-prev','x','completed',NOW() - interval '1 hour',NOW() - interval '1 hour',$1)`,
			priorScoreJSON); err != nil {
			t.Fatalf("seed prior run: %v", err)
		}
		seedRunRow(t, pool, "current-run", "sc-prev", "agent-prev", "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "current-run", ScenarioID: "sc-prev", AgentID: "agent-prev",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "current-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		var score models.Score
		_ = json.Unmarshal(scoreRaw, &score)
		if score.Trend == "Baseline" {
			t.Fatalf("trend = Baseline, want a prior score to have been picked up (non-Baseline)")
		}
	})
}

func TestSubmitScenarioResult_PrevScoreExcludesOtherAgentsAndScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		priorScore := models.Score{Trend: "Baseline", TacticBreakdown: map[string]models.TacticScore{}, CriticalFailures: []models.CriticalFailure{}}
		priorScoreJSON, _ := json.Marshal(priorScore)
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-other','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		// Same scenario, different agent — must NOT be picked up as prevScore.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at, score)
			 VALUES ('prev-other-agent','sc-excl','agent-other','x','completed',NOW() - interval '1 hour',NOW() - interval '1 hour',$1)`,
			priorScoreJSON); err != nil {
			t.Fatalf("seed prior run (other agent): %v", err)
		}
		// Same agent, different scenario — must NOT be picked up either.
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-excl','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at, score)
			 VALUES ('prev-other-scenario','sc-other','agent-excl','x','completed',NOW() - interval '1 hour',NOW() - interval '1 hour',$1)`,
			priorScoreJSON); err != nil {
			t.Fatalf("seed prior run (other scenario): %v", err)
		}
		seedRunRow(t, pool, "current-excl-run", "sc-excl", "agent-excl", "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "current-excl-run", ScenarioID: "sc-excl", AgentID: "agent-excl",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "current-excl-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		var score models.Score
		_ = json.Unmarshal(scoreRaw, &score)
		if score.Trend != "Baseline" {
			t.Fatalf("trend = %q, want Baseline (neither a different agent's nor a different scenario's prior run may be picked up)", score.Trend)
		}
	})
}

func TestSubmitScenarioResult_HygieneScoreOrchestration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		cases := []struct {
			name        string
			verdicts    []string
			wantHygiene float64
			wantLeaked  int
		}{
			{"no cleanup verdicts at all", []string{"", ""}, 100.0, 0},
			{"all reverted", []string{"reverted", "reverted"}, 100.0, 0},
			{"one leaked of two cleanable", []string{"reverted", "leaked"}, 50.0, 1},
			{"one partial of two cleanable", []string{"reverted", "partial"}, 50.0, 1},
		}
		for i, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := New(pool, ws.NewHub(), engine, "")
				runID := fmt.Sprintf("hygiene-run-%d", i)
				seedRunRow(t, pool, runID, "sc-hygiene", "agent-hygiene", "running")

				results := make([]scenario.ExecResult, len(tc.verdicts))
				for j, v := range tc.verdicts {
					results[j] = scenario.ExecResult{TaskID: fmt.Sprintf("t%d", j), ExitCode: 0, Stdout: "PASS: ok", CleanupVerdict: v}
				}
				submitResultOK(t, h, scenario.RawRunResult{RunID: runID, ScenarioID: "sc-hygiene", AgentID: "agent-hygiene", Results: results})

				var hygiene float64
				var leaked int
				if err := pool.QueryRow(context.Background(), `SELECT hygiene_score, leaked_steps FROM scenario_runs WHERE id=$1`, runID).Scan(&hygiene, &leaked); err != nil {
					t.Fatalf("read hygiene: %v", err)
				}
				if hygiene != tc.wantHygiene {
					t.Fatalf("hygiene_score = %v, want %v", hygiene, tc.wantHygiene)
				}
				if leaked != tc.wantLeaked {
					t.Fatalf("leaked_steps = %d, want %d", leaked, tc.wantLeaked)
				}
			})
		}
	})
}

func TestSubmitScenarioResult_FindingsFireOnCompletedRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-findings", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-findings"
		seedRunRow(t, pool, "findings-run", sc.ID, agentID, "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "findings-run", ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "FAIL: allowed"}},
		})

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM findings WHERE agent_id=$1 AND technique_id='T1059'`, agentID,
		).Scan(&count); err != nil {
			t.Fatalf("count findings: %v", err)
		}
		if count == 0 {
			t.Fatal("expected a findings row for a completed run with a FAIL result, got none")
		}
	})
}

// TestSubmitScenarioResult_FindingsSkippedOnPartialRun proves that the ONE step
// that was actually in-flight when a scenario was cancelled -- tagged by the
// agent's "step interrupted by scenario cancellation" marker -- never produces
// a finding, even though the run it belongs to is Partial and findings now
// otherwise fire for partial runs (see
// TestSubmitScenarioResult_PartialRun_CompletedStepsStillProduceFindings).
// A kill artifact must not masquerade as a security finding.
func TestSubmitScenarioResult_FindingsSkippedOnPartialRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-findings-partial", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-findings-partial"
		seedRunRow(t, pool, "findings-partial-run", sc.ID, agentID, "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "findings-partial-run", ScenarioID: sc.ID, AgentID: agentID, Partial: true,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: -1, Stderr: "step interrupted by scenario cancellation"}},
		})

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM findings WHERE agent_id=$1 AND technique_id='T1059'`, agentID,
		).Scan(&count); err != nil {
			t.Fatalf("count findings: %v", err)
		}
		if count != 0 {
			t.Fatalf("expected no findings row for the cancelled in-flight step, got %d", count)
		}
	})
}

// TestSubmitScenarioResult_PartialRun_CompletedStepsStillProduceFindings proves
// that a Partial run's genuinely-completed steps (real, determinate Pass/Fail
// verdicts) still populate Findings/Remediation -- only the one step that was
// actually in-flight when the scenario was cancelled (tagged with the agent's
// "step interrupted by scenario cancellation" marker, exit -1) must be excluded,
// since that entry is an artifact of the kill, not a real security outcome.
func TestSubmitScenarioResult_PartialRun_CompletedStepsStillProduceFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"},
			{Name: "step-1", TechniqueID: "T1072", Framework: "custom", Command: "echo 1"},
		}
		sc, engine := minimalLiveScenario(t, "sc-findings-partial-completed", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-findings-partial-completed"
		seedRunRow(t, pool, "findings-partial-completed-run", sc.ID, agentID, "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "findings-partial-completed-run", ScenarioID: sc.ID, AgentID: agentID, Partial: true,
			Results: []scenario.ExecResult{
				// step-0 genuinely ran to completion before cancellation.
				{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "FAIL: allowed"},
				// step-1 was in-flight when the scenario was cancelled -- the
				// agent's force-kill path tags it this way instead of leaving
				// an ambiguous bare exit -1.
				{TaskID: scenario.TaskID("T1072", "step-1"), ExitCode: -1, Stderr: "step interrupted by scenario cancellation"},
			},
		})

		var t1059Count, t1072Count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM findings WHERE agent_id=$1 AND technique_id='T1059'`, agentID,
		).Scan(&t1059Count); err != nil {
			t.Fatalf("count T1059 findings: %v", err)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM findings WHERE agent_id=$1 AND technique_id='T1072'`, agentID,
		).Scan(&t1072Count); err != nil {
			t.Fatalf("count T1072 findings: %v", err)
		}
		if t1059Count == 0 {
			t.Fatal("expected a findings row for T1059 (a real, completed FAIL within the partial run), got none")
		}
		if t1072Count != 0 {
			t.Fatalf("expected NO findings row for T1072 (the cancelled in-flight step), got %d -- a kill artifact must not masquerade as a security finding", t1072Count)
		}
	})
}

func TestSubmitScenarioResult_VariantFanOutsFireForVariantRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "base-1", TechniqueID: "T1059", Framework: "custom", Command: "echo b1", Executor: "powershell"},
		}
		sc, engine := minimalLiveScenario(t, "sc-variant-fanout", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-variant-fanout"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry", VariantDepth: scenario.VariantDepthQuick})
		if err != nil || skip != "" {
			t.Fatalf("variant dispatch: skip=%q err=%v", skip, err)
		}
		fake.WaitForMessage(t, 2*time.Second)

		var metaRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT step_meta FROM scenario_runs WHERE id=$1`, runID).Scan(&metaRaw); err != nil {
			t.Fatalf("read step_meta: %v", err)
		}
		var meta map[string]scenario.StepMeta
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			t.Fatalf("decode step_meta: %v", err)
		}
		var variantTaskID string
		for taskID, m := range meta {
			if m.BaseTaskID != "" {
				variantTaskID = taskID
				break
			}
		}
		if variantTaskID == "" {
			t.Fatal("expected at least one variant step in step_meta")
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: variantTaskID, ExitCode: 0, Stdout: "PASS: blocked"}},
		})

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_variant_results WHERE run_id=$1`, runID,
		).Scan(&count); err != nil {
			t.Fatalf("count variant results: %v", err)
		}
		if count == 0 {
			t.Fatal("expected a scenario_variant_results row for a variant-bearing run, got none")
		}
	})
}

func TestSubmitScenarioResult_VariantFanOutsNoOpForNonVariantRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-no-variant-fanout", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-no-variant-fanout"
		// step_meta left at its '{}' default — no dispatch, no variant meta.
		seedRunRow(t, pool, "no-variant-run", sc.ID, agentID, "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "no-variant-run", ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "PASS: ok"}},
		})

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_variant_results WHERE run_id=$1`, "no-variant-run",
		).Scan(&count); err != nil {
			t.Fatalf("count variant results: %v", err)
		}
		if count != 0 {
			t.Fatalf("expected no scenario_variant_results rows for a non-variant run, got %d", count)
		}
	})
}

func TestSubmitScenarioResult_BroadcastsToConnectedBrowser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "broadcast-run", "sc-broadcast", "agent-broadcast", "running")
		browser := startFakeBrowser(t, h.hub)
		defer browser.Disconnect(t)

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "broadcast-run", ScenarioID: "sc-broadcast", AgentID: "agent-broadcast",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})

		env := browser.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgScenarioResult {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgScenarioResult)
		}
		if env.AgentID != "agent-broadcast" {
			t.Fatalf("message agentId = %q, want agent-broadcast", env.AgentID)
		}
		var data struct {
			RunID      string `json:"runId"`
			ScenarioID string `json:"scenarioId"`
			AgentID    string `json:"agentId"`
			Status     string `json:"status"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode broadcast data: %v", err)
		}
		if data.RunID != "broadcast-run" || data.ScenarioID != "sc-broadcast" || data.AgentID != "agent-broadcast" || data.Status != "completed" {
			t.Fatalf("broadcast data = %+v, want matching runId/scenarioId/agentId/status=completed", data)
		}
	})
}

func TestSubmitScenarioResult_NoBrowsersConnected_StillReturns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "no-browser-run", "sc-no-browser", "agent-no-browser", "running")

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "no-browser-run", ScenarioID: "sc-no-browser", AgentID: "agent-no-browser",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})
	})
}
