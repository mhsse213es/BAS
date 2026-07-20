# Coverage Math (Scenario vs Eligible Coverage) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every run persists how many base-technique steps the scenario defined (Total) and how many survived lab-only/MaxPrivilege filtering (Eligible), and reports show both "Scenario Coverage" (executed/total) and "Eligible Coverage" (executed/eligible) so a policy-constrained run reads as complete against what it could run, not incomplete against everything the scenario defines.

**Architecture:** Two new `scenario_runs` columns are captured once at dispatch time in `dispatchRun`, mirroring the exact precedent `policy_skipped_results` already set. At report time, a new `buildCoverageSummary` function combines those two stored counts with an `Executed` count derived from `results` — reusing the existing `Technique.ID`-based grouping `groupResultsByTechnique` already uses — and is wired into `deriveExecutive`, the single shared function that already runs for every report type (single-agent, scoped, campaign).

**Tech Stack:** Go, Postgres (`pgx/v5`), the existing `internal/api`/`internal/reporting`/`internal/db`/`internal/models` packages.

## Global Constraints

- **All three numbers (Total, Eligible, Executed) are base-technique counts.** Variant expansion is deliberately excluded — the existing "Variant Coverage Analysis" report section already owns that, and mixing them would make these numbers read confusingly (e.g. "260/260" instead of "26/26" on a 10×-variant-expanded run).
- **Total** = `len(steps)` right after `scenario.BuildSteps` returns (`handlers.go:1076`) — reflects any operator-selected technique/step subset for that run, but before the lab-only fidelity drop and before the MaxPrivilege filter.
- **Eligible** = `len(steps)` after *both* those filters run, before variant expansion.
- **Executed** = distinct base techniques (via `Technique.ID`, same key `groupResultsByTechnique` uses) with at least one settled, non-policy-skip result. A technique whose only result is a policy skip does **not** count as executed — it was never dispatched to the agent at all.
- **No retroactive backfill.** `steps_total_base`/`steps_eligible_base` default to `0` for rows that predate this change. A `0` denominator means "coverage data not available for this run" — reported as `0%`, not treated as an error.
- **No change to `ComputeScore`/`models.Score`.** Coverage is a descriptive completeness metric, not a security score input.
- **Campaign aggregation falls out for free.** `BuildFromCampaign` already loops per child `scenario_runs` row and pools every child's `results` into one `allResults` slice before calling `deriveExecutive` — the whole Execution Summary section is already a campaign-wide aggregate there. Summing the two new columns in that same loop makes the coverage ratios campaign-wide aggregates automatically, consistent with everything else in that section.
- Run all `go` commands from `orchestrator/`. Docker Desktop must be running for container-backed tests.

---

### Task 1: Dispatch-time capture

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (2 new columns)
- Modify: `orchestrator/internal/api/handlers.go` (`dispatchRun`)
- Modify: `orchestrator/internal/api/run_scenario_integration_test.go` (existing file — extend 2 existing tests)

**Interfaces:**
- Produces: `scenario_runs.steps_total_base int NOT NULL DEFAULT 0`, `scenario_runs.steps_eligible_base int NOT NULL DEFAULT 0` — consumed by Task 2 (reporting reads).

- [ ] **Step 1: Extend the failing tests**

In `orchestrator/internal/api/run_scenario_integration_test.go`, `TestRunScenarioIntegration_MaxPrivilegeFiltersStep`'s current tail (after the `skipped[0].Technique.ID` check):

```go
		if skipped[0].Technique.ID != "T1548" {
			t.Errorf("skipped[0].Technique.ID = %q, want T1548", skipped[0].Technique.ID)
		}
	})
}
```

becomes:

```go
		if skipped[0].Technique.ID != "T1548" {
			t.Errorf("skipped[0].Technique.ID = %q, want T1548", skipped[0].Technique.ID)
		}

		var stepsTotalBase, stepsEligibleBase int
		if err := pool.QueryRow(context.Background(),
			`SELECT steps_total_base, steps_eligible_base FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&stepsTotalBase, &stepsEligibleBase); err != nil {
			t.Fatalf("read coverage columns: %v", err)
		}
		if stepsTotalBase != 2 {
			t.Errorf("steps_total_base = %d, want 2 (both steps, before filtering)", stepsTotalBase)
		}
		if stepsEligibleBase != 1 {
			t.Errorf("steps_eligible_base = %d, want 1 (user-step only, after policy filter)", stepsEligibleBase)
		}
	})
}
```

`TestRunScenarioIntegration_MaxPrivilegeAllFilteredCompletesImmediately`'s current tail (after the `results` check):

```go
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsJSON, &results)
		if len(results) != 1 || results[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("results = %+v, want exactly 1 policy-privilege skip", results)
		}
	})
}
```

becomes:

```go
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsJSON, &results)
		if len(results) != 1 || results[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("results = %+v, want exactly 1 policy-privilege skip", results)
		}

		var stepsTotalBase, stepsEligibleBase int
		if err := pool.QueryRow(context.Background(),
			`SELECT steps_total_base, steps_eligible_base FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&stepsTotalBase, &stepsEligibleBase); err != nil {
			t.Fatalf("read coverage columns: %v", err)
		}
		if stepsTotalBase != 1 {
			t.Errorf("steps_total_base = %d, want 1", stepsTotalBase)
		}
		if stepsEligibleBase != 0 {
			t.Errorf("steps_eligible_base = %d, want 0 (every step was policy-filtered)", stepsEligibleBase)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_MaxPrivilege' -v`
Expected: FAIL — `column "steps_total_base" does not exist` (or similar Postgres error), since the columns don't exist yet.

- [ ] **Step 3: Add the schema columns**

In `orchestrator/internal/db/postgres.go`, the current line:

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```

becomes:

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
		// steps_total_base/steps_eligible_base capture the run's base-technique
		// step counts at dispatch time — Total (before any runtime filtering)
		// and Eligible (after the lab-only and MaxPrivilege filters, before
		// variant expansion). Written once, mirroring policy_skipped_results;
		// no retroactive backfill for runs that predate this column.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_total_base int NOT NULL DEFAULT 0`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS steps_eligible_base int NOT NULL DEFAULT 0`,
```

- [ ] **Step 4: Capture `stepsTotalBase` right after `BuildSteps`**

In `orchestrator/internal/api/handlers.go`, the current block:

```go
	steps, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("build steps: %w", err)
	}
```

becomes:

```go
	steps, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("build steps: %w", err)
	}
	// stepsTotalBase captures the scenario's full base-technique step count for
	// this run's configuration (reflecting any operator-selected subset) before
	// any runtime filtering — the "Total" side of Scenario Coverage.
	stepsTotalBase := len(steps)
```

- [ ] **Step 5: Persist both counts in the all-policy-skipped early-return path**

The current block:

```go
			skippedJSON, _ := json.Marshal(policySkipped)
			_, err := h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'completed', results = $1::jsonb, completed_at = NOW() WHERE id = $2`,
				skippedJSON, runID,
			)
			if err != nil {
				return "", "", fmt.Errorf("complete all-policy-skipped run: %w", err)
			}
			return runID, "", nil
```

becomes:

```go
			skippedJSON, _ := json.Marshal(policySkipped)
			_, err := h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'completed', results = $1::jsonb, completed_at = NOW(),
				        steps_total_base = $2, steps_eligible_base = 0 WHERE id = $3`,
				skippedJSON, stepsTotalBase, runID,
			)
			if err != nil {
				return "", "", fmt.Errorf("complete all-policy-skipped run: %w", err)
			}
			return runID, "", nil
```

- [ ] **Step 6: Persist both counts on the normal (non-early-return) path**

The current block:

```go
			return runID, "", nil
		}
	}

	// ── Variant expansion layer ───────────────────────────────────────────────
	// Each base step is followed by its variant steps (encoding × privilege ×
	// exec-context combos). The agent sees a flat step list — it has no concept
	// of variants. StepMeta carries BaseTaskID + VariantSpec so the result
	// processor can write scenario_variant_results without re-querying here.
```

becomes:

```go
			return runID, "", nil
		}
	}

	// stepsEligibleBase is captured here, after both the lab-only and
	// MaxPrivilege filters have run (but before variant expansion) — the
	// "Eligible" side of Eligible Coverage. When o.MaxPrivilege=="", this
	// reflects only the lab-only filter's outcome, matching Total.
	stepsEligibleBase := len(steps)
	if _, err := h.db.Exec(context.Background(),
		`UPDATE scenario_runs SET steps_total_base = $1, steps_eligible_base = $2 WHERE id = $3`,
		stepsTotalBase, stepsEligibleBase, runID,
	); err != nil {
		return "", "", fmt.Errorf("persist coverage counts: %w", err)
	}

	// ── Variant expansion layer ───────────────────────────────────────────────
	// Each base step is followed by its variant steps (encoding × privilege ×
	// exec-context combos). The agent sees a flat step list — it has no concept
	// of variants. StepMeta carries BaseTaskID + VariantSpec so the result
	// processor can write scenario_variant_results without re-querying here.
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_MaxPrivilege' -v`
Expected: both PASS.

- [ ] **Step 8: Run the full dispatch/run suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration|TestClassifyAgentOS' -v`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/handlers.go orchestrator/internal/api/run_scenario_integration_test.go
git commit -m "feat(reporting): capture steps_total_base/steps_eligible_base at dispatch time"
git push
```

---

### Task 2: `CoverageSummary` aggregation

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go` (`CoverageSummary` struct, `FullReport` fields, `buildCoverageSummary`, the 3 report-building SELECT queries)
- Modify: `orchestrator/internal/reporting/insights.go` (`deriveExecutive`)
- Test: `orchestrator/internal/reporting/engine_test.go` (existing file)

**Interfaces:**
- Consumes: `scenario_runs.steps_total_base`/`steps_eligible_base` (Task 1). `groupResultsByTechnique(results []models.SimulationResult) []TechniqueGroup` (already exists, `engine.go:1927`).
- Produces: `reporting.CoverageSummary{ScenarioTotal, Eligible, Executed, ScenarioCoveragePct, EligibleCoveragePct int}`. `reporting.buildCoverageSummary(results []models.SimulationResult, totalBase, eligibleBase int) CoverageSummary`. `FullReport.StepsTotalBase`/`.StepsEligibleBase int` (raw, read from DB). `FullReport.Coverage CoverageSummary` (computed).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/reporting/engine_test.go`:

```go
func TestBuildCoverageSummary(t *testing.T) {
	cases := []struct {
		name            string
		results         []models.SimulationResult
		totalBase       int
		eligibleBase    int
		wantExecuted    int
		wantScenarioPct int
		wantEligiblePct int
	}{
		{
			name: "no filtering — every step executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass},
				{Technique: models.AttackTechnique{ID: "T1548"}, Result: models.ResultFail},
			},
			totalBase: 2, eligibleBase: 2,
			wantExecuted: 2, wantScenarioPct: 100, wantEligiblePct: 100,
		},
		{
			name: "policy skip excluded from Executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass},
				{Technique: models.AttackTechnique{ID: "T1548"}, Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege},
			},
			totalBase: 2, eligibleBase: 1,
			wantExecuted: 1, wantScenarioPct: 50, wantEligiblePct: 100,
		},
		{
			name: "non-policy skip still counts as executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultSkipped, SkipReason: models.SkipReasonMissingContent},
			},
			totalBase: 1, eligibleBase: 1,
			wantExecuted: 1, wantScenarioPct: 100, wantEligiblePct: 100,
		},
		{
			name: "dispatched but never returned — Executed < Eligible",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass},
			},
			totalBase: 2, eligibleBase: 2,
			wantExecuted: 1, wantScenarioPct: 50, wantEligiblePct: 50,
		},
		{
			name: "zero denominators — no coverage data available",
			results: nil, totalBase: 0, eligibleBase: 0,
			wantExecuted: 0, wantScenarioPct: 0, wantEligiblePct: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildCoverageSummary(c.results, c.totalBase, c.eligibleBase)
			if got.Executed != c.wantExecuted || got.ScenarioCoveragePct != c.wantScenarioPct || got.EligibleCoveragePct != c.wantEligiblePct {
				t.Errorf("buildCoverageSummary() = %+v, want Executed=%d ScenarioCoveragePct=%d EligibleCoveragePct=%d",
					got, c.wantExecuted, c.wantScenarioPct, c.wantEligiblePct)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildCoverageSummary -v`
Expected: FAIL — compile error (`undefined: buildCoverageSummary`).

- [ ] **Step 3: Add `CoverageSummary`, `FullReport` fields, and `buildCoverageSummary`**

In `orchestrator/internal/reporting/engine.go`, the current `FullReport` field block:

```go
	// SkipBreakdown counts Result=Skipped entries by SkipReason. Populated by
	// deriveExecutive so a policy-constrained run reads as "compliant," not
	// "incomplete."
	SkipBreakdown SkipBreakdown `json:"skipBreakdown"`
}
```

becomes:

```go
	// SkipBreakdown counts Result=Skipped entries by SkipReason. Populated by
	// deriveExecutive so a policy-constrained run reads as "compliant," not
	// "incomplete."
	SkipBreakdown SkipBreakdown `json:"skipBreakdown"`
	// StepsTotalBase/StepsEligibleBase are read directly from
	// scenario_runs.steps_total_base/steps_eligible_base (captured once at
	// dispatch time) — the raw inputs to Coverage, computed by deriveExecutive.
	StepsTotalBase    int `json:"stepsTotalBase"`
	StepsEligibleBase int `json:"stepsEligibleBase"`
	// Coverage reports Scenario Coverage (executed/total) and Eligible Coverage
	// (executed/eligible) so a policy-constrained run reads as complete against
	// what it could run, not incomplete against everything the scenario defines.
	Coverage CoverageSummary `json:"coverage"`
}
```

The current end of `buildSkipBreakdown`:

```go
// buildSkipBreakdown counts skipped results by SkipReason. An empty or
// unrecognized reason falls into Platform — an unclassified skip is still an
// environment gap, not a policy decision.
func buildSkipBreakdown(results []models.SimulationResult) SkipBreakdown {
	var sb SkipBreakdown
	for _, r := range results {
		if r.Result != models.ResultSkipped {
			continue
		}
		switch r.SkipReason {
		case models.SkipReasonPolicyPrivilege:
			sb.Policy++
		case models.SkipReasonMissingContent:
			sb.Content++
		default:
			sb.Platform++
		}
	}
	return sb
}

// killChainAction renders a concise adversary-action label for a kill-chain node.
```

becomes:

```go
// buildSkipBreakdown counts skipped results by SkipReason. An empty or
// unrecognized reason falls into Platform — an unclassified skip is still an
// environment gap, not a policy decision.
func buildSkipBreakdown(results []models.SimulationResult) SkipBreakdown {
	var sb SkipBreakdown
	for _, r := range results {
		if r.Result != models.ResultSkipped {
			continue
		}
		switch r.SkipReason {
		case models.SkipReasonPolicyPrivilege:
			sb.Policy++
		case models.SkipReasonMissingContent:
			sb.Content++
		default:
			sb.Platform++
		}
	}
	return sb
}

// CoverageSummary reports how much of a scenario's base-technique steps were
// attemptable (Eligible) and defined (ScenarioTotal), against how many
// actually executed. Separate from SkipBreakdown's "why" and separate from
// PASS/FAIL scoring — this is a completeness metric, not a security score.
type CoverageSummary struct {
	ScenarioTotal int `json:"scenarioTotal"`
	Eligible      int `json:"eligible"`
	Executed      int `json:"executed"`
	// ScenarioCoveragePct = Executed/ScenarioTotal*100 (0 when ScenarioTotal==0).
	ScenarioCoveragePct int `json:"scenarioCoveragePct"`
	// EligibleCoveragePct = Executed/Eligible*100 (0 when Eligible==0).
	EligibleCoveragePct int `json:"eligibleCoveragePct"`
}

// buildCoverageSummary derives Executed from results — distinct base
// techniques (by Technique.ID, the same key groupResultsByTechnique uses)
// with at least one non-policy-skip result — and combines it with the
// dispatch-time-captured totalBase/eligibleBase counts into both coverage
// ratios. A policy-skipped technique was never dispatched to the agent at
// all, so it must not count as executed. A zero denominator means coverage
// data isn't available for this run (e.g. it predates this feature) — 0%,
// not an error.
func buildCoverageSummary(results []models.SimulationResult, totalBase, eligibleBase int) CoverageSummary {
	executable := make([]models.SimulationResult, 0, len(results))
	for _, r := range results {
		if r.SkipReason == models.SkipReasonPolicyPrivilege {
			continue
		}
		executable = append(executable, r)
	}
	executed := len(groupResultsByTechnique(executable))
	cs := CoverageSummary{ScenarioTotal: totalBase, Eligible: eligibleBase, Executed: executed}
	if totalBase > 0 {
		cs.ScenarioCoveragePct = executed * 100 / totalBase
	}
	if eligibleBase > 0 {
		cs.EligibleCoveragePct = executed * 100 / eligibleBase
	}
	return cs
}

// killChainAction renders a concise adversary-action label for a kill-chain node.
```

- [ ] **Step 4: Wire `Coverage` into `deriveExecutive`**

In `orchestrator/internal/reporting/insights.go`, the current line:

```go
	report.SkipBreakdown = buildSkipBreakdown(results)
```

becomes:

```go
	report.SkipBreakdown = buildSkipBreakdown(results)
	report.Coverage = buildCoverageSummary(results, report.StepsTotalBase, report.StepsEligibleBase)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestBuildCoverageSummary -v`
Expected: PASS.

- [ ] **Step 6: Read `steps_total_base`/`steps_eligible_base` in `Build` (single-agent report)**

In `orchestrator/internal/reporting/engine.go`, the current query in `Build`:

```go
	latestRow := e.db.QueryRow(ctx,
		`SELECT name, results, score, started_at, reverted
		 FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial')
		 ORDER BY started_at DESC LIMIT 1`, agentID)
	var resultsRaw, scoreRaw2, revertedRaw []byte
	if err := latestRow.Scan(&latestScenarioName, &resultsRaw, &scoreRaw2, &latestRunAt, &revertedRaw); err == nil {
```

becomes:

```go
	latestRow := e.db.QueryRow(ctx,
		`SELECT name, results, score, started_at, reverted, steps_total_base, steps_eligible_base
		 FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial')
		 ORDER BY started_at DESC LIMIT 1`, agentID)
	var resultsRaw, scoreRaw2, revertedRaw []byte
	if err := latestRow.Scan(&latestScenarioName, &resultsRaw, &scoreRaw2, &latestRunAt, &revertedRaw,
		&report.StepsTotalBase, &report.StepsEligibleBase); err == nil {
```

- [ ] **Step 7: Read the two columns in `BuildFromRun`**

The current query:

```go
	err := e.db.QueryRow(ctx,
		`SELECT agent_id, scenario_id, name, status, results, score, started_at, completed_at, reverted,
		        detection_rate, undetected_rate, mttd_ms, detection_summary,
		        perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after,
		        alerts_total, alerts_high_fidelity, noise_score
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &scenarioID, &scenarioName, &status, &resultsRaw, &scoreRaw, &startedAt, &completedAt, &revertedRaw,
		&detRate, &undetRate, &mttd, &detSummaryRaw,
		&cpuBefore, &cpuAfter, &ramBefore, &ramAfter, &diskBefore, &diskAfter,
		&report.AlertsTotal, &report.AlertsHighFidelity, &report.NoiseScore)
```

becomes:

```go
	err := e.db.QueryRow(ctx,
		`SELECT agent_id, scenario_id, name, status, results, score, started_at, completed_at, reverted,
		        detection_rate, undetected_rate, mttd_ms, detection_summary,
		        perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after,
		        alerts_total, alerts_high_fidelity, noise_score, steps_total_base, steps_eligible_base
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &scenarioID, &scenarioName, &status, &resultsRaw, &scoreRaw, &startedAt, &completedAt, &revertedRaw,
		&detRate, &undetRate, &mttd, &detSummaryRaw,
		&cpuBefore, &cpuAfter, &ramBefore, &ramAfter, &diskBefore, &diskAfter,
		&report.AlertsTotal, &report.AlertsHighFidelity, &report.NoiseScore,
		&report.StepsTotalBase, &report.StepsEligibleBase)
```

- [ ] **Step 8: Sum the two columns across child runs in `BuildFromCampaign`**

The current query and loop:

```go
	rows, err := e.db.Query(ctx,
		`SELECT sr.id, sr.agent_id, COALESCE(a.hostname,''), sr.status, sr.results, sr.score,
		        sr.started_at, sr.completed_at
		   FROM scenario_runs sr LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.campaign_id = $1 ORDER BY sr.started_at`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allResults []models.SimulationResult
	agentSet := map[string]bool{}
	var runCount int
	for rows.Next() {
		var rid, agentID, hostname, status string
		var resultsRaw, scoreRaw []byte
		var sAt time.Time
		var cAt *time.Time
		if rows.Scan(&rid, &agentID, &hostname, &status, &resultsRaw, &scoreRaw, &sAt, &cAt) != nil {
			continue
		}
```

becomes:

```go
	rows, err := e.db.Query(ctx,
		`SELECT sr.id, sr.agent_id, COALESCE(a.hostname,''), sr.status, sr.results, sr.score,
		        sr.started_at, sr.completed_at, sr.steps_total_base, sr.steps_eligible_base
		   FROM scenario_runs sr LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.campaign_id = $1 ORDER BY sr.started_at`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allResults []models.SimulationResult
	agentSet := map[string]bool{}
	var runCount int
	for rows.Next() {
		var rid, agentID, hostname, status string
		var resultsRaw, scoreRaw []byte
		var sAt time.Time
		var cAt *time.Time
		var stepsTotalBase, stepsEligibleBase int
		if rows.Scan(&rid, &agentID, &hostname, &status, &resultsRaw, &scoreRaw, &sAt, &cAt,
			&stepsTotalBase, &stepsEligibleBase) != nil {
			continue
		}
		report.StepsTotalBase += stepsTotalBase
		report.StepsEligibleBase += stepsEligibleBase
```

- [ ] **Step 9: Run the full `internal/reporting` suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/reporting/... -v 2>&1 | tail -60`
Expected: `ok`. This exercises `Build`/`BuildFromRun`/`BuildFromCampaign`'s existing tests, which now also read the two new columns and populate `Coverage` via `deriveExecutive` — confirming nothing else broke.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/reporting/engine.go orchestrator/internal/reporting/insights.go orchestrator/internal/reporting/engine_test.go
git commit -m "feat(reporting): CoverageSummary — Scenario Coverage and Eligible Coverage ratios"
git push
```

---

### Task 3: "Scenario Coverage" / "Eligible Coverage" HTML rows

**Files:**
- Modify: `orchestrator/internal/reporting/html.go` (extend the Execution Summary table)
- Test: `orchestrator/internal/reporting/html_test.go` (existing file)

**Interfaces:**
- Consumes: `FullReport.Coverage` (Task 2).
- Produces: nothing new — final rendering step.

- [ ] **Step 1: Extend the failing test**

In `orchestrator/internal/reporting/html_test.go`, `TestGenerateHTMLRendersAllSections`'s `rep` literal currently has:

```go
		Reliability:   Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
		SkipBreakdown: SkipBreakdown{Policy: 4, Content: 1, Platform: 2},
```

Add a `Coverage` field right after it:

```go
		Reliability:   Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
		SkipBreakdown: SkipBreakdown{Policy: 4, Content: 1, Platform: 2},
		Coverage: CoverageSummary{
			ScenarioTotal: 40, Eligible: 26, Executed: 26,
			ScenarioCoveragePct: 65, EligibleCoveragePct: 100,
		},
```

In the same test's `want` substring list, the current entries include:

```go
		"Skipped (Platform)",      // execution-summary row label
```

Add these entries right after it:

```go
		"Skipped (Platform)",      // execution-summary row label
		"Scenario Coverage",       // new coverage row label
		"Eligible Coverage",       // new coverage row label
		"26/40",                   // scenario coverage ratio
		"26/26",                   // eligible coverage ratio
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestGenerateHTMLRendersAllSections -v`
Expected: FAIL — the rendered HTML doesn't contain "Scenario Coverage"/"Eligible Coverage" or the ratios yet.

- [ ] **Step 3: Add the two rows to the Execution Summary table**

In the `reportHTML` template constant, the current block:

```html
  <tr><td>Skipped (Platform)</td><td><strong>{{.skipBreakdown.platform}}</strong></td>
      <td></td><td></td></tr>
</table>

<h3>Simulation Reliability</h3>
```

becomes:

```html
  <tr><td>Skipped (Platform)</td><td><strong>{{.skipBreakdown.platform}}</strong></td>
      <td></td><td></td></tr>
  <tr><td>Scenario Coverage</td><td colspan="3"><strong>{{.coverage.executed}}/{{.coverage.scenarioTotal}}</strong> ({{.coverage.scenarioCoveragePct}}%)</td></tr>
  <tr><td>Eligible Coverage</td><td colspan="3"><strong>{{.coverage.executed}}/{{.coverage.eligible}}</strong> ({{.coverage.eligibleCoveragePct}}%)</td></tr>
</table>

<h3>Simulation Reliability</h3>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestGenerateHTMLRendersAllSections -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/reporting/html.go orchestrator/internal/reporting/html_test.go
git commit -m "feat(reporting): render Scenario Coverage / Eligible Coverage rows"
git push
```

---

### Task 4: Full verification

**Files:** none created — build/vet/gofmt only.

- [ ] **Step 1: Full build/vet/gofmt**

```bash
cd orchestrator
go build ./...
go vet ./...
gofmt -w internal/db/postgres.go internal/api/handlers.go internal/api/run_scenario_integration_test.go internal/reporting/engine.go internal/reporting/insights.go internal/reporting/engine_test.go internal/reporting/html.go internal/reporting/html_test.go
gofmt -l internal/db/postgres.go internal/api/handlers.go internal/api/run_scenario_integration_test.go internal/reporting/engine.go internal/reporting/insights.go internal/reporting/engine_test.go internal/reporting/html.go internal/reporting/html_test.go
```
Expected: build/vet clean; `gofmt -w` normalizes any rough struct-tag alignment; the follow-up `gofmt -l` prints nothing (or only CRLF-line-ending noise on files this Windows checkout hasn't normalized — cosmetic-only, see `project_docker_windows` memory).

- [ ] **Step 2: Commit any gofmt reformatting**

If Step 1's `gofmt -w` changed anything (`git status --short orchestrator/internal`), commit it:

```bash
git add -u orchestrator/internal
git commit -m "chore(reporting): gofmt struct-tag alignment"
git push
```

If nothing changed, skip this step.

- [ ] **Step 3: Full `internal/api` and `internal/reporting` suites**

```bash
cd orchestrator
go test ./internal/reporting/... -v 2>&1 | tail -60
go test ./internal/api/... 2>&1 | tail -20
```
Expected: `internal/reporting` fully green (fast, no container dependency). `internal/api` ends with `ok` — this package takes several minutes; if anything unrelated fails, re-run that specific test in isolation before treating it as a real regression.

- [ ] **Step 4: Report results to the user**

Summarize: test results, and confirm all three items from the original MaxPrivilege follow-up roadmap are now complete — campaign-wide `ExecutionPolicy` propagation, the SkipReason reporting breakdown, and this coverage-math feature.
