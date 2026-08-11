# Live Runs: Collapse Full Variant Sweep Runs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Live Runs shows exactly one row for a Full Variant Sweep (live or in history) instead of one row per technique it dispatched, with a drill-down list on click.

**Architecture:** Tag each sweep-dispatched `scenario_runs` row with `sweep_id` at creation (permanent, not a heuristic). Add that one field to the existing `GET /api/scenarios/runs` response — nothing else about that shared endpoint changes, since 7 other consumers depend on seeing every individual technique run unchanged. A new, unbounded `GET /api/vex/sweeps/{id}/runs` endpoint serves both the collapsed row's aggregate badge and the drill-down list. All grouping/collapsing happens client-side, only in Live Runs' `loadRuns()`.

**Tech Stack:** Go (chi router, pgx/Postgres) backend; vanilla JS in `orchestrator/wwwroot/index.html` frontend, no framework, no JS test runner — verification is `node --check` plus manual QA, per established project convention.

## Global Constraints

- `GET /api/scenarios/runs`'s existing per-row shape/behavior does not change for any of its other 7 consumers — only one new `sweepId` field is added, everything else (query, `LIMIT 100`, every other field) stays exactly as-is.
- Sweep-dispatched `scenario_runs` rows are tagged with `sweep_id` at INSERT time, never backfilled or heuristically inferred.
- `sweep_id` must persist as true SQL `NULL` for non-sweep dispatches (not empty string) — the column has a `REFERENCES vex_sweeps(id)` foreign key, so an empty string would violate it for any non-sweep dispatch.
- The new `GET /api/vex/sweeps/{id}/runs` endpoint is unbounded (no `LIMIT`) since a sweep can dispatch more techniques than `GET /api/scenarios/runs`'s 100-row cap.
- Reuse the existing `CanViewVariantRun` permission for the new endpoint — no new permission.
- Clicking a technique inside the drill-down reuses the existing, unmodified `openRunPanel`/`viewRunResults` — no new single-run detail view.
- Syntax verification for every frontend task:
  ```bash
  awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
  ```
  Run from the repo root (`C:\Users\Administrator\Downloads\Audspect_Cloud`).
- Go verification for every backend task: `cd orchestrator && go build ./...` and the specified `go test` command. Container-backed tests are guarded with `if testing.Short() { t.Skip(...) }` per this codebase's convention — run them without `-short`.

---

## Task 1: Schema — `sweep_id` column + model field

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (migration list, insert before its closing `}` at line 1393)
- Modify: `orchestrator/internal/models/schema.go` (`ScenarioRun` struct, line 132-162)

**Interfaces:**
- Produces: `scenario_runs.sweep_id` column (nullable `text REFERENCES vex_sweeps(id)`), indexed. `models.ScenarioRun.SweepID *string` (json tag `sweepId,omitempty`).

- [ ] **Step 1: Add the migration**

Find the tail of the migration statement list (currently ending at line 1392, right before the closing `}` at line 1393):
```go
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS owner_id    text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS assigned_at timestamptz`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_owner_id ON job_targets (owner_id) WHERE owner_id != ''`,
	}
```
Insert two new statements immediately before the closing `}`:
```go
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS owner_id    text NOT NULL DEFAULT ''`,
		`ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS assigned_at timestamptz`,
		`CREATE INDEX IF NOT EXISTS idx_job_targets_owner_id ON job_targets (owner_id) WHERE owner_id != ''`,

		// Live Runs: collapse Full Variant Sweep technique runs into one row.
		// See docs/superpowers/specs/2026-08-11-sweep-run-grouping-design.md.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS sweep_id text REFERENCES vex_sweeps(id)`,
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_sweep_id ON scenario_runs (sweep_id)`,
	}
```
(`vex_sweeps` is created earlier in this same list, so the `REFERENCES` constraint resolves without reordering.)

- [ ] **Step 2: Add the model field**

Find `models.ScenarioRun` (`orchestrator/internal/models/schema.go:132-142`):
```go
type ScenarioRun struct {
	ID          string             `json:"id"`
	ScenarioID  string             `json:"scenarioId"`
	Name        string             `json:"name"`
	AgentID     string             `json:"agentId"`
	Status      string             `json:"status"` // running | completed | partial | failed
	Results     []SimulationResult `json:"results"`
```
Add `SweepID` right after `AgentID`:
```go
type ScenarioRun struct {
	ID          string             `json:"id"`
	ScenarioID  string             `json:"scenarioId"`
	Name        string             `json:"name"`
	AgentID     string             `json:"agentId"`
	// SweepID is non-nil only for a scenario_run dispatched by a Full Variant
	// Sweep (internal/vexsweep) -- see docs/superpowers/specs/2026-08-11-sweep-run-grouping-design.md.
	SweepID     *string            `json:"sweepId,omitempty"`
	Status      string             `json:"status"` // running | completed | partial | failed
	Results     []SimulationResult `json:"results"`
```

- [ ] **Step 3: Build**

```bash
cd orchestrator && go build ./...
```
Expected: no errors (the new field is unused so far, which is fine for a build check).

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/models/schema.go
git commit -m "feat(sweep-grouping): add scenario_runs.sweep_id column and model field"
```

---

## Task 2: Thread `sweepID` through the sweep dispatch path

**Files:**
- Modify: `orchestrator/internal/vexsweep/dispatcher.go` (`DispatchFn` type line 12, `dispatchNext` line 64-90)
- Modify: `orchestrator/internal/vexsweep/dispatcher_test.go` (5 existing tests' `SetDispatch` closures)
- Modify: `orchestrator/internal/api/variant_handlers.go` (`dispatchVariantForSweep` line 638-651, `dispatchVariantRun` line 548-632)
- Modify: `orchestrator/internal/api/variant_handlers_test.go` (1 existing test's call site, line 27)
- Test: `orchestrator/internal/api/variant_handlers_test.go` (2 new tests)

**Interfaces:**
- Consumes: `models.ScenarioRun.SweepID` (Task 1).
- Produces: `vexsweep.DispatchFn` now takes `sweepID` as its first parameter (after `ctx`). `dispatchVariantForSweep(ctx, sweepID, agentID, techniqueID, mode string, includeAdvanced bool)`. `dispatchVariantRun(ctx, sweepID, agentID, techniqueID, baseType, baseID, executionMode string, templates []variant.Template)`.

- [ ] **Step 1: Update `DispatchFn`'s signature and its one call site**

`orchestrator/internal/vexsweep/dispatcher.go:12`, change:
```go
type DispatchFn func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)
```
to:
```go
type DispatchFn func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)
```
`dispatcher.go:76` (inside `dispatchNext`, which already receives `sw Sweep` as a parameter), change:
```go
	scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.AgentID, sw.Techniques[nextIdx], sw.Mode, sw.IncludeAdvanced)
```
to:
```go
	scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Techniques[nextIdx], sw.Mode, sw.IncludeAdvanced)
```

- [ ] **Step 2: Fix the 5 existing dispatcher tests' `SetDispatch` closures**

`orchestrator/internal/vexsweep/dispatcher_test.go` has 5 tests, each calling `d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {...})`. Every one of these closures' signatures must gain a `sweepID string` parameter (as the 2nd parameter, after `ctx`) to match the new `DispatchFn` type, or the package will fail to compile.

In `TestDispatcher_Tick_DispatchesFirstTechniqueForNewSweep` (line 30):
```go
		d.SetDispatch(func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			return "sr-1", "vr-1", 33, nil
		})
```
becomes:
```go
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			return "sr-1", "vr-1", 33, nil
		})
```

Apply the identical `sweepID,` insertion (after `ctx,`, before `agentID,`) to the closure signatures in:
- `TestDispatcher_Tick_AdvancesWhenCurrentTechniqueFinishes` (line 76)
- `TestDispatcher_Tick_CompletesSweepAfterLastTechnique` (line 115)
- `TestDispatcher_Tick_MarksFailedOnDispatchError` (line 148)
- `TestDispatcher_Tick_IgnoresStoppedAndFailedSweeps` (line 184)

None of these 5 closure bodies reference `sweepID` — only the parameter list changes, matching the new `DispatchFn` type; the bodies (what they append/return) stay exactly as they are today.

- [ ] **Step 3: Run the vexsweep package tests to confirm they compile and pass**

```bash
cd orchestrator && go test ./internal/vexsweep/... -v
```
Expected: all 5 `TestDispatcher_Tick_*` tests PASS (plus any `store_test.go` tests, unaffected by this change).

- [ ] **Step 4: Update `dispatchVariantForSweep` and `dispatchVariantRun` signatures**

`orchestrator/internal/api/variant_handlers.go:638`, change:
```go
func (h *Handler) dispatchVariantForSweep(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error) {
	templates, baseID, err := h.resolveTemplates(ctx, techniqueID, "art", "", "", "", includeAdvanced)
	if err != nil {
		return "", "", 0, err
	}
	if len(templates) == 0 {
		return "", "", 0, fmt.Errorf("no variants generated for %s", techniqueID)
	}
	scenarioRunID, variantRunID, err = h.dispatchVariantRun(ctx, agentID, techniqueID, "art", baseID, mode, templates)
	if err != nil {
		return "", "", 0, err
	}
	return scenarioRunID, variantRunID, len(templates), nil
}
```
to:
```go
func (h *Handler) dispatchVariantForSweep(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error) {
	templates, baseID, err := h.resolveTemplates(ctx, techniqueID, "art", "", "", "", includeAdvanced)
	if err != nil {
		return "", "", 0, err
	}
	if len(templates) == 0 {
		return "", "", 0, fmt.Errorf("no variants generated for %s", techniqueID)
	}
	scenarioRunID, variantRunID, err = h.dispatchVariantRun(ctx, sweepID, agentID, techniqueID, "art", baseID, mode, templates)
	if err != nil {
		return "", "", 0, err
	}
	return scenarioRunID, variantRunID, len(templates), nil
}
```

`orchestrator/internal/api/variant_handlers.go:548-567`, change:
```go
func (h *Handler) dispatchVariantRun(
	ctx context.Context,
	agentID, techniqueID, baseType, baseID, executionMode string,
	templates []variant.Template,
) (scenarioRunID, variantRunID string, err error) {

	syntheticScenarioID := "__variant__" + strings.ToLower(techniqueID)
	runName := "Variant: " + techniqueID + " (" + baseID + ")"
	genVersion := variant.GeneratorVersion

	err = h.db.QueryRow(ctx,
		`INSERT INTO scenario_runs
			(scenario_id, agent_id, name, status, results, steps_total, initiated_by)
		 VALUES ($1, $2, $3, 'running', '[]', $4, 'variant-executor')
		 RETURNING id`,
		syntheticScenarioID, agentID, runName, len(templates),
	).Scan(&scenarioRunID)
	if err != nil {
		return "", "", fmt.Errorf("create scenario_run: %w", err)
	}
```
to:
```go
func (h *Handler) dispatchVariantRun(
	ctx context.Context,
	sweepID, agentID, techniqueID, baseType, baseID, executionMode string,
	templates []variant.Template,
) (scenarioRunID, variantRunID string, err error) {

	syntheticScenarioID := "__variant__" + strings.ToLower(techniqueID)
	runName := "Variant: " + techniqueID + " (" + baseID + ")"
	genVersion := variant.GeneratorVersion

	// sweep_id has a REFERENCES vex_sweeps(id) constraint -- an empty string
	// would violate it for every non-sweep dispatch, so "" must become a true
	// SQL NULL, not the literal empty string, via a nil *string.
	var sweepIDArg *string
	if sweepID != "" {
		sweepIDArg = &sweepID
	}

	err = h.db.QueryRow(ctx,
		`INSERT INTO scenario_runs
			(scenario_id, agent_id, name, status, results, steps_total, initiated_by, sweep_id)
		 VALUES ($1, $2, $3, 'running', '[]', $4, 'variant-executor', $5)
		 RETURNING id`,
		syntheticScenarioID, agentID, runName, len(templates), sweepIDArg,
	).Scan(&scenarioRunID)
	if err != nil {
		return "", "", fmt.Errorf("create scenario_run: %w", err)
	}
```
Leave everything after this point in `dispatchVariantRun` (the `variant_runs` INSERT, the `steps` loop, `SendToAgent`) exactly as it is — none of it references `sweepID`.

- [ ] **Step 5: Fix the one other `dispatchVariantRun` caller**

`orchestrator/internal/api/variant_handlers.go:109` (the ad-hoc single-technique variant run HTTP handler — never sweep-dispatched):
```go
	runID, vrID, err := h.dispatchVariantRun(ctx, req.AgentID, req.TechniqueID,
		coalesce(req.BaseType, "art"), baseID, mode, templates)
```
becomes:
```go
	runID, vrID, err := h.dispatchVariantRun(ctx, "", req.AgentID, req.TechniqueID,
		coalesce(req.BaseType, "art"), baseID, mode, templates)
```

- [ ] **Step 6: Fix the one existing `dispatchVariantForSweep` test call site**

`orchestrator/internal/api/variant_handlers_test.go:27`:
```go
		_, _, _, err := h.dispatchVariantForSweep(context.Background(), "agent-1", "T1059.001", "sequential", false)
```
becomes:
```go
		_, _, _, err := h.dispatchVariantForSweep(context.Background(), "", "agent-1", "T1059.001", "sequential", false)
```

- [ ] **Step 7: Write the new failing tests for `sweep_id` persistence**

Add to `orchestrator/internal/api/variant_handlers_test.go` (needs `"github.com/audspect/bas/internal/variant"` and `"github.com/audspect/bas/internal/vexsweep"` added to the existing import block if not already present — `vexsweep` is already imported per `TestHandler_WithVexSweep_StoresReference`'s existing use at line 35):
```go
func TestDispatchVariantRun_PersistsSweepID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-tag')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-sweep-tag", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		templates := []variant.Template{{
			ID: "tpl-1", TechniqueID: "T1059.001", Encoding: "none", ExecContext: "user",
			Evasion: "none", Executor: "powershell", Command: "Get-Process",
		}}
		// dispatchVariantRun's final SendToAgent step always fails here (no real
		// agent connection in this bare test hub) -- expected and irrelevant: the
		// scenario_runs row (with sweep_id) is already committed by the time that
		// happens, which is what this test verifies, so the returned error is
		// deliberately discarded.
		_, _, _ = h.dispatchVariantRun(ctx, sw.ID, "agent-sweep-tag", "T1059.001", "art", "tpl-1", "sequential", templates)

		var gotSweepID *string
		if err := pool.QueryRow(ctx,
			`SELECT sweep_id FROM scenario_runs WHERE agent_id = $1 ORDER BY started_at DESC LIMIT 1`,
			"agent-sweep-tag",
		).Scan(&gotSweepID); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if gotSweepID == nil || *gotSweepID != sw.ID {
			t.Fatalf("sweep_id = %v, want %q", gotSweepID, sw.ID)
		}
	})
}

func TestDispatchVariantRun_NoSweepID_PersistsNull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-no-sweep-tag')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		templates := []variant.Template{{
			ID: "tpl-1", TechniqueID: "T1059.001", Encoding: "none", ExecContext: "user",
			Evasion: "none", Executor: "powershell", Command: "Get-Process",
		}}
		_, _, _ = h.dispatchVariantRun(ctx, "", "agent-no-sweep-tag", "T1059.001", "art", "tpl-1", "sequential", templates)

		var gotSweepID *string
		if err := pool.QueryRow(ctx,
			`SELECT sweep_id FROM scenario_runs WHERE agent_id = $1 ORDER BY started_at DESC LIMIT 1`,
			"agent-no-sweep-tag",
		).Scan(&gotSweepID); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if gotSweepID != nil {
			t.Fatalf("sweep_id = %q, want NULL (not sweep-dispatched)", *gotSweepID)
		}
	})
}
```

- [ ] **Step 8: Run the new tests**

```bash
cd orchestrator && go test ./internal/api/... -run "TestDispatchVariantRun_" -v
```
Expected: both PASS.

- [ ] **Step 9: Run the full package tests to confirm nothing else broke**

```bash
cd orchestrator && go build ./... && go test ./internal/vexsweep/... ./internal/api/... -run "TestDispatch|TestDispatcher" -v
```
Expected: all PASS, including the updated `TestDispatchVariantForSweep_NoARTStoreReturnsError` and all 5 `TestDispatcher_Tick_*` tests.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/vexsweep/dispatcher.go orchestrator/internal/vexsweep/dispatcher_test.go \
        orchestrator/internal/api/variant_handlers.go orchestrator/internal/api/variant_handlers_test.go
git commit -m "feat(sweep-grouping): thread sweepID through dispatch, persist sweep_id as NULL-safe"
```

---

## Task 3: `GET /api/scenarios/runs` exposes `sweepId` + shared row-scan helper

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`ListScenarioRuns`, line 2239-2302)
- Test: `orchestrator/internal/api/handlers_test.go` (or the file containing existing `ListScenarioRuns` tests, if one exists — check via `grep -rn "func TestListScenarioRuns" orchestrator/internal/api/` at execution time and add to that file if found, otherwise create `orchestrator/internal/api/scenario_runs_handlers_test.go`)

**Interfaces:**
- Consumes: `models.ScenarioRun.SweepID` (Task 1), `scenario_runs.sweep_id` column (Task 1).
- Produces: package-level `runRow` type (moved out of `ListScenarioRuns`) and `scanRunRows(rows pgx.Rows) ([]runRow, error)` helper, both reused by Task 4's new endpoint. Both `ListScenarioRuns`'s and the new endpoint's queries must `SELECT` columns in this exact fixed order for `scanRunRows` to work: `id, scenario_id, agent_id, sweep_id, name, status, results, score, initiated_by, started_at, completed_at, steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary, alerts_total, alerts_high_fidelity, noise_score, reverted`.

- [ ] **Step 1: Extract `runRow` to package level and add `scanRunRows`**

Find `ListScenarioRuns` (`orchestrator/internal/api/handlers.go:2239-2302`):
```go
func (h *Handler) ListScenarioRuns(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	scenarioID := r.URL.Query().Get("scenarioId")

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted
		 FROM scenario_runs
		 WHERE ($1 = '' OR agent_id = $1)
		   AND ($2 = '' OR scenario_id = $2)
		 ORDER BY started_at DESC LIMIT 100`,
		agentID, scenarioID,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type runRow struct {
		models.ScenarioRun
		InitiatedBy *string `json:"initiatedBy"`
		// DetectedTechs is the set of technique ids whose FAIL the blue team still
		// caught (from the run's detection_summary, with the coarse event-token
		// fallback) — same classification the campaign rollup and kill-chain use.
		// Lets the dashboard split fails into "detected" vs "missed" honestly.
		DetectedTechs map[string]bool `json:"detectedTechs,omitempty"`
	}
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw, detRaw, revertedRaw []byte
		var p models.RunProgress
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt,
			&p.StepsTotal, &p.StepsDone, &p.StepsRunning, &p.StepsPassed, &p.StepsFailed, &p.StepsTimeout, &detRaw,
			&run.AlertsTotal, &run.AlertsHighFidelity, &run.NoiseScore, &revertedRaw); err != nil {
			log.Printf("[api] list runs scan: %v", err)
			continue
		}
		json.Unmarshal(resultsJSON, &run.Results)
		if len(scoreRaw) > 0 {
			json.Unmarshal(scoreRaw, &run.Score)
		}
		if len(revertedRaw) > 0 {
			json.Unmarshal(revertedRaw, &run.Reverted)
		}
		if d := reporting.DetectedTechniques(detRaw, run.Results); len(d) > 0 {
			run.DetectedTechs = d
		}
		// Attach the derived step breakdown only when there's something to show
		// (a run that has emitted events). Lets the UI surface partial progress
		// for in-flight runs and dead-agent partials that never returned results.
		if p.StepsTotal > 0 || p.StepsDone > 0 {
			run.Progress = &p
		}
		runs = append(runs, run)
	}
	if runs == nil {
		runs = []runRow{}
	}
	respond(w, runs)
}
```

Replace it with:
```go
// runRow is the shared scenario_runs row shape returned by both
// ListScenarioRuns and GetVexSweepRuns (internal/api/vexsweep_handlers.go).
type runRow struct {
	models.ScenarioRun
	InitiatedBy *string `json:"initiatedBy"`
	// DetectedTechs is the set of technique ids whose FAIL the blue team still
	// caught (from the run's detection_summary, with the coarse event-token
	// fallback) — same classification the campaign rollup and kill-chain use.
	// Lets the dashboard split fails into "detected" vs "missed" honestly.
	DetectedTechs map[string]bool `json:"detectedTechs,omitempty"`
}

// scanRunRows scans a scenario_runs query's rows, decoding the JSON blob
// columns and deriving DetectedTechs/Progress the same way for every caller.
// Every caller's SELECT must list columns in exactly this order: id,
// scenario_id, agent_id, sweep_id, name, status, results, score,
// initiated_by, started_at, completed_at, steps_total, steps_done,
// steps_running, steps_passed, steps_failed, steps_timeout,
// detection_summary, alerts_total, alerts_high_fidelity, noise_score,
// reverted.
func scanRunRows(rows pgx.Rows) ([]runRow, error) {
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw, detRaw, revertedRaw []byte
		var p models.RunProgress
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.SweepID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt,
			&p.StepsTotal, &p.StepsDone, &p.StepsRunning, &p.StepsPassed, &p.StepsFailed, &p.StepsTimeout, &detRaw,
			&run.AlertsTotal, &run.AlertsHighFidelity, &run.NoiseScore, &revertedRaw); err != nil {
			log.Printf("[api] scan run row: %v", err)
			continue
		}
		json.Unmarshal(resultsJSON, &run.Results)
		if len(scoreRaw) > 0 {
			json.Unmarshal(scoreRaw, &run.Score)
		}
		if len(revertedRaw) > 0 {
			json.Unmarshal(revertedRaw, &run.Reverted)
		}
		if d := reporting.DetectedTechniques(detRaw, run.Results); len(d) > 0 {
			run.DetectedTechs = d
		}
		// Attach the derived step breakdown only when there's something to show
		// (a run that has emitted events). Lets the UI surface partial progress
		// for in-flight runs and dead-agent partials that never returned results.
		if p.StepsTotal > 0 || p.StepsDone > 0 {
			run.Progress = &p
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (h *Handler) ListScenarioRuns(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	scenarioID := r.URL.Query().Get("scenarioId")

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted
		 FROM scenario_runs
		 WHERE ($1 = '' OR agent_id = $1)
		   AND ($2 = '' OR scenario_id = $2)
		 ORDER BY started_at DESC LIMIT 100`,
		agentID, scenarioID,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRow{}
	}
	respond(w, runs)
}
```
(`pgx` must already be imported in `handlers.go` — it uses `h.db.Query` returning `pgx.Rows` throughout the file; if the `pgx.Rows` type itself isn't already referenced by name anywhere in this file, add `"github.com/jackc/pgx/v5"` to the import block.)

- [ ] **Step 2: Write the failing regression test**

First check whether `ListScenarioRuns` already has test coverage: run `grep -rn "func TestListScenarioRuns" orchestrator/internal/api/`. If a test file is found, add the new test there; otherwise create `orchestrator/internal/api/scenario_runs_handlers_test.go` with the package/import boilerplate matching `vexsweep_handlers_test.go` (package `api`, imports `bytes`/`context`/`encoding/json`/`net/http`/`testing`, `github.com/audspect/bas/internal/auth`, `github.com/audspect/bas/internal/ws`, `github.com/jackc/pgx/v5/pgxpool`).

```go
func TestListScenarioRuns_ExposesSweepIdOnlyForTaggedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-list-sweep')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-list-sweep", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total, sweep_id)
			 VALUES ('sr-tagged', 'sc-x', 'agent-list-sweep', 'tagged run', 'completed', '[]', 1, $1)`,
			sw.ID); err != nil {
			t.Fatalf("seed tagged run: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-untagged', 'sc-x', 'agent-list-sweep', 'untagged run', 'completed', '[]', 1)`); err != nil {
			t.Fatalf("seed untagged run: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "list-runs-sweep-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/scenarios/runs?agentId=agent-list-sweep", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.ListScenarioRuns, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var got []struct {
			ID      string  `json:"id"`
			SweepID *string `json:"sweepId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		byID := map[string]*string{}
		for _, r := range got {
			byID[r.ID] = r.SweepID
		}
		if byID["sr-tagged"] == nil || *byID["sr-tagged"] != sw.ID {
			t.Errorf("sr-tagged sweepId = %v, want %q", byID["sr-tagged"], sw.ID)
		}
		if byID["sr-untagged"] != nil {
			t.Errorf("sr-untagged sweepId = %q, want nil (not sweep-dispatched)", *byID["sr-untagged"])
		}
	})
}
```

- [ ] **Step 3: Run the test to verify it fails before Step 1's fix**

If Step 1 was already applied before writing this test, temporarily verify by reverting Step 1's `SELECT`/scan changes locally is unnecessary — instead just run the test now, after Step 1, to confirm it passes (Step 1 and Step 2 are naturally coupled here since the query change is a one-line SELECT list edit, not meaningfully separable into a pre-fix failing state without extra churn). Run:
```bash
cd orchestrator && go test ./internal/api/... -run "TestListScenarioRuns_ExposesSweepIdOnlyForTaggedRows" -v
```
Expected: PASS.

- [ ] **Step 4: Run the broader handler test suite for a regression check**

```bash
cd orchestrator && go build ./... && go test ./internal/api/... -run "TestListScenarioRuns" -v
```
Expected: all PASS, including any pre-existing `ListScenarioRuns` tests found in Step 2 — confirms every other field's behavior is unchanged.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/*_test.go
git commit -m "feat(sweep-grouping): expose sweepId on GET /api/scenarios/runs, extract shared row scanner"
```

---

## Task 4: New `GET /api/vex/sweeps/{id}/runs` endpoint

**Files:**
- Modify: `orchestrator/internal/api/vexsweep_handlers.go` (new handler, near `GetVexSweep` line 111-120)
- Modify: `orchestrator/internal/api/routes.go` (new route, near line 332)
- Test: `orchestrator/internal/api/vexsweep_handlers_test.go`

**Interfaces:**
- Consumes: `scanRunRows`/`runRow` (Task 3), `sweepToJSON` (existing, `vexsweep_handlers.go:174-194`), `h.vexSweep.Get` (existing).
- Produces: `GET /api/vex/sweeps/{id}/runs` → `{"sweep": {...}, "runs": [...]}`, used by Task 5 (aggregate badge) and Task 6 (drill-down list).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/vexsweep_handlers_test.go`:
```go
func TestGetVexSweepRuns_ReturnsOnlyTaggedRunsPlusSweepSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-runs')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-sweep-runs", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{1, 1}, TotalVariants: 2,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total, sweep_id)
			 VALUES ('sr-a', 'sc-x', 'agent-sweep-runs', 'technique A', 'completed', '[]', 1, $1)`, sw.ID); err != nil {
			t.Fatalf("seed sr-a: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total, sweep_id)
			 VALUES ('sr-b', 'sc-x', 'agent-sweep-runs', 'technique B', 'completed', '[]', 1, $1)`, sw.ID); err != nil {
			t.Fatalf("seed sr-b: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-unrelated', 'sc-x', 'agent-sweep-runs', 'unrelated run', 'completed', '[]', 1)`); err != nil {
			t.Fatalf("seed sr-unrelated: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-runs-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/"+sw.ID+"/runs", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.GetVexSweepRuns, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var got struct {
			Sweep struct {
				ID string `json:"id"`
			} `json:"sweep"`
			Runs []struct {
				ID string `json:"id"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Sweep.ID != sw.ID {
			t.Errorf("sweep.id = %q, want %q", got.Sweep.ID, sw.ID)
		}
		if len(got.Runs) != 2 {
			t.Fatalf("len(runs) = %d, want 2 (sr-unrelated must be excluded)", len(got.Runs))
		}
		gotIDs := map[string]bool{got.Runs[0].ID: true, got.Runs[1].ID: true}
		if !gotIDs["sr-a"] || !gotIDs["sr-b"] {
			t.Errorf("runs = %v, want [sr-a, sr-b]", gotIDs)
		}
	})
}

func TestGetVexSweepRuns_404ForUnknownSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := vexsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-runs-404-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/does-not-exist/runs", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", "does-not-exist")
		rec := callAuthed(h.GetVexSweepRuns, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body: %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator && go test ./internal/api/... -run "TestGetVexSweepRuns" -v
```
Expected: FAIL with `h.GetVexSweepRuns undefined` (method doesn't exist yet).

- [ ] **Step 3: Implement the handler**

Add to `orchestrator/internal/api/vexsweep_handlers.go`, right after `GetVexSweep` (line 111-120):
```go
// GET /api/vex/sweeps/{id}/runs
// Returns the sweep's summary plus EVERY scenario_runs row it dispatched,
// unbounded (not subject to ListScenarioRuns' 100-row cap) -- a sweep can
// dispatch far more than 100 techniques over its lifetime, so an aggregate
// or drill-down built only from the paginated main list would be silently
// wrong for large or older sweeps. See
// docs/superpowers/specs/2026-08-11-sweep-run-grouping-design.md.
func (h *Handler) GetVexSweepRuns(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sw, err := h.vexSweep.Get(r.Context(), id)
	if err != nil {
		jsonError(w, "sweep not found", http.StatusNotFound)
		return
	}

	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted
		 FROM scenario_runs WHERE sweep_id = $1 ORDER BY started_at`,
		id,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRow{}
	}

	jsonOK(w, map[string]any{"sweep": sweepToJSON(h.db, sw), "runs": runs})
}
```
(`h.db` here is a `*pgxpool.Pool`, same as every other handler in this file — `vexsweep_handlers.go` already imports `github.com/jackc/pgx/v5/pgxpool` for `sweepToJSON`'s signature.)

- [ ] **Step 4: Register the route**

`orchestrator/internal/api/routes.go`, find (line 330-334):
```go
		r.With(auth.RequirePermission(auth.CanRunVariants)).Post("/api/vex/sweeps", h.CreateVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/active", h.GetActiveVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}", h.GetVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps", h.ListVexSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/vex/sweeps/{id}/cancel", h.CancelVexSweep)
```
Add, right after the `{id}` route:
```go
		r.With(auth.RequirePermission(auth.CanRunVariants)).Post("/api/vex/sweeps", h.CreateVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/active", h.GetActiveVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}", h.GetVexSweep)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps/{id}/runs", h.GetVexSweepRuns)
		r.With(auth.RequirePermission(auth.CanViewVariantRun)).Get("/api/vex/sweeps", h.ListVexSweeps)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/vex/sweeps/{id}/cancel", h.CancelVexSweep)
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd orchestrator && go test ./internal/api/... -run "TestGetVexSweepRuns" -v
```
Expected: both PASS.

- [ ] **Step 6: Full backend regression check**

```bash
cd orchestrator && go build ./... && go test ./internal/... -short
```
Expected: all PASS (the `-short` run skips container-backed tests, confirming nothing non-DB-related broke; the specific container-backed tests above were already verified in Steps 5 and Task 2/3's steps).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/vexsweep_handlers.go orchestrator/internal/api/vexsweep_handlers_test.go orchestrator/internal/api/routes.go
git commit -m "feat(sweep-grouping): add GET /api/vex/sweeps/{id}/runs endpoint"
```

---

## Task 5: Frontend — collapse sweep rows in `loadRuns()`

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`loadRuns()`, line 10081-10141)

**Interfaces:**
- Consumes: `sweepId` field on `GET /api/scenarios/runs` rows (Task 3), `GET /api/vex/sweeps/{id}/runs` (Task 4), existing `apicall`, `agents` global, `fmtDate`, `x` (HTML-escape helper).
- Produces: `runRowHtml(r)` (one run's `<tr>`, extracted from the existing inline map body), `renderRunRows(list)`, `renderSweepRow(payload)`. The collapsed row's button calls `openSweepDrilldown(sweepId)` — **not implemented until Task 6**; between this task's commit and Task 6's, clicking it will throw a JS error in the browser. This is a deliberate, transient sequencing choice (matches how this session's earlier multi-task frontend plans have worked) — Task 6 follows immediately after.

- [ ] **Step 1: Extract the existing per-row rendering into `runRowHtml`**

Find `loadRuns()` (`orchestrator/wwwroot/index.html:10081-10141`):
```js
function loadRuns() {
  apicall('/api/scenarios/runs').then(function(runs) {
    document.getElementById('runs-cnt').textContent = runs.length;
    var tbody = document.getElementById('runs-body');
    if (!runs.length) { tbody.innerHTML = '<tr><td colspan="9" class="empty">No runs yet. Go to Scenarios and run one.</td></tr>'; return; }
    tbody.innerHTML = runs.map(function(r) {
      var cnt = (r.results || []).length;
      var fail = (r.results || []).filter(function(c) { return c.result === 'fail'; }).length;
      var badge = cnt ? (fail + ' fail / ' + (cnt - fail) + ' pass') : '—';
      var scoreHtml = '—';
      if (r.score && typeof r.score.preventionScore !== 'undefined') {
        var prevPct = Math.round(r.score.preventionScore || 0);
        var expVal  = Math.round(r.score.exposureScore || 0);
        var cls     = r.score.classification || '';
        var prevCol = prevPct >= 80 ? 'var(--teal)' : prevPct >= 50 ? 'var(--warning)' : 'var(--danger)';
        var expCol  = expVal  <= 20 ? 'var(--success)' : expVal  <= 50 ? 'var(--warning)' : 'var(--danger)';
        var trend   = r.score.trend || '';
        var trendBadge = trend === 'Improving' ? '<span style="color:var(--success);font-size:0.65rem;margin-left:0.3rem">↑</span>' :
                         trend === 'Degrading' ? '<span style="color:var(--danger);font-size:0.65rem;margin-left:0.3rem">↓</span>' : '';
        scoreHtml = '<span style="font-weight:600;color:' + prevCol + '">' + prevPct + '%</span>' +
                    '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.2rem">prev</span>' +
                    '<span style="color:' + expCol + ';font-size:0.72rem;margin-left:0.45rem">exp:' + expVal + '</span>' +
                    trendBadge;
      } else if (r.score && typeof r.score.riskScore !== 'undefined') {
        var cls2 = r.score.classification || '';
        var col2 = cls2 === 'Protected' ? 'var(--success)' : cls2 === 'Medium Risk' ? 'var(--warning)' : 'var(--danger)';
        scoreHtml = '<span style="font-weight:600;color:' + col2 + '">' + r.score.riskScore + '</span>' +
                    '<span style="color:var(--muted);font-size:0.72rem;margin-left:0.3rem">' + x(cls2) + '</span>';
      } else if (r.progress && r.progress.stepsDone > 0) {
        var pr = r.progress;
        scoreHtml = '<span style="color:var(--success);font-weight:600">' + pr.stepsPassed + '</span>' +
                    '<span style="color:var(--muted);font-size:0.6rem">pass</span> / ' +
                    '<span style="color:var(--danger);font-weight:600">' + pr.stepsFailed + '</span>' +
                    '<span style="color:var(--muted);font-size:0.6rem">fail</span>' +
                    (pr.stepsTimeout ? ' / <span style="color:var(--warning);font-weight:600">' + pr.stepsTimeout + '</span><span style="color:var(--muted);font-size:0.6rem">to</span>' : '') +
                    '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.35rem">' + pr.stepsDone + '/' + pr.stepsTotal + ' partial</span>';
      }
      return '<tr>' +
        '<td><code>' + x(r.id ? r.id.substring(0,14) : '—') + '</code></td>' +
        '<td style="font-weight:500">' + x(r.name) + '</td>' +
        '<td><code>' + x(r.agentId) + '</code></td>' +
        '<td><span class="sbadge s-' + x(r.status) + '">' + x(r.status) + '</span></td>' +
        '<td style="color:var(--muted);font-size:0.78rem">' + x(r.initiatedBy || '—') + '</td>' +
        '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(r.startedAt) + '</td>' +
        '<td style="color:var(--muted);font-size:0.78rem">' + (r.completedAt ? fmtDate(r.completedAt) : '—') + '</td>' +
        '<td>' + (function() {
          var acts = '';
          if (r.id && (r.status === 'running' || r.progress)) acts += '<button class="btn btn-outline btn-sm" onclick="openRunPanel(\'' + x(r.id) + '\',\'' + x(r.name).replace(/'/g,'&#39;') + '\')" title="Live run timeline + progress">&#9673; Live</button> ';
          if (r.id && r.status === 'running') acts += '<button class="btn btn-outline-red btn-sm" onclick="stopRun(\'' + x(r.id) + '\')" title="Stop this run — keeps completed steps, marks the run partial">&#9632; Stop</button> ';
          if (cnt) acts += '<button class="btn btn-outline btn-sm" onclick=\'viewRunResults(' + JSON.stringify(r).replace(/'/g,"&#39;") + ')\'>' + badge + '</button>';
          return acts || '—';
        })() + '</td>' +
        '<td>' + scoreHtml + '</td></tr>';
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

Replace it with:
```js
// runRowHtml renders one individual (non-sweep-collapsed) run's <tr> --
// extracted unchanged from loadRuns() so it can also be reused for a sweep
// row's per-sweep fetch-failure fallback (see loadRuns() below).
function runRowHtml(r) {
  var cnt = (r.results || []).length;
  var fail = (r.results || []).filter(function(c) { return c.result === 'fail'; }).length;
  var badge = cnt ? (fail + ' fail / ' + (cnt - fail) + ' pass') : '—';
  var scoreHtml = '—';
  if (r.score && typeof r.score.preventionScore !== 'undefined') {
    var prevPct = Math.round(r.score.preventionScore || 0);
    var expVal  = Math.round(r.score.exposureScore || 0);
    var cls     = r.score.classification || '';
    var prevCol = prevPct >= 80 ? 'var(--teal)' : prevPct >= 50 ? 'var(--warning)' : 'var(--danger)';
    var expCol  = expVal  <= 20 ? 'var(--success)' : expVal  <= 50 ? 'var(--warning)' : 'var(--danger)';
    var trend   = r.score.trend || '';
    var trendBadge = trend === 'Improving' ? '<span style="color:var(--success);font-size:0.65rem;margin-left:0.3rem">↑</span>' :
                     trend === 'Degrading' ? '<span style="color:var(--danger);font-size:0.65rem;margin-left:0.3rem">↓</span>' : '';
    scoreHtml = '<span style="font-weight:600;color:' + prevCol + '">' + prevPct + '%</span>' +
                '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.2rem">prev</span>' +
                '<span style="color:' + expCol + ';font-size:0.72rem;margin-left:0.45rem">exp:' + expVal + '</span>' +
                trendBadge;
  } else if (r.score && typeof r.score.riskScore !== 'undefined') {
    var cls2 = r.score.classification || '';
    var col2 = cls2 === 'Protected' ? 'var(--success)' : cls2 === 'Medium Risk' ? 'var(--warning)' : 'var(--danger)';
    scoreHtml = '<span style="font-weight:600;color:' + col2 + '">' + r.score.riskScore + '</span>' +
                '<span style="color:var(--muted);font-size:0.72rem;margin-left:0.3rem">' + x(cls2) + '</span>';
  } else if (r.progress && r.progress.stepsDone > 0) {
    var pr = r.progress;
    scoreHtml = '<span style="color:var(--success);font-weight:600">' + pr.stepsPassed + '</span>' +
                '<span style="color:var(--muted);font-size:0.6rem">pass</span> / ' +
                '<span style="color:var(--danger);font-weight:600">' + pr.stepsFailed + '</span>' +
                '<span style="color:var(--muted);font-size:0.6rem">fail</span>' +
                (pr.stepsTimeout ? ' / <span style="color:var(--warning);font-weight:600">' + pr.stepsTimeout + '</span><span style="color:var(--muted);font-size:0.6rem">to</span>' : '') +
                '<span style="color:var(--muted);font-size:0.65rem;margin-left:0.35rem">' + pr.stepsDone + '/' + pr.stepsTotal + ' partial</span>';
  }
  return '<tr>' +
    '<td><code>' + x(r.id ? r.id.substring(0,14) : '—') + '</code></td>' +
    '<td style="font-weight:500">' + x(r.name) + '</td>' +
    '<td><code>' + x(r.agentId) + '</code></td>' +
    '<td><span class="sbadge s-' + x(r.status) + '">' + x(r.status) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(r.initiatedBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(r.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (r.completedAt ? fmtDate(r.completedAt) : '—') + '</td>' +
    '<td>' + (function() {
      var acts = '';
      if (r.id && (r.status === 'running' || r.progress)) acts += '<button class="btn btn-outline btn-sm" onclick="openRunPanel(\'' + x(r.id) + '\',\'' + x(r.name).replace(/'/g,'&#39;') + '\')" title="Live run timeline + progress">&#9673; Live</button> ';
      if (r.id && r.status === 'running') acts += '<button class="btn btn-outline-red btn-sm" onclick="stopRun(\'' + x(r.id) + '\')" title="Stop this run — keeps completed steps, marks the run partial">&#9632; Stop</button> ';
      if (cnt) acts += '<button class="btn btn-outline btn-sm" onclick=\'viewRunResults(' + JSON.stringify(r).replace(/'/g,"&#39;") + ')\'>' + badge + '</button>';
      return acts || '—';
    })() + '</td>' +
    '<td>' + scoreHtml + '</td></tr>';
}

function renderRunRows(list) {
  return list.map(runRowHtml).join('');
}

// renderSweepRow builds one collapsed "Full Variant Sweep" <tr> from a
// GET /api/vex/sweeps/{id}/runs response ({sweep, runs}). The badge sums
// each child run's own fail/pass counts (same per-run counting runRowHtml
// already uses) across the WHOLE sweep, not a per-technique pass/fail --
// i.e. total variants failed vs. passed across every technique dispatched.
function renderSweepRow(payload) {
  var sw = payload.sweep, childRuns = payload.runs || [];
  var totalCnt = 0, totalFail = 0;
  childRuns.forEach(function(r) {
    var cnt = (r.results || []).length;
    var fail = (r.results || []).filter(function(c) { return c.result === 'fail'; }).length;
    totalCnt += cnt; totalFail += fail;
  });
  var badge = totalCnt ? (totalFail + ' fail / ' + (totalCnt - totalFail) + ' pass') : '—';
  var progressLabel = sw.status === 'running'
    ? sw.completedVariants + '/' + sw.totalVariants + ' variants'
    : sw.totalTechniques + ' technique(s)';
  var agent = agents.find(function(a) { return a.agentId === sw.agentId; });
  var agentLabel = agent ? agent.hostname : sw.agentId;
  return '<tr>' +
    '<td><code>' + x(sw.id.substring(0,14)) + '</code></td>' +
    '<td style="font-weight:500">Full Variant Sweep — ' + x(agentLabel) + '</td>' +
    '<td><code>' + x(sw.agentId) + '</code></td>' +
    '<td><span class="sbadge s-' + x(sw.status) + '">' + x(sw.status) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(sw.createdBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(sw.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (sw.completedAt ? fmtDate(sw.completedAt) : '—') + '</td>' +
    '<td><button class="btn btn-outline btn-sm" onclick="openSweepDrilldown(\'' + x(sw.id) + '\')" title="View every technique this sweep dispatched">' +
        x(progressLabel) + ' — ' + badge + '</button></td>' +
    '<td>—</td></tr>';
}

function loadRuns() {
  apicall('/api/scenarios/runs').then(function(runs) {
    // Group sweep-dispatched rows (non-null sweepId) so Live Runs shows one
    // row per sweep instead of one row per technique it dispatched. Every
    // OTHER consumer of this same endpoint (Dashboard, Coverage matrix, etc.)
    // ignores sweepId entirely and is completely unaffected.
    var sweepIds = [];
    var seenSweepIds = {};
    var individualRuns = [];
    runs.forEach(function(r) {
      if (r.sweepId) {
        if (!seenSweepIds[r.sweepId]) { seenSweepIds[r.sweepId] = true; sweepIds.push(r.sweepId); }
      } else {
        individualRuns.push(r);
      }
    });

    var tbody = document.getElementById('runs-body');
    if (!runs.length) {
      document.getElementById('runs-cnt').textContent = '0';
      tbody.innerHTML = '<tr><td colspan="9" class="empty">No runs yet. Go to Scenarios and run one.</td></tr>';
      return;
    }

    if (!sweepIds.length) {
      document.getElementById('runs-cnt').textContent = individualRuns.length;
      tbody.innerHTML = renderRunRows(individualRuns);
      return;
    }

    Promise.all(sweepIds.map(function(id) {
      return apicall('/api/vex/sweeps/' + id + '/runs').then(function(res) {
        return { id: id, ok: true, data: res };
      }).catch(function() {
        return { id: id, ok: false };
      });
    })).then(function(sweepResults) {
      var rowsToRenderIndividually = individualRuns.slice();
      var sweepRowsHtml = [];
      sweepResults.forEach(function(sr) {
        if (!sr.ok) {
          // The per-sweep fetch failed -- fall back to rendering this sweep's
          // rows individually rather than silently hiding runs that genuinely
          // exist. Never show fewer runs than actually exist.
          rowsToRenderIndividually = rowsToRenderIndividually.concat(
            runs.filter(function(r) { return r.sweepId === sr.id; })
          );
          return;
        }
        sweepRowsHtml.push(renderSweepRow(sr.data));
      });
      document.getElementById('runs-cnt').textContent = rowsToRenderIndividually.length + sweepRowsHtml.length;
      tbody.innerHTML = renderRunRows(rowsToRenderIndividually) + sweepRowsHtml.join('');
    });
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 2: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(sweep-grouping): collapse sweep-dispatched runs into one row in Live Runs"
```

---

## Task 6: Frontend — drill-down panel

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (new overlay markup near `run-live-overlay` line 4244-4255, new JS functions near `closeRunLive()` line 13262)

**Interfaces:**
- Consumes: `GET /api/vex/sweeps/{id}/runs` (Task 4), existing `openRunPanel`/`viewRunResults` (unmodified), `apicall`, `x`, `showToast`.
- Produces: `openSweepDrilldown(sweepId)` (referenced by Task 5's `renderSweepRow`), `closeSweepDrilldown()`.

- [ ] **Step 1: Add the drill-down overlay markup**

Find the existing `run-live-overlay` (`orchestrator/wwwroot/index.html:4244-4255`):
```html
<div id="run-live-overlay" class="drawer-overlay" onclick="if(event.target===this)closeRunLive()">
  <div class="drawer" style="width:540px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="run-live-title">Live Run</h3>
      <button class="drawer-close" onclick="closeRunLive()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="run-live-progress"></div>
      <ul id="run-live-timeline" style="list-style:none;margin:0;padding:0"></ul>
    </div>
  </div>
</div>
```
Add a new sibling overlay right after its closing `</div>`:
```html
<div id="run-live-overlay" class="drawer-overlay" onclick="if(event.target===this)closeRunLive()">
  <div class="drawer" style="width:540px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="run-live-title">Live Run</h3>
      <button class="drawer-close" onclick="closeRunLive()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="run-live-progress"></div>
      <ul id="run-live-timeline" style="list-style:none;margin:0;padding:0"></ul>
    </div>
  </div>
</div>

<!-- Full Variant Sweep drill-down: every technique a sweep dispatched -->
<div id="sweep-drilldown-overlay" class="drawer-overlay" onclick="if(event.target===this)closeSweepDrilldown()">
  <div class="drawer" style="width:540px;max-width:94vw">
    <div class="drawer-header">
      <h3 id="sweep-drilldown-title">Full Variant Sweep</h3>
      <button class="drawer-close" onclick="closeSweepDrilldown()">&#10005;</button>
    </div>
    <div class="drawer-body">
      <div id="sweep-drilldown-summary" class="sub2" style="margin-bottom:0.75rem"></div>
      <ul id="sweep-drilldown-list" style="list-style:none;margin:0;padding:0"></ul>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add the JS functions**

Find `closeRunLive()`:
```js
function closeRunLive() { document.getElementById('run-live-overlay').classList.remove('open'); }
```
Add right after it:
```js
function closeRunLive() { document.getElementById('run-live-overlay').classList.remove('open'); }

// openSweepDrilldown lists every technique a Full Variant Sweep dispatched --
// each list item reuses the EXISTING, unmodified openRunPanel/viewRunResults
// for that specific run, matching how loadRuns() already opens them for a
// normal individual run.
function openSweepDrilldown(sweepId) {
  document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep';
  document.getElementById('sweep-drilldown-summary').textContent = 'Loading…';
  document.getElementById('sweep-drilldown-list').innerHTML = '';
  document.getElementById('sweep-drilldown-overlay').classList.add('open');
  apicall('/api/vex/sweeps/' + sweepId + '/runs').then(function(payload) {
    var sw = payload.sweep, childRuns = payload.runs || [];
    document.getElementById('sweep-drilldown-title').textContent = 'Full Variant Sweep — ' + (sw.agentId || '');
    document.getElementById('sweep-drilldown-summary').textContent =
      sw.status + ' · ' + childRuns.length + ' technique(s) dispatched';
    document.getElementById('sweep-drilldown-list').innerHTML = childRuns.map(function(r) {
      var cnt = (r.results || []).length;
      var fail = (r.results || []).filter(function(c) { return c.result === 'fail'; }).length;
      var badge = cnt ? (fail + ' fail / ' + (cnt - fail) + ' pass') : r.status;
      var liveBtn = (r.id && (r.status === 'running' || r.progress))
        ? '<button class="btn btn-outline btn-sm" onclick="openRunPanel(\'' + x(r.id) + '\',\'' + x(r.name).replace(/'/g,'&#39;') + '\')">&#9673; Live</button> '
        : '';
      var resultBtn = cnt
        ? '<button class="btn btn-outline btn-sm" onclick=\'viewRunResults(' + JSON.stringify(r).replace(/'/g,"&#39;") + ')\'>' + badge + '</button>'
        : '<span class="tiny muted">' + x(badge) + '</span>';
      return '<li style="padding:0.5rem 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:0.5rem">' +
        '<span>' + x(r.name) + '</span>' +
        '<span style="white-space:nowrap">' + liveBtn + resultBtn + '</span></li>';
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); closeSweepDrilldown(); });
}

function closeSweepDrilldown() { document.getElementById('sweep-drilldown-overlay').classList.remove('open'); }
```

- [ ] **Step 3: Syntax-check**

```bash
awk '/^<script>$/{flag=1;next}/^<\/script>$/{flag=0}flag' orchestrator/wwwroot/index.html | node --check
```
Expected: no output, exit code 0.

- [ ] **Step 4: Manual browser QA checklist**

(Flag as deferred if no live orchestrator instance with real registered agents/sweeps is available — same caveat as this session's prior frontend-only work, logged to the Pending Manual QA Backlog memory.)
- Start a Full Variant Sweep on an agent; confirm Live Runs shows exactly ONE "Full Variant Sweep — `<hostname>`" row, not one per technique, and its progress label updates as the sweep advances.
- Click the collapsed row; confirm the drill-down lists every technique dispatched so far, each with a Live/results button that opens the existing single-run views correctly.
- Let the sweep finish (or stop it); confirm the row persists in history with the final status/badge, and the drill-down still opens and lists every technique with final results.
- Confirm a normal individual (non-sweep) run still renders exactly as before, alongside sweep rows in the same table.
- Confirm the Dashboard and Technique Coverage matrix are visually unchanged before/after this change (regression check for the "other 7 consumers unaffected" constraint).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(sweep-grouping): add drill-down panel for collapsed sweep rows"
```

---

## Post-implementation

After Task 6's QA passes, this feature is complete: Live Runs shows one row per Full Variant Sweep (live and in history) instead of one row per technique, with a drill-down list reusing every existing single-run detail view unchanged, and zero behavior change for any other consumer of `GET /api/scenarios/runs`.
