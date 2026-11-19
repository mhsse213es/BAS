# Representative Factory Validation — Implementation Plan

> **For agentic workers:** execute task-by-task with TDD. Steps use checkbox syntax.

**Goal:** Bound factory validation to a deterministic, representative, capped
subset of a scenario's expanded steps, with honest coverage evidence, so a
462-step scenario validates within a predictable budget and never claims full
validation when a subset ran.

**Architecture:** The cap lives orchestrator-side in `dispatchRun`, after
`BuildSteps` + existing filters, before dispatch. A pure selector picks the
subset; profile + coverage persist on `scenario_runs` and flow into the
`content_validations` evidence and the `validation_resulted` SLA event.

**Tech Stack:** Go, pgx/pgxpool, testcontainers for DB tests.

**Spec:** `docs/superpowers/specs/2026-11-03-factory-representative-validation-design.md`

## Global Constraints

- No agent change; no change to `BuildSteps` expansion or to
  `classifyCompletedRun` verdict logic.
- Deterministic selection keyed on `ScenarioStep.TaskID` (stable hash).
- Honest outcomes: PASS = selected profile passed; failure modes never PASS
  (already enforced — preserve).
- Defaults: `PerTechnique=1`, `MaxSteps=25`, timeout hard max 30 min.

---

## Task 1: Representative selector (pure, unit-tested)

**Files:**
- Create: `orchestrator/internal/scenario/validation_profile.go`
- Test: `orchestrator/internal/scenario/validation_profile_test.go`

**Produces:**
- `type ValidationProfile string`; `ValidationProfileRepresentative = "representative"`, `ValidationProfileFull = "full"`.
- `type RepresentativeLimits struct { MaxSteps, PerTechnique int }`; `DefaultRepresentativeLimits() RepresentativeLimits` → `{25, 1}`.
- `type ValidationCoverage struct { Profile string; TotalSteps, SelectedSteps, SkippedSteps, TechniquesTotal, TechniquesSelected int; Truncated bool }` (json tags snake_case).
- `func SelectRepresentative(steps []ScenarioStep, lim RepresentativeLimits) ([]ScenarioStep, ValidationCoverage)`.

- [ ] Step 1: tests — deterministic order & reproducibility (same input twice → identical subset); ≤PerTechnique per `TechniqueID`; global `MaxSteps` cap with `Truncated=true` when it drops steps; coverage counts correct; empty input → empty subset + zeroed coverage; `PerTechnique` honored across interleaved techniques.
- [ ] Step 2: run — FAIL (undefined).
- [ ] Step 3: implement selector. Stable sort by `(TechniqueID, ProxyTechniqueID, TaskID)`; take ≤PerTechnique per `TechniqueID`; cap to `MaxSteps`; fill coverage (`TotalSteps=len(steps)`).
- [ ] Step 4: run — PASS; `go test ./internal/scenario/ -run Representative`.
- [ ] Step 5: commit.

## Task 2: Profile into dispatch + coverage persistence

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`dispatchOpts`, `DispatchFactoryValidation`, `dispatchRun`)
- Modify: `orchestrator/internal/db/postgres.go` (two `ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS`)
- Test: `orchestrator/internal/api/dispatch_run_test.go` (or a new `factory_validation_subset_test.go`)

**Consumes:** Task 1 selector. **Produces:** `scenario_runs.validation_profile text`, `scenario_runs.validation_coverage jsonb`; a factory-validation run dispatches only the representative subset and records coverage.

- [ ] Step 1: migration lines in postgres.go: `validation_profile text NOT NULL DEFAULT ''`, `validation_coverage jsonb`.
- [ ] Step 2: `dispatchOpts.ValidationProfile scenario.ValidationProfile`; `DispatchFactoryValidation` sets `ValidationProfileRepresentative`.
- [ ] Step 3: test (RED) — a factory-validation dispatch of a multi-technique scenario sends ≤MaxSteps steps and writes `validation_profile='representative'` + a `validation_coverage` row with `total>selected`.
- [ ] Step 4: in `dispatchRun`, after variant expansion and before `persistStepMeta`: if `o.ValidationProfile == ValidationProfileRepresentative`, `steps, cov = SelectRepresentative(steps, DefaultRepresentativeLimits())`, log it, and `UPDATE scenario_runs SET validation_profile=$1, validation_coverage=$2`. Leave `steps_total_base` as the honest full count.
- [ ] Step 5: run — PASS; `go build ./...`.
- [ ] Step 6: commit.

## Task 3: Honest outcome + evidence in the lab

**Files:**
- Modify: `orchestrator/internal/validationlab/orchestrator.go` (`resolveIfComplete`, `recordExecutionOutcome`)
- Test: `orchestrator/internal/validationlab/orchestrator_test.go`

**Consumes:** `scenario_runs.validation_profile`/`validation_coverage`. **Produces:** `content_validations.detail` and the `validation_resulted` payload carry `profile` + `coverage`.

- [ ] Step 1: test (RED) — a completed representative run resolves to PASS whose `content_validations.detail` contains `profile='representative'` and the coverage object; a FAIL/timeout still records the profile and never PASSes.
- [ ] Step 2: `resolveIfComplete` SELECT adds `validation_profile, validation_coverage`; pass both into `recordExecutionOutcome`'s detail; include in the `validation_resulted` tcv payload. Verdict logic unchanged.
- [ ] Step 3: run — PASS.
- [ ] Step 4: commit.

## Task 4: Configurable lab timeout with a hard ceiling

**Files:**
- Modify: `orchestrator/internal/validationlab/orchestrator.go` (exported setter or env read + clamp const)
- Modify: `orchestrator/cmd/server/main.go` (read `VALIDATION_LAB_TIMEOUT_MINUTES`)
- Test: `orchestrator/internal/validationlab/orchestrator_test.go`

- [ ] Step 1: test (RED) — clamp: 0/unset → 10m default; 5 → 5m; 999 → 30m hard max.
- [ ] Step 2: add `validationTimeoutHardMaxMinutes = 30`; a `clampValidationTimeout(minutes int) time.Duration`; wire env in main.go.
- [ ] Step 3: run — PASS; `go build ./...`.
- [ ] Step 4: commit.

## Review Focus

- A representative subset that still errors/partial must FAIL, never PASS (req 6) — covered in Task 3 tests.
- Determinism across process restarts (TaskID stability) — Task 1 reproducibility test.
- `steps_total_base` stays the full count so coverage "total" is honest — Task 2 assertion.
- Empty runnable set after filters (nothing to select) keeps the existing all-skipped path, not a representative PASS — Task 2: selection runs only on non-empty `steps` (the all-skipped guard precedes it).
