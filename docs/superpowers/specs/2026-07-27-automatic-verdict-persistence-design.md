# Automatic Verdict Persistence — Design Spec

**Status:** Approved for planning
**Author:** Audspect (brainstormed 2026-07-27)
**Scope:** Phase A0 of the "Purple Team packs" roadmap item ([[project_scenario_roadmap]]) — a prerequisite discovered while designing the [[project_outcome_validation_framework]]-adjacent Exercise Detection Bridge (spec: `docs/superpowers/specs/2026-07-27-exercise-detection-bridge-design.md`). Independently useful beyond that bridge: it completes the Verification Store's own documented intent for every consumer of `verification.History`/`CurrentForRun`, not just the exercise engine.

## Problem

`internal/verification`'s package doc comment describes the store's data flow as:

> Simulation → Expected Detection → Verification Engine → Verification Store → Reporting

implying something already persists verification results into
`verification_history`. In reality, tracing every call site of
`Store.Attest` finds exactly two: the manual analyst-verification API
handler (`internal/api/verification_handlers.go`) and the SP3 API-connector
orchestrator (`internal/detectverify/orchestrate.go`). **Automatic on-host
verification — the result of `verifyExpectation`/`automaticVerifier`/
`dlpVerifier`, computed fresh every time a report is rendered — is never
written to the store.** `SourceAutomatic` is a defined constant
(`verification/store.go:48`) that is never actually used anywhere.

Consequences:
- `Store.History(runID, expectationID)` for a purely-automatic expectation
  that no analyst has ever touched returns empty — the audit trail the
  store's own doc comment promises doesn't exist for the common case.
- `Store.CurrentForRun`/a future `CurrentApprovedForRun` return nothing for
  such expectations, which is what makes the Exercise Detection Bridge spec
  unable to observe real BAS-triggered detections (the motivating case for
  this spec, but not the only consumer that benefits from the fix).

## Non-goals

- No change to `applyOverride`'s existing override semantics (a stored
  manual/API attestation still always wins over an automatic one — this
  spec never touches or supersedes an existing record, see "Safety
  invariant" below).
- No change to report rendering — reports already compute automatic
  verdicts in-memory on demand; this spec adds a *parallel* persistence
  path, not a new read path for reports.
- No backfill of historical runs beyond what the poller naturally picks up
  going forward (existing completed runs get `auto_verified=false` by
  column default, so they DO get processed on the next poll tick after
  deploy — this is intentional, not a gap, but no special one-time backfill
  script is written).
- No new UI. `Store.History`/`CurrentForRun` already have UI consumers
  (Detection Verification tab); this spec only makes the data they read
  more complete.

## Safety invariant

The poller must never supersede or duplicate an existing record. Before
attesting anything for a run, it reads `Store.CurrentForRun(runID)` (all
sources, all workflow states) and **only attests expectations with no
active record at all**. If a human already reviewed an expectation, or an
API connector already attested it, the poller leaves it untouched — even if
its own automatic computation would produce the same or a different
verdict. This is the single load-bearing correctness property of this
spec; every other decision below serves it.

## Architecture

```
Poll tick (new PollScheduler-driven job, same pattern as OpenAEV's sync job)
  → SELECT id, scenario_id, results FROM scenario_runs
      WHERE status IN ('completed','failed','partial') AND NOT auto_verified
      LIMIT N
  → for each run:
      results := unmarshal(row.results)  // []models.SimulationResult
      verdicts := reporting.ComputeAutomaticVerifications(scenarios, scenarioID, results)
      existing := verification.Store.CurrentForRun(ctx, runID)  // all sources
      for _, vr := range verdicts:
          if vr.Status not in {Detected, NotDetected, NotApplicable}: skip  // nothing provable
          if existing[vr.ExpectedID] already present: skip                  // safety invariant
          Store.Attest(Source: automatic, WorkflowState: Approved, Result: mapped from vr.Status, RuleIDs: ...)
      mark scenario_runs.auto_verified = true  // bounds the query regardless of outcome
```

## Components

### 1. `reporting.ComputeAutomaticVerifications` — new exported function

`orchestrator/internal/reporting/detection_validation.go`. Extracts the
per-expectation verification loop that `BuildDetectionValidationWithStore`
already runs internally, but returns the raw results instead of aggregating
them into a report section. `BuildDetectionValidationWithStore` is
refactored to call this instead of duplicating the loop (DRY — one
`verifyExpectation` call site for both consumers).

```go
// ComputeAutomaticVerifications runs the automatic verification engine over
// every step's expectations for one run and returns the raw, unaggregated
// results — the same computation BuildDetectionValidationWithStore performs
// internally before rolling results into a report section, exposed here for
// callers (the automatic-verdict-persistence poller) that need the raw
// per-expectation verdicts rather than a rendered report.
func ComputeAutomaticVerifications(specs []StepDetectionSpec, results []models.SimulationResult) []VerificationResult {
	evByTech := evidenceByTechnique(results)
	var out []VerificationResult
	for _, spec := range specs {
		ev := evByTech[spec.TechniqueID]
		ev.TechniqueID = spec.TechniqueID
		for _, exp := range spec.Expected {
			out = append(out, verifyExpectation(exp, ev))
		}
	}
	return out
}
```

`BuildDetectionValidationWithStore`'s existing per-expectation loop (the
`for _, exp := range expected { vr := verifyExpectation(exp, ev) ... }`
block, currently at `detection_validation.go:435-436`) is refactored to
call `ComputeAutomaticVerifications` once per `spec` up front (or the whole
function restructured to compute all verdicts first via this new function,
then iterate them for aggregation) rather than calling `verifyExpectation`
inline a second time — implementers should verify the exact refactor keeps
`BuildDetectionValidationWithStore`'s existing test suite passing
unmodified, since this is a pure extraction with no behavior change.

### 2. `Engine`-level wrapper for scenario resolution

The poller lives outside `internal/reporting.Engine` (it needs to run on a
schedule against arbitrary runs, not per-report-request), but scenario
resolution (`e.scenarios.Get`/`ResolveStepExpectations`, building
`[]StepDetectionSpec`) is exactly `buildDetectionValidation`'s existing
first half. Extract that half into its own exported function so the poller
doesn't need reporting-internal access:

```go
// ResolveStepDetectionSpecs resolves a scenario's steps into their detection
// expectations via the given resolver. Returns nil if the scenario is
// unknown or declares no expectations — callers should treat that as
// nothing to verify, not an error.
func ResolveStepDetectionSpecs(scenarios ScenarioResolver, scenarioID string) []StepDetectionSpec {
	sc, ok := scenarios.Get(scenarioID)
	if !ok {
		return nil
	}
	var specs []StepDetectionSpec
	for _, step := range sc.Steps {
		exp, refs := scenarios.ResolveStepExpectations(step)
		if len(exp) == 0 {
			continue
		}
		specs = append(specs, StepDetectionSpec{
			TechniqueID: step.TechniqueID,
			Expected:    exp,
			Telemetry:   step.Telemetry,
			ProfileRefs: refs,
		})
	}
	return specs
}
```

`buildDetectionValidation` (the `Engine` method) is refactored to call this
too, replacing its own inline loop — another pure extraction, same
"existing tests must pass unmodified" requirement.

### 3. New package `internal/verifysync`

Single-responsibility: the poller. Depends on `internal/reporting`
(`ScenarioResolver`, `StepDetectionSpec`, `VerificationResult`,
`ResolveStepDetectionSpecs`, `ComputeAutomaticVerifications`, the `Status*`
constants), `internal/verification` (`Store`, `AttestInput`, `Source*`/
`Result*` constants), `internal/models` (`SimulationResult`), and
`*pgxpool.Pool` directly (for the `scenario_runs` sweep query — this
package, not `reporting.Engine`, owns that query since it's not part of any
report-building flow).

```go
package verifysync

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/verification"
)

// Job periodically persists automatic verification results for completed
// BAS runs, closing the gap where verification.Store never otherwise
// receives automatic-source records (see design spec
// docs/superpowers/specs/2026-07-27-automatic-verdict-persistence-design.md).
type Job struct {
	db         *pgxpool.Pool
	store      *verification.Store
	scenarios  reporting.ScenarioResolver
	batchSize  int
}

func NewJob(db *pgxpool.Pool, store *verification.Store, scenarios reporting.ScenarioResolver) *Job {
	return &Job{db: db, store: store, scenarios: scenarios, batchSize: 50}
}

// Tick processes up to one batch of not-yet-processed runs. Safe to call on
// every scheduler tick regardless of how many runs are pending — each call
// bounds itself to batchSize.
func (j *Job) Tick(ctx context.Context) {
	rows, err := j.db.Query(ctx,
		`SELECT id, scenario_id, results FROM scenario_runs
		 WHERE status IN ('completed','failed','partial') AND NOT auto_verified
		 LIMIT $1`, j.batchSize)
	if err != nil {
		log.Printf("[verifysync] query pending runs: %v", err)
		return
	}
	type pending struct {
		runID, scenarioID string
		resultsRaw        []byte
	}
	var runs []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.runID, &p.scenarioID, &p.resultsRaw); err != nil {
			rows.Close()
			log.Printf("[verifysync] scan pending run: %v", err)
			return
		}
		runs = append(runs, p)
	}
	rows.Close()

	for _, p := range runs {
		if err := j.processRun(ctx, p.runID, p.scenarioID, p.resultsRaw); err != nil {
			log.Printf("[verifysync] process run %s: %v", p.runID, err)
			continue // leave auto_verified=false, retried next tick
		}
		if _, err := j.db.Exec(ctx,
			`UPDATE scenario_runs SET auto_verified=true WHERE id=$1`, p.runID); err != nil {
			log.Printf("[verifysync] mark run %s processed: %v", p.runID, err)
		}
	}
}

func (j *Job) processRun(ctx context.Context, runID, scenarioID string, resultsRaw []byte) error {
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			return err
		}
	}
	specs := reporting.ResolveStepDetectionSpecs(j.scenarios, scenarioID)
	if len(specs) == 0 {
		return nil // nothing declared any expectation — mark processed, nothing to do
	}
	verdicts := reporting.ComputeAutomaticVerifications(specs, results)

	existing, err := j.store.CurrentForRun(ctx, runID)
	if err != nil {
		return err
	}

	for _, vr := range verdicts {
		result, ok := mapStatusToResult(vr.Status)
		if !ok {
			continue // Pending/Unknown — nothing provable, never attested
		}
		if _, already := existing[vr.ExpectedID]; already {
			continue // safety invariant: never supersede an existing record, of any source
		}
		if _, err := j.store.Attest(ctx, verification.AttestInput{
			RunID:         runID,
			ExpectationID: vr.ExpectedID,
			TechniqueID:   vr.TechniqueID,
			Domain:        vr.Domain,
			Provider:      vr.Provider,
			Result:        result,
			WorkflowState: verification.StateApproved,
			Source:        verification.SourceAutomatic,
			VerifiedBy:    "automatic",
		}); err != nil {
			return err
		}
	}
	return nil
}

func mapStatusToResult(status string) (string, bool) {
	switch status {
	case reporting.StatusDetected:
		return verification.ResultDetected, true
	case reporting.StatusNotDetected:
		return verification.ResultNotDetected, true
	case reporting.StatusNotApplicable:
		return verification.ResultNotApplicable, true
	default:
		return "", false
	}
}
```

Neither `AttestInput` nor `VerificationResult` currently carries `RuleIDs` —
this spec adds it to both, all the way through:

- **`VerificationResult`** (`orchestrator/internal/reporting/detection_validation.go`)
  gains `RuleIDs []string`, populated by `verifyExpectation`/
  `automaticVerifier.Verify`/`dlpVerifier.Verify` from the live
  `exp.RuleIDs` each already has in scope — mirrors how `ExpectedOutcome`/
  `ObservedOutcome`/`Comparison` were added to this same struct in the
  Outcome Validation Framework work.
- **`verification.AttestInput`** and **`verification.Record`** gain
  `RuleIDs []string`, threaded through `Attest`'s `INSERT`/`recordCols`/
  `scanRecord` exactly like `TechniqueID`/`Domain`/`Provider` already are.
- `processRun` (Component 3 above) sets `AttestInput.RuleIDs: vr.RuleIDs`.

This spec owns adding `RuleIDs` end-to-end (previously assigned to the
Exercise Detection Bridge spec, before this poller's dependency on it was
discovered); the Exercise Detection Bridge spec is corrected below to
consume the field rather than re-add it, so the two plans don't race to add
the same column twice.

### 4. Migration

Two additive, nullable/defaulted columns, following this codebase's
existing `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` pattern
(`orchestrator/internal/db/postgres.go`):

```sql
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS auto_verified boolean NOT NULL DEFAULT false;
ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS rule_ids text[] NOT NULL DEFAULT '{}';
```

`recordCols`/`scanRecord`/the `Attest` INSERT statement in
`orchestrator/internal/verification/store.go` are extended to include
`rule_ids`, matching the pattern already used for `technique_id`/`domain`/
`provider`.

### 5. Wiring

`orchestrator/cmd/server/main.go`: construct `verifysync.NewJob(pool,
verificationStore, engine)` — `engine` is the existing local
`*scenario.Engine` variable already passed to `WithScenarios(engine)` at
`main.go:204` (it satisfies `reporting.ScenarioResolver` — `Get(id string)
(*Scenario, bool)` at `scenario/engine.go:125` plus the already-used
`ResolveStepExpectations`); `verificationStore` is the existing
`*verification.Store` instance already constructed there. Alongside the
other poll-scheduled jobs already started in `main.go` (OpenAEV's sync job
is the precedent), using a new `exercise.NewPollScheduler(interval)`
instance (the generic, already-reused-elsewhere scheduler — importing it
from `internal/exercise` for its ticking is precedented by OpenAEV's own
Module 1 correction, not a new pattern) with `.Start(job.Tick)`. Interval: 5
minutes (fast enough that the exercise bridge doesn't wait long, coarse
enough not to hammer the DB with the sweep query).

## Edge cases

- **Run has zero expectations** (`ResolveStepDetectionSpecs` returns nil) →
  `processRun` returns `nil` immediately, `auto_verified` still gets set to
  `true` — the run is never re-queried, no wasted repeated work.
- **Run already fully covered by manual/API attestations** → every
  `vr.ExpectedID` is found in `existing`, loop attests nothing, still marked
  processed. Correct — nothing left for automatic verdicts to fill in.
  Partial coverage (some expectations attested, some not) is handled
  per-expectation by the same check — only the gaps get filled.
- **`Attest` returns `ErrConflict`** (a concurrent attestation raced this
  one — e.g. an analyst attested the same expectation between the
  `CurrentForRun` read and this `Attest` call) → `processRun` returns the
  error, `auto_verified` is NOT set, retried next tick; on retry,
  `CurrentForRun` now sees the concurrent record and skips it — self-healing,
  no special conflict-handling code needed beyond what `Attest` already does.
- **`results` JSON is empty/null** (a run that failed before producing any
  step results) → `json.Unmarshal` on empty bytes is skipped (`len(resultsRaw)
  > 0` guard); `results` stays a nil slice; `ComputeAutomaticVerifications`
  still runs (per-expectation verification against empty evidence correctly
  resolves to `NotDetected` for endpoint-domain expectations, matching
  today's existing report-rendering behavior for such runs).
- **Two poller instances running concurrently** (e.g. during a rolling
  deploy) → the `LIMIT N` sweep query has no row-locking, so both could pick
  up the same run. `Attest`'s existing `FOR UPDATE` row lock + the partial
  unique active-row index already serialize concurrent attestations
  correctly (this is exactly the concurrency the store's existing locking
  was built for — SP2's design already accounts for concurrent writers); at
  worst one instance's `Attest` calls return `ErrConflict` for
  already-attested expectations and both mark `auto_verified=true`
  harmlessly.

## Testing approach

- **`ComputeAutomaticVerifications`**: extend existing `detection_validation_test.go` fixtures — assert it returns the same per-expectation results `BuildDetectionValidationWithStore` would aggregate from, for a multi-domain multi-expectation fixture (reuse the existing golden-output fixture's input).
- **`ResolveStepDetectionSpecs`**: unit test against a fake `ScenarioResolver` — unknown scenario ID → nil; scenario with steps declaring no expectations → nil; mixed → only expectation-bearing steps produce a `StepDetectionSpec`.
- **`VerificationResult.RuleIDs` threading**: extend existing `automaticVerifier`/`dlpVerifier` tests to assert `RuleIDs` round-trips from `exp.RuleIDs`.
- **`verifysync.Job.processRun`**: Docker/Postgres-testcontainer test (matches `internal/verification`'s existing pattern) — seed a `scenario_runs` row + a fake `ScenarioResolver` with known expectations; assert: (a) fresh run with no existing records → all Detected/NotDetected expectations get `Attest`ed with `Source=automatic`; (b) a run where one expectation already has a manual `Approved` record → that expectation is untouched, only the others get attested (the safety-invariant test — the single most important test in this plan); (c) `NotApplicable`/an expectation whose `Status` resolves to `Unknown` → not attested.
- **`Job.Tick`**: seed multiple pending runs, assert `auto_verified` flips to `true` for all after one `Tick` call; seed a run that already has `auto_verified=true`, assert it's never touched (query excludes it).
- **Backward compatibility**: `BuildDetectionValidationWithStore`'s and `buildDetectionValidation`'s existing test suites must pass unmodified after the extraction refactor — this is a pure extraction, not a behavior change.

## Relationship to the Exercise Detection Bridge spec

The Exercise Detection Bridge spec (`2026-07-27-exercise-detection-bridge-design.md`) is updated post-hoc with one correction: its Component 1 ("`verification.Record` gains `RuleIDs`") is now owned by this spec instead, since this spec's poller needs `RuleIDs` threaded through the same path first. The bridge spec's `CurrentApprovedForRun` and `ResolveDetectionEvidence` components are otherwise unaffected — they now correctly assume `Approved` automatic records exist in the store, which this spec is what makes true.
