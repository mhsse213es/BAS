# Automatic Verdict Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist automatic (on-host) detection verification results into `verification_history` — today only manual and API-connector attestations are ever written there — via a new periodic poller, so `Store.CurrentForRun`/`History` are complete for every consumer, not just human/connector-reviewed expectations.

**Architecture:** A new `internal/verifysync` package polls `scenario_runs` for terminally-statused rows not yet processed, computes automatic verdicts by reusing the exact per-expectation verification logic `reporting.BuildDetectionValidationWithStore` already runs (extracted into two new small exported functions), and `Attest()`s each Detected/NotDetected/NotApplicable result whose expectation has no existing record of any source — never superseding a human or connector attestation.

**Tech Stack:** Go, PostgreSQL (`pgxpool`), the existing `internal/testutil` Docker-testcontainer test harness.

## Global Constraints

- **Safety invariant (from the spec, non-negotiable):** the poller must never write over an expectation that already has ANY active `verification_history` record, regardless of that record's source. Check `Store.CurrentForRun(runID)` before every `Attest` call and skip anything already present.
- Only `Detected`/`NotDetected`/`NotApplicable` results get attested. `Pending`/`Unknown` are never provable automatically and must never be persisted.
- All new DB schema changes are additive (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`), matching this codebase's existing migration pattern in `orchestrator/internal/db/postgres.go` — no destructive changes, no backfill script.
- Every extraction of existing logic into a new function must leave existing test suites (`TestBuildDetectionValidationGoldenOutput`, `TestAutomaticVerifier`, and all of `internal/reporting`'s/`internal/verification`'s existing tests) passing **unmodified** — these are pure extractions, not behavior changes.
- Docker Desktop must be running for every `internal/verification`/`internal/reporting`/`internal/verifysync` test (Postgres testcontainer via `internal/testutil`). Check `docker info` before running these suites; if it's down, ask the user to start it rather than skipping tests.

---

### Task 1: Thread `RuleIDs` through `VerificationResult`

**Files:**
- Modify: `orchestrator/internal/reporting/detection_validation.go:53-72` (`VerificationResult` struct), `:97-108` (`baseResult`)
- Test: `orchestrator/internal/reporting/detection_validation_test.go`

**Interfaces:**
- Produces: `VerificationResult.RuleIDs []string` — populated by every verifier (`automaticVerifier`, `manualVerifier`, `apiVerifier`, `dlpVerifier`) since all of them call `baseResult`. Consumed by Task 3's `ComputeAutomaticVerifications` and, later, `internal/verifysync` (Task 4).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/reporting/detection_validation_test.go` (near `TestAutomaticVerifier`, same file):

```go
func TestAutomaticVerifier_ThreadsRuleIDs(t *testing.T) {
	exp := endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)
	exp.RuleIDs = []string{"AUDRULE-000001", "AUDRULE-000002"}

	r := automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if len(r.RuleIDs) != 2 || r.RuleIDs[0] != "AUDRULE-000001" || r.RuleIDs[1] != "AUDRULE-000002" {
		t.Errorf("RuleIDs = %v, want [AUDRULE-000001 AUDRULE-000002]", r.RuleIDs)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (from `orchestrator/`): `go test ./internal/reporting/... -run TestAutomaticVerifier_ThreadsRuleIDs -v`
Expected: FAIL — `r.RuleIDs undefined (type VerificationResult has no field or method RuleIDs)`

- [ ] **Step 3: Add the field and thread it through `baseResult`**

In `orchestrator/internal/reporting/detection_validation.go`, the `VerificationResult` struct currently ends:

```go
	// ExpectedOutcome/ObservedOutcome/Comparison are the Outcome Validation
	// Framework's richer internal computation — not surfaced in any report
	// JSON (ExpectationRow has no equivalent fields). Status remains the only
	// field existing scoring/report code consumes, now derived from Comparison.
	ExpectedOutcome string
	ObservedOutcome string
	Comparison      ComparisonResult
}
```

Add `RuleIDs` after `Comparison`:

```go
	ExpectedOutcome string
	ObservedOutcome string
	Comparison      ComparisonResult

	// RuleIDs links this verdict to Detection Rule Library entries
	// (internal/rulelib.Rule.ID), carried through from the live
	// ExpectedDetection.RuleIDs at verification time. Not surfaced in any
	// report JSON today — read by the automatic-verdict-persistence poller
	// (internal/verifysync) so it can persist the linkage onto
	// verification.Record.
	RuleIDs []string
}
```

`baseResult` currently:

```go
func baseResult(exp scenario.ExpectedDetection, ev StepEvidence, verifiedBy string) VerificationResult {
	return VerificationResult{
		ExpectedID:  exp.ID,
		Provider:    exp.Provider,
		Domain:      scenario.ResolveDomain(exp),
		Confidence:  exp.Confidence,
		VerifiedBy:  verifiedBy,
		Timestamp:   time.Now().UTC(),
		Finding:     exp.Finding,
		TechniqueID: ev.TechniqueID,
	}
}
```

Add `RuleIDs: exp.RuleIDs` (one line — this single edit point covers every verifier, since all four call `baseResult`):

```go
func baseResult(exp scenario.ExpectedDetection, ev StepEvidence, verifiedBy string) VerificationResult {
	return VerificationResult{
		ExpectedID:  exp.ID,
		Provider:    exp.Provider,
		Domain:      scenario.ResolveDomain(exp),
		Confidence:  exp.Confidence,
		VerifiedBy:  verifiedBy,
		Timestamp:   time.Now().UTC(),
		Finding:     exp.Finding,
		TechniqueID: ev.TechniqueID,
		RuleIDs:     exp.RuleIDs,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/reporting/... -run TestAutomaticVerifier_ThreadsRuleIDs -v`
Expected: PASS

- [ ] **Step 5: Run the full reporting suite to confirm no regression**

Run: `go test ./internal/reporting/... -run 'TestAutomaticVerifier|TestBuildDetectionValidationGoldenOutput|TestDLPVerifier' -v`
Expected: all PASS, unmodified assertions

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/detection_validation_test.go
git commit -m "feat(reporting): thread RuleIDs through VerificationResult via baseResult"
```

---

### Task 2: `verification.Record`/`AttestInput` gain `RuleIDs` + `rule_ids` column

**Files:**
- Modify: `orchestrator/internal/verification/store.go` (`Record` struct, `AttestInput` struct, `recordCols`, `scanRecord`, `Attest`)
- Modify: `orchestrator/internal/db/postgres.go:1019` (add migration line)
- Test: `orchestrator/internal/verification/store_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 (independent file/package).
- Produces: `verification.Record.RuleIDs []string`, `verification.AttestInput.RuleIDs []string`. Consumed by Task 4's `verifysync.Job.processRun`.

- [ ] **Step 1: Add the migration line**

In `orchestrator/internal/db/postgres.go`, immediately after line 1019 (`` `ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`, ``), add:

```go
		`ALTER TABLE verification_history ADD COLUMN IF NOT EXISTS rule_ids text[] NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 2: Write the failing test**

Add to `orchestrator/internal/verification/store_test.go`:

```go
func TestAttest_PersistsRuleIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		rec, err := store.Attest(context.Background(), AttestInput{
			RunID: "run-rule-1", ExpectationID: "exp-rule-1", VerifiedBy: "alice",
			RuleIDs: []string{"AUDRULE-000001", "AUDRULE-000002"},
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if len(rec.RuleIDs) != 2 || rec.RuleIDs[0] != "AUDRULE-000001" || rec.RuleIDs[1] != "AUDRULE-000002" {
			t.Fatalf("rec.RuleIDs = %v, want [AUDRULE-000001 AUDRULE-000002]", rec.RuleIDs)
		}

		// Round-trip through a fresh read, not just the RETURNING clause.
		reread, err := store.CurrentForRun(context.Background(), "run-rule-1")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}
		if len(reread["exp-rule-1"].RuleIDs) != 2 {
			t.Fatalf("reread RuleIDs = %v, want 2 entries", reread["exp-rule-1"].RuleIDs)
		}
	})
}

func TestAttest_NilRuleIDsDoesNotViolateNotNull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		// RuleIDs deliberately left nil (zero value) — must not violate the
		// rule_ids text[] NOT NULL column constraint.
		rec, err := store.Attest(context.Background(), AttestInput{
			RunID: "run-rule-2", ExpectationID: "exp-rule-2", VerifiedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Attest with nil RuleIDs: %v", err)
		}
		if len(rec.RuleIDs) != 0 {
			t.Fatalf("rec.RuleIDs = %v, want empty", rec.RuleIDs)
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/verification/... -run 'TestAttest_PersistsRuleIDs|TestAttest_NilRuleIDsDoesNotViolateNotNull' -v`
Expected: FAIL — `unknown field RuleIDs in struct literal of type AttestInput`

- [ ] **Step 4: Add `RuleIDs` to `Record` and `AttestInput`**

In `orchestrator/internal/verification/store.go`, `Record` currently ends:

```go
type Record struct {
	ID             string    `json:"id"`
	RunID          string    `json:"runId"`
	ExpectationID  string    `json:"expectationId"`
	ProfileName    string    `json:"profileName"`
	ProfileVersion int       `json:"profileVersion"`
	TechniqueID    string    `json:"techniqueId"`
	Domain         string    `json:"domain"`
	Provider       string    `json:"provider"`
	Result         string    `json:"result"`
	WorkflowState  string    `json:"workflowState"`
	Source         string    `json:"source"`
	Note           string    `json:"note"`
	AlertID        string    `json:"alertId"`
	VerifiedBy     string    `json:"verifiedBy"`
	VerifiedAt     time.Time `json:"verifiedAt"`
	SupersedesID   string    `json:"supersedesId,omitempty"`
	Active         bool      `json:"active"`
}
```

Add `RuleIDs` before the closing brace:

```go
	SupersedesID   string    `json:"supersedesId,omitempty"`
	Active         bool      `json:"active"`
	RuleIDs        []string  `json:"ruleIds,omitempty"`
}
```

`AttestInput` currently ends:

```go
type AttestInput struct {
	RunID          string
	ExpectationID  string
	ProfileName    string
	ProfileVersion int
	TechniqueID    string
	Domain         string
	Provider       string
	Result         string
	WorkflowState  string
	Source         string
	Note           string
	AlertID        string
	VerifiedBy     string
}
```

Add `RuleIDs`:

```go
	AlertID        string
	VerifiedBy     string
	RuleIDs        []string
}
```

- [ ] **Step 5: Update `recordCols`, `scanRecord`, and `Attest`**

`recordCols` currently:

```go
const recordCols = `id, run_id, expectation_id, profile_name, profile_version,
	technique_id, domain, provider, result, workflow_state, verification_source,
	note, alert_id, verified_by, verified_at, supersedes_id, active`
```

Add `rule_ids`:

```go
const recordCols = `id, run_id, expectation_id, profile_name, profile_version,
	technique_id, domain, provider, result, workflow_state, verification_source,
	note, alert_id, verified_by, verified_at, supersedes_id, active, rule_ids`
```

`scanRecord` currently:

```go
func scanRecord(row pgx.Row) (Record, error) {
	var r Record
	err := row.Scan(&r.ID, &r.RunID, &r.ExpectationID, &r.ProfileName, &r.ProfileVersion,
		&r.TechniqueID, &r.Domain, &r.Provider, &r.Result, &r.WorkflowState, &r.Source,
		&r.Note, &r.AlertID, &r.VerifiedBy, &r.VerifiedAt, &r.SupersedesID, &r.Active)
	return r, err
}
```

Add `&r.RuleIDs`, matching `recordCols`' new column order:

```go
func scanRecord(row pgx.Row) (Record, error) {
	var r Record
	err := row.Scan(&r.ID, &r.RunID, &r.ExpectationID, &r.ProfileName, &r.ProfileVersion,
		&r.TechniqueID, &r.Domain, &r.Provider, &r.Result, &r.WorkflowState, &r.Source,
		&r.Note, &r.AlertID, &r.VerifiedBy, &r.VerifiedAt, &r.SupersedesID, &r.Active, &r.RuleIDs)
	return r, err
}
```

In `Attest`, immediately before the `INSERT` (`orchestrator/internal/verification/store.go`, inside the `func (s *Store) Attest` body, right after the `priorID` block and before `rec, err := scanRecord(...)`), normalize a nil `RuleIDs` to an empty slice — mirroring the exact fix already applied elsewhere in this codebase for nil-slice-into-`NOT NULL text[]` (see `internal/openaev/store.go`'s `Upsert`, which hit the identical bug for `Platforms`/`TechniqueIDs`/`Tags`):

```go
	if priorID != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE verification_history SET active=false WHERE id=$1`, priorID); err != nil {
			return Record{}, err
		}
	}

	ruleIDs := in.RuleIDs
	if ruleIDs == nil {
		ruleIDs = []string{}
	}

	rec, err := scanRecord(tx.QueryRow(ctx,
```

The `INSERT` itself currently:

```go
	rec, err := scanRecord(tx.QueryRow(ctx,
		`INSERT INTO verification_history
			(run_id, expectation_id, profile_name, profile_version, technique_id,
			 domain, provider, result, workflow_state, verification_source,
			 note, alert_id, verified_by, supersedes_id, active)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,true)
		 RETURNING `+recordCols,
		in.RunID, in.ExpectationID, in.ProfileName, in.ProfileVersion, in.TechniqueID,
		in.Domain, in.Provider, in.Result, in.WorkflowState, in.Source,
		in.Note, in.AlertID, in.VerifiedBy, priorID))
```

Add `rule_ids`/`$15`/`ruleIDs`:

```go
	rec, err := scanRecord(tx.QueryRow(ctx,
		`INSERT INTO verification_history
			(run_id, expectation_id, profile_name, profile_version, technique_id,
			 domain, provider, result, workflow_state, verification_source,
			 note, alert_id, verified_by, supersedes_id, active, rule_ids)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,true,$15)
		 RETURNING `+recordCols,
		in.RunID, in.ExpectationID, in.ProfileName, in.ProfileVersion, in.TechniqueID,
		in.Domain, in.Provider, in.Result, in.WorkflowState, in.Source,
		in.Note, in.AlertID, in.VerifiedBy, priorID, ruleIDs))
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/verification/... -run 'TestAttest_PersistsRuleIDs|TestAttest_NilRuleIDsDoesNotViolateNotNull' -v`
Expected: PASS

- [ ] **Step 7: Run the full verification suite to confirm no regression**

Run: `go test ./internal/verification/... -v -count=1`
Expected: 100% PASS

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/verification/store.go orchestrator/internal/verification/store_test.go orchestrator/internal/db/postgres.go
git commit -m "feat(verification): RuleIDs on Record/AttestInput + rule_ids column"
```

---

### Task 3: `ComputeAutomaticVerifications` + `ResolveStepDetectionSpecs`

**Files:**
- Modify: `orchestrator/internal/reporting/detection_validation.go` (add two new exported functions; refactor the `Engine.buildDetectionValidation` method)
- Test: `orchestrator/internal/reporting/detection_validation_test.go`

**Interfaces:**
- Consumes: `VerificationResult.RuleIDs` (Task 1), `StepDetectionSpec{TechniqueID, Expected, Telemetry, ProfileRefs}` (pre-existing), `ScenarioResolver{Get(id string) (*scenario.Scenario, bool); ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)}` (pre-existing), `evidenceByTechnique(results []models.SimulationResult) map[string]StepEvidence` (pre-existing, unexported, same package), `verifyExpectation(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult` (pre-existing, unexported, same package).
- Produces: `reporting.ComputeAutomaticVerifications(specs []StepDetectionSpec, results []models.SimulationResult) []VerificationResult` and `reporting.ResolveStepDetectionSpecs(scenarios ScenarioResolver, scenarioID string) []StepDetectionSpec`. Both consumed by Task 4's `internal/verifysync`.

**Deviation from the spec, noted transparently:** the spec's Component 1
suggested `BuildDetectionValidationWithStore` should be refactored to
*call* `ComputeAutomaticVerifications` instead of its own inline loop.
Reading the full function body shows that loop also builds report rows and
running score aggregates (`covNum`/`covDen`/`domAgg`/`sec.FalseSilence`, …)
in the same pass — forcing it to consume a separately-computed, flat
`[]VerificationResult` would require a fragile order-dependent zip back
onto `specs`/`exp`, risking the byte-identical-report guarantee
`TestBuildDetectionValidationGoldenOutput` exists to protect. Instead,
`ComputeAutomaticVerifications` is a small, independent function with its
own ~6-line loop (a deliberate, minor duplication of iteration structure,
not of verification logic — it still calls the same shared
`verifyExpectation`). `BuildDetectionValidationWithStore` itself is **not
modified** by this task. `ResolveStepDetectionSpecs` **is** a clean,
verified-safe extraction of `buildDetectionValidation`'s spec-assembly
half (see Step 5) and is applied as originally spec'd.

- [ ] **Step 1: Write the failing test for `ComputeAutomaticVerifications`**

Add to `orchestrator/internal/reporting/detection_validation_test.go`:

```go
func TestComputeAutomaticVerifications(t *testing.T) {
	specs := []StepDetectionSpec{
		{
			TechniqueID: "T1055",
			Expected:    []scenario.ExpectedDetection{endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)},
		},
	}
	results := []models.SimulationResult{
		{ID: "T1055", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Defender"}},
	}
	got := ComputeAutomaticVerifications(specs, results)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].ExpectedID != "e1" || got[0].Status != StatusDetected {
		t.Errorf("got[0] = %+v, want ExpectedID=e1 Status=Detected", got[0])
	}
}
```

Note: `models.SimulationResult` has no `AlertProvider` field — the alert
provider lives on the nested `DetectionAlert.Provider`
(`evidenceByTechnique` reads `r.DetectionAlert.Provider` into
`StepEvidence.AlertProvider`); `SimulationResult.ID` is confusingly named
but holds the technique ID string (e.g. `"T1055"`) —
`evidenceByTechnique` reads it as `TechniqueID: r.ID`. Both are already
reflected correctly above.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/reporting/... -run TestComputeAutomaticVerifications -v`
Expected: FAIL — `undefined: ComputeAutomaticVerifications`

- [ ] **Step 3: Implement `ComputeAutomaticVerifications`**

Add to `orchestrator/internal/reporting/detection_validation.go`, immediately after the `StepDetectionSpec` struct definition (after its closing `}`):

```go
// ComputeAutomaticVerifications runs the automatic verification engine over
// every step's expectations for one run and returns the raw, unaggregated
// per-expectation results — the same per-expectation computation
// BuildDetectionValidationWithStore performs internally, exposed here for
// callers (the automatic-verdict-persistence poller, internal/verifysync)
// that need individual verdicts rather than a rendered report section. Kept
// as its own small loop rather than sharing BuildDetectionValidationWithStore's
// larger loop — that loop also builds report rows and running score
// aggregates in the same pass, and forcing a shared call there would risk
// the byte-identical-report guarantee TestBuildDetectionValidationGoldenOutput
// protects.
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

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/reporting/... -run TestComputeAutomaticVerifications -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for `ResolveStepDetectionSpecs`**

Add to `orchestrator/internal/reporting/detection_validation_test.go`:

```go
type fakeScenarioResolver struct {
	scenarios map[string]*scenario.Scenario
	expByStep map[string][]scenario.ExpectedDetection
}

func (f fakeScenarioResolver) Get(id string) (*scenario.Scenario, bool) {
	sc, ok := f.scenarios[id]
	return sc, ok
}

func (f fakeScenarioResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return f.expByStep[step.TechniqueID], nil
}

func TestResolveStepDetectionSpecs(t *testing.T) {
	resolver := fakeScenarioResolver{
		scenarios: map[string]*scenario.Scenario{
			"sc-1": {
				ID: "sc-1",
				Steps: []scenario.Step{
					{TechniqueID: "T1055", Telemetry: []string{"Sysmon EID 1"}},
					{TechniqueID: "T1003"}, // no expectations declared
				},
			},
		},
		expByStep: map[string][]scenario.ExpectedDetection{
			"T1055": {endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)},
		},
	}

	specs := ResolveStepDetectionSpecs(resolver, "sc-1")
	if len(specs) != 1 {
		t.Fatalf("len(specs) = %d, want 1 (step with zero expectations must be excluded)", len(specs))
	}
	if specs[0].TechniqueID != "T1055" || len(specs[0].Expected) != 1 {
		t.Errorf("specs[0] = %+v, want TechniqueID=T1055 with 1 expectation", specs[0])
	}

	if got := ResolveStepDetectionSpecs(resolver, "unknown-scenario"); got != nil {
		t.Errorf("unknown scenario: got %v, want nil", got)
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/reporting/... -run TestResolveStepDetectionSpecs -v`
Expected: FAIL — `undefined: ResolveStepDetectionSpecs`

- [ ] **Step 7: Implement `ResolveStepDetectionSpecs` and refactor `buildDetectionValidation`**

Add to `orchestrator/internal/reporting/detection_validation.go`, immediately after `ComputeAutomaticVerifications`:

```go
// ResolveStepDetectionSpecs resolves a scenario's steps into their detection
// expectations via the given resolver. Returns nil if the scenario is
// unknown or declares no expectations anywhere — callers should treat that
// as nothing to verify, not an error.
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

`Engine.buildDetectionValidation` currently:

```go
func (e *Engine) buildDetectionValidation(ctx context.Context, runID, scenarioID string, results []models.SimulationResult) DetectionValidationSection {
	if e.scenarios == nil || scenarioID == "" {
		return DetectionValidationSection{}
	}
	sc, ok := e.scenarios.Get(scenarioID)
	if !ok {
		return DetectionValidationSection{}
	}
	var specs []StepDetectionSpec
	for _, step := range sc.Steps {
		exp, refs := e.scenarios.ResolveStepExpectations(step)
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
	// Overlay stored attestations (manual SP2 / API SP3). Off-host expectations
	// the automatic engine could only mark Pending become resolved here once an
	// analyst or connector has verified them. Kept read-only: reporting consumes
	// the store, never writes it.
	overrides := e.storedVerifications(ctx, runID)
	return BuildDetectionValidationWithStore(specs, results, overrides)
}
```

Replace the spec-assembly block (this is behaviorally identical: the
original's `!ok` early-return and the new version's nil-specs path both
terminate at `BuildDetectionValidationWithStore`'s own `total == 0` check,
which returns the same zero-value `DetectionValidationSection{}` either
way):

```go
func (e *Engine) buildDetectionValidation(ctx context.Context, runID, scenarioID string, results []models.SimulationResult) DetectionValidationSection {
	if e.scenarios == nil || scenarioID == "" {
		return DetectionValidationSection{}
	}
	specs := ResolveStepDetectionSpecs(e.scenarios, scenarioID)
	// Overlay stored attestations (manual SP2 / API SP3). Off-host expectations
	// the automatic engine could only mark Pending become resolved here once an
	// analyst or connector has verified them. Kept read-only: reporting consumes
	// the store, never writes it.
	overrides := e.storedVerifications(ctx, runID)
	return BuildDetectionValidationWithStore(specs, results, overrides)
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/reporting/... -run TestResolveStepDetectionSpecs -v`
Expected: PASS

- [ ] **Step 9: Run the full reporting suite to confirm no regression**

Run: `go test ./internal/reporting/... -v -count=1`
Expected: 100% PASS, including `TestBuildDetectionValidationGoldenOutput` unchanged

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/detection_validation_test.go
git commit -m "feat(reporting): ComputeAutomaticVerifications + ResolveStepDetectionSpecs extractions"
```

---

### Task 4: `internal/verifysync` package

**Files:**
- Create: `orchestrator/internal/verifysync/job.go`
- Test: `orchestrator/internal/verifysync/job_test.go`
- Modify: `orchestrator/internal/db/postgres.go:1019` (second migration line, adjacent to Task 2's)

**Interfaces:**
- Consumes: `reporting.ScenarioResolver`, `reporting.StepDetectionSpec`, `reporting.VerificationResult` (with `.RuleIDs`, Task 1), `reporting.ResolveStepDetectionSpecs`, `reporting.ComputeAutomaticVerifications`, `reporting.Status{Detected,NotDetected,NotApplicable}` (all Task 3 + pre-existing), `verification.Store{CurrentForRun, Attest}`, `verification.AttestInput` (with `.RuleIDs`, Task 2), `verification.{StateApproved, SourceAutomatic, Result{Detected,NotDetected,NotApplicable}}` (pre-existing), `models.SimulationResult` (pre-existing).
- Produces: `verifysync.NewJob(db *pgxpool.Pool, store *verification.Store, scenarios reporting.ScenarioResolver) *Job`, `(*Job).Tick(ctx context.Context)`. Consumed by Task 5's `main.go` wiring.

- [ ] **Step 1: Add the `auto_verified` migration line**

In `orchestrator/internal/db/postgres.go`, immediately after Task 2's new `rule_ids` line, add:

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS auto_verified boolean NOT NULL DEFAULT false`,
```

- [ ] **Step 2: Write the failing safety-invariant test**

This is the single most important test in this plan — it proves the poller
never overwrites an existing (e.g. human-reviewed) record. Create
`orchestrator/internal/verifysync/job_test.go`:

```go
package verifysync

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/verification"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

type fakeResolver struct {
	sc  *scenario.Scenario
	exp map[string][]scenario.ExpectedDetection
}

func (f fakeResolver) Get(id string) (*scenario.Scenario, bool) {
	if f.sc == nil || f.sc.ID != id {
		return nil, false
	}
	return f.sc, true
}

func (f fakeResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return f.exp[step.TechniqueID], nil
}

func endpointExp(id, provider string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID: id, Provider: provider, Type: scenario.DomainEndpoint,
		Confidence: scenario.ConfidenceRequired,
	}
}

func TestProcessRun_NeverOverwritesExistingRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := verification.NewStore(pool)

		// exp-manual already has a human-reviewed record — must survive untouched.
		if _, err := store.Attest(ctx, verification.AttestInput{
			RunID: "run-1", ExpectationID: "exp-manual", VerifiedBy: "analyst",
			Result: verification.ResultNotDetected, WorkflowState: verification.StateApproved,
			Source: verification.SourceManual,
		}); err != nil {
			t.Fatalf("seed manual attestation: %v", err)
		}

		resolver := fakeResolver{
			sc: &scenario.Scenario{ID: "sc-1", Steps: []scenario.Step{
				{TechniqueID: "T1055"}, {TechniqueID: "T1003"},
			}},
			exp: map[string][]scenario.ExpectedDetection{
				"T1055": {endpointExp("exp-manual", "microsoft_defender")},
				"T1003": {endpointExp("exp-auto", "microsoft_defender")},
			},
		}

		job := NewJob(pool, store, resolver)
		resultsRaw := []byte(`[{"id":"T1055","detectionVerdict":"undetected"},{"id":"T1003","detectionVerdict":"detected","detectionAlert":{"provider":"Microsoft Defender","channel":"c","eventId":1,"confidence":"high"}}]`)
		if err := job.processRun(ctx, "run-1", "sc-1", resultsRaw); err != nil {
			t.Fatalf("processRun: %v", err)
		}

		current, err := store.CurrentForRun(ctx, "run-1")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}

		manual := current["exp-manual"]
		if manual.Source != verification.SourceManual || manual.Result != verification.ResultNotDetected {
			t.Fatalf("exp-manual record was overwritten: %+v, want untouched manual/NotDetected", manual)
		}

		auto := current["exp-auto"]
		if auto.Source != verification.SourceAutomatic || auto.Result != verification.ResultDetected {
			t.Fatalf("exp-auto = %+v, want new automatic/Detected record", auto)
		}
	})
}
```

Check `models.SimulationResult`'s exact JSON field tags (`id`, `detectionVerdict`, `alertProvider` above are best-effort based on this codebase's established `camelCase` JSON convention — confirm against `orchestrator/internal/models/schema.go`'s actual `json:"..."` tags before running this step, and correct the literal JSON above if they differ).

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/verifysync/... -run TestProcessRun_NeverOverwritesExistingRecord -v`
Expected: FAIL — package `verifysync` / `NewJob`/`processRun` undefined

- [ ] **Step 4: Implement `internal/verifysync/job.go`**

```go
// Package verifysync persists automatic (on-host) detection verification
// results into internal/verification's store. Nothing else does this today
// — Store.Attest is otherwise only called by manual analyst review and the
// SP3 API connectors — leaving verification_history empty for the common
// case of a purely-automatic BAS run. See design spec
// docs/superpowers/specs/2026-07-27-automatic-verdict-persistence-design.md.
//
// Safety invariant: this package NEVER supersedes an existing
// verification_history record of any source. It reads
// Store.CurrentForRun before attesting and only fills expectations with no
// active record at all.
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
// BAS runs.
type Job struct {
	db        *pgxpool.Pool
	store     *verification.Store
	scenarios reporting.ScenarioResolver
	batchSize int
}

// NewJob builds a Job. batchSize defaults to 50 (bounds each Tick's DB work
// regardless of how many runs are pending).
func NewJob(db *pgxpool.Pool, store *verification.Store, scenarios reporting.ScenarioResolver) *Job {
	return &Job{db: db, store: store, scenarios: scenarios, batchSize: 50}
}

// Tick processes up to one batch of not-yet-processed runs. Safe to call on
// every scheduler tick regardless of how many runs are pending.
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
		return nil // nothing declared any expectation
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
			RuleIDs:       vr.RuleIDs,
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

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/verifysync/... -run TestProcessRun_NeverOverwritesExistingRecord -v`
Expected: PASS

- [ ] **Step 6: Write and pass the remaining `Tick`/edge-case tests**

Add to `orchestrator/internal/verifysync/job_test.go`:

```go
func TestProcessRun_ZeroExpectations_NoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := verification.NewStore(pool)
		resolver := fakeResolver{sc: &scenario.Scenario{ID: "sc-empty", Steps: []scenario.Step{{TechniqueID: "T9999"}}}}
		job := NewJob(pool, store, resolver)
		if err := job.processRun(context.Background(), "run-empty", "sc-empty", nil); err != nil {
			t.Fatalf("processRun with zero expectations: %v", err)
		}
	})
}

func TestTick_MarksProcessedRunsAutoVerified(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// scenario_runs.agent_id has a NOT NULL FK to agents(agent_id) —
		// seed an agent row first (mirrors internal/pathcorrelation's and
		// internal/exposure's existing test pattern for this exact table).
		if _, err := pool.Exec(ctx,
			`INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			 VALUES ('vs-tick-agent', 'VSHOST01', '10.0.0.5', 'Windows 11', 'idle', 'active', NOW())`); err != nil {
			t.Fatalf("seed agents: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, agent_id, scenario_id, name, status, results, started_at)
			 VALUES ('run-tick-1', 'vs-tick-agent', 'sc-tick', 'n', 'completed', '[]', NOW())`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}
		store := verification.NewStore(pool)
		resolver := fakeResolver{sc: &scenario.Scenario{ID: "sc-tick", Steps: nil}}
		job := NewJob(pool, store, resolver)
		job.Tick(ctx)

		var autoVerified bool
		if err := pool.QueryRow(ctx, `SELECT auto_verified FROM scenario_runs WHERE id='run-tick-1'`).Scan(&autoVerified); err != nil {
			t.Fatalf("query auto_verified: %v", err)
		}
		if !autoVerified {
			t.Fatal("auto_verified = false after Tick, want true")
		}
	})
}
```

- [ ] **Step 7: Run the full verifysync suite**

Run: `go test ./internal/verifysync/... -v -count=1`
Expected: 100% PASS

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/verifysync/job.go orchestrator/internal/verifysync/job_test.go orchestrator/internal/db/postgres.go
git commit -m "feat(verifysync): new poller persisting automatic verdicts into verification.Store"
```

---

### Task 5: Wire `verifysync.Job` into `main.go`

**Files:**
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `verifysync.NewJob` (Task 4), `exercise.NewPollScheduler` (pre-existing, `internal/exercise/scheduler.go`), the existing local `pool *pgxpool.Pool`, `verificationStore := verification.NewStore(pool)` (existing, `main.go:188`), `engine` (existing local `*scenario.Engine`, already passed to `WithScenarios(engine)` at `main.go:204`).

- [ ] **Step 1: Add the import**

In `orchestrator/cmd/server/main.go`'s import block, add:

```go
	"github.com/audspect/bas/internal/verifysync"
```

- [ ] **Step 2: Construct and start the job**

`engine := scenario.NewEngine(cfg.ScenariosDir)` is constructed at
`main.go:140`, before `verificationStore := verification.NewStore(pool)` at
`main.go:188` — both are already in scope by line 188. `"time"`
(`main.go:13`) and `"github.com/audspect/bas/internal/exercise"`
(`main.go:24`) are both already imported. Immediately after line 188, add:

```go
	verifyJob := verifysync.NewJob(pool, verificationStore, engine)
	verifySyncScheduler := exercise.NewPollScheduler(5 * time.Minute)
	verifySyncScheduler.Start(verifyJob.Tick)
```

- [ ] **Step 3: Verify it compiles**

Run (from `orchestrator/`): `go build ./...`
Expected: no errors

- [ ] **Step 4: Run the full affected-package test suite**

Run: `go test ./internal/reporting/... ./internal/verification/... ./internal/verifysync/... ./internal/scenario/... -v -count=1`
Expected: 100% PASS

- [ ] **Step 5: Run `go vet`**

Run: `go vet ./...`
Expected: no output

- [ ] **Step 6: Commit**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(server): wire verifysync.Job into main — automatic verdicts now persisted"
```
