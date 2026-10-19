# dlpreport Pipeline Integration — Phase 1 Audit and Plan

Status: PLAN, pending review. No code written yet.

## 1. Real call graph (verified by reading the code, 2026-10-19)

Execution and results:

1. A scenario step runs. Its result is a `models.SimulationResult` with `ID` (technique), `StepName` (set from `step.Name` in `internal/scenario/interpreter.go:115`), `RawOutput`, `DetectionVerdict`, `Channel`, override/connectivity fields, and `SinkTokenObserved`.
2. `scenario_runs.results` stores the JSON array of those results. It is the persisted source of truth for a run.

Evaluation (live, per report build):

3. `Engine.BuildFromRun` (`internal/reporting/engine.go:1900`) reads `scenario_runs.results` from Postgres, then calls `buildDetectionValidation` (`engine.go:1995`).
4. `buildDetectionValidation` resolves specs with `ResolveStepDetectionSpecs` (one `StepDetectionSpec` per step that declares expectations) and calls `BuildDetectionValidationWithStore` (`detection_validation.go:496`).
5. That function calls `evidenceByTechnique(results)` (`detection_validation.go:672`), which keys evidence by technique ID, then calls `verifyExpectation` per expectation.
6. `verifyExpectation` dispatches DLP expectations (`ResolveOutcomeFamily == "dlp"`) to `dlpVerifier.Verify` (`dlp.go:153`). That verifier produces `VerificationResult` with `Comparison`, `Status`, `ObservedOutcome`, and `DLPEvidence` (`CollectionMethod`, `Limitations`, `FixtureID`, `Channel`, `Override`, `Connectivity`).
7. `BuildDetectionValidationWithStore` copies only selected fields into `ExpectationRow` (`detection_validation.go:534`). **`DLPEvidence` is dropped here.** `ExpectationRow` has no DLP fields.

Persistence (automatic verdicts only):

8. `internal/verifysync/job.go` polls runs, calls `ComputeAutomaticVerifications`, then `mapStatusToResult` and `store.Attest`. It persists `Result` (Detected/NotDetected) and nothing else. `MissingEvidence` maps to Unknown and is never attested. `DLPEvidence` is dropped.

There is no persisted full report. `FullReport` is built on demand from `scenario_runs.results`.

## 2. Findings that constrain the design

**F1. Evidence is keyed by technique, not by step.** `evidenceByTechnique` returns one `StepEvidence` per technique ID. The DLP scenario `scenarios/dlp-exfiltration-db-export.yaml` has steps 2 and 3 both using `T1567.002`. Both expectations therefore receive the same evidence: the same `Channel`, `FixtureID`, `SinkTokenObserved`, and `RawOutput`. This is a pre-existing misattribution in the live report and in `verifysync`'s persisted verdicts. It is not caused by the new record. A correct per-step record cannot exist until this is fixed for DLP steps.

**F2. Step identity exists in persisted results.** `SimulationResult.StepName` is persisted in `scenario_runs.results`, and it equals the scenario step `name`. `StepDetectionSpec` has no `StepName` today, so the spec side needs one added.

**F3. `VerificationResult.Timestamp` is verification time, not evidence time.** `baseResult` sets `time.Now()`. The record must not use it as provenance. Evidence time is not captured anywhere, so `Provenance.Timestamp` stays zero and this is listed as unavailable.

**F4. No correlation ID and no integrity hash exist for DLP evidence.** `DLPEvidence.CorrelationID` is always empty by design. The record reports these as unavailable.

**F5. Classification and telemetry verdicts do not exist for DLP channel steps.** A channel step runs an operation and observes enforcement. It does not classify, and no SIEM telemetry is correlated to it in this path. These dimensions are reported honestly as NotEvaluated and Unverifiable, never as Correct or Absent.

## 3. Decisions

**D1. Measurement unit: one record per expectation, which for DLP is one per step.** It is a per-channel enforcement result for one controlled operation. It is not a per-sample classification and not a scenario-level aggregate. Scenario-level roll-ups are out of this slice.

**D2. Derivation, not persistence.** Records are built during the report build from the same `VerificationResult` values, and they are deterministic functions of the persisted `scenario_runs.results`. Retries and repeated report builds therefore produce identical records, not duplicates. No new table and no migration are added in this slice. Persisting records would require a schema decision that is out of scope here, and the verdict store has no evidence columns today.

**D3. Correlation key.** A record is correlated by `(run_id, scenario_id, step_name)`. Technique ID alone is not a valid key (F1). Channel and collection method are carried as attributes, not used as keys.

**D4. Step-keyed evidence for DLP expectations only.** `StepDetectionSpec` gains `StepName`, populated from `step.Name` in `ResolveStepDetectionSpecs`. `BuildDetectionValidationWithStore` builds a step-keyed evidence map alongside the technique map. For DLP-family expectations it uses the step-keyed evidence, falling back to the technique map only when the step name is empty. Non-DLP expectations keep today's behavior exactly.
- This corrects existing DLP report rows for shared-technique steps. The change is intentional and must be called out in the review and the QA log.
- The fallback case is marked in the record's limitations ("step identity unavailable; evidence matched by technique").
- Historical `verifysync` verdicts already persisted for shared-technique DLP runs stay misattributed. This is listed as an open item and is not fixed here.

**D5. Enforcement mapping is conditioned on the comparator, not a second copy of its rules.**
- `Blocked` if `ObservedOutcome == OperationBlocked`.
- `Overridden` if `DLPEvidence.Override.Occurred` (checked before Blocked and Allowed, so an override is never reported as a clean block or allow).
- `Allowed` if `ObservedOutcome == OperationSucceeded` and `Comparison` is `Match` or `Mismatch`.
- `Unknown` otherwise (MissingEvidence, NotTested, skip). The `Limitations` text carries the explanation.
- The mapping never returns `Allowed` for a MissingEvidence comparison, so a softer-outcome success is not overclaimed.

**D6. Classification, telemetry, response.** Classification is `NotEvaluated` with the limitation "no classification verdict for a channel step". Telemetry is `Unverifiable` with the limitation "no SIEM/console telemetry is correlated to this step". Response is `NotTested`. Because the enforcement and telemetry values are uncertain, `Validate()` requires `Limitations` to be non-empty, and that is what the DLPEvidence limitation text supplies.

**D7. Provenance.** `SourceSystem` is `local-dlp-sink` when `CollectionMethod == "sink-receipt"`, and `local-observer` when `"local-marker"`. It is empty otherwise. It is never a vendor name, because the channel is our own sink, not a vendor console. `CorrelationID` and `IntegrityHash` are empty. `CollectionMethod` is copied from `DLPEvidence`.

**D8. Missing results.** If a spec's step name has no matching result, the record is still emitted with Enforcement `Unknown` and the limitation "no result recorded for this step". A spec is never silently dropped.

**D9. Backward compatibility.** `DetectionValidationSection` gains `DLPRecords []dlpreport.Record` with `json:"dlpRecords,omitempty"`. Reports with no DLP steps omit the key entirely, so their JSON is byte-identical. `ExpectationRow` is unchanged.

**D10. Import direction.** `internal/reporting` imports `internal/dlpreport`. `dlpreport` imports only `dlpclassify`, and neither imports `reporting`, so there is no cycle. This is checked during implementation.

## 4. Files

- `orchestrator/internal/reporting/detection_validation.go`: `StepDetectionSpec.StepName`, `ResolveStepDetectionSpecs` populating it, step-keyed evidence for DLP expectations, `DLPRecords` on `DetectionValidationSection`, and collecting records in `BuildDetectionValidationWithStore`.
- `orchestrator/internal/reporting/dlp_record.go` (new): `dlpRecordFor(exp, vr, ev, stepName, fallback) dlpreport.Record`, the D5–D8 mapping.
- `orchestrator/internal/reporting/dlp_record_test.go` (new): unit tests for the mapping.
- `orchestrator/internal/reporting/detection_validation_pipeline_test.go` (new): the seam test (see §5).
- `orchestrator/internal/verifysync/job.go`: no change in this slice.
- `orchestrator/internal/dlpreport/`: no change.

## 5. Tests

Pipeline seam (required by the brief, not a unit-only test). Call `BuildDetectionValidationWithStore` with real `ResolveStepDetectionSpecs` output for `dlp-exfiltration-db-export` and real `SimulationResult` values for steps 2 and 3, which share `T1567.002`. Assert:
- Two records are emitted, one per step.
- Step 2's record has its own channel and fixture, and step 3's has its own. Neither gets the other's evidence. This is the F1 regression test.
- Enforcement, provenance, and limitations are populated from `DLPEvidence`.

Mapping (unit):
- Match with an observed block gives Blocked.
- Mismatch with an observed success gives Allowed.
- Success against a softer expected outcome gives Unknown, not Allowed.
- Override occurred gives Overridden, even when the observation was a success.
- Skipped step gives Unknown, with limitation text "did not run".
- Spec with no matching result gives Unknown, with limitation "no result recorded".
- `Validate()` passes on every emitted record.

Compatibility:
- A report with no DLP expectations has no `dlpRecords` key in its JSON.
- Existing `detection_validation_test.go` passes unchanged. That run proves the non-DLP path is untouched.

Honesty:
- No emitted record has a vendor `SourceSystem`.
- No record has a non-zero `Provenance.Timestamp`.
- No record has a non-empty `CorrelationID` or `IntegrityHash`.

## 6. Risks

- The F1 correction changes existing DLP report numbers for shared-technique steps. The before and after values must be recorded in the QA log.
- `verifysync` persisted verdicts for historical shared-technique runs remain wrong. A decision is needed on whether to re-verify them.
- Non-DLP scenarios that share techniques across steps have the same F1 defect. This slice does not fix it.

## 7. Open decisions for the reviewer

1. Is scoping the F1 fix to DLP steps the right boundary, or should it be fixed for all families in this slice?
2. Is "derive on report build, no persistence" acceptable for this slice, given the brief asked for persistence?
3. Should historical `verifysync` verdicts for shared-technique DLP runs be re-verified, or only flagged?
