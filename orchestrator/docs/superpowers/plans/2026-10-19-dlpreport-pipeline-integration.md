# dlpreport pipeline integration — revised plan

**Goal:** persist one `dlpreport.Record` per DLP expectation that the real
verification pipeline actually evaluated, with no duplicates on retry and no
change to any existing verdict, record or report.

**Real call graph (verified in code):**
`scenario_runs.results` -> `verifysync.Job.Tick` -> `processRun` ->
`reporting.ComputeAutomaticVerifications` -> `dlpVerifier.Verify` ->
`VerificationResult{DLPEvidence}` -> `store.Attest` (status only).
`DLPEvidence` is produced and then dropped at the Attest boundary, so today
the DLP detail (observed outcome, collection method, limitations, override)
is never persisted anywhere. This slice keeps it.

## Decisions (ruled, with cost if wrong)

1. **Keying is by step TaskID, never technique.** Records come from
   `VerificationResult`s that already carry the TaskID-keyed evidence from the
   lookup fix (`ef6ada21`). Cost if wrong: records would collapse like verdicts did.
2. **Enforcement is derived only from evaluated results, with precedence:**
   - Override occurred -> `Overridden` (first, always).
   - Skipped / `ObservationUnknown` -> `Unknown`.
   - `OperationBlocked` -> `Blocked` (self-reported marker; limitation says so).
   - `OperationSucceeded` + `sink-receipt` -> `Allowed` (destination-side ground truth).
   - `OperationSucceeded` + `local-marker` -> `Unknown`, never `Allowed`
     (a self-reported success is not proof the data left).
   - `Quarantined` / `Encrypted` / `Challenged`: no source vocabulary exists, so never emitted. Cost if wrong: under-reporting those outcomes.
3. **Classification is `NotEvaluated`** for this path. A policy-outcome
   match is not a classification-accuracy measurement, so mapping
   Match->Correct would overclaim. Cost if wrong: the Classification column
   stays empty for DLP until a real classification evaluator is wired.
4. **The comparison is kept verbatim** in a wrapper next to the Record
   (`Comparison`: Match / Mismatch / MissingEvidence, plus `ExpectedOutcome`,
   `Status`). That preserves the Incorrect / MissingEvidence / other
   distinction without bending any Record dimension to carry it.
5. **Telemetry = `Unverifiable`, Response = `NotTested`.** This path
   correlates no SIEM or ticket evidence; claiming otherwise would be false.
6. **Persistence: new table `dlp_evidence_records`**, PK `(run_id,
   expectation_id)`, insert `ON CONFLICT DO NOTHING`. First write wins,
   matching the verdict store's never-supersede rule. Cost if wrong: a
   late sink receipt that arrives after the first pass leaves the record at
   Unknown until a new run. This is accepted and stated in Limitations.
7. **Written before attestation in `processRun`.** A failure returns an error
   and the run stays `auto_verified=false`; the retry re-inserts only missing
   rows (PK), so no duplicates and no partial-record drift on retry.
8. **Non-DLP verdicts write nothing.** Legacy verdicts, store rows and
   report output are unchanged.
9. **Record.JSON tags added** (additive; Record had none and nothing
   serialised it).

## Out of scope (explicit)
- No §7 metrics, precision, recall, latency or operational-impact numbers.
- No report/UI rendering of records. Storage only.
- No live vendor claims: fixtures and local markers are labelled as such.
- ScenarioVersion left empty: no content version is threaded to this path today.

## Tests
- Pure mapping table tests (every enforcement precedence branch, classification
  NotEvaluated, Validate passes, limitations non-empty when uncertain).
- Pipeline seam: seed `scenario_runs` with real results JSON and call `Tick`
  (the real entry point). Assert: DLP expectation -> exactly one record with the
  expected enforcement; non-DLP expectation -> no record.
- Idempotency/retry: run `processRun` twice on the same run -> still one row.
- Skip path: skipped DLP step -> Unknown record, comparison MissingEvidence, status NotTested.
- Not covered: a true mid-write persistence failure. Only the idempotent-retry
  path is exercised; that gap is stated, not hidden.
