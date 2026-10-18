# DLP Mastery Priority 3: incremental evidence-model extension to `internal/reporting/dlp.go`

## Locked scope (user decision, verbatim intent)

Build now, in `internal/reporting/dlp.go`:
1. **Evidence provenance** — timestamp, evidence source/collection method, correlation ID, where available.
2. **Confidence and limitations** — explain *why* evidence supports, contradicts, or cannot establish the expected outcome.
3. **Synthetic-data manifest linkage** — link each verification to the exact catalogued `dlpfixture` entry actually used. Must be exact; never inferred from the scenario name.

Preserve, don't rebuild: enforcement outcome logic (`dlpComparator`/`dlpVerifier`'s existing Match/Mismatch/MissingEvidence behavior) stays byte-for-byte compatible.

Deferred (do not build): classification outcome, telemetry outcome, response outcome. No speculative empty fields for these.

Hard constraints: don't touch the 10 signed scenario YAML files; keep stored-result/caller backward compatibility (new fields must be additive/optional); don't invent a timestamp or correlation ID when the collector doesn't provide one.

## Architecture finding that shapes this plan

`VerificationResult`/`StepEvidence` are shared across every outcome family (detection, dlp, future ones), built via `evidenceByTechnique(results []models.SimulationResult)` in `detection_validation.go`, which **collapses evidence by `TechniqueID`** — not by step. Many DLP scenarios have multiple distinct fixture-bearing steps sharing one `technique_id` (e.g. `dlp-exfiltration-cloud-storage.yaml` has 11 steps across one technique, each with a different fixture). `StepDetectionSpec`/`ComputeAutomaticVerifications` only carry `TechniqueID`, not step identity or scenario ID — no scenario ID is threaded into this pipeline at all today.

Consequence: exact `(ScenarioID, StepName)` lookup (what `dlpfixture.Occurrence` uses) is **not available** without changing the spec-building pipeline outside `dlp.go` — out of scope for this increment.

**Resolution (builder's call):** `models.SimulationResult.StepName` already carries the exact, real per-step name (same literal text used as `dlpfixture.Occurrence.StepName`), and it already travels alongside every other per-step field (`RawOutput`, `SinkTokenObserved`) through the existing collapse in `evidenceByTechnique` — adding `StepName` to `StepEvidence` is a one-field, zero-behavior-change addition; whichever step's record wins the technique-level collapse, its `StepName` is carried with it, consistently with its other fields. Fixture lookup then keys on `StepName` alone (not `(ScenarioID, StepName)`), via a new `dlpfixture.FixtureIDForStep(stepName string) (id string, ok bool)` that returns `ok=false` if zero or *more than one* fixture claims that exact step name (ambiguity-safe: today no two different fixtures share a literal step name, verified by inspecting `catalog.go`, but the function must stay safe if that ever changes). This satisfies "must be exact... never inferred from the scenario name" — it's an exact literal match on the step's own real name, never a guess from the scenario's identity.

`CorrelationID`: no part of today's pipeline threads a real correlation token (e.g. the sink-service's actual token value) into `StepEvidence` — only a derived boolean (`SinkTokenObserved`). Threading the real token through would mean touching `models.SimulationResult`, the sink-receipt pipeline, and every call site — well outside "incremental extension to `dlp.go`". Per the user's own rule 2 ("represent as unavailable rather than inventing one"), `CorrelationID` stays empty in this increment. The field exists now so a later, real correlation-ID plumbing change populates it without another struct change.

## Design

### `orchestrator/internal/dlpfixture/lookup.go` (new, small addition to the already-merged package)

```go
// FixtureIDForStep returns the catalog Fixture.ID whose Occurrences contain
// exactly this stepName, and true if the match is unambiguous. Zero matches,
// or a stepName claimed by more than one different fixture, return ("", false)
// -- callers must treat that as "no stable fixture reference available", never
// guess. This is an exact match against a real step's own name, never an
// inference from a scenario's ID or description.
func FixtureIDForStep(stepName string) (string, bool)
```

Unit tests: exact known step name resolves; unknown step name returns false; (synthetic) ambiguous case across two fixtures returns false.

### `orchestrator/internal/reporting/detection_validation.go` (minimal additive touch)

- `StepEvidence` gains one field: `StepName string` (doc comment: carried from `models.SimulationResult.StepName`, same collapse-by-technique caveats as every other field here).
- `evidenceByTechnique` populates it from `r.StepName` alongside the existing fields it already copies.
- `VerificationResult` gains one new optional field: `DLPEvidence *DLPEvidence` (nil for every verifier except `dlpVerifier`). Doc comment states it's nil outside the "dlp" family.

### `orchestrator/internal/reporting/dlp.go` (the bulk of the change)

```go
// DLPEvidence carries the three evidence-model dimensions Audspect can
// honestly populate today without a vendor connector or new telemetry
// correlation -- see dlp.txt §6 and docs/superpowers/plans/2026-10-18-dlpevidence.md.
// Classification/telemetry/response outcomes are deliberately absent, not
// empty placeholders -- they require evidence sources that don't exist yet.
type DLPEvidence struct {
    CollectionMethod string // "sink-receipt" | "local-marker" | "" (no usable observation)
    CorrelationID    string // always "" today -- see this file's design notes; present for forward compatibility
    FixtureID        string // dlpfixture.Fixture.ID, exact match only; "" if unresolved
    Limitations      string // always populated: what this verdict's evidence does/doesn't establish
}
```

`dlpVerifier.Verify` builds one `DLPEvidence` per call (including on the skip-marker early-return path, where `CollectionMethod=""`, `FixtureID` still resolved from `ev.StepName` if available, `Limitations` explains the skip) and sets `r.DLPEvidence = &ev`.

`limitationsFor(expected, observed string, comparison ComparisonResult) string` — a small pure function, one branch per case already enumerated in the design conversation:
- `Match`: states plainly that the observation matches the expected outcome.
- `Mismatch` with `observed=Blocked`: "operation was blocked even though <expected> was expected" (confirmed deviation, per `dlpComparator`'s own asymmetry doc).
- `Mismatch` with `observed=Succeeded, expected=Block`: confirmed enforcement failure.
- `MissingEvidence` with `observed=Unknown`: no usable observation collected; not evidence either way.
- `MissingEvidence` with `observed=Succeeded`, expected a softer outcome (Warn/Justify/Audit/Quarantine/Encrypt/Redact): the exact "script completion is not evidence that the DLP warning appeared" case from the user's own example — generalized to name whichever soft outcome was actually expected.

### Tests (`dlp_test.go` additions, `lookup_test.go` new)

Per the user's explicit list:
- Missing provenance (no sink token, no marker, skip path) → `CollectionMethod=""`, `CorrelationID=""`.
- Unknown outcome → `Limitations` names it as non-conclusive, not a failure.
- Absent fixture reference (step name not in catalog, or evidence carries no step name) → `FixtureID=""`, no panic, no guess.
- Backward compatibility: existing `dlpComparator`/`dlpVerifier` test cases (Match/Mismatch/MissingEvidence outcomes) still produce identical `Comparison`/`Status`/`ObservedOutcome`/`ExpectedOutcome` — run the existing `dlp_test.go` suite unmodified and green throughout; a JSON round-trip test confirming a result with `DLPEvidence=nil` (old stored shape) still deserializes and a new one with it set serializes with `omitempty` so old consumers ignore it.
- A real end-to-end case using an actual `dlpfixture` entry (e.g. the Visa Card Record step) confirming `FixtureID` resolves to `"visa-card-record"` from a `StepEvidence{StepName: "...Visa Card Record..."}`.

## Tasks (TDD, one commit each)

1. `dlpfixture.FixtureIDForStep` + tests (RED→GREEN).
2. `StepEvidence.StepName` + `evidenceByTechnique` population + `VerificationResult.DLPEvidence` field (additive, no test changes needed yet beyond confirming existing suite stays green).
3. `DLPEvidence` struct + `limitationsFor` + wiring into `dlpVerifier.Verify` (all paths: skip, sink-receipt, local-marker, unknown) + full test list above.

## Review focus for final review

- Confirm `dlpComparator`'s existing Match/Mismatch/MissingEvidence truth table is byte-for-byte unchanged (diff `dlp_test.go`'s pre-existing cases).
- Confirm no invented timestamp/correlation ID anywhere — grep for `time.Now()` / literal correlation values in the new code.
- Confirm `FixtureIDForStep` truly requires an exact, unambiguous step-name match (test the ambiguous-match-returns-false case actually fails closed).
- Confirm `VerificationResult.DLPEvidence` is nil for every non-dlp verifier path (automatic/manual/api verifiers for the "detection" family untouched).
- Confirm JSON `omitempty` on the new fields so existing stored results / report consumers are unaffected.
