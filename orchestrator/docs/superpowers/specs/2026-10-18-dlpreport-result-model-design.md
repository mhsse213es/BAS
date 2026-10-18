# dlpreport Unified Result Model — Design Spec

## Intent

Closes `dlp.txt` §6 ("Audspect's result model: what customers should actually receive"):

> Every execution should produce a structured, independently reviewable evidence record... Use separate dimensions instead of collapsing everything into one green/red status.

§6 names 12 required fields (Scenario ID and version, Control objective, Preconditions, Synthetic data manifest, Action attempted, Enforcement outcome, Classification outcome, Telemetry outcome, Response outcome, Evidence provenance, Confidence and limitations) and, for 4 of them, an explicit closed vocabulary:

- Enforcement outcome: Allowed, blocked, quarantined, encrypted, challenged, overridden or unknown.
- Classification outcome: Correct, incorrect, not evaluated, unsupported or unknown.
- Telemetry outcome: Event absent, present, delayed, incomplete or unverifiable.
- Response outcome: Alert, case, escalation and remediation state.

## Why this is a new package, not an addition to `internal/reporting` or `internal/dlpcorrelate`

`internal/reporting/dlp.go`'s `DLPEvidence` already carries 3 of §6's dimensions honestly (provenance-adjacent fields, `Limitations`) but is explicitly scoped to what the LIVE `dlpVerifier` can populate during verification — its own doc comment says "Classification/telemetry/response outcomes are deliberately absent... they require evidence sources that don't exist yet." `internal/dlpcorrelate`'s 6 campaigns are each scoped to one specific `dlp.txt` §3C scenario's own stage structure, not a general-purpose record shape. §6 asks for something neither provides: ONE universal record shape any scenario (DLP or otherwise structured this way) could be rendered into, independent of which campaign or evaluator produced it. A new package, `internal/dlpreport`, holds this shape without coupling `reporting` or `dlpcorrelate` to it.

## Why this slice defines the types and ONE safe translation helper, not a full translation layer for every dimension

A naive design would add `EnforcementOutcomeFromComparison(reporting.ComparisonResult) EnforcementOutcome` alongside the Classification helper. This was considered and rejected: `reporting.ComparisonResult` (Match/Mismatch/MissingEvidence/NotApplicable/Unknown) tells you whether the observed outcome matched what was EXPECTED — the same `ComparisonResult` value (e.g. `Match`) can correspond to a genuinely different real-world enforcement outcome depending on what was expected (`Match` on an expected `Block` means the action was blocked; `Match` on an expected `Allow` means the action succeeded). Deriving `EnforcementOutcome` honestly requires the expected value, the observed primitive, AND override evidence together — exactly the asymmetric logic `internal/reporting/dlp.go`'s `dlpComparator` already encodes carefully (an observed block is conclusive regardless of expectation; an observed bare "succeeded" is only conclusive against Allow/Block, never against the softer catalog values Warn/Justify/Audit/Quarantine/Encrypt/Redact). Re-deriving this in a second place risks silently drifting from `dlpComparator`'s own careful, already-reviewed judgment calls. This slice therefore leaves `Enforcement`/`Telemetry`/`Response` as fields the CALLER sets directly from whatever already-computed judgment they have — the exact "decoupled consumption" discipline every `dlpcorrelate` campaign in this initiative already follows (never re-deriving a live evaluator's logic, only consuming its already-computed verdict). `Classification` gets a helper because `dlpclassify.DLPCLSOutcome`→`ClassificationOutcome` is a genuine, unambiguous, non-lossy-in-any-relevant-way coarsening (TruePositive/TrueNegative both mean "classified correctly," with no missing context the way Enforcement's case has).

## Goals

1. `internal/dlpreport` package with:
   - `EnforcementOutcome`, `ClassificationOutcome`, `TelemetryOutcome`, `ResponseOutcome` — 4 string-based enums with exactly the constant vocabularies §6 names (quoted above).
   - `EvidenceProvenance` struct: `Timestamp time.Time`, `SourceSystem string`, `CorrelationID string`, `IntegrityHash string`, `CollectionMethod string`.
   - `Record` struct with all 12 §6 fields: `ScenarioID`, `ScenarioVersion`, `ControlObjective`, `Preconditions`, `SyntheticDataManifest`, `ActionAttempted` (all `string`), `Enforcement EnforcementOutcome`, `Classification ClassificationOutcome`, `Telemetry TelemetryOutcome`, `Response ResponseOutcome`, `Provenance EvidenceProvenance`, `Confidence string`, `Limitations string`.
   - `ClassificationOutcomeFromDLPCLS(dlpclassify.DLPCLSOutcome) ClassificationOutcome` — `OutcomeTruePositive`/`OutcomeTrueNegative` → `ClassificationCorrect`; `OutcomeFalsePositive`/`OutcomeFalseNegative`/`OutcomeMisclassified` → `ClassificationIncorrect`; `OutcomeUnsupported` → `ClassificationUnsupported`; `OutcomeNotTested`/`OutcomeInconclusive` → `ClassificationNotEvaluated`; the 5 label-lifecycle outcomes (`OutcomeLabel*`) and any unrecognized value → `ClassificationUnknown` (never silently defaulted to Correct).
   - `(Record) Validate() error` — returns an error when `Limitations` is empty AND at least one of `Enforcement`/`Classification`/`Telemetry`/`Response` is one of its own "uncertain" values (`EnforcementUnknown`, `ClassificationUnknown`/`ClassificationNotEvaluated`, `TelemetryUnverifiable`, `ResponseNotTested`) — mirrors `DLPEvidence.Limitations`'s own existing discipline ("Always populated") at the level of this new unified type, a self-consistency check on `Record` itself, not a re-derivation of any other package's logic.

## Non-goals

- No `EnforcementOutcomeFromComparison`/`TelemetryOutcomeFromX`/`ResponseOutcomeFromX` helper — see the dedicated section above. Building these honestly requires either reusing `dlpComparator`'s own internal logic (not currently exported) or re-deriving it, and is left to a future slice that can make that call deliberately, not as a side effect of defining the record shape.
- No wiring into the real run/report pipeline — this slice defines the type only.
- No change to `internal/reporting/dlp.go`, `internal/dlpclassify`, or `internal/dlpcorrelate` — `dlpreport` imports `dlpclassify` for one type-only translation helper and nothing else.
- No persistence/serialization concerns (DB schema, JSON tags) — out of scope; `Record` is a plain Go value type for this slice.

## Anti-goals

- Must not fabricate an `Enforcement`/`Telemetry`/`Response` value from thin evidence — these 3 fields are always caller-supplied, never computed inside this package from a lossy heuristic.
- Must not duplicate `dlpComparator`'s asymmetric Allow/Block-is-conclusive-but-softer-outcomes-are-not judgment under a new name.
- `Validate()` must never be used to silently fix up a `Record` (e.g., auto-filling `Limitations`) — it only reports a defect, it doesn't correct one.

## What's left to the builder

- Exact constant string values for each enum (must match §6's wording closely enough to be recognizable in a customer-facing report, but Go identifier/constant naming is the builder's call).
- Exact `Validate()` error message text.
