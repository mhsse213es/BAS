# dlpcorrelate (Cross-Channel Campaign Correlation) — Design

## Intent and why

`dlp.txt` §3C names 6 "cross-channel and multi-stage" campaigns as what
"distinguish Audspect from a collection of isolated policy checks" — each
one chains several independently-verifiable steps (classify → label →
attempt disclosure → verify enforcement → verify security event/case
evidence) and explicitly says the result must never collapse into one
green/red status (§6) and must never let a later stage's success erase an
earlier stage's real failure ("Prevents a misleading maturity score based
solely on aggressive blocking," §3C Campaign 06's own framing; this is the
same "non-offsetting" principle `av.txt` names for AV multi-stage chains).

Repo audit (2026-10-18) found the exact architecture already proven, in a
different domain: `internal/avefficacy/multistage.go`'s
`MultiStageScenario`/`EvaluateMultiStageScenario` — ordered stages, each
independently evaluated, the chain stops advancing the moment a stage is
blocked or inconclusive (later stages are reported `StageSkipped`, never
silently omitted), and a real failure at one stage is never hidden by a
later stage's pass. That package is itself coupled to `avcatalog.Vector`/
`avval` (AV-domain types) and cannot be imported here, but its *pattern* —
not its domain model — is exactly what DLP's cross-channel campaigns need,
generalized to accept stage verdicts from whichever DLP evaluator each
stage actually uses (DLP-CLS for classification, the label-lifecycle
evaluator for document-workflow persistence, DLP-ENF/channel sinks for
enforcement, and — honestly — nothing yet for telemetry/case-evidence
stages, since no DLP-specific SIEM/case-correlation evaluator exists in
this repo).

## Goals

1. A new standalone package, `internal/dlpcorrelate`, with an
   evaluator-agnostic ordered-stage chain core: `StageResult` (a stage's
   outcome in a currency every DLP evaluator's verdict can be translated
   into, by the caller, not by this package), `CorrelationChain` (an
   ordered list of stage definitions), `EvaluateCorrelationChain`
   (applies the chain-stop/non-offsetting rule, mirroring
   `avefficacy.EvaluateMultiStageScenario`'s own logic exactly, generalized
   away from AV-specific types).
2. One real, concrete campaign definition — `dlp.txt`'s own Campaign 01
   ("Sensitive record to external disclosure") — built end-to-end against
   already-existing evaluators: Stage 1 classification via
   `dlpclassify.VerifyClassificationSample`, Stage 2 document-workflow
   persistence via `dlpclassify.VerifyLabelExpectation` (the label
   lifecycle evaluator already answers "did the data's classification
   survive moving through a workflow," which is exactly Campaign 01's own
   Stage 2 question), Stage 3 unauthorized-external-share enforcement via
   the already-live `internal/reporting` DLP comparator's outcome
   (translated into a `StageResult` by the campaign's own code, not a new
   abstraction).
3. Stage 4 ("verify the security event and case evidence") is included in
   Campaign 01's definition but is honestly, permanently `StageNotTested`
   today — no DLP-specific telemetry/case-correlation evaluator exists
   anywhere in this repo (confirmed by audit: dlp.txt §6's unified
   enforcement/classification/telemetry/response result model and §7's
   detection-and-investigation metrics are both still-open gaps named in
   `[[project_dlp_mastery_initiative]]`/the DLP Mastery backlog). This
   package does not invent telemetry evidence to make Stage 4 look
   complete.

## Non-goals

- Campaigns 02-06 are not built in this slice. Each one needs either
  infrastructure this repo doesn't have yet (Campaign 05's SIEM
  ingestion/incident-creation measurement; Campaign 04's identity+data+
  channel correlation needs an actual departing-employee identity
  fixture, not yet modeled anywhere) or is a straightforward re-application
  of this same `dlpcorrelate` core with a different stage sequence
  (Campaigns 02, 03, 06) that is deliberately left to a follow-on slice
  rather than bundled here, to keep this slice reviewable and to prove
  the generic core against one real worked example before reusing it 5
  more times.
- No new DLP-POL/DLP-CLS/DLP-ENF logic. This package only sequences and
  aggregates pre-computed verdicts from those already-built evaluators;
  it never re-implements or second-guesses their own Verify logic.
- No SIEM/ticketing/case-management integration. Stage 4 stays
  `StageNotTested` until that capability exists elsewhere in the repo.

## Anti-goals

- Must not silently drop Stage 4 from Campaign 01's definition to make
  the campaign "complete" — the whole point of a 4-stage chain with an
  honestly-unbuildable 4th stage is that the gap is visible in the
  result, not edited out of the campaign.
- Must not let Stage 3 catching the disclosure (a real block) retroactively
  excuse Stage 1/2 misclassifying or mislabeling the data — each stage's
  own outcome is preserved in `EvaluateCorrelationChain`'s result list
  even after the chain stops, exactly like `avefficacy`'s own
  `StageSkipped` discipline (a skipped stage is recorded as skipped, not
  as passing).
- Must not import `avefficacy`, `avcatalog`, or `avval` — the precedent is
  borrowed as a pattern, never as a dependency (a different domain's
  types must not leak into DLP's own evidence model).

## Builder's call

```go
package dlpcorrelate

// StageOutcome is the one currency every DLP evaluator's own verdict is
// translated into by the campaign definition's own code (never by this
// package, which has no DLP-domain knowledge of its own).
type StageOutcome string

const (
	StageContinues    StageOutcome = "continues"     // this stage's own check passed or let the data keep moving (e.g. correct classification, no unauthorized block exercised yet) -- chain advances
	StageCaught       StageOutcome = "caught"         // this stage caught/blocked the violation -- chain stops advancing here, same as avefficacy's FindingVerifiedProtection
	StageFailed       StageOutcome = "failed"         // this stage's own check is a confirmed failure (e.g. misclassification, unauthorized disclosure succeeded) -- recorded, chain still advances per the non-offsetting rule (a failure here must not be hidden, but it also must not synthetically stop a chain whose real behavior was to let the data through)
	StageInconclusive StageOutcome = "inconclusive"   // missing evidence -- chain stops advancing, same as avefficacy's inconclusive handling
	StageNotTested    StageOutcome = "not_tested"     // no evaluator capability exists for this stage at all (distinct from Inconclusive: this is "we cannot test this today," not "we tried and the evidence was missing") -- chain stops advancing
)

// StageResult is one stage's outcome, evidence reason, and position.
type StageResult struct {
	StageOrder    int
	Label         string
	Dimension     string // which evaluator produced this: "DLP-CLS" | "DLP-CLS-LABEL" | "DLP-ENF" | "" (not_tested)
	Outcome       StageOutcome
	Reason        string
	StageSkipped  bool // true when the chain stopped before this stage was reached
}

// StageDefinition names a stage before it has a result -- used to build
// the "skipped" placeholder for every stage after the chain stops.
type StageDefinition struct {
	Label     string
	Dimension string
}

// CorrelationChain is an ordered, named campaign -- dlp.txt §3C's own
// campaign definitions become one CorrelationChain each, with a fixed
// Stages list and the caller supplying one evaluated StageResult per
// reachable stage.
type CorrelationChain struct {
	ID     string
	Name   string
	Stages []StageDefinition
}

// ChainResult is the aggregate, non-offsetting verdict for one evaluated
// chain run.
type ChainResult struct {
	ChainID        string
	StageResults   []StageResult
	AnyFailed      bool // true if ANY stage (reached or not) resolved StageFailed -- never cleared by a later stage
	AnyNotTested   bool
	StoppedAtLabel string // empty if the chain ran to completion
}

// EvaluateCorrelationChain takes a chain definition and the caller's own
// pre-computed results for each stage IT WAS ABLE TO REACH (results may be
// shorter than chain.Stages -- this function fills in StageSkipped
// placeholders for the rest), applies the chain-stop/non-offsetting rule
// (mirrors avefficacy.EvaluateMultiStageScenario's own logic, generalized
// away from AV-specific types), and returns the aggregate.
func EvaluateCorrelationChain(chain CorrelationChain, reached []StageResult) (ChainResult, error)
```

**Chain-stop semantics** (the one piece of real logic in this package):
`StageContinues` and `StageFailed` both let the chain advance (a failure
is recorded, never erases prior/later stages, and does NOT stop the
chain — the data kept moving, so later stages are still meaningful to
evaluate). `StageCaught`, `StageInconclusive`, and `StageNotTested` all
stop the chain — every stage after the stopping one gets a
`StageSkipped: true` placeholder with `Reason` naming which stage and
why. `AnyFailed`/`AnyNotTested` scan the full reached-plus-skipped result
list, never just the last stage.

**Campaign 01 definition** (new file, `campaign01.go`):

```go
var Campaign01SensitiveRecordToExternalDisclosure = CorrelationChain{
	ID:   "DLPCORRELATE-CAMPAIGN-01",
	Name: "Sensitive record to external disclosure",
	Stages: []StageDefinition{
		{Label: "classify the seeded record", Dimension: "DLP-CLS"},
		{Label: "verify classification persists through document workflow", Dimension: "DLP-CLS-LABEL"},
		{Label: "attempt unauthorized external share, verify enforcement", Dimension: "DLP-ENF"},
		{Label: "verify security event and case evidence", Dimension: ""},
	},
}
```

A new function, `EvaluateCampaign01(classVerdict dlpclassify.DLPCLSVerdict, labelVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error)`,
translates each already-computed real verdict into a `StageResult` (one
`switch`/`if` per stage, no shared translation helper needed for only 3
call sites) and always appends a 4th, permanently-`StageNotTested` result
for the security-event/case-evidence stage with `Reason: "no DLP-specific
telemetry/case-correlation evaluator exists in this repo"`, then calls
`EvaluateCorrelationChain`.

## What's left to the builder

- Exact field names on `dlpclassify.DLPCLSVerdict`/`reporting.ComparisonResult`
  translation branches (read those two packages' real `Outcome`/`Comparison`
  enum values directly — do not guess from this spec).
- Whether `EvaluateCampaign01`'s 4 parameters should instead take 2
  `DLPCLSVerdict`s via a small named struct for readability — either is
  fine; this spec only pins the semantic mapping (3 real evaluators → 3
  stages + 1 permanent gap stage), not the exact Go parameter-list shape.
- Campaigns 02-06: deliberately not designed here. A follow-on slice
  should repeat this same "map dlp.txt's own campaign description onto
  already-existing evaluators, name what's genuinely untestable today"
  exercise per campaign, reusing this same `CorrelationChain`/
  `EvaluateCorrelationChain` core without modification.
