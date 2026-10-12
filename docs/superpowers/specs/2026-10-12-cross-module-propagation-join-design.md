# Cross-Module Propagation Join — Design Spec

Sub-project #7 of the ransomware-mastery master roadmap (`ransomware.txt` row 7, narrative section "7. Enterprise-wide ransomware propagation").

## A. Problem statement

The roadmap's table row for #7 compresses to "combine `rwevidence` Containment + existing `latmove`/AD-mastery into one campaign." The full narrative section is more specific and more demanding:

> Combine your existing AD mastery and lateral-movement validation with ransomware-specific objectives. Test whether an assumed-compromised identity can reach protected servers, administrative shares, backup systems, virtual infrastructure, and other critical assets within an explicitly authorized test boundary. Measure reachable assets, privilege barriers, segmentation effectiveness, propagation containment and time to isolate affected systems. Deliverable: a cross-module campaign that proves whether controls prevent a simulated ransomware incident from spreading.

Five named measures: reachable assets, privilege barriers, segmentation effectiveness, propagation containment, time to isolate. Grounding this against real code (not the roadmap's own characterization) surfaced three facts that reshape what "campaign" can honestly mean in this pass:

1. **"AD mastery" and "lateral-movement validation" are two separate existing systems**, both named explicitly in the narrative — not one thing. AD mastery is `internal/adprimitive` (the attack-primitive catalog) and `internal/admatrix` (the graph-reachability/coverage engine built on it). Lateral-movement validation is `internal/latmove` (OS/network-level remote-execution validation) and `internal/latdetect` (its detection bridge).
2. **The existing `Campaign` concept (`internal/campaign`) is homogeneous-scenario fan-out, not a cross-module evidence join.** `campaign.Aggregate(runs []ChildRun, skips []Skip) Summary` only reads `models.SimulationResult`/`models.Score`/`DetectedTechs` and rolls them into Prevented/Detected/Missed/Errored counts across child runs of the *same* scenario dispatched to multiple agents. It has zero awareness of `rwevidence.Containment`, `latmove`, or `admatrix`. Reusing it buys dispatch/rollup plumbing, not the join this sub-project needs. "Campaign" in the roadmap's wording is descriptive of the deliverable's intent, not a literal binding to this package.
3. **Only one of the three evidence sources is persisted anywhere.** `rwevidence` writes to `rw_capability_results` (Postgres), which is what let sub-projects #5 and #6 build `dxcorrelate`/`rwresponse` as DB-reading joins keyed by `run_id`. `internal/latmove` has no store at all (`Observation`, `AccessCondition`, `CleanupResult` exist only as whatever a caller constructs in-memory, per call). `admatrix.Simulate` is a pure function with no persistence and no run scoping — its existing HTTP surface (`GetADAssessmentJSON`/`HTML`/`PDF`) computes a static catalog-level report with no `db`/`pool` reference anywhere, not a per-run record.

A fourth fact narrows "propagation containment" specifically: `rwevidence.ContainmentObserver` is scoped to the four ransomware-payload techniques (T1490/T1486/T1567.002/T1560.001) only. Neither `latmove` nor `admatrix` has any containment/isolation observer — `latmove.CleanupVerifier` confirms a *test artifact* was removed, not that a host was isolated, and must never be read as a containment signal. There is no real "was the AD or lateral-movement leg of this propagation path contained" measurement anywhere in the codebase today.

**Scope decision for this pass:** build `internal/rwpropagation`, a pure-Go package that joins all three evidence sources into one report, preserving each source's provenance and validation level rather than collapsing them into a single score. No HTTP endpoint, no new persistence, no real `latmove`/`admatrix` execution wiring — those require a real producer and lifecycle for AD/lateral-movement evidence that doesn't exist yet, and are explicitly deferred (section F). The deliverable is a tested, provenance-preserving cross-module report — not a claim that enterprise-wide propagation is prevented, and not a claim that any of the underlying evidence is live rather than simulated/fake-backed.

## B. `internal/rwpropagation` — core types

Pure Go, no I/O calls (it imports `internal/db`, `internal/latmove`, `internal/admatrix`, `internal/adprimitive`, and `internal/controlval` only for their *types*, mirroring `rwresponse`'s own precedent of importing `db` for `RWAttemptRow`'s type without ever calling `db`).

```go
package rwpropagation

import (
	"time"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/latmove"
)

// AssessmentContext identifies the single simulated incident a Report
// covers. RunID ties the ransomware leg to rwevidence's run-scoped rows;
// AssessmentID is the correlation anchor for the AD and lateral-movement
// legs, which have no run-scoped store to anchor them instead.
type AssessmentContext struct {
	AssessmentID string
	RunID        string
}

// ADReachability is one admatrix.Simulate result, carried through with its
// validation level explicit. Level is always admatrix.LevelModelSimulated
// today -- a simulated graph-reachability answer, never a claim that a real
// account can reach a live target.
type ADReachability struct {
	Target    adprimitive.Capability
	Reachable bool
	Steps     []adprimitive.Primitive
	Level     admatrix.ValidationLevel
}

// LateralMovementAccess is one latmove discovery result. Condition is
// preserved exactly (Granted/Denied/Unknown) -- never collapsed to a bool,
// and never read as if it were an ADReachability.Reachable value or vice
// versa. AD authorization and OS/network reachability are different
// questions; conflating them is exactly the segmentation-effectiveness
// mistake this package exists to avoid.
type LateralMovementAccess struct {
	Technique   latmove.Technique
	Principal   string
	Destination string
	Condition   latmove.AccessCondition
}

// LateralMovementExecution is one latmove attempt's classified outcome.
type LateralMovementExecution struct {
	Key    latmove.AttemptKey
	Result latmove.AttemptResult
}

// TechniqueContainmentStatus distinguishes WHY a technique's containment
// entry has no real verdict, when it has none -- three semantically
// different situations that must never be collapsed into one another:
type TechniqueContainmentStatus string

const (
	// ContainmentStatusEvaluated means a real PASS/FAIL/ERROR containment
	// row exists for this technique: a genuine verdict was reached.
	ContainmentStatusEvaluated TechniqueContainmentStatus = "evaluated"
	// ContainmentStatusNotApplicable means rwevidence itself decided
	// containment does not apply to this technique (a SKIPPED row with
	// SkipReason == not_applicable exists) -- a decided "no", not a gap.
	ContainmentStatusNotApplicable TechniqueContainmentStatus = "not_applicable"
	// ContainmentStatusNotInstrumented means this technique was attempted
	// in the run (it appears in RansomwareRows under some OTHER
	// capability) but carries ZERO containment-capability rows at all --
	// an instrumentation gap, never silently dropped or treated as a
	// negative (FAIL) result.
	ContainmentStatusNotInstrumented TechniqueContainmentStatus = "not_instrumented"
)

// RansomwareContainment is one ransomware technique's containment
// evidence, read from the same run-scoped rows #5/#6 already consume.
// Scope note, load-bearing: this measures containment of the SPECIFIC
// ransomware capability attempt only -- never a claim about the AD or
// lateral-movement legs, which have no containment observer at all (see
// ContainmentNoObserver below). Verdict and CreatedAt are zero-valued
// when Status == ContainmentStatusNotInstrumented -- there is no row to
// read them from.
type RansomwareContainment struct {
	TechniqueID string
	Status      TechniqueContainmentStatus
	Verdict     controlval.Verdict
	Reason      string
	CreatedAt   time.Time
}

// ContainmentAvailability distinguishes "this leg has at least one
// technique-level entry to report" from "there is no observer for this
// leg at all" -- the latter is not a verdict, it is an honest statement
// that nothing in this codebase can answer the question yet.
type ContainmentAvailability string

const (
	ContainmentMeasured   ContainmentAvailability = "measured"
	ContainmentNoObserver ContainmentAvailability = "no_observer"
)

// LegContainment pairs a propagation leg with its containment
// availability and, only when Measured, one entry per distinct
// TechniqueID attempted on that leg. Never one value standing in for
// several techniques: T1486's containment outcome must never be read as
// speaking for T1490's, T1567.002's, or T1560.001's.
type LegContainment struct {
	Leg          string // "ad" | "lateral_movement" | "ransomware_payload"
	Availability ContainmentAvailability
	Containment  []RansomwareContainment // one entry per distinct TechniqueID; empty when Availability == ContainmentNoObserver
}

// TimeToIsolateStatus mirrors rwresponse.ResponseLatencyStatus's semantics
// exactly: a fixed status, never a computed duration, because no causal
// link between a detection event and an isolation action exists anywhere
// in this codebase today. Reused rather than reinvented.
type TimeToIsolateStatus string

const TimeToIsolateNotEstablishable TimeToIsolateStatus = "not_establishable"
```

**Structural invariant (not a runtime branch):** `BuildReport` always emits exactly 3 `LegContainment` entries. The `"ad"` and `"lateral_movement"` entries are hardcoded to `ContainmentNoObserver` — this is a fact about what exists in the codebase today, asserted by a test, never computed from input data, because there is no input shape in this package that could carry AD or lateral-movement containment evidence even if a caller tried to supply it.

## C. Correlation and error-handling

Each caller-supplied item is tagged with the `AssessmentID` the caller claims it belongs to. `BuildReport` verifies that tag against the context — it cannot verify the caller's claim is actually true, only catch disagreement when the tags themselves don't match.

```go
type TaggedADReachability struct {
	AssessmentID string
	Result       admatrix.SimResult
}

type TaggedLateralMovementAccess struct {
	AssessmentID string
	Technique    latmove.Technique
	Principal    string
	Destination  string
	Condition    latmove.AccessCondition
}

type TaggedLateralMovementExecution struct {
	AssessmentID string
	Key          latmove.AttemptKey
	Result       latmove.AttemptResult
}

// Input is everything the caller supplies for one assessment.
// RansomwareRows' correlation to Context.RunID is enforced by
// construction, not by a field on the row: the caller is expected to have
// fetched these via db.RWCapabilityAttempts(ctx, pool, Context.RunID),
// which already filtered by run_id -- there is no separate RunID field on
// db.RWAttemptRow to check here.
type Input struct {
	Context                  AssessmentContext
	ADReachability            []TaggedADReachability
	LateralMovementAccess     []TaggedLateralMovementAccess
	LateralMovementExecution  []TaggedLateralMovementExecution
	RansomwareRows            []db.RWAttemptRow
}

// Exclusion records one supplied item this package declined to include in
// the report, and why -- never dropped silently.
type Exclusion struct {
	Source string // "ad_reachability" | "lateral_movement_access" | "lateral_movement_execution"
	Reason string
}

type CorrelationStatus string

const (
	CorrelationEstablished  CorrelationStatus = "established"
	CorrelationUncorrelated CorrelationStatus = "uncorrelated"
)

type Report struct {
	Assessment  AssessmentContext
	Correlation CorrelationStatus
	Exclusions  []Exclusion

	ADReachability            []ADReachability
	LateralMovementAccess     []LateralMovementAccess
	LateralMovementExecution  []LateralMovementExecution
	Containment               []LegContainment
	TimeToIsolate             TimeToIsolateStatus
	TimeToIsolateReason       string
}
```

`BuildReport(input Input) Report` — no `error` return; every "something was off" case is a value in the result, the same discipline `dxcorrelate.Correlate` and `rwresponse.BuildEffectivenessReport` already use. Logic, in order:

1. **Empty context.** If `input.Context.AssessmentID == ""`, every tagged item is excluded with reason `"no AssessmentID set on context"`, and `Correlation = CorrelationUncorrelated`. An assessment with no identity gets no conclusions, not a best-effort one.
2. **Per-item tag check.** Otherwise, for each tagged item in `ADReachability`, `LateralMovementAccess`, and `LateralMovementExecution`: if `item.AssessmentID != input.Context.AssessmentID`, append an `Exclusion` (naming the source and the mismatch) and drop the item from the corresponding typed slice in `Report` — it is never included in a report whose `Correlation` claims to be established.
3. **Report-level flag.** If `len(Exclusions) > 0` for any reason (including the empty-context case), `Correlation = CorrelationUncorrelated` for the whole report — one mismatched item taints the correlation claim as a whole, even though every correctly-tagged item still appears in its slice. `Correlation = CorrelationEstablished` only when the context is non-empty and every supplied item matched.
4. **Empty-but-correctly-tagged is not an exclusion.** A leg with zero supplied items (nothing to report, not a mismatch) never produces an `Exclusion` and never affects `Correlation` — "nothing was supplied" and "something was supplied but doesn't belong" are different, and must stay visibly different in the output.
5. **Containment.** The `"ad"` and `"lateral_movement"` `LegContainment` entries are always `ContainmentNoObserver` with an empty `Containment` slice, independent of everything above. The `"ransomware_payload"` entry is derived from `input.RansomwareRows` as follows:
   a. `techniqueSet` = every distinct `TechniqueID` appearing anywhere in `RansomwareRows`, under any capability — "attempted in this run," sorted lexicographically for stable output order.
   b. If `techniqueSet` is empty (no ransomware rows supplied at all), the leg is `ContainmentNoObserver` with an empty `Containment` slice — nothing was attempted, so there is nothing to report, the same "nothing supplied" case as the other legs.
   c. Otherwise the leg is `ContainmentMeasured`, and for each technique in `techniqueSet`, one `RansomwareContainment` entry is built:
      - `containmentRows` = the subset of `RansomwareRows` for this technique where `Capability == "containment"`.
      - If `containmentRows` is empty: `Status = ContainmentStatusNotInstrumented`, `Verdict` and `CreatedAt` left zero-valued, `Reason = ""`. The technique was attempted (it has rows under some other capability) but nothing ever checked containment for it.
      - Otherwise, pick one row deterministically: earliest `CreatedAt` wins; if multiple rows share the earliest `CreatedAt`, the one with the lexicographically smallest `Action` wins (a deterministic, data-derived tie-break — never dependent on input slice order). Call it `r`.
        - If `r.Verdict == controlval.VerdictSkipped && r.SkipReason == controlval.SkipNotApplicable`: `Status = ContainmentStatusNotApplicable`.
        - Otherwise: `Status = ContainmentStatusEvaluated`.
        - Either way, `Verdict = r.Verdict`, `Reason = r.Reason`, `CreatedAt = r.CreatedAt`.
   A technique's entry never represents another technique's evidence — `ContainmentStatusNotApplicable` for T1490 and `ContainmentStatusEvaluated` for T1486 coexist in the same slice without either one influencing the other.
6. **Time to isolate.** `TimeToIsolate = TimeToIsolateNotEstablishable` unconditionally, with `TimeToIsolateReason` set to a fixed string explaining why (no causal detection→isolation link exists in this codebase today) — never computed from any timestamp present in the input, because no such timestamp means what it would need to mean.

## D. Testing strategy

This package needs **zero database integration tests.** It only consumes `[]db.RWAttemptRow` as already-proven output — `db.RWCapabilityAttempts` itself was fully tested against real Postgres in sub-project #5's Task 4. Every test here is pure Go, constructing literal values for all three evidence shapes; no testcontainers.

**Provenance preservation**
- `ADReachability.Level` stays `admatrix.LevelModelSimulated` through the join.
- `LateralMovementAccess.Condition` passes through exactly as `Granted`/`Denied`/`Unknown` — never collapsed to a bool.
- A `Denied` AD-reachability result is never conflated with a `Denied` lateral-movement result in the same report (segmentation separation, pinned directly: build a report with one leg `Reachable: false` and the other leg `Condition: AccessDenied`, assert both appear independently and neither field influences the other).

**Containment-scope structural tests**
- `BuildReport` always returns exactly 3 `LegContainment` entries, legs `"ad"`, `"lateral_movement"`, `"ransomware_payload"`, in that fixed order.
- `"ad"` and `"lateral_movement"` are `ContainmentNoObserver` with an empty `Containment` slice unconditionally — true even when the input supplies AD/lateral-movement evidence, since there is no field through which such evidence could reach a containment verdict.
- `"ransomware_payload"` is `ContainmentNoObserver` with an empty slice when `RansomwareRows` is empty.
- A multi-technique run (e.g. T1486 with a real PASS containment row, T1490 with a SKIPPED/not_applicable containment row, and T1560.001 with only a Prevention row and zero containment rows) produces exactly 3 `RansomwareContainment` entries — one per technique, each with its own correct `Status` (`evaluated` / `not_applicable` / `not_instrumented` respectively) — and T1486's `Status`/`Verdict` must not appear on, or influence, T1490's or T1560.001's entries.
- Duplicate containment rows for the same technique with different `CreatedAt` resolve to the earliest; duplicate rows with the *same* `CreatedAt` resolve deterministically by lexicographically-smallest `Action`, and this result does not change when the input slice is reordered.

**Time-to-isolate invariant**
- `TimeToIsolateNotEstablishable` regardless of any input shape, including inputs that carry real `CreatedAt` timestamps elsewhere in the report — proving independence, the same test shape as `rwresponse`'s `TestBuildEffectivenessReport_ResponseLatencyAlwaysNotEstablishable`.

**Correlation**
- Empty `AssessmentID` → `CorrelationUncorrelated`, every item excluded, reasons recorded.
- All items correctly tagged → `CorrelationEstablished`, zero `Exclusions`.
- One mismatched item among several correct ones → `CorrelationUncorrelated` overall, exactly the mismatched item in `Exclusions`, the correctly-tagged items still present in their typed slices (partial survival, not all-or-nothing loss).
- Multiple mismatches across different sources (one `ADReachability` item and one `LateralMovementExecution` item both wrong) → both recorded in `Exclusions`, not just the first (no short-circuiting).
- Zero evidence supplied for a leg, correctly tagged (i.e., nothing to exclude) → `CorrelationEstablished`, distinguishing "nothing was supplied" from "something was supplied but didn't match."

**Determinism**
- The same `Input` with its slices reordered produces an identical `Report` (`Correlation`, `Exclusions`, every leg's contents) — mirrors `dxcorrelate`'s and `rwresponse`'s existing order-independence tests.

**One real cross-package test**
- Construct a real `admatrix.SimResult` via `admatrix.Simulate()` against a small real catalog slice, a real `latmove.Observation` classified via `latmove.ClassifyAttempt()`, and literal `db.RWAttemptRow` values shaped like a genuine ransomware run (e.g. a T1486 containment row with a real `controlval.Verdict`, plus a T1490 row under a different capability to exercise the `not_instrumented` path) — all three tagged to the same `AssessmentContext`. Assert the resulting `Report` is `CorrelationEstablished`, all three legs populated, the `ransomware_payload` leg carries one entry per technique with the right `Status` each, and every provenance/validation-level field intact. This is the "the join actually works end-to-end" test, without needing Postgres.

## E. Explicitly deferred (not in this spec)

- **HTTP API endpoint.** No GET endpoint is justified yet: a `RunID` can retrieve ransomware evidence via the existing DB read, but it cannot reconstruct AD or lateral-movement evidence that was never persisted. An endpoint added now would either omit those inputs entirely or require an ad hoc request-body payload contract with no precedent elsewhere in this codebase. Revisit when there is a real producer for AD/lateral-movement evidence and a defined lifecycle for collecting it.
- **Persistence for `latmove` and `admatrix`.** Neither package has a DB store today, and nothing in the codebase calls either from a real dispatch path — building storage for evidence nothing currently produces would be premature. A future pass that wires `latmove`/`admatrix` into a real scenario-execution path is the natural trigger to add their own stores, mirroring `rwevidence_store.go`.
- **Real lateral-movement/AD execution wiring.** `latmove` and `admatrix` remain fake-backed/model-simulated vertical slices, same maturity level as `rwevidence` before any real observer exists. This sub-project does not change that.
- **A real containment/isolation observer for the AD or lateral-movement legs.** Building one (mirroring `rwevidence.ContainmentObserver`'s contract) is a legitimate future sub-project, not a quick addition here — the user explicitly declined to let this pass invent one.
- **Real time-to-isolate measurement.** Requires trustworthy detection and isolation timestamps, plus evidence that the isolation event corresponds to the specific detection being measured — run-level proximity is not sufficient (same conclusion sub-project #6 already reached for response latency generally). `TimeToIsolateNotEstablishable` stays fixed until that evidence contract exists.
- **A second sub-project number (`#7b`) for the above.** Not created yet, per explicit decision — the deferred items are recorded here; they get their own roadmap entry only when picked up.
