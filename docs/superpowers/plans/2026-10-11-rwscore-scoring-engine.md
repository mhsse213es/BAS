# rwscore Scoring Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution already decided: native/inline, standing session preference). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn sub-project #1's already-persisted `rw_capability_results` coverage counts into a 5-dimension weighted score, a 3-tier rating, and the one risk gate the roadmap names, reachable through one new read-only API endpoint.

**Architecture:** A new, pure-computation Go package `internal/rwscore` (no I/O, no DB import) that buckets coverage rows per dimension, computes a weight-redistributed overall score, applies a single hardcoded risk gate (Recovery FAIL caps the rating), and returns a `RunScore`. One new handler in `internal/api` translates `db.RWCoverageRow` into `rwscore.CoverageRow` and calls it.

**Tech Stack:** Go, chi router (existing), Postgres via pgxpool (existing, read-only reuse of sub-project #1's `db.RWCapabilityCoverage`).

**Spec:** `docs/superpowers/specs/2026-10-11-rwscore-scoring-engine-design.md`

## Global Constraints

- Weights: Prevention 0.25, Detection 0.20, Containment 0.20, Recovery 0.25, DataProtection 0.10 — illustrative, not an industry standard (spec section C).
- `insufficient_evidence` (UNKNOWN) always stays in a dimension's pass-rate denominator — never silently excluded (spec section B, the roadmap's own named anti-pattern).
- `not_applicable` is neutral: excluded from both numerator and denominator, never changes a score (spec section B).
- A dimension with zero evaluated rows is excluded from the weighted average with its weight redistributed proportionally across the remaining non-empty dimensions — never treated as a hard 0 (spec section C, exact formula given there).
- Rating thresholds: Overall >= 80 Protected, >= 50 AtRisk, else Vulnerable (spec section E) — illustrative, calibrate later.
- Exactly one risk gate ships: `Recovery.Fail > 0` caps Rating at AtRisk, never upgrades a lower rating (spec section D). No second gate is invented.
- `rwscore` never imports `internal/db` — it defines its own `CoverageRow`, mirroring `db.RWCoverageRow` field-for-field; the caller translates (spec section A).

## Review Focus

- A dimension whose only rows are `insufficient_evidence` (UNKNOWN) must pull its PassRate below what a naive `Pass/(Pass+Fail)` calculation would give — a simpler-looking implementation that drops UNKNOWN from the denominator passes every other test while reintroducing the roadmap's named anti-pattern. Task 1 is where this can go wrong.
- A dimension with zero evaluated rows must have its weight *redistributed*, not silently dropped (which under-fills the 0-100 scale with no visible reason) and not counted as a hard 0 (double-penalizing a gap `NotTested` already reports separately). Task 2's hand-computed test is the only thing that catches a dropped-vs-redistributed-vs-hard-0 mixup, since several wrong implementations produce a plausible-looking non-error number.
- The risk gate must be provably a *ceiling*, never an upgrade — a swapped comparison or an `<=` typo would let a failed Recovery test still reach Protected under some input, silently defeating the entire reason this sub-project exists. Task 2 pins both directions (capped-down and never-upgraded).
- A nonexistent `runId` must 404 before any coverage query runs, not return an empty-looking "Vulnerable" score indistinguishable from a real catastrophic assessment. Task 3 is where this is checked.
- `CriticalFailures` messages must name only what the input data actually supports (technique-level aggregate counts), never implying per-action detail the `CoverageRow` input doesn't carry. Task 2's message-format test pins the exact string shape.

---

### Task 1: `rwscore` package — dimension bucketing and pass-rate math

**Files:**
- Create: `orchestrator/internal/rwscore/types.go`
- Create: `orchestrator/internal/rwscore/score.go`
- Create: `orchestrator/internal/rwscore/score_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `rwscore.Dimension` (5 constants), `rwscore.CoverageRow{TechniqueID, Capability, Verdict, SkipReason, SpecificReason string; Count int}`, `rwscore.DimensionScore{Dimension Dimension; Pass, Fail, Error, Unknown, NotApplicable, NotTested int; PassRate float64}`, unexported `bucketDimension(dim Dimension, rows []CoverageRow) DimensionScore` and `allDimensions []Dimension` — Task 2 consumes both directly (same package).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwscore/score_test.go`:

```go
package rwscore

import "testing"

func TestBucketDimension_AllPassIsPassRateOne(t *testing.T) {
	rows := []CoverageRow{{Capability: "prevention", Verdict: "PASS", Count: 5}}
	ds := bucketDimension(DimensionPrevention, rows)
	if ds.PassRate != 1.0 {
		t.Fatalf("PassRate = %v, want 1.0", ds.PassRate)
	}
	if ds.Pass != 5 {
		t.Fatalf("Pass = %d, want 5", ds.Pass)
	}
}

func TestBucketDimension_AllFailIsPassRateZero(t *testing.T) {
	rows := []CoverageRow{{Capability: "recovery", Verdict: "FAIL", Count: 3}}
	ds := bucketDimension(DimensionRecovery, rows)
	if ds.PassRate != 0.0 {
		t.Fatalf("PassRate = %v, want 0.0", ds.PassRate)
	}
	if ds.Fail != 3 {
		t.Fatalf("Fail = %d, want 3", ds.Fail)
	}
}

func TestBucketDimension_UnknownLowersPassRateBelowNaiveExclusion(t *testing.T) {
	// Acceptance criterion 3: insufficient_evidence (UNKNOWN) rows must stay
	// in the denominator. A WRONG implementation using a naive
	// Pass/(Pass+Fail) calculation (excluding Unknown from the denominator)
	// would compute 1.0 here, since there are zero Fail rows -- this test
	// fails against that wrong implementation and passes only against the
	// correct one (Pass/(Pass+Fail+Error+Unknown)).
	rows := []CoverageRow{
		{Capability: "detection", Verdict: "PASS", Count: 2},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "insufficient_evidence", Count: 2},
	}
	ds := bucketDimension(DimensionDetection, rows)
	if ds.PassRate != 0.5 {
		t.Fatalf("PassRate = %v, want 0.5 (2 pass / (2 pass + 2 unknown) -- a naive Pass/(Pass+Fail) calc would wrongly give 1.0)", ds.PassRate)
	}
	if ds.Unknown != 2 {
		t.Fatalf("Unknown = %d, want 2", ds.Unknown)
	}
}

func TestBucketDimension_NotApplicableNeverChangesPassRate(t *testing.T) {
	withNA := []CoverageRow{
		{Capability: "containment", Verdict: "PASS", Count: 4},
		{Capability: "containment", Verdict: "SKIPPED", SkipReason: "not_applicable", Count: 100},
	}
	withoutNA := []CoverageRow{
		{Capability: "containment", Verdict: "PASS", Count: 4},
	}
	dsWith := bucketDimension(DimensionContainment, withNA)
	dsWithout := bucketDimension(DimensionContainment, withoutNA)
	if dsWith.PassRate != dsWithout.PassRate {
		t.Fatalf("PassRate with not_applicable rows = %v, without = %v -- not_applicable must be neutral", dsWith.PassRate, dsWithout.PassRate)
	}
	if dsWith.NotApplicable != 100 {
		t.Fatalf("NotApplicable = %d, want 100", dsWith.NotApplicable)
	}
}

func TestBucketDimension_EmptyDenominatorIsZeroNotNaN(t *testing.T) {
	rows := []CoverageRow{{Capability: "data_protection", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 10}}
	ds := bucketDimension(DimensionDataProtection, rows)
	if ds.PassRate != 0.0 {
		t.Fatalf("PassRate = %v, want 0.0 (not NaN) when nothing was evaluated", ds.PassRate)
	}
	if ds.NotTested != 10 {
		t.Fatalf("NotTested = %d, want 10", ds.NotTested)
	}
}

func TestBucketDimension_ErrorCountsSeparatelyFromUnknown(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "detection", Verdict: "ERROR", Count: 1},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "insufficient_evidence", Count: 1},
	}
	ds := bucketDimension(DimensionDetection, rows)
	if ds.Error != 1 || ds.Unknown != 1 {
		t.Fatalf("Error=%d Unknown=%d, want 1/1 -- an evaluator that ran and failed operationally must stay distinct from ambiguous evidence", ds.Error, ds.Unknown)
	}
	if ds.PassRate != 0.0 {
		t.Fatalf("PassRate = %v, want 0.0 (0 pass / (0+0+1+1))", ds.PassRate)
	}
}

func TestBucketDimension_IgnoresRowsForOtherDimensions(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 99},
		{Capability: "recovery", Verdict: "FAIL", Count: 1},
	}
	ds := bucketDimension(DimensionRecovery, rows)
	if ds.Pass != 0 || ds.Fail != 1 {
		t.Fatalf("Pass=%d Fail=%d, want 0/1 -- a row for a different capability must never be counted", ds.Pass, ds.Fail)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwscore/ -v`
Expected: FAIL — `undefined: bucketDimension`, `undefined: DimensionPrevention`, `undefined: CoverageRow` (compile error; the package doesn't exist yet)

- [ ] **Step 3: Implement `types.go` and `score.go`**

Create `orchestrator/internal/rwscore/types.go`:

```go
// Package rwscore is the ransomware-mastery scoring engine: it turns a
// run's rw_capability_results coverage counts (internal/db, sub-project
// #1) into a 5-dimension weighted score, a qualitative rating, and the
// risk-gate override the roadmap names by name. Pure computation -- no
// I/O, no DB import, so the whole engine is table-driven unit tests.
package rwscore

// Dimension names one of the five ransomware-mastery scoring dimensions --
// the same five rwevidence.Capability values, duplicated here (not
// imported) so rwscore stays input-agnostic, the same discipline
// rwevidence.StepInput uses to stay independent of scenario/models.
type Dimension string

const (
	DimensionPrevention     Dimension = "prevention"
	DimensionDetection      Dimension = "detection"
	DimensionContainment    Dimension = "containment"
	DimensionRecovery       Dimension = "recovery"
	DimensionDataProtection Dimension = "data_protection"
)

// CoverageRow mirrors db.RWCoverageRow's shape field-for-field -- rwscore
// never imports internal/db; the caller (internal/api) translates.
type CoverageRow struct {
	TechniqueID    string
	Capability     string
	Verdict        string
	SkipReason     string
	SpecificReason string
	Count          int
}

// DimensionScore is one dimension's independently-computed bucket counts
// and pass rate. Every count is carried, not just the ratio, so nothing a
// caller might want to surface is hidden behind a single opaque
// percentage.
type DimensionScore struct {
	Dimension     Dimension
	Pass          int
	Fail          int
	Error         int
	Unknown       int
	NotApplicable int
	NotTested     int
	PassRate      float64
}
```

Create `orchestrator/internal/rwscore/score.go`:

```go
package rwscore

var allDimensions = []Dimension{
	DimensionPrevention, DimensionDetection, DimensionContainment,
	DimensionRecovery, DimensionDataProtection,
}

// bucketDimension sums every CoverageRow belonging to dim into its 6
// buckets and computes PassRate = Pass/(Pass+Fail+Error+Unknown) -- 0 if
// that denominator is 0 (nothing to average, not NaN). NotApplicable and
// NotTested never enter this denominator (spec section B).
func bucketDimension(dim Dimension, rows []CoverageRow) DimensionScore {
	ds := DimensionScore{Dimension: dim}
	for _, r := range rows {
		if Dimension(r.Capability) != dim {
			continue
		}
		switch r.Verdict {
		case "PASS":
			ds.Pass += r.Count
		case "FAIL":
			ds.Fail += r.Count
		case "ERROR":
			ds.Error += r.Count
		case "SKIPPED":
			switch r.SkipReason {
			case "insufficient_evidence":
				ds.Unknown += r.Count
			case "not_applicable":
				ds.NotApplicable += r.Count
			case "not_tested":
				ds.NotTested += r.Count
			}
		}
	}
	if denom := ds.Pass + ds.Fail + ds.Error + ds.Unknown; denom > 0 {
		ds.PassRate = float64(ds.Pass) / float64(denom)
	}
	return ds
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwscore/ -v`
Expected: PASS (7/7)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/rwscore/types.go internal/rwscore/score.go internal/rwscore/score_test.go
git commit -m "feat(rwscore): dimension bucketing and pass-rate math

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `ScoreRun` — weighted overall score, rating, and the Recovery risk gate

**Files:**
- Modify: `orchestrator/internal/rwscore/types.go` (add `Rating`, `RunScore`)
- Modify: `orchestrator/internal/rwscore/score.go` (add `weights`, `ScoreRun`, `ratingFor`, `recoveryFailureMessages`)
- Modify: `orchestrator/internal/rwscore/score_test.go`

**Interfaces:**
- Consumes: `Dimension`, `CoverageRow`, `DimensionScore`, `bucketDimension`, `allDimensions` (Task 1).
- Produces: `rwscore.Rating` (3 constants), `rwscore.RunScore{Overall float64; Rating Rating; Dimensions []DimensionScore; CriticalFailures []string; GateTriggered bool}`, `rwscore.ScoreRun(rows []CoverageRow) RunScore` — Task 3's handler calls this directly.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/rwscore/score_test.go`:

```go
func TestScoreRun_FullWeightedAverageAllDimensionsPresent(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},     // PassRate 1.0
		{Capability: "detection", Verdict: "FAIL", Count: 10},       // PassRate 0.0
		{Capability: "containment", Verdict: "PASS", Count: 5},
		{Capability: "containment", Verdict: "FAIL", Count: 5},      // PassRate 0.5
		{Capability: "recovery", Verdict: "PASS", Count: 10},        // PassRate 1.0
		{Capability: "data_protection", Verdict: "PASS", Count: 10}, // PassRate 1.0
	}
	score := ScoreRun(rows)
	// Overall = 100 * (0.25*1.0 + 0.20*0.0 + 0.20*0.5 + 0.25*1.0 + 0.10*1.0)
	//         = 100 * (0.25 + 0 + 0.10 + 0.25 + 0.10) = 100 * 0.70 = 70
	if score.Overall != 70.0 {
		t.Fatalf("Overall = %v, want 70.0", score.Overall)
	}
	if score.Rating != RatingAtRisk { // 50 <= 70 < 80
		t.Fatalf("Rating = %q, want at_risk", score.Rating)
	}
	if len(score.Dimensions) != 5 {
		t.Fatalf("got %d dimensions, want 5", len(score.Dimensions))
	}
}

func TestScoreRun_EmptyDimensionExcludedAndWeightRedistributed(t *testing.T) {
	// Recovery has zero evaluated rows (entirely not_tested). Spec section
	// C requires its 0.25 weight to be EXCLUDED and the remaining weights
	// (Prevention .25 + Detection .20 + Containment .20 + DataProtection
	// .10 = 0.75) rescaled to sum to 1.0 -- not Recovery counted as a hard
	// 0. With all 4 remaining PassRates at 1.0, the correct redistributed
	// Overall is 100.0. A WRONG implementation that instead counts the
	// empty Recovery dimension as a hard 0 with its original 0.25 weight
	// would compute 100*(0.25+0.20+0.20+0+0.10) = 75.0 -- a different,
	// distinguishable number, not just "doesn't error."
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},
		{Capability: "detection", Verdict: "PASS", Count: 10},
		{Capability: "containment", Verdict: "PASS", Count: 10},
		{Capability: "recovery", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 10},
		{Capability: "data_protection", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if score.Overall != 100.0 {
		t.Fatalf("Overall = %v, want 100.0 (redistributed) -- a hard-0 implementation would give 75.0 instead", score.Overall)
	}
}

func TestScoreRun_AllDimensionsEmptyGivesZeroAndVulnerable(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
		{Capability: "detection", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
		{Capability: "containment", Verdict: "SKIPPED", SkipReason: "not_applicable", Count: 1},
		{Capability: "recovery", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
		{Capability: "data_protection", Verdict: "SKIPPED", SkipReason: "not_tested", Count: 1},
	}
	score := ScoreRun(rows)
	if score.Overall != 0.0 {
		t.Fatalf("Overall = %v, want 0.0", score.Overall)
	}
	if score.Rating != RatingVulnerable {
		t.Fatalf("Rating = %q, want vulnerable -- absence of evidence must never read as safety", score.Rating)
	}
}

func TestScoreRun_RecoveryFailureCapsRatingAtAtRiskEvenWithHighOverall(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},
		{Capability: "detection", Verdict: "PASS", Count: 10},
		{Capability: "containment", Verdict: "PASS", Count: 10},
		{Capability: "recovery", Verdict: "FAIL", TechniqueID: "T1490", Count: 1},
		{Capability: "data_protection", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if score.Rating != RatingAtRisk {
		t.Fatalf("Rating = %q, want at_risk -- a failed critical Recovery test must never allow Protected regardless of the numeric score", score.Rating)
	}
	if !score.GateTriggered {
		t.Fatal("GateTriggered = false, want true")
	}
}

func TestScoreRun_GateNeverUpgradesALowRating(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "FAIL", Count: 10},
		{Capability: "detection", Verdict: "FAIL", Count: 10},
		{Capability: "containment", Verdict: "FAIL", Count: 10},
		{Capability: "recovery", Verdict: "FAIL", TechniqueID: "T1490", Count: 1},
		{Capability: "data_protection", Verdict: "FAIL", Count: 10},
	}
	score := ScoreRun(rows)
	if score.Rating != RatingVulnerable {
		t.Fatalf("Rating = %q, want vulnerable -- the gate is a ceiling, never an upgrade", score.Rating)
	}
}

func TestScoreRun_CriticalFailuresNameTheExactTechniqueAndCount(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "prevention", Verdict: "PASS", Count: 10},
		{Capability: "detection", Verdict: "PASS", Count: 10},
		{Capability: "containment", Verdict: "PASS", Count: 10},
		{Capability: "recovery", Verdict: "FAIL", TechniqueID: "T1490", Count: 2},
		{Capability: "data_protection", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if len(score.CriticalFailures) != 1 || score.CriticalFailures[0] != "Recovery FAILED for T1490 (2 attempt(s))" {
		t.Fatalf("CriticalFailures = %v, want [\"Recovery FAILED for T1490 (2 attempt(s))\"]", score.CriticalFailures)
	}
}

func TestScoreRun_NoCriticalFailuresWhenGateNotTriggered(t *testing.T) {
	rows := []CoverageRow{
		{Capability: "recovery", Verdict: "PASS", Count: 10},
	}
	score := ScoreRun(rows)
	if len(score.CriticalFailures) != 0 {
		t.Fatalf("CriticalFailures = %v, want empty", score.CriticalFailures)
	}
	if score.GateTriggered {
		t.Fatal("GateTriggered = true, want false")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwscore/ -run TestScoreRun -v`
Expected: FAIL — `undefined: ScoreRun`, `undefined: RatingAtRisk`, `undefined: RunScore` (compile error)

- [ ] **Step 3: Implement `ScoreRun` and its helpers**

Add to `orchestrator/internal/rwscore/types.go`:

```go
// Rating is the overall qualitative rating a customer sees.
type Rating string

const (
	RatingProtected  Rating = "protected"
	RatingAtRisk     Rating = "at_risk"
	RatingVulnerable Rating = "vulnerable"
)

// RunScore is this sub-project's complete deliverable for one run.
type RunScore struct {
	Overall          float64
	Rating           Rating
	Dimensions       []DimensionScore
	CriticalFailures []string
	GateTriggered    bool
}
```

Add to `orchestrator/internal/rwscore/score.go`:

```go
import (
	"fmt"
	"sort"
)

// weights are the roadmap's own illustrative starting weights
// (ransomware.txt lines 194-221) -- NOT an industry standard, calibrate
// later against real validation data.
var weights = map[Dimension]float64{
	DimensionPrevention:     0.25,
	DimensionDetection:      0.20,
	DimensionContainment:    0.20,
	DimensionRecovery:       0.25,
	DimensionDataProtection: 0.10,
}

// ScoreRun is the package's one public entry point: pure function, no I/O,
// same input always gives the same output.
func ScoreRun(rows []CoverageRow) RunScore {
	dims := make([]DimensionScore, len(allDimensions))
	byDim := map[Dimension]DimensionScore{}
	for i, d := range allDimensions {
		ds := bucketDimension(d, rows)
		dims[i] = ds
		byDim[d] = ds
	}

	// Weighted average over only the dimensions with at least one
	// evaluated row -- an empty dimension's weight is excluded and the
	// remaining weights are implicitly rescaled by dividing the weighted
	// sum by their own total rather than by 1.0 (spec section C's exact
	// formula).
	var weightedSum, weightTotal float64
	for _, d := range allDimensions {
		ds := byDim[d]
		if ds.Pass+ds.Fail+ds.Error+ds.Unknown == 0 {
			continue
		}
		weightedSum += weights[d] * ds.PassRate
		weightTotal += weights[d]
	}
	var overall float64
	if weightTotal > 0 {
		overall = 100 * weightedSum / weightTotal
	}

	rating := ratingFor(overall)

	gateTriggered := false
	var criticalFailures []string
	if recovery := byDim[DimensionRecovery]; recovery.Fail > 0 {
		gateTriggered = true
		if rating == RatingProtected {
			rating = RatingAtRisk
		}
		criticalFailures = recoveryFailureMessages(rows)
	}

	return RunScore{
		Overall:          overall,
		Rating:           rating,
		Dimensions:       dims,
		CriticalFailures: criticalFailures,
		GateTriggered:    gateTriggered,
	}
}

func ratingFor(overall float64) Rating {
	switch {
	case overall >= 80:
		return RatingProtected
	case overall >= 50:
		return RatingAtRisk
	default:
		return RatingVulnerable
	}
}

// recoveryFailureMessages names the exact technique(s) and count(s) behind
// a triggered Recovery gate -- never finer-grained than the input actually
// supports (CoverageRow is already a technique-level aggregate).
func recoveryFailureMessages(rows []CoverageRow) []string {
	counts := map[string]int{}
	for _, r := range rows {
		if Dimension(r.Capability) == DimensionRecovery && r.Verdict == "FAIL" {
			counts[r.TechniqueID] += r.Count
		}
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic order
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, fmt.Sprintf("Recovery FAILED for %s (%d attempt(s))", id, counts[id]))
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwscore/ -run TestScoreRun -v`
Expected: PASS (7/7)

- [ ] **Step 5: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/rwscore/ -v`
Expected: PASS (14/14 — Task 1's 7 + Task 2's 7)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/rwscore/types.go internal/rwscore/score.go internal/rwscore/score_test.go
git commit -m "feat(rwscore): ScoreRun -- weighted overall score, rating, and the Recovery risk gate

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `GetRunRWScore` API endpoint + route registration

**Files:**
- Create: `orchestrator/internal/api/rwscore_handlers.go`
- Create: `orchestrator/internal/api/rwscore_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go:252` (insert the new route right after `GetRunIOCs`, inside the existing JWT-authenticated `r.Group` — same plain-`Get`, no-extra-permission precedent as its neighbors at lines 240-252/517-518)

**Interfaces:**
- Consumes: `rwscore.CoverageRow`, `rwscore.ScoreRun` (Tasks 1-2); `db.RWCapabilityCoverage`, `db.RWCoverageRow` (sub-project #1, unchanged).
- Produces: nothing new for later tasks — this is the integration point itself.

This test needs a real Postgres connection, same container-backed pattern as sub-project #1's `internal/api` tests. Confirmed against the real codebase during planning: `jsonError(w http.ResponseWriter, msg string, code int)` (`handlers.go:3940`) and `jsonOK(w http.ResponseWriter, v any)` (`variant_handlers.go:831`) are the real response helpers; `chi.URLParam(r, "runId")` and the manual-`chi.NewRouteContext()`-plus-`RouteCtxKey` pattern for testing a chi-param handler directly (confirmed against `content_gate_test.go:104-108`) are the real idioms — none of this is invented.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/rwscore_handlers_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetRunRWScore_NonexistentRunReturns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/does-not-exist/rw-score", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "does-not-exist")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetRunRWScore(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunRWScore_RealRunReturnsScoreMatchingPersistedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "rwscore-endpoint-run"
		seedRunRow(t, pool, runID, "ransomware-drill", "agent-rwscore", "running")

		results := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: "PASS"},
			{Capability: rwevidence.CapabilityRecovery, TechniqueID: "T1490", Verdict: "FAIL"},
		}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "action-1", results); err != nil {
			t.Fatalf("seed: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/rw-score", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", runID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetRunRWScore(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Rating        string `json:"Rating"`
			GateTriggered bool   `json:"GateTriggered"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.GateTriggered {
			t.Fatal("GateTriggered = false, want true -- the seeded Recovery FAIL must trip the gate")
		}
		if got.Rating != "at_risk" {
			t.Fatalf("Rating = %q, want at_risk", got.Rating)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run TestGetRunRWScore -v`
Expected: FAIL — `undefined: h.GetRunRWScore` (compile error)

- [ ] **Step 3: Implement the handler**

Create `orchestrator/internal/api/rwscore_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwscore"
)

// ── GET /api/scenarios/runs/{runId}/rw-score ──────────────────────────────

func (h *Handler) GetRunRWScore(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	ctx := r.Context()

	var exists string
	if err := h.db.QueryRow(ctx, `SELECT id FROM scenario_runs WHERE id = $1`, runID).Scan(&exists); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	rows, err := db.RWCapabilityCoverage(ctx, h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	scoreRows := make([]rwscore.CoverageRow, len(rows))
	for i, row := range rows {
		scoreRows[i] = rwscore.CoverageRow{
			TechniqueID:    row.TechniqueID,
			Capability:     row.Capability,
			Verdict:        row.Verdict,
			SkipReason:     row.SkipReason,
			SpecificReason: row.SpecificReason,
			Count:          row.Count,
		}
	}
	jsonOK(w, rwscore.ScoreRun(scoreRows))
}
```

Modify `orchestrator/internal/api/routes.go` — insert right after line 252 (`r.Get("/api/scenarios/runs/{runId}/iocs", h.GetRunIOCs)`), inside the same JWT-authenticated `r.Group`, same plain-`Get` style as every other read-only run report on the surrounding lines:

```go
		r.Get("/api/scenarios/runs/{runId}/iocs", h.GetRunIOCs)
		r.Get("/api/scenarios/runs/{runId}/rw-score", h.GetRunRWScore)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run TestGetRunRWScore -v`
Expected: PASS (2/2)

- [ ] **Step 5: Run the full api package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/api/ -timeout 20m -v 2>&1 | tail -50`
Expected: PASS — existing routes/tests unaffected (additive route registration only)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/api/rwscore_handlers.go internal/api/rwscore_handlers_test.go internal/api/routes.go
git commit -m "feat(api): GetRunRWScore -- reachable rwscore endpoint at /api/scenarios/runs/{runId}/rw-score

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Full regression gate across all three touched packages

**Files:**
- None (verification-only task; no new code).

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: nothing — this is the plan's terminal verification layer.

- [ ] **Step 1: Run the combined regression**

Run: `cd orchestrator && go test ./internal/rwscore/ ./internal/db/ ./internal/api/ -timeout 20m -v 2>&1 | tail -80`
Expected: all three packages `ok`, 0 FAIL lines across the combined run

- [ ] **Step 2: If everything passes, there is nothing to commit for this task** — it only exists to catch anything Task 3's own narrower run (Task 3 Step 5 already touched `internal/api`, but not `internal/rwscore`/`internal/db` together in the same invocation) might have missed from cross-package interaction.
