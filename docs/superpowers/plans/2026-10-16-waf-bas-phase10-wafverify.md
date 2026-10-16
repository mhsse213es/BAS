# WAF BAS Mastery Phase 10: Independent Verification and Continuous Mastery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafverify`, the final phase of the waf.txt 10-phase roadmap: a meta-validation layer that evaluates `wafval.Verdict` pairs already produced by any other phase, covering waf.txt Phase 10's 5 named items (regression suites, vendor/version benchmarks, finding reproduction, remediation retests, coverage-quality gates).

**Architecture:** A private, deliberately scoped `verdictRank` primitive orders `ClaimPrevention`-shaped verdicts only (`Missed < DetectedButAllowed < Blocked`); three shapes (Regression, Benchmark, Remediation) build on it for ranked before/after comparisons, while Reproduction is a pure-equality shape that works on any verdict including `ClaimFalsePositive`-shaped ones, and Coverage Gate is an independent ratio-against-threshold check with no verdict involved at all.

**Tech Stack:** Go 1.26.6, stdlib only (`fmt`), `internal/wafval` (already merged, read-only dependency).

**Spec:** `docs/superpowers/specs/2026-10-16-waf-bas-phase10-wafverify-design.md`

## Global Constraints

- Package `internal/wafverify` depends only on `internal/wafval` (+ stdlib `fmt`); it does not depend on `internal/wafcatalog`, `internal/wafpolicygap`, `internal/wafevasion`, `internal/wafapiflow`, `internal/wafbotabuse`, `internal/waforigin`, `internal/wafdetection`, or `internal/wafprofile`, and none of those depend on it either.
- This is the second (after `wafdetection`) fully attack-agnostic WAF-mastery phase with zero catalog cross-reference.
- `verdictRank` is scoped to `ClaimPrevention`-shaped verdicts only (per spec §3) and must never be extended to rank `VerdictAllowed`/`VerdictIncorrectlyBlocked`. Reproduction (Task 3) is the only shape built to handle `ClaimFalsePositive`-shaped verdicts, via equality rather than ranking.
- This is the FINAL phase of the waf.txt 10-phase roadmap — after this plan's final review there is no Phase 11 to continue to.
- `wafval.Verdict`'s 6 constants (confirmed against `orchestrator/internal/wafval/wafval.go`): `VerdictBlocked`, `VerdictDetectedButAllowed`, `VerdictMissed`, `VerdictAllowed`, `VerdictIncorrectlyBlocked`, `VerdictInconclusive`.

## Review Focus

- `EvaluateRegression`/`EvaluateBenchmark`/`EvaluateRemediation` must all independently confirm they return their `Inconclusive` outcome (not silently rank it as the lowest value, 0) when given `VerdictAllowed`, `VerdictIncorrectlyBlocked`, or `VerdictInconclusive` on either side. Pinned in Tasks 1, 2, 4.
- `EvaluateReproduction` must be proven to work on a matching pair of `ClaimFalsePositive`-shaped verdicts (both `VerdictAllowed`), the one case the other 3 ranked shapes structurally cannot handle. Pinned in Task 3.
- `RemediationUnchanged`'s neutral naming must be tested at the high end (`baseline=retest=VerdictBlocked`) specifically, not just the low end. Pinned in Task 4.
- `EvaluateCoverageGate`'s `ratio==minimumCoverage` boundary must resolve to `Pass`, not `Fail`. Pinned in Task 5.
- `EvaluateCoverageGate` must error (not return a status) on an invalid count pair, while still returning `CoverageGateInconclusive` as a normal status for the degenerate `totalScenarios<=0` case — these two "nothing meaningful happened" paths must not be conflated. Pinned in Task 5.

---

### Task 1: Shared ranking primitive and Regression shape

**Files:**
- Create: `orchestrator/internal/wafverify/regression.go`
- Test: `orchestrator/internal/wafverify/regression_test.go`

**Interfaces:**
- Consumes: `wafval.Verdict` (+ `VerdictBlocked`, `VerdictDetectedButAllowed`, `VerdictMissed`, `VerdictAllowed`, `VerdictIncorrectlyBlocked`, `VerdictInconclusive`) — already merged, `internal/wafval`.
- Produces: unexported `verdictRank(v wafval.Verdict) (rank int, ok bool)` (consumed by Tasks 2 and 4, same package, no import needed), `RegressionScenario{ID, Description, Provenance string}`, `NewRegressionScenario(id string, description string, provenance string) (RegressionScenario, error)`, `RegressionStatus` (+ 4 constants: `RegressionStable`, `RegressionImproved`, `RegressionRegressed`, `RegressionInconclusive`), `EvaluateRegression(scenario RegressionScenario, baseline wafval.Verdict, current wafval.Verdict) (RegressionStatus, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafverify/regression_test.go
package wafverify

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestVerdictRank_RankedValuesInOrder(t *testing.T) {
	missedRank, missedOK := verdictRank(wafval.VerdictMissed)
	detectedRank, detectedOK := verdictRank(wafval.VerdictDetectedButAllowed)
	blockedRank, blockedOK := verdictRank(wafval.VerdictBlocked)
	if !missedOK || !detectedOK || !blockedOK {
		t.Fatalf("expected all 3 ranked verdicts to report ok=true, got missed=%v detected=%v blocked=%v", missedOK, detectedOK, blockedOK)
	}
	if !(missedRank < detectedRank && detectedRank < blockedRank) {
		t.Errorf("ranks = missed:%d detected:%d blocked:%d, want missed < detected < blocked", missedRank, detectedRank, blockedRank)
	}
}

func TestVerdictRank_UnrankedValues(t *testing.T) {
	for _, v := range []wafval.Verdict{wafval.VerdictAllowed, wafval.VerdictIncorrectlyBlocked, wafval.VerdictInconclusive} {
		if _, ok := verdictRank(v); ok {
			t.Errorf("verdictRank(%q) ok = true, want false", v)
		}
	}
}

func mustRegressionScenario(t *testing.T) RegressionScenario {
	t.Helper()
	s, err := NewRegressionScenario("WAFVERIFY-001", "x", "y")
	if err != nil {
		t.Fatalf("NewRegressionScenario: %v", err)
	}
	return s
}

func TestNewRegressionScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewRegressionScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewRegressionScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewRegressionScenario("WAFVERIFY-001", "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewRegressionScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewRegressionScenario("WAFVERIFY-001", "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func TestEvaluateRegression_EqualRanks_ReturnsStable(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, reason, err := EvaluateRegression(scenario, wafval.VerdictBlocked, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionStable {
		t.Errorf("status = %q, want %q", status, RegressionStable)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateRegression_RankIncrease_ReturnsImproved(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictMissed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionImproved {
		t.Errorf("status = %q, want %q", status, RegressionImproved)
	}
}

func TestEvaluateRegression_RankDecrease_ReturnsRegressed(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictBlocked, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionRegressed {
		t.Errorf("status = %q, want %q", status, RegressionRegressed)
	}
}

// Review Focus: a FalsePositive-shaped verdict on either side must
// trigger Inconclusive, not be silently ranked as 0.
func TestEvaluateRegression_BaselineUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictAllowed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionInconclusive {
		t.Errorf("status = %q, want %q", status, RegressionInconclusive)
	}
}

func TestEvaluateRegression_CurrentUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustRegressionScenario(t)
	status, _, err := EvaluateRegression(scenario, wafval.VerdictBlocked, wafval.VerdictInconclusive)
	if err != nil {
		t.Fatalf("EvaluateRegression: %v", err)
	}
	if status != RegressionInconclusive {
		t.Errorf("status = %q, want %q", status, RegressionInconclusive)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafverify/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `regression.go`**

```go
// orchestrator/internal/wafverify/regression.go
// Package wafverify is a meta-validation layer covering waf.txt Phase
// 10's independent-verification-and-continuous-mastery items: regression
// suites, vendor/version benchmarks, finding reproduction, remediation
// retests, and coverage-quality gates. This is the final phase of the
// waf.txt 10-phase roadmap. Unlike every attack-content phase, it is
// generic over any already-computed wafval.Verdict regardless of which
// attack vector, evasion technique, or profile produced it, so it
// depends only on internal/wafval and never cross-references
// internal/wafcatalog or any sibling WAF-phase package. There is no
// cross-run persistence here: "before/after" is expressed purely as two
// function arguments, never a stored history.
package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// verdictRank orders ClaimPrevention-shaped verdicts only: Missed (0) <
// DetectedButAllowed (1) < Blocked (2). VerdictAllowed and
// VerdictIncorrectlyBlocked are ClaimFalsePositive-shaped -- their
// "better" direction runs the opposite way, so mixing them onto this
// scale would conflate two different claim types. VerdictInconclusive
// has no direction at all. All three report ok=false rather than
// falling through to a default rank.
func verdictRank(v wafval.Verdict) (rank int, ok bool) {
	switch v {
	case wafval.VerdictMissed:
		return 0, true
	case wafval.VerdictDetectedButAllowed:
		return 1, true
	case wafval.VerdictBlocked:
		return 2, true
	default:
		return 0, false
	}
}

// RegressionScenario is the claim that a scenario's verdict stays
// stable (or improves) over time, rather than silently regressing.
type RegressionScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewRegressionScenario validates at construction time, never at render
// time.
func NewRegressionScenario(id string, description string, provenance string) (RegressionScenario, error) {
	if id == "" {
		return RegressionScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return RegressionScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return RegressionScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return RegressionScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// RegressionStatus is the outcome of comparing a baseline verdict
// against a current one for the same scenario.
type RegressionStatus string

const (
	RegressionStable       RegressionStatus = "stable"
	RegressionImproved     RegressionStatus = "improved"
	RegressionRegressed    RegressionStatus = "regressed"
	RegressionInconclusive RegressionStatus = "inconclusive"
)

// EvaluateRegression ranks both verdicts; either side unrankable
// resolves to RegressionInconclusive rather than guessing a direction.
func EvaluateRegression(scenario RegressionScenario, baseline wafval.Verdict, current wafval.Verdict) (RegressionStatus, string, error) {
	baselineRank, baselineOK := verdictRank(baseline)
	currentRank, currentOK := verdictRank(current)
	if !baselineOK || !currentOK {
		return RegressionInconclusive, fmt.Sprintf("baseline verdict %q or current verdict %q is not a ClaimPrevention-shaped verdict this comparison can rank", baseline, current), nil
	}
	switch {
	case currentRank < baselineRank:
		return RegressionRegressed, fmt.Sprintf("current verdict %q ranks below baseline verdict %q", current, baseline), nil
	case currentRank > baselineRank:
		return RegressionImproved, fmt.Sprintf("current verdict %q ranks above baseline verdict %q", current, baseline), nil
	default:
		return RegressionStable, fmt.Sprintf("current verdict %q matches baseline verdict %q", current, baseline), nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafverify/... -v`
Expected: PASS — all test functions pass.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafverify/regression.go orchestrator/internal/wafverify/regression_test.go
git commit -m "feat(wafverify): shared verdict ranking and regression shape"
```

---

### Task 2: Benchmark shape

**Files:**
- Create: `orchestrator/internal/wafverify/benchmark.go`
- Test: `orchestrator/internal/wafverify/benchmark_test.go`

**Interfaces:**
- Consumes: unexported `verdictRank` (Task 1, same package, no import); `wafval.Verdict` (+ `VerdictBlocked`, `VerdictMissed`, `VerdictAllowed`) — `internal/wafval`. No dependency on Task 1's `RegressionScenario`/`EvaluateRegression`.
- Produces: `BenchmarkScenario{ID, Description, Provenance string}`, `NewBenchmarkScenario(id string, description string, provenance string) (BenchmarkScenario, error)`, `VendorResult{Vendor, Version string, Verdict wafval.Verdict}`, `NewVendorResult(vendor string, version string, verdict wafval.Verdict) (VendorResult, error)`, `BenchmarkOutcome` (+ 4 constants: `BenchmarkStronger`, `BenchmarkWeaker`, `BenchmarkTied`, `BenchmarkInconclusive`), `EvaluateBenchmark(scenario BenchmarkScenario, a VendorResult, b VendorResult) (BenchmarkOutcome, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafverify/benchmark_test.go
package wafverify

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func mustBenchmarkScenario(t *testing.T) BenchmarkScenario {
	t.Helper()
	s, err := NewBenchmarkScenario("WAFVERIFY-002", "x", "y")
	if err != nil {
		t.Fatalf("NewBenchmarkScenario: %v", err)
	}
	return s
}

func TestNewBenchmarkScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewBenchmarkScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewVendorResult_EmptyVendor_Rejected(t *testing.T) {
	_, err := NewVendorResult("", "v1", wafval.VerdictBlocked)
	if err == nil {
		t.Fatal("want error for empty vendor, got nil")
	}
}

func TestNewVendorResult_EmptyVersion_Rejected(t *testing.T) {
	_, err := NewVendorResult("VendorA", "", wafval.VerdictBlocked)
	if err == nil {
		t.Fatal("want error for empty version, got nil")
	}
}

func mustVendorResult(t *testing.T, vendor string, verdict wafval.Verdict) VendorResult {
	t.Helper()
	v, err := NewVendorResult(vendor, "v1", verdict)
	if err != nil {
		t.Fatalf("NewVendorResult: %v", err)
	}
	return v
}

func TestEvaluateBenchmark_AStronger_ReturnsStrongerAndNamesBothVendors(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictBlocked)
	b := mustVendorResult(t, "VendorB", wafval.VerdictMissed)
	outcome, reason, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkStronger {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkStronger)
	}
	if !strings.Contains(reason, "VendorA") || !strings.Contains(reason, "VendorB") {
		t.Errorf("reason = %q, want it to name both VendorA and VendorB", reason)
	}
}

func TestEvaluateBenchmark_AWeaker_ReturnsWeaker(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictMissed)
	b := mustVendorResult(t, "VendorB", wafval.VerdictBlocked)
	outcome, _, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkWeaker {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkWeaker)
	}
}

func TestEvaluateBenchmark_EqualRanks_ReturnsTied(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictBlocked)
	b := mustVendorResult(t, "VendorB", wafval.VerdictBlocked)
	outcome, _, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkTied {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkTied)
	}
}

// Review Focus: an unrankable verdict on either side must trigger
// Inconclusive, not be silently ranked as 0.
func TestEvaluateBenchmark_AUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustBenchmarkScenario(t)
	a := mustVendorResult(t, "VendorA", wafval.VerdictAllowed)
	b := mustVendorResult(t, "VendorB", wafval.VerdictBlocked)
	outcome, _, err := EvaluateBenchmark(scenario, a, b)
	if err != nil {
		t.Fatalf("EvaluateBenchmark: %v", err)
	}
	if outcome != BenchmarkInconclusive {
		t.Errorf("outcome = %q, want %q", outcome, BenchmarkInconclusive)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafverify/... -run "TestNewBenchmarkScenario|TestNewVendorResult|TestEvaluateBenchmark" -v`
Expected: FAIL — `BenchmarkScenario`/`NewBenchmarkScenario`/`VendorResult`/`NewVendorResult`/`EvaluateBenchmark` undefined.

- [ ] **Step 3: Write `benchmark.go`**

```go
// orchestrator/internal/wafverify/benchmark.go
package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// BenchmarkScenario is the claim that two vendors' or versions' verdicts
// for the same scenario can be ranked against each other.
type BenchmarkScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewBenchmarkScenario validates at construction time, never at render
// time.
func NewBenchmarkScenario(id string, description string, provenance string) (BenchmarkScenario, error) {
	if id == "" {
		return BenchmarkScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return BenchmarkScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return BenchmarkScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return BenchmarkScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// VendorResult is one vendor's/version's verdict for a benchmark
// comparison.
type VendorResult struct {
	Vendor  string
	Version string
	Verdict wafval.Verdict
}

// NewVendorResult validates at construction time, never at render time.
func NewVendorResult(vendor string, version string, verdict wafval.Verdict) (VendorResult, error) {
	if vendor == "" {
		return VendorResult{}, fmt.Errorf("vendor must not be empty")
	}
	if version == "" {
		return VendorResult{}, fmt.Errorf("version must not be empty")
	}
	return VendorResult{Vendor: vendor, Version: version, Verdict: verdict}, nil
}

// BenchmarkOutcome is the outcome of comparing two VendorResults for the
// same scenario. Stronger/Weaker describe a relative to b.
type BenchmarkOutcome string

const (
	BenchmarkStronger     BenchmarkOutcome = "stronger"
	BenchmarkWeaker       BenchmarkOutcome = "weaker"
	BenchmarkTied         BenchmarkOutcome = "tied"
	BenchmarkInconclusive BenchmarkOutcome = "inconclusive"
)

// EvaluateBenchmark ranks both VendorResults' verdicts; either side
// unrankable resolves to BenchmarkInconclusive rather than guessing a
// direction.
func EvaluateBenchmark(scenario BenchmarkScenario, a VendorResult, b VendorResult) (BenchmarkOutcome, string, error) {
	aRank, aOK := verdictRank(a.Verdict)
	bRank, bOK := verdictRank(b.Verdict)
	if !aOK || !bOK {
		return BenchmarkInconclusive, fmt.Sprintf("%s %s's verdict %q or %s %s's verdict %q is not a ClaimPrevention-shaped verdict this comparison can rank", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	}
	switch {
	case aRank > bRank:
		return BenchmarkStronger, fmt.Sprintf("%s %s (%q) ranks above %s %s (%q)", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	case aRank < bRank:
		return BenchmarkWeaker, fmt.Sprintf("%s %s (%q) ranks below %s %s (%q)", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	default:
		return BenchmarkTied, fmt.Sprintf("%s %s (%q) ranks equal to %s %s (%q)", a.Vendor, a.Version, a.Verdict, b.Vendor, b.Version, b.Verdict), nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafverify/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafverify/benchmark.go orchestrator/internal/wafverify/benchmark_test.go
git commit -m "feat(wafverify): vendor/version benchmark shape"
```

---

### Task 3: Reproduction shape

**Files:**
- Create: `orchestrator/internal/wafverify/reproduction.go`
- Test: `orchestrator/internal/wafverify/reproduction_test.go`

**Interfaces:**
- Consumes: `wafval.Verdict` (+ `VerdictBlocked`, `VerdictMissed`, `VerdictAllowed`, `VerdictIncorrectlyBlocked`, `VerdictInconclusive`) — `internal/wafval`. No dependency on Tasks 1-2; does not use `verdictRank`.
- Produces: `ReproductionScenario{ID, Description, Provenance string}`, `NewReproductionScenario(id string, description string, provenance string) (ReproductionScenario, error)`, `ReproductionStatus` (+ 3 constants: `ReproductionConfirmed`, `ReproductionNotConfirmed`, `ReproductionInconclusive`), `EvaluateReproduction(scenario ReproductionScenario, original wafval.Verdict, attempt wafval.Verdict) (ReproductionStatus, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafverify/reproduction_test.go
package wafverify

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func mustReproductionScenario(t *testing.T) ReproductionScenario {
	t.Helper()
	s, err := NewReproductionScenario("WAFVERIFY-003", "x", "y")
	if err != nil {
		t.Fatalf("NewReproductionScenario: %v", err)
	}
	return s
}

func TestNewReproductionScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewReproductionScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestEvaluateReproduction_MatchingVerdicts_ReturnsConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, reason, err := EvaluateReproduction(scenario, wafval.VerdictBlocked, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionConfirmed)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateReproduction_DifferingVerdicts_ReturnsNotConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictBlocked, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionNotConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionNotConfirmed)
	}
}

func TestEvaluateReproduction_OriginalInconclusive_ReturnsInconclusive(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictInconclusive, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionInconclusive {
		t.Errorf("status = %q, want %q", status, ReproductionInconclusive)
	}
}

func TestEvaluateReproduction_AttemptInconclusive_ReturnsInconclusive(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictBlocked, wafval.VerdictInconclusive)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionInconclusive {
		t.Errorf("status = %q, want %q", status, ReproductionInconclusive)
	}
}

// Review Focus: this is the one shape that must work on a matching
// pair of ClaimFalsePositive-shaped verdicts, which the ranked shapes
// (Regression/Benchmark/Remediation) structurally cannot handle.
func TestEvaluateReproduction_MatchingFalsePositiveVerdicts_ReturnsConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictAllowed, wafval.VerdictAllowed)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionConfirmed)
	}
}

func TestEvaluateReproduction_MatchingIncorrectlyBlockedVerdicts_ReturnsConfirmed(t *testing.T) {
	scenario := mustReproductionScenario(t)
	status, _, err := EvaluateReproduction(scenario, wafval.VerdictIncorrectlyBlocked, wafval.VerdictIncorrectlyBlocked)
	if err != nil {
		t.Fatalf("EvaluateReproduction: %v", err)
	}
	if status != ReproductionConfirmed {
		t.Errorf("status = %q, want %q", status, ReproductionConfirmed)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafverify/... -run "TestNewReproductionScenario|TestEvaluateReproduction" -v`
Expected: FAIL — `ReproductionScenario`/`NewReproductionScenario`/`EvaluateReproduction` undefined.

- [ ] **Step 3: Write `reproduction.go`**

```go
// orchestrator/internal/wafverify/reproduction.go
package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// ReproductionScenario is the claim that a finding can be reproduced:
// re-running the same scenario produces the same verdict.
type ReproductionScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewReproductionScenario validates at construction time, never at
// render time.
func NewReproductionScenario(id string, description string, provenance string) (ReproductionScenario, error) {
	if id == "" {
		return ReproductionScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return ReproductionScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return ReproductionScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return ReproductionScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// ReproductionStatus is the outcome of comparing an original finding's
// verdict against a reproduction attempt's verdict.
type ReproductionStatus string

const (
	ReproductionConfirmed    ReproductionStatus = "confirmed"
	ReproductionNotConfirmed ReproductionStatus = "not_confirmed"
	ReproductionInconclusive ReproductionStatus = "inconclusive"
)

// EvaluateReproduction compares original and attempt by exact equality,
// not by rank -- reproducibility applies uniformly to any verdict,
// including ClaimFalsePositive-shaped ones, which the ranked shapes
// (Regression/Benchmark/Remediation) cannot handle. A VerdictInconclusive
// on either side has nothing to confirm or deny.
func EvaluateReproduction(scenario ReproductionScenario, original wafval.Verdict, attempt wafval.Verdict) (ReproductionStatus, string, error) {
	if original == wafval.VerdictInconclusive || attempt == wafval.VerdictInconclusive {
		return ReproductionInconclusive, fmt.Sprintf("original verdict %q or reproduction-attempt verdict %q is itself inconclusive; nothing to confirm or deny", original, attempt), nil
	}
	if original == attempt {
		return ReproductionConfirmed, fmt.Sprintf("reproduction attempt verdict %q matches the original finding's verdict %q", attempt, original), nil
	}
	return ReproductionNotConfirmed, fmt.Sprintf("reproduction attempt verdict %q does not match the original finding's verdict %q", attempt, original), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafverify/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafverify/reproduction.go orchestrator/internal/wafverify/reproduction_test.go
git commit -m "feat(wafverify): finding reproduction shape"
```

---

### Task 4: Remediation shape

**Files:**
- Create: `orchestrator/internal/wafverify/remediation.go`
- Test: `orchestrator/internal/wafverify/remediation_test.go`

**Interfaces:**
- Consumes: unexported `verdictRank` (Task 1, same package, no import); `wafval.Verdict` (+ `VerdictBlocked`, `VerdictMissed`, `VerdictAllowed`) — `internal/wafval`. No dependency on Tasks 2-3.
- Produces: `RemediationScenario{ID, Description, Provenance string}`, `NewRemediationScenario(id string, description string, provenance string) (RemediationScenario, error)`, `RemediationStatus` (+ 4 constants: `RemediationFixed`, `RemediationUnchanged`, `RemediationRegressed`, `RemediationInconclusive`), `EvaluateRemediation(scenario RemediationScenario, baseline wafval.Verdict, retest wafval.Verdict) (RemediationStatus, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafverify/remediation_test.go
package wafverify

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func mustRemediationScenario(t *testing.T) RemediationScenario {
	t.Helper()
	s, err := NewRemediationScenario("WAFVERIFY-004", "x", "y")
	if err != nil {
		t.Fatalf("NewRemediationScenario: %v", err)
	}
	return s
}

func TestNewRemediationScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewRemediationScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestEvaluateRemediation_RankIncrease_ReturnsFixed(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, reason, err := EvaluateRemediation(scenario, wafval.VerdictMissed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationFixed {
		t.Errorf("status = %q, want %q", status, RemediationFixed)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateRemediation_RankDecrease_ReturnsRegressed(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictBlocked, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationRegressed {
		t.Errorf("status = %q, want %q", status, RemediationRegressed)
	}
}

// Review Focus: Unchanged must be tested at the low end (still broken)...
func TestEvaluateRemediation_EqualRanksAtLowEnd_ReturnsUnchanged(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictMissed, wafval.VerdictMissed)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationUnchanged {
		t.Errorf("status = %q, want %q", status, RemediationUnchanged)
	}
}

// ...and at the high end (already fixed), to prove the label is
// neutral regardless of which rank the pair sits at.
func TestEvaluateRemediation_EqualRanksAtHighEnd_ReturnsUnchanged(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictBlocked, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationUnchanged {
		t.Errorf("status = %q, want %q", status, RemediationUnchanged)
	}
}

// Review Focus: an unrankable verdict on either side must trigger
// Inconclusive, not be silently ranked as 0.
func TestEvaluateRemediation_BaselineUnrankable_ReturnsInconclusive(t *testing.T) {
	scenario := mustRemediationScenario(t)
	status, _, err := EvaluateRemediation(scenario, wafval.VerdictAllowed, wafval.VerdictBlocked)
	if err != nil {
		t.Fatalf("EvaluateRemediation: %v", err)
	}
	if status != RemediationInconclusive {
		t.Errorf("status = %q, want %q", status, RemediationInconclusive)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafverify/... -run "TestNewRemediationScenario|TestEvaluateRemediation" -v`
Expected: FAIL — `RemediationScenario`/`NewRemediationScenario`/`EvaluateRemediation` undefined.

- [ ] **Step 3: Write `remediation.go`**

```go
// orchestrator/internal/wafverify/remediation.go
package wafverify

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// RemediationScenario is the claim that a previously-identified issue's
// fix can be confirmed by re-testing it.
type RemediationScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewRemediationScenario validates at construction time, never at
// render time.
func NewRemediationScenario(id string, description string, provenance string) (RemediationScenario, error) {
	if id == "" {
		return RemediationScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return RemediationScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return RemediationScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return RemediationScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// RemediationStatus is the outcome of comparing a baseline (pre-fix)
// verdict against a retest (post-fix) verdict. Unchanged is deliberately
// neutral: it applies whether the pair sits at a low (still-broken) or
// high (already-fixed) rank, never implying "still broken" on its own.
type RemediationStatus string

const (
	RemediationFixed        RemediationStatus = "fixed"
	RemediationUnchanged    RemediationStatus = "unchanged"
	RemediationRegressed    RemediationStatus = "regressed"
	RemediationInconclusive RemediationStatus = "inconclusive"
)

// EvaluateRemediation ranks both verdicts; either side unrankable
// resolves to RemediationInconclusive rather than guessing a direction.
func EvaluateRemediation(scenario RemediationScenario, baseline wafval.Verdict, retest wafval.Verdict) (RemediationStatus, string, error) {
	baselineRank, baselineOK := verdictRank(baseline)
	retestRank, retestOK := verdictRank(retest)
	if !baselineOK || !retestOK {
		return RemediationInconclusive, fmt.Sprintf("baseline verdict %q or retest verdict %q is not a ClaimPrevention-shaped verdict this comparison can rank", baseline, retest), nil
	}
	switch {
	case retestRank > baselineRank:
		return RemediationFixed, fmt.Sprintf("retest verdict %q ranks above baseline verdict %q", retest, baseline), nil
	case retestRank < baselineRank:
		return RemediationRegressed, fmt.Sprintf("retest verdict %q ranks below baseline verdict %q", retest, baseline), nil
	default:
		return RemediationUnchanged, fmt.Sprintf("retest verdict %q matches baseline verdict %q", retest, baseline), nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafverify/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafverify/remediation.go orchestrator/internal/wafverify/remediation_test.go
git commit -m "feat(wafverify): remediation retest shape"
```

---

### Task 5: Coverage gate shape and seed catalog

**Files:**
- Create: `orchestrator/internal/wafverify/coveragegate.go`, `orchestrator/internal/wafverify/catalog.go`
- Test: `orchestrator/internal/wafverify/coveragegate_test.go`, `orchestrator/internal/wafverify/catalog_test.go`

**Interfaces:**
- Consumes: `NewRegressionScenario` (Task 1), `NewBenchmarkScenario` (Task 2), `NewReproductionScenario` (Task 3), `NewRemediationScenario` (Task 4) — all same package, no import.
- Produces: `CoverageGateScenario{ID, Description, Provenance string, MinimumCoverage float64}`, `NewCoverageGateScenario(id string, description string, provenance string, minimumCoverage float64) (CoverageGateScenario, error)`, `CoverageGateStatus` (+ 3 constants: `CoverageGatePass`, `CoverageGateFail`, `CoverageGateInconclusive`), `EvaluateCoverageGate(scenario CoverageGateScenario, totalScenarios int, exercisedScenarios int) (CoverageGateStatus, string, error)`, `AudspectWAFVerifyCatalog() (regression []RegressionScenario, benchmark []BenchmarkScenario, reproduction []ReproductionScenario, remediation []RemediationScenario, coverageGate []CoverageGateScenario, err error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafverify/coveragegate_test.go
package wafverify

import "testing"

func TestNewCoverageGateScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewCoverageGateScenario("", "x", "y", 0.8)
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewCoverageGateScenario_NegativeMinimumCoverage_Rejected(t *testing.T) {
	_, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", -0.1)
	if err == nil {
		t.Fatal("want error for minimumCoverage < 0, got nil")
	}
}

func TestNewCoverageGateScenario_MinimumCoverageOverOne_Rejected(t *testing.T) {
	_, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", 1.1)
	if err == nil {
		t.Fatal("want error for minimumCoverage > 1, got nil")
	}
}

func TestNewCoverageGateScenario_ZeroMinimumCoverage_Succeeds(t *testing.T) {
	if _, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", 0.0); err != nil {
		t.Fatalf("NewCoverageGateScenario: %v", err)
	}
}

func TestNewCoverageGateScenario_OneMinimumCoverage_Succeeds(t *testing.T) {
	if _, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", 1.0); err != nil {
		t.Fatalf("NewCoverageGateScenario: %v", err)
	}
}

func mustCoverageGateScenario(t *testing.T, minimumCoverage float64) CoverageGateScenario {
	t.Helper()
	s, err := NewCoverageGateScenario("WAFVERIFY-005", "x", "y", minimumCoverage)
	if err != nil {
		t.Fatalf("NewCoverageGateScenario: %v", err)
	}
	return s
}

func TestEvaluateCoverageGate_NegativeExercised_ReturnsError(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	if _, _, err := EvaluateCoverageGate(scenario, 10, -1); err == nil {
		t.Fatal("want error for exercisedScenarios < 0, got nil")
	}
}

func TestEvaluateCoverageGate_ExercisedExceedsTotal_ReturnsError(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	if _, _, err := EvaluateCoverageGate(scenario, 10, 11); err == nil {
		t.Fatal("want error for exercisedScenarios > totalScenarios, got nil")
	}
}

func TestEvaluateCoverageGate_ZeroTotal_ReturnsInconclusiveNotError(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	status, _, err := EvaluateCoverageGate(scenario, 0, 0)
	if err != nil {
		t.Fatalf("EvaluateCoverageGate: %v", err)
	}
	if status != CoverageGateInconclusive {
		t.Errorf("status = %q, want %q", status, CoverageGateInconclusive)
	}
}

// Review Focus: the exact-equality boundary must resolve to Pass.
func TestEvaluateCoverageGate_RatioExactlyAtThreshold_ReturnsPass(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	status, reason, err := EvaluateCoverageGate(scenario, 10, 8)
	if err != nil {
		t.Fatalf("EvaluateCoverageGate: %v", err)
	}
	if status != CoverageGatePass {
		t.Errorf("status = %q, want %q", status, CoverageGatePass)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateCoverageGate_RatioBelowThreshold_ReturnsFail(t *testing.T) {
	scenario := mustCoverageGateScenario(t, 0.8)
	status, _, err := EvaluateCoverageGate(scenario, 10, 7)
	if err != nil {
		t.Fatalf("EvaluateCoverageGate: %v", err)
	}
	if status != CoverageGateFail {
		t.Errorf("status = %q, want %q", status, CoverageGateFail)
	}
}
```

```go
// orchestrator/internal/wafverify/catalog_test.go
package wafverify

import "testing"

func TestAudspectWAFVerifyCatalog_ReturnsFiveScenariosTotal(t *testing.T) {
	regression, benchmark, reproduction, remediation, coverageGate, err := AudspectWAFVerifyCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFVerifyCatalog: %v", err)
	}
	if len(regression) != 1 {
		t.Errorf("len(regression) = %d, want 1", len(regression))
	}
	if len(benchmark) != 1 {
		t.Errorf("len(benchmark) = %d, want 1", len(benchmark))
	}
	if len(reproduction) != 1 {
		t.Errorf("len(reproduction) = %d, want 1", len(reproduction))
	}
	if len(remediation) != 1 {
		t.Errorf("len(remediation) = %d, want 1", len(remediation))
	}
	if len(coverageGate) != 1 {
		t.Errorf("len(coverageGate) = %d, want 1", len(coverageGate))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafverify/... -run "TestNewCoverageGateScenario|TestEvaluateCoverageGate|TestAudspectWAFVerifyCatalog" -v`
Expected: FAIL — `CoverageGateScenario`/`NewCoverageGateScenario`/`EvaluateCoverageGate`/`AudspectWAFVerifyCatalog` undefined.

- [ ] **Step 3: Write `coveragegate.go`**

```go
// orchestrator/internal/wafverify/coveragegate.go
package wafverify

import "fmt"

// CoverageGateScenario is the claim that the testing program's own
// scenario coverage meets a declared minimum ratio.
type CoverageGateScenario struct {
	ID              string
	Description     string
	Provenance      string
	MinimumCoverage float64
}

// NewCoverageGateScenario validates at construction time, never at
// render time. minimumCoverage must be in [0.0, 1.0] inclusive.
func NewCoverageGateScenario(id string, description string, provenance string, minimumCoverage float64) (CoverageGateScenario, error) {
	if id == "" {
		return CoverageGateScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return CoverageGateScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return CoverageGateScenario{}, fmt.Errorf("provenance must not be empty")
	}
	if minimumCoverage < 0.0 || minimumCoverage > 1.0 {
		return CoverageGateScenario{}, fmt.Errorf("minimumCoverage must be in [0.0, 1.0], got %v", minimumCoverage)
	}
	return CoverageGateScenario{ID: id, Description: description, Provenance: provenance, MinimumCoverage: minimumCoverage}, nil
}

// CoverageGateStatus is the outcome of comparing exercised scenarios
// against total scenarios for a declared minimum ratio.
type CoverageGateStatus string

const (
	CoverageGatePass         CoverageGateStatus = "pass"
	CoverageGateFail         CoverageGateStatus = "fail"
	CoverageGateInconclusive CoverageGateStatus = "inconclusive"
)

// EvaluateCoverageGate errors on an invalid count pair (a caller bug,
// not a measurable outcome) but returns CoverageGateInconclusive as a
// normal status -- not an error -- for the degenerate totalScenarios<=0
// case, since a catalog of size zero is a real, if degenerate, state.
func EvaluateCoverageGate(scenario CoverageGateScenario, totalScenarios int, exercisedScenarios int) (CoverageGateStatus, string, error) {
	if exercisedScenarios < 0 {
		return "", "", fmt.Errorf("exercisedScenarios must not be negative, got %d", exercisedScenarios)
	}
	if exercisedScenarios > totalScenarios {
		return "", "", fmt.Errorf("exercisedScenarios (%d) must not exceed totalScenarios (%d)", exercisedScenarios, totalScenarios)
	}
	if totalScenarios <= 0 {
		return CoverageGateInconclusive, "totalScenarios is zero or negative; there is nothing to measure", nil
	}
	ratio := float64(exercisedScenarios) / float64(totalScenarios)
	if ratio >= scenario.MinimumCoverage {
		return CoverageGatePass, fmt.Sprintf("coverage ratio %.4f meets the minimum %.4f", ratio, scenario.MinimumCoverage), nil
	}
	return CoverageGateFail, fmt.Sprintf("coverage ratio %.4f is below the minimum %.4f", ratio, scenario.MinimumCoverage), nil
}
```

- [ ] **Step 4: Write `catalog.go`**

```go
// orchestrator/internal/wafverify/catalog.go
package wafverify

import "fmt"

// AudspectWAFVerifyCatalog returns Audspect's real, current seed
// independent-verification scenario set: one scenario per named item
// from waf.txt Phase 10, the final phase of the waf.txt roadmap.
func AudspectWAFVerifyCatalog() (regression []RegressionScenario, benchmark []BenchmarkScenario, reproduction []ReproductionScenario, remediation []RemediationScenario, coverageGate []CoverageGateScenario, err error) {
	r, err := NewRegressionScenario("WAFVERIFY-001",
		"a scenario's verdict must stay stable, or improve, across repeated runs over time -- a regression is a verdict that got worse without a code or policy change explaining why",
		"manually authored from waf.txt Phase 10's named regression-suites item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	b, err := NewBenchmarkScenario("WAFVERIFY-002",
		"two vendors' or two versions' verdicts for the same scenario can be ranked against each other to produce a comparative benchmark",
		"manually authored from waf.txt Phase 10's named vendor/version-benchmarks item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	rep, err := NewReproductionScenario("WAFVERIFY-003",
		"a finding must be reproducible: re-running the same scenario against the same target must produce the same verdict",
		"manually authored from waf.txt Phase 10's named finding-reproduction item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	rem, err := NewRemediationScenario("WAFVERIFY-004",
		"after a reported fix, re-testing the same scenario must show whether the verdict actually improved, stayed the same, or regressed",
		"manually authored from waf.txt Phase 10's named remediation-retests item")
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	cg, err := NewCoverageGateScenario("WAFVERIFY-005",
		"the testing program's own scenario coverage must meet a minimum ratio of exercised to total scenarios before its results can be trusted as representative",
		"manually authored from waf.txt Phase 10's named coverage-quality-gates item", 0.8)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("loading seed verify catalog: %w", err)
	}

	return []RegressionScenario{r}, []BenchmarkScenario{b}, []ReproductionScenario{rep}, []RemediationScenario{rem}, []CoverageGateScenario{cg}, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafverify/... -v`
Expected: PASS — every test in the package passes.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/wafverify/coveragegate.go orchestrator/internal/wafverify/coveragegate_test.go orchestrator/internal/wafverify/catalog.go orchestrator/internal/wafverify/catalog_test.go
git commit -m "feat(wafverify): coverage-quality gate shape and AudspectWAFVerifyCatalog seeding all 5 named items"
```
