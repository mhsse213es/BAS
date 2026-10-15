# Web Gateway BAS Mastery Phase 5 (Mastery Certification and Regression) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Satisfy Phase 5's two exit criteria. (1) At least one mutation test is proven to catch a deliberately-introduced regression and to confirm recovery after the fix. (2) Coverage reporting cites its denominator and exclusions on every report, never a bare percentage.

**Scope note, decided before writing this plan:** Phase 5's own Goal text also names false-positive tracking, reproducibility metrics, evidence-completeness auditing, and release gates. None of these are named in Phase 5's own Exit Criteria (§3) — the same Goal-text-vs-binding-exit-criteria distinction every prior phase in this initiative has drawn correctly for its own out-of-scope Goal text. This plan does not build them; they remain available for a future round when the user asks for them.

**Architecture:** Two genuinely separate deliverables.
- **Mutation testing (Task 1):** needs **zero new production code**. "Weaken a policy in a lab, verify the relevant scenario catches the regression, restore, verify recovery" maps directly onto this package's existing `FixtureGatewayProvider`/`VerifyHTTPExpectation` pipeline from Phase 1: a fixture's evidence record is the thing that gets "weakened" (flipped from `block` to `allow`), the existing, unmodified `VerifyHTTPExpectation` is the thing that must sense the regression, and flipping the fixture back is the "restore." This is the same "reuse the existing pipeline, add no new types" pattern Phase 2a's Task 1 and Phase 3's Task 1 already used for their own scenario proofs — it is a test-only file. No live vendor lab exists yet (Phase 2b is still blocked per `docs/webgw-mastery-qa-log.md`), so this is explicitly fixture-level mutation, documented as such, never claiming a live product was actually reconfigured.
- **Coverage reporting (Task 2):** new Go code — `CoverageReport`/`CoverageExclusion` types plus a `Summary()` method whose output format structurally cannot omit the denominator or the exclusions list, satisfying the spec's own quality-proof requirement ("no coverage percentage without a defined denominator and explicit exclusions") by construction rather than by convention. The test proving this uses this initiative's own real, current domain-coverage count — 9 of the 12 domains in the architecture spec's §5 Coverage Matrix are covered as of Phase 4 (01, 02, 03, 05, 06, 08, 09, 10, 11; domains 04 and 07 remain unbuilt, domain 12 is marked "Started," not fully covered, so it is counted as not-yet-covered rather than overclaimed) — never an invented example number. A second test uses the real Zscaler-`Unsupported` exclusion from Phase 4 as a genuine exclusion example, which is why `CoverageExclusion` is modeled generically (`ItemID`, not `DomainID`) — the denominator this package reports on is not only "domains," it already spans domains and vendors.

**Tech Stack:** Go standard library only — no new dependency, no live vendor integration (same discipline as every prior phase).

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` §3 Phase 5. Exit criteria: "at least one mutation test is proven to catch a deliberately-introduced regression and to confirm recovery after the fix; coverage reporting cites its denominator and exclusions on every report, never a bare percentage."

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other `github.com/audspect/bas/...` package — unchanged since Phase 1. Verify with `go list -deps ./internal/webgwefficacy/...` after Task 2; exactly one `github.com/audspect/bas/...` entry (itself).
- The 5-state `WebGWVerdict` is reused as-is wherever a verdict appears in this plan's code — the mutation test reuses the package's existing verdicts directly; no new verdict type is introduced anywhere.
- No live lab anywhere in this plan — mutation testing operates at the fixture level only, and is documented in its own test's doc comment as fixture-level, never implying a real product was reconfigured.
- No fabricated coverage numbers. The self-report test's domain count (9 of 12) must be traceable to the architecture spec's own current §5 Coverage Matrix as of this phase, not invented; if that matrix has changed by the time this task executes, re-derive the count from the matrix as it then reads and ledger the discrepancy as a ruling.

## Review Focus

1. **`CoverageReport.Summary()` must never emit a bare percentage** — its output must always state both the denominator (total count) and the exclusions list, even when there are zero exclusions (stating "none" explicitly, never omitting the clause).
2. **`CoverageReport.Summary()` must not divide by zero** when the total count is 0 — confirm a guard exists and is exercised by a test, not just assumed safe.
3. **The mutation test must prove all three states explicitly**, not just "fails when mutated": pre-mutation `Pass` (baseline), post-mutation `Fail` (regression caught), post-restore `Pass` (recovery confirmed) — the exit criterion names both "catch the regression" and "confirm recovery," and a test that only shows the middle state proves half the claim.
4. **The mutation test must reuse a real, already-verified `Verify*` function from an earlier phase** (`VerifyHTTPExpectation`), never a hand-built `VerdictDetail` literal standing in for one — otherwise it proves nothing about this harness's actual sensitivity to a real regression.
5. **`CoverageExclusion` must generalize across different kinds of denominator items** (domains, vendors), not assume only one — confirm its field is named and typed generically (`ItemID string`, not e.g. `DomainID string`), since the real exclusion example this plan uses (Zscaler) is a vendor, not a domain.

---

### Task 1: Mutation testing — prove the harness catches and recovers from a regression

**Files:**
- Create: `orchestrator/internal/webgwefficacy/mutation_test.go`

**Interfaces:**
- Consumes: `HTTPExpectation`, `HTTPObservation`, `TimeWindow`, `ExpectedBlock`, `VerdictPass`, `VerdictFail`, `NewFixtureGatewayProvider`, `GatewayEvidence`, `SourceFixture`, `VerifyHTTPExpectation` (all Phase 1, unmodified).
- Produces: nothing new — this task adds no production code and no new type. It is a standalone proof against Phase 1's existing, unmodified API, in the same spirit as Phase 2a's Task 1 and Phase 3's Task 1.

- [ ] **Step 1: Write the mutation test**

```go
package webgwefficacy

import (
	"testing"
	"time"
)

// TestMutationTesting_ProxyBypassRegression_CaughtAndRecovered proves
// Phase 5's own mutation-testing exit criterion end-to-end, entirely
// at the fixture level (no live vendor lab exists yet -- Phase 2b is
// still blocked per docs/webgw-mastery-qa-log.md; this test never
// claims a real product was reconfigured). It deliberately introduces
// a regression into a fixture-backed scenario's own evidence
// (simulating a policy weakening in a lab), confirms the harness's
// existing, UNMODIFIED VerifyHTTPExpectation pipeline actually senses
// it rather than staying green, then restores the evidence and
// confirms recovery.
func TestMutationTesting_ProxyBypassRegression_CaughtAndRecovered(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}

	// Baseline: the policy correctly blocks the DoH bypass attempt.
	healthyProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Timestamp: now, Source: SourceFixture},
	})
	baseline := VerifyHTTPExpectation(exp, HTTPObservation{}, healthyProvider, window)
	if baseline.Prevention.Verdict != VerdictPass {
		t.Fatalf("baseline Prevention.Verdict = %q, want %q -- the scenario must start healthy before mutation", baseline.Prevention.Verdict, VerdictPass)
	}

	// Mutation: simulate a policy regression in a lab -- the same
	// bypass attempt now gets allowed through.
	mutatedProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Timestamp: now, Source: SourceFixture},
	})
	mutated := VerifyHTTPExpectation(exp, HTTPObservation{}, mutatedProvider, window)
	if mutated.Prevention.Verdict != VerdictFail {
		t.Fatalf("mutated Prevention.Verdict = %q, want %q -- the harness must catch the deliberately-introduced regression, never stay green", mutated.Prevention.Verdict, VerdictFail)
	}

	// Recovery: restore the original policy, confirm the scenario
	// reports healthy again rather than assuming the fix worked.
	recovered := VerifyHTTPExpectation(exp, HTTPObservation{}, healthyProvider, window)
	if recovered.Prevention.Verdict != VerdictPass {
		t.Errorf("recovered Prevention.Verdict = %q, want %q -- recovery after the fix must be confirmed, not assumed", recovered.Prevention.Verdict, VerdictPass)
	}
}

// TestMutationTesting_FailClosedRegression_CaughtAndRecovered is a
// second, independent proof using a different capability
// (Phase 3's fail-open/fail-closed check) so the exit criterion's
// "proven" language rests on more than one code path.
func TestMutationTesting_FailClosedRegression_CaughtAndRecovered(t *testing.T) {
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}

	healthyProvider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	baseline := VerifyFailureModeExpectation(exp, healthyProvider, window)
	if baseline.Verdict != VerdictPass {
		t.Fatalf("baseline Verdict = %q, want %q", baseline.Verdict, VerdictPass)
	}

	mutatedProvider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailOpen, Timestamp: now, Source: SourceFixture},
	})
	mutated := VerifyFailureModeExpectation(exp, mutatedProvider, window)
	if mutated.Verdict != VerdictFail {
		t.Fatalf("mutated Verdict = %q, want %q -- the harness must catch the fail-open regression", mutated.Verdict, VerdictFail)
	}

	recovered := VerifyFailureModeExpectation(exp, healthyProvider, window)
	if recovered.Verdict != VerdictPass {
		t.Errorf("recovered Verdict = %q, want %q", recovered.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestMutationTesting -v`
Expected: PASS, both tests, against Phase 1/3's existing, unmodified code — no production code in this task.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/mutation_test.go
git commit -m "test(webgwefficacy): prove mutation testing catches and recovers from a regression"
```

---

### Task 2: Coverage reporting with explicit denominator and exclusions

**Files:**
- Create: `orchestrator/internal/webgwefficacy/coverage.go`
- Test: `orchestrator/internal/webgwefficacy/coverage_test.go`

**Interfaces:**
- Consumes: nothing from this package — `CoverageReport` reports on the package from the outside, it does not call into `VerifyHTTPExpectation` or any other function.
- Produces: `CoverageExclusion{ItemID, Reason}`, `CoverageReport{TotalItems, CoveredItems, Exclusions, GeneratedAt}`, `NewCoverageReport(totalItems, coveredItems int, exclusions []CoverageExclusion, generatedAt time.Time) CoverageReport`, `(CoverageReport) Summary() string` — this plan's terminal capability; no later task consumes it.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"strings"
	"testing"
	"time"
)

// TestCoverageReport_Summary_RealWebGWDomainCoverage_NineOfTwelve uses
// this initiative's own real, current domain-coverage count as of
// Phase 4 -- not an invented example. Per the architecture spec's §5
// Coverage Matrix: domains 01, 02, 03, 05, 06, 08, 09, 10, 11 are
// covered (9); domains 04 and 07 remain unbuilt, and domain 12 is
// marked "Started" (not fully covered), so the honest count is 9 of
// 12, with zero of the 12 domains individually excluded from this
// count.
func TestCoverageReport_Summary_RealWebGWDomainCoverage_NineOfTwelve(t *testing.T) {
	report := NewCoverageReport(12, 9, nil, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	summary := report.Summary()

	if !strings.Contains(summary, "9") || !strings.Contains(summary, "12") {
		t.Errorf("Summary() = %q, want it to state both covered (9) and total (12)", summary)
	}
	if !strings.Contains(summary, "exclusions: none") {
		t.Errorf("Summary() = %q, want it to explicitly state there are no exclusions, never omit the clause", summary)
	}
}

// TestCoverageReport_Summary_WithExclusions_CitesEachReason uses the
// real Zscaler-Unsupported exclusion from Phase 4
// (docs/webgw-mastery-qa-log.md item #3) as a genuine exclusion
// example -- proving CoverageExclusion generalizes beyond "domain"
// to any denominator item this package reports coverage over.
func TestCoverageReport_Summary_WithExclusions_CitesEachReason(t *testing.T) {
	exclusions := []CoverageExclusion{
		{ItemID: "zscaler", Reason: "no self-serve trial/signup; sales-gated"},
	}
	report := NewCoverageReport(6, 1, exclusions, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	summary := report.Summary()

	if !strings.Contains(summary, "zscaler") {
		t.Errorf("Summary() = %q, want it to name the excluded item", summary)
	}
	if !strings.Contains(summary, "sales-gated") {
		t.Errorf("Summary() = %q, want it to cite the exclusion's own reason", summary)
	}
}

// TestCoverageReport_Summary_ZeroTotalItems_NoPanic guards the
// percentage calculation's division against a zero denominator.
func TestCoverageReport_Summary_ZeroTotalItems_NoPanic(t *testing.T) {
	report := NewCoverageReport(0, 0, nil, time.Now())

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Summary() panicked on zero TotalItems: %v", r)
		}
	}()
	_ = report.Summary()
}

// TestCoverageReport_Summary_NeverBarePercentage confirms the
// rendered string is never JUST a percentage -- it must always carry
// the raw covered/total counts alongside any percentage figure.
func TestCoverageReport_Summary_NeverBarePercentage(t *testing.T) {
	report := NewCoverageReport(4, 2, nil, time.Now())
	summary := report.Summary()

	if !strings.Contains(summary, "2") || !strings.Contains(summary, "4") {
		t.Errorf("Summary() = %q, want the raw covered/total counts present alongside any percentage", summary)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestCoverageReport -v`
Expected: FAIL — `undefined: NewCoverageReport` (and related types).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"fmt"
	"strings"
	"time"
)

// CoverageExclusion is one denominator item (a domain, a vendor, or
// any other thing this package reports coverage over) that is
// deliberately excluded from a coverage count, together with why --
// generalized beyond "domain" because this package's own real
// exclusion examples span both domains and vendors (e.g. Zscaler,
// Phase 4).
type CoverageExclusion struct {
	ItemID string `json:"itemId"`
	Reason string `json:"reason"`
}

// CoverageReport is a coverage count with an explicit denominator and
// explicit exclusions attached -- never a bare percentage, per the
// architecture spec's own quality-proof requirement ("no coverage
// percentage without a defined denominator and explicit exclusions").
// This package never maintains its own hardcoded copy of "all WebGW
// domains" -- that list lives in the architecture spec's own Coverage
// Matrix (§5); callers derive TotalItems/CoveredItems from it rather
// than this package duplicating and drifting from it.
type CoverageReport struct {
	TotalItems   int                 `json:"totalItems"`
	CoveredItems int                 `json:"coveredItems"`
	Exclusions   []CoverageExclusion `json:"exclusions"`
	GeneratedAt  time.Time           `json:"generatedAt"`
}

func NewCoverageReport(totalItems, coveredItems int, exclusions []CoverageExclusion, generatedAt time.Time) CoverageReport {
	return CoverageReport{
		TotalItems:   totalItems,
		CoveredItems: coveredItems,
		Exclusions:   exclusions,
		GeneratedAt:  generatedAt,
	}
}

// Summary renders this report as a single human-readable line that
// always states its denominator and exclusions explicitly, by
// construction -- there is no code path that emits a percentage
// without also stating the raw counts and the exclusions clause.
func (r CoverageReport) Summary() string {
	pct := 0.0
	if r.TotalItems > 0 {
		pct = float64(r.CoveredItems) / float64(r.TotalItems) * 100
	}

	exclusionText := "none"
	if len(r.Exclusions) > 0 {
		reasons := make([]string, len(r.Exclusions))
		for i, e := range r.Exclusions {
			reasons[i] = fmt.Sprintf("%s (%s)", e.ItemID, e.Reason)
		}
		exclusionText = strings.Join(reasons, "; ")
	}

	return fmt.Sprintf(
		"%d/%d covered (%.1f%% of %d total); exclusions: %s; generated %s",
		r.CoveredItems, r.TotalItems, pct, r.TotalItems, exclusionText, r.GeneratedAt.Format(time.RFC3339),
	)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Phases 1-4 (67) plus Task 1's 2 and Task 2's 4 new tests (73 total).

- [ ] **Step 5: Verify the zero-import-dependency constraint**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/coverage.go internal/webgwefficacy/coverage_test.go
git commit -m "feat(webgwefficacy): add coverage reporting with explicit denominator and exclusions"
```

---

## Execution Handoff

Per the user's explicit instruction, this plan proceeds directly to Native inline execution without a separate approval checkpoint.
