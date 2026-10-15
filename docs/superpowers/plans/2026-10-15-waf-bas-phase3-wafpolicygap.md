# WAF BAS Mastery Phase 3: Configuration and Policy-Gap Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafpolicygap`, which drives Phase 2's catalog (`internal/wafcatalog`) through Phase 1's already-built two-leg policy-gap comparison (`wafval.Pair`/`EvaluatePolicyGap`), for configuration weaknesses that are a genuine baseline-vs-weakened comparison, plus a single-leg path for weaknesses that aren't.

**Architecture:** A pure-Go, I/O-free package depending one-way on both `internal/wafval` and `internal/wafcatalog` (`wafval` ← `wafcatalog` ← `wafpolicygap`). `PolicyGapScenario` is construction-validated against the real seed catalog (`wafcatalog.AudspectWAFAttackCatalog()`), never a fictional vector ID. Two evaluation functions, one per scenario shape, each pure orchestration over existing `wafval`/`wafcatalog` machinery — zero new verdict logic.

**Tech Stack:** Go 1.26.6, stdlib only, `internal/wafval` and `internal/wafcatalog` (both already merged, read-only dependencies).

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase3-wafpolicygap-design.md`

## Global Constraints

- Package `internal/wafpolicygap` depends on `internal/wafval` and `internal/wafcatalog`; neither ever depends back on it (spec §3).
- Zero new `wafval` verdict logic — this phase adds only new callers of what Phase 1 already built (spec §6, §11).
- `AttackVectorID` on every `PolicyGapScenario` must reference a real ID in `wafcatalog.AudspectWAFAttackCatalog()`, validated at construction (spec §5).
- Calling the wrong evaluation function for a scenario's shape (`EvaluatePairedScenario` on a single-leg weakness, or vice versa) returns an error, never a panic or a silently wrong result (spec §6).
- Fixture-backed only — no real HTTP, no ModSecurity in this phase (spec §2).
- `AudspectWAFPolicyGapCatalog()` ships exactly 6 scenarios, one per `WeaknessType`, per spec §8's table.
- **Lesson carried from Phase 2's Task 3 ruling:** every `wafval.Observation` literal in this plan's tests must explicitly set `Enforcement`/`Detection`/`Origin` to the appropriate `*Unknown` constant on axes a mechanism doesn't observe. Go's zero-value `""` is NOT `wafval`'s `Unknown` sentinel, and an omitted field is read as a known empty value, which can force a spurious cross-mechanism `Contradictory` resolution.

## Review Focus

- An `AttackVectorID` referencing a non-existent or retired vector ID must be rejected by `NewPolicyGapScenario`, not silently carried through to evaluation time where it would fail far from its actual cause. Pinned in Task 1.
- Calling `EvaluatePairedScenario` on a single-leg weakness scenario (or `EvaluateCoverageGapScenario` on a paired one) must return an error, not silently evaluate the wrong shape and produce a misleading verdict. Pinned in Task 3.
- A caller passing a `vector` whose `ID` doesn't match `scenario.AttackVectorID` is a real caller bug (wrong vector for this scenario) and must be rejected, not silently evaluated against the mismatched vector. Pinned in Task 3.
- A paired scenario with `policyDifferentiationConfirmed=false` must yield `Inconclusive` even when the two legs' responses visibly differ — this is the single most important "don't overclaim a policy gap" guarantee in the whole phase, and it must be re-pinned here, not just trusted from Phase 1's own tests. Pinned in Task 3.
- `AudspectWAFPolicyGapCatalog()` must genuinely cover all 6 distinct `WeaknessType` values (not, say, two scenarios of the same type and a gap elsewhere) — pinned in Task 4.

---

### Task 1: Core types and construction-time validation

**Files:**
- Create: `orchestrator/internal/wafpolicygap/types.go`
- Create: `orchestrator/internal/wafpolicygap/scenario.go`
- Test: `orchestrator/internal/wafpolicygap/scenario_test.go`

**Interfaces:**
- Consumes: `wafcatalog.AudspectWAFAttackCatalog() ([]wafcatalog.AttackVector, error)` (already merged, Phase 2) for cross-package ID validation.
- Produces: `WeaknessType` (+ 6 constants: `WeaknessDetectionOnlyMode`, `WeaknessExclusionRule`, `WeaknessOverlyBroadException`, `WeaknessPriorityConflict`, `WeaknessUnprotectedRoute`, `WeaknessMissingCoverage`), `(w WeaknessType) IsPaired() bool`, `PolicyGapScenario{ID, Weakness WeaknessType, AttackVectorID string, BaselinePolicyDescription, WeakenedPolicyDescription, Provenance string}`, `NewPolicyGapScenario(id string, weakness WeaknessType, attackVectorID string, baselineDesc, weakenedDesc, provenance string) (PolicyGapScenario, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafpolicygap/scenario_test.go
package wafpolicygap

import "testing"

func TestNewPolicyGapScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001",
		"OWASP CRS default anomaly-scoring mode, rule set enabled",
		"the matching rule for this payload was switched to detection-only (log, no block)",
		"manually authored")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario: %v", err)
	}
	if s.ID != "GAP-001" {
		t.Errorf("ID = %q, want %q", s.ID, "GAP-001")
	}
}

func TestNewPolicyGapScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("", WeaknessDetectionOnlyMode, "POLICY-001", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewPolicyGapScenario_UnknownWeakness_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessType("bogus_weakness"), "POLICY-001", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for unknown Weakness, got nil")
	}
}

// Review Focus: an AttackVectorID referencing a non-existent vector must be
// rejected at construction, not silently carried to evaluation time.
func TestNewPolicyGapScenario_UnknownAttackVectorID_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "FAKE-999", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for an AttackVectorID that does not exist in wafcatalog, got nil")
	}
}

func TestNewPolicyGapScenario_EmptyBaselineDesc_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001", "", "x", "x")
	if err == nil {
		t.Fatal("want error for empty BaselinePolicyDescription, got nil")
	}
}

func TestNewPolicyGapScenario_EmptyWeakenedDesc_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001", "x", "", "x")
	if err == nil {
		t.Fatal("want error for empty WeakenedPolicyDescription, got nil")
	}
}

func TestNewPolicyGapScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001", "x", "x", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestWeaknessType_IsPaired(t *testing.T) {
	paired := []WeaknessType{WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException, WeaknessPriorityConflict}
	for _, w := range paired {
		if !w.IsPaired() {
			t.Errorf("%q.IsPaired() = false, want true", w)
		}
	}
	singleLeg := []WeaknessType{WeaknessUnprotectedRoute, WeaknessMissingCoverage}
	for _, w := range singleLeg {
		if w.IsPaired() {
			t.Errorf("%q.IsPaired() = true, want false", w)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/wafpolicygap/types.go
// Package wafpolicygap drives internal/wafcatalog's attack vectors through
// internal/wafval's already-built two-leg policy-gap comparison
// (wafval.Pair/EvaluatePolicyGap), for configuration weaknesses that are a
// genuine baseline-vs-weakened comparison, plus a single-leg path for
// weaknesses that aren't. It depends on both wafval and wafcatalog;
// neither ever depends back on it. Zero new wafval verdict logic -- pure
// orchestration. Fixture-backed only; real execution is deferred.
package wafpolicygap

// WeaknessType is one of the six configuration-gap categories waf.txt names.
type WeaknessType string

const (
	WeaknessDetectionOnlyMode    WeaknessType = "detection_only_mode"
	WeaknessExclusionRule        WeaknessType = "exclusion_rule"
	WeaknessOverlyBroadException WeaknessType = "overly_broad_exception"
	WeaknessPriorityConflict     WeaknessType = "priority_conflict"
	WeaknessUnprotectedRoute     WeaknessType = "unprotected_route"
	WeaknessMissingCoverage      WeaknessType = "missing_coverage"
)

// IsPaired reports whether w is evaluated as a baseline-vs-weakened pair
// (via wafval.Pair/EvaluatePolicyGap) or as a single-leg coverage-absence
// check (via a direct wafval.EvaluateClaim call). Detection-only mode,
// exclusion rules, overly broad exceptions, and priority conflicts all
// describe a policy that used to block something and was changed -- a
// genuine two-leg comparison. Unprotected routes and missing coverage
// describe the absence of protection from the start -- there is no
// baseline leg where it was ever covered.
func (w WeaknessType) IsPaired() bool {
	switch w {
	case WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException, WeaknessPriorityConflict:
		return true
	default:
		return false
	}
}

// PolicyGapScenario declares one configuration-gap claim against a specific,
// real AttackVector from internal/wafcatalog. BaselinePolicyDescription
// describes the declared/expected policy state; WeakenedPolicyDescription
// describes the actual gap -- for a paired scenario, the weakening applied;
// for a single-leg scenario, what's actually missing.
type PolicyGapScenario struct {
	ID                        string
	Weakness                  WeaknessType
	AttackVectorID            string
	BaselinePolicyDescription string
	WeakenedPolicyDescription string
	Provenance                string
}
```

- [ ] **Step 4: Write `scenario.go`**

```go
// orchestrator/internal/wafpolicygap/scenario.go
package wafpolicygap

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

func validWeakness(w WeaknessType) bool {
	switch w {
	case WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException,
		WeaknessPriorityConflict, WeaknessUnprotectedRoute, WeaknessMissingCoverage:
		return true
	default:
		return false
	}
}

// NewPolicyGapScenario validates at construction time, never at evaluation
// time. attackVectorID must reference a real ID in
// wafcatalog.AudspectWAFAttackCatalog() -- a fictional or retired vector ID
// is rejected here, never silently carried to evaluation.
func NewPolicyGapScenario(
	id string,
	weakness WeaknessType,
	attackVectorID string,
	baselineDesc string,
	weakenedDesc string,
	provenance string,
) (PolicyGapScenario, error) {
	if id == "" {
		return PolicyGapScenario{}, fmt.Errorf("id must not be empty")
	}
	if !validWeakness(weakness) {
		return PolicyGapScenario{}, fmt.Errorf("weakness %q is not one of the known WeaknessType constants", weakness)
	}
	if attackVectorID == "" {
		return PolicyGapScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return PolicyGapScenario{}, fmt.Errorf("loading wafcatalog for cross-reference: %w", err)
	}
	found := false
	for _, v := range vectors {
		if v.ID == attackVectorID {
			found = true
			break
		}
	}
	if !found {
		return PolicyGapScenario{}, fmt.Errorf("attackVectorID %q does not exist in wafcatalog.AudspectWAFAttackCatalog()", attackVectorID)
	}
	if baselineDesc == "" {
		return PolicyGapScenario{}, fmt.Errorf("baselineDesc must not be empty")
	}
	if weakenedDesc == "" {
		return PolicyGapScenario{}, fmt.Errorf("weakenedDesc must not be empty")
	}
	if provenance == "" {
		return PolicyGapScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return PolicyGapScenario{
		ID: id, Weakness: weakness, AttackVectorID: attackVectorID,
		BaselinePolicyDescription: baselineDesc, WeakenedPolicyDescription: weakenedDesc, Provenance: provenance,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -v`
Expected: PASS — all 8 test functions pass (`TestWeaknessType_IsPaired` covers 6 sub-cases in two loops).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/wafpolicygap/types.go orchestrator/internal/wafpolicygap/scenario.go orchestrator/internal/wafpolicygap/scenario_test.go
git commit -m "feat(wafpolicygap): WeaknessType/PolicyGapScenario types and construction-time validation"
```

---

### Task 2: Catalog-wide ID uniqueness

**Files:**
- Create: `orchestrator/internal/wafpolicygap/validate.go`
- Test: `orchestrator/internal/wafpolicygap/validate_test.go`

**Interfaces:**
- Consumes: `PolicyGapScenario`, `NewPolicyGapScenario` (Task 1).
- Produces: `ValidatePolicyGapCatalog(scenarios []PolicyGapScenario) error`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafpolicygap/validate_test.go
package wafpolicygap

import "testing"

func mustScenario(t *testing.T, id string, attackVectorID string) PolicyGapScenario {
	t.Helper()
	s, err := NewPolicyGapScenario(id, WeaknessDetectionOnlyMode, attackVectorID, "x", "x", "x")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario(%q): %v", id, err)
	}
	return s
}

func TestValidatePolicyGapCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidatePolicyGapCatalog([]PolicyGapScenario{
		mustScenario(t, "GAP-001", "POLICY-001"),
		mustScenario(t, "GAP-002", "SQLI-001"),
	})
	if err != nil {
		t.Fatalf("ValidatePolicyGapCatalog: %v", err)
	}
}

func TestValidatePolicyGapCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidatePolicyGapCatalog([]PolicyGapScenario{
		mustScenario(t, "GAP-001", "POLICY-001"),
		mustScenario(t, "GAP-001", "SQLI-001"),
	})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidatePolicyGapCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidatePolicyGapCatalog(nil); err != nil {
		t.Fatalf("ValidatePolicyGapCatalog(nil): %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -run TestValidatePolicyGapCatalog -v`
Expected: FAIL — `ValidatePolicyGapCatalog` is undefined.

- [ ] **Step 3: Write `validate.go`**

```go
// orchestrator/internal/wafpolicygap/validate.go
package wafpolicygap

import "fmt"

// ValidatePolicyGapCatalog rejects a catalog containing two scenarios with
// the same ID. NewPolicyGapScenario cannot see sibling entries, so this is
// the single place uniqueness is enforced across a whole catalog snapshot.
func ValidatePolicyGapCatalog(scenarios []PolicyGapScenario) error {
	seen := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		if seen[s.ID] {
			return fmt.Errorf("duplicate policy-gap scenario ID %q", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -run TestValidatePolicyGapCatalog -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafpolicygap/validate.go orchestrator/internal/wafpolicygap/validate_test.go
git commit -m "feat(wafpolicygap): catalog-wide ID uniqueness validation"
```

---

### Task 3: Evaluation — paired and single-leg

**Files:**
- Create: `orchestrator/internal/wafpolicygap/evaluate.go`
- Test: `orchestrator/internal/wafpolicygap/evaluate_test.go`

**Interfaces:**
- Consumes: `PolicyGapScenario`, `WeaknessType.IsPaired()` (Task 1); `wafcatalog.AttackVector`, `wafcatalog.AudspectWAFAttackCatalog()` (already merged); `wafval.Pair{Baseline, Weakened wafval.Result, PolicyDifferentiationConfirmed bool}`, `wafval.EvaluatePolicyGap(p wafval.Pair) (wafval.Verdict, string)`, `wafval.EvaluateClaim(exp wafval.Expectation, results []wafval.CollectionResult, key wafval.CorrelationKey) wafval.Result`, `wafval.CollectionResult`, `wafval.Observation`, `wafval.CorrelationKey`, `wafval.TimeWindow`, `wafval.MechanismWAFEngine`, `wafval.MechanismOriginApp`, `wafval.CoverageFound`, `wafval.CoverageSearchedVerifiedNone`, `wafval.EnforcementBlocked`, `wafval.EnforcementAllowed`, `wafval.EnforcementUnknown`, `wafval.DetectionMatched`, `wafval.DetectionNotMatched`, `wafval.DetectionUnknown`, `wafval.OriginReceived`, `wafval.OriginUnknown`, `wafval.EvidenceObserved`, `wafval.VerdictMissed`, `wafval.VerdictInconclusive`, `wafval.CompletenessInsufficient` (all already merged, `internal/wafval`).
- Produces: `EvaluatePairedScenario(scenario PolicyGapScenario, vector wafcatalog.AttackVector, policyBasis string, baselineEvidence []wafval.CollectionResult, baselineKey wafval.CorrelationKey, weakenedEvidence []wafval.CollectionResult, weakenedKey wafval.CorrelationKey, policyDifferentiationConfirmed bool) (wafval.Verdict, string, error)`, `EvaluateCoverageGapScenario(scenario PolicyGapScenario, vector wafcatalog.AttackVector, policyBasis string, evidence []wafval.CollectionResult, key wafval.CorrelationKey) (wafval.Result, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafpolicygap/evaluate_test.go
package wafpolicygap

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func mustVectorByID(t *testing.T, id string) wafcatalog.AttackVector {
	t.Helper()
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %q not found in AudspectWAFAttackCatalog", id)
	return wafcatalog.AttackVector{}
}

func mustGAP001(t *testing.T) PolicyGapScenario {
	t.Helper()
	s, err := NewPolicyGapScenario("GAP-001", WeaknessDetectionOnlyMode, "POLICY-001",
		"OWASP CRS default anomaly-scoring mode, rule set enabled",
		"the matching rule for this payload was switched to detection-only (log, no block)",
		"manually authored")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario: %v", err)
	}
	return s
}

func mustGAP005(t *testing.T) PolicyGapScenario {
	t.Helper()
	s, err := NewPolicyGapScenario("GAP-005", WeaknessUnprotectedRoute, "SSRF-001",
		"declared policy: every API route sits behind the WAF",
		"this route was never added to the WAF's protected hostname/path set",
		"manually authored")
	if err != nil {
		t.Fatalf("NewPolicyGapScenario: %v", err)
	}
	return s
}

// Review Focus: calling EvaluatePairedScenario on a single-leg weakness
// must return an error, not silently evaluate the wrong shape.
func TestEvaluatePairedScenario_SingleLegScenario_ReturnsError(t *testing.T) {
	scenario := mustGAP005(t) // WeaknessUnprotectedRoute, not paired
	vector := mustVectorByID(t, "SSRF-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, _, err := EvaluatePairedScenario(scenario, vector, "pb", nil, key, nil, key, true)
	if err == nil {
		t.Fatal("want error for a single-leg scenario passed to EvaluatePairedScenario, got nil")
	}
}

// Review Focus: calling EvaluateCoverageGapScenario on a paired weakness
// must return an error, not silently evaluate the wrong shape.
func TestEvaluateCoverageGapScenario_PairedScenario_ReturnsError(t *testing.T) {
	scenario := mustGAP001(t) // WeaknessDetectionOnlyMode, paired
	vector := mustVectorByID(t, "POLICY-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, err := EvaluateCoverageGapScenario(scenario, vector, "pb", nil, key)
	if err == nil {
		t.Fatal("want error for a paired scenario passed to EvaluateCoverageGapScenario, got nil")
	}
}

// Review Focus: a vector whose ID doesn't match scenario.AttackVectorID is
// a caller bug and must be rejected.
func TestEvaluatePairedScenario_VectorIDMismatch_ReturnsError(t *testing.T) {
	scenario := mustGAP001(t) // references POLICY-001
	wrongVector := mustVectorByID(t, "SQLI-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, _, err := EvaluatePairedScenario(scenario, wrongVector, "pb", nil, key, nil, key, true)
	if err == nil {
		t.Fatal("want error when vector.ID does not match scenario.AttackVectorID, got nil")
	}
}

func TestEvaluateCoverageGapScenario_VectorIDMismatch_ReturnsError(t *testing.T) {
	scenario := mustGAP005(t) // references SSRF-001
	wrongVector := mustVectorByID(t, "SQLI-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	_, err := EvaluateCoverageGapScenario(scenario, wrongVector, "pb", nil, key)
	if err == nil {
		t.Fatal("want error when vector.ID does not match scenario.AttackVectorID, got nil")
	}
}

// TestEvaluatePairedScenario_GAP001_ConfirmedDifferentiation_YieldsMissed
// proves spec §10 acceptance gate item 6: a detection-only misconfiguration,
// confirmed in force, reads as a genuine policy-attributed Missed.
func TestEvaluatePairedScenario_GAP001_ConfirmedDifferentiation_YieldsMissed(t *testing.T) {
	scenario := mustGAP001(t)
	vector := mustVectorByID(t, "POLICY-001")
	now := time.Now()
	window := wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	baselineKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	weakenedKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	baselineEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "b1", RequestID: "r1", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	weakenedEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "w1", RequestID: "r2", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}

	verdict, reason, err := EvaluatePairedScenario(scenario, vector, "owasp-crs-default", baselineEvidence, baselineKey, weakenedEvidence, weakenedKey, true)
	if err != nil {
		t.Fatalf("EvaluatePairedScenario: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
	if reason == "" {
		t.Error("want a non-empty policy-attribution reason")
	}
}

// TestEvaluatePairedScenario_GAP001_UnconfirmedDifferentiation_YieldsInconclusive
// proves spec §10 acceptance gate item 7, and is the Review Focus item for
// this task: an unconfirmed policy change must never read as a real gap,
// even though the two legs visibly differ.
func TestEvaluatePairedScenario_GAP001_UnconfirmedDifferentiation_YieldsInconclusive(t *testing.T) {
	scenario := mustGAP001(t)
	vector := mustVectorByID(t, "POLICY-001")
	now := time.Now()
	window := wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	baselineKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	weakenedKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	baselineEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "b1", RequestID: "r1", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	weakenedEvidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "w1", RequestID: "r2", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}

	verdict, _, err := EvaluatePairedScenario(scenario, vector, "owasp-crs-default", baselineEvidence, baselineKey, weakenedEvidence, weakenedKey, false)
	if err != nil {
		t.Fatalf("EvaluatePairedScenario: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- an unconfirmed policy differentiation must never read as a real gap", verdict, wafval.VerdictInconclusive)
	}
}

// TestEvaluateCoverageGapScenario_GAP005_NoWAFCoverage_YieldsInconclusive
// proves spec §10 acceptance gate item 8: a route with no WAF evidence at
// all is an Inconclusive finding, never a false "missed".
func TestEvaluateCoverageGapScenario_GAP005_NoWAFCoverage_YieldsInconclusive(t *testing.T) {
	scenario := mustGAP005(t)
	vector := mustVectorByID(t, "SSRF-001")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	evidence := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismOriginApp, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismOriginApp, EventID: "o1", RequestID: "r1", ObservedAt: now, Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginReceived, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result, err := EvaluateCoverageGapScenario(scenario, vector, "owasp-crs-default", evidence, key)
	if err != nil {
		t.Fatalf("EvaluateCoverageGapScenario: %v", err)
	}
	if result.Verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- no WAF-engine evidence at all means the route's coverage cannot be assessed, not that the attack was missed", result.Verdict, wafval.VerdictInconclusive)
	}
	if result.Completeness != wafval.CompletenessInsufficient {
		t.Errorf("Completeness = %q, want %q", result.Completeness, wafval.CompletenessInsufficient)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -run "TestEvaluatePairedScenario|TestEvaluateCoverageGapScenario" -v`
Expected: FAIL — `EvaluatePairedScenario`/`EvaluateCoverageGapScenario` are undefined.

- [ ] **Step 3: Write `evaluate.go`**

```go
// orchestrator/internal/wafpolicygap/evaluate.go
package wafpolicygap

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func checkVectorMatch(scenario PolicyGapScenario, vector wafcatalog.AttackVector) error {
	if vector.ID != scenario.AttackVectorID {
		return fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	return nil
}

// EvaluatePairedScenario drives scenario's referenced vector's malicious leg
// through baseline and weakened evidence, then wafval.EvaluatePolicyGap.
func EvaluatePairedScenario(
	scenario PolicyGapScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	baselineEvidence []wafval.CollectionResult,
	baselineKey wafval.CorrelationKey,
	weakenedEvidence []wafval.CollectionResult,
	weakenedKey wafval.CorrelationKey,
	policyDifferentiationConfirmed bool,
) (wafval.Verdict, string, error) {
	if !scenario.Weakness.IsPaired() {
		return "", "", fmt.Errorf("scenario %q has weakness %q, which is not a paired weakness -- use EvaluateCoverageGapScenario", scenario.ID, scenario.Weakness)
	}
	if err := checkVectorMatch(scenario, vector); err != nil {
		return "", "", err
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	baseline := wafval.EvaluateClaim(maliciousExpectation, baselineEvidence, baselineKey)
	weakened := wafval.EvaluateClaim(maliciousExpectation, weakenedEvidence, weakenedKey)
	pair := wafval.Pair{Baseline: baseline, Weakened: weakened, PolicyDifferentiationConfirmed: policyDifferentiationConfirmed}
	verdict, reason := wafval.EvaluatePolicyGap(pair)
	return verdict, reason, nil
}

// EvaluateCoverageGapScenario drives scenario's referenced vector's
// malicious leg through a single evidence set via wafval.EvaluateClaim.
func EvaluateCoverageGapScenario(
	scenario PolicyGapScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	evidence []wafval.CollectionResult,
	key wafval.CorrelationKey,
) (wafval.Result, error) {
	if scenario.Weakness.IsPaired() {
		return wafval.Result{}, fmt.Errorf("scenario %q has weakness %q, which is a paired weakness -- use EvaluatePairedScenario", scenario.ID, scenario.Weakness)
	}
	if err := checkVectorMatch(scenario, vector); err != nil {
		return wafval.Result{}, err
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	return wafval.EvaluateClaim(maliciousExpectation, evidence, key), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -run "TestEvaluatePairedScenario|TestEvaluateCoverageGapScenario" -v`
Expected: PASS (7/7).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafpolicygap/evaluate.go orchestrator/internal/wafpolicygap/evaluate_test.go
git commit -m "feat(wafpolicygap): paired and single-leg scenario evaluation"
```

---

### Task 4: Seed scenario catalog

**Files:**
- Create: `orchestrator/internal/wafpolicygap/catalog.go`
- Test: `orchestrator/internal/wafpolicygap/catalog_test.go`

**Interfaces:**
- Consumes: `PolicyGapScenario`, `NewPolicyGapScenario`, all 6 `WeaknessType` constants (Task 1); `ValidatePolicyGapCatalog` (Task 2).
- Produces: `AudspectWAFPolicyGapCatalog() ([]PolicyGapScenario, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafpolicygap/catalog_test.go
package wafpolicygap

import "testing"

func TestAudspectWAFPolicyGapCatalog_ReturnsSixScenarios(t *testing.T) {
	scenarios, err := AudspectWAFPolicyGapCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFPolicyGapCatalog: %v", err)
	}
	if len(scenarios) != 6 {
		t.Fatalf("len(scenarios) = %d, want 6", len(scenarios))
	}
	if err := ValidatePolicyGapCatalog(scenarios); err != nil {
		t.Errorf("ValidatePolicyGapCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 6 distinct weakness types, not
// duplicate one and skip another.
func TestAudspectWAFPolicyGapCatalog_CoversAllSixWeaknessTypes(t *testing.T) {
	scenarios, err := AudspectWAFPolicyGapCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFPolicyGapCatalog: %v", err)
	}
	want := []WeaknessType{
		WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException,
		WeaknessPriorityConflict, WeaknessUnprotectedRoute, WeaknessMissingCoverage,
	}
	seen := make(map[WeaknessType]int)
	for _, s := range scenarios {
		seen[s.Weakness]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("weakness %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -run TestAudspectWAFPolicyGapCatalog -v`
Expected: FAIL — `AudspectWAFPolicyGapCatalog` is undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafpolicygap/catalog.go
package wafpolicygap

import "fmt"

// AudspectWAFPolicyGapCatalog returns Audspect's real, current seed
// policy-gap scenario catalog: exactly one scenario per WeaknessType,
// validated before being returned.
func AudspectWAFPolicyGapCatalog() ([]PolicyGapScenario, error) {
	type seed struct {
		id, weaknessID, attackVectorID, baselineDesc, weakenedDesc, provenance string
		weakness                                                              WeaknessType
	}
	seeds := []seed{
		{
			id: "GAP-001", weakness: WeaknessDetectionOnlyMode, attackVectorID: "POLICY-001",
			baselineDesc: "OWASP CRS default anomaly-scoring mode, rule set enabled",
			weakenedDesc: "the matching rule for this payload was switched to detection-only (log, no block)",
			provenance:   "manually authored from waf.txt Phase 3's named weak-mode category",
		},
		{
			id: "GAP-002", weakness: WeaknessExclusionRule, attackVectorID: "SQLI-001",
			baselineDesc: "the SQLi rule set applies to this endpoint's query parameters with no exclusions",
			weakenedDesc: "a targeted per-rule exclusion was added for this specific SQLi signature on this endpoint",
			provenance:   "manually authored from waf.txt Phase 3's named exclusion category",
		},
		{
			id: "GAP-003", weakness: WeaknessOverlyBroadException, attackVectorID: "POLICY-002",
			baselineDesc: "every API route, including legacy ones, is inspected by the WAF",
			weakenedDesc: "an overly broad legacy-compatibility exception exempts an entire API path prefix from inspection",
			provenance:   "manually authored from waf.txt Phase 3's named overly-broad-exception category",
		},
		{
			id: "GAP-004", weakness: WeaknessPriorityConflict, attackVectorID: "XSS-001",
			baselineDesc: "the block rule for this XSS signature is declared to evaluate before any allow/exception rule",
			weakenedDesc: "a lower-priority allow-rule was misconfigured to evaluate before the higher-priority block-rule, causing a bypass",
			provenance:   "manually authored from waf.txt Phase 3's named priority-conflict category",
		},
		{
			id: "GAP-005", weakness: WeaknessUnprotectedRoute, attackVectorID: "SSRF-001",
			baselineDesc: "declared policy: every API route, including webhook endpoints, sits behind the WAF",
			weakenedDesc: "this route was never added to the WAF's protected hostname/path set",
			provenance:   "manually authored from waf.txt Phase 3's named unprotected-route category",
		},
		{
			id: "GAP-006", weakness: WeaknessMissingCoverage, attackVectorID: "API-001",
			baselineDesc: "declared policy: all API routes under /api/ are covered by the WAF's API-abuse rule set",
			weakenedDesc: "this specific route was added to the application after the WAF policy was last updated, and the policy was never revised to cover it",
			provenance:   "manually authored from waf.txt Phase 3's named missing-coverage category",
		},
	}

	var out []PolicyGapScenario
	for _, sd := range seeds {
		s, err := NewPolicyGapScenario(sd.id, sd.weakness, sd.attackVectorID, sd.baselineDesc, sd.weakenedDesc, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed policy-gap catalog: %w", err)
		}
		out = append(out, s)
	}

	if err := ValidatePolicyGapCatalog(out); err != nil {
		return nil, fmt.Errorf("seed policy-gap catalog failed validation: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafpolicygap/... -v`
Expected: PASS — every test in the package passes, including every earlier task's tests run together for the first time.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafpolicygap/catalog.go orchestrator/internal/wafpolicygap/catalog_test.go
git commit -m "feat(wafpolicygap): AudspectWAFPolicyGapCatalog seeding all 6 weakness types"
```
