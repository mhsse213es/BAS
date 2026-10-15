# WAF BAS Mastery Phase 4: Protocol, Parser and Evasion Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafevasion`, which compares a canonical malicious payload against a wire-level evasive re-encoding of the same attack, using `wafval.EvaluateClaim` for each leg and a new package-local decision rule (`EvaluateEvasionGap`) for the comparison itself — distinct from Phase 3's reused `wafval.Pair`/`EvaluatePolicyGap` because this phase's attribution story (origin-equivalence of an encoding) is different from Phase 3's (a confirmed policy change).

**Architecture:** A pure-Go, I/O-free package depending one-way on `internal/wafval` and `internal/wafcatalog` (`wafval` ← `wafcatalog` ← `wafevasion`), independent of `internal/wafpolicygap`. `EvasionScenario` is construction-validated against the real seed catalog (`wafcatalog.AudspectWAFAttackCatalog()`). Unlike Phase 3, there is exactly one evaluation function — every evasion technique is inherently a two-leg (canonical vs. evasive) comparison, so there is no paired/single-leg split.

**Tech Stack:** Go 1.26.6, stdlib only, `internal/wafval` and `internal/wafcatalog` (both already merged, read-only dependencies).

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase4-wafevasion-design.md`

## Global Constraints

- Package `internal/wafevasion` depends on `internal/wafval` and `internal/wafcatalog`; neither ever depends back on it, and it does not depend on `internal/wafpolicygap` (spec §2).
- Zero new `wafval` verdict logic — `EvaluateEvasionGap`'s decision rule lives entirely in `wafevasion`, built from `wafval.EvaluateClaim`'s existing output (spec §3, §9).
- `AttackVectorID` on every `EvasionScenario` must reference a real ID in `wafcatalog.AudspectWAFAttackCatalog()`, validated at construction (spec §4).
- With `originEquivalenceConfirmed = false`, `EvaluateEvasionGap` must return `Inconclusive` even when the two legs' fixture evidence visibly differs (spec §8 item 4).
- A canonical leg that was never reliably blocked (not `VerdictBlocked` with `Confidence` High or Medium) must resolve to `Inconclusive`, never a false bypass or a false "no gap" (spec §8 item 5).
- Fixture-backed only — no real HTTP, no real WAF/browser normalization behavior in this phase (spec §2, §9).
- `AudspectWAFEvasionCatalog()` ships exactly 6 scenarios, one per `EvasionTechnique`, per spec §7's table.
- **Lesson carried from Phase 2 and Phase 3:** every `wafval.Observation` literal in this plan's tests must explicitly set `Enforcement`/`Detection`/`Origin` to the appropriate `*Unknown` constant on axes a mechanism doesn't observe. Go's zero-value `""` is NOT `wafval`'s `Unknown` sentinel, and an omitted field is read as a known empty value, which can force a spurious cross-mechanism `Contradictory` resolution.

## Review Focus

- An `AttackVectorID` referencing a non-existent or retired vector ID must be rejected by `NewEvasionScenario`, not silently carried through to evaluation time. Pinned in Task 1.
- `originEquivalenceConfirmed = false` must yield `Inconclusive` even when the canonical and evasive legs visibly differ — this is the single most important "don't overclaim an evasion bypass" guarantee in the whole phase, directly carried forward from the same lesson in Phase 3's unconfirmed-differentiation guarantee. Pinned in Task 3.
- A canonical leg that was never reliably blocked to begin with (the WAF didn't even catch the plain-form attack) must resolve to `Inconclusive`, not be silently read as "no evasion gap" — that would overstate the WAF's actual coverage. Pinned in Task 3.
- A caller passing a `vector` whose `ID` doesn't match `scenario.AttackVectorID` is a real caller bug and must be rejected, not silently evaluated against the mismatched vector. Pinned in Task 3.
- `AudspectWAFEvasionCatalog()` must genuinely cover all 6 distinct `EvasionTechnique` values (not, say, two scenarios of the same technique and a gap elsewhere). Pinned in Task 4.

---

### Task 1: Core types and construction-time validation

**Files:**
- Create: `orchestrator/internal/wafevasion/types.go`
- Create: `orchestrator/internal/wafevasion/scenario.go`
- Test: `orchestrator/internal/wafevasion/scenario_test.go`

**Interfaces:**
- Consumes: `wafcatalog.AudspectWAFAttackCatalog() ([]wafcatalog.AttackVector, error)` (already merged, Phase 2) for cross-package ID validation.
- Produces: `EvasionTechnique` (+ 6 constants: `EvasionEncodingObfuscation`, `EvasionNormalizationMismatch`, `EvasionContentTypeConfusion`, `EvasionHTTPDiscrepancy`, `EvasionMultipartBoundaryManipulation`, `EvasionRequestBoundaryAbuse`), `EvasionScenario{ID, Technique EvasionTechnique, AttackVectorID, CanonicalPayloadDescription, EvasivePayloadDescription, OriginEquivalenceRationale, Provenance string}`, `NewEvasionScenario(id string, technique EvasionTechnique, attackVectorID string, canonicalDesc, evasiveDesc, originEquivalenceRationale, provenance string) (EvasionScenario, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafevasion/scenario_test.go
package wafevasion

import "testing"

func TestNewEvasionScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002",
		"plain SQLi payload in the query parameter",
		"the identical SQLi payload, double-URL-encoded",
		"the origin application URL-decodes query parameters twice before passing them to the query layer, so the double-encoded form decodes to the identical payload",
		"manually authored")
	if err != nil {
		t.Fatalf("NewEvasionScenario: %v", err)
	}
	if s.ID != "EVADE-001" {
		t.Errorf("ID = %q, want %q", s.ID, "EVADE-001")
	}
}

func TestNewEvasionScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("", EvasionEncodingObfuscation, "SQLI-002", "x", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewEvasionScenario_UnknownTechnique_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionTechnique("bogus_technique"), "SQLI-002", "x", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for unknown Technique, got nil")
	}
}

// Review Focus: an AttackVectorID referencing a non-existent vector must be
// rejected at construction, not silently carried to evaluation time.
func TestNewEvasionScenario_UnknownAttackVectorID_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "FAKE-999", "x", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for an AttackVectorID that does not exist in wafcatalog, got nil")
	}
}

func TestNewEvasionScenario_EmptyCanonicalDesc_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for empty CanonicalPayloadDescription, got nil")
	}
}

func TestNewEvasionScenario_EmptyEvasiveDesc_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "x", "", "x", "x")
	if err == nil {
		t.Fatal("want error for empty EvasivePayloadDescription, got nil")
	}
}

func TestNewEvasionScenario_EmptyOriginEquivalenceRationale_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "x", "x", "", "x")
	if err == nil {
		t.Fatal("want error for empty OriginEquivalenceRationale, got nil")
	}
}

func TestNewEvasionScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "x", "x", "x", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestEvasionTechnique_AllSixConstantsDistinct(t *testing.T) {
	all := []EvasionTechnique{
		EvasionEncodingObfuscation, EvasionNormalizationMismatch, EvasionContentTypeConfusion,
		EvasionHTTPDiscrepancy, EvasionMultipartBoundaryManipulation, EvasionRequestBoundaryAbuse,
	}
	seen := make(map[EvasionTechnique]bool)
	for _, t2 := range all {
		if seen[t2] {
			t.Errorf("duplicate EvasionTechnique value %q", t2)
		}
		seen[t2] = true
	}
	if len(seen) != 6 {
		t.Errorf("len(seen) = %d, want 6", len(seen))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafevasion/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/wafevasion/types.go
// Package wafevasion compares a canonical malicious payload against a
// wire-level evasive re-encoding of the same attack: does a WAF that
// reliably blocks the canonical form still catch the re-encoded
// equivalent? It depends on wafval and wafcatalog; neither ever depends
// back on it, and it does not depend on internal/wafpolicygap -- the two
// phases are independent consumers of the same two lower layers, not a
// chain. EvaluateEvasionGap's decision rule lives entirely here, built
// from wafval.EvaluateClaim's existing output -- zero new wafval verdict
// logic. Fixture-backed only; real execution is deferred.
package wafevasion

// EvasionTechnique is one of the six protocol/parser evasion categories
// waf.txt names, each a distinct way a malicious payload can be
// re-expressed at the wire level without changing what the origin
// application ultimately executes.
type EvasionTechnique string

const (
	EvasionEncodingObfuscation           EvasionTechnique = "encoding_obfuscation"
	EvasionNormalizationMismatch         EvasionTechnique = "normalization_mismatch"
	EvasionContentTypeConfusion          EvasionTechnique = "content_type_confusion"
	EvasionHTTPDiscrepancy               EvasionTechnique = "http_discrepancy"
	EvasionMultipartBoundaryManipulation EvasionTechnique = "multipart_boundary_manipulation"
	EvasionRequestBoundaryAbuse          EvasionTechnique = "request_boundary_abuse"
)

// EvasionScenario declares one evasion-technique claim against a specific,
// real AttackVector from internal/wafcatalog. OriginEquivalenceRationale is
// mandatory and distinct from the two payload descriptions: it is the
// documented reason the evasive encoding is expected to decode to the
// identical attack at the origin -- the thing that makes a divergence in
// WAF behavior attributable to the technique rather than to a different
// attack.
type EvasionScenario struct {
	ID                          string
	Technique                   EvasionTechnique
	AttackVectorID              string
	CanonicalPayloadDescription string
	EvasivePayloadDescription   string
	OriginEquivalenceRationale  string
	Provenance                  string
}
```

- [ ] **Step 4: Write `scenario.go`**

```go
// orchestrator/internal/wafevasion/scenario.go
package wafevasion

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

func validTechnique(t EvasionTechnique) bool {
	switch t {
	case EvasionEncodingObfuscation, EvasionNormalizationMismatch, EvasionContentTypeConfusion,
		EvasionHTTPDiscrepancy, EvasionMultipartBoundaryManipulation, EvasionRequestBoundaryAbuse:
		return true
	default:
		return false
	}
}

// NewEvasionScenario validates at construction time, never at evaluation
// time. attackVectorID must reference a real ID in
// wafcatalog.AudspectWAFAttackCatalog() -- a fictional or retired vector ID
// is rejected here, never silently carried to evaluation.
func NewEvasionScenario(
	id string,
	technique EvasionTechnique,
	attackVectorID string,
	canonicalDesc string,
	evasiveDesc string,
	originEquivalenceRationale string,
	provenance string,
) (EvasionScenario, error) {
	if id == "" {
		return EvasionScenario{}, fmt.Errorf("id must not be empty")
	}
	if !validTechnique(technique) {
		return EvasionScenario{}, fmt.Errorf("technique %q is not one of the known EvasionTechnique constants", technique)
	}
	if attackVectorID == "" {
		return EvasionScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EvasionScenario{}, fmt.Errorf("loading wafcatalog for cross-reference: %w", err)
	}
	found := false
	for _, v := range vectors {
		if v.ID == attackVectorID {
			found = true
			break
		}
	}
	if !found {
		return EvasionScenario{}, fmt.Errorf("attackVectorID %q does not exist in wafcatalog.AudspectWAFAttackCatalog()", attackVectorID)
	}
	if canonicalDesc == "" {
		return EvasionScenario{}, fmt.Errorf("canonicalDesc must not be empty")
	}
	if evasiveDesc == "" {
		return EvasionScenario{}, fmt.Errorf("evasiveDesc must not be empty")
	}
	if originEquivalenceRationale == "" {
		return EvasionScenario{}, fmt.Errorf("originEquivalenceRationale must not be empty")
	}
	if provenance == "" {
		return EvasionScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return EvasionScenario{
		ID: id, Technique: technique, AttackVectorID: attackVectorID,
		CanonicalPayloadDescription: canonicalDesc, EvasivePayloadDescription: evasiveDesc,
		OriginEquivalenceRationale: originEquivalenceRationale, Provenance: provenance,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafevasion/... -v`
Expected: PASS — all 9 test functions pass.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/wafevasion/types.go orchestrator/internal/wafevasion/scenario.go orchestrator/internal/wafevasion/scenario_test.go
git commit -m "feat(wafevasion): EvasionTechnique/EvasionScenario types and construction-time validation"
```

---

### Task 2: Catalog-wide ID uniqueness

**Files:**
- Create: `orchestrator/internal/wafevasion/validate.go`
- Test: `orchestrator/internal/wafevasion/validate_test.go`

**Interfaces:**
- Consumes: `EvasionScenario`, `NewEvasionScenario` (Task 1).
- Produces: `ValidateEvasionCatalog(scenarios []EvasionScenario) error`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafevasion/validate_test.go
package wafevasion

import "testing"

func mustScenario(t *testing.T, id string, attackVectorID string) EvasionScenario {
	t.Helper()
	s, err := NewEvasionScenario(id, EvasionEncodingObfuscation, attackVectorID, "x", "x", "x", "x")
	if err != nil {
		t.Fatalf("NewEvasionScenario(%q): %v", id, err)
	}
	return s
}

func TestValidateEvasionCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateEvasionCatalog([]EvasionScenario{
		mustScenario(t, "EVADE-001", "SQLI-002"),
		mustScenario(t, "EVADE-002", "PATHTRAV-001"),
	})
	if err != nil {
		t.Fatalf("ValidateEvasionCatalog: %v", err)
	}
}

func TestValidateEvasionCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateEvasionCatalog([]EvasionScenario{
		mustScenario(t, "EVADE-001", "SQLI-002"),
		mustScenario(t, "EVADE-001", "PATHTRAV-001"),
	})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateEvasionCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateEvasionCatalog(nil); err != nil {
		t.Fatalf("ValidateEvasionCatalog(nil): %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafevasion/... -run TestValidateEvasionCatalog -v`
Expected: FAIL — `ValidateEvasionCatalog` is undefined.

- [ ] **Step 3: Write `validate.go`**

```go
// orchestrator/internal/wafevasion/validate.go
package wafevasion

import "fmt"

// ValidateEvasionCatalog rejects a catalog containing two scenarios with
// the same ID. NewEvasionScenario cannot see sibling entries, so this is
// the single place uniqueness is enforced across a whole catalog snapshot.
func ValidateEvasionCatalog(scenarios []EvasionScenario) error {
	seen := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		if seen[s.ID] {
			return fmt.Errorf("duplicate evasion scenario ID %q", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafevasion/... -run TestValidateEvasionCatalog -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafevasion/validate.go orchestrator/internal/wafevasion/validate_test.go
git commit -m "feat(wafevasion): catalog-wide ID uniqueness validation"
```

---

### Task 3: Evasion-gap evaluation

**Files:**
- Create: `orchestrator/internal/wafevasion/evaluate.go`
- Test: `orchestrator/internal/wafevasion/evaluate_test.go`

**Interfaces:**
- Consumes: `EvasionScenario` (Task 1); `wafcatalog.AttackVector`, `wafcatalog.AudspectWAFAttackCatalog()` (already merged); `wafval.EvaluateClaim(exp wafval.Expectation, results []wafval.CollectionResult, key wafval.CorrelationKey) wafval.Result`, `wafval.CollectionResult`, `wafval.Observation`, `wafval.CorrelationKey`, `wafval.TimeWindow`, `wafval.MechanismWAFEngine`, `wafval.CoverageFound`, `wafval.CoverageSearchedVerifiedNone`, `wafval.EnforcementBlocked`, `wafval.EnforcementAllowed`, `wafval.EnforcementUnknown`, `wafval.DetectionMatched`, `wafval.DetectionNotMatched`, `wafval.DetectionUnknown`, `wafval.OriginUnknown`, `wafval.EvidenceObserved`, `wafval.VerdictMissed`, `wafval.VerdictBlocked`, `wafval.VerdictDetectedButAllowed`, `wafval.VerdictInconclusive`, `wafval.ConfidenceHigh`, `wafval.ConfidenceMedium` (all already merged, `internal/wafval`).
- Produces: `EvaluateEvasionGap(scenario EvasionScenario, vector wafcatalog.AttackVector, policyBasis string, canonicalEvidence []wafval.CollectionResult, canonicalKey wafval.CorrelationKey, evasiveEvidence []wafval.CollectionResult, evasiveKey wafval.CorrelationKey, originEquivalenceConfirmed bool) (wafval.Verdict, string, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafevasion/evaluate_test.go
package wafevasion

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

func mustEVADE001(t *testing.T) EvasionScenario {
	t.Helper()
	s, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002",
		"plain SQLi payload in the query parameter",
		"the identical SQLi payload, double-URL-encoded",
		"the origin application URL-decodes query parameters twice before passing them to the query layer, so the double-encoded form decodes to the identical payload",
		"manually authored")
	if err != nil {
		t.Fatalf("NewEvasionScenario: %v", err)
	}
	return s
}

func testWindow() wafval.TimeWindow {
	now := time.Now()
	return wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
}

// Review Focus: a vector whose ID doesn't match scenario.AttackVectorID is
// a caller bug and must be rejected.
func TestEvaluateEvasionGap_VectorIDMismatch_ReturnsError(t *testing.T) {
	scenario := mustEVADE001(t) // references SQLI-002
	wrongVector := mustVectorByID(t, "PATHTRAV-001")
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: testWindow()}
	_, _, err := EvaluateEvasionGap(scenario, wrongVector, "pb", nil, key, nil, key, true)
	if err == nil {
		t.Fatal("want error when vector.ID does not match scenario.AttackVectorID, got nil")
	}
}

func blockedEvidence(eventID, requestID string, now time.Time) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: eventID, RequestID: requestID, ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
}

func missedEvidence(eventID, requestID string, now time.Time) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: eventID, RequestID: requestID, ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
}

func allowedButDetectedEvidence(eventID, requestID string, now time.Time) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: eventID, RequestID: requestID, ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
}

// Review Focus, and spec §8 item 4: an unconfirmed origin-equivalence must
// never read as a real evasion bypass, even though the two legs visibly
// differ.
func TestEvaluateEvasionGap_UnconfirmedEquivalence_YieldsInconclusive(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		missedEvidence("v1", "r2", now), evasiveKey,
		false)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- an unconfirmed origin-equivalence must never read as a real evasion bypass", verdict, wafval.VerdictInconclusive)
	}
}

// Review Focus, and spec §8 item 5: a canonical leg that was never reliably
// blocked makes the evasion comparison moot -- it must resolve to
// Inconclusive, not a false "no gap".
func TestEvaluateEvasionGap_CanonicalNotReliablyBlocked_YieldsInconclusive(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		missedEvidence("c1", "r1", now), canonicalKey, // canonical itself missed
		missedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a canonical leg that was never reliably blocked must not yield a false bypass or false no-gap verdict", verdict, wafval.VerdictInconclusive)
	}
}

// Spec §8 item 6: confirmed equivalence, reliably blocked canonical,
// missed evasive leg -> a genuine evasion bypass.
func TestEvaluateEvasionGap_ConfirmedEquivalence_EvasiveMissed_YieldsMissed(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, reason, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		missedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
	if reason == "" {
		t.Error("want a non-empty evasion-attribution reason")
	}
}

func TestEvaluateEvasionGap_ConfirmedEquivalence_EvasiveDetectedButAllowed_YieldsDetectedButAllowed(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		allowedButDetectedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictDetectedButAllowed {
		t.Errorf("Verdict = %q, want %q", verdict, wafval.VerdictDetectedButAllowed)
	}
}

func TestEvaluateEvasionGap_ConfirmedEquivalence_EvasiveBlocked_YieldsBlocked(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		blockedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q -- no evasion gap should be demonstrated when the evasive leg is still blocked", verdict, wafval.VerdictBlocked)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafevasion/... -run TestEvaluateEvasionGap -v`
Expected: FAIL — `EvaluateEvasionGap` is undefined.

- [ ] **Step 3: Write `evaluate.go`**

```go
// orchestrator/internal/wafevasion/evaluate.go
package wafevasion

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func trustworthyBlocked(r wafval.Result) bool {
	return r.Verdict == wafval.VerdictBlocked &&
		(r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium)
}

func decideEvasionGap(canonical, evasive wafval.Result, originEquivalenceConfirmed bool) (wafval.Verdict, string) {
	if !originEquivalenceConfirmed {
		return wafval.VerdictInconclusive, "origin-equivalence of the evasive encoding not confirmed; differing responses not attributable to the evasion technique"
	}
	if !trustworthyBlocked(canonical) {
		return wafval.VerdictInconclusive, "canonical baseline did not establish a reliable block; evasive-leg behavior cannot be attributed to the evasion technique"
	}
	switch evasive.Verdict {
	case wafval.VerdictMissed:
		return wafval.VerdictMissed, "evasion bypass confirmed: canonical payload blocked, evasive-encoded equivalent neither detected nor blocked"
	case wafval.VerdictDetectedButAllowed:
		return wafval.VerdictDetectedButAllowed, "evasion-driven enforcement gap: evasive encoding still detected but not blocked"
	case wafval.VerdictBlocked:
		return wafval.VerdictBlocked, "no evasion gap demonstrated: evasive-encoded variant still blocked"
	default:
		return wafval.VerdictInconclusive, "evasive-leg outcome not attributable to the evasion technique"
	}
}

// EvaluateEvasionGap drives scenario's referenced vector's malicious leg
// through both the canonical and evasive-encoded evidence, then applies
// decideEvasionGap. Unlike wafpolicygap's two evaluation functions, there is
// no shape check here -- every EvasionScenario is inherently a two-leg
// comparison.
func EvaluateEvasionGap(
	scenario EvasionScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	canonicalEvidence []wafval.CollectionResult,
	canonicalKey wafval.CorrelationKey,
	evasiveEvidence []wafval.CollectionResult,
	evasiveKey wafval.CorrelationKey,
	originEquivalenceConfirmed bool,
) (wafval.Verdict, string, error) {
	if vector.ID != scenario.AttackVectorID {
		return "", "", fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	canonical := wafval.EvaluateClaim(maliciousExpectation, canonicalEvidence, canonicalKey)
	evasive := wafval.EvaluateClaim(maliciousExpectation, evasiveEvidence, evasiveKey)
	verdict, reason := decideEvasionGap(canonical, evasive, originEquivalenceConfirmed)
	return verdict, reason, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafevasion/... -run TestEvaluateEvasionGap -v`
Expected: PASS (6/6).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafevasion/evaluate.go orchestrator/internal/wafevasion/evaluate_test.go
git commit -m "feat(wafevasion): canonical-vs-evasive-encoding gap evaluation"
```

---

### Task 4: Seed evasion catalog

**Files:**
- Create: `orchestrator/internal/wafevasion/catalog.go`
- Test: `orchestrator/internal/wafevasion/catalog_test.go`

**Interfaces:**
- Consumes: `EvasionScenario`, `NewEvasionScenario`, all 6 `EvasionTechnique` constants (Task 1); `ValidateEvasionCatalog` (Task 2).
- Produces: `AudspectWAFEvasionCatalog() ([]EvasionScenario, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafevasion/catalog_test.go
package wafevasion

import "testing"

func TestAudspectWAFEvasionCatalog_ReturnsSixScenarios(t *testing.T) {
	scenarios, err := AudspectWAFEvasionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFEvasionCatalog: %v", err)
	}
	if len(scenarios) != 6 {
		t.Fatalf("len(scenarios) = %d, want 6", len(scenarios))
	}
	if err := ValidateEvasionCatalog(scenarios); err != nil {
		t.Errorf("ValidateEvasionCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 6 distinct evasion techniques,
// not duplicate one and skip another.
func TestAudspectWAFEvasionCatalog_CoversAllSixTechniques(t *testing.T) {
	scenarios, err := AudspectWAFEvasionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFEvasionCatalog: %v", err)
	}
	want := []EvasionTechnique{
		EvasionEncodingObfuscation, EvasionNormalizationMismatch, EvasionContentTypeConfusion,
		EvasionHTTPDiscrepancy, EvasionMultipartBoundaryManipulation, EvasionRequestBoundaryAbuse,
	}
	seen := make(map[EvasionTechnique]int)
	for _, s := range scenarios {
		seen[s.Technique]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("technique %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafevasion/... -run TestAudspectWAFEvasionCatalog -v`
Expected: FAIL — `AudspectWAFEvasionCatalog` is undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafevasion/catalog.go
package wafevasion

import "fmt"

// AudspectWAFEvasionCatalog returns Audspect's real, current seed evasion
// scenario catalog: exactly one scenario per EvasionTechnique, validated
// before being returned.
func AudspectWAFEvasionCatalog() ([]EvasionScenario, error) {
	type seed struct {
		id, attackVectorID, canonicalDesc, evasiveDesc, originEquivalenceRationale, provenance string
		technique                                                                              EvasionTechnique
	}
	seeds := []seed{
		{
			id: "EVADE-001", technique: EvasionEncodingObfuscation, attackVectorID: "SQLI-002",
			canonicalDesc: "plain SQLi payload in the query parameter",
			evasiveDesc:   "the identical SQLi payload, double-URL-encoded",
			originEquivalenceRationale: "the origin application URL-decodes query parameters twice before passing them to the query layer, so the double-encoded form decodes to the identical payload",
			provenance: "manually authored from waf.txt Phase 4's named encoding category",
		},
		{
			id: "EVADE-002", technique: EvasionNormalizationMismatch, attackVectorID: "PATHTRAV-001",
			canonicalDesc: "plain ../ directory-traversal path segments",
			evasiveDesc:   "the identical traversal expressed with Unicode/overlong-encoded path segments",
			originEquivalenceRationale: "the origin's filesystem path resolver performs Unicode normalization before resolving the path, so the overlong-encoded segments normalize to the identical traversal",
			provenance: "manually authored from waf.txt Phase 4's named normalization category",
		},
		{
			id: "EVADE-003", technique: EvasionContentTypeConfusion, attackVectorID: "FILEUP-001",
			canonicalDesc: "an uploaded file declared with its real executable content-type",
			evasiveDesc:   "the identical file bytes uploaded with a mislabeled benign-looking content-type",
			originEquivalenceRationale: "the origin's upload handler determines file type by inspecting the byte content, not the declared content-type header, so the mislabeled upload is processed identically to the canonical one",
			provenance: "manually authored from waf.txt Phase 4's named content-types category",
		},
		{
			id: "EVADE-004", technique: EvasionHTTPDiscrepancy, attackVectorID: "HTTPPARSE-001",
			canonicalDesc: "a canonical request carrying a single instance of the targeted header",
			evasiveDesc:   "the identical request with the targeted header duplicated, where the two instances disagree",
			originEquivalenceRationale: "the origin's HTTP server resolves duplicate headers by always taking the last occurrence, which carries the same value the canonical single-header request carried",
			provenance: "manually authored from waf.txt Phase 4's named HTTP-discrepancies category",
		},
		{
			id: "EVADE-005", technique: EvasionMultipartBoundaryManipulation, attackVectorID: "FILEUP-002",
			canonicalDesc: "a multipart upload using a canonical, unambiguous boundary string",
			evasiveDesc:   "the identical upload body framed with a boundary string crafted to be parsed differently by a strict parser than by a lenient one",
			originEquivalenceRationale: "the origin's multipart parser is lenient and extracts the identical file part regardless of which boundary-parsing interpretation is applied",
			provenance: "manually authored from waf.txt Phase 4's named multipart-uploads category",
		},
		{
			id: "EVADE-006", technique: EvasionRequestBoundaryAbuse, attackVectorID: "HTTPPARSE-002",
			canonicalDesc: "a canonical request framed with a single, consistent Content-Length header",
			evasiveDesc:   "the identical request body framed with a Transfer-Encoding/Content-Length conflict",
			originEquivalenceRationale: "the origin's HTTP server resolves the conflicting framing by always preferring Transfer-Encoding, and arrives at the identical body as the canonical Content-Length-framed request",
			provenance: "manually authored from waf.txt Phase 4's named request-boundary category",
		},
	}

	var out []EvasionScenario
	for _, sd := range seeds {
		s, err := NewEvasionScenario(sd.id, sd.technique, sd.attackVectorID, sd.canonicalDesc, sd.evasiveDesc, sd.originEquivalenceRationale, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed evasion catalog: %w", err)
		}
		out = append(out, s)
	}

	if err := ValidateEvasionCatalog(out); err != nil {
		return nil, fmt.Errorf("seed evasion catalog failed validation: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafevasion/... -v`
Expected: PASS — every test in the package passes, including every earlier task's tests run together for the first time.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafevasion/catalog.go orchestrator/internal/wafevasion/catalog_test.go
git commit -m "feat(wafevasion): AudspectWAFEvasionCatalog seeding all 6 evasion techniques"
```
