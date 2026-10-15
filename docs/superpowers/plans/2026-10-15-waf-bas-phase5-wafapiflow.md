# WAF BAS Mastery Phase 5: API and Business-Flow Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafapiflow`, a new attack-vector catalog covering API-schema, authorization-boundary, sensitive-workflow, GraphQL, and resource-quantity attacks — an attack surface Phase 2's `wafcatalog` doesn't cover — evaluated through the unmodified `wafval.EvaluateClaim` pipeline Phase 2 already built.

**Architecture:** A pure-Go, I/O-free package depending only on `internal/wafval`, structurally a sibling of `internal/wafcatalog` rather than a consumer of it (no dependency on `wafcatalog`, `wafpolicygap`, or `wafevasion`). It reuses `wafcatalog`'s proven `AttackVector`/`Expectations`/aggregator *pattern*, redefined locally with its own types, because every one of Phase 5's five named items is structurally "one malicious request a control should block, with a benign counterpart that should be allowed" — exactly what that pattern already models. No new evaluation function and no new `wafval` verdict logic are needed in this phase.

**Tech Stack:** Go 1.26.6, stdlib only (regexp for CWE-ID format), `internal/wafval` (already merged, read-only dependency).

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase5-wafapiflow-design.md`

## Global Constraints

- Package `internal/wafapiflow` depends only on `internal/wafval`; it does not depend on `internal/wafcatalog`, `internal/wafpolicygap`, or `internal/wafevasion` (spec §2).
- Zero new `wafval` verdict logic — every vector's claim is evaluated by the unmodified `wafval.EvaluateClaim` (spec §2, §6).
- `NewAPIFlowVector` validates identically to `wafcatalog.NewAttackVector`: ID non-empty, `Version >= 1`, known `Category`/`Severity`, `Malicious.{Method,Path,Description}` non-empty, every `Standards.CWEIDs` entry matches `^CWE-\d+$`, `Standards` has at least one of its four mapping fields set, `Provenance` non-empty, and exactly one of `BenignCounterpart`/`NoBenignCounterpartReason` (spec §4).
- `Expectations(policyBasis)` returns exactly 1 entry (malicious only, `wafval.ClaimPrevention`) when `NoBenignCounterpartReason` is set, or exactly 2 (malicious then benign, `wafval.ClaimFalsePositive`) when `BenignCounterpart` is set — never 0, never padded (spec §6).
- `AudspectWAFAPIFlowCatalog()` ships exactly 5 vectors, one per `APIFlowCategory`, per spec §7's table.

## Review Focus

- Both `BenignCounterpart` and `NoBenignCounterpartReason` set, or neither set, must both be rejected at construction — this is the single rule that keeps every vector's benign-counterpart story honest (never a silent omission, never a contradictory double-statement). Pinned in Task 1.
- A malformed `CWEIDs` entry (not matching `^CWE-\d+$`) must be rejected at construction, not silently stored and surfaced later in a client-facing report as a broken reference. Pinned in Task 1.
- A catalog containing two vectors with the same ID must be rejected — `NewAPIFlowVector` cannot see sibling entries, so this is the only place that's caught. Pinned in Task 2.
- `Expectations` must never return zero entries (every vector has at least a malicious leg) and must never pad to 2 entries when there is no `BenignCounterpart` — a caller iterating this slice to collect evidence must see exactly what the vector actually declares. Pinned in Task 3.
- `AudspectWAFAPIFlowCatalog()` must genuinely cover all 5 distinct `APIFlowCategory` values (not, say, two vectors of the same category and a gap elsewhere). Pinned in Task 4.

---

### Task 1: Core types and construction-time validation

**Files:**
- Create: `orchestrator/internal/wafapiflow/types.go`
- Create: `orchestrator/internal/wafapiflow/vector.go`
- Test: `orchestrator/internal/wafapiflow/vector_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (first task); stdlib `regexp` only.
- Produces: `APIFlowCategory` (+ 5 constants: `CategorySchemaConformance`, `CategoryAuthBoundary`, `CategorySensitiveWorkflow`, `CategoryGraphQLAbuse`, `CategoryResourceControl`), `Severity` (+ 4 constants: `SeverityCritical`, `SeverityHigh`, `SeverityMedium`, `SeverityLow`), `RequestTemplate{Method, Path, PayloadLocation, Payload, Description string}`, `StandardsMapping{CWEIDs []string, WSTGCategory, Top10Category, APITop10Category string, ATTACKTechniques []string}`, `APIFlowVector{ID string, Version int, Category APIFlowCategory, Name string, Severity Severity, Preconditions string, Malicious RequestTemplate, BenignCounterpart *RequestTemplate, NoBenignCounterpartReason string, Standards StandardsMapping, Provenance string}`, `NewAPIFlowVector(id string, version int, category APIFlowCategory, name string, severity Severity, preconditions string, malicious RequestTemplate, benignCounterpart *RequestTemplate, noBenignCounterpartReason string, standards StandardsMapping, provenance string) (APIFlowVector, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafapiflow/vector_test.go
package wafapiflow

import "testing"

func validMalicious() RequestTemplate {
	return RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": -1}`, Description: "negative-quantity checkout abuse"}
}

func validBenign() RequestTemplate {
	return RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": 2}`, Description: "valid positive quantity"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-1284"}}
}

func TestNewAPIFlowVector_Valid_Succeeds(t *testing.T) {
	benign := validBenign()
	v, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "Negative Quantity Schema Violation", SeverityHigh,
		"checkout API declares quantity as a positive integer", validMalicious(), &benign, "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewAPIFlowVector: %v", err)
	}
	if v.ID != "APIFLOW-001" {
		t.Errorf("ID = %q, want %q", v.ID, "APIFLOW-001")
	}
}

func TestNewAPIFlowVector_EmptyID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewAPIFlowVector_VersionLessThanOne_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 0, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for version < 1, got nil")
	}
}

func TestNewAPIFlowVector_UnknownCategory_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, APIFlowCategory("bogus_category"), "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Category, got nil")
	}
}

func TestNewAPIFlowVector_UnknownSeverity_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", Severity("bogus_severity"), "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Severity, got nil")
	}
}

func TestNewAPIFlowVector_EmptyMaliciousMethod_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Method = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewAPIFlowVector_EmptyMaliciousPath_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Path = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Path, got nil")
	}
}

func TestNewAPIFlowVector_EmptyMaliciousDescription_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Description = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

// Review Focus: a malformed CWE ID must be rejected at construction, not
// silently stored and surfaced later in a client-facing report.
func TestNewAPIFlowVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{CWEIDs: []string{"not-a-cwe-id"}}, "x")
	if err == nil {
		t.Fatal("want error for malformed CWE ID, got nil")
	}
}

func TestNewAPIFlowVector_StandardsAllEmpty_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has no mapping field set, got nil")
	}
}

func TestNewAPIFlowVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

// Review Focus: both BenignCounterpart and NoBenignCounterpartReason set is
// a contradictory double-statement and must be rejected.
func TestNewAPIFlowVector_BothBenignAndReasonSet_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "no benign exists", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

// Review Focus: neither set is a silent omission and must be rejected.
func TestNewAPIFlowVector_NeitherBenignNorReasonSet_Rejected(t *testing.T) {
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), nil, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

func TestNewAPIFlowVector_BenignCounterpartInvalid_Rejected(t *testing.T) {
	benign := validBenign()
	benign.Description = ""
	_, err := NewAPIFlowVector("APIFLOW-001", 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for an invalid BenignCounterpart (empty Description), got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/wafapiflow/types.go
// Package wafapiflow is a vendor-neutral, I/O-free attack-vector catalog
// covering API-schema, authorization-boundary, sensitive-workflow,
// GraphQL, and resource-quantity attacks -- an attack surface
// internal/wafcatalog's generic web-attack catalog does not cover. It
// depends only on internal/wafval, structurally a sibling of wafcatalog
// rather than a consumer of it: no dependency on wafcatalog, wafpolicygap,
// or wafevasion. Every vector's claim is evaluated by the unmodified
// wafval.EvaluateClaim -- zero new wafval verdict logic. Fixture-backed
// only; real execution is deferred.
package wafapiflow

// APIFlowCategory is one of the five breadth categories this catalog
// covers.
type APIFlowCategory string

const (
	CategorySchemaConformance APIFlowCategory = "schema_conformance"
	CategoryAuthBoundary      APIFlowCategory = "auth_boundary"
	CategorySensitiveWorkflow APIFlowCategory = "sensitive_workflow"
	CategoryGraphQLAbuse      APIFlowCategory = "graphql_abuse"
	CategoryResourceControl   APIFlowCategory = "resource_control"
)

// Severity is the catalog entry's declared risk level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// RequestTemplate describes one request shape without executing it.
type RequestTemplate struct {
	Method          string
	Path            string
	PayloadLocation string
	Payload         string
	Description     string
}

// StandardsMapping ties a vector to external references. At least one of
// CWEIDs/WSTGCategory/Top10Category/APITop10Category must be non-empty.
// ATTACKTechniques is always optional.
type StandardsMapping struct {
	CWEIDs           []string
	WSTGCategory     string
	Top10Category    string
	APITop10Category string
	ATTACKTechniques []string
}

// APIFlowVector is one versioned catalog entry. BenignCounterpart is nil
// only when NoBenignCounterpartReason explains why no legitimate lookalike
// exists -- never a silent omission.
type APIFlowVector struct {
	ID                        string
	Version                   int
	Category                  APIFlowCategory
	Name                      string
	Severity                  Severity
	Preconditions             string
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string
}
```

- [ ] **Step 4: Write `vector.go`**

```go
// orchestrator/internal/wafapiflow/vector.go
package wafapiflow

import (
	"fmt"
	"regexp"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validCategory(c APIFlowCategory) bool {
	switch c {
	case CategorySchemaConformance, CategoryAuthBoundary, CategorySensitiveWorkflow, CategoryGraphQLAbuse, CategoryResourceControl:
		return true
	default:
		return false
	}
}

func validSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

func validateRequestTemplate(r RequestTemplate, label string) error {
	if r.Method == "" {
		return fmt.Errorf("%s.Method must not be empty", label)
	}
	if r.Path == "" {
		return fmt.Errorf("%s.Path must not be empty", label)
	}
	if r.Description == "" {
		return fmt.Errorf("%s.Description must not be empty", label)
	}
	return nil
}

func validateStandards(s StandardsMapping) error {
	for _, id := range s.CWEIDs {
		if !cweIDPattern.MatchString(id) {
			return fmt.Errorf("CWE ID %q does not match ^CWE-\\d+$", id)
		}
	}
	if len(s.CWEIDs) == 0 && s.WSTGCategory == "" && s.Top10Category == "" && s.APITop10Category == "" {
		return fmt.Errorf("Standards must set at least one of CWEIDs, WSTGCategory, Top10Category, APITop10Category")
	}
	return nil
}

// NewAPIFlowVector validates at construction time, never at render time.
func NewAPIFlowVector(
	id string,
	version int,
	category APIFlowCategory,
	name string,
	severity Severity,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (APIFlowVector, error) {
	if id == "" {
		return APIFlowVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return APIFlowVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validCategory(category) {
		return APIFlowVector{}, fmt.Errorf("category %q is not one of the known APIFlowCategory constants", category)
	}
	if !validSeverity(severity) {
		return APIFlowVector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return APIFlowVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return APIFlowVector{}, err
	}
	if provenance == "" {
		return APIFlowVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return APIFlowVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return APIFlowVector{}, err
		}
	}
	return APIFlowVector{
		ID: id, Version: version, Category: category, Name: name, Severity: severity,
		Preconditions: preconditions, Malicious: malicious, BenignCounterpart: benignCounterpart,
		NoBenignCounterpartReason: noBenignCounterpartReason, Standards: standards, Provenance: provenance,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -v`
Expected: PASS — all 13 test functions pass.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/wafapiflow/types.go orchestrator/internal/wafapiflow/vector.go orchestrator/internal/wafapiflow/vector_test.go
git commit -m "feat(wafapiflow): APIFlowVector types and construction-time validation"
```

---

### Task 2: Catalog-wide ID uniqueness

**Files:**
- Create: `orchestrator/internal/wafapiflow/validate.go`
- Test: `orchestrator/internal/wafapiflow/validate_test.go`

**Interfaces:**
- Consumes: `APIFlowVector`, `NewAPIFlowVector` (Task 1).
- Produces: `ValidateAPIFlowCatalog(vectors []APIFlowVector) error`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafapiflow/validate_test.go
package wafapiflow

import "testing"

func mustVector(t *testing.T, id string) APIFlowVector {
	t.Helper()
	benign := validBenign()
	v, err := NewAPIFlowVector(id, 1, CategorySchemaConformance, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAPIFlowVector(%q): %v", id, err)
	}
	return v
}

func TestValidateAPIFlowCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateAPIFlowCatalog([]APIFlowVector{mustVector(t, "APIFLOW-001"), mustVector(t, "APIFLOW-002")})
	if err != nil {
		t.Fatalf("ValidateAPIFlowCatalog: %v", err)
	}
}

func TestValidateAPIFlowCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateAPIFlowCatalog([]APIFlowVector{mustVector(t, "APIFLOW-001"), mustVector(t, "APIFLOW-001")})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateAPIFlowCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateAPIFlowCatalog(nil); err != nil {
		t.Fatalf("ValidateAPIFlowCatalog(nil): %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -run TestValidateAPIFlowCatalog -v`
Expected: FAIL — `ValidateAPIFlowCatalog` is undefined.

- [ ] **Step 3: Write `validate.go`**

```go
// orchestrator/internal/wafapiflow/validate.go
package wafapiflow

import "fmt"

// ValidateAPIFlowCatalog rejects a catalog containing two vectors with the
// same ID. NewAPIFlowVector cannot see sibling entries, so this is the
// single place uniqueness is enforced across a whole catalog snapshot.
func ValidateAPIFlowCatalog(vectors []APIFlowVector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate API-flow vector ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -run TestValidateAPIFlowCatalog -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafapiflow/validate.go orchestrator/internal/wafapiflow/validate_test.go
git commit -m "feat(wafapiflow): catalog-wide ID uniqueness validation"
```

---

### Task 3: Evidence integration

**Files:**
- Create: `orchestrator/internal/wafapiflow/evidence.go`
- Test: `orchestrator/internal/wafapiflow/evidence_test.go`

**Interfaces:**
- Consumes: `APIFlowVector`, `RequestTemplate`, `NewAPIFlowVector` (Task 1); `wafval.Expectation{Claim, PolicyBasis, PolicyVerified}`, `wafval.ClaimPrevention`, `wafval.ClaimFalsePositive` (all already merged, `internal/wafval`).
- Produces: `APIFlowLeg` (+ 2 constants: `LegMalicious`, `LegBenign`), `APIFlowLegExpectation{VectorID string, Leg APIFlowLeg, Request RequestTemplate, Expectation wafval.Expectation}`, `(v APIFlowVector) Expectations(policyBasis string) []APIFlowLegExpectation`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafapiflow/evidence_test.go
package wafapiflow

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestAPIFlowVector_Expectations_WithBenignCounterpart_ReturnsTwoLegs(t *testing.T) {
	v := mustVector(t, "APIFLOW-001")
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMalicious with ClaimPrevention", legs[0])
	}
	if legs[1].Leg != LegBenign || legs[1].Expectation.Claim != wafval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want LegBenign with ClaimFalsePositive", legs[1])
	}
}

// Review Focus: Expectations must never pad to 2 entries when there is no
// BenignCounterpart -- exactly 1 (the malicious leg), always first.
func TestAPIFlowVector_Expectations_NoBenignCounterpart_ReturnsOneLeg(t *testing.T) {
	v, err := NewAPIFlowVector("APIFLOW-004", 1, CategoryGraphQLAbuse, "x", SeverityHigh, "x", validMalicious(), nil, "no legitimate lookalike for this probe", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAPIFlowVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMalicious with ClaimPrevention", legs[0])
	}
}

func TestAPIFlowVector_Expectations_VectorIDCarriedOnEachLeg(t *testing.T) {
	v := mustVector(t, "APIFLOW-001")
	legs := v.Expectations("owasp-crs-default")
	for _, leg := range legs {
		if leg.VectorID != "APIFLOW-001" {
			t.Errorf("leg.VectorID = %q, want %q", leg.VectorID, "APIFLOW-001")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -run TestAPIFlowVector_Expectations -v`
Expected: FAIL — `Expectations` is undefined.

- [ ] **Step 3: Write `evidence.go`**

```go
// orchestrator/internal/wafapiflow/evidence.go
package wafapiflow

import "github.com/audspect/bas/internal/wafval"

// APIFlowLeg names which half of an APIFlowVector a leg's expectation came
// from.
type APIFlowLeg string

const (
	LegMalicious APIFlowLeg = "malicious"
	LegBenign    APIFlowLeg = "benign"
)

// APIFlowLegExpectation pairs one leg's request template with the
// wafval.Expectation it resolves to, so a test harness can collect
// evidence and call wafval.EvaluateClaim without re-deriving the claim
// mapping itself.
type APIFlowLegExpectation struct {
	VectorID    string
	Leg         APIFlowLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's APIFlowLegExpectation, plus the
// benign leg's when BenignCounterpart is set -- never a padded slice.
// policyBasis is caller-supplied: the catalog is deployment-neutral and
// does not know what policy is actually in force, so PolicyVerified is
// always false here; only the evidence-collecting caller can confirm a
// policy was in force.
func (v APIFlowVector) Expectations(policyBasis string) []APIFlowLegExpectation {
	legs := []APIFlowLegExpectation{
		{
			VectorID: v.ID,
			Leg:      LegMalicious,
			Request:  v.Malicious,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimPrevention, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		},
	}
	if v.BenignCounterpart != nil {
		legs = append(legs, APIFlowLegExpectation{
			VectorID: v.ID,
			Leg:      LegBenign,
			Request:  *v.BenignCounterpart,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimFalsePositive, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		})
	}
	return legs
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -run TestAPIFlowVector_Expectations -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafapiflow/evidence.go orchestrator/internal/wafapiflow/evidence_test.go
git commit -m "feat(wafapiflow): evidence integration via Expectations"
```

---

### Task 4: Seed vector catalog

**Files:**
- Create: `orchestrator/internal/wafapiflow/catalog.go`
- Test: `orchestrator/internal/wafapiflow/catalog_test.go`

**Interfaces:**
- Consumes: `APIFlowVector`, `NewAPIFlowVector`, all 5 `APIFlowCategory` constants, all 4 `Severity` constants, `RequestTemplate`, `StandardsMapping` (Task 1); `ValidateAPIFlowCatalog` (Task 2).
- Produces: `AudspectWAFAPIFlowCatalog() ([]APIFlowVector, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafapiflow/catalog_test.go
package wafapiflow

import "testing"

func TestAudspectWAFAPIFlowCatalog_ReturnsFiveVectors(t *testing.T) {
	vectors, err := AudspectWAFAPIFlowCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAPIFlowCatalog: %v", err)
	}
	if len(vectors) != 5 {
		t.Fatalf("len(vectors) = %d, want 5", len(vectors))
	}
	if err := ValidateAPIFlowCatalog(vectors); err != nil {
		t.Errorf("ValidateAPIFlowCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 5 distinct categories, not
// duplicate one and skip another.
func TestAudspectWAFAPIFlowCatalog_CoversAllFiveCategories(t *testing.T) {
	vectors, err := AudspectWAFAPIFlowCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAPIFlowCatalog: %v", err)
	}
	want := []APIFlowCategory{
		CategorySchemaConformance, CategoryAuthBoundary, CategorySensitiveWorkflow, CategoryGraphQLAbuse, CategoryResourceControl,
	}
	seen := make(map[APIFlowCategory]int)
	for _, v := range vectors {
		seen[v.Category]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("category %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -run TestAudspectWAFAPIFlowCatalog -v`
Expected: FAIL — `AudspectWAFAPIFlowCatalog` is undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafapiflow/catalog.go
package wafapiflow

import "fmt"

// AudspectWAFAPIFlowCatalog returns Audspect's real, current seed
// API/business-flow vector catalog: exactly one vector per
// APIFlowCategory, validated before being returned.
func AudspectWAFAPIFlowCatalog() ([]APIFlowVector, error) {
	type seed struct {
		id, name, preconditions, provenance string
		category                            APIFlowCategory
		severity                            Severity
		malicious, benign                   RequestTemplate
		standards                           StandardsMapping
	}
	seeds := []seed{
		{
			id: "APIFLOW-001", category: CategorySchemaConformance, name: "Negative-Quantity Schema Violation", severity: SeverityHigh,
			preconditions: "checkout API's OpenAPI schema declares quantity as a positive integer (minimum: 1)",
			malicious: RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": -1}`,
				Description: "submits a negative quantity for a checkout line item, where the schema declares quantity as a positive integer, attempting a negative-quantity refund/credit abuse"},
			benign: RequestTemplate{Method: "POST", Path: "/api/checkout/items", PayloadLocation: "body:quantity", Payload: `{"itemId": "SKU-1001", "quantity": 2}`,
				Description: "submits a valid positive quantity for the same checkout line item"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-1284"}}, provenance: "manually authored from waf.txt Phase 5's named API-schemas category",
		},
		{
			id: "APIFLOW-002", category: CategoryAuthBoundary, name: "Wrong-Scope Token Boundary Bypass", severity: SeverityHigh,
			preconditions: "profile-update endpoint requires a bearer token carrying the write:profile scope",
			malicious: RequestTemplate{Method: "PATCH", Path: "/api/users/me/profile", PayloadLocation: "header:Authorization", Payload: "Bearer <token with scope=read:profile>",
				Description: "uses a validly-signed bearer token carrying only read:profile scope to call a write:profile-scoped endpoint, attempting a scope-boundary bypass"},
			benign: RequestTemplate{Method: "PATCH", Path: "/api/users/me/profile", PayloadLocation: "header:Authorization", Payload: "Bearer <token with scope=write:profile>",
				Description: "uses a bearer token actually carrying the write:profile scope the endpoint requires"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-285"}}, provenance: "manually authored from waf.txt Phase 5's named authentication-boundaries category",
		},
		{
			id: "APIFLOW-003", category: CategorySensitiveWorkflow, name: "Password-Reset Token Replay", severity: SeverityCritical,
			preconditions: "password-reset tokens are declared single-use",
			malicious: RequestTemplate{Method: "POST", Path: "/api/password-reset/confirm", PayloadLocation: "body:token", Payload: `{"token": "<token already consumed by a completed reset>", "newPassword": "NewPass123!"}`,
				Description: "replays a password-reset token already consumed by a completed reset, attempting to set a new password a second time with the same single-use token"},
			benign: RequestTemplate{Method: "POST", Path: "/api/password-reset/confirm", PayloadLocation: "body:token", Payload: `{"token": "<freshly issued, not-yet-consumed token>", "newPassword": "NewPass123!"}`,
				Description: "uses a freshly issued, not-yet-consumed password-reset token for the identical set-new-password operation"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-294"}}, provenance: "manually authored from waf.txt Phase 5's named sensitive-workflows category",
		},
		{
			id: "APIFLOW-004", category: CategoryGraphQLAbuse, name: "Unbounded GraphQL Query Depth", severity: SeverityHigh,
			preconditions: "GraphQL endpoint allows recursive field selections with no server-enforced depth limit",
			malicious: RequestTemplate{Method: "POST", Path: "/graphql", PayloadLocation: "body:query", Payload: "query { user(id: 1) { friends { friends { friends { /* ~50 levels deep */ } } } } }",
				Description: "submits a GraphQL query with ~50 levels of nested recursive field selections, attempting to exhaust backend resources via unbounded query depth"},
			benign: RequestTemplate{Method: "POST", Path: "/graphql", PayloadLocation: "body:query", Payload: "query { user(id: 1) { friends { id name } } }",
				Description: "submits the same query shape at a shallow, reasonable depth (2 levels) a legitimate client would send"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-400"}}, provenance: "manually authored from waf.txt Phase 5's named GraphQL category",
		},
		{
			id: "APIFLOW-005", category: CategoryResourceControl, name: "Unbounded Bulk-Export Limit", severity: SeverityHigh,
			preconditions: "bulk-export endpoint accepts a caller-supplied limit query parameter with no server-enforced maximum",
			malicious: RequestTemplate{Method: "GET", Path: "/api/records/export", PayloadLocation: "query:limit", Payload: "?limit=999999999",
				Description: "requests the bulk-export endpoint with an unbounded limit parameter, attempting to exfiltrate the entire dataset in a single call"},
			benign: RequestTemplate{Method: "GET", Path: "/api/records/export", PayloadLocation: "query:limit", Payload: "?limit=100",
				Description: "requests the same export endpoint with a limit value within the endpoint's intended bound"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-770"}}, provenance: "manually authored from waf.txt Phase 5's named resource-controls category",
		},
	}

	var out []APIFlowVector
	for _, sd := range seeds {
		benign := sd.benign
		v, err := NewAPIFlowVector(sd.id, 1, sd.category, sd.name, sd.severity, sd.preconditions, sd.malicious, &benign, "", sd.standards, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed API-flow catalog: %w", err)
		}
		out = append(out, v)
	}

	if err := ValidateAPIFlowCatalog(out); err != nil {
		return nil, fmt.Errorf("seed API-flow catalog failed validation: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafapiflow/... -v`
Expected: PASS — every test in the package passes, including every earlier task's tests run together for the first time.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafapiflow/catalog.go orchestrator/internal/wafapiflow/catalog_test.go
git commit -m "feat(wafapiflow): AudspectWAFAPIFlowCatalog seeding all 5 categories"
```
