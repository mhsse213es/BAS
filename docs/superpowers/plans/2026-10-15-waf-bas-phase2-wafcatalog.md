# WAF BAS Mastery Phase 2: Versioned Attack-Test Catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafcatalog`, a versioned, standards-mapped attack-vector catalog that resolves into `internal/wafval`'s evidence contract, proven entirely by fixtures.

**Architecture:** A pure-Go, I/O-free sibling package to `internal/wafval` (one-way dependency, same as `adefficacy`→`controlval`). Each `AttackVector` is a construction-validated catalog entry owning a malicious request and, except where explicitly justified, its benign lookalike. `Expectations(policyBasis)` resolves a vector's legs into `wafval.Expectation`s that a fixture test (or, later, a real lab adapter) feeds into `wafval.EvaluateClaim`.

**Tech Stack:** Go 1.26.6, stdlib only (`fmt`, `regexp`, `strings`), `internal/wafval` (already merged, read-only dependency).

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase2-wafcatalog-design.md`

## Global Constraints

- Package `internal/wafcatalog` depends on `internal/wafval`; `wafval` never depends back on it (spec §3).
- No HTTP client, no vendor SDK, no ModSecurity/CRS-specific code anywhere in this package (spec §2, §3).
- Every validation happens at construction time (`NewAttackVector`), never at render/use time (spec §5).
- Every `AttackVector`'s `Standards` must set at least one of `CWEIDs`/`WSTGCategory`/`Top10Category`/`APITop10Category`; `ATTACKTechniques` is always optional (spec §4, §9).
- Every `CWEIDs` entry must match `^CWE-\d+$` (spec §5).
- Exactly one of `BenignCounterpart != nil` or `NoBenignCounterpartReason != ""` holds on every vector — never both, never neither (spec §5, §6).
- The seed catalog covers all 11 `AttackFamily` constants with roughly 25–30 total vectors (spec §9) — this plan ships 26.
- This phase is fixture-backed only; no step in this plan makes a real network call (spec §2, §10).

## Review Focus

- A `Family` value that is a syntactically valid Go string but not one of the 11 known constants (e.g. a typo like `"sql_injecton"`) must be rejected by `NewAttackVector`, not silently accepted — `AttackFamily` is just a `string` underneath, so Go's type system cannot catch this. Pinned in Task 1.
- A `CWEIDs` entry with the wrong case or missing the `CWE-` prefix (e.g. `"cwe-89"` or `"89"`) must be rejected by the format check, not silently accepted. Pinned in Task 1.
- A vector that sets **both** `BenignCounterpart` and a non-empty `NoBenignCounterpartReason` simultaneously is a contradictory state and must be rejected outright, not resolved by picking one silently. Pinned in Task 1.
- `AudspectWAFAttackCatalog()` must actually call `ValidateCatalog` and propagate its error — with 26 hand-authored entries across 4 files, an accidental duplicate ID is an easy slip, and the aggregator must fail loudly rather than silently return a catalog containing it. Pinned in Task 8.
- `Expectations(policyBasis)` called on a vector whose `BenignCounterpart` is `nil` must return a slice of length exactly 1 — never a length-2 slice padded with a zero-value second `LegExpectation`, which a careless caller could mistake for a real benign leg. Pinned in Task 3.

---

### Task 1: Core types and construction-time validation

**Files:**
- Create: `orchestrator/internal/wafcatalog/types.go`
- Create: `orchestrator/internal/wafcatalog/vector.go`
- Test: `orchestrator/internal/wafcatalog/vector_test.go`

**Interfaces:**
- Consumes: nothing from this plan (first task).
- Produces: `AttackFamily` (+ 11 constants), `Severity` (+ 4 constants), `RequestTemplate{Method, Path, PayloadLocation, Payload, Description string}`, `StandardsMapping{CWEIDs []string, WSTGCategory, Top10Category, APITop10Category string, ATTACKTechniques []string}`, `AttackVector{ID string, Version int, Family AttackFamily, Name string, Severity Severity, Preconditions string, Malicious RequestTemplate, BenignCounterpart *RequestTemplate, NoBenignCounterpartReason string, Standards StandardsMapping, Provenance string}`, `NewAttackVector(id string, version int, family AttackFamily, name string, severity Severity, preconditions string, malicious RequestTemplate, benignCounterpart *RequestTemplate, noBenignCounterpartReason string, standards StandardsMapping, provenance string) (AttackVector, error)`.

- [ ] **Step 1: Write the failing tests for `NewAttackVector`'s validation gates**

```go
// orchestrator/internal/wafcatalog/vector_test.go
package wafcatalog

import "testing"

func validMalicious() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "' OR 1=1--", Description: "test payload"}
}

func validBenign() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "laptop stand", Description: "ordinary search term"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-89"}, Top10Category: "A03:2021-Injection"}
}

func TestNewAttackVector_Valid_Succeeds(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "UNION-based SQLi", SeverityCritical,
		"target has a SQL-backed search endpoint", validMalicious(), &benign, "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	if v.ID != "SQLI-001" {
		t.Errorf("ID = %q, want %q", v.ID, "SQLI-001")
	}
}

func TestNewAttackVector_EmptyID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewAttackVector_VersionBelowOne_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 0, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for Version < 1, got nil")
	}
}

// Review Focus: a Family value that is a syntactically valid string but not
// one of the 11 known constants must be rejected -- AttackFamily is just a
// string underneath, so Go's type system cannot catch a typo like this.
func TestNewAttackVector_UnknownFamily_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, AttackFamily("sql_injecton"), "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Family, got nil")
	}
}

func TestNewAttackVector_UnknownSeverity_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", Severity("extreme"), "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Severity, got nil")
	}
}

func TestNewAttackVector_MaliciousMissingMethod_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Method = ""
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewAttackVector_MaliciousMissingDescription_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Description = ""
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

// Review Focus: a CWE ID with the wrong case or missing the "CWE-" prefix
// must be rejected by the format check.
func TestNewAttackVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := validBenign()
	for _, bad := range []string{"cwe-89", "89", "CWE89", "CWE-"} {
		standards := StandardsMapping{CWEIDs: []string{bad}}
		_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", standards, "x")
		if err == nil {
			t.Errorf("CWE ID %q: want error, got nil", bad)
		}
	}
}

func TestNewAttackVector_NoStandardsMapping_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has none of CWEIDs/WSTGCategory/Top10Category/APITop10Category set, got nil")
	}
}

func TestNewAttackVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestNewAttackVector_NeitherBenignNorReason_Rejected(t *testing.T) {
	_, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "x", SeverityCritical, "x", validMalicious(), nil, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

// Review Focus: setting BOTH BenignCounterpart and a non-empty
// NoBenignCounterpartReason is a contradictory state and must be rejected,
// never resolved by silently picking one.
func TestNewAttackVector_BothBenignAndReason_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "x", SeverityCritical, "x", validMalicious(), &benign, "no counterpart needed", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

func TestNewAttackVector_NoBenignCounterpartReason_Succeeds(t *testing.T) {
	v, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "metadata SSRF", SeverityCritical, "x",
		validMalicious(), nil, "no legitimate client request targets this address range", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	if v.BenignCounterpart != nil {
		t.Error("BenignCounterpart should be nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run TestNewAttackVector -v`
Expected: FAIL — `types.go`/`vector.go` don't exist yet, so this is a compile error naming undefined symbols (`AttackFamily`, `NewAttackVector`, etc.), not a runtime failure. That's the correct RED state for a from-scratch package.

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/wafcatalog/types.go
// Package wafcatalog is a vendor-neutral, I/O-free, versioned attack-test
// catalog that resolves into internal/wafval's evidence contract. It depends
// on wafval; wafval never depends on it. It imports stdlib only -- no HTTP
// client, no vendor SDK, no ModSecurity/CRS-specific code. Real execution
// against a controlled lab is a separate, deferred package.
package wafcatalog

// AttackFamily is one of the eleven breadth categories this catalog covers.
type AttackFamily string

const (
	FamilySQLInjection    AttackFamily = "sql_injection"
	FamilyXSS             AttackFamily = "xss"
	FamilyPathTraversal   AttackFamily = "path_traversal"
	FamilySSRF            AttackFamily = "ssrf"
	FamilyFileUpload      AttackFamily = "file_upload"
	FamilyHTTPParser      AttackFamily = "http_parser_discrepancy"
	FamilyAPIAbuse        AttackFamily = "api_abuse"
	FamilyAuthAbuse       AttackFamily = "auth_abuse"
	FamilyRateLimit       AttackFamily = "rate_limit"
	FamilyCacheWeakness   AttackFamily = "cache_weakness"
	FamilyPolicyMisconfig AttackFamily = "policy_misconfig"
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

// AttackVector is one versioned catalog entry. BenignCounterpart is nil only
// when NoBenignCounterpartReason explains why no legitimate lookalike
// exists -- never a silent omission.
type AttackVector struct {
	ID                        string
	Version                   int
	Family                    AttackFamily
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
// orchestrator/internal/wafcatalog/vector.go
package wafcatalog

import (
	"fmt"
	"regexp"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validFamily(f AttackFamily) bool {
	switch f {
	case FamilySQLInjection, FamilyXSS, FamilyPathTraversal, FamilySSRF, FamilyFileUpload,
		FamilyHTTPParser, FamilyAPIAbuse, FamilyAuthAbuse, FamilyRateLimit, FamilyCacheWeakness, FamilyPolicyMisconfig:
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

// NewAttackVector validates at construction time, never at render time.
func NewAttackVector(
	id string,
	version int,
	family AttackFamily,
	name string,
	severity Severity,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (AttackVector, error) {
	if id == "" {
		return AttackVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return AttackVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validFamily(family) {
		return AttackVector{}, fmt.Errorf("family %q is not one of the known AttackFamily constants", family)
	}
	if !validSeverity(severity) {
		return AttackVector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return AttackVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return AttackVector{}, err
	}
	if provenance == "" {
		return AttackVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return AttackVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return AttackVector{}, err
		}
	}
	return AttackVector{
		ID: id, Version: version, Family: family, Name: name, Severity: severity,
		Preconditions: preconditions, Malicious: malicious, BenignCounterpart: benignCounterpart,
		NoBenignCounterpartReason: noBenignCounterpartReason, Standards: standards, Provenance: provenance,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run TestNewAttackVector -v`
Expected: PASS — all 13 test functions pass (the malformed-CWE-ID test covers 4 sub-cases in a loop).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/wafcatalog/types.go orchestrator/internal/wafcatalog/vector.go orchestrator/internal/wafcatalog/vector_test.go
git commit -m "feat(wafcatalog): AttackVector type and construction-time validation"
```

---

### Task 2: Catalog-wide ID uniqueness

**Files:**
- Create: `orchestrator/internal/wafcatalog/validate.go`
- Test: `orchestrator/internal/wafcatalog/validate_test.go`

**Interfaces:**
- Consumes: `AttackVector`, `NewAttackVector` (Task 1).
- Produces: `ValidateCatalog(vectors []AttackVector) error`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafcatalog/validate_test.go
package wafcatalog

import "testing"

func mustVector(t *testing.T, id string) AttackVector {
	t.Helper()
	benign := validBenign()
	v, err := NewAttackVector(id, 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector(%q): %v", id, err)
	}
	return v
}

func TestValidateCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateCatalog([]AttackVector{mustVector(t, "SQLI-001"), mustVector(t, "SQLI-002")})
	if err != nil {
		t.Fatalf("ValidateCatalog: %v", err)
	}
}

func TestValidateCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateCatalog([]AttackVector{mustVector(t, "SQLI-001"), mustVector(t, "SQLI-001")})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateCatalog(nil); err != nil {
		t.Fatalf("ValidateCatalog(nil): %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run TestValidateCatalog -v`
Expected: FAIL — `ValidateCatalog` is undefined.

- [ ] **Step 3: Write `validate.go`**

```go
// orchestrator/internal/wafcatalog/validate.go
package wafcatalog

import "fmt"

// ValidateCatalog rejects a catalog containing two entries with the same ID.
// NewAttackVector cannot see sibling entries, so this is the single place
// uniqueness is enforced across a whole catalog snapshot.
func ValidateCatalog(vectors []AttackVector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate attack vector ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run TestValidateCatalog -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/validate.go orchestrator/internal/wafcatalog/validate_test.go
git commit -m "feat(wafcatalog): catalog-wide ID uniqueness validation"
```

---

### Task 3: Evidence-contract integration

**Files:**
- Create: `orchestrator/internal/wafcatalog/evidence.go`
- Test: `orchestrator/internal/wafcatalog/evidence_test.go`

**Interfaces:**
- Consumes: `AttackVector`, `NewAttackVector` (Task 1); `wafval.ClaimType`, `wafval.ClaimPrevention`, `wafval.ClaimFalsePositive`, `wafval.Expectation{Claim, PolicyBasis, PolicyVerified}`, `wafval.EvaluateClaim(exp wafval.Expectation, results []wafval.CollectionResult, key wafval.CorrelationKey) wafval.Result`, `wafval.CollectionResult{Mechanism, Coverage, Observations}`, `wafval.Observation{Mechanism, Provider, EventID, RequestID, ObservedAt, Enforcement, Detection, Origin, MatchedRule, EvidenceKind, Detail}`, `wafval.CorrelationKey{TestExecutionID, RequestID, Target, Window}`, `wafval.TimeWindow{Start, End}`, `wafval.MechanismWAFEngine`, `wafval.MechanismOriginApp`, `wafval.CoverageFound`, `wafval.CoverageSearchedVerifiedNone`, `wafval.EnforcementBlocked`, `wafval.EnforcementAllowed`, `wafval.DetectionMatched`, `wafval.DetectionNotMatched`, `wafval.OriginReceived`, `wafval.OriginNotObserved`, `wafval.EvidenceObserved`, `wafval.VerdictBlocked`, `wafval.VerdictMissed`, `wafval.VerdictAllowed`, `wafval.VerdictIncorrectlyBlocked` (all from the already-merged `internal/wafval` package).
- Produces: `AttackLeg` (+ `LegMalicious`, `LegBenign`), `LegExpectation{VectorID string, Leg AttackLeg, Request RequestTemplate, Expectation wafval.Expectation}`, `(v AttackVector) Expectations(policyBasis string) []LegExpectation`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafcatalog/evidence_test.go
package wafcatalog

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafval"
)

// Review Focus: a vector with no BenignCounterpart must return exactly one
// LegExpectation -- never a length-2 slice padded with a zero-value second
// entry that a careless caller could mistake for a real benign leg.
func TestExpectations_NoBenignCounterpart_ReturnsExactlyOne(t *testing.T) {
	v, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "metadata SSRF", SeverityCritical, "x",
		validMalicious(), nil, "no legitimate counterpart", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMalicious {
		t.Errorf("legs[0].Leg = %q, want %q", legs[0].Leg, LegMalicious)
	}
	if legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0].Expectation.Claim = %q, want %q", legs[0].Expectation.Claim, wafval.ClaimPrevention)
	}
}

func TestExpectations_WithBenignCounterpart_ReturnsBoth(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want malicious/ClaimPrevention", legs[0])
	}
	if legs[1].Leg != LegBenign || legs[1].Expectation.Claim != wafval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want benign/ClaimFalsePositive", legs[1])
	}
	if legs[0].Expectation.PolicyBasis != "owasp-crs-default" || legs[1].Expectation.PolicyBasis != "owasp-crs-default" {
		t.Errorf("PolicyBasis not threaded through to both legs: %+v", legs)
	}
}

// TestMaliciousLeg_BlockedByWAF_YieldsBlocked proves a catalog-driven
// malicious leg flows correctly through wafval.EvaluateClaim end to end
// (spec §11, acceptance gate item 7).
func TestMaliciousLeg_BlockedByWAF_YieldsBlocked(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-1", RequestID: "req-1", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-1", RequestID: "req-1", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, EvidenceKind: wafval.EvidenceObserved},
		}},
		{Mechanism: wafval.MechanismOriginApp, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismOriginApp, EventID: "evt-2", RequestID: "req-1", ObservedAt: now, Origin: wafval.OriginNotObserved, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	if result.Verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictBlocked)
	}
}

// TestBenignLeg_Allowed_YieldsAllowed proves the benign leg flows correctly
// (spec §11, acceptance gate item 8).
func TestBenignLeg_Allowed_YieldsAllowed(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-2", RequestID: "req-2", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-3", RequestID: "req-2", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[1].Expectation, results, key)
	if result.Verdict != wafval.VerdictAllowed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictAllowed)
	}
}

// TestMaliciousLeg_AllowedAndUndetected_YieldsMissed proves a genuine
// catalog-driven negative finding (spec §11, acceptance gate item 9).
func TestMaliciousLeg_AllowedAndUndetected_YieldsMissed(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-3", RequestID: "req-3", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-4", RequestID: "req-3", ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, EvidenceKind: wafval.EvidenceObserved},
		}},
		{Mechanism: wafval.MechanismOriginApp, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismOriginApp, EventID: "evt-5", RequestID: "req-3", ObservedAt: now, Origin: wafval.OriginReceived, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	if result.Verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictMissed)
	}
}

// TestBenignLeg_Blocked_YieldsIncorrectlyBlocked proves the catalog genuinely
// surfaces a false positive (spec §11, acceptance gate item 10).
func TestBenignLeg_Blocked_YieldsIncorrectlyBlocked(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-4", RequestID: "req-4", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-6", RequestID: "req-4", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	result := wafval.EvaluateClaim(legs[1].Expectation, results, key)
	if result.Verdict != wafval.VerdictIncorrectlyBlocked {
		t.Errorf("Verdict = %q, want %q", result.Verdict, wafval.VerdictIncorrectlyBlocked)
	}
}

// TestSameFixture_RunTwice_IdenticalResult proves determinism (spec §11,
// acceptance gate item 12).
func TestSameFixture_RunTwice_IdenticalResult(t *testing.T) {
	benign := validBenign()
	v, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "x", SeverityCritical, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewAttackVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	now := time.Now()
	key := wafval.CorrelationKey{TestExecutionID: "exec-5", RequestID: "req-5", Target: "example.test", Window: wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}}
	results := []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: "evt-7", RequestID: "req-5", ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
	first := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	second := wafval.EvaluateClaim(legs[0].Expectation, results, key)
	if first.Verdict != second.Verdict || first.Confidence != second.Confidence || first.Completeness != second.Completeness {
		t.Errorf("non-deterministic: first=%+v, second=%+v", first, second)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestExpectations|TestMaliciousLeg|TestBenignLeg|TestSameFixture" -v`
Expected: FAIL — `AttackLeg`, `LegMalicious`, `LegExpectation`, `Expectations` are undefined.

- [ ] **Step 3: Write `evidence.go`**

```go
// orchestrator/internal/wafcatalog/evidence.go
package wafcatalog

import "github.com/audspect/bas/internal/wafval"

// AttackLeg names which half of an AttackVector a LegExpectation came from.
type AttackLeg string

const (
	LegMalicious AttackLeg = "malicious"
	LegBenign    AttackLeg = "benign"
)

// LegExpectation pairs one leg's request template with the wafval.Expectation
// it resolves to, so a test harness can collect evidence and call
// wafval.EvaluateClaim without re-deriving the claim mapping itself.
type LegExpectation struct {
	VectorID    string
	Leg         AttackLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's LegExpectation, plus the benign
// leg's when BenignCounterpart is set -- never a padded slice. policyBasis
// is caller-supplied: the catalog is deployment-neutral and does not know
// what policy is actually in force, so PolicyVerified is always false here;
// only the evidence-collecting caller can confirm a policy was in force.
func (v AttackVector) Expectations(policyBasis string) []LegExpectation {
	legs := []LegExpectation{
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
		legs = append(legs, LegExpectation{
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

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestExpectations|TestMaliciousLeg|TestBenignLeg|TestSameFixture" -v`
Expected: PASS (7/7).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/evidence.go orchestrator/internal/wafcatalog/evidence_test.go
git commit -m "feat(wafcatalog): evidence-contract integration with wafval"
```

---

### Task 4: Seed catalog — injection families (SQL injection, XSS, path traversal)

**Files:**
- Create: `orchestrator/internal/wafcatalog/catalog_injection.go`
- Test: `orchestrator/internal/wafcatalog/catalog_injection_test.go`

**Interfaces:**
- Consumes: `AttackVector`, `NewAttackVector`, `RequestTemplate`, `StandardsMapping`, `FamilySQLInjection`, `FamilyXSS`, `FamilyPathTraversal`, `SeverityCritical`, `SeverityHigh`, `SeverityMedium` (Task 1); `ValidateCatalog` (Task 2).
- Produces: `sqlInjectionVectors() ([]AttackVector, error)`, `xssVectors() ([]AttackVector, error)`, `pathTraversalVectors() ([]AttackVector, error)` — each consumed by Task 8's aggregator.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafcatalog/catalog_injection_test.go
package wafcatalog

import "testing"

func TestSqlInjectionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := sqlInjectionVectors()
	if err != nil {
		t.Fatalf("sqlInjectionVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilySQLInjection {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilySQLInjection)
		}
	}
}

func TestXssVectors_ValidAndUnique(t *testing.T) {
	vectors, err := xssVectors()
	if err != nil {
		t.Fatalf("xssVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestPathTraversalVectors_ValidAndUnique(t *testing.T) {
	vectors, err := pathTraversalVectors()
	if err != nil {
		t.Fatalf("pathTraversalVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestSqlInjectionVectors|TestXssVectors|TestPathTraversalVectors" -v`
Expected: FAIL — the three functions are undefined.

- [ ] **Step 3: Write `catalog_injection.go`**

```go
// orchestrator/internal/wafcatalog/catalog_injection.go
package wafcatalog

func sqlInjectionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "laptop stand", Description: "ordinary search term a legitimate user would submit"}
	v1, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "UNION-based SQL injection in a search parameter", SeverityCritical,
		"target exposes a search endpoint backed by a SQL database",
		RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "' UNION SELECT NULL,NULL,NULL--", Description: "UNION-based injection attempting column enumeration via a search query parameter"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-89"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-89 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "jane.doe", Description: "ordinary login username"}
	v2, err := NewAttackVector("SQLI-002", 1, FamilySQLInjection, "Boolean-based blind SQL injection in a login form", SeverityCritical,
		"target has a username/password login form backed by a SQL database",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "admin' OR '1'='1", Description: "boolean-based blind SQLi attempting authentication bypass via an OR-tautology in the username field"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-89"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-89 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/products", PayloadLocation: "query:id", Payload: "1", Description: "ordinary numeric product ID"}
	v3, err := NewAttackVector("SQLI-003", 1, FamilySQLInjection, "Error-based SQL injection via a numeric ID parameter", SeverityHigh,
		"target exposes a product-detail endpoint keyed by a numeric ID, backed by a SQL database",
		RequestTemplate{Method: "GET", Path: "/products", PayloadLocation: "query:id", Payload: "1' AND 1=CONVERT(int,(SELECT @@version))--", Description: "error-based injection attempting to leak the database version via a type-conversion error"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-89"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-89 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}

func xssVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "running shoes", Description: "ordinary search term"}
	v1, err := NewAttackVector("XSS-001", 1, FamilyXSS, "Reflected XSS via a search query parameter", SeverityHigh,
		"target reflects the search query parameter back into the response HTML without encoding",
		RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "<script>alert(document.cookie)</script>", Description: "reflected XSS attempting script execution via an unencoded search query reflection"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-79"}, WSTGCategory: "WSTG-INPV-01", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-79 / OWASP WSTG-INPV-01")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/comments", PayloadLocation: "body:json:body", Payload: "Great article, thanks for sharing!", Description: "ordinary comment text"}
	v2, err := NewAttackVector("XSS-002", 1, FamilyXSS, "Stored XSS via a comment field", SeverityHigh,
		"target stores and later renders a comment body without encoding",
		RequestTemplate{Method: "POST", Path: "/comments", PayloadLocation: "body:json:body", Payload: "<img src=x onerror=alert(1)>", Description: "stored XSS attempting script execution via an unencoded comment body rendered to later viewers"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-79"}, WSTGCategory: "WSTG-INPV-02", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-79 / OWASP WSTG-INPV-02")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/profile", PayloadLocation: "fragment", Payload: "#section-bio", Description: "ordinary URL fragment navigating to a profile section"}
	v3, err := NewAttackVector("XSS-003", 1, FamilyXSS, "DOM-based XSS via a URL fragment reflected into innerHTML", SeverityMedium,
		"target's client-side script reads location.hash and writes it into the DOM via innerHTML without sanitization",
		RequestTemplate{Method: "GET", Path: "/profile", PayloadLocation: "fragment", Payload: "#<svg/onload=alert(1)>", Description: "DOM-based XSS attempting script execution via a URL fragment written unsanitized into innerHTML"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-79"}, WSTGCategory: "WSTG-CLNT-01", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-79 / OWASP WSTG-CLNT-01")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}

func pathTraversalVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/download", PayloadLocation: "query:file", Payload: "invoice-2026-09.pdf", Description: "ordinary filename within the intended download directory"}
	v1, err := NewAttackVector("PATHTRAV-001", 1, FamilyPathTraversal, "Classic directory traversal via a file-download parameter", SeverityCritical,
		"target exposes a file-download endpoint that builds a filesystem path from a user-supplied filename",
		RequestTemplate{Method: "GET", Path: "/download", PayloadLocation: "query:file", Payload: "../../../../etc/passwd", Description: "directory traversal attempting to read a file outside the intended download directory"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-22"}, WSTGCategory: "WSTG-INPV-11", Top10Category: "A01:2021-Broken Access Control"},
		"manually authored from CWE-22 / OWASP WSTG-INPV-11")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/assets/logo.png", Description: "ordinary static asset request"}
	v2, err := NewAttackVector("PATHTRAV-002", 1, FamilyPathTraversal, "Double-URL-encoded directory traversal against a static-asset route", SeverityHigh,
		"target serves static assets from a route that decodes the path twice before filesystem access",
		RequestTemplate{Method: "GET", Path: "/assets/%252e%252e%252fconfig/app.yaml", Description: "double-URL-encoded traversal attempting to bypass a single-decode path-normalization filter"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-22"}, WSTGCategory: "WSTG-INPV-11", Top10Category: "A01:2021-Broken Access Control"},
		"manually authored from CWE-22 / OWASP WSTG-INPV-11")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestSqlInjectionVectors|TestXssVectors|TestPathTraversalVectors" -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/catalog_injection.go orchestrator/internal/wafcatalog/catalog_injection_test.go
git commit -m "feat(wafcatalog): seed catalog -- SQLi, XSS, path traversal"
```

---

### Task 5: Seed catalog — request-shape families (SSRF, file upload, HTTP parser discrepancies)

**Files:**
- Create: `orchestrator/internal/wafcatalog/catalog_network.go`
- Test: `orchestrator/internal/wafcatalog/catalog_network_test.go`

**Interfaces:**
- Consumes: `AttackVector`, `NewAttackVector`, `RequestTemplate`, `StandardsMapping`, `FamilySSRF`, `FamilyFileUpload`, `FamilyHTTPParser`, `SeverityCritical`, `SeverityHigh` (Task 1); `ValidateCatalog` (Task 2).
- Produces: `ssrfVectors() ([]AttackVector, error)`, `fileUploadVectors() ([]AttackVector, error)`, `httpParserVectors() ([]AttackVector, error)` — each consumed by Task 8's aggregator.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafcatalog/catalog_network_test.go
package wafcatalog

import "testing"

func TestSsrfVectors_ValidAndUnique(t *testing.T) {
	vectors, err := ssrfVectors()
	if err != nil {
		t.Fatalf("ssrfVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	foundNoCounterpart := false
	for _, v := range vectors {
		if v.BenignCounterpart == nil {
			foundNoCounterpart = true
			if v.NoBenignCounterpartReason == "" {
				t.Errorf("vector %q has nil BenignCounterpart but empty NoBenignCounterpartReason", v.ID)
			}
		}
	}
	if !foundNoCounterpart {
		t.Error("expected at least one SSRF vector with no benign counterpart (metadata-endpoint probe)")
	}
}

func TestFileUploadVectors_ValidAndUnique(t *testing.T) {
	vectors, err := fileUploadVectors()
	if err != nil {
		t.Fatalf("fileUploadVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestHttpParserVectors_ValidAndUnique(t *testing.T) {
	vectors, err := httpParserVectors()
	if err != nil {
		t.Fatalf("httpParserVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestSsrfVectors|TestFileUploadVectors|TestHttpParserVectors" -v`
Expected: FAIL — the three functions are undefined.

- [ ] **Step 3: Write `catalog_network.go`**

```go
// orchestrator/internal/wafcatalog/catalog_network.go
package wafcatalog

func ssrfVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/api/webhooks", PayloadLocation: "body:json:callbackUrl", Payload: "https://partner.example.com/webhook", Description: "ordinary external partner webhook URL"}
	v1, err := NewAttackVector("SSRF-001", 1, FamilySSRF, "SSRF via a webhook callback URL targeting an internal service", SeverityCritical,
		"target accepts a user-supplied callback URL and fetches it server-side",
		RequestTemplate{Method: "POST", Path: "/api/webhooks", PayloadLocation: "body:json:callbackUrl", Payload: "http://127.0.0.1:8080/admin/internal-status", Description: "SSRF attempting to reach an internal admin service via a user-controlled webhook callback URL"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-918"}, WSTGCategory: "WSTG-INPV-19", Top10Category: "A10:2021-Server-Side Request Forgery"},
		"manually authored from CWE-918 / OWASP WSTG-INPV-19")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "Cloud metadata endpoint SSRF via a URL-fetch parameter", SeverityCritical,
		"target exposes a URL-fetch/webhook/import feature that accepts a user-supplied URL",
		RequestTemplate{Method: "POST", Path: "/api/fetch-url", PayloadLocation: "body:json:url", Payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Description: "attempts to reach cloud-provider instance metadata via a user-controlled URL-fetch feature"},
		nil, "no legitimate client request targets the cloud metadata address range; there is no meaningful benign lookalike for this vector",
		StandardsMapping{CWEIDs: []string{"CWE-918"}, WSTGCategory: "WSTG-INPV-19", Top10Category: "A10:2021-Server-Side Request Forgery"},
		"manually authored from CWE-918 / OWASP WSTG-INPV-19")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func fileUploadVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:file", Payload: "<jpeg bytes>", Description: "ordinary JPEG image upload named vacation.jpg"}
	v1, err := NewAttackVector("FILEUP-001", 1, FamilyFileUpload, "Web-shell upload via a double file extension", SeverityCritical,
		"target accepts file uploads and serves the upload directory via a web-accessible path",
		RequestTemplate{Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:file", Payload: "<?php system($_GET['cmd']); ?>", Description: "uploads a PHP web shell disguised with a double extension (shell.php.jpg) attempting remote code execution if the server executes it as PHP"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-434"}, Top10Category: "A08:2021-Software and Data Integrity Failures"},
		"manually authored from CWE-434")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/upload/archive", PayloadLocation: "body:multipart:file", Payload: "<normal zip bytes>", Description: "ordinary project-files.zip archive of modest size"}
	v2, err := NewAttackVector("FILEUP-002", 1, FamilyFileUpload, "Decompression-bomb archive upload", SeverityHigh,
		"target accepts archive uploads and extracts them server-side",
		RequestTemplate{Method: "POST", Path: "/upload/archive", PayloadLocation: "body:multipart:file", Payload: "<highly compressed archive engineered to expand to many GB on extraction>", Description: "uploads a decompression bomb attempting resource exhaustion via server-side archive extraction"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-434"}, Top10Category: "A08:2021-Software and Data Integrity Failures"},
		"manually authored from CWE-434")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func httpParserVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/checkout", PayloadLocation: "header:Content-Length", Payload: "well-formed single Content-Length", Description: "ordinary checkout request with one well-formed Content-Length header"}
	v1, err := NewAttackVector("HTTPPARSE-001", 1, FamilyHTTPParser, "HTTP request smuggling via conflicting Content-Length and Transfer-Encoding headers", SeverityCritical,
		"target sits behind a front-end proxy and an origin server that disagree on which header takes precedence (CL.TE desync)",
		RequestTemplate{Method: "POST", Path: "/checkout", PayloadLocation: "header:Transfer-Encoding+body", Payload: "Content-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nA\\r\\n0\\r\\n\\r\\nSMUGGLED", Description: "CL.TE request smuggling attempting to desynchronize the front-end proxy and origin server's framing of the request boundary"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-444"}}, "manually authored from CWE-444")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/admin/settings", Description: "ordinary GET request using the permitted verb"}
	v2, err := NewAttackVector("HTTPPARSE-002", 1, FamilyHTTPParser, "HTTP verb tampering against a method-based access control", SeverityHigh,
		"target enforces an access-control rule keyed on HTTP method (e.g. blocks POST but not other verbs) on an administrative route",
		RequestTemplate{Method: "TRACE", Path: "/admin/settings", Description: "verb-tampering attempt using an unexpected HTTP method to bypass a method-specific access-control rule"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-650"}}, "manually authored from CWE-650")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestSsrfVectors|TestFileUploadVectors|TestHttpParserVectors" -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/catalog_network.go orchestrator/internal/wafcatalog/catalog_network_test.go
git commit -m "feat(wafcatalog): seed catalog -- SSRF, file upload, HTTP parser discrepancies"
```

---

### Task 6: Seed catalog — API and auth abuse families

**Files:**
- Create: `orchestrator/internal/wafcatalog/catalog_api.go`
- Test: `orchestrator/internal/wafcatalog/catalog_api_test.go`

**Interfaces:**
- Consumes: `AttackVector`, `NewAttackVector`, `RequestTemplate`, `StandardsMapping`, `FamilyAPIAbuse`, `FamilyAuthAbuse`, `SeverityCritical`, `SeverityHigh`, `SeverityMedium` (Task 1); `ValidateCatalog` (Task 2).
- Produces: `apiAbuseVectors() ([]AttackVector, error)`, `authAbuseVectors() ([]AttackVector, error)` — each consumed by Task 8's aggregator.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafcatalog/catalog_api_test.go
package wafcatalog

import "testing"

func TestApiAbuseVectors_ValidAndUnique(t *testing.T) {
	vectors, err := apiAbuseVectors()
	if err != nil {
		t.Fatalf("apiAbuseVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Standards.APITop10Category == "" {
			t.Errorf("vector %q has no APITop10Category mapping", v.ID)
		}
	}
}

func TestAuthAbuseVectors_ValidAndUnique(t *testing.T) {
	vectors, err := authAbuseVectors()
	if err != nil {
		t.Fatalf("authAbuseVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestApiAbuseVectors|TestAuthAbuseVectors" -v`
Expected: FAIL — the two functions are undefined.

- [ ] **Step 3: Write `catalog_api.go`**

```go
// orchestrator/internal/wafcatalog/catalog_api.go
package wafcatalog

func apiAbuseVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/api/orders/{own_order_id}", Description: "requesting one's own order by ID"}
	v1, err := NewAttackVector("API-001", 1, FamilyAPIAbuse, "Broken Object Level Authorization (BOLA/IDOR) on an orders endpoint", SeverityCritical,
		"target's order-detail endpoint does not verify the authenticated user owns the requested order ID",
		RequestTemplate{Method: "GET", Path: "/api/orders/{other_user_order_id}", PayloadLocation: "path:order_id", Description: "requesting another user's order by ID while authenticated as a different user, attempting object-level authorization bypass"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-639"}, APITop10Category: "API1:2023-Broken Object Level Authorization"},
		"manually authored from CWE-639 / OWASP API Security Top 10 API1:2023")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "PUT", Path: "/api/users/me", PayloadLocation: "body:json", Payload: `{"name":"Jane"}`, Description: "ordinary profile update containing only the name field"}
	v2, err := NewAttackVector("API-002", 1, FamilyAPIAbuse, "Mass assignment via an undocumented isAdmin field", SeverityHigh,
		"target's profile-update endpoint binds the request body directly onto an internal object without an allowlist of settable fields",
		RequestTemplate{Method: "PUT", Path: "/api/users/me", PayloadLocation: "body:json", Payload: `{"name":"Jane","isAdmin":true}`, Description: "mass-assignment attempt adding an undocumented isAdmin field to a profile-update request to attempt privilege escalation"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-915"}, APITop10Category: "API3:2023-Broken Object Property Level Authorization"},
		"manually authored from CWE-915 / OWASP API Security Top 10 API3:2023")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/api/users/42", Description: "ordinary user-detail request returning the default field set"}
	v3, err := NewAttackVector("API-003", 1, FamilyAPIAbuse, "Excessive data exposure via a verbose-fields query parameter", SeverityMedium,
		"target's user-detail endpoint supports a fields-selection parameter that is not restricted to a safe allowlist",
		RequestTemplate{Method: "GET", Path: "/api/users/42", PayloadLocation: "query:fields", Payload: "*", Description: "requests every field via a wildcard fields parameter, attempting to retrieve internal fields (e.g. password hash) not normally serialized"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-200"}, APITop10Category: "API3:2023-Broken Object Property Level Authorization"},
		"manually authored from CWE-200 / OWASP API Security Top 10 API3:2023")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}

func authAbuseVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:password", Payload: "<correct password>", Description: "a single normal login attempt with correct credentials"}
	v1, err := NewAttackVector("AUTH-001", 1, FamilyAuthAbuse, "Credential-stuffing burst against a login endpoint", SeverityHigh,
		"target's login endpoint has no (or a very high) lockout/rate threshold on repeated failed attempts for one username",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:password", Payload: "<bounded burst of N differing password guesses against one username within the test window>", Description: "credential-stuffing burst attempting to brute-force a single account's password via rapid sequential login attempts"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-307"}, WSTGCategory: "WSTG-ATHN-03"},
		"manually authored from CWE-307 / OWASP WSTG-ATHN-03")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "<valid username, incorrect password>", Description: "a login attempt with a valid username and an incorrect password, for comparing the returned error message"}
	v2, err := NewAttackVector("AUTH-002", 1, FamilyAuthAbuse, "Account enumeration via differing login error messages", SeverityMedium,
		"target's login endpoint returns a different error message for an unknown username than for a known username with a wrong password",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "<known-invalid username>", Description: "submits a known-invalid username to observe whether the error message differs from the valid-username/wrong-password case, attempting account enumeration"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-204"}, WSTGCategory: "WSTG-IDNT-04"},
		"manually authored from CWE-204 / OWASP WSTG-IDNT-04")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/api/profile", PayloadLocation: "header:Authorization", Payload: "<normal, correctly-signed JWT>", Description: "ordinary authenticated request with a correctly-signed JWT"}
	v3, err := NewAttackVector("AUTH-003", 1, FamilyAuthAbuse, "JWT algorithm-confusion (alg=none) tampering", SeverityCritical,
		"target's JWT verification accepts the alg header value from the token itself rather than pinning an expected algorithm",
		RequestTemplate{Method: "GET", Path: "/api/profile", PayloadLocation: "header:Authorization", Payload: "<JWT with alg header changed to \"none\" and signature stripped>", Description: "JWT algorithm-confusion attempt rewriting the token's alg header to none and removing the signature, attempting authentication bypass"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-347"}, Top10Category: "A02:2021-Cryptographic Failures"},
		"manually authored from CWE-347")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestApiAbuseVectors|TestAuthAbuseVectors" -v`
Expected: PASS (2/2).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/catalog_api.go orchestrator/internal/wafcatalog/catalog_api_test.go
git commit -m "feat(wafcatalog): seed catalog -- API abuse, auth abuse"
```

---

### Task 7: Seed catalog — operational families (rate limiting, cache weaknesses, policy misconfiguration)

**Files:**
- Create: `orchestrator/internal/wafcatalog/catalog_ops.go`
- Test: `orchestrator/internal/wafcatalog/catalog_ops_test.go`

**Interfaces:**
- Consumes: `AttackVector`, `NewAttackVector`, `RequestTemplate`, `StandardsMapping`, `FamilyRateLimit`, `FamilyCacheWeakness`, `FamilyPolicyMisconfig`, `SeverityCritical`, `SeverityHigh`, `SeverityMedium` (Task 1); `ValidateCatalog` (Task 2).
- Produces: `rateLimitVectors() ([]AttackVector, error)`, `cacheWeaknessVectors() ([]AttackVector, error)`, `policyMisconfigVectors() ([]AttackVector, error)` — each consumed by Task 8's aggregator.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafcatalog/catalog_ops_test.go
package wafcatalog

import "testing"

func TestRateLimitVectors_ValidAndUnique(t *testing.T) {
	vectors, err := rateLimitVectors()
	if err != nil {
		t.Fatalf("rateLimitVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestCacheWeaknessVectors_ValidAndUnique(t *testing.T) {
	vectors, err := cacheWeaknessVectors()
	if err != nil {
		t.Fatalf("cacheWeaknessVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestPolicyMisconfigVectors_ValidAndUnique(t *testing.T) {
	vectors, err := policyMisconfigVectors()
	if err != nil {
		t.Fatalf("policyMisconfigVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestRateLimitVectors|TestCacheWeaknessVectors|TestPolicyMisconfigVectors" -v`
Expected: FAIL — the three functions are undefined.

- [ ] **Step 3: Write `catalog_ops.go`**

```go
// orchestrator/internal/wafcatalog/catalog_ops.go
package wafcatalog

func rateLimitVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/api/quote", Description: "a single request at normal cadence"}
	v1, err := NewAttackVector("RATE-001", 1, FamilyRateLimit, "Burst beyond the declared rate limit on a public pricing endpoint", SeverityMedium,
		"target publishes a documented per-client rate limit on a public API endpoint",
		RequestTemplate{Method: "GET", Path: "/api/quote", Description: "bounded burst of N requests within a short window, exceeding the documented rate limit, attempting to confirm whether the limit is actually enforced"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-799"}, Top10Category: "A04:2021-Insecure Design"},
		"manually authored from CWE-799")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/api/account/transfer", Description: "a single request from one session at normal cadence"}
	v2, err := NewAttackVector("RATE-002", 1, FamilyRateLimit, "Distributed low-and-slow pattern exceeding an account-level aggregate limit", SeverityMedium,
		"target enforces a per-IP rate limit but not an aggregate per-account limit across sessions/source addresses",
		RequestTemplate{Method: "POST", Path: "/api/account/transfer", Description: "requests spread across multiple source addresses/sessions targeting the same account resource, each individually under the per-IP threshold but together exceeding a reasonable account-level limit"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-799"}, Top10Category: "A04:2021-Insecure Design"},
		"manually authored from CWE-799")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func cacheWeaknessVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/", Description: "ordinary request with no host-override header"}
	v1, err := NewAttackVector("CACHE-001", 1, FamilyCacheWeakness, "Web-cache poisoning via an unkeyed X-Forwarded-Host header", SeverityHigh,
		"target reflects the X-Forwarded-Host header into the response and a shared cache does not include that header in its cache key",
		RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "header:X-Forwarded-Host", Payload: "evil.example.com", Description: "cache-poisoning attempt via an unkeyed X-Forwarded-Host header, aiming for the poisoned response to be cached and served to subsequent users"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-20"}},
		"manually authored from CWE-20")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/account/profile", Description: "ordinary authenticated request to the dynamic profile page"}
	v2, err := NewAttackVector("CACHE-002", 1, FamilyCacheWeakness, "Cache deception via a static-looking extension on a dynamic authenticated endpoint", SeverityHigh,
		"target's shared cache keys on file-extension-like URL suffixes regardless of the endpoint's actual dynamic/authenticated nature",
		RequestTemplate{Method: "GET", Path: "/account/profile.css", Description: "cache-deception attempt appending a static-looking extension to a dynamic authenticated endpoint, aiming for a shared cache to store and leak a private response"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-20"}},
		"manually authored from CWE-20")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func policyMisconfigVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "weather forecast", Description: "ordinary search term"}
	v1, err := NewAttackVector("POLICY-001", 1, FamilyPolicyMisconfig, "Known-malicious request against a rule configured detection-only", SeverityHigh,
		"the matching rule for this payload is declared to be running in detection-only (log, not block) mode",
		RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "<script>alert(1)</script>", Description: "known-malicious XSS payload sent against an endpoint whose matching rule is configured detection-only, expecting a DetectedButAllowed verdict if the misconfiguration is real"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-16"}},
		"manually authored from CWE-16")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/api/legacy/import", PayloadLocation: "body:json:data", Payload: "<ordinary import data>", Description: "ordinary legacy-import request"}
	v2, err := NewAttackVector("POLICY-002", 1, FamilyPolicyMisconfig, "Known-malicious request against a route excluded by an overly broad legacy-compatibility exception", SeverityCritical,
		"the target route is covered by a policy exclusion/allowlist that exempts an entire legacy API path prefix from inspection",
		RequestTemplate{Method: "POST", Path: "/api/legacy/import", PayloadLocation: "body:json:data", Payload: "' UNION SELECT NULL,NULL,NULL--", Description: "known-malicious SQLi payload sent against a route excluded from WAF inspection by an overly broad legacy-compatibility policy exception"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-16"}},
		"manually authored from CWE-16")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run "TestRateLimitVectors|TestCacheWeaknessVectors|TestPolicyMisconfigVectors" -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/catalog_ops.go orchestrator/internal/wafcatalog/catalog_ops_test.go
git commit -m "feat(wafcatalog): seed catalog -- rate limiting, cache weaknesses, policy misconfiguration"
```

---

### Task 8: Catalog aggregator

**Files:**
- Create: `orchestrator/internal/wafcatalog/catalog.go`
- Test: `orchestrator/internal/wafcatalog/catalog_test.go`

**Interfaces:**
- Consumes: `sqlInjectionVectors`, `xssVectors`, `pathTraversalVectors` (Task 4); `ssrfVectors`, `fileUploadVectors`, `httpParserVectors` (Task 5); `apiAbuseVectors`, `authAbuseVectors` (Task 6); `rateLimitVectors`, `cacheWeaknessVectors`, `policyMisconfigVectors` (Task 7); `ValidateCatalog` (Task 2); all 11 `AttackFamily` constants (Task 1).
- Produces: `AudspectWAFAttackCatalog() ([]AttackVector, error)` — the package's public entry point.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafcatalog/catalog_test.go
package wafcatalog

import "testing"

func TestAudspectWAFAttackCatalog_ReturnsValidatedCatalog(t *testing.T) {
	vectors, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	if len(vectors) != 26 {
		t.Fatalf("len(vectors) = %d, want 26", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("returned catalog fails ValidateCatalog: %v", err)
	}
}

func TestAudspectWAFAttackCatalog_CoversAllElevenFamilies(t *testing.T) {
	vectors, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	want := []AttackFamily{
		FamilySQLInjection, FamilyXSS, FamilyPathTraversal, FamilySSRF, FamilyFileUpload,
		FamilyHTTPParser, FamilyAPIAbuse, FamilyAuthAbuse, FamilyRateLimit, FamilyCacheWeakness, FamilyPolicyMisconfig,
	}
	seen := make(map[AttackFamily]bool)
	for _, v := range vectors {
		seen[v.Family] = true
	}
	for _, f := range want {
		if !seen[f] {
			t.Errorf("no vector found for family %q", f)
		}
	}
}

// Review Focus: AudspectWAFAttackCatalog must actually call ValidateCatalog
// and propagate its error -- with 26 hand-authored entries across 4 files,
// an accidental duplicate ID is an easy slip, and the aggregator must fail
// loudly rather than silently return a catalog containing one. This test
// cannot inject a real duplicate into the production seed data without
// breaking it, so it proves the wiring the same way Task 2 proved
// ValidateCatalog itself: by confirming the aggregator's own vectors contain
// no duplicate (the positive case already covered by
// TestAudspectWAFAttackCatalog_ReturnsValidatedCatalog above) and that every
// individual family function's output independently passes ValidateCatalog
// (already proven in Tasks 4-7) -- together these show there is no seam
// where a duplicate could slip past unvalidated.
func TestAudspectWAFAttackCatalog_EveryEntryIndividuallyValid(t *testing.T) {
	vectors, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	ids := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if ids[v.ID] {
			t.Errorf("duplicate ID %q present in the returned catalog despite ValidateCatalog", v.ID)
		}
		ids[v.ID] = true
		if v.ID == "" || v.Provenance == "" {
			t.Errorf("vector %+v failed basic construction invariants", v)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -run TestAudspectWAFAttackCatalog -v`
Expected: FAIL — `AudspectWAFAttackCatalog` is undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafcatalog/catalog.go
package wafcatalog

import "fmt"

// AudspectWAFAttackCatalog returns Audspect's real, current seed attack-test
// catalog: roughly 25-30 hand-authored vectors across all eleven AttackFamily
// constants, validated before being returned. A seed-data error (a bad
// construction call, or a duplicate ID introduced while hand-authoring
// across family files) returns an error here rather than a silently
// incomplete or invalid catalog.
func AudspectWAFAttackCatalog() ([]AttackVector, error) {
	var all []AttackVector

	families := []func() ([]AttackVector, error){
		sqlInjectionVectors, xssVectors, pathTraversalVectors,
		ssrfVectors, fileUploadVectors, httpParserVectors,
		apiAbuseVectors, authAbuseVectors,
		rateLimitVectors, cacheWeaknessVectors, policyMisconfigVectors,
	}
	for _, f := range families {
		vectors, err := f()
		if err != nil {
			return nil, fmt.Errorf("loading seed catalog: %w", err)
		}
		all = append(all, vectors...)
	}

	if err := ValidateCatalog(all); err != nil {
		return nil, fmt.Errorf("seed catalog failed validation: %w", err)
	}
	return all, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafcatalog/... -v`
Expected: PASS — every test in the package passes, including all tasks' tests run together for the first time as a whole package.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafcatalog/catalog.go orchestrator/internal/wafcatalog/catalog_test.go
git commit -m "feat(wafcatalog): AudspectWAFAttackCatalog aggregator"
```
