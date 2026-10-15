# WAF BAS Mastery Phase 6: Bot, Abuse and Rate-Limit Efficacy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafbotabuse`, a new attack-vector catalog covering bounded-automation, rate-limit, credential-abuse, and distributed-enforcement attack shapes, evaluated through the unmodified `wafval.EvaluateClaim` pipeline Phase 2 already built.

**Architecture:** A pure-Go, I/O-free package depending only on `internal/wafval`, structurally a third sibling of `internal/wafcatalog` and `internal/wafapiflow` (no dependency on either, or on `wafpolicygap`/`wafevasion`). It reuses the same proven `AttackVector`-equivalent/`Expectations`/aggregator pattern, redefined locally with its own types, because every one of Phase 6's four named items is "one malicious request a control should block, with a benign counterpart that should be allowed" — exactly what that pattern already models. No new evaluation function and no new `wafval` verdict logic are needed in this phase.

**Tech Stack:** Go 1.26.6, stdlib only (regexp for CWE-ID format), `internal/wafval` (already merged, read-only dependency).

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase6-wafbotabuse-design.md`

## Global Constraints

- Package `internal/wafbotabuse` depends only on `internal/wafval`; it does not depend on `internal/wafcatalog`, `internal/wafpolicygap`, `internal/wafevasion`, or `internal/wafapiflow` (spec §2).
- Zero new `wafval` verdict logic — every vector's claim is evaluated by the unmodified `wafval.EvaluateClaim` (spec §2, §6).
- `NewBotAbuseVector` validates identically to `wafcatalog.NewAttackVector`/`wafapiflow.NewAPIFlowVector`: ID non-empty, `Version >= 1`, known `Category`/`Severity`, `Malicious.{Method,Path,Description}` non-empty, every `Standards.CWEIDs` entry matches `^CWE-\d+$`, `Standards` has at least one of its four mapping fields set, `Provenance` non-empty, and exactly one of `BenignCounterpart`/`NoBenignCounterpartReason` (spec §4).
- `Expectations(policyBasis)` returns exactly 1 entry (malicious only, `wafval.ClaimPrevention`) when `NoBenignCounterpartReason` is set, or exactly 2 (malicious then benign, `wafval.ClaimFalsePositive`) when `BenignCounterpart` is set — never 0, never padded (spec §6).
- `AudspectWAFBotAbuseCatalog()` ships exactly 4 vectors, one per `BotAbuseCategory`, per spec §7's table.

## Review Focus

- Both `BenignCounterpart` and `NoBenignCounterpartReason` set, or neither set, must both be rejected at construction — the rule that keeps every vector's benign-counterpart story honest. Pinned in Task 1.
- A malformed `CWEIDs` entry (not matching `^CWE-\d+$`) must be rejected at construction, not silently stored and surfaced later in a client-facing report as a broken reference. Pinned in Task 1.
- A catalog containing two vectors with the same ID must be rejected — `NewBotAbuseVector` cannot see sibling entries, so this is the only place that's caught. Pinned in Task 2.
- `Expectations` must never return zero entries and must never pad to 2 entries when there is no `BenignCounterpart` — a caller iterating this slice to collect evidence must see exactly what the vector actually declares. Pinned in Task 3.
- `AudspectWAFBotAbuseCatalog()` must genuinely cover all 4 distinct `BotAbuseCategory` values (not, say, two vectors of the same category and a gap elsewhere). Pinned in Task 4.

---

### Task 1: Core types and construction-time validation

**Files:**
- Create: `orchestrator/internal/wafbotabuse/types.go`
- Create: `orchestrator/internal/wafbotabuse/vector.go`
- Test: `orchestrator/internal/wafbotabuse/vector_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (first task); stdlib `regexp` only.
- Produces: `BotAbuseCategory` (+ 4 constants: `CategoryBoundedAutomation`, `CategoryRateLimit`, `CategoryCredentialAbuse`, `CategoryDistributedEnforcement`), `Severity` (+ 4 constants: `SeverityCritical`, `SeverityHigh`, `SeverityMedium`, `SeverityLow`), `RequestTemplate{Method, Path, PayloadLocation, Payload, Description string}`, `StandardsMapping{CWEIDs []string, WSTGCategory, Top10Category, APITop10Category string, ATTACKTechniques []string}`, `BotAbuseVector{ID string, Version int, Category BotAbuseCategory, Name string, Severity Severity, Preconditions string, Malicious RequestTemplate, BenignCounterpart *RequestTemplate, NoBenignCounterpartReason string, Standards StandardsMapping, Provenance string}`, `NewBotAbuseVector(id string, version int, category BotAbuseCategory, name string, severity Severity, preconditions string, malicious RequestTemplate, benignCounterpart *RequestTemplate, noBenignCounterpartReason string, standards StandardsMapping, provenance string) (BotAbuseVector, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafbotabuse/vector_test.go
package wafbotabuse

import "testing"

func validMalicious() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "50 requests in 2 seconds, missing JS-challenge cookie and User-Agent", Description: "non-human-paced automated burst"}
}

func validBenign() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "single human-paced request with JS-challenge cookie and User-Agent present", Description: "single human-paced request with normal browser signals"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-799"}}
}

func TestNewBotAbuseVector_Valid_Succeeds(t *testing.T) {
	benign := validBenign()
	v, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "Non-Human-Paced Automation Burst", SeverityHigh,
		"search endpoint accepts unauthenticated GET requests with no declared per-client pacing requirement", validMalicious(), &benign, "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewBotAbuseVector: %v", err)
	}
	if v.ID != "BOTABUSE-001" {
		t.Errorf("ID = %q, want %q", v.ID, "BOTABUSE-001")
	}
}

func TestNewBotAbuseVector_EmptyID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewBotAbuseVector_VersionLessThanOne_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 0, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for version < 1, got nil")
	}
}

func TestNewBotAbuseVector_UnknownCategory_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, BotAbuseCategory("bogus_category"), "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Category, got nil")
	}
}

func TestNewBotAbuseVector_UnknownSeverity_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", Severity("bogus_severity"), "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for unknown Severity, got nil")
	}
}

func TestNewBotAbuseVector_EmptyMaliciousMethod_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Method = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewBotAbuseVector_EmptyMaliciousPath_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Path = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Path, got nil")
	}
}

func TestNewBotAbuseVector_EmptyMaliciousDescription_Rejected(t *testing.T) {
	benign := validBenign()
	malicious := validMalicious()
	malicious.Description = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", malicious, &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

// Review Focus: a malformed CWE ID must be rejected at construction, not
// silently stored and surfaced later in a client-facing report.
func TestNewBotAbuseVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{CWEIDs: []string{"not-a-cwe-id"}}, "x")
	if err == nil {
		t.Fatal("want error for malformed CWE ID, got nil")
	}
}

func TestNewBotAbuseVector_StandardsAllEmpty_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "",
		StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has no mapping field set, got nil")
	}
}

func TestNewBotAbuseVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

// Review Focus: both BenignCounterpart and NoBenignCounterpartReason set is
// a contradictory double-statement and must be rejected.
func TestNewBotAbuseVector_BothBenignAndReasonSet_Rejected(t *testing.T) {
	benign := validBenign()
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "no benign exists", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

// Review Focus: neither set is a silent omission and must be rejected.
func TestNewBotAbuseVector_NeitherBenignNorReasonSet_Rejected(t *testing.T) {
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), nil, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

func TestNewBotAbuseVector_BenignCounterpartInvalid_Rejected(t *testing.T) {
	benign := validBenign()
	benign.Description = ""
	_, err := NewBotAbuseVector("BOTABUSE-001", 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err == nil {
		t.Fatal("want error for an invalid BenignCounterpart (empty Description), got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/wafbotabuse/types.go
// Package wafbotabuse is a vendor-neutral, I/O-free attack-vector catalog
// covering bounded-automation, rate-limit, credential-abuse, and
// distributed-enforcement attack shapes. It depends only on
// internal/wafval, structurally a third sibling of wafcatalog and
// wafapiflow rather than a consumer of either: no dependency on
// wafcatalog, wafpolicygap, wafevasion, or wafapiflow. Every vector's
// claim is evaluated by the unmodified wafval.EvaluateClaim -- zero new
// wafval verdict logic. Fixture-backed only; real execution is deferred.
package wafbotabuse

// BotAbuseCategory is one of the four breadth categories this catalog
// covers.
type BotAbuseCategory string

const (
	CategoryBoundedAutomation      BotAbuseCategory = "bounded_automation"
	CategoryRateLimit              BotAbuseCategory = "rate_limit"
	CategoryCredentialAbuse        BotAbuseCategory = "credential_abuse"
	CategoryDistributedEnforcement BotAbuseCategory = "distributed_enforcement"
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

// BotAbuseVector is one versioned catalog entry. BenignCounterpart is nil
// only when NoBenignCounterpartReason explains why no legitimate lookalike
// exists -- never a silent omission.
type BotAbuseVector struct {
	ID                        string
	Version                   int
	Category                  BotAbuseCategory
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
// orchestrator/internal/wafbotabuse/vector.go
package wafbotabuse

import (
	"fmt"
	"regexp"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validCategory(c BotAbuseCategory) bool {
	switch c {
	case CategoryBoundedAutomation, CategoryRateLimit, CategoryCredentialAbuse, CategoryDistributedEnforcement:
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

// NewBotAbuseVector validates at construction time, never at render time.
func NewBotAbuseVector(
	id string,
	version int,
	category BotAbuseCategory,
	name string,
	severity Severity,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (BotAbuseVector, error) {
	if id == "" {
		return BotAbuseVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return BotAbuseVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validCategory(category) {
		return BotAbuseVector{}, fmt.Errorf("category %q is not one of the known BotAbuseCategory constants", category)
	}
	if !validSeverity(severity) {
		return BotAbuseVector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return BotAbuseVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return BotAbuseVector{}, err
	}
	if provenance == "" {
		return BotAbuseVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return BotAbuseVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return BotAbuseVector{}, err
		}
	}
	return BotAbuseVector{
		ID: id, Version: version, Category: category, Name: name, Severity: severity,
		Preconditions: preconditions, Malicious: malicious, BenignCounterpart: benignCounterpart,
		NoBenignCounterpartReason: noBenignCounterpartReason, Standards: standards, Provenance: provenance,
	}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -v`
Expected: PASS — all 13 test functions pass.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/wafbotabuse/types.go orchestrator/internal/wafbotabuse/vector.go orchestrator/internal/wafbotabuse/vector_test.go
git commit -m "feat(wafbotabuse): BotAbuseVector types and construction-time validation"
```

---

### Task 2: Catalog-wide ID uniqueness

**Files:**
- Create: `orchestrator/internal/wafbotabuse/validate.go`
- Test: `orchestrator/internal/wafbotabuse/validate_test.go`

**Interfaces:**
- Consumes: `BotAbuseVector`, `NewBotAbuseVector` (Task 1).
- Produces: `ValidateBotAbuseCatalog(vectors []BotAbuseVector) error`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafbotabuse/validate_test.go
package wafbotabuse

import "testing"

func mustVector(t *testing.T, id string) BotAbuseVector {
	t.Helper()
	benign := validBenign()
	v, err := NewBotAbuseVector(id, 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewBotAbuseVector(%q): %v", id, err)
	}
	return v
}

func TestValidateBotAbuseCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateBotAbuseCatalog([]BotAbuseVector{mustVector(t, "BOTABUSE-001"), mustVector(t, "BOTABUSE-002")})
	if err != nil {
		t.Fatalf("ValidateBotAbuseCatalog: %v", err)
	}
}

func TestValidateBotAbuseCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateBotAbuseCatalog([]BotAbuseVector{mustVector(t, "BOTABUSE-001"), mustVector(t, "BOTABUSE-001")})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateBotAbuseCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateBotAbuseCatalog(nil); err != nil {
		t.Fatalf("ValidateBotAbuseCatalog(nil): %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -run TestValidateBotAbuseCatalog -v`
Expected: FAIL — `ValidateBotAbuseCatalog` is undefined.

- [ ] **Step 3: Write `validate.go`**

```go
// orchestrator/internal/wafbotabuse/validate.go
package wafbotabuse

import "fmt"

// ValidateBotAbuseCatalog rejects a catalog containing two vectors with
// the same ID. NewBotAbuseVector cannot see sibling entries, so this is
// the single place uniqueness is enforced across a whole catalog
// snapshot.
func ValidateBotAbuseCatalog(vectors []BotAbuseVector) error {
	seen := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if seen[v.ID] {
			return fmt.Errorf("duplicate bot-abuse vector ID %q", v.ID)
		}
		seen[v.ID] = true
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -run TestValidateBotAbuseCatalog -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafbotabuse/validate.go orchestrator/internal/wafbotabuse/validate_test.go
git commit -m "feat(wafbotabuse): catalog-wide ID uniqueness validation"
```

---

### Task 3: Evidence integration

**Files:**
- Create: `orchestrator/internal/wafbotabuse/evidence.go`
- Test: `orchestrator/internal/wafbotabuse/evidence_test.go`

**Interfaces:**
- Consumes: `BotAbuseVector`, `RequestTemplate`, `NewBotAbuseVector` (Task 1); `wafval.Expectation{Claim, PolicyBasis, PolicyVerified}`, `wafval.ClaimPrevention`, `wafval.ClaimFalsePositive` (all already merged, `internal/wafval`).
- Produces: `BotAbuseLeg` (+ 2 constants: `LegMalicious`, `LegBenign`), `BotAbuseLegExpectation{VectorID string, Leg BotAbuseLeg, Request RequestTemplate, Expectation wafval.Expectation}`, `(v BotAbuseVector) Expectations(policyBasis string) []BotAbuseLegExpectation`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafbotabuse/evidence_test.go
package wafbotabuse

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestBotAbuseVector_Expectations_WithBenignCounterpart_ReturnsTwoLegs(t *testing.T) {
	v := mustVector(t, "BOTABUSE-001")
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
func TestBotAbuseVector_Expectations_NoBenignCounterpart_ReturnsOneLeg(t *testing.T) {
	v, err := NewBotAbuseVector("BOTABUSE-004", 1, CategoryDistributedEnforcement, "x", SeverityHigh, "x", validMalicious(), nil, "no legitimate lookalike for this probe", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewBotAbuseVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMalicious || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMalicious with ClaimPrevention", legs[0])
	}
}

func TestBotAbuseVector_Expectations_VectorIDCarriedOnEachLeg(t *testing.T) {
	v := mustVector(t, "BOTABUSE-001")
	legs := v.Expectations("owasp-crs-default")
	for _, leg := range legs {
		if leg.VectorID != "BOTABUSE-001" {
			t.Errorf("leg.VectorID = %q, want %q", leg.VectorID, "BOTABUSE-001")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -run TestBotAbuseVector_Expectations -v`
Expected: FAIL — `Expectations` is undefined.

- [ ] **Step 3: Write `evidence.go`**

```go
// orchestrator/internal/wafbotabuse/evidence.go
package wafbotabuse

import "github.com/audspect/bas/internal/wafval"

// BotAbuseLeg names which half of a BotAbuseVector a leg's expectation
// came from.
type BotAbuseLeg string

const (
	LegMalicious BotAbuseLeg = "malicious"
	LegBenign    BotAbuseLeg = "benign"
)

// BotAbuseLegExpectation pairs one leg's request template with the
// wafval.Expectation it resolves to, so a test harness can collect
// evidence and call wafval.EvaluateClaim without re-deriving the claim
// mapping itself.
type BotAbuseLegExpectation struct {
	VectorID    string
	Leg         BotAbuseLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's BotAbuseLegExpectation, plus
// the benign leg's when BenignCounterpart is set -- never a padded slice.
// policyBasis is caller-supplied: the catalog is deployment-neutral and
// does not know what policy is actually in force, so PolicyVerified is
// always false here; only the evidence-collecting caller can confirm a
// policy was in force.
func (v BotAbuseVector) Expectations(policyBasis string) []BotAbuseLegExpectation {
	legs := []BotAbuseLegExpectation{
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
		legs = append(legs, BotAbuseLegExpectation{
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

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -run TestBotAbuseVector_Expectations -v`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafbotabuse/evidence.go orchestrator/internal/wafbotabuse/evidence_test.go
git commit -m "feat(wafbotabuse): evidence integration via Expectations"
```

---

### Task 4: Seed vector catalog

**Files:**
- Create: `orchestrator/internal/wafbotabuse/catalog.go`
- Test: `orchestrator/internal/wafbotabuse/catalog_test.go`

**Interfaces:**
- Consumes: `BotAbuseVector`, `NewBotAbuseVector`, all 4 `BotAbuseCategory` constants, all 4 `Severity` constants, `RequestTemplate`, `StandardsMapping` (Task 1); `ValidateBotAbuseCatalog` (Task 2).
- Produces: `AudspectWAFBotAbuseCatalog() ([]BotAbuseVector, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/wafbotabuse/catalog_test.go
package wafbotabuse

import "testing"

func TestAudspectWAFBotAbuseCatalog_ReturnsFourVectors(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	if len(vectors) != 4 {
		t.Fatalf("len(vectors) = %d, want 4", len(vectors))
	}
	if err := ValidateBotAbuseCatalog(vectors); err != nil {
		t.Errorf("ValidateBotAbuseCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 4 distinct categories, not
// duplicate one and skip another.
func TestAudspectWAFBotAbuseCatalog_CoversAllFourCategories(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	want := []BotAbuseCategory{
		CategoryBoundedAutomation, CategoryRateLimit, CategoryCredentialAbuse, CategoryDistributedEnforcement,
	}
	seen := make(map[BotAbuseCategory]int)
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

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -run TestAudspectWAFBotAbuseCatalog -v`
Expected: FAIL — `AudspectWAFBotAbuseCatalog` is undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafbotabuse/catalog.go
package wafbotabuse

import "fmt"

// AudspectWAFBotAbuseCatalog returns Audspect's real, current seed
// bot/abuse/rate-limit vector catalog: exactly one vector per
// BotAbuseCategory, validated before being returned.
func AudspectWAFBotAbuseCatalog() ([]BotAbuseVector, error) {
	type seed struct {
		id, name, preconditions, provenance string
		category                            BotAbuseCategory
		severity                            Severity
		malicious, benign                   RequestTemplate
		standards                           StandardsMapping
	}
	seeds := []seed{
		{
			id: "BOTABUSE-001", category: CategoryBoundedAutomation, name: "Non-Human-Paced Automation Burst", severity: SeverityHigh,
			preconditions: "search endpoint accepts unauthenticated GET requests with no declared per-client pacing requirement",
			malicious: RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "50 requests in 2 seconds (25/sec), each missing a browser-issued JS-challenge cookie and User-Agent header",
				Description: "a rapid, non-human-paced burst of otherwise-valid search requests lacking standard browser automation signals (JS-challenge cookie, User-Agent), consistent with a headless scripted client rather than a human browsing session"},
			benign: RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "a single human-paced request carrying a valid JS-challenge cookie and a standard browser User-Agent header",
				Description: "a single search request sent at human timing with normal browser signals present"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-799"}}, provenance: "manually authored from waf.txt Phase 6's named bounded-automation category",
		},
		{
			id: "BOTABUSE-002", category: CategoryRateLimit, name: "Order-Creation Rate-Limit Overrun", severity: SeverityHigh,
			preconditions: "order-creation API declares a 500 requests/60s rate limit per API key",
			malicious: RequestTemplate{Method: "POST", Path: "/api/orders", PayloadLocation: "header:X-API-Key+timing", Payload: "the 501st order-creation request within a 60-second window from the same API key, following 500 prior requests already sent in that window",
				Description: "exceeds the order-creation API's declared rate limit (500 requests/60s per API key) by continuing past the threshold"},
			benign: RequestTemplate{Method: "POST", Path: "/api/orders", PayloadLocation: "header:X-API-Key+timing", Payload: "a single order-creation request from an API key that has sent 10 requests in the current 60-second window, well within the 500/60s limit",
				Description: "a request well within the declared rate limit"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-770"}}, provenance: "manually authored from waf.txt Phase 6's named rate-limits category",
		},
		{
			id: "BOTABUSE-003", category: CategoryCredentialAbuse, name: "Failed-Login Lockout Bypass", severity: SeverityCritical,
			preconditions: "login endpoint declares a 20 failed-attempts/5-minute lockout threshold per username",
			malicious: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+timing", Payload: "the 21st failed login attempt within 5 minutes against the same username, following 20 prior failed attempts, with no CAPTCHA/lockout triggered yet",
				Description: "continues brute-force login attempts past the declared failed-attempt threshold (20 failures/5 min) without the account entering a lockout or CAPTCHA-challenge state"},
			benign: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username", Payload: "a single login attempt against a username with zero prior failed attempts in the current window",
				Description: "a single legitimate login attempt with no preceding failure history"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-307"}}, provenance: "manually authored from waf.txt Phase 6's named credential-abuse-controls category",
		},
		{
			id: "BOTABUSE-004", category: CategoryDistributedEnforcement, name: "Cross-Node Lockout-State Bypass", severity: SeverityCritical,
			preconditions: "login endpoint's 20 failed-attempts/5-minute lockout is declared to be enforced globally across the deployment's backend nodes",
			malicious: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+routing", Payload: "20 failed login attempts against the same username, deliberately distributed 5-at-a-time across 4 different backend nodes via round-robin, so no single node locally observes more than 5 failures, while the username's true aggregate failure count across the deployment is 20",
				Description: "splits a brute-force attempt across multiple backend nodes to stay under each node's local failure threshold, testing whether the control's lockout state is shared/global across the distributed deployment or only locally enforced per node"},
			benign: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+routing", Payload: "20 login attempts, all correctly evaluated against the deployment's single shared/global failure-count state for that username",
				Description: "the same volume of attempts evaluated against genuinely shared distributed state, which should trigger the lockout identically to a single-node deployment"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-799"}}, provenance: "manually authored from waf.txt Phase 6's named distributed-enforcement category",
		},
	}

	var out []BotAbuseVector
	for _, sd := range seeds {
		benign := sd.benign
		v, err := NewBotAbuseVector(sd.id, 1, sd.category, sd.name, sd.severity, sd.preconditions, sd.malicious, &benign, "", sd.standards, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed bot-abuse catalog: %w", err)
		}
		out = append(out, v)
	}

	if err := ValidateBotAbuseCatalog(out); err != nil {
		return nil, fmt.Errorf("seed bot-abuse catalog failed validation: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafbotabuse/... -v`
Expected: PASS — every test in the package passes, including every earlier task's tests run together for the first time.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafbotabuse/catalog.go orchestrator/internal/wafbotabuse/catalog_test.go
git commit -m "feat(wafbotabuse): AudspectWAFBotAbuseCatalog seeding all 4 categories"
```
