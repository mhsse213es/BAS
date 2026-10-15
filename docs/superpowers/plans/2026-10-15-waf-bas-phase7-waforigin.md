# WAF BAS Mastery Phase 7: Origin, Deployment and Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/waforigin`, covering waf.txt Phase 7's 5 named items (routing coverage, direct-origin reachability, fail-open conditions, TLS/proxy behavior, configuration consistency) across three evaluation shapes sharing one package.

**Architecture:** Unlike Phases 2/5/6 (single-shape attack catalogs), this phase has three distinct evaluation shapes: (A) bypass pairs — a baseline/weakened comparison like `wafpolicygap`'s, but with a topology/availability attribution story instead of a policy-rule-change one, so it owns its own local decision function rather than calling `wafval.EvaluatePolicyGap`; (B) a protocol-claim vector mirroring `wafbotabuse`'s single-vector construction pattern; (C) a cross-node consistency comparison built only on `wafval.EvaluateClaim`'s already-derived output. All three cross-reference real, existing `wafcatalog.AttackVector`s rather than inventing new payloads — this phase contributes no new attack payloads, only new evaluation logic over existing ones under topology-weakening conditions.

**Tech Stack:** Go 1.26.6, stdlib only (`fmt`, `regexp`), `internal/wafval` + `internal/wafcatalog` (both already merged, read-only dependencies).

**Spec:** `docs/superpowers/specs/2026-10-15-waf-bas-phase7-waforigin-design.md`

## Global Constraints

- Package `internal/waforigin` depends only on `internal/wafval` and `internal/wafcatalog` (read-only cross-reference to existing vectors); it does not depend on `internal/wafpolicygap`, `internal/wafevasion`, `internal/wafapiflow`, or `internal/wafbotabuse`, and none of those four depend on it either (spec §2).
- Zero new `wafval` verdict-derivation logic: Task 3's `decideOriginGap` and Task 5's consistency comparison are both local, built only on `wafval.EvaluateClaim`'s existing output (spec §3, §8).
- `trustworthyBlocked` in Task 3 must match `wafevasion`'s exactly: `r.Verdict == wafval.VerdictBlocked && (r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium)`.
- `NewProtocolBehaviorVector` in Task 4 validates identically in substance to `wafbotabuse.NewBotAbuseVector`, minus the category check (spec §4.3).
- Every seed `AttackVectorID` cross-referenced in Task 6 must be a real ID present in `wafcatalog.AudspectWAFAttackCatalog()` — confirmed in this plan against `orchestrator/internal/wafcatalog/catalog_injection.go` and `catalog_network.go`: `SQLI-001`, `XSS-001`, `SSRF-001`, `PATHTRAV-001` all exist.

## Review Focus

- A `WeaknessType` whose `Kind()` is not `KindBypassPair` (including an unknown value) must be rejected by `NewBypassScenario`, not silently accepted. Pinned in Task 2.
- `EvaluateBypassScenario`'s gap case (the bypass leg's evidence shows the attack reached the origin neither detected nor blocked) must return `wafval.VerdictMissed` specifically — `wafval.VerdictAllowed` is unreachable here since the malicious leg's claim is always `ClaimPrevention` (confirmed against `wafval.derivePrevention`, which never returns `VerdictAllowed` — that value is reserved for `ClaimFalsePositive`) — a caller branching on the exact verdict value must see the right one. Pinned in Task 3.
- `ProtocolBehaviorVector`'s benign-counterpart validation must reject both `BenignCounterpart` and `NoBenignCounterpartReason` set, and reject neither set, exactly like `wafbotabuse`'s precedent — a vector construction call cannot see this ambiguity at render time. Pinned in Task 4.
- `EvaluateConfigurationConsistency`'s drift reason string must name both disagreeing nodes (by `NodeID`), not just announce that disagreement occurred — a report reader needs to know which nodes to go fix. Pinned in Task 5.
- The seed catalog's cross-referenced `AttackVectorID`s must be checked against the real `wafcatalog` catalog by a test, not just asserted to exist in prose — a typo'd ID must fail a test run, not silently ship into a report. Pinned in Task 6.

---

### Task 1: Weakness taxonomy

**Files:**
- Create: `orchestrator/internal/waforigin/types.go`
- Test: `orchestrator/internal/waforigin/types_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `WeaknessKind` (+ 3 constants: `KindBypassPair`, `KindProtocolClaim`, `KindCrossNodeConsistency`), `WeaknessType` (+ 5 constants: `WeaknessRoutingCoverageGap`, `WeaknessDirectOriginReachability`, `WeaknessFailOpenOnUnavailability`, `WeaknessTLSProxyBehavior`, `WeaknessConfigurationConsistency`), `func (w WeaknessType) Kind() WeaknessKind`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/waforigin/types_test.go
package waforigin

import "testing"

func TestWeaknessType_Kind_MapsAllFiveKnownValues(t *testing.T) {
	cases := []struct {
		weakness WeaknessType
		want     WeaknessKind
	}{
		{WeaknessRoutingCoverageGap, KindBypassPair},
		{WeaknessDirectOriginReachability, KindBypassPair},
		{WeaknessFailOpenOnUnavailability, KindBypassPair},
		{WeaknessTLSProxyBehavior, KindProtocolClaim},
		{WeaknessConfigurationConsistency, KindCrossNodeConsistency},
	}
	for _, c := range cases {
		if got := c.weakness.Kind(); got != c.want {
			t.Errorf("%q.Kind() = %q, want %q", c.weakness, got, c.want)
		}
	}
}

func TestWeaknessType_Kind_UnknownValueReturnsEmpty(t *testing.T) {
	if got := WeaknessType("bogus_weakness").Kind(); got != "" {
		t.Errorf("Kind() for unknown WeaknessType = %q, want \"\"", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/waforigin/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/waforigin/types.go
// Package waforigin is a vendor-neutral, I/O-free evaluator covering
// waf.txt Phase 7's deployment-topology and resilience items: routing
// coverage, direct-origin reachability, fail-open conditions, TLS/proxy
// behavior, and configuration consistency. It depends on internal/wafval
// and internal/wafcatalog (read-only cross-reference to existing attack
// vectors -- this package contributes no new attack payloads, only new
// evaluation logic over existing ones under topology-weakening
// conditions). It does not depend on wafpolicygap, wafevasion,
// wafapiflow, or wafbotabuse, and none of those depend on it either.
// Fixture-backed only; real topology discovery and multi-node collection
// are deferred.
package waforigin

// WeaknessKind is one of the three evaluation shapes this package covers.
type WeaknessKind string

const (
	KindBypassPair           WeaknessKind = "bypass_pair"
	KindProtocolClaim        WeaknessKind = "protocol_claim"
	KindCrossNodeConsistency WeaknessKind = "cross_node_consistency"
)

// WeaknessType is one of the five named items from waf.txt Phase 7.
type WeaknessType string

const (
	WeaknessRoutingCoverageGap       WeaknessType = "routing_coverage_gap"
	WeaknessDirectOriginReachability WeaknessType = "direct_origin_reachability"
	WeaknessFailOpenOnUnavailability WeaknessType = "fail_open_on_waf_unavailability"
	WeaknessTLSProxyBehavior         WeaknessType = "tls_proxy_behavior"
	WeaknessConfigurationConsistency WeaknessType = "configuration_consistency"
)

// Kind maps a WeaknessType to the evaluation shape it is evaluated under.
// An unknown WeaknessType returns "" -- callers must treat that as invalid,
// never as a fourth kind.
func (w WeaknessType) Kind() WeaknessKind {
	switch w {
	case WeaknessRoutingCoverageGap, WeaknessDirectOriginReachability, WeaknessFailOpenOnUnavailability:
		return KindBypassPair
	case WeaknessTLSProxyBehavior:
		return KindProtocolClaim
	case WeaknessConfigurationConsistency:
		return KindCrossNodeConsistency
	default:
		return ""
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/waforigin/... -v`
Expected: PASS — both test functions pass.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/waforigin/types.go orchestrator/internal/waforigin/types_test.go
git commit -m "feat(waforigin): WeaknessKind/WeaknessType taxonomy"
```

---

### Task 2: Kind A types and construction-time validation (bypass pairs)

**Files:**
- Create: `orchestrator/internal/waforigin/bypass.go`
- Test: `orchestrator/internal/waforigin/bypass_test.go`

**Interfaces:**
- Consumes: `WeaknessType`, `WeaknessKind`, `KindBypassPair`, `.Kind()` (Task 1).
- Produces: `BypassScenario{ID, Weakness, AttackVectorID, BaselinePathDescription, BypassPathDescription, Provenance string}` (`Weakness WeaknessType`), `NewBypassScenario(id string, weakness WeaknessType, attackVectorID string, baselinePathDescription string, bypassPathDescription string, provenance string) (BypassScenario, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/waforigin/bypass_test.go
package waforigin

import "testing"

func TestNewBypassScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001",
		"https://app.example.com/search via the production CDN/WAF edge",
		"the same payload sent to an undocumented secondary vhost never registered with the WAF",
		"manually authored")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	if s.ID != "WAFORIGIN-001" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFORIGIN-001")
	}
}

func TestNewBypassScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewBypassScenario("", WeaknessRoutingCoverageGap, "SQLI-001", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

// Review Focus: a WeaknessType whose Kind() is not KindBypassPair must be
// rejected, including an unknown value -- not silently accepted.
func TestNewBypassScenario_WeaknessFromAnotherKind_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessTLSProxyBehavior, "SQLI-001", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for a WeaknessType whose Kind() is KindProtocolClaim, got nil")
	}
}

func TestNewBypassScenario_UnknownWeakness_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessType("bogus"), "SQLI-001", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for an unknown WeaknessType, got nil")
	}
}

func TestNewBypassScenario_EmptyAttackVectorID_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for empty AttackVectorID, got nil")
	}
}

func TestNewBypassScenario_EmptyBaselinePathDescription_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "", "y", "z")
	if err == nil {
		t.Fatal("want error for empty BaselinePathDescription, got nil")
	}
}

func TestNewBypassScenario_EmptyBypassPathDescription_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "x", "", "z")
	if err == nil {
		t.Fatal("want error for empty BypassPathDescription, got nil")
	}
}

func TestNewBypassScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "x", "y", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/waforigin/... -run TestNewBypassScenario -v`
Expected: FAIL — `BypassScenario`/`NewBypassScenario` undefined.

- [ ] **Step 3: Write `bypass.go`**

```go
// orchestrator/internal/waforigin/bypass.go
package waforigin

import "fmt"

// BypassScenario is a Kind-A (bypass-pair) scenario: the claim that an
// existing, already-catalogued attack is prevented through a documented
// path, re-evaluated under a path that bypasses that documented control.
type BypassScenario struct {
	ID                      string
	Weakness                WeaknessType
	AttackVectorID          string
	BaselinePathDescription string
	BypassPathDescription   string
	Provenance              string
}

// NewBypassScenario validates at construction time, never at render time.
func NewBypassScenario(
	id string,
	weakness WeaknessType,
	attackVectorID string,
	baselinePathDescription string,
	bypassPathDescription string,
	provenance string,
) (BypassScenario, error) {
	if id == "" {
		return BypassScenario{}, fmt.Errorf("id must not be empty")
	}
	if weakness.Kind() != KindBypassPair {
		return BypassScenario{}, fmt.Errorf("weakness %q has Kind() %q, want %q", weakness, weakness.Kind(), KindBypassPair)
	}
	if attackVectorID == "" {
		return BypassScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	if baselinePathDescription == "" {
		return BypassScenario{}, fmt.Errorf("baselinePathDescription must not be empty")
	}
	if bypassPathDescription == "" {
		return BypassScenario{}, fmt.Errorf("bypassPathDescription must not be empty")
	}
	if provenance == "" {
		return BypassScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return BypassScenario{
		ID: id, Weakness: weakness, AttackVectorID: attackVectorID,
		BaselinePathDescription: baselinePathDescription, BypassPathDescription: bypassPathDescription,
		Provenance: provenance,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/waforigin/... -run TestNewBypassScenario -v`
Expected: PASS (7/7).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/waforigin/bypass.go orchestrator/internal/waforigin/bypass_test.go
git commit -m "feat(waforigin): BypassScenario types and construction-time validation"
```

---

### Task 3: Kind A evaluation (bypass-gap decision)

**Files:**
- Create: `orchestrator/internal/waforigin/evaluate_bypass.go`
- Test: `orchestrator/internal/waforigin/evaluate_bypass_test.go`

**Interfaces:**
- Consumes: `BypassScenario` (Task 2); `wafcatalog.AttackVector` (`vector.Expectations(policyBasis) []wafcatalog.LegExpectation`, each with an `.Expectation wafval.Expectation` field — already merged, `internal/wafcatalog`); `wafval.EvaluateClaim(exp wafval.Expectation, results []wafval.CollectionResult, key wafval.CorrelationKey) wafval.Result`, `wafval.CollectionResult`, `wafval.CorrelationKey`, `wafval.Verdict` (+ `VerdictBlocked`, `VerdictMissed`, `VerdictDetectedButAllowed`, `VerdictInconclusive`), `wafval.Confidence` (+ `ConfidenceHigh`, `ConfidenceMedium`) — all already merged, `internal/wafval`.
- Produces: `trustworthyBlocked(r wafval.Result) bool` (unexported), `decideOriginGap(baseline, bypass wafval.Result) (wafval.Verdict, string)` (unexported), `EvaluateBypassScenario(scenario BypassScenario, vector wafcatalog.AttackVector, policyBasis string, baselineEvidence []wafval.CollectionResult, baselineKey wafval.CorrelationKey, bypassEvidence []wafval.CollectionResult, bypassKey wafval.CorrelationKey) (wafval.Verdict, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/waforigin/evaluate_bypass_test.go
package waforigin

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func mustSQLIVector(t *testing.T) wafcatalog.AttackVector {
	t.Helper()
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range catalog {
		if v.ID == "SQLI-001" {
			return v
		}
	}
	t.Fatal("SQLI-001 not found in wafcatalog.AudspectWAFAttackCatalog()")
	return wafcatalog.AttackVector{}
}

// blockedEvidence/missedEvidence each supply BOTH a WAFEngine and an
// OriginApp CollectionResult. wafval's ClaimPrevention completeness
// requires MechanismWAFEngine present at minimum (else Insufficient ->
// forced Inconclusive), and reaches CompletenessComplete/ConfidenceHigh
// only when MechanismOriginApp is also present (see
// orchestrator/internal/wafval/evaluate.go's deriveCompleteness) --
// a single-mechanism fixture is not enough evidence to reach a
// trustworthy verdict either way.
func blockedEvidence(key wafval.CorrelationKey) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{
			Mechanism: wafval.MechanismWAFEngine,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismWAFEngine, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
		{
			Mechanism: wafval.MechanismOriginApp,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismOriginApp, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginNotObserved,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
	}
}

// missedEvidence models the attack reaching the origin neither detected
// nor blocked -- for a ClaimPrevention leg this resolves to VerdictMissed
// (wafval.derivePrevention: Enforcement=Allowed + Detection=NotMatched),
// never VerdictAllowed, which is unreachable for ClaimPrevention.
func missedEvidence(key wafval.CorrelationKey) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{
			Mechanism: wafval.MechanismWAFEngine,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismWAFEngine, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
		{
			Mechanism: wafval.MechanismOriginApp,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismOriginApp, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginReceived,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
	}
}

func testKey(id string) wafval.CorrelationKey {
	now := time.Now()
	return wafval.CorrelationKey{TestExecutionID: id, RequestID: id, Target: "test", Window: wafval.TimeWindow{Start: now, End: now.Add(time.Second)}}
}

func TestEvaluateBypassScenario_VectorIDMismatch_Rejected(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	wrongVector := mustSQLIVector(t)
	wrongVector.ID = "SQLI-999"
	_, _, err = EvaluateBypassScenario(scenario, wrongVector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), missedEvidence(testKey("bypass")), testKey("bypass"))
	if err == nil {
		t.Fatal("want error for vector.ID/scenario.AttackVectorID mismatch, got nil")
	}
}

func TestEvaluateBypassScenario_UntrustworthyBaseline_ReturnsInconclusive(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	verdict, _, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		nil, testKey("baseline"), missedEvidence(testKey("bypass")), testKey("bypass"))
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("verdict = %q, want %q (no baseline evidence collected)", verdict, wafval.VerdictInconclusive)
	}
}

// Review Focus: the gap case must return VerdictMissed specifically --
// VerdictAllowed is unreachable here since the malicious leg's claim is
// always ClaimPrevention (see wafval.derivePrevention: VerdictAllowed is
// reserved for ClaimFalsePositive).
func TestEvaluateBypassScenario_MissedBypass_ReturnsMissed(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-002", WeaknessDirectOriginReachability, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	verdict, reason, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), missedEvidence(testKey("bypass")), testKey("bypass"))
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateBypassScenario_TrustworthyBlockedBypass_ReturnsBlocked(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-003", WeaknessFailOpenOnUnavailability, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	verdict, _, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), blockedEvidence(testKey("bypass")), testKey("bypass"))
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictBlocked {
		t.Errorf("verdict = %q, want %q (bypass still blocked -- no gap)", verdict, wafval.VerdictBlocked)
	}
}

func TestEvaluateBypassScenario_DetectedButAllowedBypass_ReturnsDetectedButAllowed(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	key := testKey("bypass")
	detectedButAllowed := []wafval.CollectionResult{{
		Mechanism: wafval.MechanismWAFEngine,
		Coverage:  wafval.CoverageFound,
		Observations: []wafval.Observation{{
			Mechanism: wafval.MechanismWAFEngine, RequestID: key.RequestID,
			Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionMatched, Origin: wafval.OriginReceived,
			EvidenceKind: wafval.EvidenceObserved,
		}},
	}}
	verdict, _, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), detectedButAllowed, key)
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictDetectedButAllowed {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictDetectedButAllowed)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/waforigin/... -run TestEvaluateBypassScenario -v`
Expected: FAIL — `EvaluateBypassScenario` undefined.

- [ ] **Step 3: Write `evaluate_bypass.go`**

```go
// orchestrator/internal/waforigin/evaluate_bypass.go
package waforigin

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func trustworthyBlocked(r wafval.Result) bool {
	return r.Verdict == wafval.VerdictBlocked &&
		(r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium)
}

// decideOriginGap is local to this package, not wafval.EvaluatePolicyGap:
// the attribution story here is a network-topology/availability condition
// (an undocumented route, a path that skips the WAF, the WAF being down),
// never a policy-rule change, so EvaluatePolicyGap's PolicyDifferentiation
// semantics do not apply.
//
// The malicious leg's claim is always ClaimPrevention, so VerdictAllowed
// (reserved for ClaimFalsePositive, per wafval.derivePrevention/
// deriveFalsePositive) is never a reachable value on the bypass leg here.
// VerdictMissed is the full-gap case: the attack reached the origin
// neither detected nor blocked via the bypass path.
func decideOriginGap(baseline, bypass wafval.Result) (wafval.Verdict, string) {
	if !trustworthyBlocked(baseline) {
		return wafval.VerdictInconclusive, "baseline did not establish a reliable block through the documented path; bypass-leg behavior cannot be attributed to the bypass condition"
	}
	switch bypass.Verdict {
	case wafval.VerdictBlocked:
		return wafval.VerdictBlocked, "the bypass path did not succeed in evading enforcement -- the same attack was still blocked"
	case wafval.VerdictMissed:
		return wafval.VerdictMissed, "bypass confirmed: the same attack reached the origin neither detected nor blocked via this path"
	case wafval.VerdictDetectedButAllowed:
		return wafval.VerdictDetectedButAllowed, "the bypass path logged the attack but still allowed it through -- partial coverage gap"
	default:
		return wafval.VerdictInconclusive, "insufficient evidence to determine whether the bypass path is covered"
	}
}

// EvaluateBypassScenario drives scenario's referenced vector's malicious leg
// through both the baseline (documented-path) and bypass evidence, then
// applies decideOriginGap.
func EvaluateBypassScenario(
	scenario BypassScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	baselineEvidence []wafval.CollectionResult,
	baselineKey wafval.CorrelationKey,
	bypassEvidence []wafval.CollectionResult,
	bypassKey wafval.CorrelationKey,
) (wafval.Verdict, string, error) {
	if vector.ID != scenario.AttackVectorID {
		return "", "", fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation
	baseline := wafval.EvaluateClaim(maliciousExpectation, baselineEvidence, baselineKey)
	bypass := wafval.EvaluateClaim(maliciousExpectation, bypassEvidence, bypassKey)
	verdict, reason := decideOriginGap(baseline, bypass)
	return verdict, reason, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/waforigin/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/waforigin/evaluate_bypass.go orchestrator/internal/waforigin/evaluate_bypass_test.go
git commit -m "feat(waforigin): bypass-pair evaluation via local decideOriginGap"
```

---

### Task 4: Kind B types, validation and evidence (protocol claim)

**Files:**
- Create: `orchestrator/internal/waforigin/protocol.go`
- Test: `orchestrator/internal/waforigin/protocol_test.go`

**Interfaces:**
- Consumes: `wafval.Expectation`, `wafval.ClaimPrevention`, `wafval.ClaimFalsePositive` (already merged, `internal/wafval`).
- Produces: `RequestTemplate{Method, Path, PayloadLocation, Payload, Description string}`, `StandardsMapping{CWEIDs []string, WSTGCategory, Top10Category, APITop10Category string, ATTACKTechniques []string}`, `ProtocolBehaviorVector{ID string, Version int, Name string, Preconditions string, Malicious RequestTemplate, BenignCounterpart *RequestTemplate, NoBenignCounterpartReason string, Standards StandardsMapping, Provenance string}`, `NewProtocolBehaviorVector(id string, version int, name string, preconditions string, malicious RequestTemplate, benignCounterpart *RequestTemplate, noBenignCounterpartReason string, standards StandardsMapping, provenance string) (ProtocolBehaviorVector, error)`, `ProtocolLeg` (+ `LegMaliciousProtocol`, `LegBenignProtocol`), `ProtocolLegExpectation{VectorID string, Leg ProtocolLeg, Request RequestTemplate, Expectation wafval.Expectation}`, `(v ProtocolBehaviorVector) Expectations(policyBasis string) []ProtocolLegExpectation`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/waforigin/protocol_test.go
package waforigin

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func protocolMalicious() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header", Payload: "TLS 1.0 handshake with a forged X-Forwarded-Proto: https header while the connection actually arrived over plaintext",
		Description: "deprecated TLS version combined with a forged proxy-trust header"}
}

func protocolBenign() RequestTemplate {
	return RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header", Payload: "TLS 1.2+ handshake with a correctly-set X-Forwarded-Proto header matching the actual connection",
		Description: "declared-minimum TLS version with correctly-set proxy headers"}
}

func protocolStandards() StandardsMapping {
	return StandardsMapping{CWEIDs: []string{"CWE-319"}}
}

func TestNewProtocolBehaviorVector_Valid_Succeeds(t *testing.T) {
	benign := protocolBenign()
	v, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "TLS Downgrade with Forged Proxy Header", "origin trusts X-Forwarded-Proto without verifying the actual TLS version negotiated",
		protocolMalicious(), &benign, "", protocolStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewProtocolBehaviorVector: %v", err)
	}
	if v.ID != "WAFORIGIN-004" {
		t.Errorf("ID = %q, want %q", v.ID, "WAFORIGIN-004")
	}
}

func TestNewProtocolBehaviorVector_EmptyID_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewProtocolBehaviorVector_VersionLessThanOne_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 0, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for version < 1, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyMaliciousMethod_Rejected(t *testing.T) {
	benign := protocolBenign()
	malicious := protocolMalicious()
	malicious.Method = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", malicious, &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Method, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyMaliciousPath_Rejected(t *testing.T) {
	benign := protocolBenign()
	malicious := protocolMalicious()
	malicious.Path = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", malicious, &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Path, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyMaliciousDescription_Rejected(t *testing.T) {
	benign := protocolBenign()
	malicious := protocolMalicious()
	malicious.Description = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", malicious, &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for empty Malicious.Description, got nil")
	}
}

func TestNewProtocolBehaviorVector_MalformedCWEID_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "",
		StandardsMapping{CWEIDs: []string{"not-a-cwe-id"}}, "x")
	if err == nil {
		t.Fatal("want error for malformed CWE ID, got nil")
	}
}

func TestNewProtocolBehaviorVector_StandardsAllEmpty_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", StandardsMapping{}, "x")
	if err == nil {
		t.Fatal("want error when Standards has no mapping field set, got nil")
	}
}

func TestNewProtocolBehaviorVector_EmptyProvenance_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

// Review Focus: both set, exactly like wafbotabuse's precedent.
func TestNewProtocolBehaviorVector_BothBenignAndReasonSet_Rejected(t *testing.T) {
	benign := protocolBenign()
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "no benign exists", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error when both BenignCounterpart and NoBenignCounterpartReason are set, got nil")
	}
}

// Review Focus: neither set, exactly like wafbotabuse's precedent.
func TestNewProtocolBehaviorVector_NeitherBenignNorReasonSet_Rejected(t *testing.T) {
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), nil, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error when neither BenignCounterpart nor NoBenignCounterpartReason is set, got nil")
	}
}

func TestNewProtocolBehaviorVector_BenignCounterpartInvalid_Rejected(t *testing.T) {
	benign := protocolBenign()
	benign.Description = ""
	_, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err == nil {
		t.Fatal("want error for an invalid BenignCounterpart (empty Description), got nil")
	}
}

func TestProtocolBehaviorVector_Expectations_WithBenignCounterpart_ReturnsTwoLegs(t *testing.T) {
	benign := protocolBenign()
	v, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), &benign, "", protocolStandards(), "x")
	if err != nil {
		t.Fatalf("NewProtocolBehaviorVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Leg != LegMaliciousProtocol || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMaliciousProtocol with ClaimPrevention", legs[0])
	}
	if legs[1].Leg != LegBenignProtocol || legs[1].Expectation.Claim != wafval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want LegBenignProtocol with ClaimFalsePositive", legs[1])
	}
}

func TestProtocolBehaviorVector_Expectations_NoBenignCounterpart_ReturnsOneLeg(t *testing.T) {
	v, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "x", "x", protocolMalicious(), nil, "no legitimate lookalike for this probe", protocolStandards(), "x")
	if err != nil {
		t.Fatalf("NewProtocolBehaviorVector: %v", err)
	}
	legs := v.Expectations("owasp-crs-default")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegMaliciousProtocol || legs[0].Expectation.Claim != wafval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegMaliciousProtocol with ClaimPrevention", legs[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/waforigin/... -run "TestNewProtocolBehaviorVector|TestProtocolBehaviorVector" -v`
Expected: FAIL — `RequestTemplate`/`StandardsMapping`/`NewProtocolBehaviorVector`/etc. undefined.

- [ ] **Step 3: Write `protocol.go`**

```go
// orchestrator/internal/waforigin/protocol.go
package waforigin

import (
	"fmt"
	"regexp"

	"github.com/audspect/bas/internal/wafval"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

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
type StandardsMapping struct {
	CWEIDs           []string
	WSTGCategory     string
	Top10Category    string
	APITop10Category string
	ATTACKTechniques []string
}

// ProtocolBehaviorVector is this package's single Kind-B (protocol-claim)
// catalog entry: a probe of TLS/proxy-trust behavior, not a cross-reference
// to an existing wafcatalog vector.
type ProtocolBehaviorVector struct {
	ID                        string
	Version                   int
	Name                      string
	Preconditions             string
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string
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

// NewProtocolBehaviorVector validates at construction time, never at render
// time. Validation is identical in substance to wafbotabuse.NewBotAbuseVector,
// minus a category check -- this kind has exactly one named item.
func NewProtocolBehaviorVector(
	id string,
	version int,
	name string,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (ProtocolBehaviorVector, error) {
	if id == "" {
		return ProtocolBehaviorVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return ProtocolBehaviorVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return ProtocolBehaviorVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return ProtocolBehaviorVector{}, err
	}
	if provenance == "" {
		return ProtocolBehaviorVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return ProtocolBehaviorVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return ProtocolBehaviorVector{}, err
		}
	}
	return ProtocolBehaviorVector{
		ID: id, Version: version, Name: name, Preconditions: preconditions, Malicious: malicious,
		BenignCounterpart: benignCounterpart, NoBenignCounterpartReason: noBenignCounterpartReason,
		Standards: standards, Provenance: provenance,
	}, nil
}

// ProtocolLeg names which half of a ProtocolBehaviorVector a leg's
// expectation came from.
type ProtocolLeg string

const (
	LegMaliciousProtocol ProtocolLeg = "malicious"
	LegBenignProtocol    ProtocolLeg = "benign"
)

// ProtocolLegExpectation pairs one leg's request template with the
// wafval.Expectation it resolves to.
type ProtocolLegExpectation struct {
	VectorID    string
	Leg         ProtocolLeg
	Request     RequestTemplate
	Expectation wafval.Expectation
}

// Expectations returns the malicious leg's ProtocolLegExpectation, plus
// the benign leg's when BenignCounterpart is set -- never a padded slice.
func (v ProtocolBehaviorVector) Expectations(policyBasis string) []ProtocolLegExpectation {
	legs := []ProtocolLegExpectation{
		{
			VectorID: v.ID,
			Leg:      LegMaliciousProtocol,
			Request:  v.Malicious,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimPrevention, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		},
	}
	if v.BenignCounterpart != nil {
		legs = append(legs, ProtocolLegExpectation{
			VectorID: v.ID,
			Leg:      LegBenignProtocol,
			Request:  *v.BenignCounterpart,
			Expectation: wafval.Expectation{
				Claim: wafval.ClaimFalsePositive, PolicyBasis: policyBasis, PolicyVerified: false,
			},
		})
	}
	return legs
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/waforigin/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/waforigin/protocol.go orchestrator/internal/waforigin/protocol_test.go
git commit -m "feat(waforigin): ProtocolBehaviorVector types, validation and Expectations"
```

---

### Task 5: Kind C types and evaluation (cross-node consistency)

**Files:**
- Create: `orchestrator/internal/waforigin/consistency.go`
- Test: `orchestrator/internal/waforigin/consistency_test.go`

**Interfaces:**
- Consumes: `wafcatalog.AttackVector` (`.Expectations(policyBasis)`, already merged); `wafval.EvaluateClaim`, `wafval.CollectionResult`, `wafval.CorrelationKey`, `wafval.Verdict`, `wafval.Confidence` (+ `ConfidenceHigh`, `ConfidenceMedium`) (already merged, `internal/wafval`). Does not consume Task 3's `trustworthyBlocked` — this kind's trustworthy-result filter is Confidence-only regardless of Verdict, so it owns a separate unexported helper.
- Produces: `ConsistencyScenario{ID, AttackVectorID, Provenance string}`, `NewConsistencyScenario(id string, attackVectorID string, provenance string) (ConsistencyScenario, error)`, `NodeEvidence{NodeID string, Evidence []wafval.CollectionResult, Key wafval.CorrelationKey}`, `ConsistencyVerdict` (+ `ConsistencyConfirmed`, `ConsistencyDrift`, `ConsistencyInconclusive`), `EvaluateConfigurationConsistency(scenario ConsistencyScenario, vector wafcatalog.AttackVector, policyBasis string, nodes []NodeEvidence) (ConsistencyVerdict, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/waforigin/consistency_test.go
package waforigin

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func mustPathTravVector(t *testing.T) wafcatalog.AttackVector {
	t.Helper()
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range catalog {
		if v.ID == "PATHTRAV-001" {
			return v
		}
	}
	t.Fatal("PATHTRAV-001 not found in wafcatalog.AudspectWAFAttackCatalog()")
	return wafcatalog.AttackVector{}
}

func TestNewConsistencyScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "manually authored")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	if s.ID != "WAFORIGIN-005" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFORIGIN-005")
	}
}

func TestNewConsistencyScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewConsistencyScenario("", "PATHTRAV-001", "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewConsistencyScenario_EmptyAttackVectorID_Rejected(t *testing.T) {
	_, err := NewConsistencyScenario("WAFORIGIN-005", "", "x")
	if err == nil {
		t.Fatal("want error for empty AttackVectorID, got nil")
	}
}

func TestNewConsistencyScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestEvaluateConfigurationConsistency_VectorIDMismatch_Rejected(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	wrongVector := mustPathTravVector(t)
	wrongVector.ID = "PATHTRAV-999"
	_, _, err = EvaluateConfigurationConsistency(scenario, wrongVector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: blockedEvidence(testKey("b")), Key: testKey("b")},
	})
	if err == nil {
		t.Fatal("want error for vector.ID/scenario.AttackVectorID mismatch, got nil")
	}
}

func TestEvaluateConfigurationConsistency_FewerThanTwoTrustworthyResults_ReturnsInconclusive(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	vector := mustPathTravVector(t)
	verdict, _, err := EvaluateConfigurationConsistency(scenario, vector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: nil, Key: testKey("b")},
	})
	if err != nil {
		t.Fatalf("EvaluateConfigurationConsistency: %v", err)
	}
	if verdict != ConsistencyInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, ConsistencyInconclusive)
	}
}

func TestEvaluateConfigurationConsistency_AgreeingTrustworthyResults_ReturnsConfirmed(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	vector := mustPathTravVector(t)
	verdict, _, err := EvaluateConfigurationConsistency(scenario, vector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: blockedEvidence(testKey("b")), Key: testKey("b")},
	})
	if err != nil {
		t.Fatalf("EvaluateConfigurationConsistency: %v", err)
	}
	if verdict != ConsistencyConfirmed {
		t.Errorf("verdict = %q, want %q", verdict, ConsistencyConfirmed)
	}
}

// Review Focus: the drift reason string must name both disagreeing nodes.
func TestEvaluateConfigurationConsistency_DisagreeingTrustworthyResults_ReturnsDriftNamingBothNodes(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	vector := mustPathTravVector(t)
	verdict, reason, err := EvaluateConfigurationConsistency(scenario, vector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: missedEvidence(testKey("b")), Key: testKey("b")},
	})
	if err != nil {
		t.Fatalf("EvaluateConfigurationConsistency: %v", err)
	}
	if verdict != ConsistencyDrift {
		t.Errorf("verdict = %q, want %q", verdict, ConsistencyDrift)
	}
	if !strings.Contains(reason, "node-a") || !strings.Contains(reason, "node-b") {
		t.Errorf("reason = %q, want it to name both %q and %q", reason, "node-a", "node-b")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/waforigin/... -run "TestNewConsistencyScenario|TestEvaluateConfigurationConsistency" -v`
Expected: FAIL — `ConsistencyScenario`/`NewConsistencyScenario`/`NodeEvidence`/`EvaluateConfigurationConsistency` undefined.

- [ ] **Step 3: Write `consistency.go`**

```go
// orchestrator/internal/waforigin/consistency.go
package waforigin

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// ConsistencyScenario is a Kind-C (cross-node-consistency) scenario: the
// claim that an existing, already-catalogued attack's evidence, collected
// independently from two or more deployment nodes, resolves to the same
// verdict on every node.
type ConsistencyScenario struct {
	ID             string
	AttackVectorID string
	Provenance     string
}

// NewConsistencyScenario validates at construction time, never at render
// time.
func NewConsistencyScenario(id string, attackVectorID string, provenance string) (ConsistencyScenario, error) {
	if id == "" {
		return ConsistencyScenario{}, fmt.Errorf("id must not be empty")
	}
	if attackVectorID == "" {
		return ConsistencyScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	if provenance == "" {
		return ConsistencyScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return ConsistencyScenario{ID: id, AttackVectorID: attackVectorID, Provenance: provenance}, nil
}

// NodeEvidence is one deployment node's independently-collected evidence
// for the same correlation key's request.
type NodeEvidence struct {
	NodeID   string
	Evidence []wafval.CollectionResult
	Key      wafval.CorrelationKey
}

// ConsistencyVerdict is the outcome of comparing two or more nodes'
// independently-derived wafval.Result verdicts.
type ConsistencyVerdict string

const (
	ConsistencyConfirmed    ConsistencyVerdict = "confirmed"
	ConsistencyDrift        ConsistencyVerdict = "drift_detected"
	ConsistencyInconclusive ConsistencyVerdict = "inconclusive"
)

// trustworthyResult is Kind C's own filter: Confidence-only, regardless of
// Verdict, since a trustworthy Allowed result is just as comparable as a
// trustworthy Blocked one -- unlike Task 3's trustworthyBlocked, which also
// requires VerdictBlocked specifically.
func trustworthyResult(r wafval.Result) bool {
	return r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium
}

// EvaluateConfigurationConsistency evaluates scenario's referenced vector's
// malicious leg independently against each node's evidence, then compares
// the trustworthy results' verdicts. This adds zero new wafval
// verdict-derivation logic -- it only compares Verdict values
// wafval.EvaluateClaim already derived.
func EvaluateConfigurationConsistency(
	scenario ConsistencyScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	nodes []NodeEvidence,
) (ConsistencyVerdict, string, error) {
	if vector.ID != scenario.AttackVectorID {
		return "", "", fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation

	type trustworthyNode struct {
		nodeID string
		result wafval.Result
	}
	var trustworthy []trustworthyNode
	for _, n := range nodes {
		result := wafval.EvaluateClaim(maliciousExpectation, n.Evidence, n.Key)
		if trustworthyResult(result) {
			trustworthy = append(trustworthy, trustworthyNode{nodeID: n.NodeID, result: result})
		}
	}

	if len(trustworthy) < 2 {
		return ConsistencyInconclusive, fmt.Sprintf("only %d of %d nodes produced trustworthy evidence; at least 2 are required to assess consistency", len(trustworthy), len(nodes)), nil
	}
	first := trustworthy[0]
	for _, other := range trustworthy[1:] {
		if other.result.Verdict != first.result.Verdict {
			return ConsistencyDrift, fmt.Sprintf("node %q produced verdict %q while node %q produced verdict %q", first.nodeID, first.result.Verdict, other.nodeID, other.result.Verdict), nil
		}
	}
	return ConsistencyConfirmed, fmt.Sprintf("%d nodes agree on verdict %q", len(trustworthy), first.result.Verdict), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/waforigin/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/waforigin/consistency.go orchestrator/internal/waforigin/consistency_test.go
git commit -m "feat(waforigin): cross-node consistency evaluation"
```

---

### Task 6: Seed catalog

**Files:**
- Create: `orchestrator/internal/waforigin/catalog.go`
- Test: `orchestrator/internal/waforigin/catalog_test.go`

**Interfaces:**
- Consumes: `NewBypassScenario`, `WeaknessRoutingCoverageGap`, `WeaknessDirectOriginReachability`, `WeaknessFailOpenOnUnavailability` (Task 1-2); `NewProtocolBehaviorVector`, `RequestTemplate`, `StandardsMapping` (Task 4); `NewConsistencyScenario` (Task 5); `wafcatalog.AudspectWAFAttackCatalog() ([]wafcatalog.AttackVector, error)` (already merged, `internal/wafcatalog`).
- Produces: `AudspectWAFOriginCatalog() (bypass []BypassScenario, protocol []ProtocolBehaviorVector, consistency []ConsistencyScenario, err error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/waforigin/catalog_test.go
package waforigin

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestAudspectWAFOriginCatalog_ReturnsFiveScenariosTotal(t *testing.T) {
	bypass, protocol, consistency, err := AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	total := len(bypass) + len(protocol) + len(consistency)
	if total != 5 {
		t.Fatalf("total scenarios = %d, want 5 (got bypass=%d, protocol=%d, consistency=%d)", total, len(bypass), len(protocol), len(consistency))
	}
	if len(bypass) != 3 {
		t.Errorf("len(bypass) = %d, want 3", len(bypass))
	}
	if len(protocol) != 1 {
		t.Errorf("len(protocol) = %d, want 1", len(protocol))
	}
	if len(consistency) != 1 {
		t.Errorf("len(consistency) = %d, want 1", len(consistency))
	}
}

// Review Focus: every cross-referenced AttackVectorID must be checked
// against the real wafcatalog catalog by a test -- a typo'd ID must fail
// here, not just be asserted correct in prose.
func TestAudspectWAFOriginCatalog_CrossReferencedVectorIDsExistInWafcatalog(t *testing.T) {
	bypass, _, consistency, err := AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	realCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("wafcatalog.AudspectWAFAttackCatalog: %v", err)
	}
	realIDs := make(map[string]bool, len(realCatalog))
	for _, v := range realCatalog {
		realIDs[v.ID] = true
	}
	for _, s := range bypass {
		if !realIDs[s.AttackVectorID] {
			t.Errorf("bypass scenario %q references AttackVectorID %q, which does not exist in wafcatalog.AudspectWAFAttackCatalog()", s.ID, s.AttackVectorID)
		}
	}
	for _, s := range consistency {
		if !realIDs[s.AttackVectorID] {
			t.Errorf("consistency scenario %q references AttackVectorID %q, which does not exist in wafcatalog.AudspectWAFAttackCatalog()", s.ID, s.AttackVectorID)
		}
	}
}

func TestAudspectWAFOriginCatalog_BypassScenariosCoverAllThreeBypassWeaknesses(t *testing.T) {
	bypass, _, _, err := AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	seen := make(map[WeaknessType]int)
	for _, s := range bypass {
		seen[s.Weakness]++
	}
	for _, w := range []WeaknessType{WeaknessRoutingCoverageGap, WeaknessDirectOriginReachability, WeaknessFailOpenOnUnavailability} {
		if seen[w] != 1 {
			t.Errorf("weakness %q appears %d times in the bypass catalog, want exactly 1", w, seen[w])
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/waforigin/... -run TestAudspectWAFOriginCatalog -v`
Expected: FAIL — `AudspectWAFOriginCatalog` undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/waforigin/catalog.go
package waforigin

import "fmt"

// AudspectWAFOriginCatalog returns Audspect's real, current seed origin/
// deployment/resilience scenario set: one scenario per named item from
// waf.txt Phase 7, split across the three evaluation shapes.
func AudspectWAFOriginCatalog() (bypass []BypassScenario, protocol []ProtocolBehaviorVector, consistency []ConsistencyScenario, err error) {
	s1, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001",
		"https://app.example.com/search via the production CDN/WAF edge",
		"the same SQLi payload sent to an undocumented secondary vhost/subpath never registered with the WAF",
		"manually authored from waf.txt Phase 7's named routing-coverage item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	s2, err := NewBypassScenario("WAFORIGIN-002", WeaknessDirectOriginReachability, "XSS-001",
		"https://app.example.com/search via the production CDN/WAF edge",
		"the same reflected-XSS payload sent directly to the origin's own IP/hostname, bypassing the CDN/WAF edge entirely",
		"manually authored from waf.txt Phase 7's named direct-origin-reachability item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	s3, err := NewBypassScenario("WAFORIGIN-003", WeaknessFailOpenOnUnavailability, "SSRF-001",
		"https://app.example.com/webhook via the production WAF while the WAF is healthy",
		"the same SSRF payload sent while the WAF reports an internal error/timeout/unavailable state",
		"manually authored from waf.txt Phase 7's named fail-open-conditions item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	protocolBenign := RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header",
		Payload:     "TLS 1.2+ handshake with a correctly-set X-Forwarded-Proto header matching the actual connection",
		Description: "declared-minimum TLS version with correctly-set proxy headers"}
	p1, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "TLS Downgrade with Forged Proxy Header",
		"origin trusts X-Forwarded-Proto without independently verifying the actual TLS version negotiated at the edge",
		RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header",
			Payload:     "TLS 1.0 handshake with a forged X-Forwarded-Proto: https header while the connection actually arrived over plaintext",
			Description: "deprecated TLS version combined with a forged proxy-trust header, testing whether the origin independently verifies transport security rather than trusting a client-settable header"},
		&protocolBenign, "", StandardsMapping{CWEIDs: []string{"CWE-319"}},
		"manually authored from waf.txt Phase 7's named TLS/proxy-behavior item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	s5, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001",
		"manually authored from waf.txt Phase 7's named configuration-consistency item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	return []BypassScenario{s1, s2, s3}, []ProtocolBehaviorVector{p1}, []ConsistencyScenario{s5}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/waforigin/... -v`
Expected: PASS — every test in the package passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/waforigin/catalog.go orchestrator/internal/waforigin/catalog_test.go
git commit -m "feat(waforigin): AudspectWAFOriginCatalog seeding all 5 named items"
```
