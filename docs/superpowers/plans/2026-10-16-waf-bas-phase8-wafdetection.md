# WAF BAS Mastery Phase 8: Detection and Telemetry Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/wafdetection`, covering waf.txt Phase 8's 5 named items (WAF events, SIEM records, alerts, response timing, evidence loss) across three independent evaluation shapes sharing one package.

**Architecture:** Unlike every prior WAF-mastery phase, this one validates the evidence pipeline's own trustworthiness rather than whether an attack was blocked — it is deliberately attack-agnostic and never cross-references `wafcatalog`. Three shapes: (A) channel completeness, a thin named wrapper over `wafval.Coverage.Present()` per named telemetry channel (WAF-event log, SIEM record, evidence archive); (B) alert correlation, which takes an already-derived `wafval.Verdict` as a bare input (computed elsewhere, by whatever claim-evaluating phase produced it) and checks only whether the alerting pipeline correctly reflected it; (C) response-timing SLA, plain `time.Duration` arithmetic between two timestamps. No shape introduces new `wafval` verdict-derivation logic.

**Tech Stack:** Go 1.26.6, stdlib only (`fmt`, `time`), `internal/wafval` (already merged, read-only dependency).

**Spec:** `docs/superpowers/specs/2026-10-16-waf-bas-phase8-wafdetection-design.md`

## Global Constraints

- Package `internal/wafdetection` depends only on `internal/wafval` (+ stdlib `fmt`/`time`); it does not depend on `internal/wafcatalog`, `internal/wafpolicygap`, `internal/wafevasion`, `internal/wafapiflow`, `internal/wafbotabuse`, or `internal/waforigin`, and none of those six depend on it either (spec §2).
- Zero new `wafval` verdict-derivation logic: `EvaluateCompleteness` only reads `wafval.Coverage.Present()`'s existing result; `EvaluateAlertCorrelation` takes an already-derived `wafval.Verdict` as a bare input and never re-derives one; `EvaluateResponseTiming` does plain `time.Duration` arithmetic (spec §8).
- This phase has no vector-ID mismatch guard anywhere, unlike every prior phase, because it never cross-references `wafcatalog` — there is no `AttackVector` parameter on any evaluation function in this package.
- `wafval.Coverage.Present()` is exactly `c == CoverageFound || c == CoverageSearchedVerifiedNone` (confirmed against `orchestrator/internal/wafval/wafval.go`); the other two `Coverage` values are `CoverageSearchIncomplete` and `CoverageSourceUnavailable`.

## Review Focus

- `EvaluateCompleteness` must return `EvidencePresent` (not `EvidenceLost`) for `CoverageSearchedVerifiedNone` specifically — a verified-negative search still counts as complete evidence, not loss. Pinned in Task 1.
- `EvaluateAlertCorrelation`'s warranted+search-incomplete case must return `AlertInconclusive`, not `AlertMissing` — an incomplete search must never be conflated with a confirmed absence. Pinned in Task 2.
- `EvaluateResponseTiming` must treat `alertObservedAt` before `eventObservedAt` as `TimingInconclusive` (nonsensical ordering), not silently compute a negative latency. Pinned in Task 3.
- `NewTimingScenario` must reject `sla <= 0` at construction, not let a zero/negative SLA silently make every latency "within SLA". Pinned in Task 3.
- The seed catalog's 3 completeness scenarios must cover exactly the 3 intended channels (`ChannelWAFEventLog`/`ChannelSIEMRecord`/`ChannelEvidenceArchive`) without accidentally duplicating one — a test must assert the exact channel set, not just a count of 3. Pinned in Task 4.

---

### Task 1: Channel completeness types and evaluation

**Files:**
- Create: `orchestrator/internal/wafdetection/completeness.go`
- Test: `orchestrator/internal/wafdetection/completeness_test.go`

**Interfaces:**
- Consumes: `wafval.CollectionResult{Mechanism, Coverage, Observations}`, `wafval.Coverage` (+ `CoverageFound`, `CoverageSearchedVerifiedNone`, `CoverageSearchIncomplete`, `CoverageSourceUnavailable`) — all already merged, `internal/wafval`.
- Produces: `EvidenceChannel` (+ 4 constants: `ChannelWAFEventLog`, `ChannelSIEMRecord`, `ChannelAlertQueue`, `ChannelEvidenceArchive`), `CompletenessScenario{ID, Channel EvidenceChannel, Description, Provenance string}`, `NewCompletenessScenario(id string, channel EvidenceChannel, description string, provenance string) (CompletenessScenario, error)`, `CompletenessVerdict` (+ 3 constants: `EvidencePresent`, `EvidenceLost`, `EvidenceInconclusive`), `EvaluateCompleteness(scenario CompletenessScenario, result wafval.CollectionResult) (CompletenessVerdict, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafdetection/completeness_test.go
package wafdetection

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestNewCompletenessScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog,
		"a test execution's CorrelationKey must resolve to a findable WAF-engine event-log record", "manually authored")
	if err != nil {
		t.Fatalf("NewCompletenessScenario: %v", err)
	}
	if s.ID != "WAFDETECT-001" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFDETECT-001")
	}
}

func TestNewCompletenessScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("", ChannelWAFEventLog, "x", "y")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewCompletenessScenario_UnknownChannel_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("WAFDETECT-001", EvidenceChannel("bogus_channel"), "x", "y")
	if err == nil {
		t.Fatal("want error for an unknown EvidenceChannel, got nil")
	}
}

func TestNewCompletenessScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog, "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewCompletenessScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog, "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func mustCompletenessScenario(t *testing.T) CompletenessScenario {
	t.Helper()
	s, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog, "x", "y")
	if err != nil {
		t.Fatalf("NewCompletenessScenario: %v", err)
	}
	return s
}

func TestEvaluateCompleteness_CoverageFound_ReturnsPresent(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound,
		Observations: []wafval.Observation{{Mechanism: wafval.MechanismWAFEngine}}}
	verdict, reason, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidencePresent {
		t.Errorf("verdict = %q, want %q", verdict, EvidencePresent)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

// Review Focus: a verified-negative search still counts as complete
// evidence, not loss.
func TestEvaluateCompleteness_CoverageSearchedVerifiedNone_ReturnsPresent(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone}
	verdict, _, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidencePresent {
		t.Errorf("verdict = %q, want %q", verdict, EvidencePresent)
	}
}

func TestEvaluateCompleteness_CoverageSearchIncomplete_ReturnsLost(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchIncomplete}
	verdict, _, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidenceLost {
		t.Errorf("verdict = %q, want %q", verdict, EvidenceLost)
	}
}

func TestEvaluateCompleteness_CoverageSourceUnavailable_ReturnsLost(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	result := wafval.CollectionResult{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSourceUnavailable}
	verdict, _, err := EvaluateCompleteness(scenario, result)
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidenceLost {
		t.Errorf("verdict = %q, want %q", verdict, EvidenceLost)
	}
}

func TestEvaluateCompleteness_ZeroValueResult_ReturnsLost(t *testing.T) {
	scenario := mustCompletenessScenario(t)
	verdict, _, err := EvaluateCompleteness(scenario, wafval.CollectionResult{})
	if err != nil {
		t.Fatalf("EvaluateCompleteness: %v", err)
	}
	if verdict != EvidenceLost {
		t.Errorf("verdict = %q, want %q", verdict, EvidenceLost)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafdetection/... -v`
Expected: FAIL — package doesn't exist yet (compile error naming undefined symbols).

- [ ] **Step 3: Write `completeness.go`**

```go
// orchestrator/internal/wafdetection/completeness.go
// Package wafdetection is a vendor-neutral, I/O-free evaluator covering
// waf.txt Phase 8's detection-and-telemetry-validation items: WAF events,
// SIEM records, alerts, response timing, and evidence loss. Unlike every
// prior WAF-mastery phase, it validates the evidence pipeline's own
// trustworthiness rather than whether an attack was blocked, so it
// depends only on internal/wafval and never cross-references
// internal/wafcatalog or any sibling WAF-phase package -- no function in
// this package takes a wafcatalog.AttackVector, and there is no
// vector-ID mismatch guard anywhere. Fixture-backed only; real WAF/SIEM/
// alert-queue log collection is deferred.
package wafdetection

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// EvidenceChannel is one of the named telemetry destinations this
// package validates correlation/completeness against.
type EvidenceChannel string

const (
	ChannelWAFEventLog     EvidenceChannel = "waf_event_log"
	ChannelSIEMRecord      EvidenceChannel = "siem_record"
	ChannelAlertQueue      EvidenceChannel = "alert_queue"
	ChannelEvidenceArchive EvidenceChannel = "evidence_archive"
)

func validChannel(c EvidenceChannel) bool {
	switch c {
	case ChannelWAFEventLog, ChannelSIEMRecord, ChannelAlertQueue, ChannelEvidenceArchive:
		return true
	default:
		return false
	}
}

// CompletenessScenario is the claim that a given evidence channel
// produces findable, non-lost evidence for a correlated test execution.
type CompletenessScenario struct {
	ID          string
	Channel     EvidenceChannel
	Description string
	Provenance  string
}

// NewCompletenessScenario validates at construction time, never at
// render time.
func NewCompletenessScenario(id string, channel EvidenceChannel, description string, provenance string) (CompletenessScenario, error) {
	if id == "" {
		return CompletenessScenario{}, fmt.Errorf("id must not be empty")
	}
	if !validChannel(channel) {
		return CompletenessScenario{}, fmt.Errorf("channel %q is not one of the known EvidenceChannel constants", channel)
	}
	if description == "" {
		return CompletenessScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return CompletenessScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return CompletenessScenario{ID: id, Channel: channel, Description: description, Provenance: provenance}, nil
}

// CompletenessVerdict is the outcome of checking one channel's Coverage
// for one correlated test execution. EvidenceInconclusive is declared for
// enum symmetry with the other verdict types in this package, but
// EvaluateCompleteness itself always resolves to EvidencePresent or
// EvidenceLost given wafval.Coverage's four closed values -- it is never
// the practical result of a call.
type CompletenessVerdict string

const (
	EvidencePresent      CompletenessVerdict = "present"
	EvidenceLost         CompletenessVerdict = "lost"
	EvidenceInconclusive CompletenessVerdict = "inconclusive"
)

// EvaluateCompleteness reads result.Coverage.Present() -- true for
// CoverageFound or CoverageSearchedVerifiedNone (a verified-negative
// search still counts as complete evidence, not loss) -- and resolves
// everything else (CoverageSearchIncomplete, CoverageSourceUnavailable,
// or a zero-value CollectionResult the caller never populated) to
// EvidenceLost: the channel could not establish whether evidence exists
// either way.
func EvaluateCompleteness(scenario CompletenessScenario, result wafval.CollectionResult) (CompletenessVerdict, string, error) {
	if result.Coverage.Present() {
		return EvidencePresent, fmt.Sprintf("%s channel evidence present (coverage=%q)", scenario.Channel, result.Coverage), nil
	}
	return EvidenceLost, fmt.Sprintf("%s channel search could not establish whether evidence exists (coverage=%q)", scenario.Channel, result.Coverage), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafdetection/... -v`
Expected: PASS — all 10 test functions pass.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafdetection/completeness.go orchestrator/internal/wafdetection/completeness_test.go
git commit -m "feat(wafdetection): channel completeness types and evaluation"
```

---

### Task 2: Alert correlation types and evaluation

**Files:**
- Create: `orchestrator/internal/wafdetection/alert.go`
- Test: `orchestrator/internal/wafdetection/alert_test.go`

**Interfaces:**
- Consumes: `wafval.Verdict` (+ `VerdictBlocked`, `VerdictDetectedButAllowed`, `VerdictAllowed`, `VerdictMissed`), `wafval.CollectionResult`, `wafval.Coverage` (+ `CoverageFound`, `CoverageSearchedVerifiedNone`, `CoverageSearchIncomplete`) — all already merged, `internal/wafval`. No dependency on Task 1.
- Produces: `AlertScenario{ID, Description, Provenance string}`, `NewAlertScenario(id string, description string, provenance string) (AlertScenario, error)`, `AlertVerdict` (+ 4 constants: `AlertCorrect`, `AlertMissing`, `AlertSpurious`, `AlertInconclusive`), `alertWarranted(v wafval.Verdict) bool` (unexported), `EvaluateAlertCorrelation(underlyingVerdict wafval.Verdict, alertEvidence wafval.CollectionResult) (AlertVerdict, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafdetection/alert_test.go
package wafdetection

import (
	"testing"

	"github.com/audspect/bas/internal/wafval"
)

func TestNewAlertScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewAlertScenario("WAFDETECT-003", "a blocked or detected-but-allowed request must produce a queryable alert", "manually authored")
	if err != nil {
		t.Fatalf("NewAlertScenario: %v", err)
	}
	if s.ID != "WAFDETECT-003" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFDETECT-003")
	}
}

func TestNewAlertScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewAlertScenario("", "x", "y")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewAlertScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewAlertScenario("WAFDETECT-003", "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewAlertScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewAlertScenario("WAFDETECT-003", "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

func presentAlertEvidence() wafval.CollectionResult {
	return wafval.CollectionResult{Mechanism: wafval.MechanismIndependentSensor, Coverage: wafval.CoverageFound,
		Observations: []wafval.Observation{{Mechanism: wafval.MechanismIndependentSensor}}}
}

func verifiedAbsentAlertEvidence() wafval.CollectionResult {
	return wafval.CollectionResult{Mechanism: wafval.MechanismIndependentSensor, Coverage: wafval.CoverageSearchedVerifiedNone}
}

func incompleteAlertEvidence() wafval.CollectionResult {
	return wafval.CollectionResult{Mechanism: wafval.MechanismIndependentSensor, Coverage: wafval.CoverageSearchIncomplete}
}

func TestEvaluateAlertCorrelation_WarrantedAndPresent_ReturnsCorrect(t *testing.T) {
	verdict, reason, err := EvaluateAlertCorrelation(wafval.VerdictBlocked, presentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertCorrect {
		t.Errorf("verdict = %q, want %q", verdict, AlertCorrect)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateAlertCorrelation_WarrantedAndVerifiedAbsent_ReturnsMissing(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictDetectedButAllowed, verifiedAbsentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertMissing {
		t.Errorf("verdict = %q, want %q", verdict, AlertMissing)
	}
}

// Review Focus: an incomplete search must never be conflated with a
// confirmed absence.
func TestEvaluateAlertCorrelation_WarrantedAndSearchIncomplete_ReturnsInconclusive(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictBlocked, incompleteAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, AlertInconclusive)
	}
}

func TestEvaluateAlertCorrelation_NotWarrantedAndPresent_ReturnsSpurious(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictAllowed, presentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertSpurious {
		t.Errorf("verdict = %q, want %q", verdict, AlertSpurious)
	}
}

func TestEvaluateAlertCorrelation_NotWarrantedAndAbsent_ReturnsCorrect(t *testing.T) {
	verdict, _, err := EvaluateAlertCorrelation(wafval.VerdictMissed, verifiedAbsentAlertEvidence())
	if err != nil {
		t.Fatalf("EvaluateAlertCorrelation: %v", err)
	}
	if verdict != AlertCorrect {
		t.Errorf("verdict = %q, want %q", verdict, AlertCorrect)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafdetection/... -run "TestNewAlertScenario|TestEvaluateAlertCorrelation" -v`
Expected: FAIL — `AlertScenario`/`NewAlertScenario`/`EvaluateAlertCorrelation` undefined.

- [ ] **Step 3: Write `alert.go`**

```go
// orchestrator/internal/wafdetection/alert.go
package wafdetection

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// AlertScenario is the claim that the alerting pipeline correctly
// reflects an already-derived claim verdict: an alert exists when (and
// only when) one was warranted.
type AlertScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewAlertScenario validates at construction time, never at render time.
func NewAlertScenario(id string, description string, provenance string) (AlertScenario, error) {
	if id == "" {
		return AlertScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return AlertScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return AlertScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return AlertScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// AlertVerdict is the outcome of comparing an already-derived claim
// verdict against whether an alert actually exists for it.
type AlertVerdict string

const (
	AlertCorrect      AlertVerdict = "correct"
	AlertMissing      AlertVerdict = "missing"
	AlertSpurious     AlertVerdict = "spurious"
	AlertInconclusive AlertVerdict = "inconclusive"
)

// alertWarranted reports whether the underlying verdict is one that
// should have produced an alert: the WAF actually enforced a block or
// recognized the request (Blocked, DetectedButAllowed). A Missed verdict
// means nothing was even detected -- that is a detection-pipeline gap,
// not an alerting-pipeline failure, so it is deliberately not warranted
// here; neither is Allowed (nothing to alert on) or IncorrectlyBlocked
// (a false-positive claim, out of this scenario's scope).
func alertWarranted(v wafval.Verdict) bool {
	return v == wafval.VerdictBlocked || v == wafval.VerdictDetectedButAllowed
}

// EvaluateAlertCorrelation takes underlyingVerdict as a bare input --
// already computed elsewhere, by whatever claim-evaluating phase
// produced it -- and never re-derives one. An incomplete/unavailable
// search is never conflated with a confirmed absence: only
// CoverageSearchedVerifiedNone counts as a verified absence.
func EvaluateAlertCorrelation(underlyingVerdict wafval.Verdict, alertEvidence wafval.CollectionResult) (AlertVerdict, string, error) {
	warranted := alertWarranted(underlyingVerdict)
	hasAlert := alertEvidence.Coverage == wafval.CoverageFound && len(alertEvidence.Observations) > 0
	verifiedAbsent := alertEvidence.Coverage == wafval.CoverageSearchedVerifiedNone

	switch {
	case warranted && hasAlert:
		return AlertCorrect, "alert correctly generated for a detected/blocked request", nil
	case warranted && verifiedAbsent:
		return AlertMissing, "request was blocked/detected but no alert was found despite a verified-complete search", nil
	case warranted && !hasAlert && !verifiedAbsent:
		return AlertInconclusive, "alert-channel search was incomplete or unavailable; cannot confirm whether an alert exists", nil
	case !warranted && hasAlert:
		return AlertSpurious, "an alert was generated for a request that was neither blocked nor detected", nil
	default:
		return AlertCorrect, "no alert generated, correctly, for a request that did not warrant one", nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafdetection/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafdetection/alert.go orchestrator/internal/wafdetection/alert_test.go
git commit -m "feat(wafdetection): alert correlation types and evaluation"
```

---

### Task 3: Response timing types and evaluation

**Files:**
- Create: `orchestrator/internal/wafdetection/timing.go`
- Test: `orchestrator/internal/wafdetection/timing_test.go`

**Interfaces:**
- Consumes: nothing from Tasks 1-2; stdlib `time` only.
- Produces: `TimingScenario{ID string, SLA time.Duration, Description, Provenance string}`, `NewTimingScenario(id string, sla time.Duration, description string, provenance string) (TimingScenario, error)`, `TimingVerdict` (+ 3 constants: `TimingWithinSLA`, `TimingSLABreached`, `TimingInconclusive`), `EvaluateResponseTiming(scenario TimingScenario, eventObservedAt, alertObservedAt time.Time) (TimingVerdict, string, error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafdetection/timing_test.go
package wafdetection

import (
	"testing"
	"time"
)

func TestNewTimingScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "an alert must surface within 5 minutes of the triggering event", "manually authored")
	if err != nil {
		t.Fatalf("NewTimingScenario: %v", err)
	}
	if s.ID != "WAFDETECT-004" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFDETECT-004")
	}
}

func TestNewTimingScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewTimingScenario("", 5*time.Minute, "x", "y")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewTimingScenario_EmptyDescription_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "", "y")
	if err == nil {
		t.Fatal("want error for empty description, got nil")
	}
}

func TestNewTimingScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "x", "")
	if err == nil {
		t.Fatal("want error for empty provenance, got nil")
	}
}

// Review Focus: a zero/negative SLA must not silently make every latency
// "within SLA".
func TestNewTimingScenario_ZeroSLA_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", 0, "x", "y")
	if err == nil {
		t.Fatal("want error for SLA <= 0, got nil")
	}
}

func TestNewTimingScenario_NegativeSLA_Rejected(t *testing.T) {
	_, err := NewTimingScenario("WAFDETECT-004", -time.Minute, "x", "y")
	if err == nil {
		t.Fatal("want error for SLA <= 0, got nil")
	}
}

func mustTimingScenario(t *testing.T) TimingScenario {
	t.Helper()
	s, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute, "x", "y")
	if err != nil {
		t.Fatalf("NewTimingScenario: %v", err)
	}
	return s
}

func TestEvaluateResponseTiming_ZeroEventTimestamp_ReturnsInconclusive(t *testing.T) {
	scenario := mustTimingScenario(t)
	verdict, _, err := EvaluateResponseTiming(scenario, time.Time{}, time.Now())
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, TimingInconclusive)
	}
}

func TestEvaluateResponseTiming_ZeroAlertTimestamp_ReturnsInconclusive(t *testing.T) {
	scenario := mustTimingScenario(t)
	verdict, _, err := EvaluateResponseTiming(scenario, time.Now(), time.Time{})
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, TimingInconclusive)
	}
}

// Review Focus: a nonsensical ordering must not silently compute a
// negative latency.
func TestEvaluateResponseTiming_AlertBeforeEvent_ReturnsInconclusive(t *testing.T) {
	scenario := mustTimingScenario(t)
	event := time.Now()
	alert := event.Add(-time.Minute)
	verdict, _, err := EvaluateResponseTiming(scenario, event, alert)
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, TimingInconclusive)
	}
}

func TestEvaluateResponseTiming_LatencyAtSLABoundary_ReturnsWithinSLA(t *testing.T) {
	scenario := mustTimingScenario(t)
	event := time.Now()
	alert := event.Add(5 * time.Minute)
	verdict, reason, err := EvaluateResponseTiming(scenario, event, alert)
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingWithinSLA {
		t.Errorf("verdict = %q, want %q", verdict, TimingWithinSLA)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateResponseTiming_LatencyOverSLA_ReturnsSLABreached(t *testing.T) {
	scenario := mustTimingScenario(t)
	event := time.Now()
	alert := event.Add(5*time.Minute + time.Second)
	verdict, _, err := EvaluateResponseTiming(scenario, event, alert)
	if err != nil {
		t.Fatalf("EvaluateResponseTiming: %v", err)
	}
	if verdict != TimingSLABreached {
		t.Errorf("verdict = %q, want %q", verdict, TimingSLABreached)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafdetection/... -run "TestNewTimingScenario|TestEvaluateResponseTiming" -v`
Expected: FAIL — `TimingScenario`/`NewTimingScenario`/`EvaluateResponseTiming` undefined.

- [ ] **Step 3: Write `timing.go`**

```go
// orchestrator/internal/wafdetection/timing.go
package wafdetection

import (
	"fmt"
	"time"
)

// TimingScenario is the claim that an alert surfaces within a declared
// SLA duration of the triggering event.
type TimingScenario struct {
	ID          string
	SLA         time.Duration
	Description string
	Provenance  string
}

// NewTimingScenario validates at construction time, never at render
// time. A zero or negative SLA is rejected here so it can never silently
// make every latency "within SLA" at evaluation time.
func NewTimingScenario(id string, sla time.Duration, description string, provenance string) (TimingScenario, error) {
	if id == "" {
		return TimingScenario{}, fmt.Errorf("id must not be empty")
	}
	if sla <= 0 {
		return TimingScenario{}, fmt.Errorf("sla must be > 0, got %s", sla)
	}
	if description == "" {
		return TimingScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return TimingScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return TimingScenario{ID: id, SLA: sla, Description: description, Provenance: provenance}, nil
}

// TimingVerdict is the outcome of comparing an alert's latency against
// the scenario's declared SLA.
type TimingVerdict string

const (
	TimingWithinSLA    TimingVerdict = "within_sla"
	TimingSLABreached  TimingVerdict = "sla_breached"
	TimingInconclusive TimingVerdict = "inconclusive"
)

// EvaluateResponseTiming treats a zero timestamp, or alertObservedAt
// before eventObservedAt (the alert cannot precede the event it is
// about), as Inconclusive rather than computing a negative latency.
func EvaluateResponseTiming(scenario TimingScenario, eventObservedAt, alertObservedAt time.Time) (TimingVerdict, string, error) {
	if eventObservedAt.IsZero() || alertObservedAt.IsZero() {
		return TimingInconclusive, "a required timestamp is missing", nil
	}
	if alertObservedAt.Before(eventObservedAt) {
		return TimingInconclusive, "alertObservedAt precedes eventObservedAt, a nonsensical ordering", nil
	}
	latency := alertObservedAt.Sub(eventObservedAt)
	if latency <= scenario.SLA {
		return TimingWithinSLA, fmt.Sprintf("latency %s is within the %s SLA", latency, scenario.SLA), nil
	}
	return TimingSLABreached, fmt.Sprintf("latency %s exceeds the %s SLA", latency, scenario.SLA), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafdetection/... -v`
Expected: PASS — every test in the package so far passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafdetection/timing.go orchestrator/internal/wafdetection/timing_test.go
git commit -m "feat(wafdetection): response timing types and evaluation"
```

---

### Task 4: Seed catalog

**Files:**
- Create: `orchestrator/internal/wafdetection/catalog.go`
- Test: `orchestrator/internal/wafdetection/catalog_test.go`

**Interfaces:**
- Consumes: `NewCompletenessScenario`, `ChannelWAFEventLog`, `ChannelSIEMRecord`, `ChannelEvidenceArchive` (Task 1); `NewAlertScenario` (Task 2); `NewTimingScenario` (Task 3).
- Produces: `AudspectWAFDetectionCatalog() (completeness []CompletenessScenario, alert []AlertScenario, timing []TimingScenario, err error)`.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/wafdetection/catalog_test.go
package wafdetection

import "testing"

func TestAudspectWAFDetectionCatalog_ReturnsFiveScenariosTotal(t *testing.T) {
	completeness, alert, timing, err := AudspectWAFDetectionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFDetectionCatalog: %v", err)
	}
	total := len(completeness) + len(alert) + len(timing)
	if total != 5 {
		t.Fatalf("total scenarios = %d, want 5 (got completeness=%d, alert=%d, timing=%d)", total, len(completeness), len(alert), len(timing))
	}
	if len(completeness) != 3 {
		t.Errorf("len(completeness) = %d, want 3", len(completeness))
	}
	if len(alert) != 1 {
		t.Errorf("len(alert) = %d, want 1", len(alert))
	}
	if len(timing) != 1 {
		t.Errorf("len(timing) = %d, want 1", len(timing))
	}
}

// Review Focus: the 3 completeness scenarios must cover exactly the 3
// intended channels, not accidentally duplicate one. ChannelAlertQueue is
// deliberately NOT used by any completeness scenario -- alerts are
// covered by the separate AlertScenario shape -- so its absence here is
// correct, not a gap.
func TestAudspectWAFDetectionCatalog_CompletenessScenariosCoverExactlyThreeChannels(t *testing.T) {
	completeness, _, _, err := AudspectWAFDetectionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFDetectionCatalog: %v", err)
	}
	seen := make(map[EvidenceChannel]int)
	for _, s := range completeness {
		seen[s.Channel]++
	}
	want := []EvidenceChannel{ChannelWAFEventLog, ChannelSIEMRecord, ChannelEvidenceArchive}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("channel %q appears %d times in the completeness catalog, want exactly 1", w, seen[w])
		}
	}
	if seen[ChannelAlertQueue] != 0 {
		t.Errorf("ChannelAlertQueue appears %d times in the completeness catalog, want 0 (alerts are covered by AlertScenario, not CompletenessScenario)", seen[ChannelAlertQueue])
	}
	if len(seen) != 3 {
		t.Errorf("completeness catalog covers %d distinct channels, want exactly 3", len(seen))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/wafdetection/... -run TestAudspectWAFDetectionCatalog -v`
Expected: FAIL — `AudspectWAFDetectionCatalog` undefined.

- [ ] **Step 3: Write `catalog.go`**

```go
// orchestrator/internal/wafdetection/catalog.go
package wafdetection

import (
	"fmt"
	"time"
)

// AudspectWAFDetectionCatalog returns Audspect's real, current seed
// detection/telemetry-validation scenario set: one scenario per named
// item from waf.txt Phase 8, split across the three evaluation shapes.
func AudspectWAFDetectionCatalog() (completeness []CompletenessScenario, alert []AlertScenario, timing []TimingScenario, err error) {
	s1, err := NewCompletenessScenario("WAFDETECT-001", ChannelWAFEventLog,
		"a test execution's CorrelationKey must resolve to a findable WAF-engine event-log record",
		"manually authored from waf.txt Phase 8's named WAF-events item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s2, err := NewCompletenessScenario("WAFDETECT-002", ChannelSIEMRecord,
		"the same correlation key must resolve to a findable SIEM-ingested record, an independent corroborating source",
		"manually authored from waf.txt Phase 8's named SIEM-records item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s5, err := NewCompletenessScenario("WAFDETECT-005", ChannelEvidenceArchive,
		"evidence already confirmed present at collection time must still be retrievable from long-term archival storage, not lost to log rotation or a retention-policy gap",
		"manually authored from waf.txt Phase 8's named evidence-loss item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s3, err := NewAlertScenario("WAFDETECT-003",
		"a blocked or detected-but-allowed request must produce a queryable alert; an allowed-and-undetected request must not spuriously produce one",
		"manually authored from waf.txt Phase 8's named alerts item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	s4, err := NewTimingScenario("WAFDETECT-004", 5*time.Minute,
		"an alert must surface within 5 minutes of the triggering event, a representative SOC response-time target",
		"manually authored from waf.txt Phase 8's named response-timing item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed detection catalog: %w", err)
	}

	return []CompletenessScenario{s1, s2, s5}, []AlertScenario{s3}, []TimingScenario{s4}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/wafdetection/... -v`
Expected: PASS — every test in the package passes.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafdetection/catalog.go orchestrator/internal/wafdetection/catalog_test.go
git commit -m "feat(wafdetection): AudspectWAFDetectionCatalog seeding all 5 named items"
```
