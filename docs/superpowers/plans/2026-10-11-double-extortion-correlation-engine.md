# Double-Extortion Correlation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `T1560.001` (staging) into `rwevidence`'s existing evidence framework, then build a standalone, decoupled correlation engine that reads staging + transfer (T1567.002) + encryption (T1486) evidence and classifies it — without ever promoting control-efficacy evidence into a false behavior-occurred claim.

**Architecture:** `rwevidence` gains a 4th technique mirroring `T1567.002`'s existing shape exactly. A new, DB/HTTP-free `internal/dxcorrelate` package implements the correlation rules (leg selection, ordering, time-window, classification) against its own decoupled vocabulary. A new raw (non-aggregated) read path in `internal/db` feeds a new `internal/api` adapter + endpoint, computed live on every request — no new table.

**Tech Stack:** Go, `controlval.Verdict`/`SkipReason` (value types only, inside `rwevidence`), pgx/pgxpool, chi router — all already in this codebase.

**Spec:** `docs/superpowers/specs/2026-10-11-double-extortion-correlation-design.md`

## Global Constraints

- `rwevidence`'s capability verdicts (Prevention/Detection/Containment/DataProtection) measure **control response**, never the underlying behavior — this applies to T1560.001 and T1567.002 exactly as it does to T1486 (spec section A).
- `BehaviorOccurred` is never derived from `ControlEfficacyStatus`/`Verdict` anywhere, for any leg, under any circumstance. No code path in this plan sets `Behavior: Occurred` from a verdict value.
- `Correlate`'s classification is computed from `Behavior` alone, never from `ControlEfficacy`.
- `dxcorrelate` has zero DB or HTTP imports and never imports `rwevidence.Capability` — the API-layer adapter is the one place allowed to know both vocabularies.
- `RWCapabilityCoverage` (`internal/db/rwevidence_store.go:85`) is never modified — `rwscore` depends on its exact aggregated shape.
- No new table; correlation is computed live on every request.
- `GET /api/scenarios/runs/{runId}/double-extortion-correlation` is `tierAny` (no permission gate), mirroring the existing `GET .../rw-score` precedent exactly.
- Out of scope: staging/transfer steps for Akira/BlackCat/LockBit/Play/RansomHub; any real direct-behavior observer; persisting scenario step outcomes; any list/history endpoint or UI.

## Review Focus

- **Reintroducing the rejected inference.** The single easiest mistake: deriving `Behavior: Occurred` from a `FAIL`/`NotDetected` verdict for staging or transfer "since sub-project #1 already accepted that signal." Section A explicitly rejects this — Task 5's dedicated test (`TestToAttemptRows_BehaviorIsNeverDerivedFromControlEfficacy`) pins it across every `Verdict` value.
- **Conflating ordering with time-window.** These are two separate rules (spec section C, rules 2 and 3) — Task 3 needs one test where evidence is out-of-order but within the window, and a second, distinct test where evidence is correctly ordered but outside the window.
- **Strengthening the Clop test into a false confirmation.** Task 5's Clop-shaped test must assert `Classification: insufficient_behavior_evidence` even though real `NotDetected` control-efficacy evidence exists for both staging and transfer — the test's whole point is proving the engine does *not* promote that into a confirmed finding.
- **Treating "run not found" as an error.** Acceptance criterion 11: a run with zero relevant rows (whether the run_id never existed, or exists but ran no ransomware techniques) returns 200 with `insufficient_behavior_evidence`, never 404/500 — Task 5 pins this.
- **Letting T1486's existing capabilities leak into correlation.** The adapter (Task 5) must not translate any `T1486` row (Prevention/Detection/Containment) into a `dxcorrelate.AttemptRow` at all — Task 5's adapter test should include a `T1486` row in the input and assert it produces zero output rows for that technique.

---

### Task 1: `T1560.001` staging evidence in `rwevidence`

**Files:**
- Modify: `orchestrator/internal/rwevidence/technique.go`
- Modify: `orchestrator/internal/rwevidence/dispatch.go`
- Modify: `orchestrator/internal/rwevidence/dispatch_test.go`

**Interfaces:**
- Consumes: existing `Technique`, `Capability` (`CapabilityPrevention/Recovery/Containment/Detection/DataProtection`), `DataProtectionLookup`/`FakeDataProtectionLookup`, `EvaluateStep`, `StepDependencies` — all unchanged.
- Produces: `ArchiveStagingViaUtility() Technique` (MitreID `"T1560.001"`) — Task 5's Clop-shaped test drives evidence for this technique through `EvaluateStep` directly, by `StepInput.TechniqueID`.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/rwevidence/dispatch_test.go`:

```go
func TestEvaluateStep_T1560001Attempt_SameApplicabilitySplitAsT1567002(t *testing.T) {
	in := StepInput{
		RunID: "r1", Action: "staging-1", TechniqueID: "T1560.001",
		StepName: "Archive Staging via Compress-Archive", CheckResult: "fail", Details: "FAIL: zip created unblocked",
	}
	deps := StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &FakeRecoveryObserver{},
		Containment:    &FakeContainmentObserver{},
		Detection:      &FakeDetectionLookup{},
		DataProtection: &FakeDataProtectionLookup{Status: map[string]string{"r1/T1560.001/staging-1": "NotDetected"}},
	}
	results := EvaluateStep(in, deps)
	byCapability := map[Capability]CapabilityResult{}
	for _, r := range results {
		byCapability[r.Capability] = r
	}
	for _, cap := range []Capability{CapabilityPrevention, CapabilityRecovery, CapabilityDetection} {
		r := byCapability[cap]
		if r.Verdict != controlval.VerdictSkipped || r.SkipReason != controlval.SkipNotTested {
			t.Errorf("%s = %+v, want SKIPPED/not_tested (applicability_undecided)", cap, r)
		}
	}
	if r := byCapability[CapabilityContainment]; r.Verdict != controlval.VerdictSkipped || r.SkipReason != controlval.SkipNotApplicable {
		t.Errorf("containment = %+v, want SKIPPED/not_applicable", r)
	}
	if byCapability[CapabilityDataProtection].Verdict != controlval.VerdictFail {
		t.Errorf("data_protection = %+v, want FAIL (NotDetected)", byCapability[CapabilityDataProtection])
	}
}

func TestTechniqueFor_T1560001ReturnsArchiveStagingViaUtility(t *testing.T) {
	tech := techniqueFor("T1560.001")
	if tech.MitreID != "T1560.001" {
		t.Fatalf("MitreID = %q, want T1560.001", tech.MitreID)
	}
	if tech.ID != "archive-staging-via-utility" {
		t.Fatalf("ID = %q, want archive-staging-via-utility", tech.ID)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run "T1560001" -v`
Expected: FAIL — `undefined: ArchiveStagingViaUtility` is not yet the error (it's referenced only via `techniqueFor`, which exists); the real failure is `technique_not_mapped`/empty `Technique{}` since `"T1560.001"` isn't in `classifyRansomwareStep`'s switch or `techniqueFor`'s switch yet — every capability comes back `SKIPPED/not_tested` with reason `technique_not_mapped`, failing the Containment/DataProtection assertions, and `techniqueFor("T1560.001")` returns a zero-value `Technique{}` (`MitreID == ""`), failing the second test

- [ ] **Step 3: Implement the technique and wiring**

Append to `orchestrator/internal/rwevidence/technique.go`:

```go
// ArchiveStagingViaUtility is the fourth technique this package supports:
// local staging/archival of collected data via a compression utility
// (T1560.001, Archive Collected Data: Archive via Utility) -- the staging
// leg of the double-extortion correlation engine (sub-project #5),
// matching clop-kill-chain.yaml's Stage 3 exactly (Compress-Archive zips a
// decoy file; no real sensitive data is touched). Non-destructive: it
// stages/compresses, nothing more.
func ArchiveStagingViaUtility() Technique {
	return Technique{
		ID:        "archive-staging-via-utility",
		Name:      "Archive Staging via Compress-Archive (Archive Collected Data)",
		MitreID:   "T1560.001",
		RiskClass: adprimitive.RiskNonDestructive,
	}
}
```

Modify `orchestrator/internal/rwevidence/dispatch.go` — the technique switch:

```go
	switch in.TechniqueID {
	case "T1490", "T1486", "T1567.002", "T1560.001":
		modeled = true
```

The `techniqueFor` switch:

```go
	case "T1567.002":
		return DataExfiltrationToCloud()
	case "T1560.001":
		return ArchiveStagingViaUtility()
	}
```

The `undecidedApplicability` map — add a new entry, same shape as `T1567.002`'s:

```go
var undecidedApplicability = map[string]map[Capability]bool{
	"T1486":     {CapabilityDataProtection: true},
	"T1567.002": {CapabilityPrevention: true, CapabilityRecovery: true, CapabilityDetection: true},
	"T1560.001": {CapabilityPrevention: true, CapabilityRecovery: true, CapabilityDetection: true},
}
```

The `notApplicable` map — add a new entry:

```go
var notApplicable = map[string]map[Capability]string{
	"T1490":     {CapabilityContainment: "T1490 is a single-host VSS/backup-catalog deletion -- it has no lateral-reachability dimension to contain", CapabilityDataProtection: "T1490 destroys recovery mechanisms; it does not access, stage, or exfiltrate data"},
	"T1486":     {CapabilityRecovery: "T1486 is about whether files get encrypted, not whether recovery mechanisms survive -- that is T1490's domain"},
	"T1567.002": {CapabilityContainment: "containment of an exfil channel is covered by the DataProtection capability, not a separate Containment check"},
	"T1560.001": {CapabilityContainment: "archiving collected data locally has no lateral-reachability dimension to contain"},
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwevidence/ -run "T1560001" -v`
Expected: PASS (2/2)

- [ ] **Step 5: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/rwevidence/ -v 2>&1 | tail -60`
Expected: `ok` — every existing test (T1490/T1486/T1567.002) still passes unmodified

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/rwevidence/technique.go internal/rwevidence/dispatch.go internal/rwevidence/dispatch_test.go
git commit -m "feat(rwevidence): wire T1560.001 staging evidence, mirroring T1567.002's applicability split

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `dxcorrelate` — types and basic classification

**Files:**
- Create: `orchestrator/internal/dxcorrelate/types.go`
- Create: `orchestrator/internal/dxcorrelate/correlate.go`
- Create: `orchestrator/internal/dxcorrelate/correlate_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (first code in this new package).
- Produces: `Leg` (`LegStaging`/`LegTransfer`/`LegEncryption`), `ControlEfficacyStatus`, `BehaviorStatus`, `AttemptRow{Leg, Action, ControlEfficacy, Behavior, Reason, CreatedAt}`, `LegEvidence{Leg, ControlEfficacy, Behavior, CreatedAt, Reason}`, `Classification` (5 values), `CorrelationResult{Legs, Classification, Anomaly}`, `Correlate(rows []AttemptRow) CorrelationResult` — Task 3 adds ordering/window to this same function; Task 5's adapter constructs `AttemptRow` values and calls `Correlate` directly.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/dxcorrelate/correlate_test.go`:

```go
package dxcorrelate

import (
	"testing"
	"time"
)

func row(leg Leg, action string, efficacy ControlEfficacyStatus, behavior BehaviorStatus, at time.Time) AttemptRow {
	return AttemptRow{Leg: leg, Action: action, ControlEfficacy: efficacy, Behavior: behavior, CreatedAt: at}
}

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func TestCorrelate_AllThreeOccurredInOrder_IsThreeLegConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(time.Hour)),
		row(LegEncryption, "a3", EfficacyNoEvidence, BehaviorOccurred, t0.Add(2*time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationThreeLegConfirmed {
		t.Fatalf("Classification = %q, want three_leg_confirmed", result.Classification)
	}
	if len(result.Legs) != 3 {
		t.Fatalf("len(Legs) = %d, want 3", len(result.Legs))
	}
}

func TestCorrelate_StagingAndTransferOccurred_EncryptionNotEstablished_IsExfiltrationConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationExfiltrationConfirmedEncryptionNotEstablished {
		t.Fatalf("Classification = %q, want exfiltration_confirmed_encryption_not_established", result.Classification)
	}
}

func TestCorrelate_EncryptionOccurredAlone_IsEncryptionConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegEncryption, "a3", EfficacyNoEvidence, BehaviorOccurred, t0),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationEncryptionConfirmedExfiltrationNotEstablished {
		t.Fatalf("Classification = %q, want encryption_confirmed_exfiltration_not_established", result.Classification)
	}
}

func TestCorrelate_StagingOnly_IsPartialBehaviorEvidence(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationPartialBehaviorEvidence {
		t.Fatalf("Classification = %q, want partial_behavior_evidence", result.Classification)
	}
}

func TestCorrelate_NoRows_IsInsufficientBehaviorEvidence(t *testing.T) {
	result := Correlate(nil)
	if result.Classification != ClassificationInsufficientBehaviorEvidence {
		t.Fatalf("Classification = %q, want insufficient_behavior_evidence", result.Classification)
	}
	for _, l := range result.Legs {
		if l.ControlEfficacy != EfficacyNoEvidence {
			t.Errorf("%s ControlEfficacy = %q, want no_evidence", l.Leg, l.ControlEfficacy)
		}
		if l.Behavior != BehaviorNotEstablished {
			t.Errorf("%s Behavior = %q, want not_established", l.Leg, l.Behavior)
		}
	}
}

func TestCorrelate_DuplicateOccurredRowsForOneLeg_DeterministicallyUsesEarliest(t *testing.T) {
	rowsA := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0.Add(2*time.Hour)),
		row(LegStaging, "a2", EfficacyNotDetected, BehaviorOccurred, t0), // earliest
	}
	resultA := Correlate(rowsA)
	var stagingA LegEvidence
	for _, l := range resultA.Legs {
		if l.Leg == LegStaging {
			stagingA = l
		}
	}
	if !stagingA.CreatedAt.Equal(t0) {
		t.Fatalf("staging CreatedAt = %v, want the earliest Occurred row's timestamp %v", stagingA.CreatedAt, t0)
	}
	// Same two rows, different slice order -- must produce the identical result (deterministic).
	rowsB := []AttemptRow{rowsA[1], rowsA[0]}
	resultB := Correlate(rowsB)
	if resultA.Classification != resultB.Classification {
		t.Fatalf("order-dependent result: %q vs %q", resultA.Classification, resultB.Classification)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/dxcorrelate/ -v`
Expected: FAIL — `undefined: AttemptRow` (compile error; the package doesn't exist yet)

- [ ] **Step 3: Implement `types.go` and `correlate.go`**

Create `orchestrator/internal/dxcorrelate/types.go`:

```go
// Package dxcorrelate correlates staging, transfer, and encryption
// evidence into a double-extortion classification. It is pure Go, with
// no DB or HTTP import, and deliberately decoupled from
// rwevidence.Capability -- the API-layer adapter (internal/api) is the
// one place allowed to know both this package's Leg vocabulary and MITRE
// technique IDs.
//
// The central rule (design spec section A): ControlEfficacyStatus
// measures how a security control responded to an attempt; it never
// establishes that the underlying behavior (staging/transfer/encryption)
// actually occurred. BehaviorOccurred is set only by a genuine
// direct-observation signal -- none exists in this codebase today, for
// any leg -- never derived from a Verdict/ControlEfficacy value.
package dxcorrelate

import "time"

type Leg string

const (
	LegStaging    Leg = "staging"
	LegTransfer   Leg = "transfer"
	LegEncryption Leg = "encryption"
)

// allLegs is the fixed, canonical order every CorrelationResult.Legs
// follows -- also the expected chronological order for ordering checks
// (Task 3).
var allLegs = []Leg{LegStaging, LegTransfer, LegEncryption}

type ControlEfficacyStatus string

const (
	EfficacyDetected      ControlEfficacyStatus = "detected"
	EfficacyNotDetected   ControlEfficacyStatus = "not_detected"
	EfficacyNotApplicable ControlEfficacyStatus = "not_applicable"
	EfficacyNoEvidence    ControlEfficacyStatus = "no_evidence"
)

type BehaviorStatus string

const (
	BehaviorOccurred       BehaviorStatus = "occurred"
	BehaviorNotEstablished BehaviorStatus = "not_established"
)

// AttemptRow is one piece of evidence for one leg, as the API-layer
// adapter produces it.
type AttemptRow struct {
	Leg             Leg
	Action          string
	ControlEfficacy ControlEfficacyStatus
	Behavior        BehaviorStatus
	Reason          string
	CreatedAt       time.Time
}

// LegEvidence is one leg's selected evidence after Correlate has resolved
// duplicates (earliest-Occurred-wins, see correlate.go).
type LegEvidence struct {
	Leg             Leg
	ControlEfficacy ControlEfficacyStatus
	Behavior        BehaviorStatus
	CreatedAt       time.Time
	Reason          string
}

type Classification string

const (
	ClassificationThreeLegConfirmed                             Classification = "three_leg_confirmed"
	ClassificationExfiltrationConfirmedEncryptionNotEstablished Classification = "exfiltration_confirmed_encryption_not_established"
	ClassificationEncryptionConfirmedExfiltrationNotEstablished Classification = "encryption_confirmed_exfiltration_not_established"
	ClassificationPartialBehaviorEvidence                       Classification = "partial_behavior_evidence"
	ClassificationInsufficientBehaviorEvidence                  Classification = "insufficient_behavior_evidence"
)

// CorrelationResult always carries exactly 3 Legs, in allLegs' fixed
// order. Anomaly is set only when an ordering or time-window violation
// (Task 3) downgraded what would otherwise have been a confirmed
// classification.
type CorrelationResult struct {
	Legs           []LegEvidence
	Classification Classification
	Anomaly        string
}
```

Create `orchestrator/internal/dxcorrelate/correlate.go`:

```go
package dxcorrelate

import "sort"

// Correlate always returns exactly 3 LegEvidence entries, in allLegs'
// fixed order. Classification is computed from Behavior alone --
// ControlEfficacy is carried through purely as context (design spec
// section A).
func Correlate(rows []AttemptRow) CorrelationResult {
	legs := make([]LegEvidence, 0, 3)
	for _, leg := range allLegs {
		legs = append(legs, selectLegEvidence(leg, rows))
	}
	return CorrelationResult{Legs: legs, Classification: classify(legs)}
}

// selectLegEvidence picks, among rows matching leg, the earliest row
// with Behavior == Occurred (deterministic: ties and reordering of the
// input slice never change the result, since selection is by timestamp,
// not input order). If none occurred, falls back to the earliest row of
// any kind for its ControlEfficacy context; with no rows at all for this
// leg, reports NoEvidence/NotEstablished.
func selectLegEvidence(leg Leg, rows []AttemptRow) LegEvidence {
	var matching []AttemptRow
	for _, r := range rows {
		if r.Leg == leg {
			matching = append(matching, r)
		}
	}
	if len(matching) == 0 {
		return LegEvidence{Leg: leg, ControlEfficacy: EfficacyNoEvidence, Behavior: BehaviorNotEstablished}
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].CreatedAt.Before(matching[j].CreatedAt) })
	for _, r := range matching {
		if r.Behavior == BehaviorOccurred {
			return LegEvidence{Leg: leg, ControlEfficacy: r.ControlEfficacy, Behavior: BehaviorOccurred, CreatedAt: r.CreatedAt, Reason: r.Reason}
		}
	}
	first := matching[0]
	return LegEvidence{Leg: leg, ControlEfficacy: first.ControlEfficacy, Behavior: BehaviorNotEstablished, CreatedAt: first.CreatedAt, Reason: first.Reason}
}

func classify(legs []LegEvidence) Classification {
	byLeg := map[Leg]LegEvidence{}
	for _, l := range legs {
		byLeg[l.Leg] = l
	}
	staging := byLeg[LegStaging].Behavior == BehaviorOccurred
	transfer := byLeg[LegTransfer].Behavior == BehaviorOccurred
	encryption := byLeg[LegEncryption].Behavior == BehaviorOccurred

	switch {
	case staging && transfer && encryption:
		return ClassificationThreeLegConfirmed
	case staging && transfer && !encryption:
		return ClassificationExfiltrationConfirmedEncryptionNotEstablished
	case encryption && (!staging || !transfer):
		return ClassificationEncryptionConfirmedExfiltrationNotEstablished
	case staging || transfer || encryption:
		return ClassificationPartialBehaviorEvidence
	default:
		return ClassificationInsufficientBehaviorEvidence
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/dxcorrelate/ -v`
Expected: PASS (6/6)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/dxcorrelate/types.go internal/dxcorrelate/correlate.go internal/dxcorrelate/correlate_test.go
git commit -m "feat(dxcorrelate): types and classification -- behavior-only, never derived from control efficacy

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Ordering and time-window rules

**Files:**
- Modify: `orchestrator/internal/dxcorrelate/correlate.go`
- Modify: `orchestrator/internal/dxcorrelate/correlate_test.go`

**Interfaces:**
- Consumes: `Leg`, `LegEvidence`, `Classification`, `CorrelationResult`, `classify` (Task 2, same package).
- Produces: `Correlate` now additionally sets `CorrelationResult.Anomaly` and can downgrade a `*Confirmed*` classification to `ClassificationPartialBehaviorEvidence` — Task 5's Clop test and acceptance-criteria tests rely on `Anomaly` being non-empty exactly when a downgrade happened.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/dxcorrelate/correlate_test.go`:

```go
func TestCorrelate_OutOfOrderEvidence_DowngradesToPartialWithAnomaly(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0.Add(2*time.Hour)), // staging AFTER transfer
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationPartialBehaviorEvidence {
		t.Fatalf("Classification = %q, want partial_behavior_evidence for out-of-order evidence", result.Classification)
	}
	if result.Anomaly == "" {
		t.Fatal("Anomaly is empty, want a non-empty explanation of the ordering violation")
	}
}

func TestCorrelate_TemporallyUnrelatedEvidence_DowngradesToPartialWithAnomaly(t *testing.T) {
	// Correctly ordered, but far outside MaxCorrelationWindow -- a DIFFERENT
	// rule from the ordering test above; this must not be confused with it.
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(MaxCorrelationWindow+time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationPartialBehaviorEvidence {
		t.Fatalf("Classification = %q, want partial_behavior_evidence for temporally-unrelated evidence", result.Classification)
	}
	if result.Anomaly == "" {
		t.Fatal("Anomaly is empty, want a non-empty explanation of the time-window violation")
	}
}

func TestCorrelate_WithinWindowAndOrder_StaysConfirmed(t *testing.T) {
	rows := []AttemptRow{
		row(LegStaging, "a1", EfficacyNotDetected, BehaviorOccurred, t0),
		row(LegTransfer, "a2", EfficacyNotDetected, BehaviorOccurred, t0.Add(MaxCorrelationWindow-time.Hour)),
	}
	result := Correlate(rows)
	if result.Classification != ClassificationExfiltrationConfirmedEncryptionNotEstablished {
		t.Fatalf("Classification = %q, want exfiltration_confirmed_encryption_not_established", result.Classification)
	}
	if result.Anomaly != "" {
		t.Fatalf("Anomaly = %q, want empty for evidence within the window and correctly ordered", result.Anomaly)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/dxcorrelate/ -run "OutOfOrder|TemporallyUnrelated|WithinWindow" -v`
Expected: FAIL — `undefined: MaxCorrelationWindow` (compile error)

- [ ] **Step 3: Implement the ordering/window check**

Modify `orchestrator/internal/dxcorrelate/correlate.go`:

```go
package dxcorrelate

import (
	"fmt"
	"sort"
	"time"
)

// MaxCorrelationWindow is deliberately generous: this correlates
// simulated/fake-backed evidence today, not real attacker telemetry, so
// tuning a realistic threshold is explicitly deferred to the
// real-observer sub-project.
const MaxCorrelationWindow = 24 * time.Hour

func Correlate(rows []AttemptRow) CorrelationResult {
	legs := make([]LegEvidence, 0, 3)
	for _, leg := range allLegs {
		legs = append(legs, selectLegEvidence(leg, rows))
	}
	classification := classify(legs)
	anomaly := ""
	if isConfirmedClassification(classification) {
		if issue := orderingOrWindowIssue(legs); issue != "" {
			classification = ClassificationPartialBehaviorEvidence
			anomaly = issue
		}
	}
	return CorrelationResult{Legs: legs, Classification: classification, Anomaly: anomaly}
}

func isConfirmedClassification(c Classification) bool {
	return c == ClassificationThreeLegConfirmed ||
		c == ClassificationExfiltrationConfirmedEncryptionNotEstablished ||
		c == ClassificationEncryptionConfirmedExfiltrationNotEstablished
}

// orderingOrWindowIssue checks only the Occurred legs, in allLegs' fixed
// canonical order (staging, transfer, encryption) -- a coherent
// double-extortion sequence requires each later leg's evidence to arrive
// no earlier, and no more than MaxCorrelationWindow later, than the
// previous one.
func orderingOrWindowIssue(legs []LegEvidence) string {
	var occurred []LegEvidence
	for _, l := range legs {
		if l.Behavior == BehaviorOccurred {
			occurred = append(occurred, l)
		}
	}
	for i := 1; i < len(occurred); i++ {
		prev, cur := occurred[i-1], occurred[i]
		if cur.CreatedAt.Before(prev.CreatedAt) {
			return fmt.Sprintf("out-of-order evidence: %s (%s) occurs before %s (%s)", cur.Leg, cur.CreatedAt, prev.Leg, prev.CreatedAt)
		}
		if gap := cur.CreatedAt.Sub(prev.CreatedAt); gap > MaxCorrelationWindow {
			return fmt.Sprintf("temporally unrelated evidence: %s to %s gap of %s exceeds max correlation window of %s", prev.Leg, cur.Leg, gap, MaxCorrelationWindow)
		}
	}
	return ""
}
```

(`selectLegEvidence` and `classify` are unchanged from Task 2 — only `Correlate` itself and the two new helpers above are added/modified.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/dxcorrelate/ -v`
Expected: PASS (9/9 — Task 2's 6 + Task 3's 3)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/dxcorrelate/correlate.go internal/dxcorrelate/correlate_test.go
git commit -m "feat(dxcorrelate): ordering and time-window rules -- distinct checks, both downgrade to partial

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Raw per-attempt read path

**Files:**
- Modify: `orchestrator/internal/db/rwevidence_store.go`
- Modify: `orchestrator/internal/db/rwevidence_store_test.go`

**Interfaces:**
- Consumes: the existing `rw_capability_results` table and `WriteRWCapabilityResults` (unchanged) for test seeding.
- Produces: `RWAttemptRow{TechniqueID, Action, Capability, Verdict controlval.Verdict, SkipReason controlval.SkipReason, Reason string, CreatedAt time.Time}`, `RWCapabilityAttempts(ctx, pool, runID) ([]RWAttemptRow, error)` — Task 5's adapter consumes this directly.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/db/rwevidence_store_test.go` (package `db_test`):

```go
func TestRWCapabilityAttempts_PreservesActionAndTimestampPerRowUnlikeCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "attempts-test-run"
		staging := []rwevidence.CapabilityResult{{Capability: rwevidence.CapabilityDataProtection, TechniqueID: "T1560.001", Verdict: "FAIL"}}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "action-staging", staging); err != nil {
			t.Fatalf("seed staging: %v", err)
		}
		transfer := []rwevidence.CapabilityResult{{Capability: rwevidence.CapabilityDataProtection, TechniqueID: "T1567.002", Verdict: "FAIL"}}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "action-transfer", transfer); err != nil {
			t.Fatalf("seed transfer: %v", err)
		}

		rows, err := db.RWCapabilityAttempts(context.Background(), pool, runID)
		if err != nil {
			t.Fatalf("RWCapabilityAttempts: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("got %d rows, want 2 -- no aggregation across distinct actions", len(rows))
		}
		actions := map[string]bool{}
		for _, r := range rows {
			actions[r.Action] = true
			if r.CreatedAt.IsZero() {
				t.Fatalf("CreatedAt is zero for action=%s, want a real timestamp", r.Action)
			}
		}
		if !actions["action-staging"] || !actions["action-transfer"] {
			t.Fatalf("got actions %v, want both action-staging and action-transfer preserved distinctly", actions)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/ -run TestRWCapabilityAttempts -v`
Expected: FAIL — `undefined: db.RWCapabilityAttempts` (compile error)

- [ ] **Step 3: Implement `RWAttemptRow` and `RWCapabilityAttempts`**

Modify `orchestrator/internal/db/rwevidence_store.go` — add `"time"` to the import block:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/rwevidence"
)
```

Append this function and type (immediately after `RWCapabilityCoverage`, which is never modified):

```go
// RWAttemptRow is one individual, non-aggregated capability-result row --
// unlike RWCoverageRow, this preserves action and created_at per row,
// needed by sub-project #5's correlation engine for event ordering.
type RWAttemptRow struct {
	TechniqueID string
	Action      string
	Capability  string
	Verdict     controlval.Verdict
	SkipReason  controlval.SkipReason
	Reason      string
	CreatedAt   time.Time
}

// RWCapabilityAttempts returns every row for runID individually, ordered
// by created_at ascending -- no GROUP BY, no aggregation. Kept entirely
// separate from RWCapabilityCoverage, which rwscore depends on in its
// exact aggregated form.
func RWCapabilityAttempts(ctx context.Context, pool *pgxpool.Pool, runID string) ([]RWAttemptRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT technique_id, action, capability, verdict, COALESCE(skip_reason, ''), reason, created_at
		FROM rw_capability_results
		WHERE run_id = $1
		ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("rw_capability_results attempts query failed for run=%s: %w", runID, err)
	}
	defer rows.Close()

	var out []RWAttemptRow
	for rows.Next() {
		var r RWAttemptRow
		var verdict, skipReason string
		if err := rows.Scan(&r.TechniqueID, &r.Action, &r.Capability, &verdict, &skipReason, &r.Reason, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("rw_capability_results attempts scan failed for run=%s: %w", runID, err)
		}
		r.Verdict = controlval.Verdict(verdict)
		r.SkipReason = controlval.SkipReason(skipReason)
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/ -run TestRWCapabilityAttempts -v -timeout 60s`
Expected: PASS (1/1)

- [ ] **Step 5: Run the full db package to verify `RWCapabilityCoverage`/`rwscore` are unaffected**

Run: `cd orchestrator && go test ./internal/db/ -timeout 15m`
Expected: `ok` — every existing test, including all `rwscore`-dependent coverage tests, still passes unmodified

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/db/rwevidence_store.go internal/db/rwevidence_store_test.go
git commit -m "feat(db): RWCapabilityAttempts -- raw per-attempt read, RWCapabilityCoverage untouched

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: API adapter, endpoint, route, and the Clop end-to-end test

**Files:**
- Create: `orchestrator/internal/api/dxcorrelate_handlers.go`
- Create: `orchestrator/internal/api/dxcorrelate_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `db.RWAttemptRow`, `db.RWCapabilityAttempts` (Task 4); `dxcorrelate.Leg`, `dxcorrelate.AttemptRow`, `dxcorrelate.ControlEfficacyStatus`/`BehaviorStatus` constants, `dxcorrelate.Correlate`, `dxcorrelate.CorrelationResult` (Tasks 2-3); `rwevidence.StepInput`, `rwevidence.StepDependencies`, `rwevidence.EvaluateStep`, `rwevidence.FakeDataProtectionLookup`, `rwevidence.FakeRecoveryObserver`, `rwevidence.FakeContainmentObserver`, `rwevidence.FakeDetectionLookup`, `controlval.FakeProvider` (Task 1 + pre-existing) for the Clop-shaped test's seeding.
- Produces: nothing new for later tasks — this is the integration point itself.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/dxcorrelate_handlers_test.go`:

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

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dxcorrelate"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestToAttemptRows_MapsStagingAndTransferIgnoresEncryptionCapabilities(t *testing.T) {
	rows := []db.RWAttemptRow{
		{TechniqueID: "T1560.001", Capability: "data_protection", Verdict: "FAIL", Action: "a1"},
		{TechniqueID: "T1567.002", Capability: "data_protection", Verdict: "PASS", Action: "a2"},
		{TechniqueID: "T1486", Capability: "prevention", Verdict: "FAIL", Action: "a3"},
		{TechniqueID: "T1486", Capability: "detection", Verdict: "PASS", Action: "a4"},
		{TechniqueID: "T1486", Capability: "containment", Verdict: "FAIL", Action: "a5"},
	}
	out := toAttemptRows(rows)
	if len(out) != 2 {
		t.Fatalf("got %d attempt rows, want 2 -- T1486's Prevention/Detection/Containment must never be translated", len(out))
	}
	byLeg := map[dxcorrelate.Leg]dxcorrelate.AttemptRow{}
	for _, r := range out {
		byLeg[r.Leg] = r
	}
	if byLeg[dxcorrelate.LegStaging].ControlEfficacy != dxcorrelate.EfficacyNotDetected {
		t.Errorf("staging ControlEfficacy = %q, want not_detected", byLeg[dxcorrelate.LegStaging].ControlEfficacy)
	}
	if byLeg[dxcorrelate.LegTransfer].ControlEfficacy != dxcorrelate.EfficacyDetected {
		t.Errorf("transfer ControlEfficacy = %q, want detected", byLeg[dxcorrelate.LegTransfer].ControlEfficacy)
	}
}

func TestToAttemptRows_BehaviorIsNeverDerivedFromControlEfficacy(t *testing.T) {
	for _, verdict := range []controlval.Verdict{"PASS", "FAIL", "ERROR", "SKIPPED"} {
		rows := []db.RWAttemptRow{{TechniqueID: "T1560.001", Capability: "data_protection", Verdict: verdict, SkipReason: "not_applicable", Action: "a"}}
		out := toAttemptRows(rows)
		if len(out) != 1 {
			t.Fatalf("verdict=%s: got %d attempt rows, want 1", verdict, len(out))
		}
		if out[0].Behavior != dxcorrelate.BehaviorNotEstablished {
			t.Fatalf("verdict=%s: Behavior = %q, want not_established -- control-efficacy must never establish behavior", verdict, out[0].Behavior)
		}
	}
}

func clopShapedDeps(runID, action, techniqueID string) rwevidence.StepDependencies {
	key := runID + "/" + techniqueID + "/" + action
	return rwevidence.StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &rwevidence.FakeRecoveryObserver{},
		Containment:    &rwevidence.FakeContainmentObserver{},
		Detection:      &rwevidence.FakeDetectionLookup{},
		DataProtection: &rwevidence.FakeDataProtectionLookup{Status: map[string]string{key: "NotDetected"}},
	}
}

func TestGetDoubleExtortionCorrelation_ClopShapedRun_ReportsHonestInsufficientEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "clop-shaped-run"

		stagingIn := rwevidence.StepInput{RunID: runID, Action: "staging-action", TechniqueID: "T1560.001", StepName: "Cl0p Stage 3 — Archive Staging via Compress-Archive (T1560.001)", CheckResult: "fail", Details: "FAIL: zip created unblocked"}
		stagingResults := rwevidence.EvaluateStep(stagingIn, clopShapedDeps(runID, "staging-action", "T1560.001"))
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "staging-action", stagingResults); err != nil {
			t.Fatalf("seed staging: %v", err)
		}

		transferIn := rwevidence.StepInput{RunID: runID, Action: "transfer-action", TechniqueID: "T1567.002", StepName: "Cl0p Stage 4 — Cloud Storage Egress Reachability (T1567.002)", CheckResult: "fail", Details: "FAIL: reachable"}
		transferResults := rwevidence.EvaluateStep(transferIn, clopShapedDeps(runID, "transfer-action", "T1567.002"))
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "transfer-action", transferResults); err != nil {
			t.Fatalf("seed transfer: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/double-extortion-correlation", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", runID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDoubleExtortionCorrelation(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Legs []struct {
				Leg             string `json:"leg"`
				ControlEfficacy string `json:"controlEfficacy"`
			} `json:"legs"`
			Classification string `json:"classification"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Classification != "insufficient_behavior_evidence" {
			t.Fatalf("Classification = %q, want insufficient_behavior_evidence -- real NotDetected control-efficacy evidence must never be promoted to a confirmed finding", got.Classification)
		}
		byLeg := map[string]string{}
		for _, l := range got.Legs {
			byLeg[l.Leg] = l.ControlEfficacy
		}
		if byLeg["staging"] != "not_detected" {
			t.Errorf("staging controlEfficacy = %q, want not_detected", byLeg["staging"])
		}
		if byLeg["transfer"] != "not_detected" {
			t.Errorf("transfer controlEfficacy = %q, want not_detected", byLeg["transfer"])
		}
		if byLeg["encryption"] != "no_evidence" {
			t.Errorf("encryption controlEfficacy = %q, want no_evidence", byLeg["encryption"])
		}
	})
}

func TestGetDoubleExtortionCorrelation_NoRelevantEvidence_Returns200InsufficientEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nonexistent-run/double-extortion-correlation", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "nonexistent-run")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDoubleExtortionCorrelation(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 -- a run with zero relevant evidence is not an error", rec.Code)
		}
		var got struct {
			Classification string `json:"classification"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Classification != "insufficient_behavior_evidence" {
			t.Fatalf("Classification = %q, want insufficient_behavior_evidence", got.Classification)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestToAttemptRows|TestGetDoubleExtortionCorrelation" -v`
Expected: FAIL — `undefined: toAttemptRows` (compile error)

- [ ] **Step 3: Implement the adapter and handler**

Create `orchestrator/internal/api/dxcorrelate_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dxcorrelate"
)

// toAttemptRows adapts raw per-attempt rows into dxcorrelate's own Leg
// vocabulary -- the one place in this sub-project allowed to know both
// MITRE technique IDs and dxcorrelate's types. No case produces
// Leg=encryption, or Behavior=Occurred for any leg: there is no accepted
// direct-behavior signal in this codebase today (design spec section A).
// T1486's Prevention/Detection/Containment rows are deliberately NOT
// translated into any AttemptRow at all.
func toAttemptRows(rows []db.RWAttemptRow) []dxcorrelate.AttemptRow {
	out := make([]dxcorrelate.AttemptRow, 0, len(rows))
	for _, r := range rows {
		var leg dxcorrelate.Leg
		switch {
		case r.TechniqueID == "T1560.001" && r.Capability == "data_protection":
			leg = dxcorrelate.LegStaging
		case r.TechniqueID == "T1567.002" && r.Capability == "data_protection":
			leg = dxcorrelate.LegTransfer
		default:
			continue
		}
		out = append(out, dxcorrelate.AttemptRow{
			Leg:             leg,
			Action:          r.Action,
			ControlEfficacy: controlEfficacyFor(r),
			Behavior:        dxcorrelate.BehaviorNotEstablished,
			Reason:          r.Reason,
			CreatedAt:       r.CreatedAt,
		})
	}
	return out
}

func controlEfficacyFor(r db.RWAttemptRow) dxcorrelate.ControlEfficacyStatus {
	switch {
	case r.Verdict == "PASS":
		return dxcorrelate.EfficacyDetected
	case r.Verdict == "FAIL":
		return dxcorrelate.EfficacyNotDetected
	case r.Verdict == "SKIPPED" && r.SkipReason == "not_applicable":
		return dxcorrelate.EfficacyNotApplicable
	default:
		return dxcorrelate.EfficacyNoEvidence
	}
}

type dxLegJSON struct {
	Leg             string `json:"leg"`
	ControlEfficacy string `json:"controlEfficacy"`
	Behavior        string `json:"behavior"`
	Reason          string `json:"reason,omitempty"`
}

type dxCorrelationJSON struct {
	Legs           []dxLegJSON `json:"legs"`
	Classification string      `json:"classification"`
	Anomaly        string      `json:"anomaly,omitempty"`
}

func toCorrelationJSON(result dxcorrelate.CorrelationResult) dxCorrelationJSON {
	out := dxCorrelationJSON{Legs: make([]dxLegJSON, len(result.Legs)), Classification: string(result.Classification), Anomaly: result.Anomaly}
	for i, l := range result.Legs {
		out.Legs[i] = dxLegJSON{Leg: string(l.Leg), ControlEfficacy: string(l.ControlEfficacy), Behavior: string(l.Behavior), Reason: l.Reason}
	}
	return out
}

func (h *Handler) GetDoubleExtortionCorrelation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID := chi.URLParam(r, "runId")

	rows, err := db.RWCapabilityAttempts(ctx, h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	result := dxcorrelate.Correlate(toAttemptRows(rows))
	jsonOK(w, toCorrelationJSON(result))
}
```

Modify `orchestrator/internal/api/routes.go` — insert right after the existing `r.Get("/api/scenarios/runs/{runId}/rw-score", h.GetRunRWScore)` line:

```go
		r.Get("/api/scenarios/runs/{runId}/rw-score", h.GetRunRWScore)
		r.Get("/api/scenarios/runs/{runId}/double-extortion-correlation", h.GetDoubleExtortionCorrelation)
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — add right after the existing rw-score matrix entry:

```go
	{http.MethodGet, "/api/scenarios/runs/{runId}/rw-score", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/double-extortion-correlation", tierAny, ""},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestToAttemptRows|TestGetDoubleExtortionCorrelation" -v -timeout 120s`
Expected: PASS (4/4)

- [ ] **Step 5: Run the two RBAC matrix tests explicitly**

Run: `cd orchestrator && go test ./internal/api/ -run "TestRBACMatrix_NoDrift|TestRBACMatrix_AuthorizationBoundary" -v -timeout 300s`
Expected: PASS — confirms the new route is registered correctly and that `tierAny` lets every role (including anonymous-rejected-with-401, every authenticated role accepted) through consistently with the existing `rw-score` GET.

- [ ] **Step 6: Run the full api package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/api/ -timeout 20m`
Expected: `ok` — existing routes/tests unaffected (additive route registration only)

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/dxcorrelate_handlers.go internal/api/dxcorrelate_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): double-extortion-correlation endpoint -- Clop proves honesty, not confirmation

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: Full regression gate across all four touched packages

**Files:**
- None (verification-only task; no new code).

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: nothing — this is the plan's terminal verification layer.

- [ ] **Step 1: Run the combined regression**

Run: `cd orchestrator && go test ./internal/rwevidence/ ./internal/dxcorrelate/ ./internal/db/ ./internal/api/ -timeout 25m -v 2>&1 | tail -100`
Expected: all four packages `ok`, 0 FAIL lines across the combined run

- [ ] **Step 2: If everything passes, there is nothing to commit for this task** — it exists only to catch anything a narrower per-task run might have missed from cross-package interaction between `rwevidence`, `dxcorrelate`, `db`, and `api` together in one invocation.
