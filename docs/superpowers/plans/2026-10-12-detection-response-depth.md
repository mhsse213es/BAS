# Detection/Response Depth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the fake-backed `rwdetect` bridge (mirroring `addetect`), a content-verified ransomware detection-profile inventory, and the `rwresponse` Detection/Containment/Recovery effectiveness join, plus the API endpoint exposing it.

**Architecture:** Three small, decoupled pure-Go pieces plus an API adapter layer, each mirroring an existing precedent exactly: `internal/rwdetect` mirrors `internal/addetect`'s one-way bridge shape; `internal/rwresponse` mirrors `internal/dxcorrelate`'s pure-join discipline, consuming sub-project #5's `db.RWCapabilityAttempts`; the API handler mirrors `internal/api/dxcorrelate_handlers.go`'s exact adapter/handler/route shape.

**Tech Stack:** Go, chi router, pgx/pgxpool (via `internal/db`, consumed only by the API layer), testcontainers-go (integration tests only).

**Spec:** `docs/superpowers/specs/2026-10-12-detection-response-depth-design.md`

## Global Constraints

- Response latency is **never** a computed duration anywhere in this sub-project — only the fixed `ResponseLatencyNotEstablishable` status. This is the single most important invariant; protect it with a dedicated test (Task 3).
- Detection latency is a real field (`*time.Duration`) that stays `nil`/absent on every real run today — nothing in this sub-project calls a real `detectverify.Connector`. It exists only so a future caller that has resolved a `VerifyResult` has somewhere to put it.
- `rwresponse` never reads Prevention or DataProtection rows — only `detection`/`containment`/`recovery`.
- The 17-profile detection inventory (content) and `rwevidence`'s technique model (code — still only 4 techniques: T1490, T1486, T1567.002, T1560.001) are two separate, independently-tracked coverage measures. Never conflate them in code or comments: a profile's presence in the inventory is never a claim that its MITRE technique is modeled by `rwevidence`, or that it has real detection-provider wiring.
- `internal/rwdetect` performs no I/O and calls no `detectverify.Connector` — it only builds requests and converts results. Wiring a real `Connector` into `rwevidence.StepDependencies.Detection` is separate, later, lab-gated work (Track I), out of scope here.
- The final regression task (Task 5) must run **alone**, not concurrently with any other heavy `go test` suite on this host — this session already hit a real memory-pressure kill running two full `internal/api` suites at once on this ~7.8GB machine.

## Review Focus

- A technique with some but not all of Detection/Containment/Recovery present must show `nil`, not a zero-value struct, for each absent dimension — pinned by Task 3's `TestBuildEffectivenessReport_MissingDimensionIsNilNotZeroValue`.
- A technique whose only rows are Prevention/DataProtection must still appear in the report (grouping happens before capability filtering) with all three dimensions `nil`, never silently dropped — pinned by Task 3's `TestBuildEffectivenessReport_PreventionAndDataProtectionRowsNeverRead`.
- Multiple rows for the same (technique, capability) pair must deterministically resolve to the earliest by `CreatedAt`, regardless of input order, never panic or silently drop data — pinned by Task 3's duplicate-row test (two input orderings, same result).
- `ResponseLatency` must stay `NotEstablishable` even on a row where `DetectionLatency` is populated — proving the two fields are genuinely independent, not derived from each other — pinned by Task 3's `TestBuildEffectivenessReport_ResponseLatencyAlwaysNotEstablishable`.
- The new route's RBAC boundary (401 anonymous, 200 for every authenticated tier) must match sub-project #5's already-passing pattern exactly — pinned by Task 4's RBAC matrix run.

---

### Task 1: `internal/rwdetect` — the bridge

**Files:**
- Create: `orchestrator/internal/rwdetect/bridge.go`
- Create: `orchestrator/internal/rwdetect/bridge_test.go`

**Interfaces:**
- Consumes: `rwevidence.Technique` (`ID`, `Name`, `MitreID`, `RiskClass` — unchanged), `detectverify.VerifyRequest`, `detectverify.VerifyResult`, `detectverify.MatchedAlert`, `detectverify.VerdictDetected`/`VerdictNotDetected` (all unchanged, pre-existing).
- Produces: `VerifyRequestFor(tech rwevidence.Technique, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool)`, `DetectionLookupResultFor(result detectverify.VerifyResult) (tested, verified bool, reason string)` — not consumed by any later task in this plan (nothing here wires a real `Connector` call); available for the separate, later, lab-gated real-wiring work this bridge exists to make possible.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwdetect/bridge_test.go`:

```go
package rwdetect

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

func TestVerifyRequestFor_NoMitreIDReturnsFalse(t *testing.T) {
	tech := rwevidence.Technique{ID: "archive-staging-via-utility"} // no MitreID
	_, ok := VerifyRequestFor(tech, "run-1", "exp-1", "HOST01", "10.0.0.5", time.Time{}, time.Time{}, time.Time{})
	if ok {
		t.Fatal("expected ok=false for a technique with no MitreID")
	}
}

func TestVerifyRequestFor_MapsEveryFieldUnchanged(t *testing.T) {
	tech := rwevidence.Technique{ID: "vss-inhibition", MitreID: "T1490"}
	executedAt := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	windowStart := executedAt.Add(-5 * time.Minute)
	windowEnd := executedAt.Add(10 * time.Minute)

	got, ok := VerifyRequestFor(tech, "run-1", "exp-42", "HOST01", "10.0.0.10", executedAt, windowStart, windowEnd)
	if !ok {
		t.Fatal("expected ok=true for a technique with a MitreID")
	}
	want := detectverify.VerifyRequest{
		RunID:          "run-1",
		ExpectationID:  "exp-42",
		TechniqueID:    "T1490",
		HostName:       "HOST01",
		HostIP:         "10.0.0.10",
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}

func TestDetectionLookupResultFor_DetectedSingleAlert(t *testing.T) {
	result := detectverify.VerifyResult{
		Verdict:       detectverify.VerdictDetected,
		Confidence:    detectverify.ConfidenceHigh,
		MatchedAlerts: []detectverify.MatchedAlert{{AlertID: "a1", RuleName: "VSS Deletion"}},
	}
	tested, verified, reason := DetectionLookupResultFor(result)
	if !tested || !verified {
		t.Fatalf("tested=%v verified=%v, want true/true", tested, verified)
	}
	if reason != "1 alert matched, confidence=high" {
		t.Fatalf("reason = %q, want singular wording for exactly 1 alert", reason)
	}
}

func TestDetectionLookupResultFor_DetectedMultipleAlerts(t *testing.T) {
	result := detectverify.VerifyResult{
		Verdict:    detectverify.VerdictDetected,
		Confidence: detectverify.ConfidenceMedium,
		MatchedAlerts: []detectverify.MatchedAlert{
			{AlertID: "a1"}, {AlertID: "a2"},
		},
	}
	tested, verified, reason := DetectionLookupResultFor(result)
	if !tested || !verified {
		t.Fatalf("tested=%v verified=%v, want true/true", tested, verified)
	}
	if reason != "2 alerts matched, confidence=medium" {
		t.Fatalf("reason = %q, want plural wording for 2 alerts", reason)
	}
}

func TestDetectionLookupResultFor_NotDetected(t *testing.T) {
	result := detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}
	tested, verified, reason := DetectionLookupResultFor(result)
	if !tested {
		t.Fatal("tested should always be true -- the query ran and returned a definitive verdict")
	}
	if verified {
		t.Fatal("verified should be false for VerdictNotDetected")
	}
	if reason != "no matching alerts found in the query window" {
		t.Fatalf("reason = %q, want the fixed no-match string", reason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwdetect/ -v`
Expected: FAIL — `undefined: VerifyRequestFor` (compile error; the package doesn't exist yet)

- [ ] **Step 3: Implement the bridge**

Create `orchestrator/internal/rwdetect/bridge.go`:

```go
// Package rwdetect bridges rwevidence's Detection capability toward the
// existing, generic detectverify.Connector interface -- mirroring
// internal/addetect's one-way bridge pattern exactly (addetect bridges
// AD-M08 the same way). Depends one-way on rwevidence and detectverify
// only; neither of those packages gains any rwdetect-awareness.
//
// This package performs no I/O and calls no Connector itself: wiring a
// real Connector into rwevidence.StepDependencies.Detection is a separate,
// later, lab-gated piece of work (Track I in the ransomware-mastery
// roadmap, same category as the real Recovery/Prevention observers). This
// package only builds the request and converts the eventual result -- the
// bridge's shape, not its real wiring.
package rwdetect

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

// VerifyRequestFor builds a detectverify.VerifyRequest for checking
// whether executing tech was detected, given caller-supplied run/host/
// timing context (tech itself carries none of that -- it describes a
// technique, not an execution). Returns ok=false when tech.MitreID is
// empty: detectverify is keyed on TechniqueID, so a technique with no 1:1
// MITRE mapping cannot be checked this way.
func VerifyRequestFor(tech rwevidence.Technique, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool) {
	if tech.MitreID == "" {
		return detectverify.VerifyRequest{}, false
	}
	return detectverify.VerifyRequest{
		RunID:          runID,
		ExpectationID:  expectationID,
		TechniqueID:    tech.MitreID,
		HostName:       hostName,
		HostIP:         hostIP,
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}, true
}

// DetectionLookupResultFor converts a resolved detectverify.VerifyResult
// into rwevidence.DetectionLookup's (tested, verified, reason) return
// shape. tested is always true here: by the time a VerifyResult exists,
// the query against the provider actually ran and returned a definitive
// Detected/NotDetected verdict -- a transport/auth error surfaces as a
// non-nil error from Connector.Verify itself, before any VerifyResult
// exists, and that error propagates directly as LookupDetection's own
// error return, never through this converter.
func DetectionLookupResultFor(result detectverify.VerifyResult) (tested bool, verified bool, reason string) {
	tested = true
	verified = result.Verdict == detectverify.VerdictDetected
	if !verified {
		return tested, verified, "no matching alerts found in the query window"
	}
	plural := "s"
	if len(result.MatchedAlerts) == 1 {
		plural = ""
	}
	return tested, verified, fmt.Sprintf("%d alert%s matched, confidence=%s", len(result.MatchedAlerts), plural, result.Confidence)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwdetect/ -v`
Expected: PASS (5/5)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/rwdetect/bridge.go internal/rwdetect/bridge_test.go
git commit -m "feat(rwdetect): the bridge -- mirrors addetect exactly, no real Connector call

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Ransomware detection-profile inventory

**Files:**
- Create: `orchestrator/internal/rwdetect/profiles.go`
- Create: `orchestrator/internal/rwdetect/profiles_test.go`

**Interfaces:**
- Consumes: `scenario.ParseYAML`, `scenario.Step.DetectionProfiles` (both unchanged, pre-existing).
- Produces: `RansomwareRelevantProfiles []string` — a content inventory, not consumed by any other task in this plan (Task 3/4 don't need it); exists as its own, independently-verified coverage measure per the spec.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/rwdetect/profiles_test.go`:

```go
package rwdetect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// ransomwareScenarioFiles matches internal/api.ransomwareScenarioIDs' 8
// entries exactly (also mirrored, separately, by
// internal/rwevidence/realcorpus_test.go's own list) -- kept as its own
// small copy here since that list is unexported in rwevidence.
var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
}

// repoScenariosDir resolves ../../../scenarios relative to this package --
// same relative depth as internal/rwevidence/realcorpus_test.go's own
// helper (internal/rwdetect and internal/rwevidence sit at the same depth
// under orchestrator/internal/), reused in shape, not imported (it's
// unexported there).
func repoScenariosDir(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

func TestRansomwareRelevantProfiles_MatchesRealCorpus(t *testing.T) {
	seen := map[string]bool{}
	for _, file := range ransomwareScenarioFiles {
		b, err := os.ReadFile(filepath.Join(repoScenariosDir(t), file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		sc, err := scenario.ParseYAML(b)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, step := range sc.Steps {
			for _, p := range step.DetectionProfiles {
				seen[p] = true
			}
		}
	}

	want := map[string]bool{}
	for _, p := range RansomwareRelevantProfiles {
		want[p] = true
	}

	for p := range seen {
		if !want[p] {
			t.Errorf("real corpus references profile %q, not in RansomwareRelevantProfiles -- list is stale", p)
		}
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("RansomwareRelevantProfiles lists %q, but no real scenario step references it -- list is stale", p)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/rwdetect/ -run RansomwareRelevantProfiles -v`
Expected: FAIL — `undefined: RansomwareRelevantProfiles` (compile error)

- [ ] **Step 3: Implement the inventory**

Create `orchestrator/internal/rwdetect/profiles.go`:

```go
package rwdetect

// RansomwareRelevantProfiles are the detection-profile names referenced by
// the 8 scenarios/drills internal/api.ransomwareScenarioIDs scopes
// rwevidence's integration to: akira-kill-chain.yaml, blackcat-kill-chain.yaml,
// clop-kill-chain.yaml, lockbit-kill-chain.yaml, play-kill-chain.yaml,
// ransomhub-kill-chain.yaml, ransomware-drill.yaml,
// endpoint-mastery/em-07-ransomware-readiness.yaml.
//
// This is a content inventory, not a capability model: a profile's
// presence here says nothing about whether it has real detection-provider
// wiring (see this package's deferred Track I work) or whether its MITRE
// technique is modeled by rwevidence (see internal/rwevidence/technique.go's
// own, smaller, independently-tracked set: T1490, T1486, T1567.002,
// T1560.001 today). Verified against the real scenario YAMLs by
// TestRansomwareRelevantProfiles_MatchesRealCorpus -- this list cannot
// silently drift from the content it describes.
var RansomwareRelevantProfiles = []string{
	"windows_ad_discovery",
	"windows_archive_staging",
	"windows_backup_service_stop",
	"windows_cloud_egress",
	"windows_defender_tampering",
	"windows_file_discovery",
	"windows_log_manipulation",
	"windows_malicious_service",
	"windows_network_share_discovery",
	"windows_ransomware_encryption",
	"windows_rdp_nla_posture",
	"windows_sam_theft",
	"windows_security_process_termination",
	"windows_security_software_discovery",
	"windows_smb_lateral_probe",
	"windows_vss_inhibition",
	"windows_vulnerable_driver_load",
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/rwdetect/ -v`
Expected: PASS (6/6 — Task 1's 5 + Task 2's 1)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/rwdetect/profiles.go internal/rwdetect/profiles_test.go
git commit -m "feat(rwdetect): ransomware-relevant detection-profile inventory, content-verified against the real corpus

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `internal/rwresponse` — the effectiveness join

**Files:**
- Create: `orchestrator/internal/rwresponse/types.go`
- Create: `orchestrator/internal/rwresponse/join.go`
- Create: `orchestrator/internal/rwresponse/join_test.go`

**Interfaces:**
- Consumes: `db.RWAttemptRow` (`TechniqueID`, `Action`, `Capability string`, `Verdict controlval.Verdict`, `SkipReason controlval.SkipReason`, `Reason string`, `CreatedAt time.Time` — sub-project #5's Task 4, unchanged).
- Produces: `DimensionEvidence`, `ResponseLatencyStatus` (`ResponseLatencyNotEstablishable`), `DetectionLatencyEvidence`, `EffectivenessRow`, `EffectivenessReport`, `BuildEffectivenessReport(rows []db.RWAttemptRow, latencies []DetectionLatencyEvidence) EffectivenessReport` — Task 4's API adapter calls this directly and reads every field of `EffectivenessRow`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/rwresponse/join_test.go`:

```go
package rwresponse

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
)

func row(technique, action, capability string, verdict controlval.Verdict, skipReason controlval.SkipReason, at time.Time) db.RWAttemptRow {
	return db.RWAttemptRow{TechniqueID: technique, Action: action, Capability: capability, Verdict: verdict, SkipReason: skipReason, CreatedAt: at}
}

var t0 = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func TestBuildEffectivenessReport_AllThreeDimensionsPresent(t *testing.T) {
	rows := []db.RWAttemptRow{
		row("T1490", "a1", "detection", controlval.VerdictFail, "", t0),
		row("T1490", "a1", "containment", controlval.VerdictPass, "", t0),
		row("T1490", "a1", "recovery", controlval.VerdictPass, "", t0),
	}
	report := BuildEffectivenessReport(rows, nil)
	if len(report.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(report.Rows))
	}
	r := report.Rows[0]
	if r.Detection == nil || r.Containment == nil || r.Recovery == nil {
		t.Fatalf("expected all three dimensions present, got %+v", r)
	}
	if r.Detection.Verdict != controlval.VerdictFail {
		t.Errorf("Detection.Verdict = %q, want FAIL", r.Detection.Verdict)
	}
}

func TestBuildEffectivenessReport_MissingDimensionIsNilNotZeroValue(t *testing.T) {
	rows := []db.RWAttemptRow{
		row("T1490", "a1", "containment", controlval.VerdictPass, "", t0),
		row("T1490", "a1", "recovery", controlval.VerdictPass, "", t0),
		// no detection row at all
	}
	report := BuildEffectivenessReport(rows, nil)
	r := report.Rows[0]
	if r.Detection != nil {
		t.Fatalf("Detection = %+v, want nil -- no detection row exists for this technique", r.Detection)
	}
	if r.Containment == nil || r.Recovery == nil {
		t.Fatal("Containment and Recovery should both be present")
	}
}

func TestBuildEffectivenessReport_PreventionAndDataProtectionRowsNeverRead(t *testing.T) {
	rows := []db.RWAttemptRow{
		row("T1486", "a1", "prevention", controlval.VerdictFail, "", t0),
		row("T1486", "a1", "data_protection", controlval.VerdictFail, "", t0),
	}
	report := BuildEffectivenessReport(rows, nil)
	if len(report.Rows) != 1 {
		t.Fatalf("got %d rows, want 1 -- the technique must still appear even with only Prevention/DataProtection rows", len(report.Rows))
	}
	r := report.Rows[0]
	if r.Detection != nil || r.Containment != nil || r.Recovery != nil {
		t.Fatalf("expected all three dimensions nil (Prevention/DataProtection are never translated), got %+v", r)
	}
}

func TestBuildEffectivenessReport_DuplicateRowsForSameCapability_DeterministicallyUsesEarliest(t *testing.T) {
	rowsA := []db.RWAttemptRow{
		row("T1490", "a2", "detection", controlval.VerdictPass, "", t0.Add(2*time.Hour)),
		row("T1490", "a1", "detection", controlval.VerdictFail, "", t0), // earliest
	}
	reportA := BuildEffectivenessReport(rowsA, nil)
	if reportA.Rows[0].Detection.Action != "a1" {
		t.Fatalf("Detection.Action = %q, want the earliest row's action a1", reportA.Rows[0].Detection.Action)
	}
	// Same two rows, different slice order -- must produce the identical result (deterministic).
	rowsB := []db.RWAttemptRow{rowsA[1], rowsA[0]}
	reportB := BuildEffectivenessReport(rowsB, nil)
	if reportA.Rows[0].Detection.Verdict != reportB.Rows[0].Detection.Verdict {
		t.Fatalf("order-dependent result: %q vs %q", reportA.Rows[0].Detection.Verdict, reportB.Rows[0].Detection.Verdict)
	}
}

func TestBuildEffectivenessReport_ResponseLatencyAlwaysNotEstablishable(t *testing.T) {
	rows := []db.RWAttemptRow{row("T1490", "a1", "detection", controlval.VerdictFail, "", t0)}
	lat := 3 * time.Second
	report := BuildEffectivenessReport(rows, []DetectionLatencyEvidence{{TechniqueID: "T1490", Action: "a1", Latency: lat}})
	r := report.Rows[0]
	if r.DetectionLatency == nil || *r.DetectionLatency != lat {
		t.Fatalf("DetectionLatency = %v, want %v", r.DetectionLatency, lat)
	}
	if r.ResponseLatency != ResponseLatencyNotEstablishable {
		t.Fatalf("ResponseLatency = %q, want not_establishable even when DetectionLatency is present -- the two are independent", r.ResponseLatency)
	}
}

func TestBuildEffectivenessReport_DetectionLatencyNilWithoutMatch(t *testing.T) {
	rows := []db.RWAttemptRow{row("T1490", "a1", "detection", controlval.VerdictFail, "", t0)}
	report := BuildEffectivenessReport(rows, nil)
	if report.Rows[0].DetectionLatency != nil {
		t.Fatalf("DetectionLatency = %v, want nil when no latency evidence supplied", report.Rows[0].DetectionLatency)
	}
}

func TestBuildEffectivenessReport_NoRows_ReturnsEmptyNotNilSlice(t *testing.T) {
	report := BuildEffectivenessReport(nil, nil)
	if report.Rows == nil {
		t.Fatal("Rows is nil, want an empty (non-nil) slice")
	}
	if len(report.Rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(report.Rows))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/rwresponse/ -v`
Expected: FAIL — `undefined: BuildEffectivenessReport` (compile error; the package doesn't exist yet)

- [ ] **Step 3: Implement `types.go` and `join.go`**

Create `orchestrator/internal/rwresponse/types.go`:

```go
// Package rwresponse joins Detection, Containment, and Recovery evidence
// for one run into a response-effectiveness view, per technique. It is
// pure Go, with no DB or HTTP import -- same discipline as dxcorrelate.
// The API-layer adapter (internal/api) is the one place that calls
// db.RWCapabilityAttempts and passes its rows in here.
//
// Prevention and DataProtection rows are deliberately never read by this
// package: distinguishing prevention, detection, containment and recovery
// (this sub-project's own exit criterion) means keeping each dimension's
// independent verdict legible, not collapsing five capabilities into one
// join.
//
// ResponseLatency is always NotEstablishable today (design spec section
// A): internal/actions' action_requests table carries run_id but no
// technique_id/action column, so no causal link between a detection event
// and the containment action that answered it exists in this codebase.
// DetectionLatency is different -- a real field on detectverify.VerifyResult
// -- but nothing in this sub-project calls a real Connector, so it stays
// nil on every row built from a real run today; it exists only so a
// caller that HAS resolved a VerifyResult (via rwdetect, later, lab-gated)
// has somewhere to put it.
package rwresponse

import (
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// DimensionEvidence is one capability's selected evidence for one
// technique. A nil *DimensionEvidence on an EffectivenessRow means no row
// exists at all for that (technique, capability) pair -- distinct from a
// present row whose Verdict is SKIPPED, which still carries a SkipReason
// and Reason explaining why.
type DimensionEvidence struct {
	Verdict    controlval.Verdict
	SkipReason controlval.SkipReason
	Reason     string
	Action     string
	CreatedAt  time.Time
}

// ResponseLatencyStatus is a distinct type, not a *time.Duration left nil,
// so a caller cannot mistake "not establishable" for "zero latency" -- the
// same reasoning dxcorrelate.BehaviorStatus applies to BehaviorOccurred vs
// BehaviorNotEstablished.
type ResponseLatencyStatus string

const ResponseLatencyNotEstablishable ResponseLatencyStatus = "not_establishable"

const responseLatencyNotEstablishableReason = "no causal link between a detection event and a specific containment action exists in this codebase today (action_requests carries run_id only, not technique_id/action)"

// DetectionLatencyEvidence is one technique's measured detection latency,
// supplied by a caller that has resolved a detectverify.VerifyResult.
// Keyed by TechniqueID+Action, matching rwevidence.AttemptKey's own
// identity. BuildEffectivenessReport performs no detectverify call itself.
type DetectionLatencyEvidence struct {
	TechniqueID string
	Action      string
	Latency     time.Duration
}

// EffectivenessRow is one technique's Detection/Containment/Recovery
// evidence side by side, plus latency context.
type EffectivenessRow struct {
	TechniqueID           string
	Detection             *DimensionEvidence
	Containment           *DimensionEvidence
	Recovery              *DimensionEvidence
	DetectionLatency      *time.Duration
	ResponseLatency       ResponseLatencyStatus
	ResponseLatencyReason string
}

// EffectivenessReport is the full join for one run. Rows is empty (never
// nil) when the run has no Detection/Containment/Recovery evidence for any
// technique -- not an error.
type EffectivenessReport struct {
	Rows []EffectivenessRow
}
```

Create `orchestrator/internal/rwresponse/join.go`:

```go
package rwresponse

import (
	"sort"
	"time"

	"github.com/audspect/bas/internal/db"
)

// BuildEffectivenessReport groups rows by TechniqueID, selects each
// technique's earliest row per capability in {detection, containment,
// recovery} (deterministic -- ties and input-slice reordering never
// change the result, mirroring dxcorrelate.selectLegEvidence's own
// earliest-wins rule), and attaches latency evidence by (TechniqueID,
// Action) when latencies supplies a match. Output rows are sorted by
// TechniqueID for deterministic ordering. A technique whose only rows are
// Prevention/DataProtection still appears in the output, with Detection/
// Containment/Recovery all nil -- this package groups by TechniqueID
// first and filters by capability second, so no technique silently
// disappears because its rows happen to be outside this package's three
// read capabilities.
func BuildEffectivenessReport(rows []db.RWAttemptRow, latencies []DetectionLatencyEvidence) EffectivenessReport {
	byTechnique := map[string][]db.RWAttemptRow{}
	for _, r := range rows {
		byTechnique[r.TechniqueID] = append(byTechnique[r.TechniqueID], r)
	}

	latencyByKey := map[string]time.Duration{}
	for _, l := range latencies {
		latencyByKey[l.TechniqueID+"/"+l.Action] = l.Latency
	}

	techniqueIDs := make([]string, 0, len(byTechnique))
	for id := range byTechnique {
		techniqueIDs = append(techniqueIDs, id)
	}
	sort.Strings(techniqueIDs)

	out := make([]EffectivenessRow, 0, len(techniqueIDs))
	for _, id := range techniqueIDs {
		techRows := byTechnique[id]
		detection := selectDimension(techRows, "detection")
		containment := selectDimension(techRows, "containment")
		recovery := selectDimension(techRows, "recovery")

		rowOut := EffectivenessRow{
			TechniqueID:           id,
			Detection:             detection,
			Containment:           containment,
			Recovery:              recovery,
			ResponseLatency:       ResponseLatencyNotEstablishable,
			ResponseLatencyReason: responseLatencyNotEstablishableReason,
		}
		if detection != nil {
			if lat, ok := latencyByKey[id+"/"+detection.Action]; ok {
				rowOut.DetectionLatency = &lat
			}
		}
		out = append(out, rowOut)
	}
	return EffectivenessReport{Rows: out}
}

func selectDimension(rows []db.RWAttemptRow, capability string) *DimensionEvidence {
	var matching []db.RWAttemptRow
	for _, r := range rows {
		if r.Capability == capability {
			matching = append(matching, r)
		}
	}
	if len(matching) == 0 {
		return nil
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].CreatedAt.Before(matching[j].CreatedAt) })
	first := matching[0]
	return &DimensionEvidence{Verdict: first.Verdict, SkipReason: first.SkipReason, Reason: first.Reason, Action: first.Action, CreatedAt: first.CreatedAt}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/rwresponse/ -v`
Expected: PASS (7/7)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/rwresponse/types.go internal/rwresponse/join.go internal/rwresponse/join_test.go
git commit -m "feat(rwresponse): Detection/Containment/Recovery effectiveness join -- response latency never computed, only not_establishable

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: API adapter, endpoint, route, and the end-to-end test

**Files:**
- Create: `orchestrator/internal/api/rwresponse_handlers.go`
- Create: `orchestrator/internal/api/rwresponse_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `db.RWCapabilityAttempts`, `db.RWAttemptRow` (Task 4 of sub-project #5); `rwresponse.DimensionEvidence`, `rwresponse.EffectivenessRow`, `rwresponse.EffectivenessReport`, `rwresponse.BuildEffectivenessReport` (Task 3); `rwevidence.StepInput`, `rwevidence.StepDependencies`, `rwevidence.EvaluateStep`, the 5 Fake observers, `controlval.FakeProvider` (pre-existing) for the end-to-end test's seeding.
- Produces: nothing new for later tasks — this is the integration point itself.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/rwresponse_handlers_test.go`:

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
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func rwResponseTestDeps() rwevidence.StepDependencies {
	return rwevidence.StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &rwevidence.FakeRecoveryObserver{},
		Containment:    &rwevidence.FakeContainmentObserver{},
		Detection:      &rwevidence.FakeDetectionLookup{},
		DataProtection: &rwevidence.FakeDataProtectionLookup{},
	}
}

func TestGetDetectionResponseEffectiveness_T1490AndT1486_ReportsAllThreeDimensionsHonestly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "effectiveness-test-run"

		t1490In := rwevidence.StepInput{RunID: runID, Action: "vss-delete", TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion (T1490)", CheckResult: "fail", Details: "FAIL: shadow copies deleted"}
		t1490Results := rwevidence.EvaluateStep(t1490In, rwResponseTestDeps())
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "vss-delete", t1490Results); err != nil {
			t.Fatalf("seed T1490: %v", err)
		}

		t1486In := rwevidence.StepInput{RunID: runID, Action: "encrypt", TechniqueID: "T1486", StepName: "Mass File Encryption (T1486)", CheckResult: "fail", Details: "FAIL: files encrypted"}
		t1486Results := rwevidence.EvaluateStep(t1486In, rwResponseTestDeps())
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "encrypt", t1486Results); err != nil {
			t.Fatalf("seed T1486: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/detection-response-effectiveness", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", runID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDetectionResponseEffectiveness(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Rows []struct {
				TechniqueID     string         `json:"techniqueId"`
				Detection       map[string]any `json:"detection"`
				Containment     map[string]any `json:"containment"`
				Recovery        map[string]any `json:"recovery"`
				ResponseLatency string         `json:"responseLatency"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Rows) != 2 {
			t.Fatalf("got %d rows, want 2 (T1490 and T1486)", len(got.Rows))
		}
		for _, row := range got.Rows {
			if row.ResponseLatency != "not_establishable" {
				t.Errorf("technique %s: responseLatency = %q, want not_establishable", row.TechniqueID, row.ResponseLatency)
			}
			if row.Detection == nil || row.Containment == nil || row.Recovery == nil {
				t.Errorf("technique %s: expected all three dimensions present (every EvaluateStep attempt writes all 5 capability rows), got detection=%v containment=%v recovery=%v", row.TechniqueID, row.Detection, row.Containment, row.Recovery)
			}
		}
	})
}

func TestGetDetectionResponseEffectiveness_NoEvidence_Returns200EmptyRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nonexistent-run/detection-response-effectiveness", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "nonexistent-run")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDetectionResponseEffectiveness(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 -- a run with zero relevant evidence is not an error", rec.Code)
		}
		var got struct {
			Rows []any `json:"rows"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Rows) != 0 {
			t.Fatalf("got %d rows, want 0", len(got.Rows))
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetDetectionResponseEffectiveness" -v`
Expected: FAIL — `undefined: rwevidence.FakeRecoveryObserver`-style compile succeeds (those already exist), but `h.GetDetectionResponseEffectiveness` is undefined (compile error)

- [ ] **Step 3: Implement the adapter and handler**

Create `orchestrator/internal/api/rwresponse_handlers.go`:

```go
package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwresponse"
)

type rwDimensionJSON struct {
	Verdict    string `json:"verdict"`
	SkipReason string `json:"skipReason,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Action     string `json:"action,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
}

type rwEffectivenessRowJSON struct {
	TechniqueID           string           `json:"techniqueId"`
	Detection              *rwDimensionJSON `json:"detection"`
	Containment            *rwDimensionJSON `json:"containment"`
	Recovery               *rwDimensionJSON `json:"recovery"`
	DetectionLatencyMs     *int64           `json:"detectionLatencyMs"`
	ResponseLatency        string           `json:"responseLatency"`
	ResponseLatencyReason  string           `json:"responseLatencyReason"`
}

type rwEffectivenessReportJSON struct {
	Rows []rwEffectivenessRowJSON `json:"rows"`
}

func toDimensionJSON(d *rwresponse.DimensionEvidence) *rwDimensionJSON {
	if d == nil {
		return nil
	}
	return &rwDimensionJSON{
		Verdict:    string(d.Verdict),
		SkipReason: string(d.SkipReason),
		Reason:     d.Reason,
		Action:     d.Action,
		CreatedAt:  d.CreatedAt.Format(time.RFC3339),
	}
}

func toEffectivenessReportJSON(report rwresponse.EffectivenessReport) rwEffectivenessReportJSON {
	out := rwEffectivenessReportJSON{Rows: make([]rwEffectivenessRowJSON, len(report.Rows))}
	for i, r := range report.Rows {
		rowOut := rwEffectivenessRowJSON{
			TechniqueID:           r.TechniqueID,
			Detection:              toDimensionJSON(r.Detection),
			Containment:            toDimensionJSON(r.Containment),
			Recovery:               toDimensionJSON(r.Recovery),
			ResponseLatency:        string(r.ResponseLatency),
			ResponseLatencyReason:  r.ResponseLatencyReason,
		}
		if r.DetectionLatency != nil {
			ms := r.DetectionLatency.Milliseconds()
			rowOut.DetectionLatencyMs = &ms
		}
		out.Rows[i] = rowOut
	}
	return out
}

func (h *Handler) GetDetectionResponseEffectiveness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID := chi.URLParam(r, "runId")

	rows, err := db.RWCapabilityAttempts(ctx, h.db, runID)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	report := rwresponse.BuildEffectivenessReport(rows, nil)
	jsonOK(w, toEffectivenessReportJSON(report))
}
```

Modify `orchestrator/internal/api/routes.go` — insert right after the existing `r.Get("/api/scenarios/runs/{runId}/double-extortion-correlation", h.GetDoubleExtortionCorrelation)` line:

```go
		r.Get("/api/scenarios/runs/{runId}/double-extortion-correlation", h.GetDoubleExtortionCorrelation)
		r.Get("/api/scenarios/runs/{runId}/detection-response-effectiveness", h.GetDetectionResponseEffectiveness)
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — add right after the existing double-extortion-correlation matrix entry:

```go
	{http.MethodGet, "/api/scenarios/runs/{runId}/double-extortion-correlation", tierAny, ""},
	{http.MethodGet, "/api/scenarios/runs/{runId}/detection-response-effectiveness", tierAny, ""},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestGetDetectionResponseEffectiveness" -v -timeout 120s`
Expected: PASS (2/2)

- [ ] **Step 5: Run the two RBAC matrix tests explicitly**

Run: `cd orchestrator && go test ./internal/api/ -run "TestRBACMatrix_NoDrift|TestRBACMatrix_AuthorizationBoundary" -v -timeout 300s`
Expected: PASS — confirms the new route is registered correctly and `tierAny` lets every role through consistently with the existing `rw-score`/`double-extortion-correlation` GETs (401 anonymous, 200 viewer/analyst/admin).

- [ ] **Step 6: Run the full api package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/api/ -timeout 20m`
Expected: `ok` — existing routes/tests unaffected (additive route registration only). Run this ALONE on this host — do not run it concurrently with any other full-package `go test` invocation (memory-pressure constraint, see Global Constraints).

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/rwresponse_handlers.go internal/api/rwresponse_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): detection-response-effectiveness endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Full regression gate across all four touched packages

**Files:**
- None (verification-only task; no new code).

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: nothing — this is the plan's terminal verification layer.

- [ ] **Step 1: Run the combined regression, alone**

This host hit a real memory-pressure kill earlier this session running two full `internal/api` suites concurrently (~7.8GB RAM, two simultaneous Postgres testcontainers). Confirm nothing else heavy is running before starting this.

Run: `cd orchestrator && go test ./internal/rwdetect/ ./internal/rwresponse/ ./internal/db/ ./internal/api/ -timeout 25m -v 2>&1 | tail -100`
Expected: all four packages `ok`, 0 FAIL lines across the combined run

- [ ] **Step 2: If everything passes, there is nothing to commit for this task** — it exists only to catch anything a narrower per-task run might have missed from cross-package interaction between `rwdetect`, `rwresponse`, `db`, and `api` together in one invocation.
