# Detection/Response Depth — Design Spec

Sub-project #6 of the ransomware-mastery master roadmap (`ransomware.txt` decomposition table, row 6; narrative source `ransomware.txt` §2 item 5, "Detection, correlation and response validation", Phase 3). Depends only on #1 (`rwevidence`, done). Not lab-gated. Builds on sub-project #5's `db.RWCapabilityAttempts` (Task 4) for its evidence join.

## A. Problem statement

The roadmap table summarizes this sub-project as "connect remaining 12 of 13 detection profiles, build the deferred rwdetect latency bridge, incident-closure verification." That summary is stale and partially inaccurate against the current codebase — reconciled below rather than taken at face value (same discipline applied to sub-project #4's table-row discrepancy).

**What "13 detection profiles" actually traces to:** a July 2026 design spec (`docs/superpowers/specs/2026-07-14-detection-rule-library-design.md`) noting "~13 profiles today" as the *total* count of `scenarios/detection-profiles/*.yaml` at that time. The catalog has since grown to 29 profiles. Of those, **17** are referenced by the 8 scenarios/drills `rwevidence` scopes itself to (`internal/api/rwevidence_dispatch.go`'s `ransomwareScenarioIDs`: `akira-kill-chain`, `blackcat-kill-chain`, `clop-kill-chain`, `lockbit-kill-chain`, `play-kill-chain`, `ransomhub-kill-chain`, `ransomware-drill`, `em-07-ransomware-readiness`).

**What "already connected" actually means today:** `internal/rwevidence/detection.go`'s `DetectionFromProfileResult` carries a comment that `windows_vss_inhibition` is "already live, Microsoft-Defender auto-verified" — but that describes the pre-existing, separate Detection Validation Pack (`internal/detectverify`'s 7 connectors: Sentinel, Defender XDR, Splunk, QRadar, CrowdStrike, Trellix, Elastic). `rwevidence.DetectionLookup` itself is 100% fake-backed today, for every technique including `windows_vss_inhibition` — no technique has real detection-provider wiring inside `rwevidence`. The same comment names the deferred work explicitly: *"a detectverify-based rwdetect bridge (mirroring latdetect/addetect) for real alert-latency measurement is a separable later phase."* This spec builds that bridge's structure — fake-backed, same discipline as every other sub-project this session — not a real connector integration.

**Scope boundary (decided during brainstorming, binding for this spec):**

- **In scope:** (a) `internal/rwdetect`, a one-way bridge package mirroring `internal/addetect`'s shape exactly; (b) an explicit, content-verified inventory of the 17 ransomware-relevant detection profiles (profile-level, not a claim about technique coverage or real wiring); (c) a response-effectiveness join across the Detection/Containment/Recovery evidence `rwevidence` already models for whichever techniques it already covers today (T1490, T1486, T1567.002, T1560.001 — not the other 11 technique IDs the 8 scenarios also reference).
- **Out of scope, explicitly:** real `detectverify.Connector` wiring (Track I, lab-gated, deferred like T1/T2); expanding `rwevidence` to model the other 11 unmapped technique IDs (T1003.002, T1021.001/.002, T1070.001, T1083, T1087.002, T1135, T1489, T1518.001, T1543.003, T1562.001) across all 5 capabilities — a separate, later sub-project; the "low-and-slow composite attack sequence" scenario content named in §2.5's narrative — content-authoring work, not engineering, deferred to sub-project #10 or its own pass.
- **A profile being in the 17-profile inventory is not a claim that its detection logic is implemented or connected to a real provider.** Profile inventory (content) and technique evidence model (code) are two different, independently-tracked coverage measures — conflating them was the original roadmap table's mistake.

**The central honesty rule for this spec, matching sub-project #5's `BehaviorStatus.NotEstablished` precedent exactly:** response latency (the time from a detection event to the containment action that answered it) cannot be computed today. `internal/actions`' `action_requests` table (the EPP response-action audit trail, already feature-complete) carries `run_id` but no `technique_id` or `action` column — so there is no causal link between a specific detection and a specific containment action, only "this action happened sometime during this run." Reporting the nearest-in-time action as "the" response would overstate the evidence even if labeled run-level: that action might have been triggered by an unrelated alert or a manual operator decision. This spec therefore reports response latency as an explicit `NotEstablishable` status, never a computed duration, until a real causal link exists (a future, separately-designed piece of work). Detection latency is different: `detectverify.VerifyResult.DetectionLatency` already exists as a real field on a real (if not-yet-wired) type, so this spec threads it through as an optional value — present only when a caller supplies it, absent (nil) for every real run today, since nothing in this sub-project wires a real connector call.

## B. `internal/rwdetect` — the bridge

A new, tiny package with **no interfaces and no fakes** — unlike every other evidence package in this initiative, it does no observation itself. It mirrors `internal/addetect/bridge.go`'s exact shape: pure functions, one-way dependency on `rwevidence` (for `Technique`) and `detectverify` (for `VerifyRequest`/`VerifyResult`), and neither of those packages gains any ransomware- or rwdetect-awareness.

```go
package rwdetect

import (
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

// VerifyRequestFor builds a detectverify.VerifyRequest for checking whether
// executing tech was detected, given caller-supplied run/host/timing
// context (tech itself carries none of that -- it describes a technique,
// not an execution). Returns ok=false when tech.MitreID is empty:
// detectverify is keyed on TechniqueID, so a technique with no 1:1 MITRE
// mapping cannot be checked this way. Mirrors addetect.VerifyRequestFor
// exactly (internal/addetect/bridge.go) -- same shape, same guard, ransomware
// in place of AD.
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
// shape. tested is always true here: by the time a VerifyResult exists, the
// query against the provider actually ran and returned a definitive
// Detected/NotDetected verdict (a transport/auth error surfaces as a
// non-nil error from Connector.Verify itself, before any VerifyResult
// exists -- that error propagates directly as LookupDetection's own error
// return, never through this converter). This function performs no I/O and
// calls no Connector: wiring a real Connector into rwevidence's
// StepDependencies.Detection is the separate, later, lab-gated Track I
// piece of work this bridge exists to make possible, not something this
// sub-project does.
func DetectionLookupResultFor(result detectverify.VerifyResult) (tested bool, verified bool, reason string) {
	tested = true
	verified = result.Verdict == detectverify.VerdictDetected
	if verified {
		reason = formatDetectedReason(result)
	} else {
		reason = "no matching alerts found in the query window"
	}
	return tested, verified, reason
}

func formatDetectedReason(result detectverify.VerifyResult) string {
	plural := ""
	if len(result.MatchedAlerts) != 1 {
		plural = "s"
	}
	return fmtAlertCount(len(result.MatchedAlerts), plural, result.Confidence)
}
```

(`fmtAlertCount` is a one-line `fmt.Sprintf` helper; spelled out in the implementation plan, not here, to avoid duplicating trivial string formatting across the spec and the plan.)

### B.1. Profile inventory

Not a new package — a plain, tested data file. Location: `internal/rwdetect/profiles.go`, since this is specifically about the detection/telemetry side (not Prevention/Recovery/Containment/DataProtection, which stay `rwevidence`'s concern).

```go
// RansomwareRelevantProfiles are the detection-profile names referenced by
// the 8 scenarios/drills internal/api.ransomwareScenarioIDs scopes
// rwevidence's integration to (sub-project #1's spec "Scope" section):
// akira-kill-chain.yaml, blackcat-kill-chain.yaml, clop-kill-chain.yaml,
// lockbit-kill-chain.yaml, play-kill-chain.yaml, ransomhub-kill-chain.yaml,
// ransomware-drill.yaml, endpoint-mastery/em-07-ransomware-readiness.yaml.
//
// This is a content inventory, not a capability model: a profile's
// presence here says nothing about whether it has real detection-provider
// wiring (see this package's deferred Track I work) or whether its MITRE
// technique is modeled by rwevidence (see internal/rwevidence/technique.go's
// own, smaller, independently-tracked set: T1490, T1486, T1567.002,
// T1560.001 today). Verified against the real scenario YAMLs by
// TestRansomwareRelevantProfiles_MatchesRealCorpus (profiles_test.go) --
// this list cannot silently drift from the content it describes.
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

`profiles_test.go` mirrors `internal/rwevidence/realcorpus_test.go`'s `repoScenariosDir`/`loadRealSteps` pattern (its own small copy — these two helpers are unexported in `rwevidence` and not worth cross-package plumbing for ~15 lines): load the 8 scenario YAMLs via `scenario.ParseYAML`, collect every `step.DetectionProfiles` entry across all 8 files into a set, and assert that set is exactly `RansomwareRelevantProfiles` (as a set — order-independent). This test fails the moment a scenario author adds or removes a `detection_profiles:` reference without updating this list, the same drift-prevention role `TestRealCorpus_EveryTechniqueTaggedStepIsAccountedFor` already plays for technique coverage.

## C. `internal/rwresponse` — the effectiveness join

A new package, pure Go, no DB/HTTP import — same discipline as `dxcorrelate`. Consumes `db.RWAttemptRow` (sub-project #5's Task 4 output) directly; the API-layer adapter that calls `db.RWCapabilityAttempts` is the only place that touches the database.

```go
package rwresponse

import (
	"sort"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
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

// ResponseLatencyStatus is always NotEstablishable today (design spec
// section A): internal/actions' action_requests table carries no
// technique_id or action column, so no causal link between a detection
// event and the containment action that answered it exists in this
// codebase. This is a distinct type, not a *time.Duration left nil, so a
// caller cannot mistake "not establishable" for "zero latency" -- the same
// reasoning dxcorrelate.BehaviorStatus applies to BehaviorOccurred vs
// BehaviorNotEstablished.
type ResponseLatencyStatus string

const ResponseLatencyNotEstablishable ResponseLatencyStatus = "not_establishable"

const responseLatencyNotEstablishableReason = "no causal link between a detection event and a specific containment action exists in this codebase today (action_requests carries run_id only, not technique_id/action)"

// DetectionLatencyEvidence is one technique's measured detection latency,
// supplied by a caller that has resolved a detectverify.VerifyResult (via
// rwdetect) -- BuildEffectivenessReport performs no detectverify call
// itself. Keyed by TechniqueID+Action, matching rwevidence.AttemptKey's own
// identity. Absent from the real dispatch path today: nothing in this
// sub-project wires a real detectverify.Connector call, so every real run
// supplies an empty slice and every EffectivenessRow.DetectionLatency comes
// back nil.
type DetectionLatencyEvidence struct {
	TechniqueID string
	Action      string
	Latency     time.Duration
}

// EffectivenessRow is one technique's Detection/Containment/Recovery
// evidence side by side, plus latency context. Prevention and
// DataProtection rows are deliberately never read by this package --
// distinguishing prevention, detection, containment and recovery (the
// roadmap's own exit criterion for this phase) means keeping each
// dimension's independent verdict legible, not collapsing five
// capabilities into one join.
type EffectivenessRow struct {
	TechniqueID           string
	Detection              *DimensionEvidence
	Containment            *DimensionEvidence
	Recovery               *DimensionEvidence
	DetectionLatency       *time.Duration
	ResponseLatency        ResponseLatencyStatus
	ResponseLatencyReason  string
}

// EffectivenessReport is the full join for one run. Rows is empty (never
// nil) when the run has no Detection/Containment/Recovery evidence for any
// technique rwevidence models -- not an error, the same "zero relevant
// evidence is not an error" precedent dxcorrelate's handler established.
type EffectivenessReport struct {
	Rows []EffectivenessRow
}

// BuildEffectivenessReport groups rows by TechniqueID, selects each
// technique's earliest row per capability in {detection, containment,
// recovery} (deterministic -- ties and input-slice reordering never change
// the result, mirroring dxcorrelate.selectLegEvidence's own earliest-wins
// rule), and attaches latency evidence by (TechniqueID, Action) when
// latencies supplies a match. Output rows are sorted by TechniqueID for
// deterministic ordering.
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

		row := EffectivenessRow{
			TechniqueID:           id,
			Detection:              detection,
			Containment:            containment,
			Recovery:               recovery,
			ResponseLatency:        ResponseLatencyNotEstablishable,
			ResponseLatencyReason:  responseLatencyNotEstablishableReason,
		}
		if detection != nil {
			if lat, ok := latencyByKey[id+"/"+detection.Action]; ok {
				row.DetectionLatency = &lat
			}
		}
		out = append(out, row)
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

## D. API layer

Mirrors `dxcorrelate`'s handler shape exactly (`internal/api/dxcorrelate_handlers.go`): a new `internal/api/rwresponse_handlers.go`, camelCase JSON, one adapter function, one handler, one route, one RBAC matrix entry.

- `toDetectionLatencyEvidence` (or simply an empty slice literal, since nothing in this sub-project produces real latency evidence yet) is passed as `BuildEffectivenessReport`'s second argument — the handler calls `db.RWCapabilityAttempts(ctx, h.db, runID)` then `rwresponse.BuildEffectivenessReport(rows, nil)`.
- JSON shape: `{"rows": [{"techniqueId": "...", "detection": {...}|null, "containment": {...}|null, "recovery": {...}|null, "detectionLatencyMs": <int>|null, "responseLatency": "not_establishable", "responseLatencyReason": "..."}]}`. Each dimension's JSON object carries `verdict`, `skipReason` (omitted when empty), `reason`, `action`, `createdAt`.
- Route: `GET /api/scenarios/runs/{runId}/detection-response-effectiveness`, inserted next to `rw-score`/`double-extortion-correlation`, `tierAny` (read-only, same as every other run-evidence GET in this initiative).
- RBAC matrix: one new entry, same tier.
- A run with zero Detection/Containment/Recovery rows returns `200 {"rows": []}`, not an error — same precedent as `dxcorrelate`'s `GetDoubleExtortionCorrelation`.

## E. Testing strategy

- **`rwdetect`**: pure unit tests, no I/O, no fakes needed (there's nothing to fake — these are converters). Cases: `VerifyRequestFor` with a populated `Technique` (ok=true, fields mapped 1:1) and with `MitreID==""` (ok=false, matching `addetect`'s own test shape). `DetectionLookupResultFor` with `VerdictDetected` (tested=true, verified=true, reason mentions alert count) and `VerdictNotDetected` (tested=true, verified=false, reason is the fixed no-match string).
- **Profile inventory**: `TestRansomwareRelevantProfiles_MatchesRealCorpus` as described in B.1.
- **`rwresponse`**: mirrors `dxcorrelate`'s test shape closely.
  - A technique with Detection+Containment+Recovery rows all present → all three `DimensionEvidence` populated, correct `Verdict`/`Reason` values carried through unchanged.
  - A technique with only Containment+Recovery (no Detection row) → `Detection` is nil, not a zero-value struct — the nil-vs-present-SKIPPED distinction has a dedicated test.
  - Prevention and DataProtection rows for the same technique are never read — a dedicated test seeds both alongside Detection/Containment/Recovery rows and asserts the output ignores them (mirrors `dxcorrelate`'s "T1486 Prevention/Detection/Containment never translated" guard test).
  - Duplicate rows for the same (technique, capability) pair → deterministic earliest-wins, and order-independence (same two-variant test shape as `dxcorrelate`'s duplicate test).
  - `ResponseLatency` is `NotEstablishable` on every row, unconditionally — a test asserts this holds even when `DetectionLatency` is present, proving the two are genuinely independent fields.
  - `DetectionLatency` is nil when `latencies` is empty or has no matching `(TechniqueID, Action)` key, and populated correctly when a match exists.
  - Zero input rows → `EffectivenessReport{Rows: []EffectivenessRow{}}` (empty slice, not nil, not an error).
  - An end-to-end-shaped test (mirrors sub-project #5's Clop test): seed real `rwevidence.EvaluateStep` + `db.WriteRWCapabilityResults` results for T1490 (Containment-relevant) and T1486 (Recovery-relevant) under one run, read them back via `db.RWCapabilityAttempts`, and assert `BuildEffectivenessReport` produces two rows with the right dimensions populated and `ResponseLatency` honestly `NotEstablishable` throughout.
- **API layer**: adapter test (empty-latencies wiring), the zero-evidence-returns-200 test, and the end-to-end test wired through the real HTTP handler (same shape as `dxcorrelate_handlers_test.go`'s pair of tests), plus the RBAC matrix drift/boundary tests.
- **Full regression**: `go test ./internal/rwdetect/ ./internal/rwresponse/ ./internal/db/ ./internal/api/ -timeout 25m` as the terminal verification task, run alone (not concurrently with any other heavy test suite on this host — the memory-pressure incident during sub-project #5 established why).

## F. Explicitly deferred (not in this spec)

- Real `detectverify.Connector` wiring into `rwevidence.StepDependencies.Detection` — Track I, lab-gated, same category as T1 (real Recovery observer) and T2 (real Prevention/Detection observer).
- Modeling the other 11 unmapped technique IDs across all 5 `rwevidence` capabilities — a separate, later sub-project with its own applicability judgment calls per technique.
- A real causal link between a detection event and the containment action that answered it (would require either a schema change to the already-feature-complete `action_requests` table, or a different correlation mechanism entirely) — response latency stays `NotEstablishable` until that separate design exists.
- The "low-and-slow composite attack sequence" scenario content named in §2.5's narrative — content-authoring work for sub-project #10 or its own pass, not engineering.
