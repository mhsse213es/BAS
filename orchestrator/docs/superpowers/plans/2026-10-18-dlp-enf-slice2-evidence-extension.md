# DLP-ENF Slice 2 (Live Evidence Pipeline Extension) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the live, scenario-integrated enforcement evaluator (`internal/reporting/dlp.go`) with three additive evidence dimensions — channel type, override/justification record, and endpoint connectivity/policy-sync state — without touching `dlpComparator`'s Allow/Block logic or any existing field.

**Architecture:** Two-layer additive threading, innermost-out: (1) `internal/reporting`'s own types (`OverrideEvidence`, `ConnectivityEvidence`, new `DLPEvidence`/`StepEvidence` fields) and the `dlpVerifier`/`limitationsFor` wiring that populates `DLPEvidence` from `StepEvidence`; (2) `internal/models.SimulationResult`'s new flat fields and `evidenceByTechnique`'s passthrough into `StepEvidence`. `models` cannot import `internal/reporting` (reporting already imports models, not the reverse), so `SimulationResult` carries flat primitive fields, and `internal/reporting` is the only place that assembles them into the structured `OverrideEvidence`/`ConnectivityEvidence` types.

**Tech Stack:** Go stdlib only; no new external dependency.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-enf-design.md`, "Part A: extend the live evidence pipeline" section. That section fixes `OverrideEvidence`/`ConnectivityEvidence`'s exact shape and the `DLPEvidence` additions; it explicitly leaves the `SimulationResult`-side field names and the "nil vs. populated" rule to this plan.

## Global Constraints

- `dlpComparator.Compare` and `dlpVerifier.Verify`'s existing Allow/Block/MissingEvidence logic are unchanged — every existing `dlp_test.go` test must still pass unmodified.
- Every new field on `DLPEvidence`, `StepEvidence`, and `models.SimulationResult` is additive: `omitempty` JSON tags where the struct already uses JSON tags (`SimulationResult`); no existing field renamed, removed, or retyped.
- `OverrideEvidence`'s name is deliberately close to this file's own pre-existing, unrelated `applyOverride`/`StoredVerification` (an analyst's manual review-workflow override of a verdict — see `detection_validation.go:208-234`). `OverrideEvidence`'s doc comment must explicitly distinguish the two: `OverrideEvidence` is about an end-user's DLP-policy override (e.g. "override and send anyway"), never about a reviewer overriding this tool's own verdict.
- `DLPEvidence.Override` is `nil` unless at least one override-related signal is present on the source `StepEvidence` (occurred, or a non-empty reason/authorizer/audit-record-ID) — never a non-nil struct of all zero values, which would misrepresent "no override evidence" as "an override that we know nothing about."
- `DLPEvidence.Connectivity` is `nil` unless at least one connectivity-related signal is present (a non-nil `Online`, a non-empty policy version, or a non-zero `LastSyncedAt`) — same reasoning.
- `Channel` is a plain string (not a pointer) — empty string already means "unknown," consistent with `dlpclassify.ClassificationEvidence.Channel`'s own precedent.
- `models.SimulationResult` gets flat fields (no new nested struct type in `internal/models`) — matching that struct's existing style (`VetoedActionKey`/`VetoedExecutionClass`/`VetoedBlockSource` are flat strings, not a nested struct).

## Review Focus

- `DLPEvidence.Override`/`Connectivity` must be `nil`, not a populated-with-zero-values struct, whenever the source evidence carries no actual signal for that dimension — a report consumer must be able to treat `nil` as "we have nothing to say," not parse zero values to infer the same thing.
- `evidenceByTechnique`'s existing per-technique dedup (keeps whichever step fired a detection, drops the other step's data) must still apply to the 3 new fields — a test must prove a non-detected sibling step's channel/override/connectivity data is correctly dropped on dedup, not silently kept.
- `limitationsFor`'s new offline caveat must only fire when `Connectivity.Online` is explicitly `false` (a `*bool` pointing to `false`) — never when `Connectivity` is `nil` or `Online` is `nil` (meaning connectivity state is simply unknown, which is a different, unremarked case).
- The offline caveat must be additive to the existing `limitationsFor` switch — every existing `dlp_test.go` limitations-text assertion must still produce its original text when no connectivity evidence is present at all.
- `Channel` passing through `evidenceByTechnique` unchanged (not reset, not defaulted) when a `SimulationResult`'s `Channel` field is empty — empty must stay empty, never silently become a non-empty default.

---

### Task 1: `OverrideEvidence`/`ConnectivityEvidence` types, `DLPEvidence`/`StepEvidence` fields, and `dlpVerifier` wiring

**Files:**
- Modify: `orchestrator/internal/reporting/dlp.go`
- Modify: `orchestrator/internal/reporting/detection_validation.go` (`StepEvidence` struct only — not `evidenceByTechnique`, that's Task 2)
- Test: `orchestrator/internal/reporting/dlp_test.go` (add to existing file)

**Interfaces:**
- Consumes: nothing new — operates entirely within `internal/reporting`, using `StepEvidence`'s pre-existing fields plus the new ones this task itself adds.
- Produces: `OverrideEvidence`, `ConnectivityEvidence` (both in `dlp.go`), `DLPEvidence.Channel`/`.Override`/`.Connectivity`, `StepEvidence.Channel string` / `.OverrideOccurred bool` / `.OverrideAuthorizedBy string` / `.OverrideReason string` / `.OverrideAuditRecordID string` / `.ConnectivityOnline *bool` / `.ConnectivityPolicyVersion string` / `.ConnectivityLastSyncedAt time.Time` — consumed by Task 2's `evidenceByTechnique` wiring (exact names must match).

```go
// dlp.go additions -- exactly per the spec's Part A code block
// (OverrideEvidence, ConnectivityEvidence, DLPEvidence's 3 new fields),
// plus the dlpVerifier.Verify wiring that builds Override/Connectivity
// from StepEvidence's new flat fields using the nil-unless-signal rule,
// and limitationsFor's new offline-caveat branch.
```

`dlpVerifier.Verify` (in `dlp.go`) builds the new `DLPEvidence` fields right alongside its existing `FixtureID`/`Limitations` construction:

- `DLPEvidence.Channel = ev.Channel` (direct passthrough, always).
- `DLPEvidence.Override`: `nil` unless `ev.OverrideOccurred || ev.OverrideAuthorizedBy != "" || ev.OverrideReason != "" || ev.OverrideAuditRecordID != ""`; when any is true, populate all 4 corresponding `OverrideEvidence` fields from `ev`'s.
- `DLPEvidence.Connectivity`: `nil` unless `ev.ConnectivityOnline != nil || ev.ConnectivityPolicyVersion != "" || !ev.ConnectivityLastSyncedAt.IsZero()`; when any is true, populate all 3 corresponding `ConnectivityEvidence` fields from `ev`'s.

`limitationsFor`'s signature grows one parameter: `limitationsFor(expected, observed string, comparison ComparisonResult, wasSkip bool, connectivity *ConnectivityEvidence) string`. At the top of the function (before the existing `switch comparison` — applies regardless of `Match`/`Mismatch`/`MissingEvidence`), if `connectivity != nil && connectivity.Online != nil && !*connectivity.Online`, build the existing switch's result exactly as today, then append `" The endpoint was offline at observation time."` to it before returning. All 4 call sites of `limitationsFor` inside `dlp.go` pass the new parameter.

- [ ] **Step 1: Write the failing tests**

Add to `dlp_test.go` (package-internal, same file's existing helpers like `boolPtr` are reused):

```go
func TestDLPEvidence_ChannelPassesThroughDirectly(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked", Channel: "browser"})
	if r.DLPEvidence.Channel != "browser" {
		t.Errorf("Channel = %q, want %q", r.DLPEvidence.Channel, "browser")
	}
}

func TestDLPEvidence_ChannelEmptyStaysEmpty(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.DLPEvidence.Channel != "" {
		t.Errorf("Channel = %q, want empty", r.DLPEvidence.Channel)
	}
}

func TestDLPEvidence_OverrideNilWhenNoSignal(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.DLPEvidence.Override != nil {
		t.Errorf("Override = %+v, want nil", r.DLPEvidence.Override)
	}
}

func TestDLPEvidence_OverridePopulatedWhenOccurred(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "DLP_OBSERVATION: OperationSucceeded",
		OverrideOccurred: true, OverrideAuthorizedBy: "jdoe", OverrideReason: "business need", OverrideAuditRecordID: "aud-1",
	})
	if r.DLPEvidence.Override == nil {
		t.Fatal("Override = nil, want populated")
	}
	if r.DLPEvidence.Override.Occurred != true || r.DLPEvidence.Override.AuthorizedBy != "jdoe" || r.DLPEvidence.Override.Reason != "business need" || r.DLPEvidence.Override.AuditRecordID != "aud-1" {
		t.Errorf("Override = %+v, fields don't match input", r.DLPEvidence.Override)
	}
}

func TestDLPEvidence_OverridePopulatedWhenOnlyReasonPresent(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked", OverrideReason: "attempted override, no audit record found"})
	if r.DLPEvidence.Override == nil {
		t.Fatal("Override = nil, want populated -- a non-empty Reason alone is a signal")
	}
}

func TestDLPEvidence_ConnectivityNilWhenNoSignal(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.DLPEvidence.Connectivity != nil {
		t.Errorf("Connectivity = %+v, want nil", r.DLPEvidence.Connectivity)
	}
}

func TestDLPEvidence_ConnectivityPopulatedWhenOnlineSet(t *testing.T) {
	exp := scenario.ExpectedDetection{ExpectedOutcome: "Block"}
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "DLP_OBSERVATION: OperationBlocked",
		ConnectivityOnline: boolPtr(false), ConnectivityPolicyVersion: "v12", ConnectivityLastSyncedAt: ts,
	})
	if r.DLPEvidence.Connectivity == nil {
		t.Fatal("Connectivity = nil, want populated")
	}
	if r.DLPEvidence.Connectivity.Online == nil || *r.DLPEvidence.Connectivity.Online != false {
		t.Errorf("Connectivity.Online = %v, want pointer to false", r.DLPEvidence.Connectivity.Online)
	}
	if r.DLPEvidence.Connectivity.EffectivePolicyVersion != "v12" || !r.DLPEvidence.Connectivity.LastSyncedAt.Equal(ts) {
		t.Errorf("Connectivity = %+v, fields don't match input", r.DLPEvidence.Connectivity)
	}
}

func TestLimitationsFor_OfflineCaveatAppendedWhenOffline(t *testing.T) {
	conn := &ConnectivityEvidence{Online: boolPtr(false)}
	got := limitationsFor("Block", ObservationBlocked, Match, false, conn)
	if !strings.Contains(got, "offline") {
		t.Errorf("limitationsFor result %q, want it to mention the endpoint was offline", got)
	}
}

func TestLimitationsFor_NoCaveatWhenConnectivityNil(t *testing.T) {
	got := limitationsFor("Block", ObservationBlocked, Match, false, nil)
	if strings.Contains(got, "offline") {
		t.Errorf("limitationsFor result %q, want no offline caveat when Connectivity is nil", got)
	}
}

func TestLimitationsFor_NoCaveatWhenOnlineUnknown(t *testing.T) {
	conn := &ConnectivityEvidence{} // Online is nil -- unknown, not offline
	got := limitationsFor("Block", ObservationBlocked, Match, false, conn)
	if strings.Contains(got, "offline") {
		t.Errorf("limitationsFor result %q, want no offline caveat when Online is nil (unknown)", got)
	}
}
```

`dlp_test.go` does not currently import `"time"` — add it (its existing imports are `encoding/json`, `strings`, `testing`, `models`, `scenario`; `boolPtr` already exists at line 100).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/reporting/... -run "TestDLPEvidence_|TestLimitationsFor_Offline|TestLimitationsFor_NoCaveat" -v`
Expected: FAIL (`undefined: ConnectivityEvidence`, `StepEvidence has no field Channel`, `not enough arguments in call to limitationsFor`, `undefined: time` until the import is added, etc. — plus every pre-existing call site of `limitationsFor` in `dlp.go` itself will fail to compile with the new signature until Step 3 updates them)

- [ ] **Step 3: Implement**

Add `OverrideEvidence`/`ConnectivityEvidence` and the 3 new `DLPEvidence` fields to `dlp.go`; add the 8 new fields to `StepEvidence` in `detection_validation.go`; update `dlpVerifier.Verify` to populate `Channel`/`Override`/`Connectivity` per the nil-unless-signal rule above; update `limitationsFor`'s signature and all 4 existing call sites inside `dlp.go`, adding the offline-caveat branch.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/reporting/... -v`
Expected: PASS (every pre-existing `internal/reporting` test, plus the new ones above)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/reporting/` and `go vet github.com/audspect/bas/internal/reporting/...`
Expected: no output from either (verify any `gofmt -l` hit with `gofmt -d` first — this worktree has a known CRLF/LF checkout artifact on files this task doesn't touch)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/reporting/dlp.go orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/dlp_test.go
git commit -m "feat(reporting): add channel/override/connectivity evidence to DLP enforcement evaluator"
```

---

### Task 2: `models.SimulationResult` fields and `evidenceByTechnique` passthrough

**Files:**
- Modify: `orchestrator/internal/models/schema.go` (`SimulationResult` struct)
- Modify: `orchestrator/internal/reporting/detection_validation.go` (`evidenceByTechnique` only)
- Test: `orchestrator/internal/reporting/detection_validation_test.go` (add to existing file)

**Interfaces:**
- Consumes: Task 1's `StepEvidence.Channel`/`.OverrideOccurred`/`.OverrideAuthorizedBy`/`.OverrideReason`/`.OverrideAuditRecordID`/`.ConnectivityOnline`/`.ConnectivityPolicyVersion`/`.ConnectivityLastSyncedAt` (exact field names must match Task 1's).
- Produces: `models.SimulationResult`'s 8 mirroring fields — terminal, no later task consumes these.

```go
// schema.go additions -- 8 new flat fields on SimulationResult, named
// and typed identically to StepEvidence's new fields (Task 1), with
// `json:"...,omitempty"` tags following this struct's existing
// camelCase convention (e.g. "channel", "overrideOccurred",
// "overrideAuthorizedBy", "overrideReason", "overrideAuditRecordId",
// "connectivityOnline", "connectivityPolicyVersion",
// "connectivityLastSyncedAt").
```

`evidenceByTechnique` (`detection_validation.go:648-675`) copies all 8 new fields from `r` (the `models.SimulationResult` being folded in) onto `ev` (the `StepEvidence` being built), in the same block as the existing `SinkTokenObserved`/`StepName` copies — same dedup rule applies unchanged (a field is only kept from whichever step "wins" the existing `DetectionVerdict == "detected"/"prevented"` collapse).

- [ ] **Step 1: Write the failing tests**

Add to `detection_validation_test.go`:

```go
func TestEvidenceByTechnique_PassesThroughChannelOverrideConnectivity(t *testing.T) {
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	results := []models.SimulationResult{{
		ID: "T1048", Channel: "sync-client",
		OverrideOccurred: true, OverrideAuthorizedBy: "jdoe", OverrideReason: "business need", OverrideAuditRecordID: "aud-1",
		ConnectivityOnline: boolPtr(false), ConnectivityPolicyVersion: "v12", ConnectivityLastSyncedAt: ts,
	}}
	got := evidenceByTechnique(results)
	ev, ok := got["T1048"]
	if !ok {
		t.Fatal("no evidence for T1048")
	}
	if ev.Channel != "sync-client" {
		t.Errorf("Channel = %q, want %q", ev.Channel, "sync-client")
	}
	if !ev.OverrideOccurred || ev.OverrideAuthorizedBy != "jdoe" || ev.OverrideReason != "business need" || ev.OverrideAuditRecordID != "aud-1" {
		t.Errorf("override fields did not pass through: %+v", ev)
	}
	if ev.ConnectivityOnline == nil || *ev.ConnectivityOnline != false || ev.ConnectivityPolicyVersion != "v12" || !ev.ConnectivityLastSyncedAt.Equal(ts) {
		t.Errorf("connectivity fields did not pass through: %+v", ev)
	}
}

func TestEvidenceByTechnique_DedupDropsNonWinningStepsNewFields(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "T1048", StepName: "step-a", Channel: "api", DetectionVerdict: ""},
		{ID: "T1048", StepName: "step-b", Channel: "browser", DetectionVerdict: "prevented"},
	}
	got := evidenceByTechnique(results)
	ev, ok := got["T1048"]
	if !ok {
		t.Fatal("no evidence for T1048")
	}
	if ev.Channel != "browser" {
		t.Errorf("Channel = %q, want %q (the detected/prevented step's own value) -- dedup must apply to the new fields exactly as it already does to StepName/SinkTokenObserved", ev.Channel, "browser")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/reporting/... -run "TestEvidenceByTechnique_PassesThrough|TestEvidenceByTechnique_DedupDrops" -v`
Expected: FAIL (`models.SimulationResult has no field Channel`, etc.)

- [ ] **Step 3: Implement**

Add the 8 fields to `SimulationResult`; update `evidenceByTechnique` to copy them.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/reporting/... -v` and `go test github.com/audspect/bas/internal/models/... -v`
Expected: PASS (every pre-existing test in both packages, plus the new ones above)

- [ ] **Step 5: `gofmt -l` and `go vet` both packages**

Run: `gofmt -l orchestrator/internal/models/ orchestrator/internal/reporting/` and `go vet github.com/audspect/bas/internal/models/... github.com/audspect/bas/internal/reporting/...`
Expected: no output from either (verify any `gofmt -l` hit with `gofmt -d` first)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/models/schema.go orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/detection_validation_test.go
git commit -m "feat(models,reporting): thread channel/override/connectivity through evidenceByTechnique"
```

---

## Self-Review Notes

- **Spec coverage:** every type/field Part A's code block pins (`OverrideEvidence`, `ConnectivityEvidence`, `DLPEvidence`'s 3 new fields) is in Task 1; the `evidenceByTechnique`/`SimulationResult` side the spec explicitly left open is pinned concretely in Task 2 (flat fields, exact names, the nil-unless-signal rule for the structured types built in Task 1).
- **Step scan / type consistency:** Task 2's `SimulationResult` field names match Task 1's `StepEvidence` field names exactly (`Channel`, `OverrideOccurred`, `OverrideAuthorizedBy`, `OverrideReason`, `OverrideAuditRecordID`, `ConnectivityOnline`, `ConnectivityPolicyVersion`, `ConnectivityLastSyncedAt`) — a straight 1:1 copy in `evidenceByTechnique`, no translation needed at that layer. `limitationsFor`'s new 5th parameter and all 4 call sites are named in Task 1 so the implementer doesn't discover a 4th call site mid-task and improvise its handling differently from the other 3.
- **Review Focus:** all 5 items each have a named test above (nil-vs-populated for both `Override` and `Connectivity`, the dedup-still-applies test, the offline-caveat-only-when-explicitly-false test including the `Online == nil` "unknown" case, and `Channel`'s empty-stays-empty test).
- **Proportion check:** 2 tasks, matching DLP-CLS Slice 1's 3-task size for a comparably larger surface (2 files + 2 test files vs. this slice's 3 files + 2 test files) — proportionate, split at the real seam (`internal/reporting`-only vs. `internal/models`+`evidenceByTechnique`).
- **Anti-goal check:** neither task adds a new comparator, a new outcome catalog family, or any Verify-order branch to `dlpVerifier.Verify` itself — both tasks are pure evidence threading, consistent with the spec's "no new Verify logic" framing. The `Challenge`/`Approval` outcome-catalog question the spec flagged as non-blocking is deliberately left untouched by this plan — it's a separate, optional follow-up, not bundled in here.
