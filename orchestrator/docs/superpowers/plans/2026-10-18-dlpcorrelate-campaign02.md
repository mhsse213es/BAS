# dlpcorrelate Campaign 02 (Channel Consistency) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second aggregate shape to `internal/dlpcorrelate` — channel consistency, not ordered chain — and Campaign 02's concrete worked example.

**Architecture:** One new file, `channelconsistency.go`, in the existing `internal/dlpcorrelate` package (no new package — same "campaign correlation" umbrella `dlp.txt` §3C itself uses for all 6 campaigns). `EvaluateChannelConsistency` takes N already-computed `reporting.ComparisonResult` values (one per channel) and classifies the set into one of 4 named verdicts. `Campaign02EndpointToCloudLeakage` is a 3-parameter concrete wrapper naming exactly the 3 channel variants `dlp.txt` names.

**Tech Stack:** Go stdlib only; `internal/reporting` for the `ComparisonResult` type only (no behavioral coupling, same discipline as `campaign01.go`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlpcorrelate-campaign02-design.md`.

## Global Constraints

- `EvaluateChannelConsistency` must never import or call anything from `internal/reporting` beyond the `ComparisonResult` type itself — no `Verify`/`dlpVerifier` call, matching `campaign01.go`'s own decoupling.
- The 4 verdicts (`ConsistentEnforcement`/`ConsistentFailure`/`InconsistentEnforcement`/`InsufficientEvidence`) are mutually exclusive and exhaustive over the function's own classification logic — every call produces exactly one.
- An empty `results` slice is an error, not a verdict — there is nothing to assess consistency over.
- `ChannelConsistencyResult.ChannelResults` must always include every input `ChannelResult` unchanged (consistency classification never discards or rewrites a caller-supplied result).

## Review Focus

- All-`MissingEvidence` input (zero `Match`, zero `Mismatch`) must resolve to `InsufficientEvidence`, never `ConsistentEnforcement` — defaulting an absence of evidence to "looks fine" would be a false safety claim, the exact anti-goal the spec names.
- A mix of exactly one `Match` and one `Mismatch` among 3 channels (the third `MissingEvidence`) must resolve to `InconsistentEnforcement`, with the reason text naming how many of the *informative* (Match+Mismatch) channels disagreed — not silently averaging against the inconclusive third channel.
- All-`Mismatch` input must resolve to `ConsistentFailure`, a DIFFERENT verdict from `InconsistentEnforcement` — a reasonable person reading "channel consistency" should expect "every channel uniformly fails" to be flagged as its own distinct, serious finding (a global policy gap), not silently merged with "channels disagree with each other" (a narrower, channel-specific gap) or with "looks consistent" (which it is not, in the safe sense).
- `Campaign02EndpointToCloudLeakage`'s 3 named parameters (usb, browserUpload, cloudTransfer) must each retain their own `Channel` label in the returned `ChannelResults` — a caller reading the result must be able to tell WHICH channel was inconsistent, not just that 1-of-3 disagreed.
- `EvaluateChannelConsistency` with a single-element input (e.g. only USB tested, browser/cloud not yet run) must not error and must not claim `InconsistentEnforcement` (nothing to disagree with) — it resolves to whichever of `ConsistentEnforcement`/`ConsistentFailure`/`InsufficientEvidence` that one result's own comparison implies.

---

### Task 1: Channel consistency core + Campaign 02

**Files:**
- Create: `orchestrator/internal/dlpcorrelate/channelconsistency.go`
- Test: `orchestrator/internal/dlpcorrelate/channelconsistency_test.go`

**Interfaces:**
- Consumes: `reporting.ComparisonResult` (`Match`/`Mismatch`/`MissingEvidence`/`NotApplicable`/`Unknown`) — already defined in `internal/reporting/outcome.go`, read-only type usage.
- Produces: `ConsistencyVerdict` (+4 constants), `ChannelResult{Channel, Comparison, Reason}`, `ChannelConsistencyResult{ChannelResults []ChannelResult, Verdict ConsistencyVerdict, Reason string}`, `EvaluateChannelConsistency(results []ChannelResult) (ChannelConsistencyResult, error)`, `Campaign02EndpointToCloudLeakage(usb, browserUpload, cloudTransfer ChannelResult) (ChannelConsistencyResult, error)` — terminal, nothing else in this plan consumes these.

- [ ] **Step 1: Write the failing tests**

```go
package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateChannelConsistency_AllMatch_ConsistentEnforcement(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Match},
		{Channel: "browser-upload", Comparison: reporting.Match},
		{Channel: "approved-cloud-transfer", Comparison: reporting.Match},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != ConsistentEnforcement {
		t.Errorf("Verdict = %v, want ConsistentEnforcement", got.Verdict)
	}
	if len(got.ChannelResults) != 3 {
		t.Fatalf("ChannelResults len = %d, want 3", len(got.ChannelResults))
	}
}

func TestEvaluateChannelConsistency_AllMismatch_ConsistentFailure(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Mismatch},
		{Channel: "browser-upload", Comparison: reporting.Mismatch},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != ConsistentFailure {
		t.Errorf("Verdict = %v, want ConsistentFailure (uniform gap, distinct from InconsistentEnforcement)", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_MixedWithOneInconclusive_InconsistentEnforcement(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Match},
		{Channel: "browser-upload", Comparison: reporting.Mismatch},
		{Channel: "approved-cloud-transfer", Comparison: reporting.MissingEvidence},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != InconsistentEnforcement {
		t.Errorf("Verdict = %v, want InconsistentEnforcement", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_AllMissingEvidence_InsufficientEvidence(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.MissingEvidence},
		{Channel: "browser-upload", Comparison: reporting.MissingEvidence},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != InsufficientEvidence {
		t.Errorf("Verdict = %v, want InsufficientEvidence -- must never default an absence of evidence to looking consistent", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_SingleResult_NeverInconsistent(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Match},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict == InconsistentEnforcement {
		t.Error("a single channel result has nothing to disagree with -- must not be InconsistentEnforcement")
	}
	if got.Verdict != ConsistentEnforcement {
		t.Errorf("Verdict = %v, want ConsistentEnforcement for a single Match", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_EmptyInput_IsError(t *testing.T) {
	_, err := EvaluateChannelConsistency(nil)
	if err == nil {
		t.Error("expected an error for an empty results slice -- nothing to assess consistency over")
	}
}

func TestCampaign02EndpointToCloudLeakage_PreservesChannelLabels(t *testing.T) {
	usb := ChannelResult{Channel: "usb", Comparison: reporting.Match}
	browserUpload := ChannelResult{Channel: "browser-upload", Comparison: reporting.Mismatch}
	cloudTransfer := ChannelResult{Channel: "approved-cloud-transfer", Comparison: reporting.Match}

	got, err := Campaign02EndpointToCloudLeakage(usb, browserUpload, cloudTransfer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != InconsistentEnforcement {
		t.Errorf("Verdict = %v, want InconsistentEnforcement", got.Verdict)
	}
	foundBrowserMismatch := false
	for _, r := range got.ChannelResults {
		if r.Channel == "browser-upload" && r.Comparison == reporting.Mismatch {
			foundBrowserMismatch = true
		}
	}
	if !foundBrowserMismatch {
		t.Error("ChannelResults must preserve each input's own Channel label so a caller can tell which channel disagreed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -run "TestEvaluateChannelConsistency|TestCampaign02" -v`
Expected: FAIL (`undefined: ChannelResult`, `undefined: EvaluateChannelConsistency`, etc. — build failure)

- [ ] **Step 3: Implement**

`channelconsistency.go`: `ConsistencyVerdict` string type + 4 constants (`ConsistentEnforcement`/`ConsistentFailure`/`InconsistentEnforcement`/`InsufficientEvidence`); `ChannelResult{Channel string, Comparison reporting.ComparisonResult, Reason string}`; `ChannelConsistencyResult{ChannelResults []ChannelResult, Verdict ConsistencyVerdict, Reason string}`.

`EvaluateChannelConsistency(results []ChannelResult) (ChannelConsistencyResult, error)`: error if `len(results) == 0`. Count `matchCount`/`mismatchCount` by scanning `results` for `reporting.Match`/`reporting.Mismatch` (everything else, including `MissingEvidence`/`NotApplicable`/`Unknown`, is non-informative and only contributes to the result list, never to the counts). Classify: both counts > 0 → `InconsistentEnforcement`; only `matchCount` > 0 → `ConsistentEnforcement`; only `mismatchCount` > 0 → `ConsistentFailure`; both zero → `InsufficientEvidence`. `Reason` is a `fmt.Sprintf` naming the counts for the first 3 cases, and explaining the absence of informative evidence for the 4th. Copy `results` into `ChannelConsistencyResult.ChannelResults` unchanged.

`Campaign02EndpointToCloudLeakage(usb, browserUpload, cloudTransfer ChannelResult) (ChannelConsistencyResult, error)`: calls `EvaluateChannelConsistency([]ChannelResult{usb, browserUpload, cloudTransfer})` and returns its result directly — the function's only job is to give the 3-channel shape a name matching `dlp.txt`'s own Campaign 02 text, documented in its doc comment (cite the exact channel trio and the "telemetry comparison not yet closed" gap per the spec's Non-goals).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: PASS (all tests, this task's 7 plus every pre-existing test in the package)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/dlpcorrelate/`, `go vet github.com/audspect/bas/internal/dlpcorrelate/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two, clean build from the third

- [ ] **Step 6: Commit**

```bash
git status --porcelain
git add orchestrator/internal/dlpcorrelate/channelconsistency.go orchestrator/internal/dlpcorrelate/channelconsistency_test.go
git commit -m "feat(dlpcorrelate): add channel-consistency aggregate and Campaign 02"
```

(run `git status --porcelain` BEFORE and AFTER the `git add` to confirm no other file in the package was modified and left uncommitted — see the prior slice's own caught defect: a `chain.go` fix left out of its commit while tests still passed against the dirty tree.)

---

## Self-Review Notes

- **Spec coverage:** Goal 1 (generic channel-consistency aggregate) → Task 1's `channelconsistency.go` core. Goal 2 (Campaign 02 concrete wrapper) → Task 1's `Campaign02EndpointToCloudLeakage`. Goal 3 (decoupling from real evaluators) → Task 1's implementation note (never imports beyond the `ComparisonResult` type).
- **Step scan:** classification logic is described by its exact branching rule, not transcribed, since the 7 tests above already pin every branch's expected output.
- **Type consistency:** `ChannelResult`'s field names (`Channel`/`Comparison`/`Reason`) match across the test fixtures, the Interfaces block, and the Step 3 implementation notes.
- **Review Focus:** all 5 items have a named test above (all-MissingEvidence → InsufficientEvidence not ConsistentEnforcement; mixed-with-one-inconclusive → InconsistentEnforcement; all-Mismatch → ConsistentFailure as a distinct verdict; Campaign 02's channel-label preservation; single-result → never InconsistentEnforcement).
- **Proportion check:** 1 task, smaller than Campaign 01's 2 tasks — proportionate, since this adds one new aggregate shape plus one concrete wrapper, reusing the existing package and existing `reporting.ComparisonResult` type with no new external dependency.
- **Anti-goal check:** no `CorrelationChain`/`EvaluateCorrelationChain` call anywhere in `channelconsistency.go` — confirmed a structurally separate aggregate, not a workaround of the ordered-chain model.
