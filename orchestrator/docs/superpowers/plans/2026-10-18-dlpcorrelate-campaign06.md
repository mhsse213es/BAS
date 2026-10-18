# dlpcorrelate Campaign 06 (Business Continuity vs. Data Protection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Campaign 06's concrete worked example, reusing Campaign 03's existing `ScenarioCase`/`EvaluateScenarioDifferentiation` core unchanged, generalized to variable-length legitimate/prohibited slices with a new bucket-consistency validation.

**Architecture:** One new file, `campaign06.go`, in the existing `internal/dlpcorrelate` package. No new aggregate type.

**Tech Stack:** Go stdlib only.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlpcorrelate-campaign06-design.md`.

## Global Constraints

- `campaign06.go` must not redefine any part of `EvaluateScenarioDifferentiation`'s classification switch — it validates inputs, concatenates, and delegates.
- A case in `legitimate` with `ExpectedToSucceed: false`, or a case in `prohibited` with `ExpectedToSucceed: true`, must produce an error naming that case's `Label` — never silently pass through.

## Review Focus

- The bucket-consistency check must run and fail BEFORE any call to `EvaluateScenarioDifferentiation` — a plausible-but-wrong implementation could validate after concatenation and accidentally report a validation failure as a `DifferentiationInsufficientEvidence`-shaped result instead of a genuine Go error.
- A single non-empty bucket (e.g. `legitimate` populated, `prohibited` empty) must still produce a valid result via the existing `EvaluateScenarioDifferentiation` — must not add new empty-bucket-specific error handling that duplicates or diverges from that function's own existing empty-input behavior (only a FULLY empty concatenation errors).
- The concatenation order (`legitimate` cases first, then `prohibited`) must be deterministic and must not silently drop or duplicate any case — verify `len(result.Cases) == len(legitimate) + len(prohibited)` on a success path.

---

### Task 1: Campaign 06

**Files:**
- Create: `orchestrator/internal/dlpcorrelate/campaign06.go`
- Test: `orchestrator/internal/dlpcorrelate/campaign06_test.go`

**Interfaces:**
- Consumes: `ScenarioCase`/`DifferentiationVerdict`/`ScenarioDifferentiationResult`/`EvaluateScenarioDifferentiation` (from `scenariodifferentiation.go`, same package).
- Produces: `Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited []ScenarioCase) (ScenarioDifferentiationResult, error)` — terminal.

- [ ] **Step 1: Write the failing tests**

```go
package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

func TestCampaign06BusinessContinuityVersusDataProtection_AllCorrect_DifferentiatesCorrectly(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "finance shares quarterly report via approved SharePoint link", ExpectedToSucceed: true, Comparison: reporting.Match, Reason: "allowed as expected"},
	}
	prohibited := []ScenarioCase{
		{Label: "unauthorized bulk export to personal email", ExpectedToSucceed: false, Comparison: reporting.Match, Reason: "blocked as expected"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
	if len(got.Cases) != 2 {
		t.Errorf("len(Cases) = %d, want 2", len(got.Cases))
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_LegitimateCaseBlocked_OverBlocking(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "HR shares offer letter via approved vendor portal", ExpectedToSucceed: true, Comparison: reporting.Mismatch, Reason: "wrongly blocked"},
	}
	prohibited := []ScenarioCase{
		{Label: "unauthorized bulk export to personal email", ExpectedToSucceed: false, Comparison: reporting.Match, Reason: "blocked as expected"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != OverBlocking {
		t.Errorf("Verdict = %v, want OverBlocking", got.Verdict)
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_ProhibitedCaseGotThrough_UnderBlocking(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "finance shares quarterly report via approved SharePoint link", ExpectedToSucceed: true, Comparison: reporting.Match, Reason: "allowed as expected"},
	}
	prohibited := []ScenarioCase{
		{Label: "unauthorized bulk export to personal email", ExpectedToSucceed: false, Comparison: reporting.Mismatch, Reason: "wrongly allowed through"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != UnderBlocking {
		t.Errorf("Verdict = %v, want UnderBlocking", got.Verdict)
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_LegitimateCaseFlaggedProhibited_IsError(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "mislabeled case", ExpectedToSucceed: false, Comparison: reporting.Match},
	}
	_, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, nil)
	if err == nil {
		t.Fatal("expected an error for a legitimate-bucket case with ExpectedToSucceed=false, got nil")
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_ProhibitedCaseFlaggedLegitimate_IsError(t *testing.T) {
	prohibited := []ScenarioCase{
		{Label: "mislabeled case", ExpectedToSucceed: true, Comparison: reporting.Match},
	}
	_, err := Campaign06BusinessContinuityVersusDataProtection(nil, prohibited)
	if err == nil {
		t.Fatal("expected an error for a prohibited-bucket case with ExpectedToSucceed=true, got nil")
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_OneBucketEmpty_StillEvaluates(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "finance shares quarterly report via approved SharePoint link", ExpectedToSucceed: true, Comparison: reporting.Match, Reason: "allowed as expected"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_BothBucketsEmpty_IsError(t *testing.T) {
	_, err := Campaign06BusinessContinuityVersusDataProtection(nil, nil)
	if err == nil {
		t.Fatal("expected an error for both buckets empty, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -run "TestCampaign06" -v`
Expected: FAIL (`undefined: Campaign06BusinessContinuityVersusDataProtection` — build failure)

- [ ] **Step 3: Implement**

`campaign06.go`: `Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited []ScenarioCase) (ScenarioDifferentiationResult, error)`. For each case in `legitimate`, if `!c.ExpectedToSucceed`, return an error naming `c.Label`. For each case in `prohibited`, if `c.ExpectedToSucceed`, return an error naming `c.Label`. Concatenate `legitimate` then `prohibited` into one `[]ScenarioCase`, call `EvaluateScenarioDifferentiation` on it, return its result/error directly (no further wrapping).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlpcorrelate/... -v`
Expected: PASS (all tests in the package, including Campaigns 01-04's pre-existing ones)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/dlpcorrelate/campaign06.go orchestrator/internal/dlpcorrelate/campaign06_test.go`, `go vet github.com/audspect/bas/internal/dlpcorrelate/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two, clean build from the third

- [ ] **Step 6: Commit**

```bash
git status --porcelain
git add orchestrator/internal/dlpcorrelate/campaign06.go orchestrator/internal/dlpcorrelate/campaign06_test.go
git commit -m "feat(dlpcorrelate): add Campaign 06 (business continuity vs. data protection)"
```

(run `git status --porcelain` BEFORE and AFTER `git add` to confirm no other file was left uncommitted.)

---

## Self-Review Notes

- **Spec coverage:** Goal 1 (slice-based wrapper with bucket validation) → Step 3.
- **Step scan:** implementation described by its exact validate-then-delegate structure; the tests above pin every branch (correct-differentiation, over-blocking, under-blocking, 2 validation-error cases, 1 single-bucket case, 1 both-empty case).
- **Type consistency:** `ScenarioCase`/`DifferentiationVerdict` (`DifferentiatesCorrectly`/`OverBlocking`/`UnderBlocking`) names match `scenariodifferentiation.go` exactly — no new identifiers introduced for existing concepts.
- **Review Focus:** all 3 items have a named test above (validation runs before delegation — confirmed by the 2 error-case tests returning an error rather than a result; single-bucket-still-evaluates; case-count preservation via `len(got.Cases) != 2` in the first test).
- **Proportion check:** 1 task, comparable in size to Campaign 04's — proportionate, since this slice adds zero new aggregate logic, only a new validate-and-delegate wrapper reusing 100% of Campaign 03's existing machinery.
- **Anti-goal check:** no duplicate classification logic anywhere in `campaign06.go`; bucket-consistency violations surface as Go errors, never folded into a fabricated verdict.
