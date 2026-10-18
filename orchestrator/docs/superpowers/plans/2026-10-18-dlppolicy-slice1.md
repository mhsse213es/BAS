# dlppolicy Slice 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/dlppolicy`'s foundation types and its single-rule, single-scope policy-configuration check (`DLPPolicyRuleExpectation` / `VerifyDLPPolicyRuleExpectation`) — Slice 1 of the DLP-POL design, covering scope/exclusions, audit-vs-enforce mode, disabled/expired/unpublished rules, single-scope exception state, and propagation/freshness.

**Architecture:** New, standalone package `internal/dlppolicy`, no import of `internal/emailgwefficacy`/`internal/webgwefficacy`/`internal/dlpfixture`/`internal/reporting`. Mirrors `internal/emailgwefficacy/policybaseline.go`'s proven shape exactly: a declared `Expectation`, a fixture-backed `EvidenceProvider` interface, a deterministic `Verify...(exp, provider, window, asOf) VerdictDetail` function.

**Tech Stack:** Go (stdlib only: `time`, `encoding/json` not needed in this slice since no `RawJSON` field exists yet).

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-pol-design.md` (read in full before implementing; this plan implements only its Slice 1 section — "Foundation types" and "Slice 1 — `DLPPolicyRuleExpectation`").

## Global Constraints

- No import of `internal/emailgwefficacy`, `internal/webgwefficacy`, `internal/dlpfixture`, or `internal/reporting` from this package.
- Every evidence record carries `Source EvidenceSource` and `Provenance Provenance`.
- `VerifyDLPPolicyRuleExpectation` takes `asOf time.Time` as an explicit parameter; never reads `time.Now()` internally.
- No evidence in the window → `VerdictInconclusive`, never a pass.
- Every fixture/test value is synthetic/lab-only (e.g. `lab-ou-finance-eu`, `lab-dlp-rule-pci-scope`) — never a real customer tenant, OU path, or identifier.
- `FixtureDLPPolicyRuleProvider` (this slice's only provider) always sets `Source: SourceFixture` — never `SourceLive`.

## Review Focus

- A provider returning multiple evidence records out of timestamp order — the check must select the record with the latest `Timestamp`, not the last one returned.
- `TimeWindow` boundary records — a record with `Timestamp` exactly equal to `window.Start` or `window.End` must count as in-window (inclusive on both ends).
- `RuleExpiresAt`/`ExceptionExpiresAt` both `nil` (the common "no expiry declared" case) — the expiry-related branches must be skipped entirely, never treated as "expired at the zero time."
- Scope comparison where one side has a `nil` slice and the other has an empty (non-nil) slice for the same field (e.g. `ExcludedUsers`) — these must compare as equal, never as a spurious mismatch.
- `ConfigChangedAt`/`LastSyncedAt` lag that is nonzero but strictly less than `MaxPropagationDelay` — must still pass; only a lag that *exceeds* the configured delay fails.

---

### Task 1: Foundation types and the fixture-backed rule-evidence provider

**Files:**
- Create: `orchestrator/internal/dlppolicy/types.go`
- Create: `orchestrator/internal/dlppolicy/rulebaseline.go`
- Test: `orchestrator/internal/dlppolicy/rulebaseline_test.go`

**Interfaces:**
- Produces (used by Task 2 and by every future dlppolicy slice):
  - `type DLPPOLVerdict string` with consts `VerdictConfirmedFailure`, `VerdictConfirmedSuccess`, `VerdictInconclusive`, `VerdictNotTested`, `VerdictNotApplicable` (exact string values: `"confirmed-failure"`, `"confirmed-success"`, `"inconclusive"`, `"not-tested"`, `"not-applicable"`).
  - `type VerdictDetail struct { Verdict DLPPOLVerdict; Reason string }` (json tags `verdict`, `reason,omitempty`).
  - `type EvidenceSource string` with consts `SourceSynthetic`, `SourceFixture`, `SourceLive` (`"synthetic"`, `"recorded-fixture"`, `"live"`).
  - `type ProvenanceKind string` with consts `ProvenanceObserved`, `ProvenanceInferred` (`"observed"`, `"inferred"`).
  - `type Confidence string` with consts `ConfidenceHigh`, `ConfidenceMedium`, `ConfidenceLow` (`"high"`, `"medium"`, `"low"`).
  - `type Provenance struct { Kind ProvenanceKind; Confidence Confidence; Basis string }` (json tags `kind`, `confidence`, `basis,omitempty`).
  - `type TimeWindow struct { Start, End time.Time }`.
  - `type ScopeID string`.
  - `type DLPPolicyMode string` with consts `ModeEnforce`, `ModeAuditOnly` (`"enforce"`, `"audit-only"`).
  - `type DLPPolicyScopeDeclaration struct { IncludedLocations, ExcludedLocations, IncludedUsers, ExcludedUsers, IncludedDevices, ExcludedDevices, IncludedGroups, ExcludedGroups []string }` (json tags matching field names in camelCase, all `,omitempty`).
  - `type DLPPolicyRuleExpectation struct { RuleID string; ScopeID ScopeID; Scope DLPPolicyScopeDeclaration; ExpectedMode DLPPolicyMode; ExpectedEnabled bool; ExpectedPublished bool; RuleExpiresAt *time.Time; ExceptionExpiresAt *time.Time; MaxPropagationDelay time.Duration; ControlProduct string; Note string }` (json tags in camelCase, pointer/duration/note fields `,omitempty`).
  - `type DLPPolicyRuleEvidence struct { RuleID string; ScopeID ScopeID; ObservedScope DLPPolicyScopeDeclaration; ObservedMode DLPPolicyMode; Enabled bool; Published bool; ExceptionActive bool; ConfigChangedAt time.Time; LastSyncedAt time.Time; Timestamp time.Time; Source EvidenceSource; Provenance Provenance }` (json tags in camelCase).
  - `type DLPPolicyRuleEvidenceProvider interface { DLPPolicyRuleEvidenceFor(ruleID string, scope ScopeID, window TimeWindow) ([]DLPPolicyRuleEvidence, error) }`.
  - `type FixtureDLPPolicyRuleProvider struct{ ... }` (wraps `[]DLPPolicyRuleEvidence`) with `NewFixtureDLPPolicyRuleProvider(events []DLPPolicyRuleEvidence) *FixtureDLPPolicyRuleProvider` and the above interface's method implemented: filters by exact `RuleID` match, exact `ScopeID` match, and `Timestamp` within `[window.Start, window.End]` inclusive on both ends.

- [ ] **Step 1: Write the failing test for the fixture provider's filtering**

```go
func TestFixtureDLPPolicyRuleProvider_FiltersByRuleScopeAndWindow(t *testing.T) {
    base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
    events := []DLPPolicyRuleEvidence{
        {RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-finance", Timestamp: base, Source: SourceFixture},          // match
        {RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-hr", Timestamp: base, Source: SourceFixture},               // wrong scope
        {RuleID: "lab-dlp-rule-other", ScopeID: "lab-ou-finance", Timestamp: base, Source: SourceFixture},              // wrong rule
        {RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-finance", Timestamp: base.Add(-48 * time.Hour), Source: SourceFixture}, // out of window
    }
    p := NewFixtureDLPPolicyRuleProvider(events)
    window := TimeWindow{Start: base.Add(-time.Hour), End: base.Add(time.Hour)}

    got, err := p.DLPPolicyRuleEvidenceFor("lab-dlp-rule-pci-scope", "lab-ou-finance", window)
    if err != nil {
        t.Fatalf("DLPPolicyRuleEvidenceFor: %v", err)
    }
    if len(got) != 1 || !got[0].Timestamp.Equal(base) {
        t.Fatalf("got %+v, want exactly the one matching record at %v", got, base)
    }
}

func TestFixtureDLPPolicyRuleProvider_WindowBoundaryInclusive(t *testing.T) {
    base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
    events := []DLPPolicyRuleEvidence{{RuleID: "r1", ScopeID: "s1", Timestamp: base, Source: SourceFixture}}
    p := NewFixtureDLPPolicyRuleProvider(events)

    got, err := p.DLPPolicyRuleEvidenceFor("r1", "s1", TimeWindow{Start: base, End: base})
    if err != nil || len(got) != 1 {
        t.Fatalf("got %+v, err %v -- a record exactly at Start==End must still match (inclusive both ends)", got, err)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run TestFixtureDLPPolicyRuleProvider -v`
Expected: FAIL (package/types/functions not defined)

- [ ] **Step 3: Implement the types and provider**

Implement `types.go` and `rulebaseline.go`'s type/provider declarations exactly as specified in the Interfaces block above. `DLPPolicyRuleEvidenceFor`'s window check is `!ts.Before(window.Start) && !ts.After(window.End)` (inclusive both ends, per Review Focus).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run TestFixtureDLPPolicyRuleProvider -v`
Expected: PASS

- [ ] **Step 5: `gofmt -l` and `go vet` the package, fix any output**

Run: `gofmt -l orchestrator/internal/dlppolicy/` and `go vet github.com/audspect/bas/internal/dlppolicy/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlppolicy/types.go orchestrator/internal/dlppolicy/rulebaseline.go orchestrator/internal/dlppolicy/rulebaseline_test.go
git commit -m "feat(dlppolicy): add foundation types and fixture-backed rule-evidence provider"
```

---

### Task 2: `VerifyDLPPolicyRuleExpectation` — full branch coverage

**Files:**
- Modify: `orchestrator/internal/dlppolicy/rulebaseline.go`
- Test: `orchestrator/internal/dlppolicy/rulebaseline_test.go`

**Interfaces:**
- Consumes: every type/provider from Task 1 (`DLPPolicyRuleExpectation`, `DLPPolicyRuleEvidence`, `DLPPolicyRuleEvidenceProvider`, `FixtureDLPPolicyRuleProvider`, `VerdictDetail`, `DLPPOLVerdict` consts, `TimeWindow`).
- Produces: `func VerifyDLPPolicyRuleExpectation(exp DLPPolicyRuleExpectation, provider DLPPolicyRuleEvidenceProvider, window TimeWindow, asOf time.Time) VerdictDetail` — used by every later dlppolicy slice (2a reuses the pattern independently; 2b consumes this function's *output*, never its internals).

Verify order (first match wins — spec §"Slice 1", branches 1-10; "latest" = the evidence record with the greatest `Timestamp` among those the provider returned):

1. No evidence → `VerdictInconclusive`, reason `"no policy configuration evidence found for this rule/scope in the window"`.
2. `!latest.Enabled` → `VerdictConfirmedFailure`, reason `"rule is disabled"`.
3. `!latest.Published` → `VerdictConfirmedFailure`, reason `"rule not published/deployed to this scope"`.
4. `exp.RuleExpiresAt != nil && asOf.After(*exp.RuleExpiresAt)` → `VerdictConfirmedFailure`, reason `"rule expired but still active"`. (Reaching this branch already means `latest.Enabled && latest.Published`, since branches 2/3 return first otherwise — no need to re-check either.)
5. `exp.ExceptionExpiresAt != nil && asOf.After(*exp.ExceptionExpiresAt) && latest.ExceptionActive` → `VerdictConfirmedFailure`, reason `"exception expired but still active"`.
6. `latest.ObservedMode != exp.ExpectedMode` → `VerdictConfirmedFailure`, reason naming both modes, e.g. `fmt.Sprintf("expected mode %q, observed %q", exp.ExpectedMode, latest.ObservedMode)`.
7. `!scopesEqual(exp.Scope, latest.ObservedScope)` → `VerdictConfirmedFailure`, reason naming the specific mismatched field(s) (not a generic "scope mismatch"). `scopesEqual` is a new unexported helper in this file: compares each of the 8 `[]string` fields as **sets** (order-independent; `nil` and `[]string{}` compare equal) — this is a plan-level decision, not left open, because locations/users/devices/groups are inherently unordered membership lists.
8. `exp.ExceptionExpiresAt == nil && latest.ExceptionActive` → `VerdictConfirmedFailure`, reason `"exception active but not declared/expected on this rule in this scope"`.
9. `exp.MaxPropagationDelay > 0`, and with `lag := latest.ConfigChangedAt.Sub(latest.LastSyncedAt)`, `lag > exp.MaxPropagationDelay` → `VerdictConfirmedFailure`, reason `"stale endpoint configuration, propagation delay exceeded"`. (A `lag` that is positive but `<= exp.MaxPropagationDelay` must still pass, per Review Focus.)
10. Otherwise → `VerdictConfirmedSuccess` (no `Reason`).

- [ ] **Step 1: Write the failing tests, one per branch**

```go
func TestVerifyDLPPolicyRuleExpectation_NoEvidence_ReturnsInconclusive(t *testing.T) { /* empty fixture provider; assert VerdictInconclusive */ }
func TestVerifyDLPPolicyRuleExpectation_Disabled_ReturnsConfirmedFailure(t *testing.T) { /* latest.Enabled=false; assert VerdictConfirmedFailure, reason contains "disabled" */ }
func TestVerifyDLPPolicyRuleExpectation_NotPublished_ReturnsConfirmedFailure(t *testing.T) { /* ... */ }
func TestVerifyDLPPolicyRuleExpectation_RuleExpiredButStillActive_ReturnsConfirmedFailure(t *testing.T) { /* RuleExpiresAt in the past, Enabled+Published true */ }
func TestVerifyDLPPolicyRuleExpectation_RuleExpiresAtNil_SkipsExpiryCheck(t *testing.T) { /* RuleExpiresAt nil, everything else matching; assert ConfirmedSuccess -- Review Focus */ }
func TestVerifyDLPPolicyRuleExpectation_ExceptionExpiredButStillActive_ReturnsConfirmedFailure(t *testing.T) { /* ... */ }
func TestVerifyDLPPolicyRuleExpectation_ModeMismatch_ReturnsConfirmedFailure(t *testing.T) { /* exp ModeEnforce, observed ModeAuditOnly */ }
func TestVerifyDLPPolicyRuleExpectation_ScopeMismatch_NamesTheField(t *testing.T) { /* exp.Scope.ExcludedUsers=["a"], observed omits it; assert Reason contains "ExcludedUsers" or "a" */ }
func TestVerifyDLPPolicyRuleExpectation_ScopeNilVsEmptySlice_IsNotAMismatch(t *testing.T) { /* exp.Scope.ExcludedUsers=nil, observed=[]string{}; assert ConfirmedSuccess -- Review Focus */ }
func TestVerifyDLPPolicyRuleExpectation_ScopeSetOrderIndependent_IsNotAMismatch(t *testing.T) { /* exp=["a","b"], observed=["b","a"]; assert ConfirmedSuccess */ }
func TestVerifyDLPPolicyRuleExpectation_UndeclaredExceptionActive_ReturnsConfirmedFailure(t *testing.T) { /* exp.ExceptionExpiresAt=nil, latest.ExceptionActive=true */ }
func TestVerifyDLPPolicyRuleExpectation_PropagationDelayExceeded_ReturnsConfirmedFailure(t *testing.T) { /* lag > MaxPropagationDelay */ }
func TestVerifyDLPPolicyRuleExpectation_PropagationDelayWithinLimit_ReturnsConfirmedSuccess(t *testing.T) { /* 0 < lag <= MaxPropagationDelay -- Review Focus */ }
func TestVerifyDLPPolicyRuleExpectation_AllMatch_ReturnsConfirmedSuccess(t *testing.T) { /* fully matching, no Reason set */ }
func TestVerifyDLPPolicyRuleExpectation_MultipleRecords_PicksLatestByTimestampNotOrder(t *testing.T) { /* provider returns an older ConfirmedSuccess-shaped record AFTER a newer ConfirmedFailure-shaped one in the slice; assert the newer one's verdict wins -- Review Focus */ }
```

Each test builds its own `exp DLPPolicyRuleExpectation`, a one-or-two-record `[]DLPPolicyRuleEvidence` fed through `NewFixtureDLPPolicyRuleProvider`, and calls `VerifyDLPPolicyRuleExpectation(exp, provider, window, asOf)` with `window`/`asOf` fixed so every evidence record in the test falls inside it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -run TestVerifyDLPPolicyRuleExpectation -v`
Expected: FAIL with "VerifyDLPPolicyRuleExpectation not defined"

- [ ] **Step 3: Implement `VerifyDLPPolicyRuleExpectation` and the `scopesEqual` helper in `rulebaseline.go`**

Branch order and reasons exactly as specified above. `scopesEqual` compares all 8 fields via a set-equality helper (e.g. build a `map[string]struct{}` per slice and compare lengths + membership) — nil and empty slice both produce an empty set.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/dlppolicy/... -v`
Expected: PASS (all tests in the package, including Task 1's)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/dlppolicy/` and `go vet github.com/audspect/bas/internal/dlppolicy/...`
Expected: no output from either

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dlppolicy/rulebaseline.go orchestrator/internal/dlppolicy/rulebaseline_test.go
git commit -m "feat(dlppolicy): add VerifyDLPPolicyRuleExpectation with full branch coverage"
```

---

## Self-Review Notes

- **Spec coverage:** Task 1 covers the spec's "Foundation types" section and the provider half of "Slice 1". Task 2 covers all 10 branches of Slice 1's `VerifyDLPPolicyRuleExpectation`, including both builder-check fixes (branch 8's undeclared-exception check, and the construction-time validation note — N/A here since Slice 1 has no cross-field constructor requirement; that requirement belongs to Slice 2a's own future plan). Slices 2a/2b are explicitly out of scope for this plan — each gets its own plan once this one is merged, per the design doc's own recommendation.
- **Type consistency:** `DLPPolicyRuleEvidenceProvider`, `DLPPolicyRuleExpectation`, `DLPPolicyRuleEvidence`, and `VerdictDetail` are named identically between Task 1's Interfaces block and Task 2's Consumes block.
- **Review Focus:** all five items each have a named test in Task 2's step 1 (latest-by-timestamp-not-order, window boundary inclusivity in Task 1, nil-vs-empty-slice scope equality, missing expiry fields skip their branch, propagation delay boundary).
