# Web Gateway BAS Mastery Domain 04 (Malware, Exploit Delivery and File Protection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close domain 04's exit criterion for this round -- one known-good scenario (an EICAR test-file download correctly blocked by the gateway's malware/file-protection policy) and one negative counterpart execute end-to-end against Phase 1's existing, unmodified `HTTPExpectation` pipeline -- and keep `AudspectWebGWCoverageReport()` in sync, bringing all 12 `webGW.txt` domains to at least `Covered` status.

**Architecture:** No new production file. A file download is an HTTP request, so this reuses `HTTPExpectation`/`GatewayEvidence`/`VerifyHTTPExpectation` directly, unchanged -- the same way domains 06 and 08 deliberately avoided inventing new types where the existing ones already fit. Two scenario tests prove the exit criterion against the real, unmodified verdict pipeline. A final small task flips domain 04 from `CoverageNotCovered` to `CoverageCovered` in the one place that claim is made, and updates the existing coverage-report scenario test's asserted numbers to match.

**Tech Stack:** Go standard library only (`testing`, `time`) -- no new dependency, continuing Phase 1-5's zero-dependency discipline.

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md`, "Post-Phase-5 domain closure: Domain 04 (malware, exploit delivery and file protection)", committed directly beneath domain 07's own section, and §5's domain-04 table row (updated in the same commit).

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other `github.com/audspect/bas/...` package -- unchanged since Phase 1. This plan adds no production code, so this constraint is preserved by construction; verify with `go list -deps ./internal/webgwefficacy/...` after Task 1 anyway, to catch any accidental new import.
- The declared test artifact is the industry-standard EICAR string, never a real malware sample -- `webGW.txt`'s own domain-04 constraint: "A simulated malicious file must not be replaced with real malware simply to increase test intensity." This is documented in the scenario's own `Note` field, the same way domain 03's DLP scenarios document their synthetic-marker discipline.
- `AudspectWebGWCoverageReport()` (`coverage.go`) must stay in sync with §5's own table -- a divergence between the two is a defect in whichever one is stale, per the spec's own living-document rule.
- `CoverageReport.Summary()`'s existing logic only appends the `"; N not yet covered"` clause when `NotCoveredCount() > 0` (`coverage.go`) -- with this round's change, that count becomes 0, so the clause will not appear in the string at all. This is expected behavior, not a bug to work around.

## Review Focus

1. **The EICAR scenario's `Note` field must actually state the synthetic-artifact constraint**, not merely describe what's being tested -- a reader of the test (or a future scenario built from it as a template) needs the "never real malware" rule to travel with the scenario itself, not live only in the spec document. Pinned in Task 1.
2. **The negative counterpart must assert `VerdictFail`, not `VerdictInconclusive` or any other non-Pass verdict** -- a download that the fixture evidence shows was allowed through is a concrete policy miss, the same negative-case discipline `TestProxyBypassScenario_DNSOverHTTPSMissed` and `TestCASBScenario_PersonalTenantAllowedThrough` already established; a weaker assertion here would let a real regression (e.g. the verdict logic degrading to `Inconclusive` on a mismatch) pass silently. Pinned in Task 1.
3. **`TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions`'s `NotCoveredCount()` assertion going stale.** The existing test hardcodes `1` and the message `"only domain 04 remains unbuilt"` -- after this round both become wrong (`0` and no domain unbuilt). If Task 2 changes `coverage.go` without updating this test in the same commit, the suite catches the mismatch, but the fix must land together, not as an afterthought -- matching the discipline the domain-07 round already established for this exact test. Pinned in Task 2.
4. **The `Summary()` substring assertion assuming the `"; N not yet covered"` clause still exists.** With `NotCoveredCount()` at 0, `Summary()` returns something like `"12/12 domains covered (100%)"` with no trailing clause at all -- a test that still checks for a not-yet-covered substring (even an updated count) would be asserting something that can never appear. The updated test must check only for `"12/12"`, not for any not-covered wording. Pinned in Task 2.
5. **`report.ExcludedCount()` must remain `0`.** This round only moves a domain between `Covered` and `NotCovered`; it must never cause a domain to end up `Excluded` by accident (e.g. a copy-paste of the wrong `DomainCoverage` literal). Pinned in Task 2 by keeping the existing `ExcludedCount() != 0` assertion unchanged and verifying it still passes.

---

### Task 1: Known-good and negative EICAR file-protection scenarios

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go`

**Interfaces:**
- Consumes: `HTTPExpectation{RequestURL, URLCategory, ExpectedAction, ControlProduct, Note}`, `ExpectedBlock` (`types.go`, Phase 1, unmodified); `GatewayEvidence{RequestURL, Action, Category, PolicyRule, Timestamp, Source}`, `NewFixtureGatewayProvider` (`providers.go`, Phase 1, unmodified); `HTTPObservation{}`, `VerifyHTTPExpectation(exp, obs, provider, window) EfficacyResult`, `EfficacyResult.Prevention` (`verify.go`, Phase 1, unmodified); `VerdictPass`/`VerdictFail`, `SourceFixture` (`types.go`, unmodified).
- Produces: nothing new -- this task adds no production code. It proves domain 04's exit criterion end-to-end: one known-good scenario and one negative counterpart, matching the two-test pattern domains 01, 06, and 08 already established in this same file.

- [ ] **Step 1: Write the scenario tests**

Append to `orchestrator/internal/webgwefficacy/scenarios_test.go`, immediately after `TestCASBScenario_PersonalTenantAllowedThrough` and before `TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions`:

```go
// TestMalwareFileScenario_EICARTestFileBlocked proves a known-good
// baseline for domain 04 (malware, exploit delivery and file
// protection): a download of the industry-standard EICAR test file is
// declared expected to be blocked by the gateway's own malware/file
// protection policy, and fixture evidence confirms it was. Per
// webGW.txt's own domain-04 constraint, this never uses a real
// malware sample -- only the universally-recognized EICAR synthetic
// test string, the same discipline domain 03's DLP scenarios already
// apply to their own synthetic markers.
func TestMalwareFileScenario_EICARTestFileBlocked(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://malware-test.example/eicar-test-file.com",
		URLCategory:    "eicar-test-file",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "industry-standard EICAR synthetic test string, never a real malware sample",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Category: "eicar-test-file", PolicyRule: "block-malware-file-signature", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- known-good baseline: the EICAR test-file download was blocked", result.Prevention.Verdict, VerdictPass)
	}
}

// TestMalwareFileScenario_EICARTestFileMissed is the negative
// counterpart: the same EICAR test-file download, but fixture
// evidence shows the gateway allowed it through -- the file-protection
// gap a domain-04 test exists to surface.
func TestMalwareFileScenario_EICARTestFileMissed(t *testing.T) {
	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://malware-test.example/eicar-test-file.com",
		URLCategory:    "eicar-test-file",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
	}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "allow", Category: "eicar-test-file", Timestamp: now, Source: SourceFixture},
	})
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	if result.Prevention.Verdict != VerdictFail {
		t.Errorf("Prevention.Verdict = %q, want %q -- negative case: the EICAR test-file download was missed", result.Prevention.Verdict, VerdictFail)
	}
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestMalwareFileScenario -v`
Expected: PASS directly -- every piece these tests call already exists from Phase 1's own unmodified pipeline; there is no new implementation to watch fail against. Confirm the compiler has no errors and both tests genuinely ran before proceeding.

- [ ] **Step 3: Run the full package suite**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test including Task 1's two new ones plus the full existing suite.

- [ ] **Step 4: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove the EICAR test-file scenario end-to-end -- domain 04

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Flip domain 04 to Covered, completing all 12 domains

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/coverage.go:123`
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go` (the existing coverage-reporting scenario test, lines 217-240 as of this plan)

**Interfaces:**
- Consumes: `AudspectWebGWCoverageReport`, `CoverageCovered` (`coverage.go`, Phase 5, unmodified except for this task's own one-line change).
- Produces: nothing new -- this task updates one existing line of production code and the one existing test whose assertions depend on it.

- [ ] **Step 1: Update the existing coverage-reporting test's assertions first (RED)**

In `orchestrator/internal/webgwefficacy/scenarios_test.go`, replace `TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions` in full (including its doc comment) with:

```go
// TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions
// proves Phase 5's coverage-reporting exit criterion end-to-end
// against Audspect's real, shipped coverage data -- not a synthetic
// CoverageReport built only for this test. As of this round, all 12
// webGW.txt domains have at least one fixture-backed, proven scenario
// -- this is explicitly NOT a claim that any domain's full breadth is
// built out, per CoverageStatus's own documented meaning (01-12 each
// still have unbuilt sub-capabilities named in the spec's §5 table).
func TestCoverageReportingScenario_AudspectWebGWCoverage_CitesDenominatorAndExclusions(t *testing.T) {
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	if got := report.Denominator(); got != 12 {
		t.Errorf("Denominator() = %d, want 12 -- webGW.txt defines exactly 12 domains", got)
	}
	if got := report.CoveredCount(); got != 12 {
		t.Errorf("CoveredCount() = %d, want 12 -- all 12 domains now have at least one proven scenario", got)
	}
	if got := report.NotCoveredCount(); got != 0 {
		t.Errorf("NotCoveredCount() = %d, want 0", got)
	}
	if got := report.ExcludedCount(); got != 0 {
		t.Errorf("ExcludedCount() = %d, want 0 -- no domain has been permanently excluded from this initiative", got)
	}

	summary := report.Summary()
	if !strings.Contains(summary, "12/12") {
		t.Errorf("Summary() = %q, want it to contain the covered count alongside the denominator (\"12/12\"), never a bare percentage", summary)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestCoverageReportingScenario -v`
Expected: FAIL -- `CoveredCount() = 11, want 12` (and the other now-stale assertions), since `coverage.go` still has domain 04 as `CoverageNotCovered`.

- [ ] **Step 3: Flip domain 04 in `AudspectWebGWCoverageReport`**

In `orchestrator/internal/webgwefficacy/coverage.go`, change line 123:

```go
		{DomainID: "04", DomainName: "Malware/exploit delivery/file protection", Status: CoverageNotCovered},
```

to:

```go
		{DomainID: "04", DomainName: "Malware/exploit delivery/file protection", Status: CoverageCovered},
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test in the package, including the updated coverage-reporting scenario test.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/coverage.go internal/webgwefficacy/scenarios_test.go
git commit -m "feat(webgwefficacy): flip domain 04 to Covered, completing all 12 webGW.txt domains

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-15-webgw-mastery-domain04-eicar-file-protection.md`.

**Native** — I implement both tasks myself in this session, then one fresh reviewer checks the whole branch at the end, matching this initiative's own established execution method (every task here is deterministic, in-memory, and zero-dependency, the same risk profile that already ran natively on every prior round).
