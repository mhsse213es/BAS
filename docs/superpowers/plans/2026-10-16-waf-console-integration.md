# WAF Console Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the already-built, fully-tested 10-phase WAF BAS Mastery backend (`internal/wafval`..`internal/wafverify`) into the Audspect console as two read-only report surfaces, so a rebuild actually surfaces something new.

**Architecture:** A new `internal/wafefficacy` package defines an independent `CoverageReport` type (no cross-import with `webgwefficacy`/`emailgwefficacy`) seeded with 10 domains 1:1 with `waf.txt`'s phases. Two new API routes serve it as JSON + HTML. A second pair of routes serves `wafprofile`'s existing 6 industry/regional profiles directly, with no new type needed. Both pairs mirror the already-proven `internal/emailgwefficacy`/`internal/webgwefficacy` console-wiring pattern file-for-file.

**Tech Stack:** Go 1.26, stdlib `net/http`/`html/template`/`encoding/json`, existing `internal/api` router (chi-style `r.Get`), existing `writeBufferedReport`/`respond` helpers.

**Spec:** `docs/superpowers/specs/2026-10-16-waf-console-integration-design.md`

## Global Constraints

- `internal/wafefficacy` depends only on the 10 already-merged `internal/waf*` packages (read-only) plus stdlib `fmt`/`strings` — **no import of `internal/webgwefficacy` or `internal/emailgwefficacy`**, and neither of those imports `internal/wafefficacy` either.
- No live HTTP-probing execution engine, no new scenario-executor type, no `scenarios/*.yaml` WAF entries, no `web/src` component — all explicitly deferred per spec §6.
- Every `ComplianceReference` rendered by the industry-profiles surface (JSON and HTML) must preserve its real `VerificationStatus` and `Note` verbatim, never summarized or dropped — this is the direct anti-regression concern against the documented `webgwefficacy` stale-RBI-circular precedent (spec §2/§3/§4).
- `CoverageReport.Summary()` must always include the fixed evaluator-only/no-live-execution disclosure sentence, regardless of domain contents (spec §2.1).
- The 10 coverage domains are copied **verbatim** from `waf.txt`'s own phase names (confirmed by direct read of `waf.txt` lines 118-184 during planning — see Task 2's table).

## Review Focus

- `CoverageReport.Summary()`'s fixed disclosure sentence must be tested as actually present in the returned string, not just that `Summary()` is non-empty — a careless implementation could put the sentence only in a doc comment. **Covered by Task 1, Step 2 (`TestSummary_AlwaysIncludesNoLiveExecutionDisclosure`).**
- `AudspectWAFCoverageReport`'s 10 domains must be verified against `waf.txt`'s actual phase names/order, not just asserted as a hardcoded count of 10 — a transposition of two names would otherwise pass a count-only test. **Covered by Task 2, Step 2 (`TestAudspectWAFCoverageReport_MatchesWafTxtPhasesVerbatim`).**
- The industry-profiles JSON/HTML surfaces must never drop a `ComplianceReference`'s `Unverified` status or `Note` — tested against a real, pinned `wafprofile` seed value, not a placeholder. **Covered by Task 5, Step 2 and Task 6, Step 2.**
- `GetWAFCoverage`/`GetWAFIndustryProfiles` must return exactly the real, current report's data (no stale/synthetic copy) — matching the existing `TestGetEmailGWCoverage_ReturnsEveryTaxonomyArea` pattern of asserting against the live function's own output, not a fixture. **Covered by Task 3, Step 2 and Task 5, Step 2.**
- The handlers' error branches (a build/compute error → `500` with the error text) must either be exercised by a test or documented as structurally unreachable, never silently untested. **Addressed in Task 4 and Task 6: documented as structurally unreachable, see each task's note.**
- The 4 new routes must not collide with or shadow any existing route path. **Covered by Task 7, Step 1 (pre-registration grep).**

---

## Task 1: CoverageReport type

**Files:**
- Create: `orchestrator/internal/wafefficacy/coverage.go`
- Test: `orchestrator/internal/wafefficacy/coverage_test.go`

**Interfaces:**
- Produces: `CoverageStatus` (type `string`, consts `CoverageCovered`/`CoverageExcluded`/`CoverageNotCovered`); `DomainCoverage{DomainID, DomainName string; Status CoverageStatus; ExclusionReason string}`; `CoverageReport` (opaque struct); `NewCoverageReport(domains []DomainCoverage) (CoverageReport, error)`; `(CoverageReport) Denominator() int`, `CoveredCount() int`, `ExcludedCount() int`, `NotCoveredCount() int`, `Exclusions() []string`, `Summary() string`.

- [ ] **Step 1: Write the failing tests**

```go
package wafefficacy

import "testing"

func TestNewCoverageReport_DuplicateDomainID_Rejected(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageCovered},
		{DomainID: "01", DomainName: "B", Status: CoverageCovered},
	})
	if err == nil {
		t.Fatal("want error for duplicate DomainID, got nil")
	}
}

func TestNewCoverageReport_UnknownStatus_Rejected(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageStatus("bogus")},
	})
	if err == nil {
		t.Fatal("want error for unknown status, got nil")
	}
}

func TestNewCoverageReport_ExcludedWithoutReason_Rejected(t *testing.T) {
	_, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageExcluded},
	})
	if err == nil {
		t.Fatal("want error for excluded domain with empty ExclusionReason, got nil")
	}
}

func TestNewCoverageReport_ExcludedWithReason_Succeeds(t *testing.T) {
	if _, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageExcluded, ExclusionReason: "not built yet"},
	}); err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
}

func mustReport(t *testing.T) CoverageReport {
	t.Helper()
	r, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "A", Status: CoverageCovered},
		{DomainID: "02", DomainName: "B", Status: CoverageExcluded, ExclusionReason: "reason"},
		{DomainID: "03", DomainName: "C", Status: CoverageNotCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	return r
}

func TestCoverageReport_CountsAndDenominator(t *testing.T) {
	r := mustReport(t)
	if r.Denominator() != 3 {
		t.Errorf("Denominator() = %d, want 3", r.Denominator())
	}
	if r.CoveredCount() != 1 {
		t.Errorf("CoveredCount() = %d, want 1", r.CoveredCount())
	}
	if r.ExcludedCount() != 1 {
		t.Errorf("ExcludedCount() = %d, want 1", r.ExcludedCount())
	}
	if r.NotCoveredCount() != 1 {
		t.Errorf("NotCoveredCount() = %d, want 1", r.NotCoveredCount())
	}
}

func TestCoverageReport_Exclusions_RendersReason(t *testing.T) {
	r := mustReport(t)
	excl := r.Exclusions()
	if len(excl) != 1 {
		t.Fatalf("len(Exclusions()) = %d, want 1", len(excl))
	}
	if !contains(excl[0], "reason") {
		t.Errorf("Exclusions()[0] = %q, want it to contain %q", excl[0], "reason")
	}
}

// Review Focus: the disclosure sentence must be in the real return
// value, not merely documented, and must appear regardless of domain
// contents (tested against two different reports).
func TestSummary_AlwaysIncludesNoLiveExecutionDisclosure(t *testing.T) {
	const disclosure = "evaluator-only"
	r1 := mustReport(t)
	if !contains(r1.Summary(), disclosure) {
		t.Errorf("Summary() = %q, want it to contain %q", r1.Summary(), disclosure)
	}

	r2, err := NewCoverageReport([]DomainCoverage{{DomainID: "99", DomainName: "Z", Status: CoverageCovered}})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}
	if !contains(r2.Summary(), disclosure) {
		t.Errorf("Summary() = %q, want it to contain %q", r2.Summary(), disclosure)
	}
}

func TestSummary_IncludesCoveredCountAndDenominator(t *testing.T) {
	r := mustReport(t)
	s := r.Summary()
	if !contains(s, "1/3") {
		t.Errorf("Summary() = %q, want it to contain %q", s, "1/3")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafefficacy/... -run . -v`
Expected: FAIL — `package wafefficacy` / `CoverageStatus` / `NewCoverageReport` etc. undefined (package doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

```go
package wafefficacy

import (
	"fmt"
	"strings"
)

// CoverageStatus is one domain's coverage state in a CoverageReport.
// "Covered" means at least one fixture-backed, proven scenario exists
// for the domain -- not that the domain's full breadth is built out.
type CoverageStatus string

const (
	CoverageCovered    CoverageStatus = "covered"
	CoverageExcluded   CoverageStatus = "excluded"
	CoverageNotCovered CoverageStatus = "not-covered"
)

func validCoverageStatus(s CoverageStatus) bool {
	switch s {
	case CoverageCovered, CoverageExcluded, CoverageNotCovered:
		return true
	default:
		return false
	}
}

// DomainCoverage is one domain's entry in a CoverageReport.
// ExclusionReason is required whenever Status is CoverageExcluded --
// enforced by NewCoverageReport, never left to convention.
type DomainCoverage struct {
	DomainID        string
	DomainName      string
	Status          CoverageStatus
	ExclusionReason string
}

// CoverageReport is a validated set of DomainCoverage entries.
type CoverageReport struct {
	domains []DomainCoverage
}

// NewCoverageReport validates domains at construction time, never at
// render time: no DomainID may repeat, Status must be one of the 3
// known constants, and every CoverageExcluded domain must carry a
// non-empty ExclusionReason.
func NewCoverageReport(domains []DomainCoverage) (CoverageReport, error) {
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		if seen[d.DomainID] {
			return CoverageReport{}, fmt.Errorf("duplicate domain ID %q", d.DomainID)
		}
		seen[d.DomainID] = true
		if !validCoverageStatus(d.Status) {
			return CoverageReport{}, fmt.Errorf("domain %q has unrecognized status %q", d.DomainID, d.Status)
		}
		if d.Status == CoverageExcluded && d.ExclusionReason == "" {
			return CoverageReport{}, fmt.Errorf("domain %q marked excluded with no documented reason", d.DomainID)
		}
	}
	return CoverageReport{domains: domains}, nil
}

func (r CoverageReport) Denominator() int { return len(r.domains) }

func (r CoverageReport) CoveredCount() int    { return r.countStatus(CoverageCovered) }
func (r CoverageReport) ExcludedCount() int   { return r.countStatus(CoverageExcluded) }
func (r CoverageReport) NotCoveredCount() int { return r.countStatus(CoverageNotCovered) }

func (r CoverageReport) countStatus(status CoverageStatus) int {
	n := 0
	for _, d := range r.domains {
		if d.Status == status {
			n++
		}
	}
	return n
}

// Exclusions renders every excluded domain's own documented reason.
func (r CoverageReport) Exclusions() []string {
	var out []string
	for _, d := range r.domains {
		if d.Status == CoverageExcluded {
			out = append(out, fmt.Sprintf("%s (%s): %s", d.DomainID, d.DomainName, d.ExclusionReason))
		}
	}
	return out
}

// noLiveExecutionDisclosure is a fixed, always-rendered caveat: every
// domain this report describes is evaluator-only, judged against
// caller-supplied (today, fixture) evidence -- there is no live
// HTTP-probing execution against a real target WAF yet. This is a
// report-level caveat, not a per-domain ExclusionReason: nothing here
// is excluded, but a reader must never mistake "covered" for "this
// runs against your live WAF today."
const noLiveExecutionDisclosure = "every domain is evaluator-only (fixture-backed evidence); no live HTTP-probing execution against a real target WAF exists yet"

// Summary renders the covered count, the denominator, every
// exclusion's reason (when any exist), and the fixed
// noLiveExecutionDisclosure -- which can never be omitted by a future
// edit, since it is interpolated directly into this function's return
// value rather than left in a doc comment.
func (r CoverageReport) Summary() string {
	if r.Denominator() == 0 {
		return "0/0 domains defined -- no coverage report can be computed; " + noLiveExecutionDisclosure
	}
	s := fmt.Sprintf("%d/%d domains covered", r.CoveredCount(), r.Denominator())
	if n := r.NotCoveredCount(); n > 0 {
		s += fmt.Sprintf("; %d not yet covered", n)
	}
	if excl := r.Exclusions(); len(excl) > 0 {
		s += fmt.Sprintf("; %d excluded: %s", len(excl), strings.Join(excl, "; "))
	}
	s += "; " + noLiveExecutionDisclosure
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafefficacy/... -v`
Expected: PASS, all tests in `coverage_test.go` green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafefficacy/coverage.go orchestrator/internal/wafefficacy/coverage_test.go
git commit -m "feat(wafefficacy): CoverageReport type with mandatory no-live-execution disclosure"
```

---

## Task 2: AudspectWAFCoverageReport seed function

**Files:**
- Create: `orchestrator/internal/wafefficacy/catalog.go`
- Test: `orchestrator/internal/wafefficacy/catalog_test.go`

**Interfaces:**
- Consumes: Task 1's `DomainCoverage`, `CoverageCovered`, `NewCoverageReport`, `CoverageReport`.
- Produces: `AudspectWAFCoverageReport() (CoverageReport, error)`.

The 10 domains, `DomainID`/`DomainName` copied **verbatim** from `waf.txt` (repo root, lines 118-184 — read directly during planning):

| DomainID | DomainName |
|---|---|
| 01 | WAF capability and vendor-neutral model |
| 02 | Core attack-prevention mastery |
| 03 | Configuration and policy-gap testing |
| 04 | Protocol, parser and evasion testing |
| 05 | API and business-flow protection |
| 06 | Bot, abuse and rate-limit efficacy |
| 07 | Origin, deployment and resilience |
| 08 | Detection and telemetry validation |
| 09 | Industry and regional profiles |
| 10 | Independent verification and continuous mastery |

- [ ] **Step 1: Write the failing tests**

```go
package wafefficacy

import "testing"

func TestAudspectWAFCoverageReport_ReturnsTenDomains(t *testing.T) {
	r, err := AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	if r.Denominator() != 10 {
		t.Fatalf("Denominator() = %d, want 10", r.Denominator())
	}
	if r.CoveredCount() != 10 {
		t.Fatalf("CoveredCount() = %d, want 10 (all domains covered)", r.CoveredCount())
	}
}

// Review Focus: verify against waf.txt's own phase names verbatim, not
// just a count -- a transposition of two names must fail this test.
func TestAudspectWAFCoverageReport_MatchesWafTxtPhasesVerbatim(t *testing.T) {
	wantNames := map[string]string{
		"01": "WAF capability and vendor-neutral model",
		"02": "Core attack-prevention mastery",
		"03": "Configuration and policy-gap testing",
		"04": "Protocol, parser and evasion testing",
		"05": "API and business-flow protection",
		"06": "Bot, abuse and rate-limit efficacy",
		"07": "Origin, deployment and resilience",
		"08": "Detection and telemetry validation",
		"09": "Industry and regional profiles",
		"10": "Independent verification and continuous mastery",
	}

	r, err := AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	if got := len(wantNames); r.Denominator() != got {
		t.Fatalf("Denominator() = %d, want %d", r.Denominator(), got)
	}
	for id, name := range wantNames {
		found := false
		for _, d := range r.domains {
			if d.DomainID == id {
				found = true
				if d.DomainName != name {
					t.Errorf("domain %q DomainName = %q, want %q (verbatim from waf.txt)", id, d.DomainName, name)
				}
			}
		}
		if !found {
			t.Errorf("domain ID %q not found in AudspectWAFCoverageReport", id)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/wafefficacy/... -run AudspectWAFCoverageReport -v`
Expected: FAIL — `AudspectWAFCoverageReport` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
package wafefficacy

import "fmt"

// AudspectWAFCoverageReport returns Audspect's real, current WAF BAS
// Mastery coverage: one domain per waf.txt phase (DomainName copied
// verbatim from waf.txt), all CoverageCovered -- honest under the
// established "at least one fixture-backed, proven scenario exists"
// definition, since every phase shipped a fresh-reviewer-approved,
// tested package. See this package's noLiveExecutionDisclosure for
// what "Covered" deliberately does NOT claim.
func AudspectWAFCoverageReport() (CoverageReport, error) {
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "WAF capability and vendor-neutral model", Status: CoverageCovered},
		{DomainID: "02", DomainName: "Core attack-prevention mastery", Status: CoverageCovered},
		{DomainID: "03", DomainName: "Configuration and policy-gap testing", Status: CoverageCovered},
		{DomainID: "04", DomainName: "Protocol, parser and evasion testing", Status: CoverageCovered},
		{DomainID: "05", DomainName: "API and business-flow protection", Status: CoverageCovered},
		{DomainID: "06", DomainName: "Bot, abuse and rate-limit efficacy", Status: CoverageCovered},
		{DomainID: "07", DomainName: "Origin, deployment and resilience", Status: CoverageCovered},
		{DomainID: "08", DomainName: "Detection and telemetry validation", Status: CoverageCovered},
		{DomainID: "09", DomainName: "Industry and regional profiles", Status: CoverageCovered},
		{DomainID: "10", DomainName: "Independent verification and continuous mastery", Status: CoverageCovered},
	})
	if err != nil {
		return CoverageReport{}, fmt.Errorf("loading WAF coverage report: %w", err)
	}
	return report, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/wafefficacy/... -v`
Expected: PASS, all tests green (Task 1 + Task 2).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/wafefficacy/catalog.go orchestrator/internal/wafefficacy/catalog_test.go
git commit -m "feat(wafefficacy): seed AudspectWAFCoverageReport with waf.txt's 10 phases verbatim"
```

---

## Task 3: Reporting renderer for coverage

**Files:**
- Create: `orchestrator/internal/reporting/waf_coverage.go`

**Interfaces:**
- Consumes: Task 1/2's `wafefficacy.AudspectWAFCoverageReport()`, `CoverageReport.{Summary,Denominator}`, `DomainCoverage` fields, `CoverageStatus`.
- Produces: `WAFCoverageDomainEntry{DomainID, DomainName, Status, ExclusionReason string}`, `WAFCoverageReport{GeneratedAt time.Time; Summary string; Domains []WAFCoverageDomainEntry}`, `BuildWAFCoverageReport() (WAFCoverageReport, error)`, `WAFCoverageReportHTML(w io.Writer, rep WAFCoverageReport) error`.

This task has no test file of its own — it is a pure formatter with no branching logic beyond Task 1/2's own (already-tested) report, mirroring `internal/reporting/emailgw_coverage.go`'s precedent (which likewise has no `_test.go`). Task 4's handler test exercises this renderer end-to-end through `writeBufferedReport`.

- [ ] **Step 1: Write the implementation** (no RED step: pure formatting of already-validated data, same as the `emailgw_coverage.go` precedent)

```go
package reporting

// WAF coverage report -- HTML only (no PDF; same deliberately
// lightweight first production-wiring pass as EmailGW's and WebGW's
// own reports). This package only formats; it consumes
// internal/wafefficacy's AudspectWAFCoverageReport and knows nothing
// about how coverage data is built.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/wafefficacy"
)

// WAFCoverageDomainEntry is one domain's status, carried into the
// report verbatim from internal/wafefficacy.
type WAFCoverageDomainEntry struct {
	DomainID        string
	DomainName      string
	Status          string
	ExclusionReason string
}

// WAFCoverageReport is the canonical input to WAFCoverageReportHTML.
// Build it with BuildWAFCoverageReport.
type WAFCoverageReport struct {
	GeneratedAt time.Time
	Summary     string
	Domains     []WAFCoverageDomainEntry
}

// BuildWAFCoverageReport builds the report from wafefficacy's real,
// current coverage report -- the same data the /api/waf/coverage JSON
// endpoint serves, so the HTML report can never drift from it.
func BuildWAFCoverageReport() (WAFCoverageReport, error) {
	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		return WAFCoverageReport{}, fmt.Errorf("loading WAF coverage report: %w", err)
	}

	domains := report.DomainsForDisplay()
	entries := make([]WAFCoverageDomainEntry, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, WAFCoverageDomainEntry{
			DomainID:        d.DomainID,
			DomainName:      d.DomainName,
			Status:          string(d.Status),
			ExclusionReason: d.ExclusionReason,
		})
	}

	return WAFCoverageReport{
		GeneratedAt: time.Now().UTC(),
		Summary:     report.Summary(),
		Domains:     entries,
	}, nil
}

var wafCoverageReportTmpl = template.Must(template.New("waf-coverage").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Coverage</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.summary{font-size:.85rem;color:#3a4656;font-family:monospace;margin-bottom:24px}
.domain{border:1px solid #e8edf4;border-radius:8px;padding:12px 20px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:baseline}
.domain h2{font-size:.95rem;font-weight:800;margin:0}
.status{font-size:.75rem;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px}
.status-covered{background:#e3f6e8;color:#1a7d3f}
.status-excluded{background:#fdeee0;color:#b35c00}
.status-not-covered{background:#f2f3f5;color:#5a6472}
.exclusion-reason{font-size:.75rem;color:#6b7689;margin-top:4px}
</style>
</head>
<body>
<h1>WAF Coverage</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
<div class="summary">{{.Summary}}</div>
{{range .Domains}}
<div class="domain">
  <div>
    <h2>{{.DomainID}} -- {{.DomainName}}</h2>
    {{if .ExclusionReason}}<div class="exclusion-reason">{{.ExclusionReason}}</div>{{end}}
  </div>
  <span class="status status-{{.Status}}">{{.Status}}</span>
</div>
{{end}}
</body>
</html>
`))

// WAFCoverageReportHTML renders the report as a plain styled HTML
// page. html/template auto-escapes every field, so a status or
// exclusion reason can never inject markup into the page.
func WAFCoverageReportHTML(w io.Writer, rep WAFCoverageReport) error {
	return wafCoverageReportTmpl.Execute(w, rep)
}
```

This references `report.DomainsForDisplay()`, which Task 1's `CoverageReport` does not yet expose (its `domains` field is unexported, by design, so callers can't bypass `NewCoverageReport`'s validation). Add this reader method to `orchestrator/internal/wafefficacy/coverage.go` as part of this task, with its own test in `coverage_test.go`:

```go
// DomainsForDisplay returns every domain this report holds, in the
// order they were given to NewCoverageReport -- the only way a caller
// outside this package can read domain-level detail (DomainID,
// DomainName, Status, ExclusionReason) for rendering. It exists
// because CoverageReport's domains field is unexported by design, so
// a reporting layer cannot bypass NewCoverageReport's validation by
// constructing a CoverageReport directly.
func (r CoverageReport) DomainsForDisplay() []DomainCoverage {
	out := make([]DomainCoverage, len(r.domains))
	copy(out, r.domains)
	return out
}
```

```go
func TestDomainsForDisplay_ReturnsAllDomainsInOrder(t *testing.T) {
	r := mustReport(t)
	got := r.DomainsForDisplay()
	if len(got) != 3 {
		t.Fatalf("len(DomainsForDisplay()) = %d, want 3", len(got))
	}
	if got[0].DomainID != "01" || got[1].DomainID != "02" || got[2].DomainID != "03" {
		t.Errorf("DomainsForDisplay() order = %v, want 01,02,03", []string{got[0].DomainID, got[1].DomainID, got[2].DomainID})
	}
}
```

- [ ] **Step 2: Run the new wafefficacy test and the reporting build**

Run: `cd orchestrator && go test ./internal/wafefficacy/... -run DomainsForDisplay -v && go build ./internal/reporting/...`
Expected: `DomainsForDisplay` test PASSES; `internal/reporting` builds with no errors.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/wafefficacy/coverage.go orchestrator/internal/wafefficacy/coverage_test.go orchestrator/internal/reporting/waf_coverage.go
git commit -m "feat(reporting): WAF coverage HTML report, mirroring emailgw_coverage.go"
```

---

## Task 4: API handlers for coverage

**Files:**
- Create: `orchestrator/internal/api/waf_efficacy_handlers.go`
- Test: `orchestrator/internal/api/waf_efficacy_handlers_test.go`

**Interfaces:**
- Consumes: Task 1/2's `wafefficacy.AudspectWAFCoverageReport()`, `DomainCoverage`; Task 3's `reporting.BuildWAFCoverageReport()`, `reporting.WAFCoverageReportHTML`; the package's existing `respond(w http.ResponseWriter, v interface{})` (`orchestrator/internal/api/handlers.go:3977`) and `writeBufferedReport(w http.ResponseWriter, contentType, disposition, logLabel string, render func(io.Writer) error)` (`orchestrator/internal/api/report_render.go:34`).
- Produces: `(h *Handler) GetWAFCoverage(w http.ResponseWriter, r *http.Request)`, `(h *Handler) GetWAFCoverageHTML(w http.ResponseWriter, r *http.Request)`.

The test pattern below mirrors `orchestrator/internal/api/emailgw_handlers_test.go` exactly: construct a bare `&Handler{}`, call the method directly with `httptest.NewRecorder()`/`httptest.NewRequest()` — no running server, no port binding.

**Note on the error branch (Review Focus):** `GetWAFCoverage`/`GetWAFCoverageHTML`'s `500` paths trigger only if `wafefficacy.AudspectWAFCoverageReport()` or `reporting.BuildWAFCoverageReport()` returns an error. Both call `NewCoverageReport` with a hardcoded, always-valid 10-domain literal (no duplicate IDs, every status one of the 3 known constants, no excluded domain) — the same "declared but structurally unreachable without editing the seed data itself" situation as `wafdetection`'s `EvidenceInconclusive`. No test forces this path; the doc comment on `GetWAFCoverage` below records why.

- [ ] **Step 1: Write the failing tests**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafefficacy"
)

func TestGetWAFCoverage_ReturnsEveryDomain(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/waf/coverage", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var got struct {
		Summary string                       `json:"summary"`
		Domains []wafefficacy.DomainCoverage `json:"domains"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	if len(got.Domains) != report.Denominator() {
		t.Fatalf("len(Domains) = %d, want %d", len(got.Domains), report.Denominator())
	}
	if got.Summary != report.Summary() {
		t.Errorf("Summary = %q, want %q -- the handler must serve the real, current report", got.Summary, report.Summary())
	}
}

func TestGetWAFCoverageHTML_RendersEveryDomain(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFCoverageHTML(rr, httptest.NewRequest(http.MethodGet, "/api/waf/coverage.html", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q, want text/html; charset=utf-8", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not a full HTML document")
	}

	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWAFCoverageReport: %v", err)
	}
	for _, d := range report.DomainsForDisplay() {
		if !strings.Contains(body, d.DomainID) {
			t.Errorf("body missing domain ID %q", d.DomainID)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetWAFCoverage -v`
Expected: FAIL — `h.GetWAFCoverage`/`h.GetWAFCoverageHTML` undefined on `*Handler`.

- [ ] **Step 3: Write minimal implementation**

```go
package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/wafefficacy"
)

// wafCoverageResponse is the JSON shape served by GetWAFCoverage --
// the report's own Summary() text alongside every domain's status,
// straight from internal/wafefficacy. Read-only; computes nothing of
// its own.
type wafCoverageResponse struct {
	Summary string                       `json:"summary"`
	Domains []wafefficacy.DomainCoverage `json:"domains"`
}

// GetWAFCoverage returns Audspect's real, current WAF BAS Mastery
// coverage report (internal/wafefficacy's AudspectWAFCoverageReport).
// Its error branch is structurally unreachable today: the seed
// function's domain literal is hardcoded and always passes
// NewCoverageReport's validation, so no test forces this path --
// documented here rather than left silently untested, same as
// wafdetection's EvidenceInconclusive precedent.
func (h *Handler) GetWAFCoverage(w http.ResponseWriter, r *http.Request) {
	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading coverage report: %v", err), http.StatusInternalServerError)
		return
	}
	respond(w, wafCoverageResponse{Summary: report.Summary(), Domains: report.DomainsForDisplay()})
}

// GetWAFCoverageHTML serves the same data as GetWAFCoverage, rendered
// as a styled HTML report (internal/reporting), so it can never drift
// from the JSON endpoint.
func (h *Handler) GetWAFCoverageHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildWAFCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "waf coverage html",
		func(out io.Writer) error { return reporting.WAFCoverageReportHTML(out, rep) })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetWAFCoverage -v`
Expected: PASS, both tests green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/waf_efficacy_handlers.go orchestrator/internal/api/waf_efficacy_handlers_test.go
git commit -m "feat(api): GetWAFCoverage/GetWAFCoverageHTML handlers, mirroring emailgw_handlers.go"
```

---

## Task 5: Reporting renderer for industry profiles

**Files:**
- Create: `orchestrator/internal/reporting/waf_industry_profiles.go`
- Test: `orchestrator/internal/reporting/waf_industry_profiles_test.go`

**Interfaces:**
- Consumes: `wafprofile.AudspectWAFProfileCatalog() ([]wafprofile.Profile, error)`; `wafprofile.Profile{ID, Name string; Kind wafprofile.ProfileKind; AttackVectorIDs []string; ComplianceReferences []wafprofile.ComplianceReference; Rationale, Provenance string}`; `wafprofile.ComplianceReference{Framework string; VerificationStatus wafprofile.VerificationStatus; Note, SourceURL string}`.
- Produces: `WAFIndustryProfileComplianceEntry{Framework, VerificationStatus, Note, SourceURL string}`, `WAFIndustryProfileEntry{ID, Name, Kind string; AttackVectorIDs []string; ComplianceReferences []WAFIndustryProfileComplianceEntry; Rationale string}`, `WAFIndustryProfileReport{GeneratedAt time.Time; Profiles []WAFIndustryProfileEntry}`, `BuildWAFIndustryProfileReport() (WAFIndustryProfileReport, error)`, `WAFIndustryProfileReportHTML(w io.Writer, rep WAFIndustryProfileReport) error`.

Unlike Task 3 (pure formatting of an already-exhaustively-tested `CoverageReport`), this task's `Build...` function does its own field-mapping from `wafprofile.Profile`, so it gets a real test proving the mapping is lossless — specifically that `VerificationStatus` and `Note` survive verbatim, per this plan's Review Focus.

- [ ] **Step 1: Write the failing test**

```go
package reporting

import (
	"bytes"
	"strings"
	"testing"
)

// Review Focus: every ComplianceReference's VerificationStatus and
// Note must survive into the built report verbatim -- this is the
// direct anti-regression test against the documented webgwefficacy
// stale-RBI-circular precedent (a compliance claim silently going
// stale or being summarized away).
func TestBuildWAFIndustryProfileReport_PreservesComplianceDetailVerbatim(t *testing.T) {
	rep, err := BuildWAFIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildWAFIndustryProfileReport: %v", err)
	}
	if len(rep.Profiles) != 6 {
		t.Fatalf("len(Profiles) = %d, want 6", len(rep.Profiles))
	}

	var found bool
	for _, p := range rep.Profiles {
		if p.ID != "WAFPROFILE-BFSI" {
			continue
		}
		found = true
		var sawUnverified bool
		var sawRealNote bool
		for _, c := range p.ComplianceReferences {
			if c.VerificationStatus == "unverified" {
				sawUnverified = true
			}
			if strings.Contains(c.Note, "no specific circular number or clause verified against RBI's own text") {
				sawRealNote = true
			}
		}
		if !sawUnverified {
			t.Error("WAFPROFILE-BFSI: no complianceReference has VerificationStatus \"unverified\"")
		}
		if !sawRealNote {
			t.Error("WAFPROFILE-BFSI: the real RBI Note text was not preserved verbatim")
		}
	}
	if !found {
		t.Fatal("WAFPROFILE-BFSI not found in built report")
	}
}

func TestWAFIndustryProfileReportHTML_RendersComplianceDetail(t *testing.T) {
	rep, err := BuildWAFIndustryProfileReport()
	if err != nil {
		t.Fatalf("BuildWAFIndustryProfileReport: %v", err)
	}
	var buf bytes.Buffer
	if err := WAFIndustryProfileReportHTML(&buf, rep); err != nil {
		t.Fatalf("WAFIndustryProfileReportHTML: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "unverified") {
		t.Error("HTML body missing \"unverified\" status")
	}
	if !strings.Contains(body, "no specific circular number or clause verified against RBI's own text") {
		t.Error("HTML body missing the real RBI Note text")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run WAFIndustryProfile -v`
Expected: FAIL — `BuildWAFIndustryProfileReport`/`WAFIndustryProfileReportHTML` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
package reporting

// WAF industry-profile report -- HTML only (no PDF; same
// deliberately lightweight first production-wiring pass as the WAF
// coverage report). This package only formats; it consumes
// internal/wafprofile's AudspectWAFProfileCatalog directly -- there is
// no separate internal/wafefficacy type for industry profiles, since
// wafprofile.Profile already is the shape (unlike WebGW, which layers
// a priority/weighting type over its coverage report). Every
// ComplianceReference field renders verbatim: this report can never
// show a compliance claim stronger than what wafprofile itself
// asserts.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/wafprofile"
)

// WAFIndustryProfileComplianceEntry is one compliance reference,
// carried into the report verbatim from internal/wafprofile.
type WAFIndustryProfileComplianceEntry struct {
	Framework          string
	VerificationStatus string
	Note               string
	SourceURL          string
}

// WAFIndustryProfileEntry is one shipped industry/regional profile,
// carried into the report verbatim from internal/wafprofile.
type WAFIndustryProfileEntry struct {
	ID                   string
	Name                 string
	Kind                 string
	AttackVectorIDs      []string
	ComplianceReferences []WAFIndustryProfileComplianceEntry
	Rationale            string
}

// WAFIndustryProfileReport is the canonical input to
// WAFIndustryProfileReportHTML. Build it with
// BuildWAFIndustryProfileReport.
type WAFIndustryProfileReport struct {
	GeneratedAt time.Time
	Profiles    []WAFIndustryProfileEntry
}

// BuildWAFIndustryProfileReport builds the report from wafprofile's
// real, current 6 industry/regional profiles -- the same data the
// /api/waf/industry-profiles JSON endpoint serves, so the HTML report
// can never drift from it.
func BuildWAFIndustryProfileReport() (WAFIndustryProfileReport, error) {
	profiles, err := wafprofile.AudspectWAFProfileCatalog()
	if err != nil {
		return WAFIndustryProfileReport{}, fmt.Errorf("loading WAF profile catalog: %w", err)
	}

	entries := make([]WAFIndustryProfileEntry, 0, len(profiles))
	for _, p := range profiles {
		refs := make([]WAFIndustryProfileComplianceEntry, 0, len(p.ComplianceReferences))
		for _, c := range p.ComplianceReferences {
			refs = append(refs, WAFIndustryProfileComplianceEntry{
				Framework:          c.Framework,
				VerificationStatus: string(c.VerificationStatus),
				Note:               c.Note,
				SourceURL:          c.SourceURL,
			})
		}
		entries = append(entries, WAFIndustryProfileEntry{
			ID:                   p.ID,
			Name:                 p.Name,
			Kind:                 string(p.Kind),
			AttackVectorIDs:      p.AttackVectorIDs,
			ComplianceReferences: refs,
			Rationale:            p.Rationale,
		})
	}

	return WAFIndustryProfileReport{
		GeneratedAt: time.Now().UTC(),
		Profiles:    entries,
	}, nil
}

var wafIndustryProfileReportTmpl = template.Must(template.New("waf-industry-profiles").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Industry Profiles</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:24px}
.profile{border:1px solid #e8edf4;border-radius:8px;padding:16px 20px;margin-bottom:16px}
.profile h2{font-size:1rem;font-weight:800;margin-bottom:8px}
.kind{font-size:.7rem;text-transform:uppercase;color:#6b7689;margin-bottom:8px}
.rationale{font-size:.85rem;margin-bottom:8px}
.vectors{font-size:.75rem;color:#3a4656;font-family:monospace;margin-bottom:8px}
.compliance{border-top:1px solid #f2f3f5;padding-top:8px;margin-top:8px}
.compliance-row{font-size:.75rem;margin-bottom:4px}
.compliance-status{font-weight:700;text-transform:uppercase;margin-right:6px}
</style>
</head>
<body>
<h1>WAF Industry Profiles</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
{{range .Profiles}}
<div class="profile">
  <h2>{{.ID}} -- {{.Name}}</h2>
  <div class="kind">{{.Kind}}</div>
  <div class="rationale">{{.Rationale}}</div>
  <div class="vectors">vectors: {{range $i, $v := .AttackVectorIDs}}{{if $i}}, {{end}}{{$v}}{{end}}</div>
  <div class="compliance">
  {{range .ComplianceReferences}}
    <div class="compliance-row"><span class="compliance-status">{{.VerificationStatus}}</span>{{.Framework}} -- {{.Note}}</div>
  {{end}}
  </div>
</div>
{{end}}
</body>
</html>
`))

// WAFIndustryProfileReportHTML renders the report as a plain styled
// HTML page. html/template auto-escapes every field, so a note or
// framework name can never inject markup into the page.
func WAFIndustryProfileReportHTML(w io.Writer, rep WAFIndustryProfileReport) error {
	return wafIndustryProfileReportTmpl.Execute(w, rep)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run WAFIndustryProfile -v`
Expected: PASS, both tests green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/reporting/waf_industry_profiles.go orchestrator/internal/reporting/waf_industry_profiles_test.go
git commit -m "feat(reporting): WAF industry-profile HTML report, preserving compliance detail verbatim"
```

---

## Task 6: API handlers for industry profiles

**Files:**
- Modify: `orchestrator/internal/api/waf_efficacy_handlers.go`
- Modify: `orchestrator/internal/api/waf_efficacy_handlers_test.go`

**Interfaces:**
- Consumes: `wafprofile.AudspectWAFProfileCatalog()`, `wafprofile.Profile`, `wafprofile.ComplianceReference`; Task 5's `reporting.BuildWAFIndustryProfileReport()`, `reporting.WAFIndustryProfileReportHTML`.
- Produces: `(h *Handler) GetWAFIndustryProfiles(w http.ResponseWriter, r *http.Request)`, `(h *Handler) GetWAFIndustryProfilesHTML(w http.ResponseWriter, r *http.Request)`.

**Note on the error branch (Review Focus):** `GetWAFIndustryProfiles`/`GetWAFIndustryProfilesHTML`'s `500` paths trigger only if `wafprofile.AudspectWAFProfileCatalog()` returns an error, which itself only happens if `ValidateAgainstCatalog` finds a profile referencing an attack-vector ID absent from the real `wafcatalog` output — a condition that can't occur with `wafprofile`'s own hardcoded, already-tested seed data. Same "structurally unreachable without editing the seed data" situation as Task 4's `GetWAFCoverage`; no test forces it, and the doc comment below records why.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/waf_efficacy_handlers_test.go`:

```go
func TestGetWAFIndustryProfiles_ReturnsSixProfilesWithComplianceDetail(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFIndustryProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/waf/industry-profiles", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"id":"WAFPROFILE-BFSI"`) {
		t.Error("body missing WAFPROFILE-BFSI")
	}
	if !strings.Contains(body, "unverified") {
		t.Error("body missing \"unverified\" status")
	}
	if !strings.Contains(body, "no specific circular number or clause verified against RBI's own text") {
		t.Error("body missing the real RBI Note text verbatim")
	}

	var got []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("len(profiles) = %d, want 6", len(got))
	}
}

func TestGetWAFIndustryProfilesHTML_RendersComplianceDetail(t *testing.T) {
	h := &Handler{}
	rr := httptest.NewRecorder()
	h.GetWAFIndustryProfilesHTML(rr, httptest.NewRequest(http.MethodGet, "/api/waf/industry-profiles.html", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not a full HTML document")
	}
	if !strings.Contains(body, "unverified") {
		t.Error("body missing \"unverified\" status")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetWAFIndustryProfiles -v`
Expected: FAIL — `h.GetWAFIndustryProfiles`/`h.GetWAFIndustryProfilesHTML` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `orchestrator/internal/api/waf_efficacy_handlers.go`:

```go
// wafIndustryProfileComplianceResponse is one compliance reference in
// the JSON shape served by GetWAFIndustryProfiles -- camelCase field
// names per this package's existing JSON convention.
type wafIndustryProfileComplianceResponse struct {
	Framework          string `json:"framework"`
	VerificationStatus string `json:"verificationStatus"`
	Note               string `json:"note"`
	SourceURL          string `json:"sourceUrl,omitempty"`
}

// wafIndustryProfileResponse is one shipped industry/regional
// profile in the JSON shape served by GetWAFIndustryProfiles.
type wafIndustryProfileResponse struct {
	ID                   string                                  `json:"id"`
	Name                 string                                  `json:"name"`
	Kind                 string                                  `json:"kind"`
	AttackVectorIDs      []string                                `json:"attackVectorIds"`
	ComplianceReferences []wafIndustryProfileComplianceResponse `json:"complianceReferences"`
	Rationale            string                                  `json:"rationale"`
}

// GetWAFIndustryProfiles returns Audspect's real, current 6 WAF
// industry/regional profiles (internal/wafprofile's
// AudspectWAFProfileCatalog), unmodified. Every ComplianceReference's
// VerificationStatus and Note render verbatim -- never summarized or
// dropped. Its error branch is structurally unreachable today -- see
// this handler's task note in the implementation plan -- documented
// here rather than left silently untested.
func (h *Handler) GetWAFIndustryProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := wafprofile.AudspectWAFProfileCatalog()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading profile catalog: %v", err), http.StatusInternalServerError)
		return
	}

	out := make([]wafIndustryProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		refs := make([]wafIndustryProfileComplianceResponse, 0, len(p.ComplianceReferences))
		for _, c := range p.ComplianceReferences {
			refs = append(refs, wafIndustryProfileComplianceResponse{
				Framework:          c.Framework,
				VerificationStatus: string(c.VerificationStatus),
				Note:               c.Note,
				SourceURL:          c.SourceURL,
			})
		}
		out = append(out, wafIndustryProfileResponse{
			ID:                   p.ID,
			Name:                 p.Name,
			Kind:                 string(p.Kind),
			AttackVectorIDs:      p.AttackVectorIDs,
			ComplianceReferences: refs,
			Rationale:            p.Rationale,
		})
	}
	respond(w, out)
}

// GetWAFIndustryProfilesHTML serves the same data as
// GetWAFIndustryProfiles, rendered as a styled HTML report
// (internal/reporting), so it can never drift from the JSON endpoint.
func (h *Handler) GetWAFIndustryProfilesHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildWAFIndustryProfileReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "waf industry profiles html",
		func(out io.Writer) error { return reporting.WAFIndustryProfileReportHTML(out, rep) })
}
```

Add `"github.com/audspect/bas/internal/wafprofile"` to this file's existing import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetWAFCoverage|TestGetWAFIndustryProfiles" -v`
Expected: PASS, all 4 handler tests green.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/waf_efficacy_handlers.go orchestrator/internal/api/waf_efficacy_handlers_test.go
git commit -m "feat(api): GetWAFIndustryProfiles/GetWAFIndustryProfilesHTML, preserving compliance detail verbatim"
```

---

## Task 7: Route registration

**Files:**
- Modify: `orchestrator/internal/api/routes.go` (insert after the existing `/api/emailgw/coverage.html` line, ~line 242 — read directly before editing to re-confirm the exact insertion point, since other concurrent work may have shifted line numbers)

**Interfaces:**
- Consumes: Task 4's `h.GetWAFCoverage`/`h.GetWAFCoverageHTML`; Task 6's `h.GetWAFIndustryProfiles`/`h.GetWAFIndustryProfilesHTML`.
- Produces: 4 live routes.

- [ ] **Step 1: Confirm no existing `/api/waf/` route (Review Focus: no collision)**

Run: `cd orchestrator && grep -n "/api/waf/" internal/api/routes.go`
Expected: no output (no prior registration exists).

- [ ] **Step 2: Register the 4 routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing line `r.Get("/api/emailgw/coverage.html", h.GetEmailGWCoverageHTML)`, insert:

```go
		// WAF coverage report (internal/wafefficacy), same read-only
		// shape as /api/emailgw/coverage: Audspect's real, current WAF
		// BAS Mastery coverage data, never a computed verdict of its
		// own. Industry/regional profiles (internal/wafprofile) are a
		// separate surface below, mirroring WebGW's own split between
		// coverage and industry profiles.
		r.Get("/api/waf/coverage", h.GetWAFCoverage)
		r.Get("/api/waf/coverage.html", h.GetWAFCoverageHTML)
		r.Get("/api/waf/industry-profiles", h.GetWAFIndustryProfiles)
		r.Get("/api/waf/industry-profiles.html", h.GetWAFIndustryProfilesHTML)
```

- [ ] **Step 3: Build and run the full `internal/api` + `internal/reporting` + `internal/wafefficacy` test suites**

Run: `cd orchestrator && go build ./... && go vet ./internal/api/... ./internal/reporting/... ./internal/wafefficacy/... && go test ./internal/api/... ./internal/reporting/... ./internal/wafefficacy/... -count=1`
Expected: clean build, clean vet, all tests pass (including every pre-existing test in these 3 packages — a route-table edit must not break anything already there).

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/routes.go
git commit -m "feat(api): register /api/waf/coverage and /api/waf/industry-profiles routes"
```

---

## Final Verification

After Task 7's commit, run the full relevant-package suite once more to confirm nothing regressed end-to-end:

```bash
cd orchestrator && go build ./... && go vet ./internal/waf... ./internal/api/... ./internal/reporting/... && go test ./internal/waf... ./internal/api/... ./internal/reporting/... -count=1
```

Expected: clean build, clean vet, all tests pass across every `internal/waf*` package, `internal/api`, and `internal/reporting`.
