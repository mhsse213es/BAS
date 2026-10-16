# WAF BAS Mastery Console Integration — Design Spec

## 1. Scope

The 10-phase WAF BAS Mastery initiative (`internal/wafval` through `internal/wafverify`, all merged on `main`) is pure backend domain logic: types, evaluation functions, and seed catalogs, fully unit-tested. Confirmed by grep: zero references to any of the 10 packages anywhere in `internal/api`, `internal/reporting`, `web/src`, or `scenarios/`. After a rebuild today, nothing new appears in the Audspect console.

This phase wires the existing work into the console as **two read-only report surfaces**, following a pattern already proven twice in this codebase for structurally identical "mastery initiative" work: `internal/webgwefficacy` (Secure Web Gateway) and `internal/emailgwefficacy` (Email Gateway). Both expose a coverage report and (WebGW only) an industry-profile view as `GET /api/<name>/<thing>` JSON + `.html` pairs registered in `internal/api/routes.go`, rendered via `internal/reporting`, with no `web/src` component — the HTML endpoint is the console surface.

**Explicitly out of scope, deferred to a separate future phase with its own brainstorm:** any live HTTP-probing execution engine, any new scenario-executor type, any campaign/run/agent dispatch wiring, any `scenarios/*.yaml` WAF entries, and any `web/src` React component. Today's 10 WAF packages are evaluators over caller-supplied evidence; nothing actually sends a request to a target WAF and collects real evidence. That gap is real and is not addressed here — this phase only makes the backend's existing, honest state visible in the console, the same way `webgwefficacy`/`emailgwefficacy` surface *their* real, current state without claiming more than what's proven.

## 2. New package: `internal/wafefficacy`

A new, independent package, named to match the sibling convention (`webgwefficacy`, `emailgwefficacy`). It depends read-only on all 10 `internal/waf*` packages plus stdlib `fmt`/`strings`. **No cross-import with `webgwefficacy` or `emailgwefficacy`** — each "mastery" efficacy package is self-contained by convention, not inheritance, exactly as `emailgwefficacy`'s own `types.go` states ("independent of internal/controlval, internal/webgwefficacy... never unified with webgwefficacy's wording"). This also means `wafefficacy` does **not** import `webgwefficacy`'s `regulatory.go`, which still cites a now-superseded RBI circular never fixed there (a documented, real instance of exactly the failure mode `wafprofile`'s `Unverified`-only discipline exists to prevent) — `wafefficacy` carries no regulatory citations of its own at all; it only renders what `wafprofile` already asserts, verbatim.

### 2.1 Coverage report

```go
type CoverageStatus string
const (
    CoverageCovered    CoverageStatus = "covered"
    CoverageExcluded   CoverageStatus = "excluded"
    CoverageNotCovered CoverageStatus = "not-covered"
)

type DomainCoverage struct {
    DomainID        string
    DomainName      string
    Status          CoverageStatus
    ExclusionReason string // required when Status == CoverageExcluded
}

type CoverageReport struct { domains []DomainCoverage }

func NewCoverageReport(domains []DomainCoverage) (CoverageReport, error)
```
Validation (mirrors `webgwefficacy.NewCoverageReport` exactly, independently implemented): no duplicate `DomainID`; `Status` must be one of the 3 constants; `CoverageExcluded` requires a non-empty `ExclusionReason`.

```go
func (r CoverageReport) Denominator() int
func (r CoverageReport) CoveredCount() int
func (r CoverageReport) ExcludedCount() int
func (r CoverageReport) NotCoveredCount() int
func (r CoverageReport) Exclusions() []string
func (r CoverageReport) Summary() string
```
`Summary()` renders the covered/denominator count and every exclusion's reason, **plus one fixed, always-rendered disclosure sentence that cannot be dropped by a future edit**: that every domain below is evaluator-only, evaluated against caller-supplied (today, fixture) evidence, with no live HTTP-probing execution against a real target yet. This is a report-level caveat, not a per-domain `ExclusionReason` — nothing here is excluded, every domain genuinely has real, tested, reviewed code — but a reader must never be able to mistake "Covered" for "this runs against your live WAF today."

```go
func AudspectWAFCoverageReport() (CoverageReport, error)
```
Returns exactly these 10 domains, 1:1 with `waf.txt`'s own phase list, all `CoverageCovered` (honest under the established "at least one fixture-backed, proven scenario exists" definition — confirmed true for all 10, each phase shipped a fresh-reviewer-approved, tested package):

| DomainID | DomainName (verbatim from `waf.txt`) | Package |
|---|---|---|
| 01 | WAF capability and vendor-neutral model | `wafval` |
| 02 | Core attack-prevention mastery | `wafcatalog` |
| 03 | Configuration and policy-gap testing | `wafpolicygap` |
| 04 | Protocol, parser and evasion testing | `wafevasion` |
| 05 | API and business-flow protection | `wafapiflow` |
| 06 | Bot, abuse and rate-limit efficacy | `wafbotabuse` |
| 07 | Origin, deployment and resilience | `waforigin` |
| 08 | Detection and telemetry validation | `wafdetection` |
| 09 | Industry and regional profiles | `wafprofile` |
| 10 | Independent verification and continuous mastery | `wafverify` |

### 2.2 Industry profiles

No new type: `wafprofile.Profile` (via `wafprofile.AudspectWAFProfileCatalog()`) already is the industry/regional-profile shape (unlike WebGW, which layers a separate priority/weighting type over its coverage report — WAF doesn't need that second layer since `wafprofile` already built profiles directly against real attack-vector IDs). `wafefficacy` adds nothing here beyond a thin JSON-shaping helper the handler uses directly (see §3).

## 3. API routes (`internal/api`)

New file `internal/api/waf_efficacy_handlers.go`, following `emailgw_handlers.go`'s exact structure:

```go
func (h *Handler) GetWAFCoverage(w http.ResponseWriter, r *http.Request)
func (h *Handler) GetWAFCoverageHTML(w http.ResponseWriter, r *http.Request)
func (h *Handler) GetWAFIndustryProfiles(w http.ResponseWriter, r *http.Request)
func (h *Handler) GetWAFIndustryProfilesHTML(w http.ResponseWriter, r *http.Request)
```

- `GetWAFCoverage` calls `wafefficacy.AudspectWAFCoverageReport()`, responds JSON `{summary string, domains []DomainCoverage}` via the existing `respond()` helper. A build/compute error → `http.StatusInternalServerError` with the error text (no other error path exists: the handler computes nothing itself).
- `GetWAFCoverageHTML` calls `reporting.BuildWAFCoverageReport()` / `reporting.WAFCoverageReportHTML(out, rep)` via the existing `writeBufferedReport` helper, exactly mirroring `GetEmailGWCoverageHTML`.
- `GetWAFIndustryProfiles` calls `wafprofile.AudspectWAFProfileCatalog()` directly and responds JSON as a flat array of the 6 `Profile` structs (field names camelCased per the existing JSON convention: `id`, `name`, `kind`, `attackVectorIds`, `complianceReferences` with nested `framework`/`verificationStatus`/`note`/`sourceUrl`, `rationale`). Every `ComplianceReference`'s `verificationStatus` and `note` render verbatim — the handler never summarizes or drops them.
- `GetWAFIndustryProfilesHTML` mirrors the JSON handler via `reporting.BuildWAFIndustryProfileReport()` / `reporting.WAFIndustryProfileReportHTML`.

Routes registered in `internal/api/routes.go`, adjacent to the existing `webgw`/`emailgw` block, with the same read-only comment style:
```go
r.Get("/api/waf/coverage", h.GetWAFCoverage)
r.Get("/api/waf/coverage.html", h.GetWAFCoverageHTML)
r.Get("/api/waf/industry-profiles", h.GetWAFIndustryProfiles)
r.Get("/api/waf/industry-profiles.html", h.GetWAFIndustryProfilesHTML)
```

## 4. Reporting (`internal/reporting`)

Two new files, mirroring `emailgw_coverage.go`'s structure and `writeBufferedReport` usage exactly:
- `waf_coverage.go`: `BuildWAFCoverageReport() (WAFCoverageReport, error)`, `WAFCoverageReportHTML(out io.Writer, rep WAFCoverageReport) error`. The HTML template renders the summary line (including the fixed evaluator-only/no-live-execution disclosure), the 10-domain table, and (if ever non-empty) the exclusions list.
- `waf_industry_profiles.go`: `BuildWAFIndustryProfileReport() (WAFIndustryProfileReport, error)`, `WAFIndustryProfileReportHTML(out io.Writer, rep WAFIndustryProfileReport) error`. Renders each of the 6 profiles' name, kind, attack-vector IDs, rationale, and every compliance reference's framework/status/note — the HTML can never show a compliance claim stronger than what `wafprofile` itself asserts.

## 5. Acceptance gate

1. `wafefficacy.NewCoverageReport` rejects a duplicate `DomainID` and a `CoverageExcluded` entry with an empty `ExclusionReason`; accepts valid input.
2. `wafefficacy.CoverageReport.Summary()` always contains the fixed evaluator-only/no-live-execution disclosure sentence, regardless of domain contents.
3. `wafefficacy.AudspectWAFCoverageReport()` returns exactly the 10 domains in §2.1's table, all `CoverageCovered`, cross-checked against `waf.txt`'s own phase list (not just a count).
4. `GetWAFCoverage`/`GetWAFCoverageHTML` return the real report's data; a forced build error (test-only) returns `500` with the error text.
5. `GetWAFIndustryProfiles`/`GetWAFIndustryProfilesHTML` return exactly `wafprofile.AudspectWAFProfileCatalog()`'s 6 real profiles, with every `ComplianceReference`'s `VerificationStatus`/`Note` present verbatim in the JSON and HTML output (a test must assert the string `"unverified"` and at least one real `Note` substring appear in both).
6. `internal/reporting`'s two new HTML renderers produce valid, non-empty HTML containing the same data the JSON endpoints serve (no drift between the two).
7. New routes respond `200` on a running server (an integration-style test matching the existing `webgw_industry_profile_handlers_test.go`/`emailgw_handlers_test.go` pattern).

## 6. Deferred (explicitly)

- Any live HTTP-probing execution engine against a real target WAF.
- Any new scenario-executor type, `scenarios/*.yaml` WAF entries, or campaign/run/agent dispatch wiring.
- Any `web/src` React/SPA component — the HTML report endpoints are the console surface for this phase, matching the `webgw`/`emailgw` precedent exactly.
- Any regulatory citation more specific than what `wafprofile` already asserts (`Unverified`, framework-name-only) — `wafefficacy` adds no compliance claims of its own.
- A second, WebGW-style `IndustryProfile` priority/weighting layer over `wafprofile`'s profiles — not needed since `wafprofile` already built profiles directly against real attack-vector IDs.
