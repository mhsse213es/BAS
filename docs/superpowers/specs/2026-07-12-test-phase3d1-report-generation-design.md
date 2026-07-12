# Test Phase 3d.1 — Report Generation: Design

**Date:** 2026-07-12
**Scope:** Characterization tests for the report-generation API handlers in `orchestrator/internal/api` — run-scoped reports, agent-level full reports + audit pack, campaign reports, and the reports hub — plus one end-to-end composition test. Continues the test-generation initiative (Phases 0–3b complete; see `2026-07-09-test-generation-strategy-design.md`).

## Context

Phase 3d covers Reporting & Compliance and is split into two sub-phases:

- **3d.1 (this spec):** report generation — 14 symbols across 4 handler groups + 1 E2E capstone.
- **3d.2 (separate spec, next):** compliance — `ListComplianceFrameworks`, `GetComplianceReport`, `GetComplianceDashboardScores`, `refreshComplianceSnapshots` (the compliance fan-out deferred from 3b.2), `complianceShortName`.

Exercise reports (`GetExerciseReport{JSON,HTML,PDF,CSV}`) and variant coverage (`GetVariantCoverageReport`, `GetVariantMatrix`) are deferred to **3e**.

The rendering internals — `internal/reporting` (engine, HTML, PDF, forensic CSV, audit pack, kill chain, insights) and `internal/compliance` — already carry their own unit tests with golden files. 3d.1 tests the **handler contract layer**: parameter validation, data selection (which runs feed which report), response headers, filename construction, persistence (report_log), and error paths. Rendering correctness stays in `internal/reporting`; these tests assert **structural markers only**.

## Symbols under test

| # | Symbol | Location | Role |
|---|--------|----------|------|
| 1 | `GetRunReport` | handlers.go:4149 | Single-run HTML report |
| 2 | `GetRunReportData` | handlers.go:4173 | Run drawer JSON (findings/recs/kill-chain + alerts/perf columns) |
| 3 | `GetRunPDF` | handlers.go:4033 | Single-run PDF |
| 4 | `GetRunForensicCSV` | handlers.go:4092 | Single-run forensic CSV |
| 5 | `GetFullReportHTML` | handlers.go:3547 | Agent-level HTML report (with compliance summary rows) |
| 6 | `GetFullReportPDF` | handlers.go:3773 | Agent-level PDF (latest-run detail section) |
| 7 | `GetFullReportCSV` | handlers.go:3827 | Agent-level forensic CSV (latest run) |
| 8 | `GetAuditPack` | handlers.go:3874 | ZIP audit pack |
| 9 | `complianceRows` | handlers.go:3575 | Per-framework summary rows (aggregate) |
| 10 | `aggregateAgentResults` | handlers.go:3604 | Union of all completed/partial runs, dedup by result ID |
| 11 | `sanitizeFilename` | handlers.go:3755 | Pure — filename-safe slug, 32-char cap |
| 12 | `GetCampaignReport` / `GetCampaignPDF` / `GetCampaignCSV` | campaign_handlers.go:303/325/351 | Campaign (fleet) HTML/PDF/CSV |
| 13 | `reportDownloadPath` | report_handlers.go:16 | Pure — reconstructs generator URL from type+params |
| 14 | `CreateReport` / `ListReports` | report_handlers.go:64/105 | Reports hub: report_log persistence + history listing |

## Harness & construction

- Package `api`, container-backed via the existing `sharedDB.RunWithPool(t, fn)` harness; every test starts with the `testing.Short()` skip guard.
- Handler construction extends the existing pattern:
  ```go
  h := New(pool, ws.NewHub(), scenarioEngine, "").
      WithReporting(reporting.NewEngine(pool).WithScenarios(scenarioEngine)).
      WithCompliance(mustMapper(t)) // compliance.NewMapper() — embedded FS, real frameworks
  ```
  Real reporting engine, real embedded-FS compliance mapper, no mocks. `mustMapper(t)` wraps `compliance.NewMapper()` with a `t.Fatalf` on error.
- **PDF determinism:** `CHROME_WS_URL` stays unset in tests, so `PDFFromReport`/`htmlToPDFViaChrome` always takes the **fpdf fallback** — the endpoint still returns real PDF bytes. The Chromium-sidecar path is environment-gated and **out of scope** (same rule as prior phases' OS-fault exclusions). Guard: if a future dev environment sets `CHROME_WS_URL`, PDF tests could silently switch paths — the fixture helper unsets it via `t.Setenv("CHROME_WS_URL", "")`.
- `h.auditLog` calls (report.export audit rows) are async goroutines — **not asserted** (3b.2's async-fan-out exclusion).

## Fixture design (refinement #3 — seed realistic data once)

One shared builder drives almost every test:

```go
// seedReportableRun inserts an agent row (hostname join) and a scenario_runs row
// with a realistic multi-verdict results payload. Returns the run ID.
seedReportableRun(t, pool, runID, agentID, opts...)
```

The canonical results payload (JSON array of `models.SimulationResult`) contains **5 results** spanning:

- **All four verdicts:** `pass`, `fail`, `error`, `skipped` (plus `fail` twice at different severities).
- **≥3 ATT&CK techniques** across **≥2 tactics** — e.g. `T1059.001` PowerShell (execution), `T1003.001` LSASS Memory (credential-access), `T1547.001` Registry Run Keys (persistence) — enough for kill-chain and TopFindings to be non-empty.
- **Severity spread:** Critical / High / Medium / Low.
- **Timestamps:** distinct `executedAt` values (fixed, not `time.Now()`).
- **Remediation** populated on the FAIL results (drives recommendations).
- **Evidence fields** populated on at least one result: `command`, `exitCode`, `rawOutput`, `details`.
- **Distinct result `id`s** (UUID-like strings) — the dedup tests reuse one ID across two runs.

Options (variadic or an opts struct): status override (`completed`/`partial`/`running`), `started_at` override (to order latest-vs-older runs), campaign_id, custom results payload, run name. Also seeds the alerts/perf columns (`alerts_total`, `noise_score`, `perf_*`) with non-zero values so `GetRunReportData`'s column read is observable.

A thin `seedCampaign(t, pool, campaignID, ...)` inserts a `campaigns` row; campaign tests attach 2 child runs via the run builder's campaign_id option.

## Test matrices

### Group 1 — Run-scoped reports (`run_report_api_test.go`)

*(file name avoids colliding with `internal/reporting/campaign_report_test.go` conventions and any existing api test files)*

| Test | Pins |
|------|------|
| `TestGetRunReport_HTML` | 200; `Content-Type: text/html`; body contains seeded technique ID `T1059.001`, technique name, and scenario/run name; body non-empty |
| `TestGetRunReport_NotFound` | Unknown runId → 404 |
| `TestGetRunReportData_Shape` | 200 JSON; `topFindings` non-empty; `recommendations` non-empty; `killChain` present; seeded `alertsTotal`/`noiseScore`/`perf*` values round-tripped |
| `TestGetRunReportData_NotFound` | Unknown runId → 404 |
| `TestGetRunPDF_Success` | 200; `Content-Type: application/pdf`; body starts `%PDF`; body length > 0; `Content-Disposition` matches `bas-report-<scen>-<host>-<id8>.pdf` pattern (regex, never exact — hostname/scenario sanitized) |
| `TestGetRunPDF_NotFound` | Unknown runId → 404 |
| `TestGetRunForensicCSV_Success` | 200; `Content-Type: text/csv`; header row present; one data row per seeded result; row for `T1059.001` present; `Content-Disposition` matches `bas-forensic-*.csv` |
| `TestGetRunForensicCSV_FilterApplied` | `?filter=prevented` (`FilterResults` keeps only `pass`/`blocked` results) reduces rows and adds the `-prevented` suffix to the filename |
| `TestGetRunForensicCSV_NotFound` | Unknown runId → 404 |

### Group 2 — Agent-level full reports (`full_report_api_test.go`)

| Test | Pins |
|------|------|
| `TestGetFullReportHTML_Success` | 200 HTML; contains seeded technique + hostname; **compliance summary rows present** (mapper attached → framework names appear) |
| `TestGetFullReportHTML_NoMapper` | Handler without `WithCompliance` → still 200, report renders without compliance rows (`complianceRows` returns nil) |
| `TestFullReport_MissingAgentID_Matrix` | Table over all four agent-level endpoints (`GetFullReportHTML`/`PDF`/`CSV`, `GetAuditPack`): no `agentId` → 400 on each |
| `TestGetFullReportPDF_Success` | 200; `%PDF` magic; filename pattern `bas-report-<scen>-<host>-<date>.pdf` |
| `TestGetFullReportCSV_LatestRunOnly` | **Aggregate-vs-latest pin (refinement #9):** two completed runs with different techniques; CSV contains only the later run's technique, not the older one's |
| `TestGetFullReportCSV_NoCompletedRun` | Agent with no completed/partial runs → 404 |
| `TestGetAuditPack_ZeroRunsGuard` | No completed runs → 422 |
| `TestGetAuditPack_ZIPStructure` | 200; `Content-Type: application/zip`; parse with `archive/zip`; **assert expected entries exist** (refinement #5): `README.txt`, `summary.json`, `executive-report.html`, `executive-report.pdf`, `agent-inventory.json`, `MANIFEST.txt`, ≥1 `runs/*.json`, ≥1 `compliance/*.csv`; assert entry count ≥ 8; assert one entry's content contains seeded data (`runs/*.json` contains `T1059.001`) |
| `TestAggregateAgentResults_DedupAndUnion` | **Refinement #9:** two completed runs sharing one result ID + each holding a unique one → aggregate returns 3 results (shared ID exactly once); a `running`-status run's results excluded. White-box call on `h.aggregateAgentResults` (same package) |
| `TestComplianceRows_AggregatesAllRuns` | Rows returned for every mapper framework; a technique present only in the *older* run still influences rows (proves aggregate, not latest) |
| `TestSanitizeFilename_Table` | **Refinement #7 — exhaustive pure table:** spaces, slashes (`/`, `\`), unicode (multi-byte → per-byte `_`), reserved chars (`:*?"<>|`), dots, empty string, exactly-32, >32 (capped at 32), all-safe passthrough |

### Group 4 — Campaign reports (`campaign_report_api_test.go`)

| Test | Pins |
|------|------|
| `TestGetCampaignReport_HTML` | Campaign + 2 child runs (different agents); 200 HTML; contains both runs' techniques (fleet aggregation) |
| `TestGetCampaignReport_NotFound` | Unknown campaign → 404 |
| `TestGetCampaignPDF_Success` | 200; `%PDF`; filename `bas-campaign-*.pdf` |
| `TestGetCampaignCSV_AllChildRuns` | 200 CSV; rows from both child runs present; filename `bas-campaign-forensic-*.csv`; unknown campaign → 404 (same test, second request) |
| `TestGetCampaignCSV_FilterApplied` | Filter reduces rows, suffix in filename |

### Group 5 — Reports hub (`reports_hub_test.go`)

| Test | Pins |
|------|------|
| `TestReportDownloadPath_Table` | **Refinement #7 — full pure table:** every report type (`posture`/`audit`/`compliance`) × format (`pdf`/`html`/`csv`/empty) × missing-required-param errors (posture/audit without agentId; compliance without framework or agentId) × invalid type; filter propagation (`filter=failed` appended, `filter=all` and empty omitted); URL-escaping of agentId/framework values |
| `TestCreateReport_PersistsAndReturnsPath` | Authed POST (via `callAuthed` so claims populate `generated_by`); 200 with `id` + `downloadPath`; `report_log` row exists with `source='reports_hub'`, `status='generated'`, `generated_by=<user>`, parameters JSON round-trips |
| `TestCreateReport_InvalidType` | Bad `reportType` → 400 |
| `TestCreateReport_MalformedJSON` | Broken body → 400, no report_log row |
| `TestListReports_ReconstructsPath` | Seed a report_log row (via CreateReport); GET returns it with a freshly built `downloadPath` matching `reportDownloadPath`'s output; ordered by `generated_at DESC`; ≤100 rows contract noted |

### Shared error matrix (`report_nil_engine_test.go`) — refinement #6

One table-driven test, **not** duplicated per handler: a handler constructed **without** `WithReporting` (and where relevant without `WithCompliance`), looped over every reporting-engine-dependent endpoint in 3d.1 scope — `GetRunReport`, `GetRunReportData`, `GetRunPDF`, `GetFullReportHTML`, `GetFullReportPDF`, `GetFullReportCSV`, `GetAuditPack`, `GetCampaignReport`, `GetCampaignPDF` — each must return **503** with the "reporting engine not loaded" error. (`GetRunForensicCSV`, `GetCampaignCSV`, `CreateReport`, `ListReports` don't touch the engine — noted in the table as excluded, which itself documents the contract.)

### Report-consistency invariant (`report_consistency_test.go`) — refinement #2

One test, one seeded run, three endpoints:
- `GetRunReport` HTML body contains `T1059.001`
- `GetRunForensicCSV` body contains `T1059.001`
- `GetRunPDF` returns `%PDF` + 200 (structural marker only — fpdf output is compressed, so no content grep)

Catches an endpoint accidentally querying different data than its siblings (e.g. one switching from `results` to a different column/filter).

### E2E capstone (`e2e_report_flow_test.go`) — refinement #1

**Exactly one test**, proving composition only — every assertion here is already covered in depth elsewhere; this test exists to prove the seams:

1. Save a scenario via `scenario.Engine.Save` (authoring — 3b.3 territory).
2. Dispatch via the real `RunScenario` handler with a `startFakeAgent` connected to the hub (3b.1 helper); fake agent receives the scenario command and captures the run ID.
3. Submit a MAC-signed result payload via `SubmitScenarioResult` (3b.2 helpers `signResultMAC`) containing technique `T1059.001` with verdict `fail`.
4. Fetch `GetRunReport` (HTML contains `T1059.001`), `GetRunForensicCSV` (row present), `GetRunPDF` (`%PDF`).

No branches, no error cases, no format variations — those live in the group files. If this test grows, it's being misused.

## Response-header contract (refinement #4 — applied across all groups)

Every success-path test asserts, where applicable:
- `Content-Type` exact value.
- `Content-Disposition` filename **pattern** (regex — date/`time.Now()` parts and sanitized names never asserted byte-exact).
- **Body length > 0** (via `rec.Body.Len()`; `Content-Length` itself is not set by these streaming handlers, and `httptest.ResponseRecorder` wouldn't surface a transport-added one — the body-length assertion is the meaningful equivalent).
- `Cache-Control`: **no 3d.1 handler currently sets it** — the consistency test asserts it is absent, characterizing today's contract so a future addition is a visible diff.

## Out of scope (documented, deliberate)

- Chromium-sidecar PDF path (`CHROME_WS_URL` set) — environment-gated; fpdf fallback is the tested path.
- `auditLog` goroutines (async fan-out exclusion).
- DB-fault branches (`Query`/`Scan` failures needing fault injection) — same honest-ceiling rule as all prior phases.
- Rendering correctness (layout, page counts, template details) — `internal/reporting`'s own tests (refinement #8).
- Exercise reports, variant coverage → 3e. Compliance handlers → 3d.2.
- RBAC on report routes — already pinned by 3a's 167-route matrix.

## Validation chain

Same as 3b.3, commit-gated per the user's standing instruction: build → vet → staticcheck → full `go test ./...` → `-count=10` stress on the new tests → coverage review (`go tool cover -func`, per-function, gap-closing for real authoring-contract branches only) → then commits.

## Expected file list

| File | Contents |
|------|----------|
| `internal/api/report_fixtures_test.go` | `seedReportableRun`, `seedCampaign`, `mustMapper`, canonical results payload builder |
| `internal/api/run_report_api_test.go` | Group 1 (9 tests) |
| `internal/api/full_report_api_test.go` | Group 2 (11 tests) |
| `internal/api/campaign_report_api_test.go` | Group 4 (5 tests) |
| `internal/api/reports_hub_test.go` | Group 5 (5 tests) |
| `internal/api/report_nil_engine_test.go` | Shared 503 matrix (1 table test) |
| `internal/api/report_consistency_test.go` | Cross-format invariant (1 test) |
| `internal/api/e2e_report_flow_test.go` | E2E capstone (1 test) |

~33 test functions. No production files change (test-only phase; any real bug found gets flagged to the user first, per standing rules).
