# Phase 3d.1 Report-Generation Tests — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add characterization tests for the 14 report-generation symbols in `orchestrator/internal/api` plus one end-to-end composition test, locking the handler-contract layer (parameter validation, data selection, response headers, filename construction, report_log persistence, error paths) without duplicating `internal/reporting`'s rendering golden tests.

**Architecture:** Container-backed tests in package `api` using the existing `sharedDB.RunWithPool` harness. Handlers built with a real `reporting.Engine` and real embedded-FS `compliance.Mapper` — no mocks. One shared fixture (`seedReportableRun`) writes a realistic multi-verdict `scenario_runs.results` payload that drives almost every test. Assertions are structural markers (status, `Content-Type`, `Content-Disposition` filename regex, body-length, key content substrings, ZIP entry lists) — never byte-exact rendered output.

**Tech Stack:** Go, `testing`, `net/http/httptest`, `archive/zip`, testcontainers-backed Postgres (`sharedDB`), pgx.

## Global Constraints

- **Test-only phase.** No production files change. A genuine product bug found mid-work is flagged to the user before any fix (per standing "minimal changes" rule).
- Every container-backed test starts with `if testing.Short() { t.Skip("skipping container-backed test in -short mode") }`.
- Package is `api` (white-box — same package as production, matching all existing api tests).
- PDF tests keep `CHROME_WS_URL` unset (fpdf fallback path) via `t.Setenv("CHROME_WS_URL", "")` in the fixture helper. Chromium sidecar path is out of scope.
- `auditLog` goroutines, DB-fault branches, and rendering correctness are out of scope (documented in spec).
- Filename assertions use regex/prefix/suffix matching — never assert `time.Now()` date bytes or sanitized host/scenario names exactly.
- Commit cadence: **defer all commits until the full validation chain is green** IF the user chooses that gating again at execution handoff; otherwise commit per-task as written below. (Default below = commit per task; the executing session may override.)
- Commit trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Push immediately after each commit (or after the final batch, per gating choice).

---

## Existing helpers this plan reuses (do not redefine)

From `result_ingestion_helpers_test.go`:
- `signResultMAC(secret string, body []byte) string`
- `seedRunRow(t, pool, runID, scenarioID, agentID, status string)` — inserts an agent (hostname `'h'`, ON CONFLICT DO NOTHING) + a `scenario_runs` row with `started_at=NOW()` and default empty `results='[]'`.
- `rawResultBody(t, raw scenario.RawRunResult) []byte`
- `submitResultReq` / `validSubmitResultReq`
- `startFakeBrowser(t, hub) *fakeBrowser`

From `run_dispatch_helpers_test.go`:
- `startFakeAgent(t, hub *ws.Hub, agentID string) *fakeAgent` (has `.WaitForMessage(t, timeout)`, `.Disconnect(t)`)
- `wsProbeMessage() models.WSMessage`
- `wsEnvelope` struct

From `submit_scenario_result_test.go`:
- `submitResultOK(t, h *Handler, raw scenario.RawRunResult)`
- `readRunResults(t, pool, runID) []models.SimulationResult`

From `run_scenario_gates_test.go`:
- `runScenarioReq(scenarioID string, body map[string]any) *http.Request`
- `seedActiveAgent(t, pool, agentID, osVersion string)`
- `minimalLiveScenario(t, id, steps...) (*scenario.Scenario, *scenario.Engine)`
- `minimalPostureScenario(t, id) (*scenario.Scenario, *scenario.Engine)`

From `event_handlers_test.go`:
- `withURLParam(r *http.Request, key, val string) *http.Request`

From `testmain_test.go`:
- `sharedDB *testutil.TestDB`, `seedUser`, `authedRequest`, `callAuthed`

Production reference (read-only):
- `reporting.NewEngine(pool).WithScenarios(engine)` — `reporting.NewEngine(db *pgxpool.Pool) *Engine`.
- `compliance.NewMapper() (*compliance.Mapper, error)`.
- `New(db, hub, engine, secret).WithReporting(e).WithCompliance(m)`.
- `models.SimulationResult` JSON tags: `id`, `technique{id,name,tactic}`, `result` (`pass`/`fail`/`error`/`skipped`), `severity`, `threatImpact`, `details`, `remediation`, `rawOutput`, `durationMs`, `executedAt`, `command`, `exitCode`, `startedAt`.
- `scenario_runs` columns used: `id, scenario_id, agent_id, name, status, results, started_at, alerts_total, alerts_high_fidelity, noise_score, perf_cpu_before/after, perf_ram_before/after, perf_disk_before/after, campaign_id`.
- `agents` columns for hostname join: `agent_id, hostname, os_version, state, security_products`.
- `campaigns` columns: `id, name, scenario_id, scenario_name, mode`.
- `report_log` columns: `id, report_type, format, scope_label, parameters, source, status, generated_by, generated_at`.
- Audit-pack ZIP entries (`reporting/auditpack.go`): `README.txt`, `summary.json`, `executive-report.html`, `executive-report.pdf`, `agent-inventory.json`, `MANIFEST.txt`, `runs/<name>-<id8>.json`, `compliance/<fwID>.csv`.
- `reporting.FilterResults` values: `""`/`all` (passthrough), `prevented` (keeps `pass`/`blocked`), `not_prevented`, `detected`, others.

---

### Task 1: Shared fixtures

**Files:**
- Create: `orchestrator/internal/api/report_fixtures_test.go`

**Interfaces:**
- Produces:
  - `mustMapper(t *testing.T) *compliance.Mapper`
  - `newReportingHandler(t *testing.T, pool *pgxpool.Pool, engine *scenario.Engine) *Handler` — builds `New(...).WithReporting(...).WithCompliance(...)`, sets `t.Setenv("CHROME_WS_URL", "")`.
  - `canonicalResults() []models.SimulationResult` — 5 results, all four verdicts, 3 techniques / 2 tactics, severity spread, remediation on FAILs, evidence on ≥1, distinct IDs, fixed timestamps.
  - `seedReportableRun(t, pool, runID, agentID string, opts reportRunOpts)` — inserts agent (rich columns) + `scenario_runs` row; returns nothing.
  - `reportRunOpts` struct: `Status string` (default `"completed"`), `StartedAt time.Time` (zero → `NOW()`), `CampaignID string`, `Name string`, `Results []models.SimulationResult` (nil → `canonicalResults()`), `TechniqueOverride string` (optional single-technique convenience for aggregate/latest tests).
  - `seedCampaign(t, pool, campaignID, scenarioName string)`

- [ ] **Step 1: Write the fixtures file**

```go
package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mustMapper loads the real embedded-FS compliance mapper or fails the test.
func mustMapper(t *testing.T) *compliance.Mapper {
	t.Helper()
	m, err := compliance.NewMapper()
	if err != nil {
		t.Fatalf("compliance.NewMapper: %v", err)
	}
	return m
}

// newReportingHandler builds a Handler wired with a real reporting engine and
// compliance mapper. CHROME_WS_URL is cleared so PDF rendering deterministically
// takes the built-in fpdf fallback rather than the Chromium sidecar.
func newReportingHandler(t *testing.T, pool *pgxpool.Pool, engine *scenario.Engine) *Handler {
	t.Helper()
	t.Setenv("CHROME_WS_URL", "")
	if engine == nil {
		engine = scenario.NewEngine(t.TempDir())
	}
	return New(pool, ws.NewHub(), engine, "").
		WithReporting(reporting.NewEngine(pool).WithScenarios(engine)).
		WithCompliance(mustMapper(t))
}

// canonicalResults is the realistic multi-verdict payload that drives almost
// every 3d.1 report test: all four verdicts, three ATT&CK techniques across two
// tactics, a severity spread, remediation text on the FAILs (drives
// recommendations), and evidence fields on at least one result. Timestamps are
// fixed (never time.Now()) so nothing here is non-deterministic.
func canonicalResults() []models.SimulationResult {
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return []models.SimulationResult{
		{
			ID:           "res-fail-crit",
			Technique:    models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"},
			Result:       models.ResultFail,
			Severity:     "Critical",
			ThreatImpact: "Arbitrary code execution",
			Details:      "PowerShell downgrade attack succeeded",
			Remediation:  "Enable Constrained Language Mode and script-block logging",
			RawOutput:    "PS> IEX(...)",
			Command:      "powershell -enc ...",
			ExitCode:     0,
			DurationMs:   1200,
			ExecutedAt:   base,
			StartedAt:    base,
		},
		{
			ID:           "res-fail-high",
			Technique:    models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory", Tactic: "credential-access"},
			Result:       models.ResultFail,
			Severity:     "High",
			ThreatImpact: "Credential theft",
			Details:      "LSASS dump not blocked",
			Remediation:  "Enable Credential Guard and LSA protection",
			ExecutedAt:   base.Add(1 * time.Minute),
			StartedAt:    base.Add(1 * time.Minute),
		},
		{
			ID:         "res-pass",
			Technique:  models.AttackTechnique{ID: "T1547.001", Name: "Registry Run Keys", Tactic: "persistence"},
			Result:     models.ResultPass,
			Severity:   "Medium",
			Details:    "Run-key write blocked by control",
			ExecutedAt: base.Add(2 * time.Minute),
			StartedAt:  base.Add(2 * time.Minute),
		},
		{
			ID:         "res-error",
			Technique:  models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"},
			Result:     models.ResultError,
			Severity:   "Low",
			Details:    "Technique errored (missing prerequisite)",
			ExecutedAt: base.Add(3 * time.Minute),
			StartedAt:  base.Add(3 * time.Minute),
		},
		{
			ID:         "res-skipped",
			Technique:  models.AttackTechnique{ID: "T1112", Name: "Modify Registry", Tactic: "defense-evasion"},
			Result:     models.ResultSkipped,
			Severity:   "Low",
			Details:    "Skipped — OS mismatch",
			ExecutedAt: base.Add(4 * time.Minute),
			StartedAt:  base.Add(4 * time.Minute),
		},
	}
}

type reportRunOpts struct {
	Status            string
	StartedAt         time.Time
	CampaignID        string
	Name              string
	Results           []models.SimulationResult
	TechniqueOverride string
}

// seedReportableRun inserts a rich agents row (all report-relevant columns
// populated so the report engine renders a hostname and security context) and a
// scenario_runs row carrying a realistic results payload plus non-zero
// alerts/perf columns (so GetRunReportData's column read is observable).
func seedReportableRun(t *testing.T, pool *pgxpool.Pool, runID, agentID string, opts reportRunOpts) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, ip_address, os_version, username, status, env_label, state, security_products)
		 VALUES ($1,$2,'10.0.0.5','Windows 11','svc-bas','idle','Production','active','["Defender"]')
		 ON CONFLICT (agent_id) DO NOTHING`,
		agentID, "host-"+agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	results := opts.Results
	if results == nil {
		results = canonicalResults()
	}
	if opts.TechniqueOverride != "" {
		results = []models.SimulationResult{{
			ID:         "res-" + opts.TechniqueOverride,
			Technique:  models.AttackTechnique{ID: opts.TechniqueOverride, Name: "Override", Tactic: "execution"},
			Result:     models.ResultFail,
			Severity:   "High",
			ExecutedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			StartedAt:  time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		}}
	}
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}

	status := opts.Status
	if status == "" {
		status = "completed"
	}
	name := opts.Name
	if name == "" {
		name = "Report Test Run"
	}

	// started_at: explicit if provided, else NOW().
	var startedExpr string
	args := []any{runID, agentID, name, status, resultsJSON}
	if !opts.StartedAt.IsZero() {
		startedExpr = "$6"
		args = append(args, opts.StartedAt)
	} else {
		startedExpr = "NOW()"
	}
	campaignExpr := "NULL"
	if opts.CampaignID != "" {
		campaignExpr = "$" + itoa(len(args)+1)
		args = append(args, opts.CampaignID)
	}

	q := `INSERT INTO scenario_runs
	        (id, scenario_id, agent_id, name, status, results, started_at, campaign_id,
	         alerts_total, alerts_high_fidelity, noise_score,
	         perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after)
	      VALUES ($1,'sc-report',$2,$3,$4,$5,` + startedExpr + `,` + campaignExpr + `,
	         42, 7, 3.5, 10, 25, 30, 55, 1, 2)`
	if _, err := pool.Exec(ctx, q, args...); err != nil {
		t.Fatalf("seed reportable run: %v", err)
	}
}

// itoa avoids importing strconv just for parameter-index building.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func seedCampaign(t *testing.T, pool *pgxpool.Pool, campaignID, scenarioName string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO campaigns (id, name, scenario_id, scenario_name, mode)
		 VALUES ($1,$2,'sc-report',$3,'posture')`,
		campaignID, "Campaign "+campaignID, scenarioName); err != nil {
		t.Fatalf("seed campaign: %v", err)
	}
}
```

- [ ] **Step 2: Verify the package compiles**

Run: `cd orchestrator && go vet ./internal/api/`
Expected: no errors. (Fixtures are package-level funcs; unused ones don't fail the build — Go only errors on unused imports/locals. If `go vet` flags an unused import, remove it; every import above is used by later tasks so keep them.)

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/report_fixtures_test.go
git commit -m "test(api): add Phase 3d.1 report-generation fixtures"
```

---

### Task 2: Run-scoped report tests (Group 1)

**Files:**
- Create: `orchestrator/internal/api/run_report_api_test.go`

**Interfaces:**
- Consumes: `newReportingHandler`, `seedReportableRun`, `withURLParam`, `canonicalResults`.

- [ ] **Step 1: Write the tests**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGetRunReport_HTML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-html", "agent-rr-html", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-html/report", nil), "runId", "rr-html")
		rec := httptest.NewRecorder()
		h.GetRunReport(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("content-type = %q", ct)
		}
		body := rec.Body.String()
		if rec.Body.Len() == 0 {
			t.Fatal("empty body")
		}
		if !strings.Contains(body, "T1059.001") {
			t.Fatalf("HTML report missing seeded technique T1059.001")
		}
	})
}

func TestGetRunReport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/report", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunReport(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunReportData_Shape(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-data", "agent-rr-data", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-data/report.json", nil), "runId", "rr-data")
		rec := httptest.NewRecorder()
		h.GetRunReportData(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Seeded alerts/perf columns round-trip.
		if out["alertsTotal"].(float64) != 42 {
			t.Fatalf("alertsTotal = %v, want 42", out["alertsTotal"])
		}
		if out["noiseScore"].(float64) != 3.5 {
			t.Fatalf("noiseScore = %v, want 3.5", out["noiseScore"])
		}
		if _, ok := out["topFindings"]; !ok {
			t.Fatal("missing topFindings key")
		}
		if _, ok := out["killChain"]; !ok {
			t.Fatal("missing killChain key")
		}
	})
}

func TestGetRunReportData_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/report.json", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunReportData(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

var pdfMagic = []byte("%PDF")

func TestGetRunPDF_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-pdf", "agent-rr-pdf", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-pdf/pdf", nil), "runId", "rr-pdf")
		rec := httptest.NewRecorder()
		h.GetRunPDF(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body len = %d", rec.Code, rec.Body.Len())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
			t.Fatalf("content-type = %q", ct)
		}
		if rec.Body.Len() == 0 || !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Fatalf("body is not a PDF (len=%d)", rec.Body.Len())
		}
		cd := rec.Header().Get("Content-Disposition")
		if !regexp.MustCompile(`filename="bas-report-.*\.pdf"`).MatchString(cd) {
			t.Fatalf("content-disposition = %q", cd)
		}
	})
}

func TestGetRunPDF_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/pdf", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunPDF(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunForensicCSV_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-csv", "agent-rr-csv", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-csv/forensic.csv", nil), "runId", "rr-csv")
		rec := httptest.NewRecorder()
		h.GetRunForensicCSV(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Fatalf("content-type = %q", ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") {
			t.Fatalf("CSV missing seeded technique T1059.001:\n%s", body)
		}
		if !regexp.MustCompile(`filename="bas-forensic-.*\.csv"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

func TestGetRunForensicCSV_FilterApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-csv-f", "agent-rr-csv-f", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-csv-f/forensic.csv?filter=prevented", nil), "runId", "rr-csv-f")
		rec := httptest.NewRecorder()
		h.GetRunForensicCSV(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		// filter=prevented keeps only the single PASS result; the FAILs drop out.
		body := rec.Body.String()
		if strings.Contains(body, "T1059.001") {
			t.Fatalf("filter=prevented should have dropped the failing T1059.001 row:\n%s", body)
		}
		if !strings.Contains(body, "T1547.001") {
			t.Fatalf("filter=prevented should keep the passing T1547.001 row:\n%s", body)
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), "-prevented-") {
			t.Fatalf("filename missing -prevented- suffix: %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

func TestGetRunForensicCSV_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/forensic.csv", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunForensicCSV(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Run the group**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestGetRun(Report|ReportData|PDF|ForensicCSV)' -v`
Expected: all PASS. If `filter=prevented` behaves differently than assumed (e.g. `blocked` vs `pass` handling), adjust the assertion to the observed FilterResults contract — the *product* is authoritative (characterization). Note any surprise for the coverage-review write-up.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/run_report_api_test.go
git commit -m "test(api): add run-scoped report handler tests (3d.1 group 1)"
```

---

### Task 3: Agent-level full report + audit pack + pure funcs (Group 2)

**Files:**
- Create: `orchestrator/internal/api/full_report_api_test.go`

**Interfaces:**
- Consumes: `newReportingHandler`, `seedReportableRun`, `mustMapper`, `withURLParam`, `canonicalResults`.

- [ ] **Step 1: Write the tests**

```go
package api

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fullReq(path, agentID string) *http.Request {
	if agentID != "" {
		path += "?agentId=" + agentID
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestGetFullReportHTML_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "fr-html", "agent-fr-html", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportHTML(rec, fullReq("/api/report/full/html", "agent-fr-html"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") {
			t.Fatal("full HTML report missing seeded technique")
		}
		// Compliance summary rows present because a mapper is attached — at least
		// one known framework short/name string should appear.
		if !strings.Contains(body, "SEBI") && !strings.Contains(body, "NIST") && !strings.Contains(body, "ISO") {
			t.Fatalf("expected compliance summary rows in full HTML report")
		}
	})
}

func TestGetFullReportHTML_NoMapper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "fr-nomap", "agent-fr-nomap", reportRunOpts{})
		// Handler WITHOUT WithCompliance — complianceRows returns nil, report still renders.
		engine := scenario.NewEngine(t.TempDir())
		t.Setenv("CHROME_WS_URL", "")
		h := New(pool, ws.NewHub(), engine, "").
			WithReporting(newReportingHandler(t, pool, engine).reportingEngine)
		rec := httptest.NewRecorder()
		h.GetFullReportHTML(rec, fullReq("/api/report/full/html", "agent-fr-nomap"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (report should render without a mapper)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "T1059.001") {
			t.Fatal("report body missing seeded technique")
		}
	})
}

func TestFullReport_MissingAgentID_Matrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		cases := []struct {
			name string
			fn   http.HandlerFunc
			path string
		}{
			{"html", h.GetFullReportHTML, "/api/report/full/html"},
			{"pdf", h.GetFullReportPDF, "/api/report/full/pdf"},
			{"csv", h.GetFullReportCSV, "/api/report/full/csv"},
			{"auditpack", h.GetAuditPack, "/api/report/audit-pack"},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			c.fn(rec, fullReq(c.path, "")) // no agentId
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestGetFullReportPDF_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "fr-pdf", "agent-fr-pdf", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportPDF(rec, fullReq("/api/report/full/pdf", "agent-fr-pdf"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/pdf" {
			t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
		}
		if !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Fatal("body is not a PDF")
		}
		if !regexp.MustCompile(`filename="bas-report-.*\.pdf"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

// TestGetFullReportCSV_LatestRunOnly pins that the agent-level CSV reflects only
// the LATEST completed/partial run, not older ones (business logic, not
// rendering). The older run carries T1003.001; the newer carries only the
// override technique — the CSV must contain the newer, not the older.
func TestGetFullReportCSV_LatestRunOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "agent-fr-latest"
		older := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
		newer := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "fr-old", agentID, reportRunOpts{StartedAt: older, TechniqueOverride: "T1003.001"})
		seedReportableRun(t, pool, "fr-new", agentID, reportRunOpts{StartedAt: newer, TechniqueOverride: "T1218.011"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportCSV(rec, fullReq("/api/report/full/csv", agentID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1218.011") {
			t.Fatalf("CSV should contain the latest run's technique T1218.011:\n%s", body)
		}
		if strings.Contains(body, "T1003.001") {
			t.Fatalf("CSV should NOT contain the older run's technique T1003.001 (latest-only):\n%s", body)
		}
	})
}

func TestGetFullReportCSV_NoCompletedRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// Agent exists (seeded via a running-only run) but no completed/partial run.
		seedReportableRun(t, pool, "fr-running", "agent-fr-none", reportRunOpts{Status: "running"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportCSV(rec, fullReq("/api/report/full/csv", "agent-fr-none"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetAuditPack_ZeroRunsGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "ap-running", "agent-ap-none", reportRunOpts{Status: "running"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetAuditPack(rec, fullReq("/api/report/audit-pack", "agent-ap-none"))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
	})
}

func TestGetAuditPack_ZIPStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "ap-ok", "agent-ap-ok", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetAuditPack(rec, fullReq("/api/report/audit-pack", "agent-ap-ok"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/zip" {
			t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
		}
		raw := rec.Body.Bytes()
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("not a valid zip: %v", err)
		}
		names := map[string]bool{}
		var runEntry string
		for _, f := range zr.File {
			names[f.Name] = true
			if strings.HasPrefix(f.Name, "runs/") {
				runEntry = f.Name
			}
		}
		for _, want := range []string{"README.txt", "summary.json", "executive-report.html", "agent-inventory.json", "MANIFEST.txt"} {
			if !names[want] {
				t.Fatalf("audit pack missing entry %q; have %v", want, names)
			}
		}
		if len(zr.File) < 6 {
			t.Fatalf("audit pack entry count = %d, want >= 6", len(zr.File))
		}
		if runEntry == "" {
			t.Fatal("audit pack has no runs/*.json entry")
		}
		// One entry contains seeded content.
		rf, err := zr.Open(runEntry)
		if err != nil {
			t.Fatalf("open run entry: %v", err)
		}
		defer rf.Close()
		content, _ := io.ReadAll(rf)
		if !strings.Contains(string(content), "T1059.001") {
			t.Fatalf("run entry %q missing seeded technique T1059.001", runEntry)
		}
	})
}

// TestAggregateAgentResults_DedupAndUnion pins the dedup-by-result-ID and
// union-across-completed/partial business logic (white-box call).
func TestAggregateAgentResults_DedupAndUnion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "agent-agg"
		shared := models.SimulationResult{ID: "shared-id", Technique: models.AttackTechnique{ID: "T1000"}, Result: models.ResultFail}
		uniqA := models.SimulationResult{ID: "uniq-a", Technique: models.AttackTechnique{ID: "T1001"}, Result: models.ResultPass}
		uniqB := models.SimulationResult{ID: "uniq-b", Technique: models.AttackTechnique{ID: "T1002"}, Result: models.ResultPass}
		seedReportableRun(t, pool, "agg-1", agentID, reportRunOpts{Status: "completed", Results: []models.SimulationResult{shared, uniqA}})
		seedReportableRun(t, pool, "agg-2", agentID, reportRunOpts{Status: "partial", Results: []models.SimulationResult{shared, uniqB}})
		seedReportableRun(t, pool, "agg-run", agentID, reportRunOpts{Status: "running", Results: []models.SimulationResult{{ID: "excluded", Result: models.ResultFail}}})
		h := newReportingHandler(t, pool, nil)
		got := h.aggregateAgentResults(newReqCtx(), agentID)
		ids := map[string]int{}
		for _, r := range got {
			ids[r.ID]++
		}
		if ids["shared-id"] != 1 {
			t.Fatalf("shared-id count = %d, want exactly 1 (dedup)", ids["shared-id"])
		}
		if ids["uniq-a"] != 1 || ids["uniq-b"] != 1 {
			t.Fatalf("expected both unique results present: %v", ids)
		}
		if ids["excluded"] != 0 {
			t.Fatal("running-status run's results must be excluded from aggregate")
		}
		if len(got) != 3 {
			t.Fatalf("aggregate len = %d, want 3", len(got))
		}
	})
}

func TestComplianceRows_AggregatesAllRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-1", "agent-cr", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rows := h.complianceRows(newReqCtx(), "agent-cr", "")
		if len(rows) == 0 {
			t.Fatal("expected compliance summary rows for every mapper framework")
		}
		if len(rows) != len(h.complianceMapper.Frameworks()) {
			t.Fatalf("row count = %d, want one per framework (%d)", len(rows), len(h.complianceMapper.Frameworks()))
		}
	})
}

func TestSanitizeFilename_Table(t *testing.T) {
	cases := []struct{ in, want string }{
		{"clean-name_1", "clean-name_1"},
		{"has spaces", "has_spaces"},
		{"a/b\\c", "a_b_c"},
		{"a:b*c?d\"e<f>g|h", "a_b_c_d_e_f_g_h"},
		{"dot.name", "dot_name"},
		{"", ""},
		{"", ""}, // placeholder replaced below for unicode
	}
	cases[6] = struct{ in, want string }{"café", "caf__"} // é is 2 bytes → 2 underscores
	for _, c := range cases {
		if got := sanitizeFilename(c.in); got != c.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// 32-char cap.
	long := strings.Repeat("x", 40)
	if got := sanitizeFilename(long); len(got) != 32 {
		t.Errorf("cap: len = %d, want 32", len(got))
	}
	exactly32 := strings.Repeat("y", 32)
	if got := sanitizeFilename(exactly32); got != exactly32 {
		t.Errorf("exactly-32 mangled: %q", got)
	}
}
```

Add the needed imports: this file also needs `context`, `github.com/audspect/bas/internal/models`. Add a tiny local `newReqCtx()` helper returning `context.Background()` (defined once here):

```go
func newReqCtx() context.Context { return context.Background() }
```

- [ ] **Step 2: Run the group**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestGetFullReport|TestFullReport_Missing|TestGetAuditPack|TestAggregateAgentResults|TestComplianceRows|TestSanitizeFilename' -v`
Expected: all PASS. If the compliance-row framework-name substring assertion misses (framework display names differ from `SEBI`/`NIST`/`ISO`), read `compliance/mappings/*.yaml` for the actual `name` values and adjust. If `café`→`caf__` byte-count differs on this platform's source encoding, compute the expected from `len([]byte("é"))`.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/full_report_api_test.go
git commit -m "test(api): add full-report/audit-pack/pure-fn tests (3d.1 group 2)"
```

---

### Task 4: Campaign report tests (Group 4)

**Files:**
- Create: `orchestrator/internal/api/campaign_report_api_test.go`

**Interfaces:**
- Consumes: `newReportingHandler`, `seedReportableRun`, `seedCampaign`, `withURLParam`.

- [ ] **Step 1: Write the tests**

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func campaignReq(path, campaignID, query string) *http.Request {
	if query != "" {
		path += "?" + query
	}
	return withURLParam(httptest.NewRequest(http.MethodGet, path, nil), "id", campaignID)
}

func seedCampaignWithRuns(t *testing.T, pool *pgxpool.Pool, campaignID string) {
	seedCampaign(t, pool, campaignID, "Fleet Scenario")
	seedReportableRun(t, pool, campaignID+"-r1", campaignID+"-a1", reportRunOpts{CampaignID: campaignID, TechniqueOverride: "T1059.001"})
	seedReportableRun(t, pool, campaignID+"-r2", campaignID+"-a2", reportRunOpts{CampaignID: campaignID, TechniqueOverride: "T1003.001"})
}

func TestGetCampaignReport_HTML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-html")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignReport(rec, campaignReq("/api/campaigns/camp-html/report", "camp-html", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") || !strings.Contains(body, "T1003.001") {
			t.Fatal("campaign HTML report should aggregate both child runs' techniques")
		}
	})
}

func TestGetCampaignReport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignReport(rec, campaignReq("/api/campaigns/nope/report", "nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetCampaignPDF_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-pdf")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignPDF(rec, campaignReq("/api/campaigns/camp-pdf/pdf", "camp-pdf", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Fatal("body is not a PDF")
		}
		if !regexp.MustCompile(`filename="bas-campaign-.*\.pdf"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

func TestGetCampaignCSV_AllChildRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-csv")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignCSV(rec, campaignReq("/api/campaigns/camp-csv/forensic.csv", "camp-csv", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") || !strings.Contains(body, "T1003.001") {
			t.Fatal("campaign CSV should include rows from both child runs")
		}
		if !regexp.MustCompile(`filename="bas-campaign-forensic-.*\.csv"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
		// unknown campaign → 404
		rec2 := httptest.NewRecorder()
		h.GetCampaignCSV(rec2, campaignReq("/api/campaigns/nope/forensic.csv", "nope", ""))
		if rec2.Code != http.StatusNotFound {
			t.Fatalf("unknown campaign: status = %d, want 404", rec2.Code)
		}
	})
}

func TestGetCampaignCSV_FilterApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedCampaignWithRuns(t, pool, "camp-csv-f")
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetCampaignCSV(rec, campaignReq("/api/campaigns/camp-csv-f/forensic.csv", "camp-csv-f", "filter=prevented"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		// Both override techniques are FAILs → prevented filter drops them both.
		body := rec.Body.String()
		if strings.Contains(body, "T1059.001") || strings.Contains(body, "T1003.001") {
			t.Fatalf("filter=prevented should drop the failing rows:\n%s", body)
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), "-prevented-") {
			t.Fatalf("filename missing -prevented- suffix: %q", rec.Header().Get("Content-Disposition"))
		}
	})
}
```

- [ ] **Step 2: Run the group**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestGetCampaign(Report|PDF|CSV)' -v`
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/campaign_report_api_test.go
git commit -m "test(api): add campaign report handler tests (3d.1 group 4)"
```

---

### Task 5: Reports hub tests (Group 5)

**Files:**
- Create: `orchestrator/internal/api/reports_hub_test.go`

**Interfaces:**
- Consumes: `newReportingHandler`, `seedReportableRun`, `authedRequest`, `callAuthed`, `sharedDB`.

- [ ] **Step 1: Write the tests**

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReportDownloadPath_Table exhaustively covers the pure URL reconstructor.
func TestReportDownloadPath_Table(t *testing.T) {
	cases := []struct {
		name                             string
		rtype, format, agent, fw, filter string
		wantErr                          bool
		wantContains                     []string
	}{
		{"posture pdf", "posture", "pdf", "a1", "", "", false, []string{"/api/report/full/pdf", "agentId=a1"}},
		{"posture html", "posture", "html", "a1", "", "", false, []string{"/api/report/full/html"}},
		{"posture csv", "posture", "csv", "a1", "", "", false, []string{"/api/report/full/csv"}},
		{"posture default→pdf", "posture", "", "a1", "", "", false, []string{"/api/report/full/pdf"}},
		{"posture no agent", "posture", "pdf", "", "", "", true, nil},
		{"posture filter", "posture", "pdf", "a1", "", "failed", false, []string{"filter=failed"}},
		{"posture filter=all omitted", "posture", "pdf", "a1", "", "all", false, []string{"/api/report/full/pdf"}},
		{"audit", "audit", "", "a1", "", "", false, []string{"/api/report/audit-pack", "agentId=a1"}},
		{"audit no agent", "audit", "", "", "", "", true, nil},
		{"compliance", "compliance", "json", "a1", "SEBI_CSCRF", "", false, []string{"/api/compliance/report", "framework=SEBI_CSCRF", "format=json"}},
		{"compliance default format", "compliance", "", "a1", "SEBI_CSCRF", "", false, []string{"format=html"}},
		{"compliance no fw", "compliance", "json", "a1", "", "", true, nil},
		{"compliance no agent", "compliance", "json", "", "SEBI_CSCRF", "", true, nil},
		{"invalid type", "bogus", "", "a1", "", "", true, nil},
		{"escaping", "compliance", "json", "a b", "F&W", "", false, []string{"agentId=a+b", "framework=F%26W"}},
	}
	for _, c := range cases {
		got, err := reportDownloadPath(c.rtype, c.format, c.agent, c.fw, c.filter)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got path %q", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		for _, sub := range c.wantContains {
			if !strings.Contains(got, sub) {
				t.Errorf("%s: path %q missing %q", c.name, got, sub)
			}
		}
	}
}

func TestCreateReport_PersistsAndReturnsPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		uid := seedUser(t, pool, "reporter", "pw-Password1!", "admin", true)
		h := newReportingHandler(t, pool, nil)
		body := `{"reportType":"posture","format":"pdf","agentId":"agent-x"}`
		req := authedRequest(t, http.MethodPost, "/api/reports", strings.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateReport, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !strings.Contains(out["downloadPath"].(string), "/api/report/full/pdf") {
			t.Fatalf("downloadPath = %v", out["downloadPath"])
		}
		var rtype, source, status, by string
		if err := pool.QueryRow(context.Background(),
			`SELECT report_type, source, status, COALESCE(generated_by,'') FROM report_log WHERE id=$1`,
			out["id"],
		).Scan(&rtype, &source, &status, &by); err != nil {
			t.Fatalf("report_log row not found: %v", err)
		}
		if rtype != "posture" || source != "reports_hub" || status != "generated" {
			t.Fatalf("row mismatch: type=%q source=%q status=%q", rtype, source, status)
		}
		if by != uid {
			t.Fatalf("generated_by = %q, want %q", by, uid)
		}
	})
}

func TestCreateReport_InvalidType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/reports", strings.NewReader(`{"reportType":"bogus"}`))
		rec := httptest.NewRecorder()
		h.CreateReport(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateReport_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/reports", strings.NewReader(`{"reportType":`))
		rec := httptest.NewRecorder()
		h.CreateReport(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM report_log`).Scan(&n)
		if n != 0 {
			t.Fatalf("malformed body should not persist a report_log row, found %d", n)
		}
	})
}

func TestListReports_ReconstructsPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		uid := seedUser(t, pool, "lister", "pw-Password1!", "admin", true)
		h := newReportingHandler(t, pool, nil)
		// Create a report via the real handler so the row shape is authentic.
		createReq := authedRequest(t, http.MethodPost, "/api/reports", strings.NewReader(`{"reportType":"compliance","format":"csv","agentId":"a9","framework":"SEBI_CSCRF"}`), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateReport, createReq); rec.Code != http.StatusOK {
			t.Fatalf("seed create status = %d", rec.Code)
		}
		listRec := httptest.NewRecorder()
		h.ListReports(listRec, httptest.NewRequest(http.MethodGet, "/api/reports", nil))
		if listRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", listRec.Code)
		}
		var out []map[string]any
		if err := json.Unmarshal(listRec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) == 0 {
			t.Fatal("expected at least one report row")
		}
		dp, _ := out[0]["downloadPath"].(string)
		if !strings.Contains(dp, "/api/compliance/report") || !strings.Contains(dp, "framework=SEBI_CSCRF") {
			t.Fatalf("reconstructed downloadPath = %q", dp)
		}
	})
}
```

- [ ] **Step 2: Run the group**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestReportDownloadPath|TestCreateReport|TestListReports' -v`
Expected: all PASS. If `auth.RoleAdmin` is spelled differently, grep `internal/auth` for the exact constant and use it.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/reports_hub_test.go
git commit -m "test(api): add reports-hub handler tests (3d.1 group 5)"
```

---

### Task 6: Nil-engine matrix + cross-format consistency invariant

**Files:**
- Create: `orchestrator/internal/api/report_nil_engine_test.go`
- Create: `orchestrator/internal/api/report_consistency_test.go`

**Interfaces:**
- Consumes: `seedReportableRun`, `newReportingHandler`, `withURLParam`, `fullReq`, `campaignReq`.

- [ ] **Step 1: Write the nil-engine matrix**

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReportHandlers_NilEngine503 covers every reporting-engine-dependent
// endpoint in 3d.1 scope with a Handler that has no reporting engine attached.
// Endpoints that do NOT touch the engine (GetRunForensicCSV, GetCampaignCSV,
// CreateReport, ListReports) are intentionally excluded — that exclusion itself
// documents which handlers depend on the engine.
func TestReportHandlers_NilEngine503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// No WithReporting — reportingEngine stays nil.
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cases := []struct {
			name string
			fn   http.HandlerFunc
			req  *http.Request
		}{
			{"GetRunReport", h.GetRunReport, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "r")},
			{"GetRunReportData", h.GetRunReportData, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "r")},
			{"GetRunPDF", h.GetRunPDF, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "r")},
			{"GetFullReportHTML", h.GetFullReportHTML, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetFullReportPDF", h.GetFullReportPDF, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetFullReportCSV", h.GetFullReportCSV, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetAuditPack", h.GetAuditPack, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetCampaignReport", h.GetCampaignReport, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "c")},
			{"GetCampaignPDF", h.GetCampaignPDF, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "c")},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			c.fn(rec, c.req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s: status = %d, want 503", c.name, rec.Code)
			}
		}
	})
}
```

- [ ] **Step 2: Write the consistency invariant**

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReportConsistency_SameDataAcrossFormats seeds one run and asserts every
// format exposes the same underlying technique — catching an endpoint that
// accidentally queries different data than its siblings. Cache-Control is
// asserted absent, characterizing today's contract.
func TestReportConsistency_SameDataAcrossFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "consist", "agent-consist", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)

		htmlRec := httptest.NewRecorder()
		h.GetRunReport(htmlRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "consist"))
		if !strings.Contains(htmlRec.Body.String(), "T1059.001") {
			t.Fatal("HTML missing T1059.001")
		}
		if cc := htmlRec.Header().Get("Cache-Control"); cc != "" {
			t.Fatalf("HTML unexpectedly sets Cache-Control=%q (contract change)", cc)
		}

		csvRec := httptest.NewRecorder()
		h.GetRunForensicCSV(csvRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "consist"))
		if !strings.Contains(csvRec.Body.String(), "T1059.001") {
			t.Fatal("CSV missing T1059.001")
		}

		pdfRec := httptest.NewRecorder()
		h.GetRunPDF(pdfRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "consist"))
		if pdfRec.Code != http.StatusOK || !strings.HasPrefix(pdfRec.Body.String(), "%PDF") {
			t.Fatalf("PDF not generated (status=%d)", pdfRec.Code)
		}
	})
}
```

- [ ] **Step 3: Run both**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestReportHandlers_NilEngine503|TestReportConsistency' -v`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/report_nil_engine_test.go orchestrator/internal/api/report_consistency_test.go
git commit -m "test(api): add nil-engine matrix + cross-format consistency (3d.1)"
```

---

### Task 7: E2E composition capstone (exactly one test)

**Files:**
- Create: `orchestrator/internal/api/e2e_report_flow_test.go`

**Interfaces:**
- Consumes: `minimalLiveScenario`, `seedActiveAgent`, `startFakeAgent`, `runScenarioReq`, `submitResultOK`, `newReportingHandler` pattern, `withURLParam`.

- [ ] **Step 1: Write the single capstone test**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestE2E_AuthoringToReporting proves the seams between the already-tested
// phases compose: author a scenario, dispatch it to a connected agent, ingest a
// MAC-signed result, then render the report. Every assertion here is covered in
// depth elsewhere — this test exists ONLY to prove composition. Do not grow it.
func TestE2E_AuthoringToReporting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// 1. Authoring: a live scenario with one T1059.001 step.
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059.001", Framework: "custom", Command: "echo hi"}}
		sc, engine := minimalLiveScenario(t, "e2e-sc", steps...)

		hub := ws.NewHub()
		t.Setenv("CHROME_WS_URL", "")
		h := New(pool, hub, engine, "").
			WithReporting(reporting.NewEngine(pool).WithScenarios(engine)).
			WithCompliance(mustMapper(t))

		// 2. Dispatch: connect a fake agent, run the scenario, capture runId.
		agentID := "e2e-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, hub, agentID)
		defer fake.Disconnect(t)

		runRec := httptest.NewRecorder()
		h.RunScenario(runRec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if runRec.Code != http.StatusOK {
			t.Fatalf("dispatch status = %d, body = %s", runRec.Code, runRec.Body.String())
		}
		var dispatch map[string]any
		_ = json.Unmarshal(runRec.Body.Bytes(), &dispatch)
		runID, _ := dispatch["runId"].(string)
		if runID == "" {
			t.Fatal("dispatch returned no runId")
		}
		fake.WaitForMessage(t, 3*time.Second) // agent received the command

		// 3. Ingestion: submit a result for the dispatched step (fail verdict).
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059.001", "step-0"), ExitCode: 0, Stdout: "FAIL: technique not blocked"}},
		})

		// 4. Reporting: the run report reflects the submitted technique.
		htmlRec := httptest.NewRecorder()
		h.GetRunReport(htmlRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if htmlRec.Code != http.StatusOK {
			t.Fatalf("report status = %d", htmlRec.Code)
		}
		if !strings.Contains(htmlRec.Body.String(), "T1059.001") {
			t.Fatal("report HTML missing the technique that flowed through the whole pipeline")
		}

		csvRec := httptest.NewRecorder()
		h.GetRunForensicCSV(csvRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if !strings.Contains(csvRec.Body.String(), "T1059.001") {
			t.Fatal("forensic CSV missing the technique")
		}

		pdfRec := httptest.NewRecorder()
		h.GetRunPDF(pdfRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if pdfRec.Code != http.StatusOK || !strings.HasPrefix(pdfRec.Body.String(), "%PDF") {
			t.Fatalf("PDF not generated (status=%d)", pdfRec.Code)
		}
	})
}
```

- [ ] **Step 2: Run the capstone**

Run: `cd orchestrator && go test ./internal/api/ -run 'TestE2E_AuthoringToReporting' -v`
Expected: PASS. If dispatch returns non-200 because a live scenario needs different gate params, mirror `run_scenario_gates_test.go`'s working `TestRunScenario_ModeValidation` invocation (posture mode) instead — the composition proof doesn't depend on live mode specifically. If the submitted result doesn't interpret to a T1059.001 row, verify `scenario.TaskID` construction against `submit_scenario_result_test.go:193`.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/e2e_report_flow_test.go
git commit -m "test(api): add authoring→reporting E2E composition capstone (3d.1)"
```

---

### Task 8: Full validation chain + coverage review + memory

**Files:**
- Modify (if gap-closing needed): any 3d.1 test file
- Modify: `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_test_generation_phase0.md` and `MEMORY.md`

- [ ] **Step 1: Build + vet + staticcheck**

Run: `cd orchestrator && go build ./... && go vet ./internal/api/ && staticcheck ./internal/api/`
Expected: all clean.

- [ ] **Step 2: Full api suite**

Run: `cd orchestrator && go test ./internal/api/ -v 2>&1 | tail -40`
Expected: all PASS (existing + ~33 new).

- [ ] **Step 3: Determinism stress (background for the api package)**

Run (background): `cd orchestrator && go test ./internal/api/ -run 'Report|Campaign|AuditPack|SanitizeFilename|ReportDownloadPath|Aggregate|Compliance|E2E|Consist' -count=10`
Expected: 10/10 PASS. Poll via TaskOutput; do not block the session.

- [ ] **Step 4: Coverage review**

Run: `cd orchestrator && go test ./internal/api/ -run 'Report|Campaign|AuditPack|SanitizeFilename|ReportDownloadPath|Aggregate|Compliance|E2E|Consist' -coverprofile=/tmp/3d1.out && go tool cover -func=/tmp/3d1.out | grep -E 'handlers.go|report_handlers.go|campaign_handlers.go'`
Expected: 14 target symbols. Review per-function percentages. Close real authoring/selection/validation gaps with targeted tests; leave OS-fault branches, `auditLog` goroutines, and the Chromium path uncovered by design. Record numbers for the report.

- [ ] **Step 5: Update memory**

Add a "Phase 3d.1 DONE" paragraph to `project_test_generation_phase0.md` (symbols + coverage, fpdf-fallback decision, aggregate-vs-latest pins, ZIP-entry assertions, the one E2E capstone, any product bug found/flagged). Update the `MEMORY.md` index line. Convert relative dates to absolute (2026-07-12).

- [ ] **Step 6: Final commit + push**

```bash
git add orchestrator/internal/api/*.go
git commit -m "test(api): Phase 3d.1 coverage-review gap-closing"   # only if gaps closed
git add <memory files>
git commit -m "docs(memory): record Phase 3d.1 report-generation complete"
git push
```

- [ ] **Step 7: Report to the user**

Total test count, per-symbol coverage numbers, any product finding, and that 3d.1 is complete (3d.2 compliance is next).

---

## Self-Review

**1. Spec coverage:** Every spec symbol maps to a task — Group 1→T2, Group 2 (incl. `complianceRows`/`aggregateAgentResults`/`sanitizeFilename`)→T3, Group 4→T4, Group 5 (`reportDownloadPath`/`CreateReport`/`ListReports`)→T5, nil-engine matrix + consistency→T6, E2E→T7, validation/coverage/memory→T8. Header contract (Content-Type, filename regex, body-length, Cache-Control-absent) is applied across T2–T6. All nine brainstorm refinements are represented (E2E-one-test T7; consistency invariant T6; realistic single fixture T1; header verification T2–T6; ZIP entry list T3; nil-engine shared matrix T6; pure-fn tables T3+T5; PDF structural-only everywhere; aggregate-vs-latest+dedup T3).

**2. Placeholder scan:** No TBD/TODO; every code step is complete Go. The `itoa` helper avoids a `strconv` import purely for parameter-index building; acceptable (values are always < 100 here). The `cases[6]` unicode reassignment is explicit rather than inline only because a multi-byte literal in a struct-tag table reads poorly — behavior is unchanged.

**3. Type consistency:** `reportRunOpts` fields, `seedReportableRun` signature, `newReportingHandler`, `canonicalResults`, `mustMapper`, `newReqCtx` are defined once (T1/T3) and consumed with matching names/types throughout. Handler method names (`GetRunReport`, `GetRunReportData`, `GetRunPDF`, `GetRunForensicCSV`, `GetFullReportHTML/PDF/CSV`, `GetAuditPack`, `GetCampaignReport/PDF/CSV`, `CreateReport`, `ListReports`, `aggregateAgentResults`, `complianceRows`, `sanitizeFilename`, `reportDownloadPath`) all match the grep'd production signatures. `newReqCtx` is defined in T3's file and reused there only; T5 uses `context.Background()` directly (different file, imports context) — no cross-file dependency on `newReqCtx`.

**Fix applied during review:** T3 references `models` and `context` — added to its import list note. T3's `newReqCtx` is used by both `TestAggregateAgentResults` and `TestComplianceRows` in the same file; fine. `fullReq` (T3) and `campaignReq` (T4) live in different files in the same package — no collision, distinct names.
