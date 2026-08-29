# Posture Finding SLA Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A fleet-wide SLA compliance report — severity breakdown, monthly trend, recently-resolved history — computed from already-persisted `finding_slas` data.

**Architecture:** A new pure package `internal/slareport` (`ComputeReport`, no DB dependency, mirrors `internal/slapolicy`/`internal/driftanalytics`'s shape) does all the aggregation; a single new handler fetches the raw `finding_slas` rows, calls it once, and separately fetches a bounded recently-resolved list. No new schema.

**Tech Stack:** Go, Postgres (`pgxpool`), testcontainers-backed Go tests. No new table, no live server needed.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-29-posture-finding-sla-reporting-design.md`

## Global Constraints

- Build directly on `main` — no worktree, no branches/PRs.
- Commit after each task; push immediately after every commit.
- Every response in this initiative's API layer is `map[string]any`, never a typed struct — the handler's JSON output follows the same convention (the `slareport` package's own types stay internal to that package, never marshaled directly).
- Historical (resolved-episode) on-time/late classification always uses `slapolicy.EvaluateSLABreach(deadlineAt, resolvedAt)` — timestamp ground truth, never the `status` column, which can lag `TickSLABreaches`' 5-minute cadence.
- `CurrentlyOpen` counts (live state) use the `status` column — that's a different question (right now) than historical classification (what actually happened).
- No new schema, no change to `TickSLABreaches`/`sla_policy`/any existing endpoint. No UI — this is D1 (API only); a UI is a separate future sub-project (D2).

---

### Task 1: `internal/slareport` — pure computation package

**Files:**
- Create: `orchestrator/internal/slareport/slareport.go`
- Test: `orchestrator/internal/slareport/slareport_test.go`

**Interfaces:**
- Consumes: `slapolicy.EvaluateSLABreach(deadlineAt, now time.Time) bool` (existing, `internal/slapolicy`, Sub-project B).
- Produces: `slareport.Episode{Severity string, DeadlineAt time.Time, Status string, ResolvedAt *time.Time}`, `slareport.Stats{Severity string, TotalEpisodes, OnTime, Late, CurrentlyOpen int, ComplianceRate float64}`, `slareport.MonthStats{Month string, Resolved, OnTime int, ComplianceRate float64}`, `slareport.Report{Overall Stats, BySeverity []Stats, MonthlyTrend []MonthStats}`, `func ComputeReport(episodes []Episode) Report`. Task 2 calls `ComputeReport` directly.

No container needed — pure functions, no DB/network dependency.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/slareport/slareport_test.go`:

```go
package slareport

import (
	"testing"
	"time"
)

func TestComputeReport_EmptyInput(t *testing.T) {
	r := ComputeReport(nil)
	if r.Overall.TotalEpisodes != 0 || r.Overall.ComplianceRate != 0 {
		t.Fatalf("Overall = %+v, want zero-valued (no divide-by-zero)", r.Overall)
	}
	if len(r.BySeverity) != 0 || len(r.MonthlyTrend) != 0 {
		t.Fatalf("BySeverity=%v MonthlyTrend=%v, want both empty", r.BySeverity, r.MonthlyTrend)
	}
}

func TestComputeReport_AllOnTime_100PercentCompliance(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := deadline.Add(-time.Hour)
	episodes := []Episode{
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
	}
	r := ComputeReport(episodes)
	if r.Overall.OnTime != 2 || r.Overall.Late != 0 || r.Overall.ComplianceRate != 100 {
		t.Fatalf("Overall = %+v, want OnTime=2 Late=0 ComplianceRate=100", r.Overall)
	}
}

func TestComputeReport_AllLate_0PercentCompliance(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	after := deadline.Add(time.Hour)
	episodes := []Episode{
		{Severity: "Critical", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &after},
	}
	r := ComputeReport(episodes)
	if r.Overall.OnTime != 0 || r.Overall.Late != 1 || r.Overall.ComplianceRate != 0 {
		t.Fatalf("Overall = %+v, want OnTime=0 Late=1 ComplianceRate=0", r.Overall)
	}
}

func TestComputeReport_ResolvedExactlyAtDeadline_CountsAsLate(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	episodes := []Episode{
		{Severity: "Medium", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &deadline},
	}
	r := ComputeReport(episodes)
	if r.Overall.Late != 1 {
		t.Fatalf("Overall = %+v, want Late=1 (deadline exactly reached counts as breached, matching EvaluateSLABreach)", r.Overall)
	}
}

func TestComputeReport_CurrentlyOpenExcludedFromComplianceRate(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := deadline.Add(-time.Hour)
	episodes := []Episode{
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before}, // on time
		{Severity: "High", DeadlineAt: deadline, Status: "active"},                        // still open
		{Severity: "High", DeadlineAt: deadline, Status: "breached"},                      // still open, already missed
	}
	r := ComputeReport(episodes)
	if r.Overall.TotalEpisodes != 3 {
		t.Errorf("TotalEpisodes = %d, want 3", r.Overall.TotalEpisodes)
	}
	if r.Overall.CurrentlyOpen != 2 {
		t.Errorf("CurrentlyOpen = %d, want 2 (active + breached)", r.Overall.CurrentlyOpen)
	}
	if r.Overall.OnTime != 1 || r.Overall.Late != 0 || r.Overall.ComplianceRate != 100 {
		t.Errorf("OnTime=%d Late=%d ComplianceRate=%.1f, want 1/0/100 (open episodes excluded from the rate)",
			r.Overall.OnTime, r.Overall.Late, r.Overall.ComplianceRate)
	}
}

func TestComputeReport_BySeverity_OnlyIncludesSeveritiesWithEpisodes(t *testing.T) {
	deadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := deadline.Add(-time.Hour)
	after := deadline.Add(time.Hour)
	episodes := []Episode{
		{Severity: "Critical", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &after},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &before},
	}
	r := ComputeReport(episodes)
	if len(r.BySeverity) != 2 {
		t.Fatalf("BySeverity = %+v, want exactly 2 rows (Critical, High -- Medium/Low have no episodes)", r.BySeverity)
	}
	bySev := map[string]Stats{}
	for _, s := range r.BySeverity {
		bySev[s.Severity] = s
	}
	if bySev["Critical"].TotalEpisodes != 1 || bySev["Critical"].ComplianceRate != 100 {
		t.Errorf("Critical = %+v, want TotalEpisodes=1 ComplianceRate=100", bySev["Critical"])
	}
	if bySev["High"].TotalEpisodes != 2 || bySev["High"].OnTime != 1 || bySev["High"].Late != 1 || bySev["High"].ComplianceRate != 50 {
		t.Errorf("High = %+v, want TotalEpisodes=2 OnTime=1 Late=1 ComplianceRate=50", bySev["High"])
	}
}

func TestComputeReport_MonthlyTrend_BucketsByResolvedMonth(t *testing.T) {
	deadline := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	julOnTime := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	julLate := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	augOnTime := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	augDeadline := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	episodes := []Episode{
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &julOnTime},
		{Severity: "High", DeadlineAt: deadline, Status: "resolved", ResolvedAt: &julLate},
		{Severity: "High", DeadlineAt: augDeadline, Status: "resolved", ResolvedAt: &augOnTime},
		{Severity: "High", DeadlineAt: augDeadline, Status: "active"}, // still open -- never bucketed into a month
	}
	r := ComputeReport(episodes)
	if len(r.MonthlyTrend) != 2 {
		t.Fatalf("MonthlyTrend = %+v, want exactly 2 months", r.MonthlyTrend)
	}
	byMonth := map[string]MonthStats{}
	for _, m := range r.MonthlyTrend {
		byMonth[m.Month] = m
	}
	if byMonth["2026-07"].Resolved != 2 || byMonth["2026-07"].OnTime != 1 || byMonth["2026-07"].ComplianceRate != 50 {
		t.Errorf("2026-07 = %+v, want Resolved=2 OnTime=1 ComplianceRate=50", byMonth["2026-07"])
	}
	if byMonth["2026-08"].Resolved != 1 || byMonth["2026-08"].OnTime != 1 || byMonth["2026-08"].ComplianceRate != 100 {
		t.Errorf("2026-08 = %+v, want Resolved=1 OnTime=1 ComplianceRate=100", byMonth["2026-08"])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/slareport/... -v`
Expected: FAIL — package `internal/slareport` does not exist / types undefined

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/slareport/slareport.go`:

```go
// Package slareport computes fleet-wide SLA compliance statistics from a
// list of finding_slas episodes. No I/O -- the API layer fetches the raw
// rows and calls ComputeReport once. Historical (resolved-episode) on-time/
// late classification is deliberately timestamp-based (deadline_at vs
// resolved_at, via slapolicy.EvaluateSLABreach) rather than status-based --
// TickSLABreaches only runs every 5 minutes, so status can lag the ground
// truth by up to that long.
package slareport

import (
	"time"

	"github.com/audspect/bas/internal/slapolicy"
)

// Episode is one finding_slas row's data relevant to reporting.
type Episode struct {
	Severity   string
	DeadlineAt time.Time
	Status     string // "active" | "breached" | "resolved"
	ResolvedAt *time.Time
}

// Stats is one bucket's aggregate numbers -- used for both the fleet-wide
// overall summary (Severity == "") and each per-severity row.
type Stats struct {
	Severity       string
	TotalEpisodes  int
	OnTime         int
	Late           int
	CurrentlyOpen  int
	ComplianceRate float64 // OnTime / (OnTime+Late) * 100; 0 if none resolved yet
}

// MonthStats is one calendar month's resolution outcomes, bucketed by
// ResolvedAt.
type MonthStats struct {
	Month          string // "YYYY-MM"
	Resolved       int
	OnTime         int
	ComplianceRate float64
}

type Report struct {
	Overall      Stats
	BySeverity   []Stats
	MonthlyTrend []MonthStats
}

func ComputeReport(episodes []Episode) Report {
	overall := &Stats{}
	bySeverity := map[string]*Stats{}
	byMonth := map[string]*MonthStats{}

	for _, e := range episodes {
		sev := bySeverity[e.Severity]
		if sev == nil {
			sev = &Stats{Severity: e.Severity}
			bySeverity[e.Severity] = sev
		}
		overall.TotalEpisodes++
		sev.TotalEpisodes++

		if e.ResolvedAt == nil {
			overall.CurrentlyOpen++
			sev.CurrentlyOpen++
			continue
		}

		onTime := !slapolicy.EvaluateSLABreach(e.DeadlineAt, *e.ResolvedAt)
		if onTime {
			overall.OnTime++
			sev.OnTime++
		} else {
			overall.Late++
			sev.Late++
		}

		month := e.ResolvedAt.Format("2006-01")
		m := byMonth[month]
		if m == nil {
			m = &MonthStats{Month: month}
			byMonth[month] = m
		}
		m.Resolved++
		if onTime {
			m.OnTime++
		}
	}

	overall.ComplianceRate = complianceRate(overall.OnTime, overall.Late)
	r := Report{Overall: *overall}
	for _, s := range bySeverity {
		s.ComplianceRate = complianceRate(s.OnTime, s.Late)
		r.BySeverity = append(r.BySeverity, *s)
	}
	for _, m := range byMonth {
		m.ComplianceRate = complianceRate(m.OnTime, m.Resolved-m.OnTime)
		r.MonthlyTrend = append(r.MonthlyTrend, *m)
	}
	return r
}

func complianceRate(onTime, late int) float64 {
	total := onTime + late
	if total == 0 {
		return 0
	}
	return float64(onTime) / float64(total) * 100
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/slareport/... -v`
Expected: PASS (all 7 test functions)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/slareport/
git commit -m "feat: add internal/slareport pure computation package

ComputeReport aggregates finding_slas episodes into fleet-wide,
per-severity, and monthly-trend compliance stats. Historical on-time/
late classification uses deadline_at vs resolved_at (via
slapolicy.EvaluateSLABreach), never the status column, which can lag
TickSLABreaches' 5-minute cadence."
git push
```

---

### Task 2: `GET /api/sla/report` handler

**Files:**
- Create: `orchestrator/internal/api/sla_report_handlers.go`
- Test: `orchestrator/internal/api/sla_report_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go:569`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:344`

**Interfaces:**
- Consumes: `slareport.Episode`, `slareport.ComputeReport` (Task 1); `slapolicy.EvaluateSLABreach` (existing).
- Produces: `func (h *Handler) GetSLAReport(w http.ResponseWriter, r *http.Request)`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/sla_report_handlers_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetSLAReport_ComputesFromSeededEpisodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('rpt-a1', 'RPT-A1')`)

		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rpt-1', 'rpt-a1', 'windows-firewall-enabled', 'security-configuration', 'Windows Firewall disabled', 'High', 'remediated', NOW(), NOW(), NOW())`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rpt-2', 'rpt-a1', 'windows-smbv1-disabled', 'security-configuration', 'SMBv1 enabled', 'High', 'remediated', NOW(), NOW(), NOW())`)
		mustExecAPI(t, pool,
			`INSERT INTO posture_findings (id, agent_id, check_id, category, title, severity, status, first_seen, last_seen, last_observed_at)
			 VALUES ('pf-rpt-3', 'rpt-a1', 'linux-firewall-enabled', 'security-configuration', 'UFW not active', 'Critical', 'open', NOW(), NOW(), NOW())`)

		deadline := time.Now().Add(-time.Hour)
		onTimeResolved := deadline.Add(-time.Minute)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, resolved_at)
			 VALUES ('fs-rpt-1', 'pf-rpt-1', 'High', $1, $2, 'resolved', $3)`,
			deadline.Add(-72*time.Hour), deadline, onTimeResolved)

		lateResolved := deadline.Add(time.Minute)
		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status, resolved_at)
			 VALUES ('fs-rpt-2', 'pf-rpt-2', 'High', $1, $2, 'resolved', $3)`,
			deadline.Add(-72*time.Hour), deadline, lateResolved)

		mustExecAPI(t, pool,
			`INSERT INTO finding_slas (id, posture_finding_id, severity_at_start, started_at, deadline_at, status)
			 VALUES ('fs-rpt-3', 'pf-rpt-3', 'Critical', NOW(), $1, 'active')`,
			time.Now().Add(time.Hour))

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/report", nil)
		w := httptest.NewRecorder()
		h.GetSLAReport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		overall := got["overall"].(map[string]any)
		if overall["totalEpisodes"].(float64) != 3 {
			t.Errorf("overall.totalEpisodes = %v, want 3", overall["totalEpisodes"])
		}
		if overall["currentlyOpen"].(float64) != 1 {
			t.Errorf("overall.currentlyOpen = %v, want 1", overall["currentlyOpen"])
		}
		if overall["onTime"].(float64) != 1 || overall["late"].(float64) != 1 {
			t.Errorf("overall onTime/late = %v/%v, want 1/1", overall["onTime"], overall["late"])
		}

		bySeverity := got["bySeverity"].([]any)
		if len(bySeverity) != 2 {
			t.Fatalf("bySeverity = %v, want 2 rows (High, Critical)", bySeverity)
		}

		recent := got["recentlyResolved"].([]any)
		if len(recent) != 2 {
			t.Fatalf("recentlyResolved = %v, want 2 rows", recent)
		}
		first := recent[0].(map[string]any)
		if first["checkId"] != "windows-smbv1-disabled" || first["onTime"] != false {
			t.Errorf("recentlyResolved[0] = %+v, want checkId=windows-smbv1-disabled onTime=false (most recently resolved first)", first)
		}
	})
}

func TestGetSLAReport_NoEpisodes_ReturnsZeroValuedReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/sla/report", nil)
		w := httptest.NewRecorder()
		h.GetSLAReport(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		var got map[string]any
		json.Unmarshal(w.Body.Bytes(), &got)
		overall := got["overall"].(map[string]any)
		if overall["totalEpisodes"].(float64) != 0 {
			t.Errorf("overall.totalEpisodes = %v, want 0", overall["totalEpisodes"])
		}
		if len(got["recentlyResolved"].([]any)) != 0 {
			t.Errorf("recentlyResolved = %v, want empty", got["recentlyResolved"])
		}
	})
}
```

`mustExecAPI`/`sharedDB` are package-level helpers already available without import (defined elsewhere in `package api`'s test files).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetSLAReport' -v`
Expected: FAIL — `h.GetSLAReport` undefined

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/api/sla_report_handlers.go`:

```go
package api

import (
	"net/http"
	"time"

	"github.com/audspect/bas/internal/slapolicy"
	"github.com/audspect/bas/internal/slareport"
)

// GetSLAReport returns the fleet-wide SLA compliance report: overall and
// per-severity stats, a monthly trend, and a bounded recently-resolved
// history. GET /api/sla/report
func (h *Handler) GetSLAReport(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT severity_at_start, deadline_at, status, resolved_at FROM finding_slas`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var episodes []slareport.Episode
	for rows.Next() {
		var e slareport.Episode
		if rows.Scan(&e.Severity, &e.DeadlineAt, &e.Status, &e.ResolvedAt) != nil {
			continue
		}
		episodes = append(episodes, e)
	}
	rows.Close()
	report := slareport.ComputeReport(episodes)

	recentRows, err := h.db.Query(r.Context(),
		`SELECT pf.agent_id, pf.check_id, fs.severity_at_start, fs.started_at, fs.resolved_at, fs.deadline_at
		   FROM finding_slas fs
		   JOIN posture_findings pf ON pf.id = fs.posture_finding_id
		  WHERE fs.status = 'resolved'
		  ORDER BY fs.resolved_at DESC LIMIT 50`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer recentRows.Close()
	recentlyResolved := []map[string]any{}
	for recentRows.Next() {
		var agentID, checkID, severity string
		var startedAt, resolvedAt, deadlineAt time.Time
		if recentRows.Scan(&agentID, &checkID, &severity, &startedAt, &resolvedAt, &deadlineAt) != nil {
			continue
		}
		recentlyResolved = append(recentlyResolved, map[string]any{
			"agentId": agentID, "checkId": checkID, "severity": severity,
			"startedAt": startedAt, "resolvedAt": resolvedAt, "deadlineAt": deadlineAt,
			"onTime": !slapolicy.EvaluateSLABreach(deadlineAt, resolvedAt),
		})
	}

	respond(w, map[string]any{
		"overall":          statsToMap(report.Overall),
		"bySeverity":       severityStatsToMaps(report.BySeverity),
		"monthlyTrend":     monthStatsToMaps(report.MonthlyTrend),
		"recentlyResolved": recentlyResolved,
	})
}

func statsToMap(s slareport.Stats) map[string]any {
	return map[string]any{
		"totalEpisodes": s.TotalEpisodes, "onTime": s.OnTime, "late": s.Late,
		"currentlyOpen": s.CurrentlyOpen, "complianceRate": s.ComplianceRate,
	}
}

func severityStatsToMaps(stats []slareport.Stats) []map[string]any {
	out := make([]map[string]any, 0, len(stats))
	for _, s := range stats {
		m := statsToMap(s)
		m["severity"] = s.Severity
		out = append(out, m)
	}
	return out
}

func monthStatsToMaps(stats []slareport.MonthStats) []map[string]any {
	out := make([]map[string]any, 0, len(stats))
	for _, m := range stats {
		out = append(out, map[string]any{
			"month": m.Month, "resolved": m.Resolved, "onTime": m.OnTime, "complianceRate": m.ComplianceRate,
		})
	}
	return out
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after line 569
(`` r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/sla/breaches", h.GetSLABreaches) ``), add:

```go
		r.With(auth.RequirePermission(auth.CanExecuteRemediation)).Get("/api/sla/report", h.GetSLAReport)
```

- [ ] **Step 5: Add the route to the RBAC matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after line 344
(`` {http.MethodGet, "/api/sla/breaches", tierPermission, auth.CanExecuteRemediation}, ``), add:

```go
	{http.MethodGet, "/api/sla/report", tierPermission, auth.CanExecuteRemediation},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetSLAReport|TestRBACMatrix' -v`
Expected: PASS (both new tests, plus `TestRBACMatrix_NoDrift` confirming the new route is registered correctly)

- [ ] **Step 7: Run the full posture/SLA test surface to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run 'PostureFinding|SLA' -v`
Expected: all PASS — every test from Sub-projects A, B, C, and this task

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/sla_report_handlers.go orchestrator/internal/api/sla_report_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat: add fleet-wide SLA compliance report endpoint

GET /api/sla/report -- overall/per-severity/monthly-trend compliance
stats via internal/slareport.ComputeReport, plus a bounded (LIMIT 50)
recently-resolved history. Read-only, no new schema."
git push
```

---

### Task 3: Full-suite verification

No commit for this task — verification only, mirroring Sub-projects A, B, and C's final task.

- [ ] **Step 1: Run the full `internal/api` package**

Run: `cd orchestrator && go test ./internal/api/... -v`
Expected: zero `FAIL` lines. If the whole-package run times out or hits a resource-contention-shaped failure (the documented class in `[[project_endpoint_health_remediation]]` — a `panic: test timed out` with a goroutine dump, unrelated to any file this plan touches — it has now hit 4 different unrelated tests across Sub-projects A/B/C this session alone), re-run just that failing test name in isolation with `-run '^TestName$'` to confirm it passes clean alone before concluding it's contention and not a real regression. Do not skip this confirmation step.

- [ ] **Step 2: Run the new/adjacent packages directly**

Run: `cd orchestrator && go test ./internal/slareport/... ./internal/slapolicy/... ./internal/findings/... ./internal/endpointrisk/... ./internal/notifications/... ./internal/remediation/... -v`
Expected: all PASS

- [ ] **Step 3: Confirm no unrelated diff**

Run: `cd "C:\Users\Administrator\Downloads\Audspect_Cloud" && git status --porcelain orchestrator/internal/findings orchestrator/internal/endpointrisk orchestrator/internal/remediation orchestrator/wwwroot`
Expected: empty output (this plan never touches any of these)

- [ ] **Step 4: Report completion**

Summarize what shipped (both implementation tasks + this verification) and confirm nothing is pending. This closes out Sub-project D1 — and with it, every SLA sub-project except the future D2 (UI), which is its own not-yet-brainstormed follow-on. This repo builds directly on `main` with no worktree, so `finishing-a-development-branch`'s cleanup step is a no-op here, same as Sub-projects A, B, and C.
