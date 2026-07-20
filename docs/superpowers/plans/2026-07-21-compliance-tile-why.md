# Compliance Tile "Why" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A client asking "why is this 62%?" gets an answer without digging: hovering a compliance tile shows an instant, arithmetically-consistent tooltip; clicking it deep-links straight into a full report with a plain-language narrative sentence at the top.

**Architecture:** Fix the fleet-wide aggregation query so every number in a tile belongs to one real, coherent agent (not a blend of `MIN()`/`SUM()` from different agents). Add a server-side narrative sentence to `ComplianceReport`, generated from data the compliance mapper already computes. Wire the tile's hover/click to use both.

**Tech Stack:** Go (Postgres query + `internal/compliance` package), vanilla JS (`orchestrator/wwwroot/index.html`).

## Global Constraints

- No new database columns/migrations — `EnrolledAgentCount` is computed in-query via a window function, not stored.
- No new tooltip UI library — the hover "why" uses the native HTML `title` attribute.
- `GetComplianceScores` (single-agent query) is untouched — only the fleet-wide aggregation had the mismatch.
- The narrative must be grounded entirely in data already computed by `GenerateReport()` — never fabricate a root cause without evidence backing it.
- Map iteration in Go is non-deterministic — any "pick the most common X" logic must sort before picking, not rely on first-seen-in-map-iteration.

---

### Task 1: Fix fleet-wide compliance aggregation

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:1066-1079` (`ComplianceSnapshot` struct)
- Modify: `orchestrator/internal/db/postgres.go:1140-1173` (`GetFleetComplianceScores`)
- Create: `orchestrator/internal/db/compliance_snapshot_test.go`

**Interfaces:**
- Produces: `ComplianceSnapshot.EnrolledAgentCount int` (json `enrolledAgentCount,omitempty`) — read by Task 3's JS. `GetFleetComplianceScores` now returns one real agent's row per framework (real `AgentID`, no more `"*"` placeholder) instead of a blended `MIN()`/`SUM()` row.

- [ ] **Step 1: Add the new field to `ComplianceSnapshot`**

Current (`orchestrator/internal/db/postgres.go:1066-1079`):

```go
type ComplianceSnapshot struct {
	AgentID          string    `json:"agentId"`
	FrameworkID      string    `json:"frameworkId"`
	SnapshotAt       time.Time `json:"snapshotAt"`
	RunCount         int       `json:"runCount"`
	CompliancePct    float64   `json:"compliancePct"`
	CoveragePct      float64   `json:"coveragePct"`
	TotalControls    int       `json:"totalControls"`
	TestableControls int       `json:"testableControls"`
	TestedControls   int       `json:"testedControls"`
	PassingControls  int       `json:"passingControls"`
	FailingControls  int       `json:"failingControls"`
	ManualControls   int       `json:"manualControls"`
}
```

Becomes:

```go
type ComplianceSnapshot struct {
	AgentID            string    `json:"agentId"`
	FrameworkID        string    `json:"frameworkId"`
	SnapshotAt         time.Time `json:"snapshotAt"`
	RunCount           int       `json:"runCount"`
	CompliancePct      float64   `json:"compliancePct"`
	CoveragePct        float64   `json:"coveragePct"`
	TotalControls      int       `json:"totalControls"`
	TestableControls   int       `json:"testableControls"`
	TestedControls     int       `json:"testedControls"`
	PassingControls    int       `json:"passingControls"`
	FailingControls    int       `json:"failingControls"`
	ManualControls     int       `json:"manualControls"`
	EnrolledAgentCount int       `json:"enrolledAgentCount,omitempty"` // fleet-wide only; 0 in single-agent queries
}
```

- [ ] **Step 2: Replace the `MIN()`/`SUM()` blend with `DISTINCT ON`**

Current (`orchestrator/internal/db/postgres.go:1140-1173`):

```go
func GetFleetComplianceScores(ctx context.Context, pool *pgxpool.Pool) ([]ComplianceSnapshot, error) {
	rows, err := pool.Query(ctx, `
		SELECT framework_id,
		       MIN(snapshot_at)        AS snapshot_at,
		       SUM(run_count)          AS run_count,
		       MIN(compliance_pct)     AS compliance_pct,
		       MIN(coverage_pct)       AS coverage_pct,
		       MAX(total_controls)     AS total_controls,
		       MAX(testable_controls)  AS testable_controls,
		       SUM(tested_controls)    AS tested_controls,
		       SUM(passing_controls)   AS passing_controls,
		       SUM(failing_controls)   AS failing_controls,
		       MAX(manual_controls)    AS manual_controls
		FROM compliance_snapshots
		GROUP BY framework_id
		ORDER BY framework_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		s.AgentID = "*"
		if err := rows.Scan(&s.FrameworkID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
```

Becomes:

```go
func GetFleetComplianceScores(ctx context.Context, pool *pgxpool.Pool) ([]ComplianceSnapshot, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (framework_id)
		       framework_id, agent_id, snapshot_at, run_count,
		       compliance_pct, coverage_pct,
		       total_controls, testable_controls, tested_controls,
		       passing_controls, failing_controls, manual_controls,
		       COUNT(*) OVER (PARTITION BY framework_id) AS enrolled_agent_count
		FROM compliance_snapshots
		ORDER BY framework_id, compliance_pct ASC, snapshot_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceSnapshot
	for rows.Next() {
		var s ComplianceSnapshot
		if err := rows.Scan(&s.FrameworkID, &s.AgentID, &s.SnapshotAt, &s.RunCount,
			&s.CompliancePct, &s.CoveragePct,
			&s.TotalControls, &s.TestableControls, &s.TestedControls,
			&s.PassingControls, &s.FailingControls, &s.ManualControls,
			&s.EnrolledAgentCount); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
```

`COUNT(*) OVER (PARTITION BY framework_id)` is evaluated over every matching row before `DISTINCT ON` collapses each framework to one — `compliance_snapshots` has one row per `(agent_id, framework_id)` pair, so this correctly counts enrolled agents per framework in the same query.

- [ ] **Step 3: `go build` to confirm the struct/query changes compile**

```bash
cd orchestrator && go build ./internal/db/... && echo "BUILD_OK"
```

Expected: `BUILD_OK`, no errors. (`GetComplianceDashboardScores` in `internal/api/handlers.go` embeds `db.ComplianceSnapshot` by value into its own `scoreResp` struct — the new field is picked up automatically, no changes needed there.)

- [ ] **Step 4: Write the failing test**

Create `orchestrator/internal/db/compliance_snapshot_test.go`:

```go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestGetFleetComplianceScores_PicksWorstAgentCoherently(t *testing.T) {
	ctx := context.Background()
	const fw = "TEST_FLEET_FW"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM compliance_snapshots WHERE framework_id = $1`, fw)
	})

	// Agent A: worse score (40%), but higher raw pass count.
	if err := db.UpsertComplianceSnapshot(ctx, sharedDB.Pool, db.ComplianceSnapshot{
		AgentID: "test-agent-a", FrameworkID: fw,
		CompliancePct: 40, CoveragePct: 80,
		TotalControls: 20, TestableControls: 20, TestedControls: 10,
		PassingControls: 4, FailingControls: 6, ManualControls: 0,
	}); err != nil {
		t.Fatalf("seed agent-a: %v", err)
	}

	// Agent B: better score (90%), fewer tested controls.
	if err := db.UpsertComplianceSnapshot(ctx, sharedDB.Pool, db.ComplianceSnapshot{
		AgentID: "test-agent-b", FrameworkID: fw,
		CompliancePct: 90, CoveragePct: 50,
		TotalControls: 20, TestableControls: 20, TestedControls: 10,
		PassingControls: 9, FailingControls: 1, ManualControls: 0,
	}); err != nil {
		t.Fatalf("seed agent-b: %v", err)
	}

	snaps, err := db.GetFleetComplianceScores(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("GetFleetComplianceScores: %v", err)
	}

	var got *db.ComplianceSnapshot
	for i := range snaps {
		if snaps[i].FrameworkID == fw {
			got = &snaps[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("no snapshot returned for framework %s", fw)
	}

	if got.AgentID != "test-agent-a" {
		t.Errorf("AgentID = %q, want the worst-scoring agent test-agent-a", got.AgentID)
	}
	if got.CompliancePct != 40 {
		t.Errorf("CompliancePct = %v, want 40 (agent-a's real score)", got.CompliancePct)
	}
	// These must belong to agent-a specifically -- NOT summed across both agents
	// (the old MIN()/SUM() blend would have produced PassingControls=13, FailingControls=7).
	if got.PassingControls != 4 {
		t.Errorf("PassingControls = %d, want 4 (agent-a's own count, not summed across agents)", got.PassingControls)
	}
	if got.FailingControls != 6 {
		t.Errorf("FailingControls = %d, want 6 (agent-a's own count, not summed across agents)", got.FailingControls)
	}
	if got.EnrolledAgentCount != 2 {
		t.Errorf("EnrolledAgentCount = %d, want 2", got.EnrolledAgentCount)
	}
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd orchestrator && go test ./internal/db/... -run TestGetFleetComplianceScores_PicksWorstAgentCoherently -v
```

Expected: `--- PASS: TestGetFleetComplianceScores_PicksWorstAgentCoherently`. (Requires Docker running — this suite uses `testutil.MustSharedTestDB()`, a real `postgres:16-alpine` container. If it fails with a connection/container error, confirm `docker info` succeeds first, per this project's established convention of running Docker-gated Go tests directly on the Windows host.)

- [ ] **Step 6: Run the full `internal/db` package test suite to confirm nothing else broke**

```bash
cd orchestrator && go test ./internal/db/... -v 2>&1 | tail -40
```

Expected: all tests pass, including the pre-existing `tenant_test.go`/`harden_test.go`/`events_schema_test.go` suites (they share the same `sharedDB`/`TestMain`, so this confirms no interference).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/db/compliance_snapshot_test.go
git commit -m "$(cat <<'EOF'
fix(compliance): fleet-wide tile numbers no longer blend across agents

GetFleetComplianceScores computed compliancePct as MIN() across all
enrolled agents but pass/fail counts as SUM() across those same
agents -- two different aggregations blended into one row, so the
percentage and counts didn't reconcile. Switches to DISTINCT ON to
pick one real agent's coherent snapshot (the worst-scoring one) per
framework, plus an EnrolledAgentCount via window function for the
upcoming "worst of N" tile copy.
EOF
)"
```

---

### Task 2: Server-side narrative generation

**Files:**
- Modify: `orchestrator/internal/compliance/types.go:40-49` (`ComplianceReport`)
- Modify: `orchestrator/internal/compliance/mapper.go:220-242` (`GenerateReport`'s return + new `buildNarrative`)
- Create: `orchestrator/internal/compliance/mapper_test.go`

**Interfaces:**
- Consumes: `ComplianceSummary`, `DomainResult`, `ControlResult` (all pre-existing, `internal/compliance/types.go`, unchanged).
- Produces: `ComplianceReport.Narrative string` (json `narrative`) — read by Task 3's JS. `buildNarrative(s ComplianceSummary, domains []DomainResult, controls []ControlResult) string` (unexported, package-internal).

- [ ] **Step 1: Add the `Narrative` field**

Current (`orchestrator/internal/compliance/types.go:40-49`):

```go
type ComplianceReport struct {
	Framework    FrameworkMeta     `json:"framework"`
	AgentID      string            `json:"agentId"`
	RunID        string            `json:"runId"`
	ScenarioName string            `json:"scenarioName"`
	GeneratedAt  time.Time         `json:"generatedAt"`
	Summary      ComplianceSummary `json:"summary"`
	Domains      []DomainResult    `json:"domains"`
	Controls     []ControlResult   `json:"controls"`
}
```

Becomes:

```go
type ComplianceReport struct {
	Framework    FrameworkMeta     `json:"framework"`
	AgentID      string            `json:"agentId"`
	RunID        string            `json:"runId"`
	ScenarioName string            `json:"scenarioName"`
	GeneratedAt  time.Time         `json:"generatedAt"`
	Narrative    string            `json:"narrative"`
	Summary      ComplianceSummary `json:"summary"`
	Domains      []DomainResult    `json:"domains"`
	Controls     []ControlResult   `json:"controls"`
}
```

- [ ] **Step 2: Write the failing test**

Create `orchestrator/internal/compliance/mapper_test.go`:

```go
package compliance

import "testing"

func TestBuildNarrative_NoTestedControls(t *testing.T) {
	got := buildNarrative(ComplianceSummary{}, nil, nil)
	want := "No controls have been tested yet — run a scenario to generate compliance evidence."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_AllPassing(t *testing.T) {
	s := ComplianceSummary{TestedControls: 10, PassingControls: 10, CompliancePercent: 100}
	got := buildNarrative(s, nil, nil)
	want := "100% compliant — 10 of 10 tested controls are passing."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_MixedWithTopDomainAndTechnique(t *testing.T) {
	s := ComplianceSummary{
		TestedControls: 21, PassingControls: 13, FailingControls: 5,
		UntestedControls: 3, CompliancePercent: 62,
	}
	domains := []DomainResult{
		{Name: "Identity & Access", Failing: 3},
		{Name: "Logging & Monitoring", Failing: 2},
	}
	controls := []ControlResult{
		{Evidence: []TechniqueEvidence{
			{TechniqueID: "T1110", TechniqueName: "Brute Force", Result: "fail"},
			{TechniqueID: "T1110", TechniqueName: "Brute Force", Result: "fail"},
		}},
		{Evidence: []TechniqueEvidence{
			{TechniqueID: "T1078", TechniqueName: "Valid Accounts", Result: "fail"},
		}},
	}
	got := buildNarrative(s, domains, controls)
	want := "62% compliant — 13 of 21 tested controls are passing. 5 control(s) are failing, most concentrated in Identity & Access (3 of 5). The most common failing technique is Brute Force (T1110). 3 control(s) haven't been tested yet — run additional scenarios to close coverage gaps."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_DomainTieBreaksAlphabetically(t *testing.T) {
	s := ComplianceSummary{TestedControls: 4, PassingControls: 2, FailingControls: 2, CompliancePercent: 50}
	// domains is pre-sorted alphabetically by GenerateReport -- Alpha comes
	// before Bravo, both tied at 1 failing control each.
	domains := []DomainResult{
		{Name: "Alpha", Failing: 1},
		{Name: "Bravo", Failing: 1},
	}
	got := buildNarrative(s, domains, nil)
	want := "50% compliant — 2 of 4 tested controls are passing. 2 control(s) are failing, most concentrated in Alpha (1 of 2)."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_TechniqueTieBreaksByID(t *testing.T) {
	s := ComplianceSummary{TestedControls: 4, PassingControls: 2, FailingControls: 2, CompliancePercent: 50}
	controls := []ControlResult{
		{Evidence: []TechniqueEvidence{
			{TechniqueID: "T2000", TechniqueName: "Zeta Technique", Result: "fail"},
			{TechniqueID: "T1000", TechniqueName: "Alpha Technique", Result: "fail"},
		}},
	}
	got := buildNarrative(s, nil, controls)
	want := "50% compliant — 2 of 4 tested controls are passing. 2 control(s) are failing. The most common failing technique is Alpha Technique (T1000)."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd orchestrator && go test ./internal/compliance/... -run TestBuildNarrative -v
```

Expected: FAIL with `undefined: buildNarrative` (compile error — the function doesn't exist yet).

- [ ] **Step 4: Implement `buildNarrative`**

Add to `orchestrator/internal/compliance/mapper.go`, right before `GenerateReport`'s closing `}` (i.e., after the function ends, as a new top-level function):

```go
// buildNarrative turns a compliance report's numbers into one or two plain-
// language sentences explaining what's driving the score. Grounded entirely
// in already-computed data (never fabricates a root cause it can't show
// evidence for).
func buildNarrative(s ComplianceSummary, domains []DomainResult, controls []ControlResult) string {
	if s.TestedControls == 0 {
		return "No controls have been tested yet — run a scenario to generate compliance evidence."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%.0f%% compliant — %d of %d tested controls are passing.",
		s.CompliancePercent, s.PassingControls, s.TestedControls)

	if s.FailingControls > 0 {
		// domains is already sorted alphabetically by GenerateReport, so a
		// strict > comparison deterministically picks the alphabetically-first
		// domain on a tie.
		var topDomain string
		topDomainFails := 0
		for _, d := range domains {
			if d.Failing > topDomainFails {
				topDomain = d.Name
				topDomainFails = d.Failing
			}
		}

		// Tally failing techniques across all control evidence, then sort for
		// a deterministic pick -- map iteration order is not stable in Go, so
		// this can't just take the first map entry with the highest count.
		type techFail struct {
			id, name string
			n        int
		}
		byTech := map[string]*techFail{}
		for _, c := range controls {
			for _, ev := range c.Evidence {
				if ev.Result != "fail" {
					continue
				}
				t := byTech[ev.TechniqueID]
				if t == nil {
					t = &techFail{id: ev.TechniqueID, name: ev.TechniqueName}
					byTech[ev.TechniqueID] = t
				}
				t.n++
			}
		}
		techs := make([]*techFail, 0, len(byTech))
		for _, t := range byTech {
			techs = append(techs, t)
		}
		sort.Slice(techs, func(i, j int) bool {
			if techs[i].n != techs[j].n {
				return techs[i].n > techs[j].n
			}
			return techs[i].id < techs[j].id // deterministic tie-break
		})

		fmt.Fprintf(&b, " %d control(s) are failing", s.FailingControls)
		if topDomain != "" {
			fmt.Fprintf(&b, ", most concentrated in %s (%d of %d)", topDomain, topDomainFails, s.FailingControls)
		}
		b.WriteString(".")
		if len(techs) > 0 {
			top := techs[0]
			if top.name != "" {
				fmt.Fprintf(&b, " The most common failing technique is %s (%s).", top.name, top.id)
			} else {
				fmt.Fprintf(&b, " The most common failing technique is %s.", top.id)
			}
		}
	}

	if s.UntestedControls > 0 {
		fmt.Fprintf(&b, " %d control(s) haven't been tested yet — run additional scenarios to close coverage gaps.", s.UntestedControls)
	}

	return b.String()
}
```

`mapper.go`'s existing import block already has `fmt`, `sort`, and `strings` — no import changes needed.

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd orchestrator && go test ./internal/compliance/... -run TestBuildNarrative -v
```

Expected: all 5 `TestBuildNarrative_*` subtests PASS.

- [ ] **Step 6: Wire `buildNarrative` into `GenerateReport`'s return**

Current (`orchestrator/internal/compliance/mapper.go:220-241`):

```go
	meta := fw.FrameworkMeta

	return &ComplianceReport{
		Framework:    meta,
		AgentID:      agentID,
		RunID:        runID,
		ScenarioName: scenarioName,
		GeneratedAt:  time.Now().UTC(),
		Summary: ComplianceSummary{
			TotalControls:     totalControls,
			TestableControls:  testableControls,
			ManualControls:    manualControls,
			TestedControls:    testedControls,
			PassingControls:   passingControls,
			FailingControls:   failingControls,
			UntestedControls:  testableControls - testedControls,
			CoveragePercent:   coveragePct,
			CompliancePercent: compliancePct,
		},
		Domains:  domains,
		Controls: controlResults,
	}, nil
}
```

Becomes:

```go
	meta := fw.FrameworkMeta

	summary := ComplianceSummary{
		TotalControls:     totalControls,
		TestableControls:  testableControls,
		ManualControls:    manualControls,
		TestedControls:    testedControls,
		PassingControls:   passingControls,
		FailingControls:   failingControls,
		UntestedControls:  testableControls - testedControls,
		CoveragePercent:   coveragePct,
		CompliancePercent: compliancePct,
	}

	return &ComplianceReport{
		Framework:    meta,
		AgentID:      agentID,
		RunID:        runID,
		ScenarioName: scenarioName,
		GeneratedAt:  time.Now().UTC(),
		Narrative:    buildNarrative(summary, domains, controlResults),
		Summary:      summary,
		Domains:      domains,
		Controls:     controlResults,
	}, nil
}
```

- [ ] **Step 7: Run the full `internal/compliance` package test suite**

```bash
cd orchestrator && go test ./internal/compliance/... -v 2>&1 | tail -50
```

Expected: all tests pass, including the pre-existing `loader_test.go` suite (confirms `GenerateReport`'s behavior change didn't break framework loading/parsing, a separate concern in the same package).

- [ ] **Step 8: `go vet`**

```bash
cd orchestrator && go vet ./internal/compliance/... ./internal/db/...
```

Expected: no output, exit 0.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/compliance/types.go orchestrator/internal/compliance/mapper.go orchestrator/internal/compliance/mapper_test.go
git commit -m "$(cat <<'EOF'
feat(compliance): generate a plain-language narrative for every report

buildNarrative() turns a report's already-computed summary/domains/
evidence into 1-3 sentences explaining what's driving the score --
top failing domain, top failing technique, untested-control callout.
Grounded entirely in real data, never fabricated. Flows into JSON/CSV/
PDF exports for free since they already serialize the full
ComplianceReport struct.
EOF
)"
```

---

### Task 3: Dashboard tile hover, deep-link, and narrative display

**Files:**
- Modify: `orchestrator/wwwroot/index.html:11342-11390` (`complianceTile`)
- Modify: `orchestrator/wwwroot/index.html:12351-12384` (`renderComplianceReport`)

**Interfaces:**
- Consumes: `fw.enrolledAgentCount` (Task 1), `r.narrative` (Task 2) — both already flow through the existing `/api/compliance/scores` and `/api/compliance/report` endpoints with no handler changes needed.
- Produces: `complianceWhy(fw)` and `openComplianceDetail(frameworkId, agentId)` — new global JS functions, called from `complianceTile()`.

- [ ] **Step 1: Add `complianceWhy()` right before `complianceTile()`**

Current (`orchestrator/wwwroot/index.html`, immediately before `function complianceTile(fw) {`):

```js
function complianceTile(fw) {
```

Becomes:

```js
function complianceWhy(fw) {
  var tested = fw.testedControls || 0;
  if (tested === 0) return 'No controls tested yet — run a scenario to generate compliance evidence.';
  var pct = Math.round(fw.compliancePct || 0);
  var passing = fw.passingControls || 0;
  var failing = fw.failingControls || 0;
  var untested = fw.untestedControls != null ? fw.untestedControls : 0;
  if (fw.enrolledAgentCount > 1) {
    return pct + '% compliant — worst of ' + fw.enrolledAgentCount + ' enrolled endpoints. Click for full breakdown.';
  }
  return pct + '% compliant — ' + passing + ' of ' + tested + ' tested controls passing, ' +
    failing + ' failing, ' + untested + ' untested.';
}

function openComplianceDetail(frameworkId, agentId) {
  showTab('compliance');
  var fwSel = document.getElementById('cmp-fw-sel');
  var agSel = document.getElementById('cmp-agent-sel');
  if (fwSel) fwSel.value = frameworkId;
  if (agSel && agentId) agSel.value = agentId;
  loadComplianceReport();
}

function complianceTile(fw) {
```

- [ ] **Step 2: Use them in the tile's `title` and `onclick`**

Current (inside `complianceTile()`):

```js
  return '<div class="kpi-card stat-tile" ' +
    'style="border-left:3px solid ' + borderColor + ';cursor:pointer;min-width:155px;max-width:220px" ' +
    'onclick="showTab(\'compliance\')" title="' + x(fw.frameworkName) + '">' +
```

Becomes:

```js
  return '<div class="kpi-card stat-tile" ' +
    'style="border-left:3px solid ' + borderColor + ';cursor:pointer;min-width:155px;max-width:220px" ' +
    'onclick="openComplianceDetail(\'' + x(fw.frameworkId) + '\', \'' + x(fw.agentId) + '\')" ' +
    'title="' + x(fw.frameworkName) + '\n' + x(complianceWhy(fw)) + '">' +
```

- [ ] **Step 3: Render the narrative in the full report header**

Current (`orchestrator/wwwroot/index.html`, inside `renderComplianceReport()`):

```js
        '<div class="cmp-fw-name">' + x(r.framework.name || '') + '</div>' +
        '<div class="cmp-fw-version">' + x(r.framework.version || '') + '</div>' +
      '</div>' +
```

Becomes:

```js
        '<div class="cmp-fw-name">' + x(r.framework.name || '') + '</div>' +
        '<div class="cmp-fw-version">' + x(r.framework.version || '') + '</div>' +
        '<div class="cmp-header-narrative" style="margin-top:0.5rem;font-size:0.85rem;line-height:1.5;color:var(--text-dim);max-width:520px">' +
          x(r.narrative || '') +
        '</div>' +
      '</div>' +
```

- [ ] **Step 4: Start the dev server and verify live in a browser**

Follow this session's established dev-server smoke-test pattern (throwaway `postgres:16-alpine` container + `go run ./cmd/server` from `orchestrator/`, per `packaging/compose/docker-compose.yml`'s env vars for `DATABASE_URL`/`JWT_SECRET`/`BAS_LICENSE_PATH`/`HTTP_PORT`). Open the dashboard, and for a framework with completed runs:

- Hover a compliance tile — confirm the browser's native tooltip shows the framework name on the first line and the `complianceWhy()` sentence on the second line.
- Click the tile — confirm it lands directly on a populated report (no "Select an agent and framework..." placeholder step) with the narrative sentence visible in the header, above the ring gauge.
- If no runs have completed yet, confirm the tile's tooltip and the report's narrative both read "No controls tested yet..." / "No controls have been tested yet..." consistently rather than showing a raw `0%`/blank state.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(dashboard): compliance tiles explain "why" on hover and click

Hovering a tile shows an instant tooltip built from data the tile
already has (native title attribute, no new UI component). Clicking
deep-links straight into the full report with the agent+framework
pre-selected -- no more landing on an empty form. The full report now
shows the server-generated narrative sentence at the top, above the
ring gauge.
EOF
)"
```

---

### Task 4: Final verification and push

**Files:** none (verification only)

- [ ] **Step 1: Full backend build and test suite**

```bash
cd orchestrator
go build ./... && echo "BUILD_OK"
go vet ./... && echo "VET_OK"
go test ./internal/db/... ./internal/compliance/... -v 2>&1 | tail -60
```

Expected: `BUILD_OK`, `VET_OK`, all tests pass.

- [ ] **Step 2: Confirm commit contents match the plan**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
git log --oneline -4
git show --stat HEAD~2..HEAD
```

Expected: three commits from Tasks 1-3, touching exactly `orchestrator/internal/db/postgres.go`, `orchestrator/internal/db/compliance_snapshot_test.go`, `orchestrator/internal/compliance/types.go`, `orchestrator/internal/compliance/mapper.go`, `orchestrator/internal/compliance/mapper_test.go`, `orchestrator/wwwroot/index.html`.

- [ ] **Step 3: Push**

```bash
git push
```
