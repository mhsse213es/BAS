# Compliance Tile "Why" — Design

## Context

The dashboard's compliance tiles (`orchestrator/wwwroot/index.html:1409`, `complianceTile()` at `:11342`) show a percentage and a pass/fail/untested count per regulatory framework, refreshed from `/api/compliance/scores`. Clicking a tile calls `showTab('compliance')` and nothing else — it lands on an empty form (`#cmp-placeholder`: "Select an agent and framework, then click Generate") that requires the client's team to manually re-pick the exact agent and framework they just clicked, before any explanation appears. Even once generated, the detailed report (`renderComplianceReport()`, `loadComplianceReport()` at `:12322`) shows a ring gauge, a domain grid, and a per-control table with expandable per-technique evidence — real "why" data, but scattered across rows the viewer has to piece together themselves; there's no summary sentence anywhere.

Two more things came up while investigating:

1. **The full per-control evidence already exists and is rich.** `ComplianceReport.Controls[].Evidence[]` (`internal/compliance/types.go:94-101`) carries `TechniqueID`, `TechniqueName`, `Result`, `Details`, `Remediation` per BAS test — everything needed for a grounded, factual "why," already computed server-side by `Mapper.GenerateReport()` (`internal/compliance/mapper.go:89`). Nothing needs to be invented; it needs to be *summarized*.
2. **The fleet-wide tile's own numbers don't currently reconcile with each other.** `GetFleetComplianceScores` (`internal/db/postgres.go:1140`) computes `compliancePct` as `MIN(compliance_pct)` across all enrolled agents but `tested_controls`/`passing_controls`/`failing_controls` as `SUM(...)` across those *same* agents — two different aggregation strategies blended into one row. A fleet with several agents can show e.g. "62%" next to "50 pass · 10 fail," which doesn't arithmetically reduce to 62%, because the percentage came from one agent and the counts came from all of them combined. This has to be resolved before any "why" text can honestly explain the number.

Confirmed via `grep`: the dashboard's only call site for `loadComplianceScores()` (`:11316`) is the no-argument, fleet-wide form — there is currently no in-use single-agent dashboard view. The per-agent code path (`agentId` parameter) stays supported for forward-compatibility but isn't exercised today, so this plan's fleet-wide fix is what actually matters for the visible dashboard.

## Goal

A client asking "why is this 62%?" gets an answer in two places, no digging required:
1. **Hovering a tile** — an instant, honest, arithmetically-consistent tooltip.
2. **Clicking a tile** — a one-click deep-link straight into the full report (no empty form, no manual re-selection), with a plain-language narrative sentence at the top explaining what's driving the score.

## Architecture

### 1. Fix the fleet-wide aggregation — `internal/db/postgres.go`

Replace the `MIN()`/`SUM()` blend with `DISTINCT ON`, picking the **one real agent row** with the lowest `compliance_pct` per framework (ties broken by most recent snapshot) — every field in the returned row then belongs to that same agent and is internally consistent by construction:

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

`COUNT(*) OVER (PARTITION BY framework_id)` is evaluated over every matching row *before* `DISTINCT ON` collapses each framework down to one — since `compliance_snapshots` has one row per `(agent_id, framework_id)` pair, this correctly counts how many agents have a snapshot for that framework, in the same query, no second round-trip.

New field on `ComplianceSnapshot` (`internal/db/postgres.go:1066-1079`):

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

`GetComplianceScores` (single-agent query) and its callers are untouched — `EnrolledAgentCount` simply stays `0` there, which the frontend treats as "not fleet-wide" (see §3).

`GetComplianceDashboardScores` (`internal/api/handlers.go:3948-4003`) needs no changes — it already copies the embedded `db.ComplianceSnapshot` (including the new field) straight into `scoreResp`, and the `s.AgentID = "*"` line that used to blank out the real agent ID is simply gone now that the query returns a real one.

### 2. Narrative generation — `internal/compliance/mapper.go`

New field on `ComplianceReport` (`internal/compliance/types.go:40-49`):

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

New function in `internal/compliance/mapper.go`, called from `GenerateReport()` right before its final `return` (`mapper.go:~220`), using the exact `domains`, `controlResults`, and summary values already computed in that function — no new data collection, purely a summary of what's already there:

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
		// a deterministic pick — map iteration order is not stable in Go, so
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

`mapper.go`'s existing import block already has `fmt`, `sort`, and `strings` (used elsewhere in the file already) — no import changes needed.

`GenerateReport()`'s final return gains one line:

```go
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
```

(This requires naming the previously-inline `ComplianceSummary{...}` literal `summary` first, so `buildNarrative` can take it — a one-line refactor of the existing return statement, not a behavior change.)

Since `WriteCSV`/`WriteJSON`/PDF export all serialize `*ComplianceReport` as-is, the narrative automatically flows into every export format for free — no separate export-layer change needed.

### 3. Tile hover tooltip — `orchestrator/wwwroot/index.html`

`complianceTile()` (`:11342`) currently sets `title="' + x(fw.frameworkName) + '"'` on the outer tile `<div>` (a bare framework-name tooltip). Replace with a richer, still-plain-text `title` (native browser tooltips render `\n` as line breaks — no new tooltip component needed):

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
```

Called from `complianceTile()`:

```js
'title="' + x(fw.frameworkName) + '\n' + x(complianceWhy(fw)) + '"'
```

This never calls a new endpoint — every field `complianceWhy()` reads is already present on the `/api/compliance/scores` response (`fw.enrolledAgentCount` is the one new field, added in §1).

### 4. One-click drill-in — `orchestrator/wwwroot/index.html`

`complianceTile()`'s outer `<div>` currently has `onclick="showTab('compliance')"`. Replace with a deep-link that also selects the right agent + framework and generates the report, in one click:

```js
function openComplianceDetail(frameworkId, agentId) {
  showTab('compliance');
  var fwSel = document.getElementById('cmp-fw-sel');
  var agSel = document.getElementById('cmp-agent-sel');
  if (fwSel) fwSel.value = frameworkId;
  if (agSel && agentId) agSel.value = agentId;
  loadComplianceReport();
}
```

Called from `complianceTile()`:

```js
'onclick="openComplianceDetail(\'' + x(fw.frameworkId) + '\', \'' + x(fw.agentId) + '\')"'
```

`fw.agentId` is real now for both call paths — the worst-performing agent in fleet-wide mode (after §1's fix) or the queried agent in single-agent mode (unaffected by this plan, since that path was already correct). The existing `#cmp-agent-sel`/`#cmp-fw-sel` population logic (`:12305-12319`) already runs once on tab load and is unaffected; `openComplianceDetail` just also sets their `.value` and immediately calls the existing `loadComplianceReport()` — no duplication of that function's logic.

The "View details →" link (`:1407`, same `onclick="showTab('compliance')"` pattern, sits above the tile row) stays as a plain tab-switch — it isn't tied to any one framework/tile, so there's nothing to deep-link it to.

### 5. Narrative rendering in the full report — `orchestrator/wwwroot/index.html`

`renderComplianceReport()` (`:12351`) currently builds `#cmp-header-area` with the framework badge/name/version and the ring gauge, nothing else. Add the narrative as a plain-language line inside that same header card, between the framework name block and the gauge:

```js
'<div class="cmp-header-narrative" style="margin-top:0.5rem;font-size:0.85rem;line-height:1.5;color:var(--text-dim);max-width:520px">' +
  x(r.narrative || '') +
'</div>'
```

Placed in the existing `cmp-header-left` block, right after the `cmp-fw-version` div and before the closing `</div>` of `cmp-header-left` — reads naturally alongside the framework identity, ahead of (not competing with) the ring gauge's raw percentage.

## Non-goals

- **No change to `GetComplianceScores` (single-agent query)** — it was already internally consistent (one agent, one coherent snapshot); only the fleet-wide aggregation had the mismatch.
- **No new database columns or migrations.** `EnrolledAgentCount` is computed in-query via a window function, not stored.
- **No changes to CSV/JSON/PDF export code.** They already serialize the full `ComplianceReport` struct, so `Narrative` is included automatically once it's a field on that struct.
- **No changes to per-control evidence rendering** (`renderControlsTable`, `toggleEvidence` — `:12434-12484`) — that granular "why" already works well; this plan adds the missing *summary* layer above it, not a replacement for it.
- **No new tooltip/popover UI library.** The hover "why" uses the native HTML `title` attribute, consistent with the tile's existing tooltip usage.
- **Single-agent dashboard view isn't being built.** `loadComplianceScores(agentId)`'s parameterized path stays supported (untouched) but isn't wired to any visible dashboard control today — out of scope here.

## Testing

- **Go unit test** for `buildNarrative()` (`internal/compliance/mapper_test.go` — new file; the package's only existing test file, `loader_test.go`, covers framework-YAML parsing, a different concern): table-driven cases covering zero-tested ("No controls have been tested yet..."), all-passing (no second sentence), mixed pass/fail with a clear top domain and top technique, a tie between two domains (alphabetical tie-break), and a tie between two techniques (technique-ID tie-break) — asserting exact string output for each.
- **Go unit test** for the fixed `GetFleetComplianceScores` query, in a new `internal/db/compliance_snapshot_test.go` (`package db_test`), using the existing Docker-backed shared test Postgres (`internal/testutil.MustSharedTestDB()` — same pattern as `tenant_test.go`): seed `compliance_snapshots` with 2+ agents at different `compliance_pct` values for the same framework, assert the returned row's `AgentID`/`CompliancePct`/`PassingControls`/`FailingControls`/etc. all belong to the single lowest-`compliance_pct` agent (not a blend), and `EnrolledAgentCount` equals the seeded agent count for that framework.
- **Live UI verification** (dev server, real browser): hover a tile, confirm the tooltip text matches `complianceWhy()`'s expected phrasing for both a fleet-wide (`enrolledAgentCount > 1`) and single-agent scenario; click a tile, confirm it lands directly on a populated report (no empty-form step) with the narrative sentence visible at the top, matching what `buildNarrative()` produced for that same data.
