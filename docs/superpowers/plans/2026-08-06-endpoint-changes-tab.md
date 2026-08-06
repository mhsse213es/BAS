# Endpoint Changes Tab (V1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate the "Endpoint Changes" tab in the per-run results drawer with the endpoint-change list the agent already captures and the server already stores, but the dashboard never reads.

**Architecture:** Two small, independent changes. Backend: expose the already-populated `scenario_runs.reverted` jsonb column through `ListScenarioRuns` (the endpoint that already feeds every other field `viewRunResults` renders). Frontend: replace the `soonPanel('Endpoint Changes')` placeholder with a real render of `run.reverted`, following the same framing text already shipping in the PDF report.

**Tech Stack:** Go, `pgx/v5`, existing `ListScenarioRuns` handler; vanilla JS in `orchestrator/wwwroot/index.html` (no framework, no build step).

## Global Constraints

- No new database column, no new agent code, no new API endpoint — every piece of data needed already exists (see spec's Investigation section).
- V1 does not surface changes that failed to revert (deferred to a separate V2 design) — don't add that here.
- `models.ScenarioRun`'s public JSON shape may only gain the one new field; no other field renamed or restructured.
- Frontend: any run-reported string rendered into `innerHTML` must go through the existing `x()` HTML-escaper — never raw-interpolated (established security discipline this session, verified via XSS-safety checks on the Timeline/MITRE tabs).

---

### Task 1: Expose `reverted` through `ListScenarioRuns`

**Files:**
- Modify: `orchestrator/internal/models/schema.go:132-151` (`ScenarioRun` struct)
- Modify: `orchestrator/internal/api/handlers.go:2197-2257` (`ListScenarioRuns`)
- Test: `orchestrator/internal/api/list_scenario_runs_test.go`

**Interfaces:**
- Produces: `models.ScenarioRun.Reverted []string` (json tag `reverted,omitempty`) — Task 2's frontend work reads this as `run.reverted`.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/list_scenario_runs_test.go` (mirrors `TestListScenarioRuns_ScoreProjection` immediately above it exactly — same populated-vs-null-row pattern):

```go
func TestListScenarioRuns_RevertedProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-reverted-proj','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		revertedJSON, _ := json.Marshal([]string{
			`registry removed: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`,
			"schtask deleted: EvilTask",
		})
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, reverted)
			 VALUES ('reverted-proj-run','sc-reverted-proj','agent-reverted-proj','x','completed',NOW(),$1)`, revertedJSON); err != nil {
			t.Fatalf("seed run with reverted: %v", err)
		}
		seedRunRow(t, pool, "null-reverted-run", "sc-reverted-proj", "agent-reverted-proj", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-reverted-proj", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withReverted, withoutReverted map[string]any
		for _, r := range runs {
			if r["id"] == "reverted-proj-run" {
				withReverted = r
			}
			if r["id"] == "null-reverted-run" {
				withoutReverted = r
			}
		}
		if withReverted == nil || withoutReverted == nil {
			t.Fatalf("expected both seeded runs, got %+v", runs)
		}
		rv, ok := withReverted["reverted"].([]any)
		if !ok || len(rv) != 2 {
			t.Fatalf("reverted-proj-run reverted = %v, want 2 items", withReverted["reverted"])
		}
		if rv[0] != `registry removed: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil` {
			t.Fatalf("reverted[0] = %v, want the registry-removal string", rv[0])
		}
		if _, present := withoutReverted["reverted"]; present {
			t.Fatalf("null-reverted-run: expected omitted reverted field, got %v", withoutReverted["reverted"])
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestListScenarioRuns_RevertedProjection -v`
Expected: FAIL — `models.ScenarioRun` has no `Reverted` field yet, so `withReverted["reverted"]` is `nil` and the type assertion `.([]any)` fails.

- [ ] **Step 3: Add the field to `models.ScenarioRun`**

In `orchestrator/internal/models/schema.go`, add to the `ScenarioRun` struct (after `CompletedAt`, before the `AlertsTotal` block — matches the spec's placement rationale: a stored, canonical run property, same category as `AlertsTotal`/`NoiseScore`):

```go
	// Reverted is one human-readable line per endpoint change the agent
	// detected and successfully rolled back after the run (registry keys,
	// services, scheduled tasks, temp files, hosts file, startup entries --
	// see agent/snapshot_windows.go's captureSnapshot/revertFromSnapshot).
	// Changes that were detected but failed to revert are NOT included here
	// -- see docs/superpowers/specs/2026-08-06-endpoint-changes-tab-design.md.
	Reverted []string `json:"reverted,omitempty"`
```

So the struct reads:

```go
type ScenarioRun struct {
	ID          string             `json:"id"`
	ScenarioID  string             `json:"scenarioId"`
	Name        string             `json:"name"`
	AgentID     string             `json:"agentId"`
	Status      string             `json:"status"` // running | completed | partial | failed
	Results     []SimulationResult `json:"results"`
	Score       *Score             `json:"score,omitempty"`
	Progress    *RunProgress       `json:"progress,omitempty"`
	StartedAt   time.Time          `json:"startedAt"`
	CompletedAt *time.Time         `json:"completedAt,omitempty"`

	// Reverted is one human-readable line per endpoint change the agent
	// detected and successfully rolled back after the run (registry keys,
	// services, scheduled tasks, temp files, hosts file, startup entries --
	// see agent/snapshot_windows.go's captureSnapshot/revertFromSnapshot).
	// Changes that were detected but failed to revert are NOT included here
	// -- see docs/superpowers/specs/2026-08-06-endpoint-changes-tab-design.md.
	Reverted []string `json:"reverted,omitempty"`

	AlertsTotal        int     `json:"alertsTotal"`
	AlertsHighFidelity int     `json:"alertsHighFidelity"`
	NoiseScore         float64 `json:"noiseScore"`

	PerfCPUBefore  float64 `json:"perfCpuBefore"`
	PerfCPUAfter   float64 `json:"perfCpuAfter"`
	PerfRAMBefore  float64 `json:"perfRamBefore"`
	PerfRAMAfter   float64 `json:"perfRamAfter"`
```

(Only the new `Reverted` block is added; every other line is unchanged context to locate the insertion point.)

- [ ] **Step 4: Wire it into `ListScenarioRuns`**

In `orchestrator/internal/api/handlers.go`, change the query (`handlers.go:2201-2208`) to add `reverted`:

```go
	rows, err := h.db.Query(r.Context(),
		`SELECT id, scenario_id, agent_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted
		 FROM scenario_runs
		 WHERE ($1 = '' OR agent_id = $1)
		   AND ($2 = '' OR scenario_id = $2)
		 ORDER BY started_at DESC LIMIT 100`,
		agentID, scenarioID,
	)
```

Then update the scan block (`handlers.go:2226-2244`):

```go
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw, detRaw, revertedRaw []byte
		var p models.RunProgress
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt,
			&p.StepsTotal, &p.StepsDone, &p.StepsRunning, &p.StepsPassed, &p.StepsFailed, &p.StepsTimeout, &detRaw,
			&run.AlertsTotal, &run.AlertsHighFidelity, &run.NoiseScore, &revertedRaw); err != nil {
			log.Printf("[api] list runs scan: %v", err)
			continue
		}
		json.Unmarshal(resultsJSON, &run.Results)
		if len(scoreRaw) > 0 {
			json.Unmarshal(scoreRaw, &run.Score)
		}
		if len(revertedRaw) > 0 {
			json.Unmarshal(revertedRaw, &run.Reverted)
		}
		if d := reporting.DetectedTechniques(detRaw, run.Results); len(d) > 0 {
			run.DetectedTechs = d
		}
```

The `if len(revertedRaw) > 0` guard is load-bearing, not optional style — `json.Unmarshal` on zero-length bytes (the `NULL`-column case) returns an "unexpected end of JSON input" error rather than producing an empty slice, exactly mirroring why the adjacent `scoreRaw` uses the same guard one line above.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestListScenarioRuns -v`
Expected: PASS, including the new `TestListScenarioRuns_RevertedProjection` and every pre-existing `TestListScenarioRuns_*` test in the same file (confirms the added column/field didn't disturb the existing projections).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/models/schema.go orchestrator/internal/api/handlers.go orchestrator/internal/api/list_scenario_runs_test.go
git commit -m "feat(api): expose scenario_runs.reverted through ListScenarioRuns"
```

---

### Task 2: Render the Endpoint Changes tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (`viewRunResults`, currently ending its tab-content build around line 10953)

**Interfaces:**
- Consumes: `run.reverted` (Task 1) — a JS array of strings, or `undefined` when empty/absent (matches `omitempty` + nil-slice semantics).

- [ ] **Step 1: Add the `endpointHtml` builder**

In `orchestrator/wwwroot/index.html`, find the `mitreHtml` IIFE (added earlier this session, ends with `})();` immediately before the `// Overview keeps scorePanel...` comment). Insert a new `endpointHtml` IIFE immediately after it, following the exact same style (self-contained, only touches `run` and `x`):

```javascript
  // Endpoint Changes tab -- the agent already runs a whole-run before/after
  // snapshot (agent/snapshot_windows.go's captureSnapshot/revertFromSnapshot,
  // called once per run) and reverts anything new it finds (registry keys,
  // services, scheduled tasks, temp files, hosts file, startup entries),
  // returning one human-readable line per successfully-reverted item. That
  // list is already stored on every run (scenario_runs.reverted) and already
  // rendered in the PDF report (internal/reporting/pdf.go) -- this mirrors
  // the exact same framing text so the two surfaces agree. Changes that were
  // detected but FAILED to revert are not included here -- see
  // docs/superpowers/specs/2026-08-06-endpoint-changes-tab-design.md.
  var endpointHtml = (function() {
    var items = run.reverted || [];
    if (!items.length) {
      return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">No endpoint changes were captured for reversal during this run.</div>';
    }
    var rows = items.map(function(item) {
      return '<div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.3rem 0;border-bottom:1px solid rgba(34,50,74,0.45);font-size:0.78rem">' +
        '<span style="color:var(--muted)">&bull;</span><span>' + x(item) + '</span>' +
      '</div>';
    }).join('');
    return '<div style="padding:0.5rem 0">' +
      '<div style="color:var(--muted);font-size:0.78rem;margin-bottom:0.6rem">The agent reverted ' + items.length + ' endpoint change(s) made during the run.</div>' +
      rows +
    '</div>';
  })();
```

- [ ] **Step 2: Wire it into the tab content**

Replace the `run-tab-endpoint` line (`index.html:10953` as of this task — re-locate via `soonPanel('Endpoint Changes')` if it has shifted):

```javascript
    '<div id="run-tab-endpoint" class="run-tab-panel" style="display:none">' + soonPanel('Endpoint Changes') + '</div>';
```

with:

```javascript
    '<div id="run-tab-endpoint" class="run-tab-panel" style="display:none">' + endpointHtml + '</div>';
```

- [ ] **Step 3: Verify JS syntax**

Run (from `orchestrator/`):

```bash
node -e "
const fs = require('fs');
const content = fs.readFileSync('wwwroot/index.html', 'utf8');
const matches = [...content.matchAll(/<script>([\s\S]*?)<\/script>/g)];
const js = matches.map(m => m[1]).join('\n\n');
fs.writeFileSync('/tmp/endpoint_check.js', js);
"
node --check /tmp/endpoint_check.js
rm -f /tmp/endpoint_check.js
```

Expected: no output (clean syntax check), matching the same verification approach used for the Timeline/MITRE tabs earlier this session.

- [ ] **Step 4: Verify runtime behavior against realistic data**

This codebase's frontend has no test framework (single static HTML file) — verify via a temporary Node harness executing the exact inserted code, same approach used for Timeline/MITRE. Create a scratch file (not committed):

```javascript
function x(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// Case 1: populated
(function() {
  var run = { reverted: [
    'registry removed: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil',
    'schtask deleted: EvilTask',
    '<script>alert(1)</script>' // XSS probe -- must come out escaped
  ] };
  var endpointHtml = (function() {
    var items = run.reverted || [];
    if (!items.length) {
      return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">No endpoint changes were captured for reversal during this run.</div>';
    }
    var rows = items.map(function(item) {
      return '<div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.3rem 0;border-bottom:1px solid rgba(34,50,74,0.45);font-size:0.78rem">' +
        '<span style="color:var(--muted)">&bull;</span><span>' + x(item) + '</span>' +
      '</div>';
    }).join('');
    return '<div style="padding:0.5rem 0">' +
      '<div style="color:var(--muted);font-size:0.78rem;margin-bottom:0.6rem">The agent reverted ' + items.length + ' endpoint change(s) made during the run.</div>' +
      rows +
    '</div>';
  })();
  var failures = [];
  if (endpointHtml.indexOf('3 endpoint change(s)') === -1) failures.push('missing correct count');
  if (endpointHtml.indexOf('EvilTask') === -1) failures.push('missing schtask item');
  if (endpointHtml.indexOf('<script>alert(1)</script>') !== -1) failures.push('XSS: raw script tag leaked unescaped');
  if (endpointHtml.indexOf('&lt;script&gt;') === -1) failures.push('XSS probe was not properly escaped');
  console.log(failures.length ? 'CASE 1 FAILURES: ' + failures.join('; ') : 'CASE 1 PASSED');
})();

// Case 2: empty/absent
(function() {
  var run = {}; // reverted omitted entirely, matching omitempty+nil-slice
  var endpointHtml = (function() {
    var items = run.reverted || [];
    if (!items.length) {
      return '<div class="dash-panel dash-soon" style="padding:2rem;text-align:center;color:var(--muted);font-size:0.8rem">No endpoint changes were captured for reversal during this run.</div>';
    }
    return 'SHOULD NOT REACH HERE';
  })();
  var ok = endpointHtml.indexOf('No endpoint changes were captured') !== -1;
  console.log(ok ? 'CASE 2 PASSED' : 'CASE 2 FAILED: empty state text missing');
})();
```

Run: `node <path-to-scratch-file>.js`
Expected: `CASE 1 PASSED` and `CASE 2 PASSED` printed, no failures listed. Delete the scratch file afterward — it is not part of the repo.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): wire Endpoint Changes run tab to the existing reverted list"
```

---

## Self-Review

**Spec coverage:**
- `Reverted []string` field on `models.ScenarioRun`, placed as a canonical stored field → Task 1 Step 3. ✓
- `ListScenarioRuns` SQL + guarded unmarshal (matching `scoreRaw`'s nil-guard pattern, not `resultsJSON`'s unconditional one) → Task 1 Step 4. ✓
- Frontend render matching the PDF report's exact framing text and empty-state wording → Task 2 Step 1. ✓
- `x()` escaping discipline for agent-reported strings → Task 2 Step 1 (`x(item)`) and verified by Task 2 Step 4's XSS probe. ✓
- Non-goals (failed-revert visibility, per-step attribution, process-spawn tracking, changing `revertFromSnapshot` itself) → no task touches any of these; `agent/` is untouched by this entire plan. ✓
- Testing plan's two cases (populated jsonb value, `NULL` value) → Task 1 Step 1 (backend) and Task 2 Step 4 (frontend, mirrored). ✓

**Placeholder scan:** no TBD/TODO; every step has complete, real code.

**Type consistency:** `run.reverted` (JS, Task 2) matches `Reverted []string` `json:"reverted,omitempty"` (Go, Task 1) — a JSON string array serializes to exactly the JS array shape Task 2's code assumes (`run.reverted || []`, `.length`, `.map`). `endpointHtml` variable name used consistently between Task 2 Step 1 (definition) and Step 2 (wiring).

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-06-endpoint-changes-tab.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
