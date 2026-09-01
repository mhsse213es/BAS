# Unified Detection Validation Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Results page's "Detection Validation" tab surface the already-built, `detectverify`-authoritative per-expectation model (`internal/reporting.DetectionValidationSection`) instead of only the legacy per-run SIEM bulk-correlation panel, falling back to that legacy panel when the richer model has no data for a run.

**Architecture:** The backend already computes everything needed — `internal/reporting.Engine.BuildFromRun` populates `report.DetectionValidation`, which already overlays `detectverify`'s Verification Store attestations (`Source=api`, `Provider=<connector>`) on top of automatic on-host verdicts. The only backend gap is that `GetRunReportData` (`GET /api/scenarios/runs/{runId}/report.json`) never includes that field in its JSON response. The frontend gap is that the "Detection Validation" tab has never been wired to this endpoint at all — it independently calls the older `/api/siem/correlations/{runId}` endpoint. This plan adds the one missing response key server-side, then rewrites the tab's rendering to use it when available, falling back to the existing (unmodified) legacy panel when it isn't.

**Tech Stack:** Go (`net/http`, `encoding/json`, `pgx`), vanilla JS in a single `wwwroot/index.html`, `node --check` for JS syntax validation.

**Spec:** None — user explicitly approved skipping the spec doc for this task ("go straight to the plan, skip the spec"), treating the grounded design summary from the brainstorming conversation as approved. That summary is reproduced in full in the Global Constraints section below so this plan is self-contained.

## Global Constraints

- Do NOT delete, modify, or stop calling `loadSIEMCorrelationPanel` or `GET /api/siem/correlations/{runId}` — the legacy per-run SIEM bulk-correlation subsystem stays exactly as-is, used only as a fallback when the new section has no data.
- Do NOT build a new "unified read model" abstraction, new detection subsystem, or any new backend merge/precedence code. The backend merge already happened inside `buildDetectionValidation` (`internal/reporting/detection_validation.go:389`) before this plan starts — this plan only exposes that existing computation and renders it.
- Terminology in the new table: `DETECTED` (green) / `MISSED` (red) / `NOT RUN` (grey) — not "SIEM DETECTED/SIEM MISSED". `NotApplicable` rows are excluded from the table entirely (matching the existing legacy panel's own `not_applicable` filter).
- Reuse `report.DetectionSources` (already returned by `GetRunReportData` today) for the "Verification source" chip row — do not add a new backend field for that.
- Reuse the existing global `vfStatusColor(status)` function (`wwwroot/index.html:5776`) for badge colors — do not duplicate color logic. Do NOT reuse `vfStatusLabel` for the label text — it says "SILENT" for `NotDetected`, which is a different, deliberately-different wording convention for the analyst review queue it serves; this tab needs its own small label map using the user's exact requested words.
- Precedence: render the new table when `rep.detectionValidation.hasData === true`; call `loadSIEMCorrelationPanel(runId)` (exactly as today) when it's `false`. This is a simple boolean branch, not a scored/weighted merge.
- Do not add a second fetch of `/api/scenarios/runs/{runId}/report.json` — the drawer already fetches it once (`wwwroot/index.html:13975`) and fans the result out to multiple tabs; extend that existing `.then()` callback.
- Run `go test ./internal/api/...` (full package) before considering the backend task done. Run `node --check` on the extracted inline script before considering the frontend task done. Commit after each task; `git push` immediately after every commit.

---

### Task 1: Expose `detectionValidation` on the report.json endpoint

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:5025-5044` (the `respond(w, map[string]any{...})` block inside `GetRunReportData`)
- Test: `orchestrator/internal/api/run_report_api_test.go` (extend `TestGetRunReportData_Shape`)

**Interfaces:**
- Consumes: `report.DetectionValidation` — already a populated field of type `reporting.DetectionValidationSection` on the `report` variable already in scope in `GetRunReportData` (set by `h.reportingEngine.BuildFromRun(...)` a few lines above the `respond(...)` call). No new Go type, no new function.
- Produces: response JSON gains one new top-level key, `"detectionValidation"`, whose value is `DetectionValidationSection` marshaled via its existing `json:"..."` struct tags (already defined in `internal/reporting/detection_validation.go:301-315`): `hasData`, `coverage`, `verificationCompleteness`, `overall`, `telemetryCompleteness`, `expected`, `verified`, `detected`, `byDomain`, `rows`, `falseSilence`, `unexpectedDetections`, `profiles`. Each element of `rows` is an `ExpectationRow` (`internal/reporting/detection_validation.go:330-345`) with `technique_id`→`techniqueId`, `expectedId`, `provider`, `domain`, `confidence`, `verification`, `status`, `source`, `workflowState`, `analyst`, `timestamp`, `evidenceCount`, `integrity`, `comments` — all `json:"..."` tags already exist on the struct, no changes needed there. Task 2 consumes this exact shape from the frontend as `rep.detectionValidation`.

- [ ] **Step 1: Write the failing test**

Open `orchestrator/internal/api/run_report_api_test.go` and extend the existing `TestGetRunReportData_Shape` (around line 54-84) — add this assertion right after the existing `killChain` key check (after line 82, still inside the same `sharedDB.RunWithPool` closure, before the closing `})`):

```go
		if _, ok := out["detectionValidation"]; !ok {
			t.Fatal("missing detectionValidation key")
		}
		dv, ok := out["detectionValidation"].(map[string]any)
		if !ok {
			t.Fatalf("detectionValidation = %T, want a JSON object", out["detectionValidation"])
		}
		if _, ok := dv["hasData"]; !ok {
			t.Fatal("detectionValidation missing hasData key")
		}
```

The full function should now read (only the new lines are additions — everything else is unchanged from what's already in the file):

```go
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
		if _, ok := out["detectionValidation"]; !ok {
			t.Fatal("missing detectionValidation key")
		}
		dv, ok := out["detectionValidation"].(map[string]any)
		if !ok {
			t.Fatalf("detectionValidation = %T, want a JSON object", out["detectionValidation"])
		}
		if _, ok := dv["hasData"]; !ok {
			t.Fatal("detectionValidation missing hasData key")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd orchestrator
go test ./internal/api/... -run TestGetRunReportData_Shape -v
```

Expected: FAIL — `out["detectionValidation"]` assertion fails with "missing detectionValidation key" (the seeded fixture scenario in `seedReportableRun`/`reportRunOpts{}` declares no `detection_profiles`, so once the field IS added it will still report `hasData: false` — that's fine and expected; this step is only checking the key exists in the response at all, not that it's populated with real rows).

- [ ] **Step 3: Add the missing response key**

Open `orchestrator/internal/api/handlers.go`. Find the `respond(w, map[string]any{...})` block inside `GetRunReportData` (currently starts around line 5025 with `"topFindings": report.TopFindings,` and ends around line 5044 with `"cleanupFailed": report.CleanupFailed,`). Add one new line to that map, next to the existing `"detectionSources"` entry so the two related fields sit together:

```go
		"detectionSources":       report.DetectionSources,
		"detectionValidation":    report.DetectionValidation,
		"cleanupFailed":          report.CleanupFailed,
```

(Only the `"detectionValidation"` line is new — `"detectionSources"` and `"cleanupFailed"` already exist in the file exactly as shown; this just inserts the new line between them, matching the existing map's alignment/gofmt spacing.)

- [ ] **Step 4: Run test to verify it passes**

```bash
cd orchestrator
go test ./internal/api/... -run TestGetRunReportData_Shape -v
```

Expected: PASS

- [ ] **Step 5: Run the full internal/api suite**

```bash
cd orchestrator
go test ./internal/api/... -timeout 20m
```

Expected: `ok` with zero `FAIL` lines. This package's suite is large (~10-16 minutes) — run it with `run_in_background` and wait for the notification rather than polling.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/run_report_api_test.go
git commit -m "feat(api): expose DetectionValidation on GET /api/scenarios/runs/{runId}/report.json

The field was already computed (BuildFromRun populates report.DetectionValidation,
which already overlays detectverify's Verification Store attestations on top of
automatic on-host verdicts) but never included in this handler's response map."
git push
```

---

### Task 2: Render the unified table in the Detection Validation tab, with legacy fallback

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (two locations: the shared `report.json` fetch callback around line 13975-13983, and a new render function placed near `loadSIEMCorrelationPanel`, currently at line 14054)

**Interfaces:**
- Consumes: `rep.detectionValidation` from Task 1's new response key, shaped exactly as documented in Task 1's "Produces" — specifically `rep.detectionValidation.hasData` (bool), `.coverage` (number, 0-100), `.expected`/`.verified`/`.detected` (ints), `.rows` (array of objects with `.techniqueId`, `.provider`, `.status`, `.source`, `.domain` string fields, all already camelCase per the Go struct's JSON tags). Also consumes `rep.detectionSources` (array of `{product, detections, minMttdMs, avgMttdMs}`, already present in every `report.json` response today — unchanged by Task 1). Also consumes the existing global `vfStatusColor(status)` function (`wwwroot/index.html:5776`) and the existing global `x(s)` HTML-escape helper (used throughout this file) and `apicall`/`loadSIEMCorrelationPanel` (existing functions, unchanged).
- Produces: a new global function `renderDetectionValidationTab(rep, run)` — takes the already-fetched `rep` object (the `report.json` response) and the `run` object already in scope at the call site (`viewRunResults(run)`'s own parameter, confirmed at `wwwroot/index.html:13463` — has `.id`, `.completedAt`, `.startedAt`, `.agentId`, per `internal/models/schema.go`'s `ScenarioRun` struct, `json:"agentId"`/`json:"completedAt,omitempty"`/`json:"startedAt"`). `report.json`'s own response has NO `run` key — do not write `rep.run.*` anywhere; the run metadata comes from the separately-passed `run` parameter, not from `rep`. Returns nothing (renders directly into `#rv-siem` via `innerHTML`, or delegates to `loadSIEMCorrelationPanel(runId)`, with `runId` derived internally as `run.id`, when `rep.detectionValidation.hasData` is falsy). No other task calls into this function; it's wired into the existing shared fetch callback in this same task.

- [ ] **Step 1: Add the status-label map and the new render function**

Open `orchestrator/wwwroot/index.html`. Find `loadSIEMCorrelationPanel` (currently starting at line 14054, right after the `switchRunTab` function). Insert the new code immediately **before** `loadSIEMCorrelationPanel`'s own definition, so the legacy function stays completely untouched below it:

```javascript
// Status label map for the unified Detection Validation tab. Deliberately
// separate from vfStatusLabel (used by the analyst verification-review
// queue elsewhere in this file) -- that one says "SILENT" for NotDetected,
// a wording choice specific to that different audience. This tab uses the
// generic DETECTED/MISSED/NOT RUN wording the user explicitly requested,
// since this platform supports 6+ detection providers and "SIEM
// DETECTED/MISSED" is too narrow now that detectverify's connectors
// (Sentinel, Defender, Splunk, QRadar, CrowdStrike, Trellix) all feed in.
var DV_STATUS_LABEL = {
  Detected: 'DETECTED',
  NotDetected: 'MISSED',
  Pending: 'NOT RUN',
  Unknown: 'NOT RUN'
  // NotApplicable rows are filtered out before reaching this map -- see
  // renderDetectionValidationTab's .filter() call below.
};

// renderDetectionValidationTab renders internal/reporting.DetectionValidationSection
// (fetched as part of the shared report.json call) into the Detection
// Validation tab. This section already overlays detectverify's Verification
// Store attestations (Source=api, Provider=<connector>) on top of automatic
// on-host verdicts server-side (internal/reporting/detection_validation.go)
// -- this function only renders what's already been merged, it does not
// merge anything itself.
//
// Falls back to the legacy per-run SIEM bulk-correlation panel
// (loadSIEMCorrelationPanel, unchanged) when dv.hasData is false -- true for
// roughly 3/4 of runs today, since most scenarios don't yet declare
// detection_profiles. That fallback stays in place; this is additive, not
// a replacement.
function renderDetectionValidationTab(rep, run) {
  var el = document.getElementById('rv-siem');
  if (!el) return;
  var runId = (run && run.id) || '';
  var dv = rep && rep.detectionValidation;
  if (!dv || !dv.hasData) {
    loadSIEMCorrelationPanel(runId);
    return;
  }

  var coverage = dv.coverage || 0;
  var covColor = coverage >= 70 ? 'var(--success)' : coverage >= 40 ? 'var(--warning)' : 'var(--danger)';
  // Miss rate: percentage of *resolved* (Detected or NotDetected) expectations
  // that were NotDetected. Using dv.verified (not dv.expected) as the
  // denominator so an in-flight run with many still-Pending expectations
  // doesn't show an inflated miss rate for expectations nobody has checked
  // yet -- Pending rows are "not run", not "missed".
  var missRate = dv.verified > 0 ? Math.round(((dv.verified - dv.detected) / dv.verified) * 1000) / 10 : 0;
  // "Verified Findings" = dv.detected: a technique-scoped count of
  // expectations independently confirmed Detected, backed by connector/
  // on-host evidence -- not a raw alert tally, which the user explicitly
  // said not to present as if it were a detection-rate statistic.
  var verifiedFindings = dv.detected || 0;

  var sources = (rep.detectionSources || []).map(function(s) {
    return '<span style="display:inline-flex;align-items:center;gap:0.3rem;background:var(--elevated);border:1px solid var(--border);border-radius:999px;padding:0.15rem 0.6rem;font-size:0.72rem;color:var(--text)">' +
      '<span style="color:var(--success)">&#10003;</span>' + x(s.product) + '</span>';
  }).join(' ');

  var runTs = run && (run.completedAt || run.startedAt);
  var metaParts = [];
  if (runTs) metaParts.push('Verified: ' + new Date(runTs).toLocaleString());
  if (run && run.agentId) metaParts.push('Agent: <code>' + x(run.agentId) + '</code>');

  var rows = (dv.rows || [])
    .filter(function(row) { return row.status !== 'NotApplicable'; })
    .map(function(row) {
      var label = DV_STATUS_LABEL[row.status] || (row.status || 'NOT RUN').toUpperCase();
      var color = vfStatusColor(row.status);
      var badge = '<span style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '55;border-radius:3px;font-size:0.67rem;font-weight:700;padding:0.1rem 0.4rem">' + x(label) + '</span>';
      var providerBadge = row.provider
        ? '<span style="font-size:0.68rem;color:var(--muted);background:var(--elevated);border:1px solid var(--border);border-radius:3px;padding:0.03rem 0.3rem">' + x(row.provider) + '</span>'
        : '<span style="color:var(--muted)">&mdash;</span>';
      return '<tr><td style="font-family:monospace;font-size:0.72rem;padding:0.3rem 0.5rem">' + x(row.techniqueId) + '</td>' +
             '<td style="padding:0.3rem 0.5rem">' + badge + '</td>' +
             '<td style="padding:0.3rem 0.5rem">' + providerBadge + '</td>' +
             '<td style="font-size:0.72rem;color:var(--muted);text-transform:capitalize;padding:0.3rem 0.5rem">' + x(row.domain || '') + '</td></tr>';
    }).join('');

  el.innerHTML =
    '<div style="padding:1rem 0 0.5rem">' +
      '<div style="display:flex;gap:1.5rem;margin-bottom:0.75rem;flex-wrap:wrap">' +
        '<div style="text-align:center">' +
          '<div style="font-size:1.7rem;font-weight:700;color:' + covColor + '">' + coverage + '%</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Detection Coverage</div>' +
        '</div>' +
        '<div style="text-align:center">' +
          '<div style="font-size:1.7rem;font-weight:700;color:var(--danger)">' + missRate + '%</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Detection Miss Rate</div>' +
        '</div>' +
        '<div style="text-align:center">' +
          '<div style="font-size:1.7rem;font-weight:700">' + verifiedFindings + '</div>' +
          '<div style="font-size:0.68rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em">Verified Findings</div>' +
        '</div>' +
      '</div>' +
      (sources ? '<div style="margin-bottom:0.5rem;font-size:0.7rem;color:var(--muted)">Verification source:</div><div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-bottom:0.75rem">' + sources + '</div>' : '') +
      (metaParts.length ? '<div style="font-size:0.68rem;color:var(--muted);margin-bottom:0.75rem">' + metaParts.join(' &nbsp;|&nbsp; ') + '</div>' : '') +
      '<table style="width:100%;border-collapse:collapse;font-size:0.73rem">' +
        '<thead><tr style="border-bottom:1px solid var(--border);color:var(--muted);font-size:0.67rem;text-align:left">' +
          '<th style="padding:0.3rem 0.5rem">Technique</th>' +
          '<th style="padding:0.3rem 0.5rem">Detection</th>' +
          '<th style="padding:0.3rem 0.5rem">Source</th>' +
          '<th style="padding:0.3rem 0.5rem">Domain</th>' +
        '</tr></thead>' +
        '<tbody>' + (rows || '<tr><td colspan="4" style="color:var(--muted);padding:1rem 0;text-align:center">No technique details available</td></tr>') + '</tbody>' +
      '</table>' +
    '</div>';
}

```

- [ ] **Step 2: Wire it into the existing shared report.json fetch, replacing the direct `loadSIEMCorrelationPanel` call**

Find the shared fetch (currently at `wwwroot/index.html:13975-13983`):

```javascript
    apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/report.json').then(function(rep) {
      // Guard: a different run may have been opened while this was in flight.
      if (document.getElementById('run-report-extra') === extraEl) {
        extraEl.innerHTML = renderRunReportExtra(rep);
        var findingsEl = document.getElementById('run-report-findings');
        if (findingsEl) findingsEl.innerHTML = renderRunFindings(rep);
        var recEl = document.getElementById('run-report-recommendation');
        if (recEl) recEl.innerHTML = renderRunRecommendations(rep);
      }
    }).catch(function() {
```

Add one line inside the `if` block, calling the new function with the already-fetched `rep` and the `run` parameter already in scope in this closure (`viewRunResults(run)`'s own parameter — this callback is nested directly inside that function, confirmed at `wwwroot/index.html:13463`/`13975`):

```javascript
    apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/report.json').then(function(rep) {
      // Guard: a different run may have been opened while this was in flight.
      if (document.getElementById('run-report-extra') === extraEl) {
        extraEl.innerHTML = renderRunReportExtra(rep);
        var findingsEl = document.getElementById('run-report-findings');
        if (findingsEl) findingsEl.innerHTML = renderRunFindings(rep);
        var recEl = document.getElementById('run-report-recommendation');
        if (recEl) recEl.innerHTML = renderRunRecommendations(rep);
        renderDetectionValidationTab(rep, run);
      }
    }).catch(function() {
```

Now find the old direct call, currently at line 14011 (`// SIEM Correlation panel — load if a correlation result exists for this run.` / `loadSIEMCorrelationPanel(runId);`), and **delete both of those two lines**. The tab is now populated exclusively through `renderDetectionValidationTab`, which itself calls `loadSIEMCorrelationPanel(runId)` internally as its fallback branch — calling it a second time unconditionally here would double-fetch `/api/siem/correlations/{runId}` and race against the fallback branch's own call.

- [ ] **Step 3: Extract and syntax-check the modified inline script**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
python3 -c "
import re
data = open('orchestrator/wwwroot/index.html', encoding='utf-8').read()
scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', data, re.S)
out = '\n;\n'.join(scripts)
open(r'C:/Users/ADMINI~1/AppData/Local/Temp/claude/C--Users-Administrator-Downloads-Audspect-Cloud/76be556d-bf6b-4e85-a7ce-d0885849aac3/scratchpad/dv_tab_scripts.js', 'w', encoding='utf-8').write(out)
"
node --check "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\dv_tab_scripts.js"
```

Expected: no output from `node --check` (success is silent; a syntax error prints a `SyntaxError` with a line number). Delete the temp file afterward:

```bash
rm -f "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\dv_tab_scripts.js"
```

- [ ] **Step 4: Attempt a live browser verification; report honestly if not feasible**

Spin up the dev stack the same way prior frontend tasks this session did (Docker Postgres + `go run ./cmd/server` + login), open a run whose scenario declares `detection_profiles` (e.g. one of the LockBit/ransomware-family scenarios, or `dlp-exfiltration-validation.yaml`) in the Results drawer, and confirm:
  - The Detection Validation tab shows the new Coverage/Miss Rate/Verified Findings tiles, source chips, and per-technique table with `DETECTED`/`MISSED`/`NOT RUN` badges.
  - Opening a run whose scenario declares no `detection_profiles` still shows the old legacy SIEM panel (or its existing empty state) exactly as before.

If a live dev environment cannot reasonably be spun up in this session, say so explicitly rather than claiming this step was verified — this mirrors the honesty standard already applied to the "step-name display fix" commit earlier this session (`3d3238e`), which explicitly noted "Not yet verified against a live browser render."

- [ ] **Step 5: Commit**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): render the unified Detection Validation tab from detectverify's overlaid model

Detection Validation now reads report.detectionValidation (Task 1's newly-exposed
field) -- already the detectverify-authoritative per-expectation model, since
buildDetectionValidation already overlays the Verification Store's API attestations
on top of automatic on-host verdicts server-side. Falls back to the existing,
unmodified legacy SIEM bulk-correlation panel when detectionValidation.hasData is
false (~3/4 of runs today, since most scenarios don't yet declare detection_profiles).

Terminology changed from SIEM-specific DETECTED/MISSED to generic DETECTED/MISSED/
NOT RUN badges with the provider shown as its own column, reusing the existing
vfStatusColor() color mapping but not vfStatusLabel() (that one says SILENT, a
wording choice specific to the analyst verification-review queue it serves)."
git push
```

---

## Self-Review

**Spec coverage:** Every element of the approved design direction has a task: backend field exposure (Task 1), terminology change + Provider column + Coverage/Miss-Rate/Verified-Findings tiles + source chips + run metadata line + hasData-gated fallback to the untouched legacy panel (all Task 2). No new backend merge logic was added anywhere, matching the explicit constraint.

**Placeholder scan:** No TBD/TODO; every code block is complete, runnable code with exact file paths and line-anchored context copied from the actual current file contents read this session, not assumed.

**Type consistency:** `renderDetectionValidationTab(rep, run)` is defined once (Task 2 Step 1) and called once (Task 2 Step 2) with matching arguments. `DV_STATUS_LABEL` and `renderDetectionValidationTab` are both defined before `loadSIEMCorrelationPanel`, which `renderDetectionValidationTab` calls — no forward-reference problem since both are plain top-level `function`/`var` statements in the same script, hoisted per the file's existing pattern (already confirmed working for `displayStepName`/`x`/other cross-function calls earlier this session). Field names read off `rep.detectionValidation.*` and `rep.detectionSources[].*` match the exact `json:"..."` tags on `DetectionValidationSection`/`ExpectationRow`/`DetectionSource` verified directly from `internal/reporting/detection_validation.go` and `internal/reporting/engine.go` this session — no invented field names.
