# Posture Finding SLA Report UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render `GET /api/sla/report` in the real dashboard as a new "SLA Compliance" card + sub-tab inside the existing Reports tab.

**Architecture:** A new `.dash-panel` card in the Reports grid opens a new `#tab-sla-report` sub-tab, structured like the existing `#tab-compliance` sub-tab. `showTab('sla-report')` triggers `loadSLAReport()`, which fetches the report once and renders 4 sections via reused existing components — no new CSS, no new frontend conventions.

**Tech Stack:** Vanilla JS in `orchestrator/wwwroot/index.html`, `node --check` for JS syntax validation (no test framework for this file).

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-29-posture-finding-sla-report-ui-design.md`

## Global Constraints

- Build directly on `main` — no worktree, no branches/PRs.
- Commit after the task; push immediately after every commit.
- Reuse existing components exactly — no new CSS classes, no new frontend conventions: `.kpi-row`/`.kpi-card.stat-tile`, `.bar-row`/`.bar-label`/`.bar-track`/`.bar-fill`, `.tbl-wrap`, `.sec-hdr`, `findingSevBadge(sev)`, `.empty`, global `apicall`/`x`/`fmtDate`/`showToast`.
- Scope is `GET /api/sla/report` only — no `GET /api/sla/breaches`, no policy editing, no new top-level nav item.
- `node --check` on the extracted inline script must pass with zero output before this is considered done.
- If a real dev environment isn't reasonably available to browser-verify this, say so explicitly rather than claiming untested UI work as verified.

---

### Task 1: SLA Compliance card + sub-tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (Reports grid ~line 3422, new `#tab-sla-report` block after `#tab-compliance` ~line 3787, `showTab` dispatcher ~line 5483)

**Interfaces:**
- Consumes: `GET /api/sla/report` (existing, Sub-project D1) — response shape `{overall: {totalEpisodes,onTime,late,currentlyOpen,complianceRate}, bySeverity: [{severity,totalEpisodes,onTime,late,currentlyOpen,complianceRate}], monthlyTrend: [{month,resolved,onTime,complianceRate}], recentlyResolved: [{agentId,checkId,severity,startedAt,resolvedAt,deadlineAt,onTime}]}`.
- Produces: `window._slaReport` (cached last-fetched report, read by nothing else in this task — exists for future extension, matching this codebase's existing per-tab cache-variable convention), `loadSLAReport()`, `renderSLAKPIs`, `renderSLASeverityBars`, `renderSLAMonthlyTrend`, `renderSLARecentlyResolved`.

- [ ] **Step 1: Add the Reports-grid card**

In `orchestrator/wwwroot/index.html`, find the Reports grid (currently 3 cards):

```html
        <div class="dash-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:1.25rem">
          <div class="dash-panel" style="cursor:pointer" onclick="openReportGen('posture')"><div class="dash-panel-body"><div class="kpi-label">Posture report</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Full per-agent posture</div><div class="tiny muted">Prevention, detection, kill-chain — HTML report</div></div></div>
          <div class="dash-panel" style="cursor:pointer" onclick="openReportGen('audit')"><div class="dash-panel-body"><div class="kpi-label">Audit pack</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Evidence bundle</div><div class="tiny muted">Per-agent audit-ready package</div></div></div>
          <div class="dash-panel" style="cursor:pointer" onclick="showTab('compliance')"><div class="dash-panel-body"><div class="kpi-label">Compliance evidence</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Framework mapping</div><div class="tiny muted">SEBI/RBI/IRDAI/CERT-In/ISO/NIST — view on-screen, export JSON/CSV</div></div></div>
        </div>
```

Replace with (adds a 4th card, and widens the grid from 3 to 4 columns so all 4 stay on one row):

```html
        <div class="dash-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:1.25rem">
          <div class="dash-panel" style="cursor:pointer" onclick="openReportGen('posture')"><div class="dash-panel-body"><div class="kpi-label">Posture report</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Full per-agent posture</div><div class="tiny muted">Prevention, detection, kill-chain — HTML report</div></div></div>
          <div class="dash-panel" style="cursor:pointer" onclick="openReportGen('audit')"><div class="dash-panel-body"><div class="kpi-label">Audit pack</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Evidence bundle</div><div class="tiny muted">Per-agent audit-ready package</div></div></div>
          <div class="dash-panel" style="cursor:pointer" onclick="showTab('compliance')"><div class="dash-panel-body"><div class="kpi-label">Compliance evidence</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Framework mapping</div><div class="tiny muted">SEBI/RBI/IRDAI/CERT-In/ISO/NIST — view on-screen, export JSON/CSV</div></div></div>
          <div class="dash-panel" style="cursor:pointer" onclick="showTab('sla-report')"><div class="dash-panel-body"><div class="kpi-label">SLA Compliance</div><div style="font-weight:600;color:var(--text);margin:0.3rem 0">Fleet SLA report</div><div class="tiny muted">On-time resolution rate by severity, trend, recent history</div></div></div>
        </div>
```

- [ ] **Step 2: Add the `#tab-sla-report` sub-tab**

Find the end of `#tab-compliance` (the closing `</div>` immediately before the `<!-- ── Variant Executor ── -->` comment):

```html
        </div>
      </div>

      <!-- ── Variant Executor ──────────────────────────────────────────── -->
      <div id="tab-variants" style="display:none">
```

Insert a new block between `#tab-compliance`'s closing `</div>` and the Variant Executor comment:

```html
        </div>
      </div>

      <!-- ── SLA Compliance Report ─────────────────────────────────────── -->
      <div id="tab-sla-report" style="display:none">
        <div style="margin-bottom:0.75rem">
          <a class="tiny" style="color:var(--accent);cursor:pointer;text-decoration:none" onclick="showTab('reports')">&lsaquo; Reports</a>
        </div>
        <div class="sec-hdr">
          <h2>SLA Compliance</h2>
          <button class="btn btn-outline btn-sm" onclick="loadSLAReport()">&#x21bb; Refresh</button>
        </div>
        <div id="sla-rpt-empty" class="empty" style="display:none;padding:2rem">No SLA data yet.</div>
        <div id="sla-rpt-body">
          <div class="kpi-row" id="sla-rpt-kpis"></div>
          <div class="sec-hdr" style="margin-top:1.25rem;margin-bottom:0.75rem"><h2 style="font-size:0.8rem">By Severity</h2></div>
          <div id="sla-rpt-severity"></div>
          <div class="sec-hdr" style="margin-top:1.25rem;margin-bottom:0.75rem"><h2 style="font-size:0.8rem">Monthly Trend</h2></div>
          <div class="tbl-wrap">
            <table>
              <thead><tr><th>Month</th><th>Resolved</th><th>On-Time</th><th>Compliance Rate</th></tr></thead>
              <tbody id="sla-rpt-trend-body"></tbody>
            </table>
          </div>
          <div class="sec-hdr" style="margin-top:1.25rem;margin-bottom:0.75rem"><h2 style="font-size:0.8rem">Recently Resolved</h2></div>
          <div class="tbl-wrap">
            <table>
              <thead><tr><th>Agent</th><th>Check</th><th>Severity</th><th>Resolved</th><th>Outcome</th></tr></thead>
              <tbody id="sla-rpt-recent-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ── Variant Executor ──────────────────────────────────────────── -->
      <div id="tab-variants" style="display:none">
```

- [ ] **Step 3: Wire `showTab` and add the render functions**

Find the `showTab` dispatcher line for `reports`:

```js
  if (name === 'reports') loadReports();
```

Add immediately after it:

```js
  if (name === 'sla-report') loadSLAReport();
```

Add the following functions near the other `load*`/`render*` functions in the same `<script>` block (any reasonable location alongside similar report/list rendering functions is fine — this codebase doesn't enforce a strict ordering):

```js
function loadSLAReport() {
  apicall('/api/sla/report').then(function(rep) {
    window._slaReport = rep;
    var empty = document.getElementById('sla-rpt-empty');
    var body = document.getElementById('sla-rpt-body');
    if (!rep.overall || rep.overall.totalEpisodes === 0) {
      empty.style.display = '';
      body.style.display = 'none';
      return;
    }
    empty.style.display = 'none';
    body.style.display = '';
    renderSLAKPIs(rep.overall);
    renderSLASeverityBars(rep.bySeverity || []);
    renderSLAMonthlyTrend(rep.monthlyTrend || []);
    renderSLARecentlyResolved(rep.recentlyResolved || []);
  }).catch(function(err) { showToast('Failed to load SLA report: ' + err.message, 'error'); });
}
function slaRateColor(pct) {
  return pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
}
// slaRateDisplay renders "-" instead of a misleading "0.0%" (in danger red)
// when nothing has resolved yet in this bucket -- complianceRate is 0 by
// definition when onTime+late===0 (see internal/slareport.complianceRate),
// but that means "no data yet", not "failing".
function slaRateDisplay(onTime, late, rate) {
  if (onTime + late === 0) return { text: '—', color: 'var(--muted)' };
  return { text: rate.toFixed(1) + '%', color: slaRateColor(rate) };
}
function renderSLAKPIs(overall) {
  var tile = function(lbl, val, col) {
    return '<div class="kpi-card stat-tile"><div class="stat-top">' +
      '<div><div class="kpi-label">' + lbl + '</div><div class="kpi-value" style="color:' + col + '">' + val + '</div></div>' +
      '</div></div>';
  };
  var rate = slaRateDisplay(overall.onTime, overall.late, overall.complianceRate);
  document.getElementById('sla-rpt-kpis').innerHTML =
    tile('Compliance Rate', rate.text, rate.color) +
    tile('On-Time', overall.onTime, 'var(--success)') +
    tile('Late', overall.late, overall.late ? 'var(--danger)' : 'var(--muted)') +
    tile('Currently Open', overall.currentlyOpen, overall.currentlyOpen ? 'var(--warning)' : 'var(--muted)');
}
function renderSLASeverityBars(bySeverity) {
  var order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  var sorted = bySeverity.slice().sort(function(a, b) { return (order[a.severity] || 9) - (order[b.severity] || 9); });
  var el = document.getElementById('sla-rpt-severity');
  if (!sorted.length) { el.innerHTML = '<div class="empty" style="padding:1.25rem">No severities with SLA episodes.</div>'; return; }
  el.innerHTML = sorted.map(function(s) {
    var rate = slaRateDisplay(s.onTime, s.late, s.complianceRate);
    return '<div class="bar-row">' +
      '<div class="bar-label"><span>' + x(s.severity) + '</span><span style="color:' + rate.color + '">' + rate.text + '</span></div>' +
      '<div class="bar-track"><div class="bar-fill" style="width:' + s.complianceRate + '%;background:' + rate.color + '"></div></div>' +
      '<div style="font-size:0.68rem;color:var(--muted);margin-top:0.15rem">' + s.onTime + ' on-time &middot; ' + s.late + ' late &middot; ' + s.currentlyOpen + ' open</div>' +
      '</div>';
  }).join('');
}
function renderSLAMonthlyTrend(monthlyTrend) {
  var sorted = monthlyTrend.slice().sort(function(a, b) { return a.month < b.month ? -1 : a.month > b.month ? 1 : 0; });
  var body = document.getElementById('sla-rpt-trend-body');
  if (!sorted.length) { body.innerHTML = '<tr><td colspan="4" class="empty">No resolved episodes yet.</td></tr>'; return; }
  body.innerHTML = sorted.map(function(m) {
    var rate = slaRateDisplay(m.onTime, m.resolved - m.onTime, m.complianceRate);
    return '<tr><td>' + x(m.month) + '</td><td>' + m.resolved + '</td><td>' + m.onTime + '</td>' +
      '<td style="color:' + rate.color + '">' + rate.text + '</td></tr>';
  }).join('');
}
function renderSLARecentlyResolved(recentlyResolved) {
  var body = document.getElementById('sla-rpt-recent-body');
  if (!recentlyResolved.length) { body.innerHTML = '<tr><td colspan="5" class="empty">No resolved episodes yet.</td></tr>'; return; }
  body.innerHTML = recentlyResolved.map(function(r) {
    var outcome = r.onTime
      ? '<span class="sbadge" style="background:transparent;border:1px solid var(--success);color:var(--success)">On time</span>'
      : '<span class="sbadge" style="background:transparent;border:1px solid var(--danger);color:var(--danger)">Late</span>';
    return '<tr><td>' + x(r.agentId) + '</td><td>' + x(r.checkId) + '</td><td>' + findingSevBadge(r.severity) + '</td>' +
      '<td>' + fmtDate(r.resolvedAt) + '</td><td>' + outcome + '</td></tr>';
  }).join('');
}
```

- [ ] **Step 4: Extract and syntax-check the modified inline script**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
python3 -c "
import re
data = open('orchestrator/wwwroot/index.html', encoding='utf-8').read()
scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', data, re.S)
out = '\n;\n'.join(scripts)
open(r'C:/Users/ADMINI~1/AppData/Local/Temp/claude/C--Users-Administrator-Downloads-Audspect-Cloud/76be556d-bf6b-4e85-a7ce-d0885849aac3/scratchpad/sla_report_ui_scripts.js', 'w', encoding='utf-8').write(out)
"
node --check "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\sla_report_ui_scripts.js"
```

Expected: no output (success is silent; a syntax error prints a `SyntaxError` with a line number). If it fails, fix the reported line in `wwwroot/index.html` and re-run this step — do not proceed until it passes clean. Delete the temp file afterward:

```bash
rm -f "C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\sla_report_ui_scripts.js"
```

- [ ] **Step 5: Attempt real browser verification, or state explicitly why not**

If a dev server can reasonably be brought up (per this repo's established dev-environment recipe), start it, seed some `finding_slas` data (resolved on-time, resolved late, and active/open across at least 2 severities — reuse the exact seeding shape from `sla_report_handlers_test.go`'s `TestGetSLAReport_ComputesFromSeededEpisodes` as a reference for realistic values), log in, navigate to Reports → the new "SLA Compliance" card, and confirm: the KPI tiles show correct numbers, the severity bars render with correct widths/colors, the monthly trend table is chronologically sorted, the recently-resolved table shows the right on-time/late badges, the `‹ Reports` back-link and Refresh button both work, and the empty state renders correctly against a fresh/empty database. If a dev environment is not reasonably available at execution time, say so explicitly in the completion report rather than claiming this was browser-verified — `node --check` passing only proves the JS parses, not that it renders or behaves correctly.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat: add SLA compliance report UI

New card in the Reports grid opens a sub-tab rendering GET
/api/sla/report -- KPI tiles, per-severity compliance bars, monthly
trend table, recently-resolved table. Reuses existing components only
(kpi-card.stat-tile, bar-row, findingSevBadge, tbl-wrap) -- zero new
CSS, zero new frontend conventions."
git push
```

---

### Task 2: Report completion

No commit for this task.

- [ ] **Step 1: Confirm Task 1's `node --check` passed clean and the commit is pushed**

- [ ] **Step 2: Report completion**

Summarize what shipped (the card, the sub-tab, all 4 render functions) and state plainly whether Step 5's browser verification was actually performed or not, and why. This closes Sub-project D2 — and with it, the entire Posture/Compliance SLA initiative (Sub-projects A, B, C, D1, D2 all done).
