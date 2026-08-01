# Attack Path Validation — Sub-project B (Results Page & Documentation Redesign) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the attack-path fields Sub-project A already ships (score drivers, relationship counts, confidence, coverage, domain-compromise nuance, prioritized remediation) on the results page, and restructure the About modal's documentation, per the 16-point critique in `attackpatvalidtionImprove.txt`.

**Architecture:** Single-file, frontend-only change to `orchestrator/wwwroot/index.html`. `loadAttackPath()` gains a second parallel fetch to the already-existing `GET /api/attackpath/correlation` endpoint. A set of small, pure render-helper functions (following the file's existing `apCard`/`apTable`/`apNodePill` pattern) synthesize new panels from fields already present in the `/api/attackpath/summary` and `/api/attackpath/correlation` JSON responses. `renderAttackPath()` is rewritten to call them. No backend, API, or database changes.

**Tech Stack:** Vanilla ES5 JavaScript (`var`/`function`, no `const`/`let`/arrow functions — matches the file's existing style throughout), inline `<script>` in `orchestrator/wwwroot/index.html`, no build step, no frontend test framework.

## Global Constraints

- No backend/Go/API/database changes of any kind — every field this plan renders already exists in the `/api/attackpath/summary` or `/api/attackpath/correlation` JSON responses today.
- Reuse existing helpers (`apCard`, `apTable`, `apNodePill`, `apArrow`, `apColor`, `apBandColor`, `_fmtDuration`, `x()` for HTML-escaping) — introduce no new visual language or CSS classes beyond what's specified in each task.
- Coverage wording must say targets "represented," never "collected" — this is an established project-wide rule (the backend field itself is literally named `TargetsRepresented`, not `TargetsCollected`, for this exact reason).
- All new JS is ES5 style (`var`, `function` keyword) to match the file's existing convention — confirmed via grep that the file contains no `const`/`let`/arrow functions anywhere.
- `orchestrator/wwwroot/index.html` has no automated frontend test suite. Every task's verification step is `node --check` (syntax-only) on the extracted inline `<script>` block, plus a manual read-through of the diff against this plan's code. Full browser QA is out of scope for this plan and is deferred per this project's established convention (tracked separately after implementation).
- Spec reference: `docs/superpowers/specs/2026-08-01-attack-path-results-frontend-design.md`.

---

### Task 1: Wire up the parallel correlation fetch

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — `loadAttackPath()` function (currently ~line 4548) and the `renderAttackPath` function signature (currently ~line 5380).

**Interfaces:**
- Consumes: existing `apicall(url)` helper (returns a Promise), existing `GET /api/attackpath/correlation` endpoint (returns `pathcorrelation.AttackPathCorrelation` JSON: `{summary, detectionCoverageScore, paths, chokePoints, gaps: [{edge:{from,to,kind}, techniques, priority, reason, remediation}], statistics}`).
- Produces: `renderAttackPath(d, corr)` — `corr` is either the parsed correlation JSON object or `null` (when the correlation fetch fails, e.g. `h.rules` unwired). Every later task that reads `corr` must null-check it.

- [x] **Step 1: Replace `loadAttackPath()` to fetch both endpoints in parallel**

Find this exact function (search for `function loadAttackPath() {`):

```javascript
function loadAttackPath() {
  var body = document.getElementById('ap-body');
  if (body) body.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  apicall('/api/attackpath/summary').then(function(d) {
    // Restore in-flight job state from server after a page reload.
    var saved = _apLoadJobId();
    if (saved && saved.jobId && !_apCurrentJobId) {
      apicall('/api/attackpath/jobs/' + saved.jobId).then(function(job) {
        var terminal = ['completed','failed','timed_out','delivery_failed','cancelled'];
        if (terminal.indexOf(job.status) === -1) {
          // Job still active — restore progress panel so the user can watch it.
          _apCurrentJobId = job.id;
          _apCollectAgentId = job.agentId;
          var panel = document.getElementById('ap-collect');
          if (panel) {
            panel.style.display = '';
            document.getElementById('ap-form').style.display = 'none';
            document.getElementById('ap-progress').style.display = '';
            _apRenderJobState(job);
          }
        } else if (job.status === 'completed') {
          _apClearJobId();
          showToast('Attack-path collection completed while you were away — results ready.', 'ok');
        } else {
          _apClearJobId();
          showToast('Attack-path job ended with status: ' + job.status, 'warn');
        }
      }).catch(function() { _apClearJobId(); });
    }
    renderAttackPath(d);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

Replace it with:

```javascript
function loadAttackPath() {
  var body = document.getElementById('ap-body');
  if (body) body.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  Promise.all([
    apicall('/api/attackpath/summary'),
    apicall('/api/attackpath/correlation').catch(function() { return null; })
  ]).then(function(res) {
    var d = res[0], corr = res[1];
    // Restore in-flight job state from server after a page reload.
    var saved = _apLoadJobId();
    if (saved && saved.jobId && !_apCurrentJobId) {
      apicall('/api/attackpath/jobs/' + saved.jobId).then(function(job) {
        var terminal = ['completed','failed','timed_out','delivery_failed','cancelled'];
        if (terminal.indexOf(job.status) === -1) {
          // Job still active — restore progress panel so the user can watch it.
          _apCurrentJobId = job.id;
          _apCollectAgentId = job.agentId;
          var panel = document.getElementById('ap-collect');
          if (panel) {
            panel.style.display = '';
            document.getElementById('ap-form').style.display = 'none';
            document.getElementById('ap-progress').style.display = '';
            _apRenderJobState(job);
          }
        } else if (job.status === 'completed') {
          _apClearJobId();
          showToast('Attack-path collection completed while you were away — results ready.', 'ok');
        } else {
          _apClearJobId();
          showToast('Attack-path job ended with status: ' + job.status, 'warn');
        }
      }).catch(function() { _apClearJobId(); });
    }
    renderAttackPath(d, corr);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [x] **Step 2: Update the `renderAttackPath` signature**

Find (search for `function renderAttackPath(d) {` — there is exactly one match in the file):

```javascript
function renderAttackPath(d) {
```

Replace with:

```javascript
function renderAttackPath(d, corr) {
```

(The body is rewritten in Task 4 — this step only changes the signature so the file stays syntactically valid between tasks.)

- [x] **Step 3: Verify syntax**

```bash
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "4046,$((END-1))p" orchestrator/wwwroot/index.html > /tmp/ap_check.js
node --check /tmp/ap_check.js
```

Expected: no output (success). If it errors, the line number reported is relative to line 4046 — add 4046 to find the real line.

- [x] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(attackpath-ui): fetch correlation data alongside summary"
```

---

### Task 2: Meta bar — drop raw Nodes count, relabel Edges, add freshness badge

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — the meta bar HTML block (currently ~line 2551-2578), `_apUpdateMetaBar()` (currently ~line 5321-5339), and the small helper cluster near `apBandColor` (currently ~line 4583-4585).

**Interfaces:**
- Consumes: nothing new (uses `d.agentMeta[0]`, already available in `_apUpdateMetaBar`).
- Produces: `apFreshness(ageMs)` → `{label: 'Fresh'|'Aging'|'Stale'|'—', color: '<css color/var>'}`. Thresholds: `< 24h` → Fresh, `24h–7d` → Aging, `> 7d` → Stale.

- [ ] **Step 1: Add the `apFreshness` helper**

Find (search for `function apBandColor(band) {`):

```javascript
function apBandColor(band) {
  return band === 'Low' ? 'var(--success)' : band === 'Medium' ? 'var(--warning)' : band === 'High' ? '#f0883e' : 'var(--danger)';
}
```

Replace with:

```javascript
function apBandColor(band) {
  return band === 'Low' ? 'var(--success)' : band === 'Medium' ? 'var(--warning)' : band === 'High' ? '#f0883e' : 'var(--danger)';
}
function apFreshness(ageMs) {
  if (ageMs == null || ageMs < 0) return { label: '—', color: 'var(--muted)' };
  var hours = ageMs / 3600000;
  if (hours < 24) return { label: 'Fresh', color: 'var(--success)' };
  if (hours < 24 * 7) return { label: 'Aging', color: 'var(--warning)' };
  return { label: 'Stale', color: 'var(--danger)' };
}
```

- [ ] **Step 2: Remove the "Nodes" meta-bar cell and relabel "Edges" to "Relationships"**

Find (search for `<div class="tiny muted" style="margin-bottom:0.1rem">Nodes</div>`):

```html
            <div>
              <div class="tiny muted" style="margin-bottom:0.1rem">Nodes</div>
              <div style="font-size:0.82rem;color:var(--text)" id="ap-meta-nodes">—</div>
            </div>
            <div>
              <div class="tiny muted" style="margin-bottom:0.1rem">Edges</div>
              <div style="font-size:0.82rem;color:var(--text)" id="ap-meta-edges">—</div>
            </div>
```

Replace with:

```html
            <div>
              <div class="tiny muted" style="margin-bottom:0.1rem">Relationships</div>
              <div style="font-size:0.82rem;color:var(--text)" id="ap-meta-edges">—</div>
            </div>
```

- [ ] **Step 3: Add the freshness badge next to Graph age**

Find (search for `<div class="tiny muted" style="margin-bottom:0.1rem">Graph age</div>`):

```html
            <div>
              <div class="tiny muted" style="margin-bottom:0.1rem">Graph age</div>
              <div style="font-size:0.82rem;color:var(--text)" id="ap-meta-age">—</div>
            </div>
```

Replace with:

```html
            <div>
              <div class="tiny muted" style="margin-bottom:0.1rem">Graph age</div>
              <div style="font-size:0.82rem;color:var(--text);display:flex;align-items:center;gap:0.4rem">
                <span id="ap-meta-age">—</span>
                <span id="ap-meta-freshness" style="font-size:0.68rem;font-weight:700;padding:0.08rem 0.4rem;border-radius:4px;border:1px solid currentColor"></span>
              </div>
            </div>
```

- [ ] **Step 4: Update `_apUpdateMetaBar` to stop writing `ap-meta-nodes` and fill the freshness badge**

Find (search for `document.getElementById('ap-meta-ts').textContent = tsStr;`):

```javascript
  document.getElementById('ap-meta-ts').textContent = tsStr;
  document.getElementById('ap-meta-agent').textContent = m.hostname || m.agentId || '—';
  document.getElementById('ap-meta-nodes').textContent = m.nodeCount != null ? m.nodeCount : '—';
  document.getElementById('ap-meta-edges').textContent = m.edgeCount != null ? m.edgeCount : '—';
  document.getElementById('ap-meta-age').textContent = ageStr;
  bar.style.display = '';
```

Replace with:

```javascript
  document.getElementById('ap-meta-ts').textContent = tsStr;
  document.getElementById('ap-meta-agent').textContent = m.hostname || m.agentId || '—';
  document.getElementById('ap-meta-edges').textContent = m.edgeCount != null ? m.edgeCount : '—';
  document.getElementById('ap-meta-age').textContent = ageStr;
  var fresh = apFreshness(ageMs);
  var freshEl = document.getElementById('ap-meta-freshness');
  freshEl.textContent = fresh.label;
  freshEl.style.color = fresh.color;
  bar.style.display = '';
```

- [ ] **Step 5: Verify syntax**

```bash
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "4046,$((END-1))p" orchestrator/wwwroot/index.html > /tmp/ap_check.js
node --check /tmp/ap_check.js
```

Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(attackpath-ui): meta bar freshness badge, drop raw node count"
```

---

### Task 3: Add new render-helper functions

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — insert a new block of helper functions immediately after `_fmtDuration` (currently ~line 5314-5319), before `_apUpdateMetaBar`.

**Interfaces:**
- Consumes: `apTable`, `apNodePill`, `apArrow`, `x()` (all pre-existing).
- Produces (all new, all pure functions — no DOM access, safe to call from `renderAttackPath` in Task 4):
  - `apFindings(s)` → `string[]` of finding sentences, from a `Summary` object (`s.domainCompromiseStatus`, `s.maxBlastRadius`, `s.relationshipCounts`, `s.confidence.missing`).
  - `apFindingsHtml(s)` → HTML string for the "Findings" panel (empty string if `apFindings(s)` is empty).
  - `apScoreDriversHtml(drivers)` → HTML string for the score-drivers list, from `Summary.scoreDrivers` (`[{label, deficit}]`).
  - `apScoreCard(s)` → HTML string, full `kpi-card` for Attack Path Score with an expandable driver breakdown.
  - `apLateralCard(s)` → HTML string, full `kpi-card` for Lateral Movement with relabeled sub-text.
  - `apDomainCard(s)` → HTML string, full `kpi-card` for Domain Compromise, 3-state via `s.domainCompromiseStatus`.
  - `apGraphScopeInterp(s)` → `string`, one interpretive sentence.
  - `apScopeCard(s)` → HTML string, full `kpi-card` for Graph Scope including `apGraphScopeInterp`'s sentence.
  - `apCoverageConfidencePanel(coverage, confidence)` → HTML string, two-block panel. `coverage` is the response's top-level `coverage` object (`{targetsRequested, targetsRepresented, sharpHoundRequested, sharpHoundAvailable, completeness}`); `confidence` is `Summary.confidence` (`{level, based, missing}`).
  - `AP_EDGE_KIND_ORDER` → `string[]`, the canonical edge-kind display order: `['smb','winrm','rdp','admin-to','has-session','member-of','credential']`.
  - `apRelationshipsTable(counts)` → HTML string (via `apTable`), from `Summary.relationshipCounts`.
  - `apGapsPanel(gaps)` → HTML string (via `apTable`), from `AttackPathCorrelation.gaps` (`[{edge:{from,to,kind}, priority, reason, remediation}]`). Empty string if `gaps` is falsy/empty.
  - `apCollectionLimitations(s, coverage)` → HTML string for the dynamic "This Collection's Limitations" panel. Empty string if there's nothing to report.

- [ ] **Step 1: Insert the helper block**

Find (search for `function _fmtDuration(ms) {` through its closing brace and the blank line after it):

```javascript
function _fmtDuration(ms) {
  if (!ms || ms <= 0) return '—';
  var s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

function _apUpdateMetaBar(d) {
```

Replace with:

```javascript
function _fmtDuration(ms) {
  if (!ms || ms <= 0) return '—';
  var s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

function apFindings(s) {
  var out = [];
  if (s.domainCompromiseStatus === 'reachable') {
    out.push('A path to Domain Admin exists — at least one host can reach a Domain Admin or Crown Jewel target.');
  } else if (s.domainCompromiseStatus === 'not-observed') {
    out.push('No Domain Admin path observed in the collected graph.');
  } else {
    out.push('Domain Admin reachability is undetermined — Active Directory relationships were not collected.');
  }
  var maxReach = s.maxBlastRadius || 0;
  out.push(maxReach > 0
    ? (maxReach === 1 ? 'One lateral movement path exists from the highest-risk entry host.' : maxReach + ' lateral movement paths exist from the highest-risk entry host.')
    : 'No lateral movement paths were observed.');
  var adminEdges = (s.relationshipCounts && s.relationshipCounts['admin-to']) || 0;
  out.push(adminEdges > 0
    ? (adminEdges === 1 ? 'One local administrator relationship identified.' : adminEdges + ' local administrator relationships identified.')
    : 'No local administrator relationships identified.');
  var missing = (s.confidence && s.confidence.missing) || [];
  if (missing.indexOf('Active Directory relationships') !== -1) {
    out.push('No AD relationships collected — SharpHound was not run or is unavailable.');
  }
  var sessionEdges = (s.relationshipCounts && s.relationshipCounts['has-session']) || 0;
  out.push(sessionEdges > 0
    ? (sessionEdges === 1 ? 'One active user session detected.' : sessionEdges + ' active user sessions detected.')
    : 'No active user sessions detected.');
  return out;
}
function apFindingsHtml(s) {
  var items = apFindings(s);
  if (!items.length) return '';
  return '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:1rem">' +
    '<div style="font-weight:700;color:var(--text);margin-bottom:0.5rem">Findings</div>' +
    '<ul style="margin:0;padding-left:1.1rem;list-style:disc;color:var(--text);display:flex;flex-direction:column;gap:0.3rem">' +
    items.map(function(i) { return '<li>' + x(i) + '</li>'; }).join('') +
    '</ul></div></div>';
}
function apScoreDriversHtml(drivers) {
  if (!drivers || !drivers.length) return '<div class="tiny muted" style="margin-top:0.4rem">No score driver detail available.</div>';
  return '<div style="display:flex;flex-direction:column;gap:0.25rem;margin-top:0.4rem">' + drivers.map(function(d) {
    var ok = d.deficit === 0;
    var mark = ok ? '<span style="color:var(--success)">&#10003;</span>' : '<span style="color:var(--warning)">&#9888;</span>';
    var deficitStr = ok ? 'no deficit' : '-' + d.deficit.toFixed(1) + ' pts';
    return '<div class="tiny" style="display:flex;justify-content:space-between;gap:0.5rem"><span>' + mark + ' ' + x(d.label) + '</span><span class="muted">' + deficitStr + '</span></div>';
  }).join('') + '</div>';
}
function apScoreCard(s) {
  var val = (s.attackPathScore != null ? s.attackPathScore : '—') + '<span style="font-size:0.9rem;color:var(--muted)">/100</span>';
  var sub = (s.band || '') + ' risk · higher is safer';
  return '<div class="kpi-card"><div class="kpi-label">Attack Path Score</div>' +
    '<div class="kpi-value" style="color:' + apColor(s.attackPathScore) + '">' + val + '</div>' +
    '<div class="tiny muted">' + sub + '</div>' +
    '<details style="margin-top:0.4rem"><summary style="cursor:pointer;color:var(--accent);font-size:0.7rem;list-style:none">Score breakdown &#9660;</summary>' +
    apScoreDriversHtml(s.scoreDrivers) + '</details></div>';
}
function apLateralCard(s) {
  var avg = (s.avgBlastRadius || 0).toFixed(1);
  var max = s.maxBlastRadius || 0;
  var sub = 'Average Reach ' + avg + ' hosts · Maximum Reach ' + max + ' hosts (from ' + x(s.maxBlastEntry || 'entry host') + ')';
  return apCard('Lateral Movement', x(s.lateralMovementBand || '—'), apBandColor(s.lateralMovementBand), sub);
}
function apDomainCard(s) {
  var status = s.domainCompromiseStatus || (s.domainCompromise ? 'reachable' : 'not-observed');
  var label, color, sub;
  if (status === 'reachable') {
    label = 'Reachable'; color = 'var(--danger)'; sub = 'a host can reach Domain Admin';
  } else if (status === 'not-observed') {
    label = 'No Path Observed'; color = 'var(--success)'; sub = 'no path to Domain Admin found in the collected graph';
  } else {
    label = 'Undetermined'; color = 'var(--muted)'; sub = 'Active Directory relationships were not collected';
  }
  return apCard('Domain Compromise', label, color, sub);
}
function apGraphScopeInterp(s) {
  var hosts = s.hosts || 0;
  var size = hosts >= 20 ? 'Large' : hosts >= 5 ? 'Medium' : 'Small';
  var adEdges = ((s.relationshipCounts && s.relationshipCounts['member-of']) || 0) + ((s.relationshipCounts && s.relationshipCounts['credential']) || 0);
  var adNote = adEdges > 0 ? 'Domain relationships collected.' : 'No domain relationships collected.';
  return size + ' — ' + hosts + ' host' + (hosts === 1 ? '' : 's') + ' observed. ' + adNote;
}
function apScopeCard(s) {
  var sub = (s.users || 0) + ' users · ' + (s.groups || 0) + ' groups · ' + (s.edges || 0) + ' edges<br><span style="color:var(--muted)">' + x(apGraphScopeInterp(s)) + '</span>';
  return apCard('Graph Scope', (s.hosts || 0) + ' hosts', 'var(--text)', sub);
}
function apCoverageConfidencePanel(coverage, confidence) {
  coverage = coverage || {};
  confidence = confidence || { based: [], missing: [] };
  var compColor = coverage.completeness === 'Full' ? 'var(--success)' : coverage.completeness === 'Limited' ? 'var(--warning)' : coverage.completeness === 'Minimal' ? '#f0883e' : 'var(--muted)';
  var confColor = confidence.level === 'High' ? 'var(--success)' : confidence.level === 'Medium' ? 'var(--warning)' : 'var(--danger)';
  var covHtml = '<div style="flex:1;min-width:220px">' +
    '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Coverage</div>' +
    '<div class="tiny" style="margin-bottom:0.3rem">' + (coverage.targetsRepresented != null ? coverage.targetsRepresented : '—') + ' of ' + (coverage.targetsRequested != null ? coverage.targetsRequested : '—') + ' requested targets represented in the graph</div>' +
    '<div class="tiny" style="margin-bottom:0.3rem">SharpHound: ' + (coverage.sharpHoundRequested ? (coverage.sharpHoundAvailable ? 'Available' : 'Requested, not available') : 'Not requested') + '</div>' +
    '<span style="display:inline-block;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.72rem;font-weight:700;color:' + compColor + ';border:1px solid currentColor">' + x(coverage.completeness || 'Unknown') + '</span>' +
    '</div>';
  var basedList = (confidence.based || []).map(function(b) { return '<div class="tiny" style="color:var(--text)">&#10003; ' + x(b) + '</div>'; }).join('');
  var missingList = (confidence.missing || []).map(function(m) { return '<div class="tiny" style="color:var(--muted)">&#10005; ' + x(m) + '</div>'; }).join('');
  var confHtml = '<div style="flex:1;min-width:220px">' +
    '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Confidence</div>' +
    '<span style="display:inline-block;margin-bottom:0.4rem;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.72rem;font-weight:700;color:' + confColor + ';border:1px solid currentColor">' + x(confidence.level || '—') + '</span>' +
    '<div style="margin-top:0.2rem">' + basedList + missingList + '</div>' +
    '</div>';
  return '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:1rem;display:flex;gap:1.5rem;flex-wrap:wrap">' + covHtml + confHtml + '</div></div>';
}
var AP_EDGE_KIND_ORDER = ['smb', 'winrm', 'rdp', 'admin-to', 'has-session', 'member-of', 'credential'];
function apRelationshipsTable(counts) {
  counts = counts || {};
  var rows = AP_EDGE_KIND_ORDER.map(function(k) {
    var n = counts[k] || 0;
    var style = n === 0 ? ' style="color:var(--muted)"' : '';
    return ['<code' + style + '>' + k + '</code>', '<span' + style + '>' + n + '</span>'];
  });
  return apTable('Observed Relationships', ['Type', 'Count'], rows);
}
function apGapsPanel(gaps) {
  if (!gaps || !gaps.length) return '';
  var priorityColor = { Critical: 'var(--danger)', High: '#f0883e', Medium: 'var(--warning)', Low: 'var(--success)' };
  var rows = gaps.slice(0, 10).map(function(g) {
    var col = priorityColor[g.priority] || 'var(--muted)';
    var badge = '<span style="display:inline-block;padding:0.1rem 0.45rem;border-radius:4px;font-size:0.7rem;font-weight:700;color:' + col + ';border:1px solid currentColor">' + x(g.priority) + '</span>';
    var path = apNodePill(g.edge.from) + apArrow(g.edge.kind) + apNodePill(g.edge.to, true);
    return [badge, '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:0.15rem">' + path + '</div>', x(g.reason), x(g.remediation)];
  });
  return apTable('Priority Remediation', ['Priority', 'Path', 'Reason', 'Recommended Action'], rows);
}
function apCollectionLimitations(s, coverage) {
  var items = [];
  var missing = (s.confidence && s.confidence.missing) || [];
  if (missing.indexOf('Active Directory relationships') !== -1) items.push('SharpHound disabled or unavailable — no AD relationships in this graph');
  coverage = coverage || {};
  if (coverage.targetsRequested && coverage.targetsRepresented != null && coverage.targetsRepresented < coverage.targetsRequested) {
    items.push('Only ' + coverage.targetsRepresented + ' of ' + coverage.targetsRequested + ' requested targets are represented in the graph');
  }
  if (!items.length) return '';
  return '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:1rem">' +
    '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">This Collection\'s Limitations</div>' +
    '<ul style="margin:0 0 0.4rem;padding-left:1.1rem;list-style:disc;color:var(--muted);display:flex;flex-direction:column;gap:0.2rem">' +
    items.map(function(i) { return '<li>' + x(i) + '</li>'; }).join('') +
    '</ul><div class="tiny" style="color:var(--warning)">Results may underestimate lateral movement.</div></div></div>';
}

function _apUpdateMetaBar(d) {
```

- [ ] **Step 2: Verify syntax**

```bash
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "4046,$((END-1))p" orchestrator/wwwroot/index.html > /tmp/ap_check.js
node --check /tmp/ap_check.js
```

Expected: no output.

- [ ] **Step 3: Sanity-check every new function name is defined exactly once**

```bash
grep -c "^function apFindings\|^function apFindingsHtml\|^function apScoreDriversHtml\|^function apScoreCard\|^function apLateralCard\|^function apDomainCard\|^function apGraphScopeInterp\|^function apScopeCard\|^function apCoverageConfidencePanel\|^function apRelationshipsTable\|^function apGapsPanel\|^function apCollectionLimitations" orchestrator/wwwroot/index.html
```

Expected: `12` (one match per grep alternative — since `grep -c` counts matching *lines*, and each function is on its own line, this returns the number of matching lines, which should be exactly 12).

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(attackpath-ui): add render helpers for findings, score drivers, coverage/confidence, relationships, remediation gaps"
```

---

### Task 4: Rewire `renderAttackPath` to use the new helpers

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — `renderAttackPath(d, corr)` function body (currently ~line 5380-5426).

**Interfaces:**
- Consumes: everything produced by Task 3 (`apFindingsHtml`, `apScoreCard`, `apLateralCard`, `apDomainCard`, `apScopeCard`, `apCoverageConfidencePanel`, `apRelationshipsTable`, `apCollectionLimitations`, `apGapsPanel`), the `corr` parameter from Task 1.
- Produces: nothing new — this is the assembly point; no other task depends on `renderAttackPath`'s internals.

- [ ] **Step 1: Replace the function body**

Find (search for `function renderAttackPath(d, corr) {` through its closing brace — this is the full function after Task 1's Step 2 signature change):

```javascript
function renderAttackPath(d, corr) {
  _apUpdateMetaBar(d);
  var body = document.getElementById('ap-body');
  if (!body) return;
  if (!d || !d.collected) {
    body.innerHTML = '<div class="dash-panel"><div class="dash-panel-body" style="padding:2rem;text-align:center">' +
      '<div style="font-size:1rem;font-weight:700;color:var(--text);margin-bottom:0.4rem">No attack-path data collected yet</div>' +
      '<div class="tiny muted" style="max-width:520px;margin:0 auto 1rem">Run a collection on an enrolled agent to map lateral-movement reachability, blast radius, segmentation, and crown-jewel exposure across the fleet.</div>' +
      '<button class="btn btn-primary btn-sm" onclick="openAPCollect()">&#9654; Run Collection</button></div></div>';
    return;
  }
  var s = d.summary || {};
  var h = '<div class="kpi-row" style="margin-bottom:1rem">';
  h += apCard('Attack Path Score', (s.attackPathScore != null ? s.attackPathScore : '—') + '<span style="font-size:0.9rem;color:var(--muted)">/100</span>', apColor(s.attackPathScore), (s.band || '') + ' risk · higher is safer');
  h += apCard('Lateral Movement', x(s.lateralMovementBand || '—'), apBandColor(s.lateralMovementBand), 'avg ' + (s.avgBlastRadius || 0).toFixed(1) + ' · max ' + (s.maxBlastRadius || 0) + ' hosts/entry');
  h += apCard('Domain Compromise', s.domainCompromise ? 'Reachable' : 'Not Reachable', s.domainCompromise ? 'var(--danger)' : 'var(--success)', s.domainCompromise ? 'a host can reach Domain Admin' : 'no path to Domain Admin');
  h += apCard('Graph Scope', (s.hosts || 0) + ' hosts', 'var(--text)', (s.users || 0) + ' users · ' + (s.groups || 0) + ' groups · ' + (s.edges || 0) + ' edges');
  h += '</div>';

  if (s.domainCompromise && s.shortestDomainAdminPath && s.shortestDomainAdminPath.length) {
    var p = s.shortestDomainAdminPath;
    h += '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:1rem">';
    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.2rem">Representative Path to Domain Admin</div>';
    h += '<div class="tiny muted" style="margin-bottom:0.8rem">Shortest path from the highest-blast-radius entry host. Difficulty: <strong style="color:' + apBandColor(s.shortestDomainAdminDifficulty) + '">' + x(s.shortestDomainAdminDifficulty || '') + '</strong></div>';
    h += '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:0.25rem">' + apNodePill(p[0].from);
    for (var i = 0; i < p.length; i++) { h += apArrow(p[i].kind) + apNodePill(p[i].to, i === p.length - 1); }
    h += '</div></div></div>';
  }

  var cj = (s.crownJewels || []).filter(function(c) { return c.reachable; });
  if (cj.length) {
    h += apTable('Crown-Jewel Exposure', ['Asset', 'Tag', 'Entry Hosts', 'Min Hops'], cj.map(function(c) {
      return [x(c.node), x(c.tag), c.entryHosts, c.minHops];
    }));
  }
  if ((s.chokePoints || []).length) {
    h += apTable('Attack Choke Points', ['Node', 'On Paths', 'Path Coverage'], s.chokePoints.slice(0, 10).map(function(c) {
      return [x(c.label), c.onPaths, Math.round((c.coverage || 0) * 100) + '%'];
    }));
  }
  if ((s.segmentationViolations || []).length) {
    h += apTable('Segmentation Violations', ['From', 'Segment', 'Via', 'To', 'Segment'], s.segmentationViolations.map(function(v) {
      return [x(v.from), x(v.fromSegment), (v.kind || '').toUpperCase(), x(v.to), x(v.toSegment)];
    }));
  }
  body.innerHTML = h;
}
```

Replace with:

```javascript
function renderAttackPath(d, corr) {
  _apUpdateMetaBar(d);
  var body = document.getElementById('ap-body');
  if (!body) return;
  if (!d || !d.collected) {
    body.innerHTML = '<div class="dash-panel"><div class="dash-panel-body" style="padding:2rem;text-align:center">' +
      '<div style="font-size:1rem;font-weight:700;color:var(--text);margin-bottom:0.4rem">No attack-path data collected yet</div>' +
      '<div class="tiny muted" style="max-width:520px;margin:0 auto 1rem">Run a collection on an enrolled agent to map lateral-movement reachability, blast radius, segmentation, and crown-jewel exposure across the fleet.</div>' +
      '<button class="btn btn-primary btn-sm" onclick="openAPCollect()">&#9654; Run Collection</button></div></div>';
    return;
  }
  var s = d.summary || {};
  var h = apFindingsHtml(s);
  h += '<div class="kpi-row" style="margin-bottom:1rem">';
  h += apScoreCard(s);
  h += apLateralCard(s);
  h += apDomainCard(s);
  h += apScopeCard(s);
  h += '</div>';

  if (s.domainCompromise && s.shortestDomainAdminPath && s.shortestDomainAdminPath.length) {
    var p = s.shortestDomainAdminPath;
    h += '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:1rem">';
    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.2rem">Representative Path to Domain Admin</div>';
    h += '<div class="tiny muted" style="margin-bottom:0.8rem">Shortest path from the highest-blast-radius entry host. Difficulty: <strong style="color:' + apBandColor(s.shortestDomainAdminDifficulty) + '">' + x(s.shortestDomainAdminDifficulty || '') + '</strong></div>';
    h += '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:0.25rem">' + apNodePill(p[0].from);
    for (var i = 0; i < p.length; i++) { h += apArrow(p[i].kind) + apNodePill(p[i].to, i === p.length - 1); }
    h += '</div></div></div>';
  }

  h += apCoverageConfidencePanel(d.coverage, s.confidence);
  h += apRelationshipsTable(s.relationshipCounts);
  h += apCollectionLimitations(s, d.coverage);
  if (corr) h += apGapsPanel(corr.gaps);

  var cj = (s.crownJewels || []).filter(function(c) { return c.reachable; });
  if (cj.length) {
    h += apTable('Crown-Jewel Exposure', ['Asset', 'Tag', 'Entry Hosts', 'Min Hops'], cj.map(function(c) {
      return [x(c.node), x(c.tag), c.entryHosts, c.minHops];
    }));
  }
  if ((s.chokePoints || []).length) {
    h += apTable('Attack Choke Points', ['Node', 'On Paths', 'Path Coverage'], s.chokePoints.slice(0, 10).map(function(c) {
      return [x(c.label), c.onPaths, Math.round((c.coverage || 0) * 100) + '%'];
    }));
  }
  if ((s.segmentationViolations || []).length) {
    h += apTable('Segmentation Violations', ['From', 'Segment', 'Via', 'To', 'Segment'], s.segmentationViolations.map(function(v) {
      return [x(v.from), x(v.fromSegment), (v.kind || '').toUpperCase(), x(v.to), x(v.toSegment)];
    }));
  }
  body.innerHTML = h;
}
```

- [ ] **Step 2: Verify syntax**

```bash
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "4046,$((END-1))p" orchestrator/wwwroot/index.html > /tmp/ap_check.js
node --check /tmp/ap_check.js
```

Expected: no output.

- [ ] **Step 3: Manual review checklist**

Read the new `renderAttackPath` body and confirm:
- Every helper called (`apFindingsHtml`, `apScoreCard`, `apLateralCard`, `apDomainCard`, `apScopeCard`, `apCoverageConfidencePanel`, `apRelationshipsTable`, `apCollectionLimitations`, `apGapsPanel`) is one of the 12 functions Task 3 added (cross-check against Task 3 Step 3's grep output).
- `apGapsPanel` is only called when `corr` is truthy (it already internally handles `gaps` being empty/undefined, but `corr` itself may be `null` per Task 1).
- The three pre-existing conditional tables (Crown-Jewel Exposure, Attack Choke Points, Segmentation Violations) and the Representative-Path-to-Domain-Admin panel are byte-identical to before — this task must not touch them.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(attackpath-ui): render findings, coverage/confidence, relationships, and remediation panels"
```

---

### Task 5: About modal — regroup Prerequisites, collapse implementation details

**Files:**
- Modify: `orchestrator/wwwroot/index.html` — the About modal's Prerequisites and "What the agent does during collection" sections (currently ~line 2712-2749, inside `id="ap-about-modal"`).

**Interfaces:**
- Consumes/produces: none — pure static HTML restructuring, no JS behavior change. `<details>`/`<summary>` is an existing pattern in this file (already used elsewhere, e.g. "View Full Command" and log panels), so no new JS toggle function is needed.

- [ ] **Step 1: Regroup Prerequisites into Required / Recommended / Optional**

Find (search for `<!-- Prerequisites -->`):

```html
            <!-- Prerequisites -->
            <div style="margin-bottom:1.1rem">
              <div style="font-weight:700;color:var(--text);margin-bottom:0.5rem;font-size:0.88rem">Prerequisites</div>
              <div style="display:flex;flex-direction:column;gap:0.3rem">
                <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Windows agent online</strong> — agent must be enrolled and connected</span></div>
                <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Local enumeration permissions</strong> — the agent needs rights to enumerate local admins and active sessions on its own host</span></div>
                <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Firewall allows outbound probes</strong> — SMB (445), WinRM (5985), RDP (3389) from agent to each target</span></div>
                <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Targets explicitly listed</strong> — the agent probes only the hosts you supply; no subnet discovery</span></div>
                <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--muted);font-size:0.9rem;flex-shrink:0">○</span><span><strong>Domain-joined host + SharpHound enabled</strong> — optional; required for AD relationship edges</span></div>
              </div>
            </div>
```

Replace with:

```html
            <!-- Prerequisites -->
            <div style="margin-bottom:1.1rem">
              <div style="font-weight:700;color:var(--text);margin-bottom:0.5rem;font-size:0.88rem">Prerequisites</div>
              <div style="margin-bottom:0.5rem">
                <div class="tiny" style="font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:0.3rem">Required</div>
                <div style="display:flex;flex-direction:column;gap:0.3rem">
                  <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Windows agent online</strong> — agent must be enrolled and connected</span></div>
                  <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Local enumeration permissions</strong> — the agent needs rights to enumerate local admins and active sessions on its own host</span></div>
                  <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--success);font-size:0.9rem;flex-shrink:0">&#10003;</span><span><strong>Targets explicitly listed</strong> — the agent probes only the hosts you supply; no subnet discovery</span></div>
                </div>
              </div>
              <div style="margin-bottom:0.5rem">
                <div class="tiny" style="font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:0.3rem">Recommended</div>
                <div style="display:flex;flex-direction:column;gap:0.3rem">
                  <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--warning);font-size:0.9rem;flex-shrink:0">&#9679;</span><span><strong>Firewall allows outbound probes</strong> — SMB (445), WinRM (5985), RDP (3389) from agent to each target</span></div>
                  <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--warning);font-size:0.9rem;flex-shrink:0">&#9679;</span><span><strong>Domain-joined host + SharpHound enabled</strong> — required for Active Directory relationship edges</span></div>
                </div>
              </div>
              <div>
                <div class="tiny" style="font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:0.3rem">Optional</div>
                <div style="display:flex;flex-direction:column;gap:0.3rem">
                  <div style="display:flex;align-items:flex-start;gap:0.5rem"><span style="color:var(--muted);font-size:0.9rem;flex-shrink:0">○</span><span><strong>Crown Jewel tags</strong> — tag high-value assets in Tag Assets to surface Crown-Jewel exposure in results</span></div>
                </div>
              </div>
            </div>
```

- [ ] **Step 2: Collapse implementation detail into a "Technical Details" subsection**

Find (search for `<!-- How collection works -->`):

```html
            <!-- How collection works -->
            <div style="margin-bottom:1.1rem">
              <div style="font-weight:700;color:var(--text);margin-bottom:0.5rem;font-size:0.88rem">What the agent does during collection</div>
              <div style="display:flex;flex-direction:column;gap:0.55rem">
                <div><strong style="color:var(--text)">1 · Local identity</strong>
                  <ul style="margin:0.25rem 0 0 1.1rem;padding:0;list-style:disc;color:var(--muted)">
                    <li>Enumerates all <strong>Local Administrators</strong> and emits an <code>admin-to</code> edge for each</li>
                    <li>Enumerates <strong>Interactive Sessions</strong> and emits a <code>has-session</code> edge per logged-on user</li>
                  </ul>
                </div>
                <div><strong style="color:var(--text)">2 · Reachability probes</strong> (TCP connect, 1.5 s timeout, against your explicit target list only)
                  <ul style="margin:0.25rem 0 0 1.1rem;padding:0;list-style:disc;color:var(--muted)">
                    <li>SMB — TCP 445</li>
                    <li>WinRM — TCP 5985</li>
                    <li>RDP — TCP 3389</li>
                  </ul>
                </div>
                <div><strong style="color:var(--text)">3 · SharpHound</strong> (domain-joined hosts only, if enabled)
                  <ul style="margin:0.25rem 0 0 1.1rem;padding:0;list-style:disc;color:var(--muted)">
                    <li>Receives binary from server, executes it, uploads raw output ZIP</li>
                    <li>Server parses and merges AD edges — agent never interprets the output</li>
                  </ul>
                </div>
                <div><strong style="color:var(--text)">4 · Upload</strong> — all nodes and edges submitted to the server; server rebuilds and analyzes the graph</div>
              </div>
            </div>
```

Replace with:

```html
            <!-- How collection works -->
            <div style="margin-bottom:1.1rem">
              <div style="font-weight:700;color:var(--text);margin-bottom:0.5rem;font-size:0.88rem">What the agent does during collection</div>
              <div style="color:var(--muted);margin-bottom:0.5rem">The agent gathers local identity relationships (who is admin where, who is logged in), probes reachability to your explicit target list only, and — on domain-joined hosts with SharpHound enabled — collects Active Directory relationships. Nothing is exploited and no remote authentication is attempted.</div>
              <details>
                <summary style="cursor:pointer;color:var(--accent);font-size:0.75rem;list-style:none">Technical Details &#9660;</summary>
                <div style="display:flex;flex-direction:column;gap:0.55rem;margin-top:0.5rem">
                  <div><strong style="color:var(--text)">1 · Local identity</strong>
                    <ul style="margin:0.25rem 0 0 1.1rem;padding:0;list-style:disc;color:var(--muted)">
                      <li>Enumerates all <strong>Local Administrators</strong> and emits an <code>admin-to</code> edge for each</li>
                      <li>Enumerates <strong>Interactive Sessions</strong> and emits a <code>has-session</code> edge per logged-on user</li>
                    </ul>
                  </div>
                  <div><strong style="color:var(--text)">2 · Reachability probes</strong> (TCP connect, 1.5 s timeout, against your explicit target list only)
                    <ul style="margin:0.25rem 0 0 1.1rem;padding:0;list-style:disc;color:var(--muted)">
                      <li>SMB — TCP 445</li>
                      <li>WinRM — TCP 5985</li>
                      <li>RDP — TCP 3389</li>
                    </ul>
                  </div>
                  <div><strong style="color:var(--text)">3 · SharpHound</strong> (domain-joined hosts only, if enabled)
                    <ul style="margin:0.25rem 0 0 1.1rem;padding:0;list-style:disc;color:var(--muted)">
                      <li>Receives binary from server, executes it, uploads raw output ZIP</li>
                      <li>Server parses and merges AD edges — agent never interprets the output</li>
                    </ul>
                  </div>
                  <div><strong style="color:var(--text)">4 · Upload</strong> — all nodes and edges submitted to the server; server rebuilds and analyzes the graph</div>
                </div>
              </details>
            </div>
```

- [ ] **Step 3: Verify syntax**

```bash
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "4046,$((END-1))p" orchestrator/wwwroot/index.html > /tmp/ap_check.js
node --check /tmp/ap_check.js
```

Expected: no output (this task only touches HTML outside `<script>`, so this check should be unaffected — run it anyway as a full-file regression guard).

- [ ] **Step 4: Confirm no HTML tags were left unclosed**

```bash
grep -c '<details' orchestrator/wwwroot/index.html
grep -c '</details>' orchestrator/wwwroot/index.html
```

Expected: both counts equal `3` (baseline is 2 pre-existing `<details>` blocks elsewhere in the file, at the time this plan was written — this task adds exactly one more matched pair).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "docs(attackpath-ui): regroup prerequisites, collapse collection internals into Technical Details"
```

---

## Self-Review Notes

- **Spec coverage:** Data flow (Task 1) · Findings (Task 3/4) · reworked score cards incl. score drivers, lateral movement labels, 3-state domain compromise, graph scope interpretation (Task 3/4) · meta bar freshness badge + dropped Nodes (Task 2) · Coverage & Confidence panel (Task 3/4) · Observed Relationships table (Task 3/4) · Priority Remediation panel (Task 3/4) · dynamic per-collection Limitations panel (Task 3/4) · About modal Prerequisites regroup + Technical Details collapse (Task 5). All spec sections have a task.
- **Placeholder scan:** none — every step has literal, complete code.
- **Type consistency:** `renderAttackPath(d, corr)` signature (Task 1) matches its call site `renderAttackPath(d, corr)` (Task 1) and its body (Task 4). Helper names/signatures declared in Task 3's Interfaces block match their call sites in Task 4 exactly (`apFindingsHtml(s)`, `apScoreCard(s)`, `apLateralCard(s)`, `apDomainCard(s)`, `apScopeCard(s)`, `apCoverageConfidencePanel(d.coverage, s.confidence)`, `apRelationshipsTable(s.relationshipCounts)`, `apCollectionLimitations(s, d.coverage)`, `apGapsPanel(corr.gaps)`).
