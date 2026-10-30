import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { covSegHtml, statTileCard } from './attack-path.js';
import { openModal, scenarioFramework } from './reports.js';
import { ROLE, _riskScoreColor, showTab } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { cssVars } from '../core/css-vars.js';
import { kpi, card, grid, hbars, bar, seg, searchBox, empty, pill, kv, icon } from '../core/kit.js';
import * as M from './fnd-model.js';
import { openTechnique } from './coverage.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { rateTone } from './rich-g3.js';
import { setDashITSM } from './dash-rich.js';
import { renderSlaReport, loadReportsHero } from './rpt-view.js';
import { setHeroStat } from './shell-ui.js';
import * as RM from './rem-model.js';


// ── Findings ─────────────────────────────────────────────────────────────────
var FINDING_TAB = 'all';
export function findingSevBadge(sev, exp) {
  var col = { Critical: 'var(--danger)', High: '#e0873a', Medium: 'var(--warning)', Low: 'var(--muted)' }[sev] || 'var(--muted)';
  var ex = exp === 'detected_only' ? ' <span class="tiny muted">· Detected only</span>' : '';
  return '<span class="sbadge g1-s-e02ce1a7"' + cssVars(['g1-v-97993078', col], ['g1-v-7d75dfc9', col]) + '>' + x(sev) + '</span>' + ex;
}
export function loadSLAReport() {
  loadReportsHero();
  apicall('/api/sla/report').then(function(rep) {
    state._slaReport = rep;
    var emptyEl = document.getElementById('sla-rpt-empty');
    var body = document.getElementById('sla-rpt-body');
    if (!rep.overall || rep.overall.totalEpisodes === 0) {
      setDisplay(emptyEl, '');
      setDisplay(body, 'none');
      return;
    }
    setDisplay(emptyEl, 'none');
    setDisplay(body, '');
    renderSlaReport(rep);
  }).catch(function(err) { showToast('Failed to load SLA report: ' + err.message, 'error'); });
}
function findingStatusClass(st) { return st === 'open' ? 'failed' : st === 'remediated' ? 'completed' : 'partial'; }
export function loadFindings() {
  apicall('/api/findings').then(function(list) {
    state._findings = list || [];
    FINDING_LOADED = new Date();
    renderFindingsTiles(); renderFindingsTabs(); renderFindingsRows();
    // Async: load ticket candidates to show ticket badges on rows (analyst+)
    if (ROLE === 'admin' || ROLE === 'analyst') loadTicketCandidates();
    // Show/hide bulk push button and ticket column for analysts
    var bulkBtn = document.getElementById('findings-bulk-btn');
    var ticketTh = document.getElementById('findings-th-ticket');
    var canPush = ROLE === 'admin' || ROLE === 'analyst';
    if (bulkBtn) setDisplay(bulkBtn, canPush ? '' : 'none');
    if (ticketTh) setDisplay(ticketTh, canPush ? '' : 'none');
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function renderFindingsTiles() {
  var l = state._findings || [];
  var s = M.tileStats(l, Date.now());
  document.getElementById('findings-tiles').innerHTML =
    kpi({ label: 'Open findings', value: s.open, sub: 'of ' + s.total + ' total', icon: 'alert', tone: s.open ? 'bad' : 'ok' }) +
    kpi({ label: 'Attack surface age', value: s.open ? s.maxAge + ' days' : '0 days', sub: s.open ? 'oldest open finding' : 'nothing open', icon: 'clock', tone: M.ageTone(s.maxAge) }) +
    kpi({ label: 'Critical', value: s.critical, sub: 'need triage first', icon: 'shield', tone: s.critical ? 'bad' : 'ok' }) +
    kpi({ label: 'Reopened', value: s.reopened, sub: 'regressions', icon: 'refresh', tone: s.reopened ? 'warn' : 'ok' }) +
    kpi({ label: 'Remediated · 30d', value: s.remediated30, sub: 'closed after re-validation', icon: 'ok', tone: 'info' });
  renderFindingsInsights(l);
}
function hhmm(d) {
  var p = function(n) { return (n < 10 ? '0' : '') + n; };
  return d ? p(d.getHours()) + ':' + p(d.getMinutes()) : '';
}
// Distribution cards computed from the same /api/findings response, in the demo's order: a row of
// three (severity of what is open, how long it has been open, which control class) and a row of two
// (severity again with the load time, and the status split of everything).
function renderFindingsInsights(l) {
  var el = document.getElementById('findings-insights');
  if (!el) return;
  if (!l.length) { el.innerHTML = ''; return; }
  var openL = M.openOf(l);
  var none = function(t) { return empty('ok', t, 'No open findings right now.'); };
  var sevRow = M.sevSegments(openL, 'row');
  var buckets = M.ageBuckets(openL, Date.now());
  var ctrl = M.controlRows(openL, 5);
  var three = grid(3, [
    card('Open by severity', sevRow.length ? chartSlot({ type: 'donut', h: 150, legendRight: true, centerSub: 'open', segments: sevRow }) : none('Nothing open')),
    card('Age of open findings', openL.length
      ? chartSlot({ type: 'bar', h: 150, labels: buckets.map(function(b) { return b.label; }), series: [{ name: 'Findings', color: '#3b82f6', data: buckets.map(function(b) { return b.value; }) }] })
      : none('Nothing open')),
    card('By control', ctrl.length ? hbars(ctrl) : none('Nothing open')),
  ]);
  var sevCard = M.sevSegments(openL, 'card');
  var stSeg = M.statusSegments(l);
  var two = grid(2, [
    card('Open findings by severity', sevCard.length ? chartSlot({ type: 'donut', h: 180, legendRight: true, centerSub: 'open', segments: sevCard }) : none('Nothing open'), { sub: FINDING_LOADED ? 'Updated ' + hhmm(FINDING_LOADED) : '' }),
    card('Status', chartSlot({ type: 'donut', h: 180, legendRight: true, thick: 16, centerSub: 'total findings', segments: stSeg })),
  ]);
  el.innerHTML = '<div class="fnd-row">' + three + '</div><div class="fnd-row">' + two + '</div>';
}
var FINDING_Q = '';
var FINDING_SEV = 'all';
var FINDING_LOADED = null;
function currentFindings() { return M.filterFindings(state._findings, { status: FINDING_TAB, sev: FINDING_SEV, q: FINDING_Q }); }
// Two rows from the demo: the status chips with Push to ITSM / Refresh on the right (rendered into
// #findings-statusbar), and the search box with the severity chips (#findings-toolbar).
function renderFindingsTabs() {
  var l = state._findings || [];
  var canPush = ROLE === 'admin' || ROLE === 'analyst';
  var bar1 = document.getElementById('findings-statusbar');
  if (bar1) {
    bar1.innerHTML = seg(M.statusOptions(l), FINDING_TAB, 'setFindingTab') +
      '<div class="fnd-bar-r">' +
      '<button class="btn btn-outline' + (canPush ? '' : ' is-hidden') + '" id="findings-bulk-btn"' + on('click', 'bulkPushSelectedFindings') + '>' + icon('upload') + 'Push to ITSM</button>' +
      '<button class="btn btn-outline"' + on('click', 'loadFindings') + '>' + icon('refresh') + 'Refresh</button></div>';
  }
  var bar2 = document.getElementById('findings-toolbar');
  if (bar2) {
    bar2.innerHTML = searchBox('findings-search', 'Search findings, assets, IDs...', 'setFindingSearch') + seg(M.sevOptions(), FINDING_SEV, 'setFindingSev') + '<span class="fnd-count muted" id="findings-count"></span>';
    var q = document.getElementById('findings-search');
    if (q) q.value = FINDING_Q;
  }
}
export function setFindingTab(v) { FINDING_TAB = v; renderFindingsTabs(); renderFindingsRows(); }
export function setFindingSev(v) { FINDING_SEV = v; renderFindingsTabs(); renderFindingsRows(); }
export function setFindingSearch(el) { FINDING_Q = (el && el.value) || ''; renderFindingsRows(); }
// Export the rows the current filters show as CSV (every field quoted, formula prefixes neutralised).
export function exportFindings() {
  var rows = currentFindings();
  if (!rows.length) { showToast('No findings to export', 'err'); return; }
  var csv = M.csvText(M.CSV_HEADER, M.csvRows(rows, Date.now()));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'findings.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('Exported ' + rows.length + ' finding' + (rows.length === 1 ? '' : 's'), 'ok');
}
function renderFindingsRows() {
  var now = Date.now();
  var l = currentFindings();
  var tb = document.getElementById('findings-body');
  var cnt = document.getElementById('findings-count');
  if (cnt) cnt.textContent = l.length + ' of ' + (state._findings || []).length;
  var canTriage = (ROLE === 'admin' || ROLE === 'analyst');
  var canPush = canTriage;
  var thTriage = document.getElementById('findings-th-triage');
  var thCheck = document.getElementById('findings-th-check');
  var thTicket = document.getElementById('findings-th-ticket');
  if (thTriage) setDisplay(thTriage, canTriage ? '' : 'none');
  if (thCheck) setDisplay(thCheck, (_findingsBulkMode && canPush) ? '' : 'none');
  if (thTicket) setDisplay(thTicket, canPush ? '' : 'none');
  var colCount = 7 + (canTriage ? 1 : 0) + (canPush ? 1 : 0) + (_findingsBulkMode ? 1 : 0);
  if (!l.length) {
    var none = (state._findings || []).length && (FINDING_Q || FINDING_TAB !== 'all' || FINDING_SEV !== 'all');
    tb.innerHTML = '<tr><td colspan="' + colCount + '">' + empty('flag', none ? 'No findings match' : 'No findings yet', none ? 'Try another status or severity, or clear the search.' : 'Findings appear when a simulated technique executes without being prevented.') + '</td></tr>';
    return;
  }
  tb.innerHTML = l.map(function(f) {
    var checkCell = (_findingsBulkMode && canPush)
      ? '<td class="g1-s-49946d6d"' + on('click', 'stopEvent') + '><input type="checkbox" ' + (_findingsSelected[f.id] ? 'checked' : '') + ' ' + on('change', 'toggleFindingCheck', f.id) + ' class="u-pointer"></td>'
      : '';
    var isTicketed = _ticketCandidateIds && (f.status === 'open' || f.status === 'triaged') && !_ticketCandidateIds.has(f.id);
    var ticketCell = '';
    if (canPush) {
      ticketCell = '<td class="g1-s-49946d6d"' + on('click', 'stopEvent') + '>' +
        (isTicketed
          ? '<span class="sbadge g1-s-15c2f776">ticketed</span>'
          : (f.status === 'open' || f.status === 'triaged')
            ? '<button class="btn btn-sm g1-s-274769a5"' + on('click', 'pushFindingToITSM', f.id) + '>+ ticket</button>'
            : '') +
        '</td>';
    }
    var triageCell = '';
    if (canTriage) {
      var nextStates = ['open', 'triaged', 'remediated', 'risk_accepted'].filter(function(st) { return st !== f.status; });
      var opts = nextStates.map(function(st) { return '<option value="' + st + '">' + st.replace('_', ' ') + '</option>'; }).join('');
      triageCell = '<td class="g1-s-49946d6d"' + on('click', 'stopEvent') + '>'
        + '<select class="triage-sel g1-s-08c6acf5"' + on('change', 'quickTriageFinding', f.id)
        + '>'
        + '<option value="">Set…</option>' + opts + '</select></td>';
    }
    var sub = M.subline(f);
    return '<tr class="u-pointer"' + on('click', 'openFinding', f.id) + '>'
      + checkCell
      + '<td class="mono muted fnd-id" title="' + x(f.id) + '">' + x(M.shortId(f.id)) + '</td>'
      + '<td class="cell-main"><div>' + x(f.techniqueName || f.techniqueId) + (f.reopenedCount > 0 ? ' <span class="sbadge s-partial">reopened</span>' : '') + '</div>'
      + (sub ? '<div class="muted fnd-sub">' + x(sub) + '</div>' : '') + '</td>'
      + '<td>' + findingSevBadge(f.severity, f.exposureState) + '</td>'
      + '<td class="mono fnd-asset">' + x(f.agentId) + '</td>'
      + '<td class="mono"><span class="tech-id">' + x(f.techniqueId) + '</span></td>'
      + '<td><span class="sbadge s-' + findingStatusClass(f.status) + '">' + x((f.status || '').replace('_', ' ')) + '</span></td>'
      + '<td class="muted" title="First seen: ' + fmtDate(f.firstSeen) + (f.resolvedAt ? '\nResolved: ' + fmtDate(f.resolvedAt) : '') + '">' + x(M.ageLabel(f, now)) + '</td>'
      + ticketCell
      + triageCell
      + '</tr>';
  }).join('');
}
export function quickTriageFinding(id, sel) {
  var status = sel.value;
  if (!status) return;
  sel.value = ''; // reset to placeholder so it doesn't look stuck
  setFindingStatus(id, status);
}
export function openFinding(id) {
  document.getElementById('results-overlay').classList.remove('run-mode');
  apicall('/api/findings/' + encodeURIComponent(id)).then(function(f) {
    state._currentFinding = f;
    var e = f.enrichment || {};
    var now = Date.now();
    document.getElementById('results-title').textContent = (f.techniqueName || f.techniqueId) + ' — Finding';
    var canPush = (ROLE === 'admin' || ROLE === 'analyst');
    var pushBtn = canPush ? '<button class="btn btn-outline btn-sm"' + on('click', 'pushFindingToITSM', f.id) + '>+ Ticket</button>' : '';
    var respondBtn = (ROLE === 'admin') ? '<button class="btn btn-outline btn-sm"' + on('click', 'openRespondModal') + '>Respond</button>' : '';
    var actions = (canPush
      ? ['open', 'triaged', 'remediated', 'risk_accepted'].filter(function(st) { return st !== f.status; })
          .map(function(st) { return '<button class="btn btn-outline btn-sm"' + on('click', 'setFindingStatus', f.id, st) + '>' + st.replace('_', ' ') + '</button>'; }).join(' ')
      : '');
    document.getElementById('results-export').innerHTML = (actions ? actions + ' ' : '') + pushBtn + (pushBtn && respondBtn ? ' ' : '') + respondBtn;
    var ticketSectionId = 'finding-tickets-' + f.id;
    // Variant breakdown: a finding's own status is the worst outcome across
    // every result mapped to this (technique, control) -- one bypass keeps it
    // open even if most variants are now blocked. This shows the real split
    // instead of leaving a fully-open-looking finding after partial fixes.
    var vb = f.variantBreakdown;
    var vbHtml = '';
    if (vb && vb.total > 0) {
      var vbPct = Math.round(vb.prevented / vb.total * 100);
      var vbRows = (vb.results || []).map(function(r) {
        var cls = r.outcome === 'prevented' ? 'pass' : 'fail';
        var label = r.outcome === 'prevented' ? 'BLOCKED' : r.outcome === 'detected_only' ? 'DETECTED ONLY' : 'MISSED';
        return '<div class="cmp-ev-row"><span class="cmp-ev-badge ' + cls + '">' + label + '</span>' +
          '<span class="cmp-ev-detail">' + x((r.details || '').substring(0, 140)) + '</span></div>';
      }).join('');
      vbHtml = '<h4 class="fnd-h">Variant breakdown</h4>' +
        '<div class="g1-s-2abdc95d">' + vb.prevented + ' of ' + vb.total + ' variants blocked (' + vbPct + '%)' +
          (vb.detectedOnly ? ', ' + vb.detectedOnly + ' detected only' : '') +
          (vb.missed ? ', ' + vb.missed + ' still missed entirely' : '') + '.' +
          ((vb.missed > 0 || vb.detectedOnly > 0)
            ? ' This finding stays open until every variant is blocked — even one bypass keeps the control marked ineffective.'
            : '') +
        '</div>' +
        '<div class="cmp-evidence open">' + vbRows + '</div>';
    }
    var evidence = M.evidenceLines(f);
    var rec = M.recommendation(f);
    var recHtml = rec.mitigations.length
      ? '<ul class="fnd-rec">' + rec.mitigations.map(function(m) { return '<li><b>' + x(m.name) + '</b>' + (m.description ? '<div class="muted">' + x(m.description.substring(0, 220)) + '</div>' : '') + '</li>'; }).join('') + '</ul>'
      : '<p class="muted fnd-p">No ATT&amp;CK mitigation guidance is on file for this technique. Fix the gap, then re-validate the scenario.</p>';
    var rel = M.related(f).map(function(r) {
      return '<a class="fnd-rel" role="button" tabindex="0"' + on('click', r.action, ...r.args) + '>' + icon(r.icon) + '<span class="fnd-rel-t"><b>' + x(r.label) + '</b><em>' + x(r.sub) + '</em></span>' + icon('chevron') + '</a>';
    }).join('');
    var foot = '<div class="fnd-foot"><button class="btn btn-outline"' + on('click', 'closeResults') + '>Close</button>' +
      (canPush && f.status !== 'risk_accepted' ? '<button class="btn btn-outline"' + on('click', 'setFindingStatus', f.id, 'risk_accepted') + '>Accept risk</button>' : '') +
      '<button class="btn btn-primary"' + on('click', 'fndGo', 'remediation') + '>' + icon('wrench') + 'View remediation</button></div>';
    document.getElementById('results-body').innerHTML =
      '<div class="g3-dwr"><div class="g3-dwr-row">' + findingSevBadge(f.severity, f.exposureState) +
        ' <span class="sbadge s-' + findingStatusClass(f.status) + '">' + x((f.status || '').replace('_', ' ')) + '</span>' +
        (f.techniqueId ? ' <span class="tech-id">' + x(f.techniqueId) + '</span>' : '') + '</div>' +
      '<div class="muted mono fnd-dsub">' + x(f.id) + (f.agentId ? ' · ' + x(f.agentId) : '') + '</div>' +
      kv(M.factRows(f, now)) +
      '<div class="muted tiny">First seen ' + x(fmtDate(f.firstSeen)) + ' · last seen ' + x(fmtDate(f.lastSeen)) + '</div>' +
      (evidence.length ? '<h4 class="fnd-h">Evidence</h4><div class="fnd-code">' + evidence.map(function(r) { return '<div><span class="k">' + x(r[0]) + '</span>: ' + x(r[1]) + '</div>'; }).join('') + '</div>' : '') +
      vbHtml +
      '<h4 class="fnd-h">Recommended action</h4>' + recHtml +
      (rec.detection ? '<p class="muted fnd-p"><b>Detection:</b> ' + x(rec.detection.substring(0, 400)) + '</p>' : '') +
      (e.description ? '<div class="g1-s-34d69e4c">' + x(e.description) + '</div>' : '') +
      (e.url ? '<div class="u-mt-06"><a href="' + x(e.url) + '" target="_blank" rel="noopener" class="g1-s-824141a9">View on attack.mitre.org →</a></div>' : '') +
      (canPush
        ? '<h4 class="fnd-h">ITSM Tickets</h4>' +
            '<div id="' + x(ticketSectionId) + '"><div class="tiny muted">Loading…</div></div>'
        : '') +
      '<h4 class="fnd-h">Related</h4><div class="fnd-rels">' + rel + '</div>' +
      foot + '</div>';
    document.getElementById('results-overlay').classList.add('open');
    if (canPush) {
      loadFindingTickets(f.id, document.getElementById(ticketSectionId));
    }
  }).catch(function(e) { showToast(e.message, 'err'); });
}
// Jump links from the finding drawer: close the drawer first so the target page is visible.
export function fndGo(tab) {
  document.getElementById('results-overlay').classList.remove('open', 'run-mode');
  showTab(tab);
}
export function fndTech(id) {
  document.getElementById('results-overlay').classList.remove('open', 'run-mode');
  openTechnique(id);
}
export function setFindingStatus(id, status) {
  apicall('/api/findings/' + encodeURIComponent(id) + '/status', { method: 'POST', body: JSON.stringify({ status: status }) })
    .then(function() { showToast('Finding ' + status.replace('_', ' '), 'ok'); openFinding(id); loadFindings(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// ── Remediation ──────────────────────────────────────────────────────────────
export function loadRemediations() {
  Promise.all([apicall('/api/remediations'), apicall('/api/remediations/by-endpoint')]).then(function(res) {
    state._rems = res[0] || [];
    state._remEps = res[1] || [];
    var hs = RM.heroStats(state._rems);
    setHeroStat('rem-hs-open', hs.open);
    setHeroStat('rem-hs-critical', hs.critical);
    renderRemTiles(); renderRemToolbar(); renderRemList();
  }).catch(function(e) { document.getElementById('rem-list').innerHTML = '<div class="empty g1-s-be6df18e">' + x(e.message) + '</div>'; });
}
// Three tiles under the banner, same as the design demo: open fixes, findings they close, critical fixes.
function renderRemTiles() {
  var t = RM.tileData(state._rems);
  document.getElementById('rem-tiles').innerHTML =
    kpi({ label: 'Open remediations', value: t.open, sub: 'prioritized fixes', icon: 'wrench', tone: t.open ? 'accent' : 'ok' }) +
    kpi({ label: 'Affected findings', value: t.findings, sub: 'closed if all applied', icon: 'flag', tone: t.findings ? 'warn' : 'ok' }) +
    kpi({ label: 'Critical remediations', value: t.critical, sub: 'highest attacker value', icon: 'shield', tone: t.critical ? 'bad' : 'muted' });
}
var REM_SEV = 'all';
var REM_Q = '';
// Remediation views: 'endpoint' (default, one row per endpoint) or 'technique' (the original view).
var REM_VIEW = 'endpoint';
var REM_OPEN_EP = {};
// Section row ("Prioritized fixes" + Showing N of M) and the filter row. The search and severity
// filters are real (client-side over the loaded list); the row is rebuilt without touching the box
// the user is typing in.
function renderRemToolbar() {
  var el = document.getElementById('rem-toolbar');
  if (!el) return;
  var l = state._rems || [];
  var eps = state._remEps || [];
  var views = seg([{ id: 'endpoint', label: 'By endpoint' }, { id: 'technique', label: 'By technique' }], REM_VIEW, 'setRemView');
  if (REM_VIEW === 'endpoint') {
    el.innerHTML =
      '<div class="rem-sec"><h4 class="sec-label rem-sec-h">Endpoints</h4><span class="muted rem-sec-n">' + x(eps.length + (eps.length === 1 ? ' endpoint' : ' endpoints')) + '</span></div>' +
      '<div class="rem-filters">' + views + '</div>';
    return;
  }
  if (!l.length) { el.innerHTML = '<div class="rem-filters">' + views + '</div>'; return; }
  var c = RM.sevCounts(l);
  var opts = [['all', 'All'], ['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low']]
    .map(function(o) { return { id: o[0], label: o[1], count: c[o[0]] }; });
  var shown = RM.filterRems(l, REM_SEV, REM_Q).length;
  el.innerHTML =
    '<div class="rem-sec"><h4 class="sec-label rem-sec-h">Prioritized fixes</h4><span class="muted rem-sec-n" id="rem-showing">' + x(RM.showingText(shown, l.length)) + '</span></div>' +
    '<div class="rem-filters">' + views + searchBox('rem-search', 'Search technique or control…', 'setRemSearch') + seg(opts, REM_SEV, 'setRemFilter') + '</div>';
  var q = document.getElementById('rem-search');
  if (q) q.value = REM_Q;
}
export function setRemView(v) { REM_VIEW = v === 'technique' ? 'technique' : 'endpoint'; renderRemToolbar(); renderRemList(); }
export function toggleRemEndpoint(id) { REM_OPEN_EP[id] = !REM_OPEN_EP[id]; renderEndpointList(); }
export function setRemFilter(v) { REM_SEV = v; renderRemToolbar(); renderRemList(); }
export function setRemSearch(el) { REM_Q = (el && el.value) || ''; renderRemList(); }
// Techniques whose tickets were pushed in this session (the ticketing API returns no per-technique
// state to read back, so the card can only show what this browser tab did).
var REM_TICKETED = {};
// Endpoint view (default). One row per endpoint from /api/remediations/by-endpoint. The status
// is Open, Phase 2 (a remediation request exists) or No remediation required. A request is never
// shown as a fix: closure is verified by revalidation, not by this view.
var EP_STATUS = { 'Open': 'Open', 'Phase 2': 'Phase 2', 'No remediation required': 'No remediation required' };
function renderEndpointList() {
  var el = document.getElementById('rem-list');
  var eps = state._remEps || [];
  if (!eps.length) { el.innerHTML = card('', empty('ok', 'No endpoints', 'No agents are registered yet.')); return; }
  el.innerHTML = '<div class="rk-grid g2 rem-grid">' + eps.map(endpointCard).join('') + '</div>';
}
function endpointCard(e) {
  var key = e.agentId;
  var open = !!REM_OPEN_EP[key];
  var name = e.hostname || e.agentId;
  var sev = e.severity || {};
  var sevLine = ['critical', 'high', 'medium', 'low'].map(function(k) {
    return '<span>' + k.charAt(0).toUpperCase() + k.slice(1) + ' ' + (sev[k] || 0) + '</span>';
  }).join('');
  var head =
    '<button type="button" class="rem-ep-head"' + on('click', 'toggleRemEndpoint', key) + ' aria-expanded="' + open + '">' +
      '<span class="rem-ep-name">' + x(name) + (e.hostname ? '' : ' <span class="muted">(hostname unknown)</span>') + '</span>' +
      '<span class="muted rem-ep-id">' + x(e.agentId) + '</span>' +
      '<span class="rem-ep-stat">' + x(EP_STATUS[e.status] || e.status) + '</span>' +
    '</button>';
  var body =
    '<div class="rem-ep-sum">' +
      '<span><b>' + x(String(e.openFindings)) + '</b> open findings</span>' +
      '<span><b>' + x(String(e.techniqueCount)) + '</b> techniques</span>' +
      '<span class="rem-ep-sev">' + sevLine + '</span>' +
    '</div>';
  if (open) {
    body += '<div class="rem-ep-list">' + (e.findings || []).map(function(f) {
      var mit = (f.mitigations && f.mitigations.length) ? f.mitigations.join('; ') : 'No ATT&CK mitigation recorded for this technique.';
      return '<div class="rem-ep-f">' +
        '<div><b>' + x(f.techniqueId) + '</b> ' + x(f.techniqueName || '') + ' <span class="muted">· ' + x(f.severity) + ' · ' + x(f.exposureState === 'detected_only' ? 'Detected only' : 'Missed') + '</span></div>' +
        '<div class="muted rem-ep-mit">Recommended: ' + x(mit) + '</div>' +
      '</div>';
    }).join('') + '</div>';
  }
  return '<section class="rk-card rem-ep">' + head + body + '</section>';
}
// One prioritized-fix card per remediation, three to a row like the design demo.
function renderRemList() {
  if (REM_VIEW === 'endpoint') { renderEndpointList(); return; }
  var l = state._rems || [];
  var el = document.getElementById('rem-list');
  if (!l.length) { el.innerHTML = card('', empty('ok', 'No open remediations', 'Nothing to fix right now.')); return; }
  var shown = RM.filterRems(l, REM_SEV, REM_Q);
  var cnt = document.getElementById('rem-showing');
  if (cnt) cnt.textContent = RM.showingText(shown.length, l.length);
  if (!shown.length) { el.innerHTML = card('', empty('wrench', 'No remediations match', 'Try another severity or clear the search.')); return; }
  var canTicket = ROLE === 'admin' || ROLE === 'analyst';
  el.innerHTML = '<div class="rk-grid g3 rem-grid">' + shown.map(function(i) {
    var r = l[i], v = RM.cardView(r);
    var done = !!REM_TICKETED[v.techniqueId];
    return '<div class="rk-card rem-fix rem-' + x(v.sevKey || 'none') + '">' +
      '<div class="rem-fix-top">' + pill(v.sev, v.tone) + '<span class="rem-tid">' + x(v.techniqueId) + '</span></div>' +
      '<b class="rem-name">' + x(v.name) + '</b>' +
      '<div class="rem-closes">Closes <b>' + x(v.closes) + '</b> \u00b7 ' + x(v.agents) + '</div>' +
      (v.controls ? '<div class="rem-ctrl">' + x(v.controls) + '</div>' : '') +
      '<div class="rem-miss"><span class="rem-missed">Missed ' + v.missed + '</span><span class="muted">Detected only ' + v.detectedOnly + '</span></div>' +
      '<div class="rem-fix-acts">' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'openRemediation', i) + '>View</button>' +
        (canTicket ? '<button class="btn btn-outline btn-sm"' + on('click', 'remSingleTicket', i) + (done ? ' disabled' : '') + '>' + (done ? '&#10003; Ticketed' : '&#128279; Ticket') + '</button>' : '') +
        '<button class="btn btn-primary btn-sm"' + on('click', 'revalidateRemediation', v.techniqueId) + '>&#8635; Re-validate</button>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';
}
export function openRemediation(i) {
  var r = (state._rems || [])[i];
  if (!r) return;
  document.getElementById('results-title').textContent = r.techniqueId + ' — Remediation';
  document.getElementById('results-export').innerHTML =
    (ROLE === 'admin' || ROLE === 'analyst' ? '<button class="btn btn-outline btn-sm"' + on('click', 'remSingleTicket', i) + '>&#128279; Create Ticket</button>' : '') +
    '<button class="btn btn-primary btn-sm"' + on('click', 'revalidateRemediation', r.techniqueId) + '>&#8635; Re-validate</button>';
  var v = RM.drawerView(r);
  var steps = v.steps.map(function(m, idx) {
    return '<div class="rem-step"><div class="rem-step-n">' + (idx + 1) + '</div>' +
      '<div class="rem-step-tx"><div class="nm">' + x(m.name) + '</div>' +
      (m.description ? '<div class="ds">' + x(m.description) + '</div>' : '') + '</div></div>';
  }).join('') || '<div class="tiny muted">No ATT&amp;CK mitigations listed for this technique.</div>';
  var agents = v.targets.map(function(a) { return '<span class="tool-tag">' + x(a) + '</span>'; }).join(' ') || '<span class="tiny muted">—</span>';
  var detection = v.detection
    ? '<div class="rem-eyebrow">ATT&amp;CK Detection Guidance</div><div class="tiny">' + x(v.detection) + '</div>'
    : '';
  document.getElementById('results-title').textContent = v.name;
  document.getElementById('results-body').innerHTML =
    '<div class="rem-dr-sub">' + pill(v.sev, v.tone) + ' <span class="rem-tid">' + x(v.subtitle) + '</span></div>' +
    '<div class="tiny muted rem-dr-sum">' + x(v.summary) + (v.controls ? ' · ' + x(v.controls) : '') + '</div>' +
    '<h4 class="rem-dr-h">Recommended mitigations</h4>' + steps +
    detection +
    '<div class="rem-eyebrow">Affected Agents</div><div>' + agents + '</div>' +
    '<div class="rem-dr-note tiny muted">After applying these mitigations, re-run the linked scenario to confirm the gap is closed. Mitigation &amp; detection content © MITRE ATT&amp;CK&reg;.</div>';
  document.getElementById('results-overlay').classList.add('open');
}
export function revalidateRemediation(techniqueId) {
  // Re-validate runs ONLY the specific technique that was remediated, not the
  // entire scenario. Pre-set _runSelection to a single-technique subset so the
  // wizard skips to Options and dispatches only that one technique.
  // Priority: (1) scenario whose artTechniques list contains the ID (most common),
  //           (2) scenario with a custom step whose techniqueId matches.
  var tid = (techniqueId || '').toUpperCase();
  var match = null;
  var matchFw = 'art';
  // Pass 1 — ART scenario with this technique in its artTechniques list
  for (var i = 0; i < state.scenarios.length; i++) {
    var s = state.scenarios[i];
    var arts = s.artTechniques || [];
    for (var j = 0; j < arts.length; j++) {
      if ((arts[j] || '').toUpperCase() === tid) { match = s; matchFw = 'art'; break; }
    }
    if (match) break;
  }
  // Pass 2 — custom-step scenario with a step that has this techniqueId
  if (!match) {
    for (var i = 0; i < state.scenarios.length; i++) {
      var s = state.scenarios[i];
      var steps = s.steps || [];
      for (var j = 0; j < steps.length; j++) {
        if ((steps[j].techniqueId || '').toUpperCase() === tid) {
          match = s; matchFw = scenarioFramework(s) || 'steps'; break;
        }
      }
      if (match) break;
    }
  }
  // Pass 1b — artAllWindows scenario as fallback. These can execute any ART technique
  // as a targeted subset (server clears artAllWindows and sets ARTTechniques=[tid]).
  // Prefer 'selective' scenarios over 'full' to minimise blast radius.
  if (!match) {
    var _artAll = [];
    for (var i = 0; i < state.scenarios.length; i++) {
      if (state.scenarios[i].artAllWindows) _artAll.push(state.scenarios[i]);
    }
    _artAll.sort(function(a, b) {
      var aS = (a.id || '').indexOf('selective') !== -1 ? 0 : 1;
      var bS = (b.id || '').indexOf('selective') !== -1 ? 0 : 1;
      return aS - bS;
    });
    if (_artAll.length) { match = _artAll[0]; matchFw = 'art'; }
  }
  if (!match) {
    showToast('No scenario found for ' + techniqueId + ' — select one manually', 'ok');
    openModal();
    return;
  }
  // Pre-arm the run-selection with ONLY this one technique. locked=true bypasses
  // the picker step (jump straight to Review) and hides "Change selection".
  state._runSelection = { scId: match.id, fw: matchFw, ids: [tid], locked: true };
  showToast('Re-validating ' + techniqueId + ' only — 1 technique targeted', 'ok');
  openModal(match.id);
}

// ── Ticketing ─────────────────────────────────────────────────────────────────

// Loaded once per findings-load; Set of finding IDs with no open ticket (candidates)
var _ticketCandidateIds = null;
// Cached ITSM config list (for push dropdowns)
export var _ticketingConfigs = null;
// Bulk selection state in Findings tab
var _findingsBulkMode = false;
var _findingsSelected = {};

function loadTicketCandidates() {
  apicall('/api/ticketing/candidates').then(function(list) {
    _ticketCandidateIds = new Set((list || []).map(function(c) { return c.id; }));
    renderFindingsRows(); // re-render with ticket badges
  }).catch(function() { _ticketCandidateIds = null; });
}

export function loadTicketingConfigs(cb) {
  apicall('/api/ticketing/configs').then(function(list) {
    _ticketingConfigs = list || [];
    if (cb) cb(_ticketingConfigs);
  }).catch(function() { _ticketingConfigs = []; if (cb) cb([]); });
}

// ── Dashboard ITSM widget ───────────────────────────────────────────────────
export function loadDashboardITSM() {
  apicall('/api/ticketing/summary').then(function(s) { setDashITSM(s); }).catch(function() { setDashITSM(null); });
}

// ── Findings ticket actions ─────────────────────────────────────────────────

// Loads ticket refs for a finding and renders them in the drawer.
function loadFindingTickets(findingId, container) {
  apicall('/api/findings/' + encodeURIComponent(findingId) + '/tickets').then(function(tickets) {
    if (!container) return;
    if (!tickets || !tickets.length) {
      container.innerHTML = '<div class="tiny muted g1-s-4a562a0b">No tickets yet.</div>';
      return;
    }
    container.innerHTML = tickets.map(function(t) {
      var statusColor = t.status === 'resolved' ? 'var(--success)' : t.status === 'open' ? 'var(--warning)' : 'var(--muted)';
      var link = t.ticketUrl ? '<a href="' + x(t.ticketUrl) + '" target="_blank" rel="noopener" class="g1-s-35b86d92">↗</a>' : '';
      var reval = t.revalidationRequired ? ' <span class="sbadge g1-s-e0409a47">revalidate</span>' : '';
      return '<div class="g1-display-flex g1-s-37583365">' +
        '<span class="tech-id g1-s-34c7a996">' + x(t.ticketId) + '</span>' + link +
        '<span class="tiny g1-s-ca6fc035"' + cssVars(['g1-v-7d75dfc9', statusColor]) + '>' + x(t.status) + '</span>' + reval +
        '</div>';
    }).join('');
  }).catch(function() { if (container) container.innerHTML = '<div class="tiny muted">Failed to load tickets.</div>'; });
}

export function pushFindingToITSM(findingId) {
  loadTicketingConfigs(function(cfgs) {
    if (!cfgs || !cfgs.length) { showToast('No ITSM connectors configured — add one in Integrations first', 'err'); return; }
    var enabled = cfgs.filter(function(c) { return c.enabled; });
    if (!enabled.length) { showToast('All connectors are disabled', 'err'); return; }
    // If only one connector, push directly; otherwise prompt via a simple select
    var configId = enabled.length === 1 ? enabled[0].id : null;
    if (!configId) {
      var chosen = prompt('Multiple connectors:\n' + enabled.map(function(c,i) { return (i+1) + '. ' + c.name; }).join('\n') + '\nEnter number:');
      var idx = parseInt(chosen, 10) - 1;
      if (isNaN(idx) || idx < 0 || idx >= enabled.length) return;
      configId = enabled[idx].id;
    }
    apicall('/api/ticketing/push', { method: 'POST', body: JSON.stringify({ findingId: findingId, configId: configId, recordType: 'incident' }) })
      .then(function(r) {
        if (r.error) { showToast(r.error, 'err'); return; }
        var msg = r.ticketId ? 'Ticket created: ' + r.ticketId : 'Ticket created';
        showToast(msg, 'ok');
        openFinding(findingId); // refresh drawer to show new ticket
      }).catch(function(e) { showToast(e.message, 'err'); });
  });
}

// ── Findings bulk select ────────────────────────────────────────────────────
function toggleFindingsBulkMode(enabled) {
  _findingsBulkMode = enabled;
  _findingsSelected = {};
  var checkCol = document.getElementById('findings-th-check');
  var bulkBtn = document.getElementById('findings-bulk-btn');
  if (checkCol) setDisplay(checkCol, enabled ? '' : 'none');
  if (bulkBtn) setDisplay(bulkBtn, enabled ? '' : 'none');
  renderFindingsRows();
}

export function toggleAllFindingChecks(checked) {
  _findingsSelected = {};
  if (checked) {
    var l = currentFindings();
    l.forEach(function(f) { _findingsSelected[f.id] = true; });
  }
  renderFindingsRows();
}
export function toggleAllFindingChecksFromChecked() { toggleAllFindingChecks(this.checked); }

export function toggleFindingCheck(id) {
  if (_findingsSelected[id]) delete _findingsSelected[id];
  else _findingsSelected[id] = true;
}

export function bulkPushSelectedFindings() {
  var ids = Object.keys(_findingsSelected);
  if (!ids.length) { showToast('Select at least one finding', 'err'); return; }
  loadTicketingConfigs(function(cfgs) {
    var enabled = (cfgs || []).filter(function(c) { return c.enabled; });
    if (!enabled.length) { showToast('No ITSM connectors configured', 'err'); return; }
    var configId = enabled.length === 1 ? enabled[0].id : null;
    if (!configId) {
      var chosen = prompt('Multiple connectors:\n' + enabled.map(function(c,i) { return (i+1) + '. ' + c.name; }).join('\n') + '\nEnter number:');
      var idx = parseInt(chosen, 10) - 1;
      if (isNaN(idx) || idx < 0 || idx >= enabled.length) return;
      configId = enabled[idx].id;
    }
    apicall('/api/ticketing/push/bulk', { method: 'POST', body: JSON.stringify({ findingIds: ids, configId: configId, recordType: 'incident' }) })
      .then(function(results) {
        if (!Array.isArray(results)) { showToast((results && results.error) || 'Push failed', 'err'); return; }
        var ok = results.filter(function(r) { return !r.error; }).length;
        var fail = results.length - ok;
        showToast(ok + ' ticket' + (ok === 1 ? '' : 's') + ' created' + (fail ? ', ' + fail + ' failed' : ''), ok ? 'ok' : 'err');
        toggleFindingsBulkMode(false);
        loadFindings();
      }).catch(function(e) { showToast(e.message, 'err'); });
  });
}

// ── Remediation bulk tickets ─────────────────────────────────────────────────
export function remBulkTicket(filter) {
  var rems = state._rems || [];
  var targets = filter === 'critical' ? rems.filter(function(r) { return r.severity === 'Critical'; }) : rems;
  if (!targets.length) { showToast('No remediations to ticket', 'err'); return; }
  var findingIds = [];
  targets.forEach(function(r) { (r.findingIds || []).forEach(function(id) { findingIds.push(id); }); });
  if (!findingIds.length) { showToast('Remediations have no finding IDs — re-validate first', 'err'); return; }
  _pushFindingTickets(findingIds, function() { targets.forEach(function(r) { REM_TICKETED[r.techniqueId] = true; }); renderRemList(); });
}

export function remSingleTicket(i) {
  var r = (state._rems || [])[i];
  if (!r) return;
  var findingIds = r.findingIds || [];
  if (!findingIds.length) { showToast(r.techniqueId + ' has no finding IDs — re-validate first', 'err'); return; }
  _pushFindingTickets(findingIds, function() { REM_TICKETED[r.techniqueId] = true; renderRemList(); });
}

function _pushFindingTickets(findingIds, onOk) {
  loadTicketingConfigs(function(cfgs) {
    var enabled = (cfgs || []).filter(function(c) { return c.enabled; });
    if (!enabled.length) { showToast('No ITSM connectors configured — add one in Integrations', 'err'); return; }
    var configId = enabled.length === 1 ? enabled[0].id : null;
    if (!configId) {
      var chosen = prompt('Multiple connectors:\n' + enabled.map(function(c,i) { return (i+1) + '. ' + c.name; }).join('\n') + '\nEnter number:');
      var idx = parseInt(chosen, 10) - 1;
      if (isNaN(idx) || idx < 0 || idx >= enabled.length) return;
      configId = enabled[idx].id;
    }
    apicall('/api/ticketing/push/bulk', { method: 'POST', body: JSON.stringify({ findingIds: findingIds, configId: configId, recordType: 'incident' }) })
      .then(function(results) {
        var ok = (results || []).filter(function(r) { return !r.error; }).length;
        showToast(ok + ' ticket' + (ok === 1 ? '' : 's') + ' created', ok ? 'ok' : 'err');
        if (ok && onOk) onOk();
      }).catch(function(e) { showToast(e.message, 'err'); });
  });
}