import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { daysAgo, fmtDate, showToast } from '../core/util.js';
import { covSegHtml, statTileCard } from './attack-path.js';
import { openModal, scenarioFramework } from './reports.js';
import { ROLE, _riskScoreColor } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { cssVars } from '../core/css-vars.js';
import { kpi, card, grid, hbars, bar, seg, searchBox, empty, pill } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { countBy, sevSegments, hbarRows, matchesQuery, rateTone, normSev } from './rich-g3.js';


// ── Findings ─────────────────────────────────────────────────────────────────
var FINDING_TAB = 'all';
export function findingSevBadge(sev, exp) {
  var col = { Critical: 'var(--danger)', High: '#e0873a', Medium: 'var(--warning)', Low: 'var(--muted)' }[sev] || 'var(--muted)';
  var ex = exp === 'detected_only' ? ' <span class="tiny muted">· Detected only</span>' : '';
  return '<span class="sbadge g1-s-e02ce1a7"' + cssVars(['g1-v-97993078', col], ['g1-v-7d75dfc9', col]) + '>' + x(sev) + '</span>' + ex;
}
export function loadSLAReport() {
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
    renderSLAKPIs(rep.overall);
    renderSLASeverityBars(rep.bySeverity || []);
    renderSLAMonthlyTrend(rep.monthlyTrend || []);
    renderSLARecentlyResolved(rep.recentlyResolved || []);
  }).catch(function(err) { showToast('Failed to load SLA report: ' + err.message, 'error'); });
}
// slaRateDisplay renders "-" instead of a misleading "0.0%" (in danger red)
// when nothing has resolved yet in this bucket -- complianceRate is 0 by
// definition when onTime+late===0 (see internal/slareport.complianceRate),
// but that means "no data yet", not "failing".
function slaRateDisplay(onTime, late, rate) {
  if (onTime + late === 0) return { text: '—', color: 'var(--muted)' };
  return { text: rate.toFixed(1) + '%', color: _riskScoreColor(rate) };
}
function renderSLAKPIs(overall) {
  var rate = slaRateDisplay(overall.onTime, overall.late, overall.complianceRate);
  var resolved = overall.onTime + overall.late;
  document.getElementById('sla-rpt-kpis').innerHTML =
    kpi({ label: 'Compliance Rate', value: rate.text, sub: resolved ? overall.onTime + ' of ' + resolved + ' resolved on time' : 'nothing resolved yet', icon: 'clock', tone: resolved ? rateTone(overall.complianceRate) : 'muted' }) +
    kpi({ label: 'On-Time', value: overall.onTime, sub: 'resolved within SLA', icon: 'ok', tone: 'ok' }) +
    kpi({ label: 'Late', value: overall.late, sub: 'resolved after the deadline', icon: 'warn', tone: overall.late ? 'bad' : 'muted' }) +
    kpi({ label: 'Currently Open', value: overall.currentlyOpen, sub: 'of ' + overall.totalEpisodes + ' episodes', icon: 'flag', tone: overall.currentlyOpen ? 'warn' : 'muted' });
}
function renderSLASeverityBars(bySeverity) {
  // order[sev] || 9 would be wrong here -- Critical's value is 0, and
  // 0 || 9 evaluates to 9 in JS (0 is falsy), so Critical would silently
  // sort last instead of first. Use an explicit "in" check instead.
  var order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  var rank = function(sev) { return sev in order ? order[sev] : 9; };
  var sorted = bySeverity.slice().sort(function(a, b) { return rank(a.severity) - rank(b.severity); });
  var el = document.getElementById('sla-rpt-severity');
  var ch = document.getElementById('sla-rpt-sev-chart');
  if (!sorted.length) {
    el.innerHTML = empty('shield', 'No severities with SLA episodes');
    if (ch) ch.innerHTML = '';
    return;
  }
  el.innerHTML = sorted.map(function(s) {
    var rate = slaRateDisplay(s.onTime, s.late, s.complianceRate);
    var has = s.onTime + s.late > 0;
    return '<div class="g3-dom"><div class="g3-dom-top"><span>' + x(s.severity) + '</span><span>' + x(rate.text) + '</span></div>' +
      bar(has ? s.complianceRate : 0, has ? rateTone(s.complianceRate) : 'muted', true) +
      '<div class="g3-dom-st"><span>' + x(s.onTime) + ' on-time</span><span>' + x(s.late) + ' late</span><span>' + x(s.currentlyOpen) + ' open</span></div></div>';
  }).join('');
  if (ch) ch.innerHTML = chartSlot({ type: 'bar', stacked: true, h: 210,
    labels: sorted.map(function(s) { return s.severity; }),
    series: [
      { name: 'On-time', data: sorted.map(function(s) { return s.onTime; }), color: CHART_COLORS.ok },
      { name: 'Late', data: sorted.map(function(s) { return s.late; }), color: CHART_COLORS.bad },
      { name: 'Open', data: sorted.map(function(s) { return s.currentlyOpen; }), color: CHART_COLORS.warn }
    ] });
}
function renderSLAMonthlyTrend(monthlyTrend) {
  var sorted = monthlyTrend.slice().sort(function(a, b) { return a.month < b.month ? -1 : a.month > b.month ? 1 : 0; });
  var body = document.getElementById('sla-rpt-trend-body');
  var ch = document.getElementById('sla-rpt-trend-chart');
  if (ch) ch.innerHTML = sorted.length > 1
    ? chartSlot({ type: 'line', h: 200, suffix: '%', yMax: 100, labels: sorted.map(function(m) { return m.month; }),
        series: [{ name: 'Compliance rate', data: sorted.map(function(m) { return m.complianceRate; }), color: CHART_COLORS.accent }] })
    : empty('trend', 'Not enough history', 'A trend line needs at least two months of resolved episodes.');
  if (!sorted.length) { body.innerHTML = '<tr><td colspan="4" class="empty">No resolved episodes yet.</td></tr>'; return; }
  body.innerHTML = sorted.map(function(m) {
    var rate = slaRateDisplay(m.onTime, m.resolved - m.onTime, m.complianceRate);
    return '<tr><td>' + x(m.month) + '</td><td>' + m.resolved + '</td><td>' + m.onTime + '</td>' +
      '<td>' + (m.resolved ? pill(rate.text, rateTone(m.complianceRate)) : x(rate.text)) + '</td></tr>';
  }).join('');
}
function renderSLARecentlyResolved(recentlyResolved) {
  var body = document.getElementById('sla-rpt-recent-body');
  if (!recentlyResolved.length) { body.innerHTML = '<tr><td colspan="5" class="empty">No resolved episodes yet.</td></tr>'; return; }
  body.innerHTML = recentlyResolved.map(function(r) {
    var outcome = pill(r.onTime ? 'On time' : 'Late', r.onTime ? 'ok' : 'bad');
    return '<tr><td>' + x(r.agentId) + '</td><td><code>' + x(r.checkId) + '</code></td><td>' + findingSevBadge(r.severity) + '</td>' +
      '<td>' + fmtDate(r.resolvedAt) + '</td><td>' + outcome + '</td></tr>';
  }).join('');
}
function formatFindingAge(f) {
  if (f.status === 'remediated') {
    var age = f.resolvedAt ? daysAgo(f.firstSeen) - daysAgo(f.resolvedAt) : daysAgo(f.firstSeen);
    return Math.max(0, age) + ' days (fixed)';
  }
  return daysAgo(f.firstSeen) + ' days';
}
function findingStatusClass(st) { return st === 'open' ? 'failed' : st === 'remediated' ? 'completed' : 'partial'; }
export function loadFindings() {
  apicall('/api/findings').then(function(list) {
    state._findings = list || [];
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
  var openL = l.filter(function(f) { return f.status === 'open'; });
  var open = openL.length;
  var crit = openL.filter(function(f) { return f.severity === 'Critical'; }).length;
  var reopened = openL.filter(function(f) { return f.reopenedCount > 0; }).length;
  var since = Date.now() - 30 * 864e5;
  var remediated = l.filter(function(f) { return f.status === 'remediated' && new Date(f.lastSeen) >= since; }).length;
  var maxAge = 0;
  openL.forEach(function(f) {
    var age = daysAgo(f.firstSeen);
    if (age > maxAge) maxAge = age;
  });
  var ageTone = maxAge >= 90 ? 'bad' : maxAge >= 30 ? 'warn' : 'ok';
  document.getElementById('findings-tiles').innerHTML =
    kpi({ label: 'Open findings', value: open, sub: 'of ' + l.length + ' total', icon: 'flag', tone: open ? 'bad' : 'ok' }) +
    kpi({ label: 'Attack Surface Age', value: open ? maxAge + ' days' : '0 days', sub: open ? 'oldest open finding' : 'nothing open', icon: 'clock', tone: ageTone }) +
    kpi({ label: 'Critical', value: crit, sub: 'open and critical', icon: 'warn', tone: crit ? 'bad' : 'muted' }) +
    kpi({ label: 'Reopened', value: reopened, sub: 'came back after a fix', icon: 'trend', tone: reopened ? 'warn' : 'muted' }) +
    kpi({ label: 'Remediated · 30d', value: remediated, sub: 'fixed in the last 30 days', icon: 'ok', tone: 'ok' });
  renderFindingsInsights(l, openL);
}
// Distribution cards computed from the same /api/findings response: severity of what is still open,
// the status split of everything, and where the open findings concentrate.
function renderFindingsInsights(l, openL) {
  var el = document.getElementById('findings-insights');
  if (!el) return;
  if (!l.length) { el.innerHTML = ''; return; }
  var sevSeg = sevSegments(openL, function(f) { return f.severity; });
  var sevCard = card('Open findings by severity',
    sevSeg.length ? chartSlot({ type: 'donut', h: 170, legendRight: true, centerSub: 'open', segments: sevSeg })
      : empty('ok', 'Nothing open', 'No open findings right now.'));
  var stLabel = { open: 'Open', triaged: 'Triaged', remediated: 'Remediated', risk_accepted: 'Risk accepted' };
  var stColor = { open: CHART_COLORS.bad, triaged: CHART_COLORS.warn, remediated: CHART_COLORS.ok, risk_accepted: CHART_COLORS.violet };
  var stSeg = countBy(l, function(f) { return f.status; }, 'Unknown').map(function(p) {
    return { label: stLabel[p[0]] || p[0], value: p[1], color: stColor[p[0]] || CHART_COLORS.muted };
  });
  var stCard = card('Status', chartSlot({ type: 'donut', h: 170, legendRight: true, centerSub: 'findings', segments: stSeg }));
  var byTech = countBy(openL, function(f) { return f.techniqueName || f.techniqueId; }, 'Unknown');
  var techCard = card('Most exposed techniques', byTech.length ? hbars(hbarRows(byTech, 'bad', 5)) : empty('ok', 'No open techniques'), { sub: 'open findings' });
  el.innerHTML = grid(3, [sevCard, stCard, techCard]);
}
var FINDING_Q = '';
function renderFindingsTabs() {
  var l = state._findings || [];
  var c = function(k) { return k === 'all' ? l.length : l.filter(function(f) { return f.status === k; }).length; };
  var opts = [['all', 'All'], ['open', 'Open'], ['triaged', 'Triaged'], ['remediated', 'Remediated'], ['risk_accepted', 'Risk-accepted']]
    .map(function(o) { return { id: o[0], label: o[1], count: c(o[0]) }; });
  document.getElementById('findings-toolbar').innerHTML =
    '<div class="g3-tools">' + searchBox('findings-search', 'Search technique, agent, control…', 'setFindingSearch') + seg(opts, FINDING_TAB, 'setFindingTab') + '</div>';
  var q = document.getElementById('findings-search');
  if (q) q.value = FINDING_Q;
}
export function setFindingTab(v) { FINDING_TAB = v; renderFindingsTabs(); renderFindingsRows(); }
export function setFindingSearch(el) { FINDING_Q = (el && el.value) || ''; renderFindingsRows(); }
function renderFindingsRows() {
  var l = (state._findings || []).filter(function(f) {
    return (FINDING_TAB === 'all' || f.status === FINDING_TAB) && matchesQuery(FINDING_Q, [f.techniqueName, f.techniqueId, f.agentId, f.controlClass, f.severity]);
  });
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
  var colCount = 8 + (canTriage ? 1 : 0) + (canPush ? 1 : 0) + (_findingsBulkMode ? 1 : 0);
  if (!l.length) {
    var none = (state._findings || []).length && (FINDING_Q || FINDING_TAB !== 'all');
    tb.innerHTML = '<tr><td colspan="' + colCount + '">' + empty('flag', none ? 'No findings match' : 'No findings yet', none ? 'Try another status or clear the search.' : 'Findings appear when a simulated technique executes without being prevented.') + '</td></tr>';
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
    return '<tr class="u-pointer"' + on('click', 'openFinding', f.id) + '>'
      + checkCell
      + '<td class="cell-main">' + x(f.techniqueName || f.techniqueId) + (f.reopenedCount > 0 ? ' <span class="sbadge s-partial">reopened</span>' : '') + '</td>'
      + '<td><span class="tech-id">' + x(f.techniqueId) + '</span></td>'
      + '<td>' + findingSevBadge(f.severity, f.exposureState) + '</td>'
      + '<td class="tiny muted">' + x(f.controlClass) + '</td>'
      + '<td class="tiny muted g1-s-82cece3f">' + x(f.agentId) + '</td>'
      + '<td><span class="sbadge s-' + findingStatusClass(f.status) + '">' + x((f.status || '').replace('_', ' ')) + '</span></td>'
      + '<td class="tiny muted" title="First seen: ' + fmtDate(f.firstSeen) + (f.resolvedAt ? '\nResolved: ' + fmtDate(f.resolvedAt) : '') + '">' + formatFindingAge(f) + '</td>'
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
    document.getElementById('results-title').textContent = (f.techniqueName || f.techniqueId) + ' — Finding';
    var row = function(k, v) { return v && v.length ? '<dt>' + k + '</dt><dd>' + v + '</dd>' : ''; };
    var list = function(a) { return (a || []).map(x).join(', '); };
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
      vbHtml = '<div class="g1-s-48ee26f0">' +
        '<div class="g1-s-29cafabe">Variant Breakdown</div>' +
        '<div class="g1-s-2abdc95d">' + vb.prevented + ' of ' + vb.total + ' variants blocked (' + vbPct + '%)' +
          (vb.detectedOnly ? ', ' + vb.detectedOnly + ' detected only' : '') +
          (vb.missed ? ', ' + vb.missed + ' still missed entirely' : '') + '.' +
          ((vb.missed > 0 || vb.detectedOnly > 0)
            ? ' This finding stays open until every variant is blocked — even one bypass keeps the control marked ineffective.'
            : '') +
        '</div>' +
        '<div class="cmp-evidence open">' + vbRows + '</div>' +
      '</div>';
    }
    document.getElementById('results-body').innerHTML =
      '<div class="g3-dwr"><div class="g3-dwr-row">' + findingSevBadge(f.severity, f.exposureState) +
        ' <span class="sbadge s-' + findingStatusClass(f.status) + '">' + x((f.status || '').replace('_', ' ')) + '</span></div>' +
      '<dl class="rk-kv">' +
      row('Technique', '<span class="tech-id">' + x(f.techniqueId) + '</span> ' + x(f.techniqueName)) +
      row('Tactic', x(f.tactic)) + row('Expected control', x(f.controlClass)) +
      row('Agent', x(f.agentId)) + row('Installed product', list(f.productSnapshot)) +
      row('ATT&CK data sources', list(f.dataSources)) + row('Source', x(f.sourceType)) +
      row('Occurrences', String(f.occurrenceCount) + (f.reopenedCount > 0 ? ' · reopened ' + f.reopenedCount + '×' : '')) +
      row('First seen', fmtDate(f.firstSeen)) + row('Last seen', fmtDate(f.lastSeen)) +
      row('Exposure age', formatFindingAge(f)) +
      '</dl>' +
      vbHtml +
      (e.description ? '<div class="g1-s-34d69e4c">' + x(e.description) + '</div>' : '') +
      (e.url ? '<div class="u-mt-06"><a href="' + x(e.url) + '" target="_blank" rel="noopener" class="g1-s-824141a9">View on attack.mitre.org →</a></div>' : '') +
      (canPush
        ? '<div class="g1-s-48ee26f0">' +
            '<div class="g1-s-29cafabe">ITSM Tickets</div>' +
            '<div id="' + x(ticketSectionId) + '"><div class="tiny muted">Loading…</div></div>' +
          '</div>'
        : '') + '</div>';
    document.getElementById('results-overlay').classList.add('open');
    if (canPush) {
      loadFindingTickets(f.id, document.getElementById(ticketSectionId));
    }
  }).catch(function(e) { showToast(e.message, 'err'); });
}
export function setFindingStatus(id, status) {
  apicall('/api/findings/' + encodeURIComponent(id) + '/status', { method: 'POST', body: JSON.stringify({ status: status }) })
    .then(function() { showToast('Finding ' + status.replace('_', ' '), 'ok'); openFinding(id); loadFindings(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// ── Remediation ──────────────────────────────────────────────────────────────
export function loadRemediations() {
  apicall('/api/remediations').then(function(list) {
    state._rems = list || [];
    renderRemTiles(); renderRemList();
  }).catch(function(e) { document.getElementById('rem-list').innerHTML = '<div class="empty g1-s-be6df18e">' + x(e.message) + '</div>'; });
}
var REM_SVG = {
  wrench: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 1-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 0 1 5.4-5.4l-2.5 2.5-2-2 2.5-2.5z"/></svg>',
  wrench16: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 1-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 0 1 5.4-5.4l-2.5 2.5-2-2 2.5-2.5z"/></svg>',
  flag: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3 14V2.5h8L9.5 5.5 11 8.5H3"/></svg>',
  shield: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 1.5l5 2v4c0 3-2 5.2-5 6.5C5 12.7 3 10.5 3 7.5v-4z"/></svg>',
  shield12: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 1.5l5 2v4c0 3-2 5.2-5 6.5C5 12.7 3 10.5 3 7.5v-4z"/></svg>',
  agents12: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="12" height="4" rx="1"/><rect x="2" y="9" width="12" height="4" rx="1"/></svg>',
  layers12: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2l6 3-6 3-6-3z"/><path d="M2 8l6 3 6-3"/></svg>',
  eye12: '<svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5z"/><circle cx="8" cy="8" r="2"/></svg>'
};
function renderRemTiles() {
  var l = state._rems || [];
  var findingsTotal = l.reduce(function(s, r) { return s + (r.findingCount || 0); }, 0);
  var crit = l.filter(function(r) { return r.severity === 'Critical'; }).length;
  var missed = l.reduce(function(s, r) { return s + (r.missed || 0); }, 0);
  var detOnly = l.reduce(function(s, r) { return s + (r.detectedOnly || 0); }, 0);
  document.getElementById('rem-tiles').innerHTML =
    kpi({ label: 'Open remediations', value: l.length, sub: 'prioritized fixes', icon: 'wrench', tone: l.length ? 'warn' : 'ok' }) +
    kpi({ label: 'Affected findings', value: findingsTotal, sub: 'closed if all applied', icon: 'flag', tone: findingsTotal ? 'bad' : 'ok' }) +
    kpi({ label: 'Critical remediations', value: crit, sub: 'highest attacker value', icon: 'shield', tone: crit ? 'bad' : 'muted' }) +
    kpi({ label: 'Missed techniques', value: missed, sub: detOnly + ' detected only', icon: 'eye', tone: missed ? 'bad' : 'ok' });
  var ins = document.getElementById('rem-insights');
  if (!ins) return;
  if (!l.length) { ins.innerHTML = ''; return; }
  var wins = l.slice().sort(function(a, b) { return (b.findingCount || 0) - (a.findingCount || 0); }).slice(0, 5)
    .map(function(r) { return [(r.techniqueId || '') + ' ' + (r.techniqueName || ''), r.findingCount || 0]; });
  ins.innerHTML = grid(2, [
    card('Remediations by severity', chartSlot({ type: 'donut', h: 170, legendRight: true, centerSub: 'fixes', segments: sevSegments(l, function(r) { return r.severity; }) })),
    card('Biggest wins', hbars(hbarRows(wins, 'ok', 5)), { sub: 'findings closed per fix' })
  ]);
}
var REM_SEV = 'all';
var REM_Q = '';
function renderRemToolbar() {
  var el = document.getElementById('rem-toolbar');
  if (!el) return;
  var l = state._rems || [];
  if (!l.length) { el.innerHTML = ''; return; }
  var c = function(k) { return k === 'all' ? l.length : l.filter(function(r) { return normSev(r.severity) === k; }).length; };
  var opts = [['all', 'All'], ['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low']]
    .map(function(o) { return { id: o[0], label: o[1], count: c(o[0]) }; });
  el.innerHTML = '<div class="g3-tools">' + searchBox('rem-search', 'Search technique or control\u2026', 'setRemSearch') + seg(opts, REM_SEV, 'setRemFilter') + '</div>';
  var q = document.getElementById('rem-search');
  if (q) q.value = REM_Q;
}
export function setRemFilter(v) { REM_SEV = v; renderRemToolbar(); renderRemList(); }
export function setRemSearch(el) { REM_Q = (el && el.value) || ''; renderRemList(); }
function renderRemList() {
  renderRemToolbar();
  var l = state._rems || [];
  var el = document.getElementById('rem-list');
  if (!l.length) { el.innerHTML = card('', empty('ok', 'No open remediations', 'Nothing to fix right now.')); return; }
  var shown = [];
  l.forEach(function(r, i) {
    if (REM_SEV !== 'all' && normSev(r.severity) !== REM_SEV) return;
    if (!matchesQuery(REM_Q, [r.techniqueId, r.techniqueName, (r.controlClasses || []).join(' ')])) return;
    shown.push(i);
  });
  if (!shown.length) { el.innerHTML = card('', empty('wrench', 'No remediations match', 'Try another severity or clear the search.')); return; }
  el.innerHTML = '<div class="g3-rem-list">' + shown.map(function(i) {
    var r = l[i];
    var critCls = r.severity === 'Critical' ? ' crit' : '';
    var ctrls = (r.controlClasses || []).map(x).join(', ') || '\u2014';
    return '<div class="rem-card">' +
      '<div class="rem-ic' + critCls + '">' + REM_SVG.wrench + '</div>' +
      '<div class="rem-main">' +
        '<div class="rem-top">' + findingSevBadge(r.severity, '') + ' <span class="tech-id">' + x(r.techniqueId) + '</span></div>' +
        '<div class="rem-title">' + x(r.techniqueName) + '</div>' +
        '<div class="rem-meta">' +
          '<span>' + REM_SVG.shield12 + 'Closes ' + r.findingCount + ' finding' + (r.findingCount === 1 ? '' : 's') + '</span>' +
          '<span>' + REM_SVG.agents12 + r.agentCount + ' agent' + (r.agentCount === 1 ? '' : 's') + '</span>' +
          '<span>' + REM_SVG.layers12 + ctrls + '</span>' +
          '<span>' + REM_SVG.eye12 + 'Missed ' + r.missed + ' \u00b7 Detected only ' + r.detectedOnly + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="rem-actions">' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'openRemediation', i) + '>View</button>' +
        (ROLE === 'admin' || ROLE === 'analyst' ? '<button class="btn btn-outline btn-sm"' + on('click', 'remSingleTicket', i) + '>&#128279; Ticket</button>' : '') +
        '<button class="btn btn-primary btn-sm"' + on('click', 'revalidateRemediation', r.techniqueId) + '>&#8635; Re-validate</button>' +
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
  var ctrls = (r.controlClasses || []).map(x).join(', ') || '—';
  var stat = function(l, v) { return '<div class="rem-stat"><div class="lbl">' + l + '</div><div class="val">' + v + '</div></div>'; };
  var statGrid = '<div class="rem-stat-grid">' +
    '<div class="rem-stat"><div class="lbl">Severity</div><div class="val">' + findingSevBadge(r.severity, '') + '</div></div>' +
    stat('Findings closed', r.findingCount) +
    stat('Agents affected', r.agentCount) +
    stat('Control class', ctrls) +
    '</div>';
  var steps = (r.mitigations || []).map(function(m, idx) {
    return '<div class="rem-step"><div class="rem-step-n">' + (idx + 1) + '</div>' +
      '<div class="rem-step-tx"><div class="nm">' + x(m.name) + '</div>' +
      (m.description ? '<div class="ds">' + x(m.description) + '</div>' : '') + '</div></div>';
  }).join('') || '<div class="tiny muted">No ATT&CK mitigations listed for this technique.</div>';
  var agents = (r.recommendedTargets || []).map(function(a) { return '<span class="tool-tag">' + x(a) + '</span>'; }).join(' ') || '<span class="tiny muted">—</span>';
  var detection = r.detection
    ? '<div class="rem-eyebrow">ATT&amp;CK Detection Guidance</div><div class="tiny g1-s-bf6d0f4b">' + x(r.detection) + '</div>'
    : '';
  var checkSvg = '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" class="g1-s-0689b472"><path d="M3 8.5l3.2 3.2L13 5"/></svg>';
  document.getElementById('results-body').innerHTML =
    '<div class="g1-display-flex g1-s-bf6d23db">' + findingSevBadge(r.severity, '') + ' <span class="tech-id">' + x(r.techniqueId) + '</span></div>' +
    '<div class="g1-s-d5980386">' + x(r.techniqueName) + '</div>' +
    '<div class="tiny muted g1-s-dd11a3a0">Closes ' + r.findingCount + ' finding' + (r.findingCount === 1 ? '' : 's') + ' on ' + r.agentCount + ' agent' + (r.agentCount === 1 ? '' : 's') + ' · Missed ' + r.missed + ' · Detected only ' + r.detectedOnly + '</div>' +
    statGrid +
    '<div class="rem-eyebrow">Implementation Steps — ATT&amp;CK Mitigations</div>' + steps +
    detection +
    '<div class="rem-eyebrow">Affected Agents</div><div>' + agents + '</div>' +
    '<div class="rem-tip">' + checkSvg + '<span>After applying these mitigations, re-run the linked scenario to confirm the gap is closed and posture improves.</span></div>' +
    '<div class="tiny muted g1-s-0e2f4ee5">Mitigation &amp; detection content © MITRE ATT&CK&reg;.</div>';
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
  apicall('/api/ticketing/summary').then(function(s) {
    var sec = document.getElementById('dash-itsm-section');
    if (!sec) return;
    var open = s.openTickets || 0, resolved = s.resolvedTickets || 0, pend = s.pendingRevalidation || 0;
    if (open + resolved + pend === 0 && !(s.byProvider && s.byProvider.length)) {
      setDisplay(sec, 'none'); return;
    }
    setDisplay(sec, '');
    var tile = function(lbl, val, col) {
      return '<div class="kpi-card"><div class="kpi-label">' + lbl + '</div>' +
        '<div class="kpi-value"' + cssVars(['g1-v-7d75dfc9', col]) + '>' + val + '</div></div>';
    };
    var html = tile('Open tickets', open, open ? 'var(--warning)' : 'var(--success)') +
      tile('Resolved tickets', resolved, 'var(--success)') +
      tile('Pending revalidation', pend, pend ? 'var(--danger)' : 'var(--muted)');
    (s.byProvider || []).forEach(function(p) {
      html += tile(x(p.provider), p.count, 'var(--accent)');
    });
    document.getElementById('dash-itsm-tiles').innerHTML = html;
  }).catch(function() {});
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
    var l = (state._findings || []).filter(function(f) { return FINDING_TAB === 'all' || f.status === FINDING_TAB; });
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
  _pushFindingTickets(findingIds);
}

export function remSingleTicket(i) {
  var r = (state._rems || [])[i];
  if (!r) return;
  var findingIds = r.findingIds || [];
  if (!findingIds.length) { showToast(r.techniqueId + ' has no finding IDs — re-validate first', 'err'); return; }
  _pushFindingTickets(findingIds);
}

function _pushFindingTickets(findingIds) {
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
      }).catch(function(e) { showToast(e.message, 'err'); });
  });
}