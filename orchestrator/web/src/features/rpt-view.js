// Renderers for the redesigned Reports page and its Compliance report / SLA compliance sub-tabs.
// The numbers come from rpt-model.js (pure); this file only builds markup and fills the placeholders in
// index.html. Escape every dynamic value with x(); behaviour is attached with on() / data-on-* only.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, fmtDate, showToast } from '../core/util.js';
import { state } from '../core/state.js';
import { setDisplay } from '../core/inline-style.js';
import { kpi, card, hbars, bar, pill, chip, empty, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './rpt-model.js';

function el(id) { return document.getElementById(id); }
function put(id, html) { var e = el(id); if (e) e.innerHTML = html; }

// ── Banner and sub-tab numbers (the same three banners sit on Reports / Compliance / SLA) ──
var HERO = { reports: null, frameworks: null, agents: null, latest: '' };
function paintHero() {
  ['', '-c', '-s'].forEach(function(sfx) {
    setHeroStat('rpt-hs-reports' + sfx, HERO.reports == null ? '—' : HERO.reports);
    setHeroStat('rpt-hs-agents' + sfx, HERO.agents == null ? '—' : HERO.agents);
    setHeroStat('rpt-hs-latest' + sfx, HERO.reports === 0 ? 'None yet' : HERO.latest ? ago(HERO.latest) : '—');
    setHeroStat('rpt-hs-frameworks' + sfx, HERO.frameworks == null ? '—' : HERO.frameworks);
  });
  ['rpt-tab-n', 'rpt-tab-n-c', 'rpt-tab-n-s'].forEach(function(id) {
    var e = el(id);
    if (e) e.textContent = HERO.reports ? String(HERO.reports) : '';
  });
}
export function setReportsCount(n) { HERO.reports = n; paintHero(); }
export function setReportingAgents(n) { HERO.agents = n; paintHero(); }
// loadReportsHero fills the banner numbers from the history log and the framework list.
export function loadReportsHero() {
  apicall('/api/reports').then(function(list) { var h = M.heroStats(list, null); HERO.reports = h.reports; HERO.latest = h.latest; paintHero(); }).catch(function() {});
  apicall('/api/compliance/frameworks').then(function(f) { HERO.frameworks = M.heroStats(null, f).frameworks; paintHero(); }).catch(function() {});
  // The Compliance and SLA sub-tabs share this banner but never paint the agent list, so without this the
  // "Agents Reporting" number stayed a dash until the Reports tab had been opened. Same counting as that tab.
  if (HERO.agents == null) {
    apicall('/api/scenarios/runs').then(function(runs) { setReportingAgents(M.agentRows(runs, {}, {}).length); }).catch(function() {});
  }
}

// ── Reports tab: reports by agent ───────────────────────────────────────────
var AVAIL = [];
var OPEN = {};
export function toggleRepRuns(agentId) { OPEN[agentId] = !OPEN[agentId]; paintAvailable(AVAIL); }

var OS_SVG = {
  windows: '<svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor" aria-hidden="true"><path d="M3 5.5l8-1.1v7.1H3zM12 4.3l9-1.3v8.5h-9zM3 12.5h8v7.1l-8-1.1zM12 12.5h9V21l-9-1.3z"/></svg>',
  linux: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 10l3 2-3 2M12 15h5"/></svg>',
  mac: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/></svg>',
  other: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>'
};
var RUNS_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 20V11M12 20V5M18 20v-6"/></svg>';
var SCEN_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></svg>';
var CLOCK_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>';

// The runs of one agent: every finished run with its own PDF download. A failed run is listed but has no report.
export function runListHtml(r) {
  var body = r.list.map(function(run) {
    var acts = run.reportable
      ? '<button class="btn btn-outline btn-sm"' + on('click', 'downloadRunReport', run.id) + '>' + icon('download') + 'Download PDF</button>'
      : '<span class="tiny muted">no report for a ' + x(run.status || 'unfinished') + ' run</span>';
    return '<tr><td>' + x(run.name) + '</td><td>' + chip(run.status || '—', run.reportable ? 'ok' : 'bad') + '</td><td class="muted">' + ago(run.at) + '</td><td class="rpt-acts end">' + acts + '</td></tr>';
  }).join('');
  return '<div class="rpt-agent-more">' +
    '<div class="rpt-more-hd"><span>Whole-agent reports</span><div class="rpt-acts">' +
      '<button class="btn btn-outline btn-sm"' + on('click', 'genAgentReport', r.id, 'posture', 'pdf') + '>PDF report</button>' +
      '<button class="btn btn-outline btn-sm"' + on('click', 'genAgentReport', r.id, 'posture', 'csv') + '>CSV</button>' +
      '<button class="btn btn-outline btn-sm"' + on('click', 'genAgentReport', r.id, 'audit', '') + '>Audit pack</button></div></div>' +
    '<table class="rpt-runs"><thead><tr><th>Scenario run</th><th>Result</th><th>When</th><th></th></tr></thead><tbody>' + body + '</tbody></table></div>';
}

// One execution's result chip: the verdict (PASS / FAIL / ERROR / SKIPPED) when the run carries one, else the run status.
function execChip(e) {
  var v = e.verdict || {};
  if (v.result) {
    var tone = v.result === 'PASS' ? 'ok' : v.result === 'FAIL' ? 'bad' : v.result === 'ERROR' ? 'warn' : 'muted';
    return chip(v.result, tone);
  }
  return chip(e.status || '—', e.status === 'failed' ? 'bad' : 'muted');
}
function execCounts(e) {
  var v = e.verdict || {};
  if (!v.result) return '';
  var bits = [];
  if (v.fail) bits.push(v.fail + ' fail');
  if (v.pass) bits.push(v.pass + ' pass');
  if (v.error) bits.push(v.error + ' error');
  if (v.skipped) bits.push(v.skipped + ' skipped');
  return bits.join(' · ');
}
// The latest three executions (newest first) with their results; the rest are counted, and the full list sits behind View Full History.
function recentExecutionsHtml(r) {
  var all = r.recentExecutions || [];
  if (!all.length) return '';
  var shown = all.slice(0, 3), more = all.length - shown.length;
  var rows = shown.map(function(e) {
    return '<div class="rpt-exec"><span class="rpt-exec-name" title="' + x(e.name) + '">' + x(e.name) + '</span>' +
      '<span class="rpt-exec-counts tiny muted">' + x(execCounts(e)) + '</span>' + execChip(e) +
      '<span class="rpt-exec-time tiny muted">' + ago(e.at) + '</span></div>';
  }).join('');
  return '<div class="rpt-recent-execs"><div class="rpt-exec-label">Recent executions</div>' + rows +
    (more > 0 ? '<div class="rpt-exec-more">+ ' + more + ' more execution' + (more === 1 ? '' : 's') + '</div>' : '') + '</div>';
}

function agentCardHtml(r) {
  var open = !!OPEN[r.id];
  return '<div class="rpt-agent' + (open ? ' open' : '') + '">' +
    '<div class="rpt-agent-row">' +
      '<span class="rpt-dot ' + (r.online ? 'on' : 'off') + '" title="' + (r.online ? 'Agent online' : 'Agent offline') + '"></span>' +
      '<span class="rpt-os os-' + x(r.os || 'other') + '">' + (OS_SVG[r.os] || OS_SVG.other) + '</span>' +
      '<div class="rpt-agent-name"><b>' + x(r.host) + '</b><span>' + (r.online ? 'Online' : 'Offline') + '</span></div>' +
      (r.recent ? '<span class="rpt-recent">Recent activity</span>' : '') +
      '<div class="rpt-metric"><span class="rpt-metric-ico">' + RUNS_SVG + '</span><div><b>' + r.total + '</b><span>Total runs' + (r.failed ? ' · ' + r.failed + ' failed' : '') + '</span></div></div>' +
      '<div class="rpt-metric"><span class="rpt-metric-ico">' + SCEN_SVG + '</span><div><b>' + r.scenarios + '</b><span>Scenario' + (r.scenarios === 1 ? '' : 's') + '</span></div></div>' +
      '<button type="button" class="btn btn-outline btn-sm rpt-hist" aria-expanded="' + (open ? 'true' : 'false') + '"' + on('click', 'toggleRepRuns', r.id) + '>View Full History <span aria-hidden="true">' + (open ? '&#9652;' : '&#9662;') + '</span></button>' +
    '</div>' + (open ? runListHtml(r) : recentExecutionsHtml(r)) + '</div>';
}

export function paintAvailable(rows) {
  AVAIL = rows;
  setReportingAgents(rows.length);
  if (!rows.length) {
    put('rep-available', empty('report', 'No agents with finished runs yet', 'Run a scenario, then generate its report here.'));
    return;
  }
  put('rep-available', rows.map(agentCardHtml).join(''));
}
export function paintAvailableError() {
  put('rep-available', empty('alert', 'Could not load agents'));
}

// ── Reports tab: history table with search, type, agent, date range and sort ─
var ROWS = [];
var HOSTS = {};
function val(id) { var e = el(id); return e ? e.value : ''; }
var DEFAULT_RANGE = '30';

function hostMap() {
  var m = {};
  (state.agents || []).forEach(function(a) { m[a.agentId] = a.hostname || a.agentId; });
  return m;
}

function fillSelect(id, first, options, keep) {
  var sel = el(id);
  if (!sel) return;
  var cur = keep != null ? keep : sel.value;
  sel.innerHTML = '<option value="">' + x(first) + '</option>' + options.map(function(o) {
    return '<option value="' + x(o[0]) + '"' + (o[0] === cur ? ' selected' : '') + '>' + x(o[1]) + '</option>';
  }).join('');
}

export function paintHistory(list) {
  ROWS = M.historyRows(list);
  HOSTS = hostMap();
  setReportsCount(ROWS.length);
  fillSelect('rpt-type', 'All types', M.typeOptions(ROWS));
  fillSelect('rpt-agent', 'All agents', M.agentOptions(ROWS, HOSTS));
  renderHistory();
}

var FILE_ICON = {
  PDF: ['pdf', '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 14h6M9 17h4"/></svg>'],
  HTML: ['html', '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/></svg>'],
  CSV: ['csv', '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 10h16M4 15h16M10 4v16"/></svg>'],
  PACKAGE: ['zip', '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5M12 13v8"/></svg>']
};
var USER_SVG = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/></svg>';
var COPY_SVG = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/></svg>';

function dateParts(iso) {
  var d = new Date(iso);
  if (isNaN(d.getTime())) return { day: '—', time: '' };
  return {
    day: d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }),
    time: d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
  };
}

function histRow(r) {
  var fi = FILE_ICON[r.fmt] || FILE_ICON.PDF, dt = dateParts(r.at);
  var host = HOSTS[r.agentId] || r.agentId;
  return '<tr class="noclick">' +
    '<td><div class="rpt-file"><span class="rpt-fico f-' + fi[0] + '">' + fi[1] + '</span><div>' +
      '<div class="rpt-ftitle">' + x(r.name) + (host ? ' <span class="muted">· ' + x(host) + '</span>' : '') + (r.failed ? ' ' + chip('Failed', 'bad') : '') + '</div>' +
      '<div class="rpt-fid mono tiny muted">Assessment ID: ' + x(r.idShort) + ' <button type="button" class="rpt-copy" title="Copy the full ID" aria-label="Copy report ID"' + on('click', 'copyReportId', r.id) + '>' + COPY_SVG + '</button></div>' +
    '</div></div></td>' +
    '<td>' + chip(r.name, 'info') + '</td>' +
    '<td><div class="rpt-when">' + x(dt.day) + '</div><div class="tiny muted">' + x(dt.time) + '</div></td>' +
    '<td><span class="rpt-by"><span class="rpt-by-ico">' + USER_SVG + '</span>' + x(r.by) + '</span></td>' +
    '<td>' + chip(r.fmt, 'muted') + '</td>' +
    '<td class="td-r"><div class="rpt-acts end">' +
      (r.downloadPath ? '<a class="btn btn-primary-soft btn-sm" href="' + x(r.downloadPath) + '" target="_blank" rel="noopener">' + icon('download') + 'Download</a>' : '') +
      '<details class="rpt-menu"><summary class="btn btn-outline btn-sm" aria-label="More actions">&#8943;</summary><div class="rpt-menu-list">' +
        '<button type="button"' + on('click', 'copyReportId', r.id) + '>Copy report ID</button>' +
        (r.downloadPath ? '<button type="button"' + on('click', 'copyReportLink', r.downloadPath) + '>Copy download link</button>' : '') +
      '</div></details>' +
    '</div></td></tr>';
}

function copyText(text, done) {
  var ok = function() {
    showToast(done, 'ok');
    document.querySelectorAll('.rpt-menu[open]').forEach(function(d) { d.removeAttribute('open'); });
  };
  var fail = function() { showToast('Could not copy. Select the text and copy it by hand.', 'err'); };
  try { navigator.clipboard.writeText(text).then(ok, fail); } catch (e) { fail(); }
}
export function copyReportId(id) { copyText(id, 'Report ID copied'); }
export function copyReportLink(path) { copyText(location.origin + path, 'Download link copied'); }

function historyFilters() {
  return { q: val('rpt-q'), type: val('rpt-type'), agent: val('rpt-agent'), range: val('rpt-range') || DEFAULT_RANGE, sort: val('rpt-sort') || 'new' };
}

export function renderHistory() {
  var tb = el('reports-body');
  if (!tb) return;
  var f = historyFilters();
  var changed = !!(f.q || f.type || f.agent || f.range !== DEFAULT_RANGE || f.sort !== 'new');
  var clr = el('rpt-clear');
  if (clr) setDisplay(clr, changed ? '' : 'none');
  var note = el('rpt-count');
  if (!ROWS.length) {
    tb.innerHTML = '<tr><td colspan="6">' + empty('report', 'No reports generated yet', 'This log fills when you generate one (from the button above or the per-agent buttons). Test runs do not create reports automatically.') + '</td></tr>';
    if (note) note.textContent = '';
    return;
  }
  var rows = M.sortHistory(M.filterHistory(ROWS, f.q, f.type, { agent: f.agent, days: f.range }), f.sort);
  tb.innerHTML = rows.length ? rows.map(histRow).join('') : '<tr><td colspan="6">' + empty('search', 'No reports match', 'Clear the filters, or widen the date range.') + '</td></tr>';
  if (note) {
    var older = M.filterHistory(ROWS, f.q, f.type, { agent: f.agent, days: 'all' }).length - rows.length;
    note.textContent = 'Showing ' + rows.length + ' of ' + ROWS.length + ' report' + (ROWS.length === 1 ? '' : 's') + (older > 0 ? ' · ' + older + ' older hidden by the date range' : '');
  }
}
export function clearHistoryFilters() {
  var set = function(id, v) { var e = el(id); if (e) e.value = v; };
  set('rpt-q', ''); set('rpt-type', ''); set('rpt-agent', ''); set('rpt-range', DEFAULT_RANGE); set('rpt-sort', 'new');
  renderHistory();
}

// ── Compliance tab: one card per framework ───────────────────────────────────
export function paintFrameworkCards(scores) {
  var cards = M.frameworkCards(scores);
  if (!cards.length) {
    put('cmp-fw-cards', card('', empty('shield', 'No compliance frameworks loaded', 'Frameworks appear once the compliance mapper is available.')));
    return;
  }
  put('cmp-fw-cards', '<div class="rk-grid g2">' + cards.map(function(c) {
    return '<section class="rk-card"><div class="rk-hd"><h2>' + x(c.name) + '</h2><span class="mono rpt-pct">' + (c.has ? c.pct + '%' : '—') + '</span></div>' +
      '<div class="rpt-bar">' + bar(c.has ? c.pct : 0, c.tone) + '</div>' +
      '<p class="muted rpt-cdetail"><b>Resistance rate</b> · ' + x(c.detail) + '</p>' +
      (c.coverage ? '<p class="muted rpt-cdetail">' + x(c.coverage) + '</p>' : '') +
      (c.note ? '<p class="cmp-warn">' + x(c.note) + '</p>' : '') +
      (c.warning ? '<p class="cmp-warn"><b>Mapping note.</b> ' + x(c.warning) + '</p>' : '') +
      '<div class="rpt-acts"><button class="btn btn-outline btn-sm"' + on('click', 'openReportGen', 'compliance', c.id) + '>Generate evidence pack</button></div></section>';
  }).join('') + '</div>');
}
export function loadComplianceCards() {
  loadReportsHero();
  apicall('/api/compliance/scores').then(function(s) { paintFrameworkCards(Array.isArray(s) ? s : []); })
    .catch(function() { put('cmp-fw-cards', card('', empty('alert', 'Could not load compliance scores'))); });
}

// ── SLA tab ──────────────────────────────────────────────────────────────────
function sevBadge(sev) {
  var t = sev === 'Critical' ? 'bad' : sev === 'High' || sev === 'Medium' ? 'warn' : 'info';
  return pill(sev || '—', t);
}
export function renderSlaReport(rep) {
  var o = rep.overall || {}, recent = rep.recentlyResolved || [];
  var k = M.slaKpis(o, recent);
  put('sla-rpt-kpis',
    kpi({ label: 'SLA compliance', value: k.rate, sub: k.rateSub, icon: 'clock', tone: k.rateTone }) +
    kpi({ label: 'Median time to resolve', value: k.median, sub: k.medianSub, icon: 'wrench', tone: 'info' }) +
    kpi({ label: 'Breaches', value: k.late, sub: k.lateSub, icon: 'alert', tone: k.late ? 'bad' : 'muted' }) +
    kpi({ label: 'Currently open', value: k.open, sub: k.openSub, icon: 'shield', tone: k.open ? 'warn' : 'muted' }));

  var sev = M.slaSeverityRows(rep.bySeverity || []);
  put('sla-rpt-severity', sev.length ? hbars(sev) : empty('shield', 'No severities with SLA episodes'));

  var tr = M.slaTrend(rep.monthlyTrend || []);
  put('sla-rpt-trend-chart', tr.length > 1
    ? chartSlot({ type: 'line', h: 200, suffix: '%', yMax: 100, labels: tr.map(function(m) { return m.month; }), series: [{ name: 'Compliance rate', data: tr.map(function(m) { return m.rate; }), color: CHART_COLORS.accent }] })
    : empty('trend', 'Not enough history', 'A trend line needs at least two months of resolved episodes.'));

  put('sla-rpt-recent-body', recent.length ? recent.map(function(r) {
    return '<tr class="noclick"><td><div><code>' + x(r.checkId) + '</code></div><div class="muted tiny">' + x(r.agentId) + '</div></td>' +
      '<td>' + sevBadge(r.severity) + '</td><td class="tiny muted">' + fmtDate(r.resolvedAt) + '</td>' +
      '<td>' + pill(r.onTime ? 'On time' : 'Late', r.onTime ? 'ok' : 'bad') + '</td></tr>';
  }).join('') : '<tr><td colspan="4">' + empty('check', 'No resolved episodes yet') + '</td></tr>');
}

// Action names used by the reports markup (see globals.js ACTIONS).
export function rptFilter() { renderHistory(); }
export function rptClear() { clearHistoryFilters(); }
