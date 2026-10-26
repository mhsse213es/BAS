// Renderers for the redesigned Reports page and its Compliance report / SLA compliance sub-tabs.
// The numbers come from rpt-model.js (pure); this file only builds markup and fills the placeholders in
// index.html. Escape every dynamic value with x(); behaviour is attached with on() / data-on-* only.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, fmtDate } from '../core/util.js';
import { setDisplay } from '../core/inline-style.js';
import { kpi, card, hbars, bar, pill, chip, empty, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './rpt-model.js';

function el(id) { return document.getElementById(id); }
function put(id, html) { var e = el(id); if (e) e.innerHTML = html; }

// ── Banner and sub-tab numbers (the same three banners sit on Reports / Compliance / SLA) ──
var HERO = { reports: null, frameworks: null };
function paintHero() {
  ['', '-c', '-s'].forEach(function(sfx) {
    setHeroStat('rpt-hs-reports' + sfx, HERO.reports == null ? '—' : HERO.reports);
    setHeroStat('rpt-hs-frameworks' + sfx, HERO.frameworks == null ? '—' : HERO.frameworks);
  });
  ['rpt-tab-n', 'rpt-tab-n-c', 'rpt-tab-n-s'].forEach(function(id) {
    var e = el(id);
    if (e) e.textContent = HERO.reports ? String(HERO.reports) : '';
  });
}
export function setReportsCount(n) { HERO.reports = n; paintHero(); }
// loadReportsHero fills both banner numbers from the history log and the framework list.
export function loadReportsHero() {
  apicall('/api/reports').then(function(list) { HERO.reports = M.heroStats(list, null).reports; paintHero(); }).catch(function() {});
  apicall('/api/compliance/frameworks').then(function(f) { HERO.frameworks = M.heroStats(null, f).frameworks; paintHero(); }).catch(function() {});
}

// ── Reports tab: available reports by agent ──────────────────────────────────
export function paintAvailable(rows) {
  if (!rows.length) {
    put('rep-available', '<tr><td colspan="5">' + empty('report', 'No agents with completed runs yet', 'Run a scenario, then generate its report here.') + '</td></tr>');
    return;
  }
  put('rep-available', rows.map(function(r) {
    return '<tr>' +
      '<td><b>' + x(r.host) + '</b></td>' +
      '<td>' + x(r.lastName || 'unnamed scenario') + ' <span class="muted">(latest run)</span></td>' +
      '<td class="num">' + r.runs + '</td>' +
      '<td class="muted">' + ago(r.last) + '</td>' +
      '<td class="rpt-acts"><button class="btn btn-outline btn-sm"' + on('click', 'genAgentReport', r.id, 'posture', 'pdf') + '>PDF Report</button> ' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'genAgentReport', r.id, 'posture', 'csv') + '>CSV</button> ' +
        '<button class="btn btn-outline btn-sm"' + on('click', 'genAgentReport', r.id, 'audit', '') + '>Audit pack</button></td></tr>';
  }).join(''));
}
export function paintAvailableError() {
  put('rep-available', '<tr><td colspan="5">' + empty('alert', 'Could not load agents') + '</td></tr>');
}

// ── Reports tab: history table with search + type filter ─────────────────────
var ROWS = [];
function val(id) { var e = el(id); return e ? e.value : ''; }

export function paintHistory(list) {
  ROWS = M.historyRows(list);
  setReportsCount(ROWS.length);
  var sel = el('rpt-type');
  if (sel) {
    var keep = sel.value;
    sel.innerHTML = '<option value="">All types</option>' + M.typeOptions(ROWS).map(function(o) {
      return '<option value="' + x(o[0]) + '"' + (o[0] === keep ? ' selected' : '') + '>' + x(o[1]) + '</option>';
    }).join('');
  }
  renderHistory();
}

function histRow(r) {
  return '<tr class="noclick">' +
    '<td><div>' + x(r.title) + (r.failed ? ' ' + chip('Failed', 'bad') : '') + '</div><div class="mono muted tiny">' + x(r.shortId) + '</div></td>' +
    '<td>' + chip(r.name, 'info') + '</td>' +
    '<td class="tiny muted">' + fmtDate(r.at) + '</td>' +
    '<td class="tiny muted">' + x(r.by) + '</td>' +
    '<td>' + chip(r.fmt, 'muted') + '</td>' +
    '<td class="td-r"><div class="rpt-acts end">' +
      (r.canPreview ? '<a class="btn btn-outline btn-sm" href="' + x(r.downloadPath) + '" target="_blank" rel="noopener">' + icon('eye') + 'Preview</a>' : '') +
      (r.downloadPath ? '<a class="btn btn-outline btn-sm" href="' + x(r.downloadPath) + '" target="_blank" rel="noopener">' + icon('download') + 'Download</a>' : '') +
    '</div></td></tr>';
}

export function renderHistory() {
  var tb = el('reports-body');
  if (!tb) return;
  var q = val('rpt-q'), t = val('rpt-type');
  var clr = el('rpt-clear');
  if (clr) setDisplay(clr, (q || t) ? '' : 'none');
  if (!ROWS.length) {
    tb.innerHTML = '<tr><td colspan="6">' + empty('report', 'No reports generated yet', 'This log fills when you generate one (from the button above or the per-agent buttons). Test runs do not create reports automatically.') + '</td></tr>';
    return;
  }
  var rows = M.filterHistory(ROWS, q, t);
  tb.innerHTML = rows.length ? rows.map(histRow).join('') : '<tr><td colspan="6">' + empty('search', 'No reports match', 'Clear the filters.') + '</td></tr>';
}
export function clearHistoryFilters() {
  var q = el('rpt-q'), t = el('rpt-type');
  if (q) q.value = '';
  if (t) t.value = '';
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
      '<p class="muted rpt-cdetail">' + x(c.detail) + '</p>' +
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
