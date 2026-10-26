// Live Runs page, following the design demo: hero chips, the in-flight strip, two charts, the
// status/target filter and the Scenario Runs table card (filter, columns, paging, selection, CSV).
// Every figure comes from the /api/scenarios/runs rows loadRuns already fetched (and the agent list the
// console already holds); the table rows and every per-row action stay in reports.js.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { state } from '../core/state.js';
import { card, icon, bar, empty } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { showToast } from '../core/util.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './runs-model.js';

export { runBucket, runStats, runsPerDay } from './runs-model.js';

var lastRuns = [];
var F = { q: '', status: 'all', target: 'all' };
var T = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} };

function agents() { return state.agents || []; }
function sm(name) { return icon(name).replace('width="16" height="16"', 'width="13" height="13"'); }

// ── Hero chips ─────────────────────────────────────────────────────────────
function renderHero(runs) {
  var h = M.heroStats(runs, agents());
  setHeroStat('runs-cnt', h.running);
  setHeroStat('runs-hs-queued', h.queued);
  setHeroStat('runs-hs-pass', h.passRate);
  setHeroStat('runs-hs-agents', h.agentsBusy);
}

// ── In-flight strip ────────────────────────────────────────────────────────
function cardHtml(c) {
  var tone = c.state === 'queued' ? 'warn' : c.state === 'running' ? 'info' : 'warn';
  var openArgs = [c.id, c.name, c.steps, c.mode, c.maxPrivilege];
  var pauseBtn = !c.live ? '' : c.paused
    ? '<button class="btn btn-outline btn-sm" id="pause-btn-' + x(c.id) + '"' + on('click', 'resumeRun', c.id) + '>' + sm('play') + 'Resume</button>'
    : '<button class="btn btn-outline btn-sm" id="pause-btn-' + x(c.id) + '"' + on('click', 'pauseRun', c.id) + '>' + sm('pause') + 'Pause</button>';
  return '<div class="live-card" data-run-card="' + x(c.id) + '"' + on('click', 'openRunCard', c.id) + '>' +
    '<div class="lc-top"><span class="mono muted" title="' + x(c.id) + '">' + x(c.shortId) + '</span><span class="rk-pill tone-' + tone + '">' + x(c.label) + '</span></div>' +
    '<b class="lc-name">' + x(c.name) + '</b>' +
    '<div class="muted lc-tgt">' + sm('server') + '<span>' + x(c.target) + (c.by ? ' · ' + x(c.by) : '') + '</span></div>' +
    '<div class="lp">' + bar(c.pct, 'info') + '<span class="mono muted lp-n">' + c.pct + '%</span></div>' +
    '<div class="muted lc-step">' + x(c.step) + '</div>' +
    '<div class="lc-btns">' +
      (c.live ? '<button class="btn btn-outline btn-sm"' + on('click', 'openRunPanelAction', openArgs[0], openArgs[1], openArgs[2], openArgs[3], openArgs[4]) + ' title="Live run timeline + progress">' + sm('eye') + 'Live</button>' : '') +
      (c.live ? '<button class="btn btn-outline-red btn-sm"' + on('click', 'stopRun', c.id) + ' title="Stop this run — keeps completed steps, marks the run partial">' + sm('stop') + 'Stop</button>' : '') +
      pauseBtn +
      (c.tag ? '<span class="rk-chip tone-muted lc-res">' + x(c.tag) + '</span>' : '') +
    '</div></div>';
}

export function inFlightHtml(runs, f, agentList) {
  var list = M.liveRuns(runs).filter(function(r) { return M.matchRun(r, f, agentList); });
  var head = '<h4 class="sec-label">' + sm('bolt') + ' In flight <span class="muted">· running and queued — finished runs move to the list below</span></h4>';
  if (!list.length) {
    return head + '<div class="rk-card runs-idle">' + icon('ok') + '<b>Nothing running right now</b><div>Start a scenario from the Scenarios page and it will appear here live.</div></div>';
  }
  return head + '<div class="live-strip">' + list.map(function(r) { return cardHtml(M.liveCard(r, agentList)); }).join('') + '</div>';
}

// ── Charts ─────────────────────────────────────────────────────────────────
var SEG_COLOR = { completed: CHART_COLORS.ok, failed: CHART_COLORS.bad, running: '#22d3ee', queued: CHART_COLORS.warn, partial: CHART_COLORS.warn, cancelled: CHART_COLORS.muted };

export function chartsHtml(runs) {
  if (!runs || !runs.length) return '';
  var wk = M.weekSeries(runs);
  var segs = M.outcomeSegments(runs).map(function(s) { return { label: s.label, value: s.value, color: SEG_COLOR[s.key] || CHART_COLORS.info }; });
  var legend = '<div class="legend"><span><i class="lg-ok"></i>Passed</span><span><i class="lg-bad"></i>Failed</span></div>';
  var bars = wk.total
    ? chartSlot({ type: 'bar', stacked: true, labels: wk.labels, h: 170, yMax: Math.max(4, Math.ceil(wk.peak / 4) * 4), series: [{ name: 'Passed', color: CHART_COLORS.ok, data: wk.passed }, { name: 'Failed', color: CHART_COLORS.bad, data: wk.failed }] })
    : empty('runs', 'No completed or failed runs', 'The last seven days up to the newest run.');
  return '<div class="rk-grid g2">' +
    card('Runs this week', bars, { actions: legend }) +
    card('Outcome mix', chartSlot({ type: 'donut', segments: segs, center: String(runs.length), centerSub: 'runs', h: 170, legendRight: true })) +
    '</div>';
}

// ── Filters ────────────────────────────────────────────────────────────────
function optionsHtml(allLabel, opts, current) {
  return '<option value="all">' + x(allLabel) + '</option>' + opts.map(function(o) {
    return '<option value="' + x(o.id) + '"' + (o.id === current ? ' selected' : '') + '>' + x(o.label) + '</option>';
  }).join('');
}

function renderFilters() {
  var st = document.getElementById('runs-status-sel');
  var tg = document.getElementById('runs-target-sel');
  if (st) { st.innerHTML = optionsHtml('All statuses', M.statusOptions(lastRuns), F.status); st.value = F.status; }
  if (tg) { tg.innerHTML = optionsHtml('All targets', M.targetOptions(lastRuns, agents()), F.target); tg.value = F.target; }
  var clr = document.getElementById('runs-clear');
  if (clr) clr.hidden = !(F.q || F.status !== 'all' || F.target !== 'all');
}

function refreshLive() {
  var el = document.getElementById('runs-live');
  if (el) el.innerHTML = inFlightHtml(lastRuns, F, agents());
}

export function renderRunsSummary(runs) {
  lastRuns = runs || [];
  renderColsMenu();
  renderHero(lastRuns);
  var ch = document.getElementById('runs-summary');
  if (ch) ch.innerHTML = chartsHtml(lastRuns);
  renderFilters();
  refreshLive();
  applyRunsFilter();
}

function filtersChanged() {
  T.page = 0;
  renderFilters();
  refreshLive();
  applyRunsFilter();
}
export function filterRuns(el) { F.q = String((el && el.value) || ''); filtersChanged(); }
export function setRunsStatusFilter(el) { F.status = (el && el.value) || 'all'; filtersChanged(); }
export function setRunsTargetFilter(el) { F.target = (el && el.value) || 'all'; filtersChanged(); }
export function clearRunsFilters() {
  F.q = ''; F.status = 'all'; F.target = 'all';
  var q = document.getElementById('runs-search'); if (q) q.value = '';
  filtersChanged();
}

// ── Table (rows are built by reports.js; this layer filters, sorts, pages and selects them) ──
function bodyRows() {
  var body = document.getElementById('runs-body');
  return body ? Array.prototype.slice.call(body.querySelectorAll('tr[data-run-key]')) : [];
}
function rowOk(tr) {
  if (F.status !== 'all' && tr.getAttribute('data-run-status') !== F.status) return false;
  if (F.target !== 'all' && tr.getAttribute('data-run-target') !== F.target) return false;
  var q = F.q.trim().toLowerCase();
  if (!q) return true;
  return (tr.getAttribute('data-run-key') + ' ' + tr.textContent).toLowerCase().indexOf(q) !== -1;
}
function cellVal(tr, col) {
  var td = tr.cells[col + 1];
  if (!td) return '';
  var s = td.getAttribute('data-sort');
  return s != null ? s : td.textContent.replace(/\s+/g, ' ').trim();
}

export function applyRunsFilter() {
  var body = document.getElementById('runs-body');
  if (!body) return;
  var rows = bodyRows();
  var pageList = rows.filter(rowOk);
  var q2 = T.q.trim().toLowerCase();
  var list = pageList.filter(function(tr) { return !q2 || tr.textContent.replace(/\s+/g, ' ').toLowerCase().indexOf(q2) !== -1; });
  if (T.col >= 0) {
    var vals = list.map(function(tr) { return cellVal(tr, T.col); });
    var numeric = M.allNumeric(vals);
    list = list.slice().sort(function(a, b) {
      var u = cellVal(a, T.col), v = cellVal(b, T.col);
      var c = numeric ? M.cellNumber(u) - M.cellNumber(v) : u.localeCompare(v, undefined, { numeric: true });
      return (c || 0) * T.dir;
    });
  }
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(T.page, pages - 1);
  var start = T.page * T.per;
  var vis = list.slice(start, start + T.per);
  var rest = rows.filter(function(tr) { return list.indexOf(tr) < 0; });
  list.concat(rest).forEach(function(tr) { body.appendChild(tr); });
  rows.forEach(function(tr) { tr.hidden = vis.indexOf(tr) < 0; });
  // hidden columns
  var table = body.parentNode;
  Array.prototype.forEach.call(table.rows, function(tr) {
    Array.prototype.forEach.call(tr.cells, function(td, j) { td.classList.toggle('dt-hide', j > 0 && !!T.hidden[j - 1]); });
  });
  Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th, j) {
    if (j > 0) { th.classList.toggle('sorted', j - 1 === T.col); var a = th.querySelector('.dt-arrow'); if (a) a.textContent = j - 1 === T.col ? (T.dir > 0 ? '▲' : '▼') : ''; }
  });
  rows.forEach(function(tr) { var cb = tr.querySelector('.dt-cb'); if (cb) cb.checked = !!T.sel[tr.getAttribute('data-run-key')]; });
  var selN = Object.keys(T.sel).filter(function(k) { return rows.some(function(tr) { return tr.getAttribute('data-run-key') === k; }); }).length;
  var all = document.getElementById('runs-sel-all');
  if (all) {
    var onList = list.filter(function(tr) { return T.sel[tr.getAttribute('data-run-key')]; }).length;
    all.checked = list.length > 0 && onList === list.length;
    all.indeterminate = onList > 0 && onList < list.length;
  }
  var set = function(id, fn) { var el = document.getElementById(id); if (el) fn(el); };
  set('runs-bulk', function(el) { el.hidden = selN === 0; });
  set('runs-bulk-n', function(el) { el.textContent = String(selN); });
  set('runs-card-n', function(el) { el.textContent = String(pageList.length); });
  set('runs-dt-count', function(el) { el.textContent = list.length + ' of ' + pageList.length + ' rows'; });
  set('runs-dt-range', function(el) { el.textContent = M.rangeText(list.length, T.page, T.per); });
  set('runs-dt-pager', function(el) {
    el.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'runsPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'runsPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  });
  var anyLive = M.liveRuns(lastRuns).filter(function(r) { return M.matchRun(r, F, agents()); }).length > 0;
  set('runs-empty', function(el) {
    var none = !rows.length;
    el.hidden = list.length > 0;
    if (none) {
      el.innerHTML = empty('search', lastRuns.length ? 'No finished runs yet' : 'No runs yet', lastRuns.length ? 'Running runs appear in the in-flight strip above.' : 'Go to Scenarios and run one.');
    } else if (pageList.length && !list.length) {
      el.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'clearRunsTableQuery') + '>Clear filter</button></div>';
    } else {
      el.innerHTML = empty('search', anyLive ? 'No finished runs match these filters' : 'No runs match these filters', 'Try a different status or target.');
    }
  });
  set('runs-table-wrap', function(el) { el.hidden = !list.length; });
  set('runs-dt-foot', function(el) { el.hidden = !list.length; });
  set('runs-dt-toolbar', function(el) { el.hidden = !rows.length; });
  set('runs-card-sub', function(el) { el.hidden = !rows.length; });
  var clr = document.getElementById('runs-clear');
  if (clr) clr.hidden = !(F.q || F.status !== 'all' || F.target !== 'all');
}

export function runsTableQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; applyRunsFilter(); }
export function clearRunsTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('runs-dt-q'); if (q) q.value = ''; applyRunsFilter(); }
export function setRunsPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; applyRunsFilter(); }
export function runsPage(d) { T.page += Number(d) || 0; applyRunsFilter(); }
export function sortRunsBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  applyRunsFilter();
}
export function toggleRunsCols() { var m = document.getElementById('runs-cols'); if (m) m.hidden = !m.hidden; }
export function runsColToggle(col, el) { if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true; applyRunsFilter(); }
export function runsSelectRow(key, el) { if (el && el.checked) T.sel[key] = true; else delete T.sel[key]; applyRunsFilter(); }
export function runsSelectAll(el) {
  bodyRows().filter(rowOk).forEach(function(tr) {
    var k = tr.getAttribute('data-run-key');
    if (el && el.checked) T.sel[k] = true; else delete T.sel[k];
  });
  applyRunsFilter();
}
export function clearRunsSelection() { T.sel = {}; applyRunsFilter(); }

function headers() {
  return Array.prototype.map.call(document.querySelectorAll('#runs-table-wrap thead th'), function(th) { return th.textContent.replace(/[▲▼]/g, '').trim(); }).slice(1);
}
function exportRows(onlySelected) {
  var cols = headers().map(function(h, i) { return i; }).filter(function(i) { return !T.hidden[i]; });
  var rows = bodyRows().filter(function(tr) {
    return onlySelected ? !!T.sel[tr.getAttribute('data-run-key')] : (rowOk(tr) && (!T.q.trim() || tr.textContent.replace(/\s+/g, ' ').toLowerCase().indexOf(T.q.trim().toLowerCase()) !== -1));
  });
  var hs = headers();
  var csv = M.csvText(cols.map(function(i) { return hs[i]; }), rows.map(function(tr) {
    return cols.map(function(i) { var td = tr.cells[i + 1]; return td ? (td.getAttribute('data-csv') != null ? td.getAttribute('data-csv') : td.textContent.replace(/\s+/g, ' ').trim()) : ''; });
  }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'scenario-runs.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportRunsCsv() { exportRows(false); }
export function exportRunsSelected() { exportRows(true); }

// openRunCard / openRunRow: clicking a card or row (not one of its buttons) opens what its main button opens.
export function openRunCard(id, el, event) {
  if (event && event.target && event.target.closest && event.target.closest('button, a, input')) return;
  var b = el && el.querySelector('[data-on-click="openRunPanelAction"]');
  if (b) b.click();
}
export function openRunRow(key, el, event) {
  if (event && event.target && event.target.closest && event.target.closest('button, a, input, label, .dt-selcol')) return;
  var b = el && (el.querySelector('[data-on-click="viewRunResults"]') || el.querySelector('[data-on-click="openRunPanelAction"]'));
  if (b) b.click();
}

// Close the columns menu when the click lands anywhere else on the page.
if (typeof document !== 'undefined') {
  document.addEventListener('click', function(e) {
    var m = document.getElementById('runs-cols');
    if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
  });
}

export function renderColsMenu() {
  var m = document.getElementById('runs-cols');
  if (!m || m.getAttribute('data-ready')) return;
  m.setAttribute('data-ready', '1');
  m.innerHTML = headers().map(function(h, i) {
    return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk" checked' + on('change', 'runsColToggle', i) + '><span>' + x(h) + '</span></label>';
  }).join('');
}

export function runsStatusAttr(r) {
  var tg = M.agentLabel(agents(), r && r.agentId);
  return ' data-run-key="' + x(r && r.id) + '" data-run-status="' + x(M.filterKey(r)) + '" data-run-target="' + x(tg) + '"';
}
// The first cell of every table row: its selection checkbox.
export function runsSelCell(key) {
  return '<td class="dt-selcol"><input type="checkbox" class="dt-cb" aria-label="Select run"' + on('change', 'runsSelectRow', key) + '></td>';
}
// Attributes that make a whole run row open its results (or live panel).
export function runsRowClick(key) { return ' class="dt-click"' + on('click', 'openRunRow', key); }
