// Recommendations page view: the Top-N control row, the "What to simulate next" table card (the design
// demo's table chrome) and the insight cards below it. Data loading stays in attack-path.js
// (loadRecommendations); this module paints what it is given. Pure helpers live in rec-model.js.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { seg, pill, chip, bar, empty, icon } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import { recSummary } from './rich-g4.js';
import * as M from './rec-model.js';

var _rows = [];
var _limit = M.DEFAULT_LIMIT;
var T = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} };

export function recLimit() { return _limit; }

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }

// controlsHtml: Top 10 / 20 / 50 on the left, Copy scenario techniques and Refresh on the right.
export function renderRecControls() {
  var el = document.getElementById('rec-controls');
  if (!el) return;
  el.innerHTML = '<div class="rec-controls">' +
    seg(M.LIMITS.map(function(k) { return { id: k, label: M.limitLabel(k) }; }), _limit, 'setRecLimit') +
    '<div class="rec-controls-r">' +
      '<button type="button" class="btn btn-outline"' + on('click', 'copyRecommendedScenario') + '>' + icon('copy') + 'Copy scenario techniques</button>' +
      '<button type="button" class="btn btn-outline"' + on('click', 'loadRecommendations') + '>' + icon('refresh') + 'Refresh</button>' +
    '</div></div>';
}

// setRecLimitState stores the chosen Top-N and repaints the control row; the caller then reloads.
export function setRecLimitState(v) {
  _limit = M.normLimit(v);
  T.page = 0; T.sel = {};
  renderRecControls();
  return _limit;
}

function cardOpen(inner) {
  return '<section class="rk-card runs-card rec-card"><div class="rk-hd"><h2>What to simulate next</h2><div class="rk-hd-actions"><span class="muted rec-note">' + x(M.NOTE) + '</span></div></div>' + inner + '</section>';
}

export function renderRecLoading() {
  var el = document.getElementById('rec-table');
  if (el) el.innerHTML = cardOpen('<div class="rec-state muted">Loading…</div>');
}
export function renderRecError(msg) {
  var el = document.getElementById('rec-table');
  if (el) el.innerHTML = cardOpen('<div class="rec-state u-danger">Failed to load: ' + x(msg) + '</div>');
}

function skeletonHtml() {
  return cardOpen('<div class="runs-dt">' +
    '<div class="dt-toolbar" id="rec-dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="rec-dt-q" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'recTableQuery') + '></label>' +
      '<span class="dt-count muted" id="rec-dt-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleRecCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="rec-cols" hidden></div></div>' +
      '<select id="rec-dt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'setRecPer') + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportRecCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="rec-bulk" hidden><b id="rec-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportRecSelected') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearRecSelection') + '>Clear selection</button></div>' +
    '<div class="tbl-wrap dt-scroll" id="rec-table-wrap"><table><thead id="rec-thead"></thead><tbody id="rec-table-body"></tbody></table></div>' +
    '<div class="dt-empty" id="rec-empty" hidden></div>' +
    '<div class="dt-foot" id="rec-dt-foot"><span class="dt-range muted" id="rec-dt-range"></span><div class="dt-pager" id="rec-dt-pager"></div></div>' +
    '</div>');
}

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function currentList() { return M.sortRows(M.filterRows(_rows, T.q), T.col, T.dir); }

function cellHtml(col, t) {
  switch (col) {
    case 0: return '<td><b>' + x(t.name || t.techniqueId) + '</b><div class="mono muted rec-id">' + x(t.techniqueId) + '</div></td>';
    case 1: return '<td>' + (t.tactic ? pill(t.tactic, 'info') : '<span class="muted">—</span>') + '</td>';
    case 2: {
      var tone = M.tierTone(t.tier);
      return '<td class="rec-scorecol"><div class="rec-score">' + bar(Number(t.score) || 0, tone) + '<span class="mono muted rec-score-n">' + x(Number(t.score) || 0) + '</span></div>' +
        (t.tier ? '<div class="rec-tier tone-' + tone + '">' + x(t.tier) + '</div>' : '') + '</td>';
    }
    case 3: return '<td>' + pill(M.coverageLabel(t.coverageState), M.coverageTone(t.coverageState)) + '</td>';
    case 4: {
      var b = M.threatBits(t);
      return '<td>' + (b.length ? '<div class="rec-chips">' + b.map(function(c) { return chip(c.text, c.tone); }).join('') + '</div>' : '<span class="muted">—</span>') + '</td>';
    }
    case 5: return '<td class="num">' + (Number(t.environmentRisk) ? x(Number(t.environmentRisk)) : '—') + '</td>';
    default: return '<td class="muted rec-why">' + x((t.reasons || []).join(' · ') || '—') + '</td>';
  }
}

function paintTable() {
  var tbody = document.getElementById('rec-table-body');
  if (!tbody) return;
  var list = currentList();
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var idx = function(t) { return _rows.indexOf(t); };
  var onList = list.filter(function(t) { return T.sel[idx(t)]; }).length;
  document.getElementById('rec-thead').innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="rec-sel-all" title="Select all on this table"' + on('change', 'recSelectAll') + '></th>' +
    cols.map(function(c) {
      return '<th class="dt-th' + (c === 5 ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'recSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '</tr>';
  var all = document.getElementById('rec-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(t) {
    var i = idx(t);
    return '<tr><td class="dt-selcol"><input type="checkbox" class="dt-cb" aria-label="Select technique"' + (T.sel[i] ? ' checked' : '') + on('change', 'recSelectRow', i) + '></td>' +
      cols.map(function(c) { return cellHtml(c, t); }).join('') + '</tr>';
  }).join('');
  var menu = document.getElementById('rec-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'recColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('rec-bulk', selN === 0);
  setText('rec-bulk-n', String(selN));
  setText('rec-dt-count', list.length + ' of ' + _rows.length + ' rows');
  setText('rec-dt-range', M.rangeText(list.length, T.page, T.per));
  var pager = document.getElementById('rec-dt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'recPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'recPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('rec-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'clearRecTableQuery') + '>Clear filter</button></div>';
  }
  setHidden('rec-table-wrap', !list.length);
  setHidden('rec-dt-foot', !list.length);
}

// showRecommendations paints one API answer: banner numbers, the table card, then the insight cards.
export function showRecommendations(data) {
  var list = (data && data.techniques) || [];
  _rows = list;
  T.sel = {}; T.page = 0;
  var h = M.heroStats(list);
  setHeroStat('rec-hs-ranked', h.ranked);
  setHeroStat('rec-hs-top', h.top);
  setHeroStat('rec-hs-never', h.never);
  setHeroStat('rec-hs-path', h.path);
  var el = document.getElementById('rec-table');
  if (el) {
    if (!list.length) {
      el.innerHTML = cardOpen(empty('technique', 'No recommendations yet', 'Seed ATT&CK/ART content to rank techniques.'));
    } else {
      el.innerHTML = skeletonHtml();
      var q = document.getElementById('rec-dt-q'); if (q) q.value = T.q;
      var per = document.getElementById('rec-dt-per'); if (per) per.value = String(T.per);
      paintTable();
    }
  }
  var sum = document.getElementById('rec-summary');
  if (sum) sum.innerHTML = recSummary(list, data && data.suggestedScenario, true);
}

// ── Table controls ──
export function recTableQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; paintTable(); }
export function clearRecTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('rec-dt-q'); if (q) q.value = ''; paintTable(); }
export function setRecPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paintTable(); }
export function recPage(d) { T.page += Number(d) || 0; paintTable(); }
export function recSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function toggleRecCols() { var m = document.getElementById('rec-cols'); if (m) m.hidden = !m.hidden; }
export function recColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function recSelectRow(i, el) { if (el && el.checked) T.sel[i] = true; else delete T.sel[i]; paintTable(); }
export function recSelectAll(el) {
  currentList().forEach(function(t) { var i = _rows.indexOf(t); if (el && el.checked) T.sel[i] = true; else delete T.sel[i]; });
  paintTable();
}
export function clearRecSelection() { T.sel = {}; paintTable(); }

function exportRec(onlySelected) {
  var rows = onlySelected ? _rows.filter(function(t, i) { return T.sel[i]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(cols.map(function(c) { return M.COLUMNS[c]; }).concat(['Technique ID']), rows.map(function(t) { return M.csvRow(t, cols); }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'recommendations.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportRecCsv() { exportRec(false); }
export function exportRecSelected() { exportRec(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('rec-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});
