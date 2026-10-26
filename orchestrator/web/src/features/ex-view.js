// Exercises page view: the OpenAEV scenarios / OpenAEV exercises / Executions table cards (the design demo's
// table rule: sortable headers under 8 rows, the full toolbar with filter, count, columns, page size, CSV,
// selection and pager from 8 rows up) and the Exercise plans list. Data loading stays in openaev.js
// (loadExercisesTab); this module paints what it is given. Pure helpers live in ex-model.js.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { pill, bar, empty } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './ex-model.js';

var KINDS = ['scen', 'exs', 'execs'];
var BOX = { scen: 'ex-scen-box', exs: 'ex-exs-box', execs: 'ex-execs-box' };
var BODY = { scen: 'openaev-scenarios-body', exs: 'openaev-exercises-body', execs: 'ex-execs-body' };
var EMPTY_ID = { scen: 'openaev-scenarios-empty', exs: 'openaev-exercises-empty', execs: 'ex-execs-empty' };
var EMPTY_TXT = {
  scen: ['bolt', 'No scenarios synced yet', 'Scenarios appear here after the next OpenAEV sync.'],
  exs: ['flag', 'No exercises synced yet', 'Exercises appear here after the next OpenAEV sync.'],
  execs: ['runs', 'No executions yet', 'Launch an exercise plan to follow its progress here.'],
};
var FILE = { scen: 'openaev-scenarios.csv', exs: 'openaev-exercises.csv', execs: 'exercise-executions.csv' };

function fresh() { return { rows: null, mode: '', t: { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} } }; }
var ST = { scen: fresh(), exs: fresh(), execs: fresh() };
var PLANS = null;

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function el(id) { return document.getElementById(id); }
function setText(id, t) { var e = el(id); if (e) e.textContent = t; }
function setHidden(id, h) { var e = el(id); if (e) e.hidden = h; }
function pid(kind, s) { return 'ext-' + kind + '-' + s; }

function currentList(kind) {
  var S = ST[kind];
  return M.sortRows(kind, M.filterRows(kind, S.rows || [], S.t.q), S.t.col, S.t.dir);
}
function visibleCols(kind) {
  var T = ST[kind].t;
  return M.columnsOf(kind).map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; });
}

function skeleton(kind, mode) {
  if (mode === 'empty') {
    var t = EMPTY_TXT[kind];
    return '<div id="' + EMPTY_ID[kind] + '">' + empty(t[0], t[1], t[2]) + '</div>';
  }
  var full = mode === 'full';
  var h = '<div class="runs-dt">';
  if (full) {
    h += '<div class="dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="' + pid(kind, 'q') + '" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'exTblQuery', kind) + '></label>' +
      '<span class="dt-count muted" id="' + pid(kind, 'count') + '"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exTblCols', kind) + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols ex-cols" id="' + pid(kind, 'cols') + '" hidden></div></div>' +
      '<select id="' + pid(kind, 'per') + '" class="dt-per" aria-label="Rows per page"' + on('change', 'exTblPer', kind) + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exTblExport', kind) + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
      '<div class="dt-bulk" id="' + pid(kind, 'bulk') + '" hidden><b id="' + pid(kind, 'bulk-n') + '">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exTblExportSel', kind) + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'exTblClearSel', kind) + '>Clear selection</button></div>';
  }
  h += '<div class="tbl-wrap dt-scroll ex-wrap" id="' + pid(kind, 'wrap') + '"><table><thead id="' + pid(kind, 'thead') + '"></thead><tbody id="' + BODY[kind] + '"></tbody></table></div>';
  if (full) {
    h += '<div class="dt-empty" id="' + pid(kind, 'noruns') + '" hidden></div>' +
      '<div class="dt-foot" id="' + pid(kind, 'foot') + '"><span class="dt-range muted" id="' + pid(kind, 'range') + '"></span><div class="dt-pager" id="' + pid(kind, 'pager') + '"></div></div>';
  }
  return h + '</div>';
}

function cellHtml(kind, col, r) {
  if (kind === 'execs') {
    switch (col) {
      case 0: return '<td><b>' + x(r.name || r.plan_id || '') + '</b></td>';
      case 1: return '<td>' + pill(r.status + (M.isLive(r) ? ' · live' : ''), M.statusTone(r.status)) + '</td>';
      case 2: {
        var p = M.progressPct(r);
        return '<td class="tiny ex-progcell">' + (p == null ? '<span class="muted">—</span>'
          : '<div class="g4-prog">' + bar(p, M.statusTone(r.status)) + '<small>' + x(M.cellText(kind, r, 2)) + '</small></div>') + '</td>';
      }
      default: return '<td class="mono muted">' + x(M.startedOf(r)) + '</td>';
    }
  }
  switch (col) {
    case 0: return '<td><b>' + x(r.Name || '') + '</b></td>';
    case 1: return '<td>' + (r.Category ? x(r.Category) : '<span class="muted">—</span>') + '</td>';
    case 2: return '<td>' + (r.Severity ? pill(r.Severity, M.sevTone(r.Severity)) : '<span class="muted">—</span>') + '</td>';
    case 3: return '<td class="num">' + M.techCount(r) + '</td>';
    case 4: return '<td class="num">' + (r.InjectsCount == null ? '—' : x(r.InjectsCount)) + '</td>';
    default: return '<td class="mono muted">' + x(M.stamp(r.SourceUpdatedAt || '')) + '</td>';
  }
}

function rowOpen(kind, r) {
  return kind === 'execs'
    ? { name: 'openExerciseDetail', arg: r.id }
    : { name: 'openOpenAEVDetail', arg: r.OpenAEVScenarioID };
}

function paintTable(kind) {
  var S = ST[kind], T = S.t, full = S.mode === 'full';
  var tbody = el(BODY[kind]);
  if (!tbody) return;
  var all = S.rows || [];
  var list = currentList(kind);
  if (!full) T.per = 9999;
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols(kind);
  var names = M.columnsOf(kind);
  var onList = list.filter(function(r) { return T.sel[all.indexOf(r)]; }).length;
  el(pid(kind, 'thead')).innerHTML = '<tr>' +
    (full ? '<th class="dt-selcol"><input type="checkbox" class="dt-cb" id="' + pid(kind, 'selall') + '" title="Select all on this table"' + on('change', 'exTblSelectAll', kind) + '></th>' : '') +
    cols.map(function(c) {
      return '<th class="dt-th' + (M.NUM_COLS[kind][c] ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'exTblSort', kind, c) + '>' + x(names[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + (kind === 'execs' ? '<th></th>' : '') + '</tr>';
  var sa = el(pid(kind, 'selall'));
  if (sa) { sa.checked = list.length > 0 && onList === list.length; sa.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(r) {
    var i = all.indexOf(r);
    var o = rowOpen(kind, r);
    var live = kind === 'execs' && M.isLive(r);
    return '<tr class="dt-click" tabindex="0"' + on('click', o.name, o.arg) + on('keydown', 'exRowKeydown', o.name, o.arg) + '>' +
      (full ? '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select row"' + (T.sel[i] ? ' checked' : '') + on('change', 'exTblSelectRow', kind, i) + '></td>' : '') +
      cols.map(function(c) { return cellHtml(kind, c, r); }).join('') +
      (kind === 'execs' ? '<td class="td-r">' + (live ? '<button class="btn btn-outline-red btn-sm"' + on('click', 'abortExecutionStop', r.id) + '>&#9632; Abort</button>' : '') + '</td>' : '') +
      '</tr>';
  }).join('');
  if (!full) return;
  var menu = el(pid(kind, 'cols'));
  if (menu) {
    menu.innerHTML = names.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'exTblColToggle', kind, i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden(pid(kind, 'bulk'), selN === 0);
  setText(pid(kind, 'bulk-n'), String(selN));
  setText(pid(kind, 'count'), M.rangeCounts(list.length, all.length));
  setText(pid(kind, 'range'), M.rangeText(list.length, T.page, T.per));
  var pager = el(pid(kind, 'pager'));
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'exTblPage', kind, -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'exTblPage', kind, 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = el(pid(kind, 'noruns'));
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'exTblClear', kind) + '>Clear filter</button></div>';
  }
  setHidden(pid(kind, 'wrap'), !list.length);
  setHidden(pid(kind, 'foot'), !list.length);
}

function paint(kind) {
  var S = ST[kind], box = el(BOX[kind]);
  if (!box || S.rows === null) return;
  var mode = !S.rows.length ? 'empty' : M.isFull(S.rows.length) ? 'full' : 'light';
  if (S.mode !== mode) {
    box.innerHTML = skeleton(kind, mode);
    S.mode = mode;
    var q = el(pid(kind, 'q')); if (q) q.value = S.t.q;
    var per = el(pid(kind, 'per')); if (per) per.value = String(S.t.per);
  }
  if (mode !== 'empty') paintTable(kind);
}

function renderHero() {
  var h = M.heroStats({ scen: ST.scen.rows, plans: PLANS, execs: ST.execs.rows });
  var v = function(k) { return k == null ? '—' : k; };
  setHeroStat('ex-hs-scen', v(h.scen));
  setHeroStat('ex-hs-plans', v(h.plans));
  setHeroStat('ex-hs-execs', v(h.execs));
  setHeroStat('ex-hs-done', v(h.done));
}

// setExRows stores one list ('scen' | 'exs' | 'execs') and repaints its card and the banner numbers.
export function setExRows(kind, rows) {
  var S = ST[kind];
  S.rows = Array.isArray(rows) ? rows : [];
  S.t.sel = {};
  paint(kind);
  renderHero();
}

export function setExError(kind, msg) {
  var box = el(BOX[kind]);
  if (box && ST[kind].rows === null) box.innerHTML = '<div class="ex-state u-danger">Failed to load: ' + x(msg || 'error') + '</div>';
}

// setExPlans paints the Exercise plans list: name and caption on the left, Launch on the right.
export function setExPlans(plans) {
  PLANS = Array.isArray(plans) ? plans : [];
  var body = el('ex-plans-body');
  if (body) {
    body.innerHTML = PLANS.length
      ? PLANS.map(function(p) {
        return '<div class="ex-plan"><div class="grow"><b>' + x(p.name || '') + '</b><div class="muted ex-plan-sub">' + x(M.planSub(p)) + '</div></div>' +
          '<button class="btn btn-primary btn-sm"' + on('click', 'launchExercisePrompt', p.id) + '>Launch</button></div>';
      }).join('')
      : '<div id="ex-plans-empty">' + empty('campaign', 'No exercise plans yet', 'Create one from an OpenAEV scenario.') + '</div>';
  }
  renderHero();
}

export function setExPlansError(msg) {
  var body = el('ex-plans-body');
  if (body && PLANS === null) body.innerHTML = '<div class="ex-state u-danger">Failed to load: ' + x(msg || 'error') + '</div>';
}

// ── Table controls ──
export function exTblQuery(kind, elm) { var T = ST[kind].t; T.q = String((elm && elm.value) || ''); T.page = 0; paintTable(kind); }
export function exTblClear(kind) { var T = ST[kind].t; T.q = ''; T.page = 0; var q = el(pid(kind, 'q')); if (q) q.value = ''; paintTable(kind); }
export function exTblPer(kind, elm) { var T = ST[kind].t; T.per = Number(elm && elm.value) || 8; T.page = 0; paintTable(kind); }
export function exTblPage(kind, d) { ST[kind].t.page += Number(d) || 0; paintTable(kind); }
export function exTblSort(kind, col) {
  var T = ST[kind].t;
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable(kind);
}
export function exTblCols(kind) { var m = el(pid(kind, 'cols')); if (m) m.hidden = !m.hidden; }
export function exTblColToggle(kind, col, elm) {
  var T = ST[kind].t;
  col = Number(col);
  if (elm && elm.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable(kind);
}
export function exTblSelectRow(kind, i, elm) { var T = ST[kind].t; if (elm && elm.checked) T.sel[i] = true; else delete T.sel[i]; paintTable(kind); }
export function exTblSelectAll(kind, elm) {
  var T = ST[kind].t, all = ST[kind].rows || [];
  currentList(kind).forEach(function(r) { var i = all.indexOf(r); if (elm && elm.checked) T.sel[i] = true; else delete T.sel[i]; });
  paintTable(kind);
}
export function exTblClearSel(kind) { ST[kind].t.sel = {}; paintTable(kind); }

// exRowKeydown: Enter / Space on a focused row opens its detail drawer like a click.
export function exRowKeydown(name, arg, elm, event) {
  if (!(event && (event.key === 'Enter' || event.key === ' ') && event.target === elm)) return;
  event.preventDefault();
  elm.click();
}

function exportRows(kind, onlySelected) {
  var S = ST[kind];
  var rows = onlySelected ? (S.rows || []).filter(function(r, i) { return S.t.sel[i]; }) : currentList(kind);
  var cols = visibleCols(kind), names = M.columnsOf(kind);
  var csv = M.csvText(cols.map(function(c) { return names[c]; }), rows.map(function(r) { return M.csvRow(kind, r, cols); }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = FILE[kind];
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exTblExport(kind) { exportRows(kind, false); }
export function exTblExportSel(kind) { exportRows(kind, true); }

document.addEventListener('click', function(e) {
  if (e.target.closest && e.target.closest('.dt-colwrap')) return;
  KINDS.forEach(function(k) { var m = el(pid(k, 'cols')); if (m && !m.hidden) m.hidden = true; });
});
