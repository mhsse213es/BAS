// Settings page view: the Users & roles table card (the design demo's table rule: sortable headers under 8
// rows, the full toolbar with filter, count, columns, page size, CSV, selection and pager from 8 rows up).
// Loading and the row actions stay in evidence.js (loadUsers); this module paints the rows it is given.
// Pure helpers live in set-model.js.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast, fmtDate } from '../core/util.js';
import { pill, chip, empty } from '../core/kit.js';
import * as M from './set-model.js';

var BOX = 'users-box';
var ST = { rows: null, mode: '', t: { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} } };

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function el(id) { return document.getElementById(id); }
function setText(id, t) { var e = el(id); if (e) e.textContent = t; }
function setHidden(id, h) { var e = el(id); if (e) e.hidden = h; }
function pid(s) { return 'sut-' + s; }

function currentList() { return M.sortUsers(M.filterUsers(ST.rows || [], ST.t.q), ST.t.col, ST.t.dir); }
function visibleCols() { return M.USER_COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !ST.t.hidden[i]; }); }

function skeleton(mode) {
  if (mode === 'empty') return '<div id="users-empty">' + empty('users', 'No users found', 'Create the first user with New user.') + '</div>';
  var full = mode === 'full';
  var h = '<div class="runs-dt">';
  if (full) {
    h += '<div class="dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="' + pid('q') + '" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'setTblQuery') + '></label>' +
      '<span class="dt-count muted" id="' + pid('count') + '"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'setTblCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols ex-cols" id="' + pid('cols') + '" hidden></div></div>' +
      '<select id="' + pid('per') + '" class="dt-per" aria-label="Rows per page"' + on('change', 'setTblPer') + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'setTblExport') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
      '<div class="dt-bulk" id="' + pid('bulk') + '" hidden><b id="' + pid('bulk-n') + '">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'setTblExportSel') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'setTblClearSel') + '>Clear selection</button></div>';
  }
  h += '<div class="tbl-wrap dt-scroll ex-wrap" id="' + pid('wrap') + '"><table><thead id="' + pid('thead') + '"></thead><tbody id="users-body"></tbody></table></div>';
  if (full) {
    h += '<div class="dt-empty" id="' + pid('noruns') + '" hidden></div>' +
      '<div class="dt-foot" id="' + pid('foot') + '"><span class="dt-range muted" id="' + pid('range') + '"></span><div class="dt-pager" id="' + pid('pager') + '"></div></div>';
  }
  return h + '</div>';
}

function cellHtml(col, u) {
  switch (col) {
    case 0: {
      var name = String(u.username || '');
      return '<td><div class="row set-user"><span class="avatar avatar-sm">' + x((name.charAt(0) || '?').toUpperCase()) + '</span><b>' + x(name) + '</b>' +
        (u.mustChangePw ? ' <span class="tag u-warning">pw reset</span>' : '') + '</div></td>';
    }
    case 1: return '<td>' + chip(M.roleLabel(u.role), M.roleTone(u.role)) + '</td>';
    case 2: return '<td>' + pill(M.userStatus(u), u.isActive ? 'ok' : 'muted') + '</td>';
    case 3: return '<td class="muted">' + x(u.createdAt ? fmtDate(u.createdAt) : '—') + '</td>';
    default: return '<td class="muted">' + x(u.lastLogin ? fmtDate(u.lastLogin) : 'Never') + '</td>';
  }
}

function actionsHtml(u) {
  return '<td class="num set-acts"><button class="btn btn-outline btn-sm"' + on('click', 'openEditUser', u.id, u.username, u.role) + '>Edit</button>' +
    '<button class="btn btn-outline btn-sm"' + on('click', 'doResetPassword', u.id, u.username) + '>Reset PW</button>' +
    '<button class="btn btn-outline-' + (u.isActive ? 'red' : 'green') + ' btn-sm"' + on('click', 'toggleUserActive', u.id, !u.isActive) + '>' + (u.isActive ? 'Disable' : 'Enable') + '</button></td>';
}

function paintTable() {
  var T = ST.t, full = ST.mode === 'full';
  var tbody = el('users-body');
  if (!tbody) return;
  var all = ST.rows || [];
  var list = currentList();
  if (!full) T.per = 9999;
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var onList = list.filter(function(r) { return T.sel[all.indexOf(r)]; }).length;
  el(pid('thead')).innerHTML = '<tr>' +
    (full ? '<th class="dt-selcol"><input type="checkbox" class="dt-cb" id="' + pid('selall') + '" title="Select all on this table"' + on('change', 'setTblSelectAll') + '></th>' : '') +
    cols.map(function(c) {
      return '<th class="dt-th' + (T.col === c ? ' sorted' : '') + '"' + on('click', 'setTblSort', c) + '>' + x(M.USER_COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '<th></th></tr>';
  var sa = el(pid('selall'));
  if (sa) { sa.checked = list.length > 0 && onList === list.length; sa.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(u) {
    var i = all.indexOf(u);
    return '<tr>' +
      (full ? '<td class="dt-selcol"><input type="checkbox" class="dt-cb" aria-label="Select row"' + (T.sel[i] ? ' checked' : '') + on('change', 'setTblSelectRow', i) + '></td>' : '') +
      cols.map(function(c) { return cellHtml(c, u); }).join('') + actionsHtml(u) + '</tr>';
  }).join('');
  if (!full) return;
  var menu = el(pid('cols'));
  if (menu) {
    menu.innerHTML = M.USER_COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'setTblColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden(pid('bulk'), selN === 0);
  setText(pid('bulk-n'), String(selN));
  setText(pid('count'), M.rangeCounts(list.length, all.length));
  setText(pid('range'), M.rangeText(list.length, T.page, T.per));
  var pager = el(pid('pager'));
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'setTblPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'setTblPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = el(pid('noruns'));
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'setTblClear') + '>Clear filter</button></div>';
  }
  setHidden(pid('wrap'), !list.length);
  setHidden(pid('foot'), !list.length);
}

// setUsersRows stores the user list and repaints the table card.
export function setUsersRows(rows) {
  ST.rows = Array.isArray(rows) ? rows : [];
  ST.t.sel = {};
  var box = el(BOX);
  if (!box) return;
  var mode = !ST.rows.length ? 'empty' : M.isFull(ST.rows.length) ? 'full' : 'light';
  if (ST.mode !== mode || !el('users-body') && mode !== 'empty') {
    box.innerHTML = skeleton(mode);
    ST.mode = mode;
    var q = el(pid('q')); if (q) q.value = ST.t.q;
    var per = el(pid('per')); if (per) per.value = String(ST.t.per);
  }
  if (mode !== 'empty') paintTable();
}

// ── Table controls ──
export function setTblQuery(elm) { ST.t.q = String((elm && elm.value) || ''); ST.t.page = 0; paintTable(); }
export function setTblClear() { ST.t.q = ''; ST.t.page = 0; var q = el(pid('q')); if (q) q.value = ''; paintTable(); }
export function setTblPer(elm) { ST.t.per = Number(elm && elm.value) || 8; ST.t.page = 0; paintTable(); }
export function setTblPage(d) { ST.t.page += Number(d) || 0; paintTable(); }
export function setTblSort(col) {
  var T = ST.t;
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function setTblCols() { var m = el(pid('cols')); if (m) m.hidden = !m.hidden; }
export function setTblColToggle(col, elm) {
  var T = ST.t;
  col = Number(col);
  if (elm && elm.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function setTblSelectRow(i, elm) { if (elm && elm.checked) ST.t.sel[i] = true; else delete ST.t.sel[i]; paintTable(); }
export function setTblSelectAll(elm) {
  var all = ST.rows || [];
  currentList().forEach(function(r) { var i = all.indexOf(r); if (elm && elm.checked) ST.t.sel[i] = true; else delete ST.t.sel[i]; });
  paintTable();
}
export function setTblClearSel() { ST.t.sel = {}; paintTable(); }

function exportRows(onlySelected) {
  var rows = onlySelected ? (ST.rows || []).filter(function(r, i) { return ST.t.sel[i]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(cols.map(function(c) { return M.USER_COLUMNS[c]; }), rows.map(function(r) { return M.csvRow(r, cols); }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'users.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function setTblExport() { exportRows(false); }
export function setTblExportSel() { exportRows(true); }

document.addEventListener('click', function(e) {
  if (e.target.closest && e.target.closest('.dt-colwrap')) return;
  var m = el(pid('cols')); if (m && !m.hidden) m.hidden = true;
});
