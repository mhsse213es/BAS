// Agents page table: the design demo's table chrome (filter, row count, columns, page size, CSV,
// checkboxes + bulk bar, sortable headers, pager, "Showing a-b of N") over the agents already loaded from
// GET /api/agents. The server still owns paging (cursor + "Load more") and the search / status / group
// scope; this layer only filters, sorts and pages the rows that are loaded. Pure helpers: agt-model.js.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { icon, empty, chip } from '../core/kit.js';
import * as M from './agt-model.js';

var T = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {}, os: '' };
var CTX = { agents: [], totals: {}, hasMore: false, cells: null, filtering: false };

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function keyOf(a) { return String((a && a.agentId) || ''); }

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function currentList() { return M.sortRows(M.filterRows(M.byOs(CTX.agents, T.os), T.q), T.col, T.dir); }

// The OS filter is read by the toolbar renderer in attack-path.js and reset with the other filters.
export function agtOsFilter() { return T.os; }
export function resetAgtFilters() { T.os = ''; T.q = ''; T.page = 0; var q = document.getElementById('agt-q'); if (q) q.value = ''; }

function skeletonHtml() {
  return '<section class="rk-card flush runs-card agt-card"><div class="runs-dt">' +
    '<div class="dt-toolbar" id="agt-dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="agt-q" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'agtQuery') + '></label>' +
      '<span class="dt-count muted" id="agt-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleAgtCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="agt-cols" hidden></div></div>' +
      '<select id="agt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'setAgtPer') + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportAgtCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="agt-bulk" hidden><b id="agt-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportAgtSelected') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearAgtSelection') + '>Clear selection</button></div>' +
    '<div class="tbl-wrap dt-scroll" id="agt-table-wrap"><table><thead id="agt-thead"></thead><tbody id="agents-body"></tbody></table></div>' +
    '<div class="dt-empty" id="agt-empty" hidden></div>' +
    '<div class="dt-foot" id="agt-foot"><span class="dt-range muted" id="agt-range"></span><span class="muted agt-more-note" id="agt-more-note"></span>' +
      '<button type="button" class="btn btn-outline btn-sm" id="agt-load-more" hidden' + on('click', 'loadMoreAgents') + '>Load more</button><div class="dt-pager" id="agt-pager"></div></div>' +
    '</div></section>';
}

// The server returned nothing for this scope: say so instead of an empty table.
function emptyHtml(filtering) {
  return filtering
    ? empty('search', 'No agents match', 'Clear the filters or pick another group.')
    : empty('server', 'No agents registered yet', 'Use Deploy agent to enroll the first endpoint.');
}

export function paintAgentTable(ctx) {
  CTX = ctx;
  var mount = document.getElementById('agent-table-mount');
  if (!mount) return;
  if (!ctx.agents.length) {
    mount.innerHTML = '<div class="agt-empty">' + emptyHtml(ctx.filtering) + '</div>';
    return;
  }
  if (!document.getElementById('agents-body')) {
    mount.innerHTML = skeletonHtml();
    var per = document.getElementById('agt-per'); if (per) per.value = String(T.per);
    var q = document.getElementById('agt-q'); if (q) q.value = T.q;
  }
  paint();
}

function paint() {
  var tbody = document.getElementById('agents-body');
  if (!tbody) return;
  var list = currentList();
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var onList = list.filter(function(a) { return T.sel[keyOf(a)]; }).length;
  document.getElementById('agt-thead').innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="agt-sel-all" title="Select all on this table"' + on('change', 'agtSelectAll') + '></th>' +
    cols.map(function(c) {
      return '<th class="dt-th' + (M.NUM_COLS[c] ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'agtSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '<th class="agt-actcol"></th></tr>';
  var all = document.getElementById('agt-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(a, i) {
    var k = keyOf(a);
    return '<tr class="agt-row dt-click" tabindex="0"' + on('click', 'rowMenuDetail', k) + on('keydown', 'agentRowKeydown', k) + '>' +
      '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select agent"' + (T.sel[k] ? ' checked' : '') + on('change', 'agtSelectRow', k) + '></td>' +
      cols.map(function(c) { return CTX.cells(a, c, start + i); }).join('') +
      '<td class="agt-actcol"' + on('click', 'stopEvent') + '>' + CTX.cells(a, -1, start + i) + '</td></tr>';
  }).join('');
  var menu = document.getElementById('agt-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'agtColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('agt-bulk', selN === 0);
  setText('agt-bulk-n', String(selN));
  setText('agt-count', M.rangeCounts(list.length, CTX.agents.length));
  setText('agt-range', M.rangeText(list.length, T.page, T.per));
  setText('agt-more-note', M.footNote(CTX.agents.length, CTX.hasMore, M.fleetCount(CTX.totals)));
  setHidden('agt-load-more', !CTX.hasMore);
  var pager = document.getElementById('agt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'agtPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'agtPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('agt-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'clearAgtQuery') + '>Clear filter</button></div>';
  }
  setHidden('agt-table-wrap', !list.length);
}

// ── Table controls ──
export function agtQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; paint(); }
export function clearAgtQuery() { T.q = ''; T.os = ''; T.page = 0; var q = document.getElementById('agt-q'); if (q) q.value = ''; paint(); }
export function setAgtOs(el) { T.os = String((el && el.value) || ''); T.page = 0; paint(); }
export function setAgtPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paint(); }
export function agtPage(d) { T.page += Number(d) || 0; paint(); }
export function agtSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paint();
}
export function toggleAgtCols() { var m = document.getElementById('agt-cols'); if (m) m.hidden = !m.hidden; }
export function agtColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paint();
}
export function agtSelectRow(k, el) { if (el && el.checked) T.sel[k] = true; else delete T.sel[k]; paint(); }
export function agtSelectAll(el) {
  currentList().forEach(function(a) { if (el && el.checked) T.sel[keyOf(a)] = true; else delete T.sel[keyOf(a)]; });
  paint();
}
export function clearAgtSelection() { T.sel = {}; paint(); }
function exportAgt(onlySelected) {
  var rows = onlySelected ? CTX.agents.filter(function(a) { return T.sel[keyOf(a)]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(M.csvHeader(cols), M.csvRows(rows, cols));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'agents.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportAgtCsv() { exportAgt(false); }
export function exportAgtSelected() { exportAgt(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('agt-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});

// ── Cells (shared by the row renderer in attack-path.js) ──

// statusCell: the demo's status pill (dot + label), then the real signals the demo has no field for.
export function statusCellHtml(a, activeJob) {
  var b = M.bucketOf(a);
  var h = '<span class="rk-pill tone-' + M.STATUS_TONE[b] + '">' + x(M.STATUS_LABEL[b]) + '</span>';
  if (a.state && a.state !== 'active') h += ' ' + chip(a.state, a.state === 'retired' || a.state === 'uninstalled' ? 'muted' : 'warn');
  if (a.status !== 'offline' && !a.wsConnected) h += ' <span class="agt-flag" title="Heartbeat is reaching the server, but the WebSocket task channel is down -- dispatching a run to this agent will fail until it reconnects. Often a proxy/firewall blocking the WS Upgrade handshake.">' + icon('alert') + 'Task channel down</span>';
  if (a.status !== 'offline' && a.transport === 'legacy') h += ' <span class="agt-flag" title="This agent is on legacy transport -- it never completed mTLS bootstrap and cannot receive signed commands. Scenario dispatch will fail. Usually means it was installed without --ca-root; see the Deploy agent page for the current install command, or fetch the CA root manually from /api/config/ca-root.">' + icon('alert') + 'Legacy transport</span>';
  if (activeJob) h += ' <span class="agt-flag agt-flag-info" title="Attack-path collection: ' + x(activeJob.status) + '">AP</span>';
  return h;
}
