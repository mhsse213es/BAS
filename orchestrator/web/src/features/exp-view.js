// Exposure Explorer page: the per-asset table with the design demo's table chrome (filter, count,
// columns, page size, CSV, selection, sortable headers, pager), the two host charts and the detail drawer.
// The toolbar is built once per load so typing in the filter keeps focus. Pure helpers live in exp-model.js.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { grid, card, chip, bar, hbars, seg, empty, kv, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import { showTab } from './shell.js';
import { expFilterAssets, expFilterOpts, expScoreTiles, sevChip } from './rich-g4.js';
import * as M from './exp-model.js';

var ASSETS = [];
var FILTER = 'all';
var T = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} };
var TITLE = 'Per-asset exposure score';
var NOTE = 'Attack-path exposure, detection coverage, CVE / KEV / EPSS risk and findings — one composite score per host';

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function keyOf(a) { return String((a.asset && a.asset.hostKey) || ''); }
function noteHtml() { return '<span class="muted exp-note">' + x(NOTE) + '</span>'; }

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function baseList() { return expFilterAssets(ASSETS, FILTER, ''); }
function currentList() { return M.sortRows(M.filterRows(baseList(), T.q), T.col, T.dir); }

function skeletonHtml() {
  return card(TITLE,
    '<div class="exp-chips" id="exp-seg"></div>' +
    '<div class="runs-dt">' +
    '<div class="dt-toolbar" id="exp-dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="exp-search" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'onExposureSearch') + '></label>' +
      '<span class="dt-count muted" id="exp-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleExpCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="exp-cols" hidden></div></div>' +
      '<select id="exp-dt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'setExpPer') + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportExpCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="exp-bulk" hidden><b id="exp-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportExpSelected') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearExpSelection') + '>Clear selection</button></div>' +
    '<div class="tbl-wrap dt-scroll" id="exp-table-wrap"><table><thead id="exp-thead"></thead><tbody id="exp-table-body"></tbody></table></div>' +
    '<div class="dt-empty" id="exp-empty" hidden></div>' +
    '<div class="dt-foot" id="exp-dt-foot"><span class="dt-range muted" id="exp-dt-range"></span><div class="dt-pager" id="exp-dt-pager"></div></div>' +
    '</div>', { flush: true, cls: 'runs-card exp-card', actions: noteHtml() });
}

function cellHtml(col, a) {
  var as = a.asset || {};
  switch (col) {
    case 0: return '<td><b>' + x(as.label || as.hostKey) + '</b></td>';
    case 1: return '<td>' + (as.managed ? chip('Managed', 'ok') : chip('Discovered', 'muted')) + '</td>';
    case 2: return '<td class="exp-progcell">' + (isFinite(Number(a.exposureScore)) && a.exposureScore != null
      ? '<div class="exp-prog"><div class="grow">' + bar(a.exposureScore, M.scoreTone(a.exposureScore)) + '</div><span class="mono muted">' + x(a.exposureScore) + '%</span></div>'
      : '<span class="muted">—</span>') + '</td>';
    case 3: return '<td class="num">' + x(M.cellText(a, 3) || '—') + '</td>';
    case 4: return '<td class="num">' + x(M.cellText(a, 4) || '—') + '</td>';
    case 5: return '<td>' + (as.crownJewel ? chip(as.crownJewel, 'violet') : '<span class="muted">—</span>') + '</td>';
    case 6: return '<td class="num">' + x(M.cellText(a, 6)) + '</td>';
    default: return '<td>' + (a.kevExposed ? chip('KEV', 'bad') : '<span class="muted">—</span>') + '</td>';
  }
}

function paintTable() {
  var tbody = document.getElementById('exp-table-body');
  if (!tbody) return;
  var segEl = document.getElementById('exp-seg');
  if (segEl) segEl.innerHTML = seg(expFilterOpts(ASSETS), FILTER, 'setExposureFilter');
  var list = currentList();
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var onList = list.filter(function(a) { return T.sel[keyOf(a)]; }).length;
  document.getElementById('exp-thead').innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="exp-sel-all" title="Select all on this table"' + on('change', 'expSelectAll') + '></th>' +
    cols.map(function(c) {
      return '<th class="dt-th' + (M.NUM_COLS[c] ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'expSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '</tr>';
  var all = document.getElementById('exp-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(a) {
    var k = keyOf(a);
    return '<tr class="exp-row dt-click" tabindex="0"' + on('click', 'openExposureDetail', k) + on('keydown', 'expRowKeydown', k) + '>' +
      '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select asset"' + (T.sel[k] ? ' checked' : '') + on('change', 'expSelectRow', k) + '></td>' +
      cols.map(function(c) { return cellHtml(c, a); }).join('') + '</tr>';
  }).join('');
  var menu = document.getElementById('exp-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'expColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('exp-bulk', selN === 0);
  setText('exp-bulk-n', String(selN));
  setText('exp-count', M.rangeCounts(list.length, ASSETS.length));
  setText('exp-dt-range', M.rangeText(list.length, T.page, T.per));
  var pager = document.getElementById('exp-dt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'expPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'expPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('exp-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'clearExpTableQuery') + '>Clear filter</button></div>';
  }
  setHidden('exp-table-wrap', !list.length);
  setHidden('exp-dt-foot', !list.length);
}

function renderHero() {
  var h = M.heroStats(ASSETS);
  setHeroStat('exp-hs-assets', h.assets);
  setHeroStat('exp-hs-internet', h.internet);
  setHeroStat('exp-hs-kev', h.kev);
  setHeroStat('exp-hs-findings', h.findings);
}

// The two host charts under the table; a chart with nothing behind it says so.
function chartsHtml() {
  if (!ASSETS.length) return '';
  var hb = M.hostBars(ASSETS);
  var fr = M.findingsRows(ASSETS);
  return '<div class="exp-charts">' + grid(2, [
    card('Exposure by host', hb.labels.length
      ? chartSlot({ type: 'bar', labels: hb.labels, h: 200, series: [{ name: 'Exposure', color: CHART_COLORS.warn, data: hb.data }] })
      : empty('', 'No data yet'), { sub: hb.sub }),
    card('Open findings by host', fr.length ? hbars(fr) : empty('', 'No open findings', 'No host has an open finding right now.')),
  ]) + '</div>';
}

export function loadExposureAssets() {
  var main = document.getElementById('exp-main');
  var sum = document.getElementById('exp-summary');
  if (main) main.innerHTML = card(TITLE, '<div class="empty">Loading…</div>', { flush: true, actions: noteHtml() });
  if (sum) sum.innerHTML = '';
  apicall('/api/exposure/assets').then(function(assets) {
    ASSETS = assets || [];
    T.sel = {}; T.page = 0;
    renderHero();
    if (!ASSETS.length) {
      if (main) main.innerHTML = card(TITLE, empty('path', 'No assets found', 'Enroll an agent or run attack-path collection.'), { actions: noteHtml() });
      return;
    }
    if (main) main.innerHTML = skeletonHtml();
    var q = document.getElementById('exp-search'); if (q) q.value = T.q;
    var per = document.getElementById('exp-dt-per'); if (per) per.value = String(T.per);
    paintTable();
    if (sum) sum.innerHTML = chartsHtml();
  }).catch(function(e) {
    ASSETS = [];
    renderHero();
    if (main) main.innerHTML = card(TITLE, '<div class="empty u-danger">Failed to load: ' + x(e.message) + '</div>', { actions: noteHtml() });
  });
}

// ── Table controls ──
export function setExposureFilter(id) { FILTER = id; T.page = 0; paintTable(); }
export function onExposureSearch(el) { T.q = String((el && el.value) || ''); T.page = 0; paintTable(); }
export function clearExpTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('exp-search'); if (q) q.value = ''; paintTable(); }
export function setExpPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paintTable(); }
export function expPage(d) { T.page += Number(d) || 0; paintTable(); }
export function expSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function toggleExpCols() { var m = document.getElementById('exp-cols'); if (m) m.hidden = !m.hidden; }
export function expColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function expSelectRow(k, el) { if (el && el.checked) T.sel[k] = true; else delete T.sel[k]; paintTable(); }
export function expSelectAll(el) {
  currentList().forEach(function(a) { if (el && el.checked) T.sel[keyOf(a)] = true; else delete T.sel[keyOf(a)]; });
  paintTable();
}
export function clearExpSelection() { T.sel = {}; paintTable(); }
export function expRowKeydown(k, el, event) {
  if (event && (event.key === 'Enter' || event.key === ' ') && event.target === el) { event.preventDefault(); openExposureDetail(k); }
}

function exportExp(onlySelected) {
  var rows = onlySelected ? ASSETS.filter(function(a) { return T.sel[keyOf(a)]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(M.csvHeader(cols), M.csvRows(rows, cols));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'exposure-assets.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportExpCsv() { exportExp(false); }
export function exportExpSelected() { exportExp(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('exp-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});

// ── Detail drawer ──
function section(title, body) { return '<h4 class="sc-h4">' + x(title) + '</h4>' + body; }
function emptyNote(t) { return '<div class="tiny muted">' + x(t) + '</div>'; }

export function openExposureDetail(hostKey) {
  var row = ASSETS.filter(function(a) { return keyOf(a) === hostKey; })[0];
  setText('exp-detail-title', (row && row.asset && row.asset.label) || hostKey);
  setText('exp-detail-sub', row ? M.drawerSub(row.asset) : '');
  var body = document.getElementById('exp-detail-body');
  body.innerHTML = '<div class="empty">Loading…</div>';
  document.getElementById('exposure-detail-overlay').classList.add('open');
  apicall('/api/exposure/assets/' + encodeURIComponent(hostKey)).then(function(p) {
    setText('exp-detail-title', (p.asset && p.asset.label) || hostKey);
    setText('exp-detail-sub', M.drawerSub(p.asset));
    var h = '<div class="exp-dr-chips">' + M.chipRows(p.asset).map(function(c) { return chip(c[0], c[1]); }).join('') + '</div>';
    var facts = M.factRows(p);
    if (facts.length) h += kv(facts);

    var vulns = emptyNote('No mapped CVEs.');
    if (p.vulnerabilities && p.vulnerabilities.length) {
      vulns = '<div class="tbl-wrap"><table><thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>Technique</th></tr></thead><tbody>' +
        p.vulnerabilities.map(function(v) {
          return '<tr><td class="mono">' + x(v.cveId) + '</td><td>' + x(v.cvss || '—') + '</td><td>' + (v.kev ? chip('KEV', 'bad') : '') + '</td>' +
            '<td>' + x(v.epssScore || '—') + '</td><td>' + x(v.techniqueId) + '</td></tr>';
        }).join('') + '</tbody></table></div>';
    }
    h += section('Vulnerabilities', vulns);

    // Each score is a pure-deficit value (100 - risk), so an asset with nothing collected would read as a
    // flawless 100; the tiles show "no data" when the backend says it was not measurable.
    h += section('Scores', expScoreTiles(p.scores));

    var recs = emptyNote('No gaps on this asset’s attack paths.');
    if (p.recommendations && p.recommendations.length) {
      recs = '<div class="tbl-wrap"><table><thead><tr><th>From</th><th>Via</th><th>To</th><th>Priority</th><th>Reason</th></tr></thead><tbody>' +
        p.recommendations.map(function(g) {
          return '<tr><td>' + x(g.edge.from) + '</td><td>' + chip(g.edge.kind, 'info') + '</td><td>' + x(g.edge.to) + '</td>' +
            '<td>' + sevChip(g.priority) + '</td><td class="tiny muted">' + x(g.reason) + '</td></tr>';
        }).join('') + '</tbody></table></div>';
    }
    h += section('Prioritized recommendations', recs);

    var finds;
    if (!p.findings || !p.findings.collected) {
      finds = emptyNote('Not enrolled — no scan history.');
    } else if (p.findings.findings && p.findings.findings.length) {
      finds = '<div class="tbl-wrap"><table><thead><tr><th>Technique</th><th>Severity</th><th>State</th></tr></thead><tbody>' +
        p.findings.findings.map(function(f) {
          return '<tr><td>' + x(f.techniqueName || f.techniqueId) + '</td><td>' + sevChip(f.severity) + '</td><td>' + x(f.exposureState) + '</td></tr>';
        }).join('') + '</tbody></table></div>';
    } else {
      finds = emptyNote('No open findings.');
    }
    h += section('Findings', finds);

    h += section('Threat groups', (p.threatIntel && p.threatIntel.length)
      ? '<div class="g4-chips">' + p.threatIntel.map(function(g) { return chip(g.groupName, 'info'); }).join('') + '</div>'
      : emptyNote('No attributed threat groups.'));

    h += section('Related', '<div class="sc-rel-list">' + M.related().map(function(r) {
      return '<div class="sc-rel" tabindex="0" role="button"' + on('click', 'expGo', r.tab) + '>' + icon(r.icon) +
        '<div class="grow"><b>' + x(r.label) + '</b><em>' + x(r.sub) + '</em></div>' + icon('chevron') + '</div>';
    }).join('') + '</div>');

    body.innerHTML = h;
  }).catch(function(e) {
    body.innerHTML = '<div class="empty u-danger">Failed to load: ' + x(e.message) + '</div>';
  });
}

export function closeExposureDetail() {
  document.getElementById('exposure-detail-overlay').classList.remove('open');
}
export function closeExposureDetailOnBackdrop(el, event) { if (event.target === el) closeExposureDetail(); }
// Jump links from the drawer: close it first so the target page is visible.
export function expGo(tab) { closeExposureDetail(); showTab(tab); }
