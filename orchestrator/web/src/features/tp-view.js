// Threat Prioritization page: tier tiles, the actor table with the design demo's table chrome (filter, count,
// columns, page size, CSV, selection, sortable headers, pager), the three actor charts and the detail
// drawer. The toolbar is built once per load so typing in the filter keeps focus. Pure helpers live in tp-model.js.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { grid, card, chip, bar, hbars, seg, empty, kv, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import { showTab } from './shell.js';
import { tpFactorsHtml, tpHistoryHtml } from './rich-g4.js';
import * as M from './tp-model.js';

var ACTORS = [];
var TIER = 'all';
var LIGHT = false;
var T = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} };
var TITLE = 'Actor priority';
var SEQ = 0;

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function keyOf(a) { return String(a.actorName || ''); }

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function baseList() { return M.filterTier(ACTORS, TIER); }
function currentList() { return M.sortRows(M.filterRows(baseList(), T.q), T.col, T.dir); }

function tierOpts() {
  var opts = [{ id: 'all', label: 'All', count: ACTORS.length }];
  M.TIERS.forEach(function(t) {
    opts.push({ id: t, label: t, count: ACTORS.filter(function(a) { return M.tierOf(a) === t; }).length });
  });
  return opts;
}

function skeletonHtml() {
  var chips = '<div class="tp-chips" id="tp-seg"></div>';
  var table = '<div class="tbl-wrap' + (LIGHT ? '' : ' dt-scroll') + '" id="tp-table-wrap"><table><thead id="tp-thead"></thead><tbody id="tp-table-body"></tbody></table></div>';
  if (LIGHT) return card(TITLE, chips + table + '<div class="dt-empty" id="tp-empty" hidden></div>', { flush: true, cls: 'runs-card tp-card tp-light' });
  return card(TITLE,
    chips +
    '<div class="runs-dt">' +
    '<div class="dt-toolbar" id="tp-dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="tp-search" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'onThreatPrioritySearch') + '></label>' +
      '<span class="dt-count muted" id="tp-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleTpCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="tp-cols" hidden></div></div>' +
      '<select id="tp-dt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'setTpPer') + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportTpCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="tp-bulk" hidden><b id="tp-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportTpSelected') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearTpSelection') + '>Clear selection</button></div>' +
    table +
    '<div class="dt-empty" id="tp-empty" hidden></div>' +
    '<div class="dt-foot" id="tp-dt-foot"><span class="dt-range muted" id="tp-dt-range"></span><div class="dt-pager" id="tp-dt-pager"></div></div>' +
    '</div>', { flush: true, cls: 'runs-card tp-card' });
}

function trendCell(a) {
  var t = M.trendInfo(a);
  return '<span class="tp-tr tp-tr-' + t.cls + '">' + x(t.text) + '</span>';
}

function cellHtml(col, a, nums) {
  var tier = M.tierOf(a);
  var num = nums[col] ? ' num' : '';
  switch (col) {
    case 0: return '<td><div class="tp-actor"><span class="ta-av sm' + (tier === 'High' || tier === 'Critical' ? ' hi' : '') + '">' + x(M.initials(a.actorName)) + '</span><b>' + x(a.actorName) + '</b></div></td>';
    case 1: return '<td>' + chip(tier, M.tierTone(tier)) + '</td>';
    case 2: return '<td class="tp-scorecell' + num + '"><div class="tp-score"><div class="grow">' + bar(Math.max(0, Math.min(100, Number(a.score) || 0)), M.barTone(tier)) + '</div><span class="mono muted">' + x(Number(a.score) || 0) + '</span></div></td>';
    case 3: return '<td class="' + num.trim() + '">' + trendCell(a) + '</td>';
    default: return '<td><span class="tp-gap">' + x(Number(a.coverageGapCount) || 0) + '</span><span class="muted"> of ' + x(Number(a.techniqueCount) || 0) + ' techniques</span></td>';
  }
}

function paintTable() {
  var tbody = document.getElementById('tp-table-body');
  if (!tbody) return;
  var segEl = document.getElementById('tp-seg');
  if (segEl) segEl.innerHTML = seg(tierOpts(), TIER, 'setThreatPriorityTier');
  var list = currentList();
  var per = LIGHT ? 9999 : T.per;
  var pages = M.pageCount(list.length, per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * per;
  var rows = list.slice(start, start + per);
  var cols = LIGHT ? M.COLUMNS.map(function(c, i) { return i; }) : visibleCols();
  var nums = M.numericCols(ACTORS);
  var onList = list.filter(function(a) { return T.sel[keyOf(a)]; }).length;
  document.getElementById('tp-thead').innerHTML = '<tr>' +
    (LIGHT ? '' : '<th class="dt-selcol"><input type="checkbox" class="dt-cb" id="tp-sel-all" title="Select all on this table"' + on('change', 'tpSelectAll') + '></th>') +
    cols.map(function(c) {
      return '<th class="dt-th' + (nums[c] ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'tpSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '</tr>';
  var all = document.getElementById('tp-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(a) {
    var k = keyOf(a);
    return '<tr class="tp-row dt-click" tabindex="0"' + on('click', 'showThreatPriorityDetail', k) + on('keydown', 'tpRowKeydown', k) + '>' +
      (LIGHT ? '' : '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select actor"' + (T.sel[k] ? ' checked' : '') + on('change', 'tpSelectRow', k) + '></td>') +
      cols.map(function(c) { return cellHtml(c, a, nums); }).join('') + '</tr>';
  }).join('');
  var menu = document.getElementById('tp-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'tpColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('tp-bulk', selN === 0);
  setText('tp-bulk-n', String(selN));
  setText('tp-count', M.rangeCounts(list.length, ACTORS.length));
  setText('tp-dt-range', M.rangeText(list.length, T.page, per));
  var pager = document.getElementById('tp-dt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'tpPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'tpPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('tp-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) {
      emp.innerHTML = TIER !== 'all' && !T.q
        ? empty('search', 'No actors in this tier', 'Pick another tier to see its actors.')
        : empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + (LIGHT ? '' : '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'clearTpTableQuery') + '>Clear filter</button></div>');
    }
  }
  setHidden('tp-table-wrap', !list.length);
  setHidden('tp-dt-foot', !list.length);
}

function renderHero() {
  var h = M.heroStats(ACTORS);
  setHeroStat('tp-hs-actors', h.actors);
  setHeroStat('tp-hs-high', h.high);
  setHeroStat('tp-hs-techniques', h.techniques);
  setHeroStat('tp-hs-gaps', h.gaps);
}

// Tier tiles: tinted icon square on the left, uppercase label, value, one-line caption, coloured top border.
function tilesHtml() {
  var tiles = M.tierTiles(ACTORS);
  return '<div class="tp-tiles tp-tiles-' + tiles.length + '">' + tiles.map(function(t) {
    return '<div class="tp-tile tp-c-' + t.tone + '"><span class="tp-ico">' + icon(t.icon) + '</span><div class="tp-tb"><div class="tp-lbl">' + x(t.label) + '</div>' +
      '<div class="tp-val">' + x(t.value) + '</div><div class="tp-cap">' + x(t.caption) + '</div></div></div>';
  }).join('') + '</div>';
}

// The three actor charts under the table; a chart with nothing behind it says so.
function chartsHtml() {
  if (!ACTORS.length) return '';
  var segs = M.TIERS.map(function(t) {
    return { label: t, value: ACTORS.filter(function(a) { return M.tierOf(a) === t; }).length, color: CHART_COLORS[M.tierTone(t)] };
  });
  var top = ACTORS.slice().sort(function(a, b) { return (Number(b.score) || 0) - (Number(a.score) || 0); }).slice(0, 7);
  var widest = ACTORS.filter(function(a) { return Number(a.coverageGapCount) > 0; })
    .sort(function(a, b) { return Number(b.coverageGapCount) - Number(a.coverageGapCount); }).slice(0, 7);
  return '<div class="tp-charts">' + grid(3, [
    card('Actors by tier', chartSlot({ type: 'donut', segments: segs, center: ACTORS.length, centerSub: 'actors', h: 150 })),
    card('Top actors by score', hbars(top.map(function(a) { return [a.actorName, Number(a.score) || 0, M.tierTone(M.tierOf(a)), String(Number(a.score) || 0)]; })), { sub: 'most relevant first' }),
    card('Largest coverage gaps', widest.length
      ? hbars(widest.map(function(a) { var t = Number(a.techniqueCount) || 0, g = Number(a.coverageGapCount) || 0; return [a.actorName, t ? Math.round(g / t * 100) : 0, 'warn', g + ' of ' + t]; }))
      : empty('', 'No coverage gaps', 'Every tracked technique is validated.'), { sub: 'unvalidated techniques' }),
  ]) + '</div>';
}

export function loadThreatPriorityActors() {
  var main = document.getElementById('tp-main');
  var sum = document.getElementById('tp-summary');
  var charts = document.getElementById('tp-charts');
  if (main) main.innerHTML = card(TITLE, '<div class="empty">Loading…</div>', { flush: true });
  if (sum) sum.innerHTML = '';
  if (charts) charts.innerHTML = '';
  return apicall('/api/threat-priority/actors').then(function(actors) {
    ACTORS = actors || [];
    T.sel = {}; T.page = 0;
    renderHero();
    if (!ACTORS.length) {
      if (main) main.innerHTML = card(TITLE, empty('flag', 'No threat actors tracked yet', 'Configure a threat-intel connector to populate this view.'));
      return;
    }
    LIGHT = M.useLight(ACTORS.length);
    if (sum) sum.innerHTML = tilesHtml();
    if (main) main.innerHTML = skeletonHtml();
    var q = document.getElementById('tp-search'); if (q) q.value = T.q;
    var per = document.getElementById('tp-dt-per'); if (per) per.value = String(T.per);
    paintTable();
    if (charts) charts.innerHTML = chartsHtml();
  }).catch(function(e) {
    ACTORS = [];
    renderHero();
    if (main) main.innerHTML = card(TITLE, '<div class="empty u-danger">Failed to load: ' + x(e.message) + '</div>');
  });
}

// ── Table controls ──
export function setThreatPriorityTier(id) { TIER = id; T.page = 0; paintTable(); }
export function onThreatPrioritySearch(el) { T.q = String((el && el.value) || ''); T.page = 0; paintTable(); }
export function clearTpTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('tp-search'); if (q) q.value = ''; paintTable(); }
export function setTpPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paintTable(); }
export function tpPage(d) { T.page += Number(d) || 0; paintTable(); }
export function tpSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function toggleTpCols() { var m = document.getElementById('tp-cols'); if (m) m.hidden = !m.hidden; }
export function tpColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function tpSelectRow(k, el) { if (el && el.checked) T.sel[k] = true; else delete T.sel[k]; paintTable(); }
export function tpSelectAll(el) {
  currentList().forEach(function(a) { if (el && el.checked) T.sel[keyOf(a)] = true; else delete T.sel[keyOf(a)]; });
  paintTable();
}
export function clearTpSelection() { T.sel = {}; paintTable(); }
export function tpRowKeydown(k, el, event) {
  if (event && (event.key === 'Enter' || event.key === ' ') && event.target === el) { event.preventDefault(); showThreatPriorityDetail(k); }
}

function exportTp(onlySelected) {
  var rows = onlySelected ? ACTORS.filter(function(a) { return T.sel[keyOf(a)]; }) : currentList();
  var cols = LIGHT ? M.COLUMNS.map(function(c, i) { return i; }) : visibleCols();
  var csv = M.csvText(M.csvHeader(cols), M.csvRows(rows, cols));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'threat-prioritization.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportTpCsv() { exportTp(false); }
export function exportTpSelected() { exportTp(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('tp-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});

// ── Detail drawer ──
function section(title, body) { return '<h4 class="sc-h4">' + x(title) + '</h4>' + body; }
function emptyNote(t) { return '<div class="tiny muted">' + x(t) + '</div>'; }
function tags(list) { return '<div class="tp-tags">' + list.map(function(t) { return '<span class="tool-tag">' + x(t) + '</span>'; }).join(' ') + '</div>'; }

function sourcesHtml(sources) {
  if (!sources.length) return emptyNote('No per-source records yet — populated by the next threat-intel sync.');
  // "Unknown" (never "None"): an empty field means this source never supplied it, e.g. OpenCTI never reports
  // sectors/regions. Rendering it as "None" would read as a positive assertion the source never made.
  var unknown = '<span class="muted">Unknown</span>';
  function list(arr) { return (arr && arr.length) ? arr.map(function(v) { return '<span class="tool-tag">' + x(v) + '</span>'; }).join(' ') : unknown; }
  function row(label, val) { return '<div class="tp-src-row"><span class="tp-src-k">' + label + '</span><span class="grow">' + val + '</span></div>'; }
  return '<div class="tp-src-grid">' + sources.map(function(s) {
    return '<div class="tp-src"><div class="tp-src-h">' + x(s.source) + '</div>' +
      row('Name', x(s.name)) + row('Aliases', list(s.aliases)) + row('Sectors', list(s.sectors)) + row('Regions', list(s.regions)) +
      row('Confidence', s.confidence ? x(s.confidence) : unknown) + row('Techniques', x(s.techniqueCount)) +
      row('Last seen', s.lastSeen ? x(fmtDate(s.lastSeen)) : unknown) + '</div>';
  }).join('') + '</div>';
}

function coverageHtml(list) {
  if (!list.length) return emptyNote('No technique data.');
  var dash = '<span class="muted">&mdash;</span>';
  return '<div class="tbl-wrap"><table><thead><tr><th>Technique</th><th>Content</th><th>Prevention</th><th>Detection</th></tr></thead><tbody>' +
    list.map(function(tc) {
      var content = [
        tc.hasSimulation ? '<span class="tool-tag">Sim</span>' : '',
        tc.hasDetection ? '<span class="tool-tag">Detect</span>' : '',
        tc.hasCompliance ? '<span class="tool-tag">Compliance</span>' : '',
      ].filter(Boolean).join(' ') || dash;
      var label = tc.techniqueName ? tc.techniqueName + ' (' + tc.techniqueId + ')' : tc.techniqueId;
      return '<tr><td>' + x(label) + '</td><td>' + content + '</td><td>' + (tc.preventionVerdict ? x(tc.preventionVerdict) : dash) + '</td><td>' + (tc.detectionVerdict ? x(tc.detectionVerdict) : dash) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

function evidenceHtml(list) {
  return '<div class="tbl-wrap"><table><thead><tr><th>Technique</th><th>Via</th><th>Confidence</th><th>Since</th></tr></thead><tbody>' +
    list.map(function(e) {
      var via = e.via ? x(e.via + (e.viaName ? ' (' + e.viaName + ')' : '')) : '<span class="muted">direct</span>';
      var since = e.startTime ? x(fmtDate(e.startTime)) : '<span class="muted">&mdash;</span>';
      return '<tr><td>' + x(e.techniqueId) + '</td><td>' + via + '</td><td>' + x(e.confidence) + '%</td><td>' + since + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

function renderDetail(d) {
  setText('tp-detail-title', d.actorName);
  setText('tp-detail-sub', M.drawerSub(d));
  var h = '<div class="tp-dr-chips">' + M.chipRows(d).map(function(c) { return chip(c[0], c[1]); }).join('') + '</div>' + kv(M.factRows(d));
  h += section('Why this score', tpFactorsHtml(d.factors));
  var unc = d.uncoveredTechniques || [];
  h += section('Uncovered techniques', unc.length ? tags(unc) : emptyNote('No coverage gaps.'));
  h += section('Technique coverage breakdown', coverageHtml(d.techniqueCoverage || []));
  h += section('Sources', sourcesHtml(d.sources || []));
  var ev = d.techniqueEvidence || [];
  if (ev.length) h += section('Technique evidence', evidenceHtml(ev));
  h += section('History', tpHistoryHtml(d.history));
  h += section('Recommendations for this actor', '<div id="tp-detail-recs" class="tiny"><span class="muted">Loading…</span></div>');
  h += section('Related', '<div class="sc-rel-list">' + M.related().map(function(r) {
    return '<div class="sc-rel" tabindex="0" role="button"' + on('click', 'tpGo', r.tab) + '>' + icon(r.icon) +
      '<div class="grow"><b>' + x(r.label) + '</b><em>' + x(r.sub) + '</em></div>' + icon('chevron') + '</div>';
  }).join('') + '</div>');
  document.getElementById('tp-detail-body').innerHTML = h;

  var techSet = {};
  (d.techniqueIds || []).forEach(function(t) { techSet[t] = true; });
  var seq = SEQ;
  apicall('/api/recommend/simulations?limit=100').then(function(recData) {
    var el = document.getElementById('tp-detail-recs');
    if (!el || seq !== SEQ) return;
    var matches = ((recData && recData.techniques) || []).filter(function(t) { return techSet[t.techniqueId]; });
    el.innerHTML = matches.length
      ? matches.map(function(t) { return '<div class="tp-rec">' + x(t.techniqueId) + ' — ' + x(t.name) + ' <span class="tiny muted">(score ' + x(t.score) + ')</span></div>'; }).join('')
      : '<span class="muted">No open recommendations for this actor\'s techniques.</span>';
  }).catch(function() {
    var el = document.getElementById('tp-detail-recs');
    if (el && seq === SEQ) el.innerHTML = '<span class="muted">Could not load recommendations.</span>';
  });
}

export function showThreatPriorityDetail(actorName) {
  var seq = ++SEQ;
  var row = ACTORS.filter(function(a) { return keyOf(a) === actorName; })[0];
  setText('tp-detail-title', actorName);
  setText('tp-detail-sub', row ? M.drawerSub(row) : 'Threat actor');
  var body = document.getElementById('tp-detail-body');
  body.innerHTML = '<div class="empty">Loading…</div>';
  document.getElementById('tp-detail-overlay').classList.add('open');
  apicall('/api/threat-priority/actors/' + encodeURIComponent(actorName)).then(function(d) {
    if (seq !== SEQ) return;
    renderDetail(d);
  }).catch(function(e) {
    if (seq !== SEQ) return;
    body.innerHTML = '<div class="empty u-danger">Failed to load: ' + x(e.message) + '</div>';
  });
}

export function closeThreatPriorityDetail() {
  SEQ++;
  var o = document.getElementById('tp-detail-overlay');
  if (o) o.classList.remove('open');
}
export function closeThreatPriorityDetailOnBackdrop(el, event) { if (event.target === el) closeThreatPriorityDetail(); }
// The list is always on screen behind the drawer; "back to the list" just closes it.
export function showThreatPriorityList() { closeThreatPriorityDetail(); }
// Jump links from the drawer: close it first so the target page is visible.
export function tpGo(tab) { closeThreatPriorityDetail(); showTab(tab); }
