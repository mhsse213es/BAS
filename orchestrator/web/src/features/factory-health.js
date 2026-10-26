import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { grid, card, pill, empty, kv, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { ring } from './runs-drawer.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './fh-model.js';

var minTrendPoints = 3;
var _sources = [];
var T = { q: '', col: -1, dir: 1, page: 0, per: 8, sel: {}, hidden: {} };

export function loadFactoryHealth() {
  apicall('/api/analytics/factory-health').then(function(r) {
    if (!r || !r.threatsProcessed || !r.pipeline) {
      var t = document.getElementById('factory-health-tiles');
      if (t) t.innerHTML = empty('factory', 'Factory health is not available right now');
      return;
    }
    renderFactoryHealthHero(r);
    renderFactoryHealthTiles(r);
    renderFactoryHealthIngestion(r);
    renderFactoryHealthFunnel(r);
    renderFactoryHealthTrends(r);
  });
}

// A tile in the demo's style: tinted icon square on the left, small label, big value, one-line caption.
function tileHtml(o) {
  return '<div class="fh-tile fh-c-' + o.tone + '"><span class="fh-ico">' + icon(o.icon) + '</span><div class="fh-tb"><div class="fh-lbl">' + x(o.label) + '</div>' +
    '<div class="fh-val">' + x(o.value) + '</div>' + (o.caption ? '<div class="fh-cap">' + x(o.caption) + '</div>' : '') + '</div></div>';
}

export function metricTile(label, metric, formatter, ic, o) {
  o = o || {};
  if (metric.state === 'no_data') {
    return tileHtml({ label: label, value: 'NO DATA', caption: metric.reason || 'No data yet', icon: ic, tone: 'muted' });
  }
  return tileHtml({ label: label, value: formatter(metric.value), caption: o.caption, icon: ic, tone: o.tone || 'accent' });
}

function formatCount(v) { return String(v); }
function formatDuration(seconds) { return (seconds / 86400).toFixed(1) + 'd'; }
function formatPercent(fraction) { return (fraction * 100).toFixed(0) + '%'; }

// coverageTile: the Source -> Technique coverage as a progress ring (a no-data metric stays a plain NO DATA tile).
function coverageTile(metric, unresolved) {
  var label = 'Source → technique coverage';
  if (metric.state === 'no_data') return metricTile(label, metric, formatPercent, 'mapped');
  return '<div class="fh-tile fh-c-ok fh-ringtile">' + ring(Math.round(metric.value * 100), 'ok') + '<div class="fh-tb"><div class="fh-lbl">' + x(label) + '</div>' +
    '<div class="fh-cap">' + x(unresolved) + ' unresolved actor candidate(s)</div></div></div>';
}

function renderFactoryHealthHero(r) {
  var h = M.heroStats(r);
  var dash = function(v) { return v == null ? '—' : v; };
  setHeroStat('fh-hs-threats', dash(h.threats));
  setHeroStat('fh-hs-published', dash(h.published));
  setHeroStat('fh-hs-sources', dash(h.sources));
  setHeroStat('fh-hs-unresolved', dash(h.unresolved));
}

function renderFactoryHealthTiles(r) {
  var el = document.getElementById('factory-health-tiles');
  if (!el) return;
  var unresolved = (r.pipeline && r.pipeline.ingestion && r.pipeline.ingestion.unresolvedCandidates) || 0;
  var now = Date.now();
  el.innerHTML = grid(3, [
    metricTile('Threats processed', r.threatsProcessed, formatCount, 'layers', { tone: 'accent', caption: M.tileCaption('threats', r, now) }),
    metricTile('Published content', r.publishedContent, formatCount, 'check', { tone: 'ok', caption: M.tileCaption('published', r, now) }),
    metricTile('Median threat → content', r.medianThreatToContentTcv, formatDuration, 'clock', { tone: 'cyan', caption: M.tileCaption('tcv', r, now) }),
    metricTile('Static validation pass rate', r.staticValidationPassRate, formatPercent, 'shield', { tone: 'ok', caption: M.tileCaption('validation', r, now) }),
    metricTile('Duplicate generation rate', r.duplicateGenerationRate, formatPercent, 'refresh', { tone: 'muted' }),
    coverageTile(r.sourceToTechniqueCoverage, unresolved),
  ]);
}

// renderFactoryHealthIngestion lists per-source sync health so a viewer can
// see WHY the other metrics might be stale or missing. A source that has
// never synced successfully is labeled "never synced", never shown as an
// empty/blank timestamp -- distinct from a source that is merely stale.
// The table follows the design demo's table chrome (filter, count, columns, page size, CSV,
// selection, sortable headers, pager); the toolbar is built once per load so typing keeps focus.
function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }

function skeletonHtml(c) {
  var sub = c.healthy + ' healthy' + (c.failing ? ' · ' + c.failing + ' failing' : '') + (c.never ? ' · ' + c.never + ' never synced' : '');
  return '<h4 class="sec-label">Source ingestion <span class="muted">· ' + x(c.total + (c.total === 1 ? ' source' : ' sources') + ' · ' + sub) + '</span></h4>' +
    '<div class="rk-card runs-card fh-card"><div class="runs-dt">' +
    '<div class="dt-toolbar" id="fh-dt-toolbar">' +
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="fh-dt-q" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'fhTableQuery') + '></label>' +
      '<span class="dt-count muted" id="fh-dt-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleFhCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="fh-cols" hidden></div></div>' +
      '<select id="fh-dt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'setFhPer') + '><option value="5">5 / page</option><option value="8" selected>8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportFhCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="fh-bulk" hidden><b id="fh-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportFhSelected') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearFhSelection') + '>Clear selection</button></div>' +
    '<div class="tbl-wrap dt-scroll" id="fh-table-wrap"><table><thead id="fh-thead"></thead><tbody id="fh-body"></tbody></table></div>' +
    '<div class="dt-empty" id="fh-empty" hidden></div>' +
    '<div class="dt-foot" id="fh-dt-foot"><span class="dt-range muted" id="fh-dt-range"></span><div class="dt-pager" id="fh-dt-pager"></div></div>' +
    '</div></div>';
}

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function currentList() { return M.sortSources(M.filterSources(_sources, T.q), T.col, T.dir); }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }

function cellHtml(col, s) {
  switch (col) {
    case 0: return '<td><b>' + x(s.name) + '</b>' + (s.id && s.id !== s.name ? '<div class="mono muted fh-id">' + x(s.id) + '</div>' : '') + '</td>';
    case 1: return '<td>' + pill(s.state.label, s.state.tone) + '</td>';
    case 2: return '<td class="muted">' + x(s.lastSuccessAt ? fmtDate(s.lastSuccessAt) : 'never synced') + '</td>';
    case 3: return '<td class="num">' + x(s.failures) + '</td>';
    default: return '<td class="muted fh-diag">' + x(s.diagnostic || '—') + '</td>';
  }
}

function paintTable() {
  var tbody = document.getElementById('fh-body');
  if (!tbody) return;
  var list = currentList();
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var idx = function(s) { return _sources.indexOf(s); };
  var onList = list.filter(function(s) { return T.sel[idx(s)]; }).length;
  document.getElementById('fh-thead').innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="fh-sel-all" title="Select all on this table"' + on('change', 'fhSelectAll') + '></th>' +
    cols.map(function(c) {
      return '<th class="dt-th' + (c === 3 ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'fhSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '</tr>';
  var all = document.getElementById('fh-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(s) {
    var i = idx(s);
    return '<tr class="fh-row dt-click" tabindex="0"' + on('click', 'openFactorySource', i) + on('keydown', 'fhRowKeydown', i) + '>' +
      '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select source"' + (T.sel[i] ? ' checked' : '') + on('change', 'fhSelectRow', i) + '></td>' +
      cols.map(function(c) { return cellHtml(c, s); }).join('') + '</tr>';
  }).join('');
  var menu = document.getElementById('fh-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'fhColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('fh-bulk', selN === 0);
  setText('fh-bulk-n', String(selN));
  setText('fh-dt-count', list.length + ' of ' + _sources.length + ' rows');
  setText('fh-dt-range', M.rangeText(list.length, T.page, T.per));
  var pager = document.getElementById('fh-dt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'fhPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'fhPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('fh-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'clearFhTableQuery') + '>Clear filter</button></div>';
  }
  setHidden('fh-table-wrap', !list.length);
  setHidden('fh-dt-foot', !list.length);
}

export function renderFactoryHealthIngestion(r) {
  var el = document.getElementById('factory-health-ingestion');
  if (!el) return;
  var srcs = r.pipeline.ingestion.sources;
  _sources = M.sourceRows(srcs);
  T.sel = {}; T.page = 0;
  if (!_sources.length) {
    el.innerHTML = '<h4 class="sec-label">Source ingestion</h4>' + card('', empty('plug', 'No sources configured'));
    return;
  }
  el.innerHTML = skeletonHtml(M.sourceCounts(srcs));
  var q = document.getElementById('fh-dt-q'); if (q) q.value = T.q;
  var per = document.getElementById('fh-dt-per'); if (per) per.value = String(T.per);
  paintTable();
}

// ── Table controls ──
export function fhTableQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; paintTable(); }
export function clearFhTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('fh-dt-q'); if (q) q.value = ''; paintTable(); }
export function setFhPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paintTable(); }
export function fhPage(d) { T.page += Number(d) || 0; paintTable(); }
export function fhSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function toggleFhCols() { var m = document.getElementById('fh-cols'); if (m) m.hidden = !m.hidden; }
export function fhColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function fhSelectRow(i, el) { if (el && el.checked) T.sel[i] = true; else delete T.sel[i]; paintTable(); }
export function fhSelectAll(el) {
  currentList().forEach(function(s) { var i = _sources.indexOf(s); if (el && el.checked) T.sel[i] = true; else delete T.sel[i]; });
  paintTable();
}
export function clearFhSelection() { T.sel = {}; paintTable(); }
export function fhRowKeydown(i, el, event) {
  if (event && (event.key === 'Enter' || event.key === ' ') && event.target === el) { event.preventDefault(); openFactorySource(i); }
}

function exportFh(onlySelected) {
  var rows = onlySelected ? _sources.filter(function(s, i) { return T.sel[i]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(cols.map(function(c) { return M.COLUMNS[c]; }).concat(['ID']), rows.map(function(s) {
    return cols.map(function(c) { return M.cellText(s, c); }).concat([s.id]);
  }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'ingestion-sources.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportFhCsv() { exportFh(false); }
export function exportFhSelected() { exportFh(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('fh-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});

function renderFactoryHealthFunnel(r) {
  var el = document.getElementById('factory-health-funnel');
  if (!el) return;
  var st = M.funnelStages(r.pipeline.funnel);
  var boxes = st.map(function(s, i) {
    return '<div class="fh-stage tone-' + s.tone + '"><div class="fh-stage-v">' + x(s.value) + '</div><div class="fh-stage-n">' + x(s.label) + '</div></div>' +
      (i < st.length - 1 ? '<span class="fh-arrow" aria-hidden="true">→</span>' : '');
  }).join('');
  var lines = M.qualityLines(r.pipeline.dataQuality).map(function(l) {
    return '<span class="fh-q tone-' + l.tone + '">' + icon(l.tone === 'ok' ? 'ok' : 'alert') + x(l.text) + '</span>';
  }).join('');
  el.innerHTML = card('Content pipeline', '<div class="fh-funnel">' + boxes + '</div><div class="fh-quality">' + lines + '</div>');
}

function trendCard(title, points, suffix) {
  if (!points || points.length < minTrendPoints) return card(title, empty('trend', 'Not enough history yet'));
  return card(title, chartSlot({ type: 'line', h: 190, suffix: suffix || '', labels: points.map(function(p) { return String(p.day).slice(5); }),
    series: [{ name: title, data: points.map(function(p) { return p.value; }), color: CHART_COLORS.accent }] }));
}

function renderFactoryHealthTrends(r) {
  var a = document.getElementById('factory-health-threats-trend');
  var b = document.getElementById('factory-health-tcv-trend');
  if (a) a.innerHTML = trendCard('Threats processed per day', r.trends.threatsProcessedByDay);
  if (b) b.innerHTML = trendCard('Threat to content time per day', r.trends.tcvByDay);
}

// The source drawer: one ingestion source, shown from the response already loaded (no extra request).
export function openFactorySource(i) {
  var s = _sources[i];
  if (!s) return;
  var set = function(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; };
  set('fh-drawer-title', s.name);
  set('fh-drawer-sub', s.id || 'Ingestion source');
  var body = document.getElementById('fh-drawer-body');
  if (body) {
    body.innerHTML = '<div class="fh-dr-state">' + pill(s.state.label, s.state.tone) + '<span class="muted">' + x(s.failures) + (s.failures === 1 ? ' failure' : ' failures') + ' in window</span></div>' +
      kv([['Last success', s.lastSuccessAt ? fmtDate(s.lastSuccessAt) : 'never synced'], ['Failures in window', String(s.failures)], ['Last diagnostic', s.diagnostic || 'None reported']]);
  }
  var o = document.getElementById('fh-drawer-overlay');
  if (o) o.classList.add('open');
}
export function closeFactorySource() {
  var o = document.getElementById('fh-drawer-overlay');
  if (o) o.classList.remove('open');
}
export function closeFactoryDrawerOnBackdrop(el, event) { if (event.target === el) closeFactorySource(); }

// renderSparkline draws an inline SVG polyline, matching the existing
// attack-path.js/evidence.js convention -- no charting library. Below
// minTrendPoints (kept in sync with the backend's own threshold), it
// shows an honest empty state instead of a misleading short line.
export function renderSparkline(elementId, points) {
  var el = document.getElementById(elementId);
  if (!el) return;
  if (!points || points.length < minTrendPoints) {
    el.innerHTML = '<div class="kpi-sub" style="color:var(--muted)">Not enough history yet</div>';
    return;
  }
  var w = 240, h = 48, pad = 4;
  var values = points.map(function(p) { return p.value; });
  var min = Math.min.apply(null, values);
  var max = Math.max.apply(null, values);
  var range = max - min || 1;
  var step = (w - pad * 2) / (points.length - 1);
  var coords = values.map(function(v, i) {
    var cx = pad + i * step;
    var cy = h - pad - ((v - min) / range) * (h - pad * 2);
    return cx.toFixed(1) + ',' + cy.toFixed(1);
  }).join(' ');
  el.innerHTML = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + coords + '" fill="none" stroke="var(--accent)" stroke-width="2"/></svg>';
}
