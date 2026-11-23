import { state } from '../core/state.js';
import { apicall, apicallOk } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, showToast } from '../core/util.js';
import { covSegHtml } from './attack-path.js';
import { ROLE } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { cssVars } from '../core/css-vars.js';
import { kpi, card, grid, hbars, bar, chip, pill, empty, kv } from '../core/kit.js';
import { chartSlot } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './ioc-model.js';


// ── Indicators (IOCs) tab ────────────────────────────────────────────────────
// Fetched once (unfiltered) when the run drawer opens; type/search filtering
// happens client-side from _runIOCsAll rather than round-tripping to the
// server per keystroke (GetRunIOCs does support ?type=&search=, but the
// per-run dataset is small enough that this is simpler and more responsive).

var _runIOCTypeFilter = 'all';
var _runIOCSearch = '';
var _runIOCExpandedIdx = -1; // index into the current filtered list, not _runIOCsAll -- reset on any filter change

var IOC_TYPE_LABEL = { ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash', cve: 'CVE' };

export function renderRunIOCToolbar() {
  var el = document.getElementById('run-ioc-toolbar');
  if (!el) return;
  var counts = { all: state._runIOCsAll.length };
  state._runIOCsAll.forEach(function(i) { counts[i.type] = (counts[i.type] || 0) + 1; });
  var types = [['all', 'All'], ['ip', 'IP'], ['domain', 'Domain'], ['url', 'URL'], ['hash', 'Hash'], ['cve', 'CVE']];
  el.innerHTML =
    covSegHtml(types, _runIOCTypeFilter, 'setRunIOCTypeFilter', function(k) { return counts[k] || 0; }) +
    '<input type="text" id="run-ioc-search" placeholder="Search indicators…" value="' + x(_runIOCSearch) + '"' + on('input', 'setRunIOCSearchFromInput') + ' class="g1-s-1230a88f">';
}
export function setRunIOCTypeFilter(t) {
  _runIOCTypeFilter = t;
  _runIOCExpandedIdx = -1;
  renderRunIOCToolbar();
  renderRunIOCList();
}
// Only re-renders the list (not the toolbar) so the search input never loses
// focus/cursor position while the user is still typing.
export function setRunIOCSearchFromInput(el) { setRunIOCSearch(el.value); }
export function setRunIOCSearch(v) {
  _runIOCSearch = v;
  _runIOCExpandedIdx = -1;
  renderRunIOCList();
}
export function toggleRunIOCRow(idx) {
  _runIOCExpandedIdx = (_runIOCExpandedIdx === idx) ? -1 : idx;
  renderRunIOCList();
}
function _iocTierBadge(ind) {
  if (!ind.tier) return '<span class="tiny muted">No enrichment</span>';
  if (ind.tier === 'pending') return '<span class="tiny muted">Checking&#8230;</span>';
  var map = {
    'malicious-associated': ['Malicious', 'var(--danger)'],
    'suspicious': ['Suspicious', 'var(--warning)'],
    'unknown': ['Unknown', 'var(--muted)']
  };
  var m = map[ind.tier] || [ind.tier, 'var(--muted)'];
  var pulses = ind.pulseCount ? ' &middot; ' + ind.pulseCount + ' pulse' + (ind.pulseCount === 1 ? '' : 's') : '';
  return '<span class="g1-s-961fd92c"' + cssVars(['g1-v-7d75dfc9', m[1]]) + '>' + x(m[0]) + pulses + '</span>';
}
export function renderRunIOCList() {
  var el = document.getElementById('run-ioc-list');
  if (!el) return;
  var list = state._runIOCsAll.filter(function(i) {
    if (_runIOCTypeFilter !== 'all' && i.type !== _runIOCTypeFilter) return false;
    if (_runIOCSearch && i.value.toLowerCase().indexOf(_runIOCSearch.toLowerCase()) === -1) return false;
    return true;
  });
  if (!list.length) {
    el.innerHTML = '<div class="g1-s-3414c9bc">' +
      (state._runIOCsAll.length ? 'No indicators match this filter.' : 'No indicators extracted from this run.') + '</div>';
    return;
  }

  el.innerHTML = list.map(function(ind, idx) {
    var expanded = _runIOCExpandedIdx === idx;
    var techs = (ind.techniqueIds || []).map(function(t) {
      return '<code class="g1-s-86b92508">' + x(t) + '</code>';
    }).join('');
    var tags = (ind.tags || []).map(function(t) {
      return '<span class="tiny g1-display-inline-block g1-s-7c8b2a40">' + x(t) + '</span>';
    }).join('');
    var detail = !expanded ? '' :
      '<div class="g1-s-70a1b066">' +
        '<div class="g1-display-grid g1-s-ee837f27">' +
          '<div><div class="kpi-label">Source</div><div>' + x(ind.source || '—') + '</div></div>' +
          '<div><div class="kpi-label">Confidence</div><div>' + (ind.confidence || 0) + '%</div></div>' +
          '<div><div class="kpi-label">Extracted</div><div>' + (ind.extractedAt ? ago(ind.extractedAt) : '—') + '</div></div>' +
          '<div><div class="kpi-label">Seen in techniques</div><div>' + (techs || '<span class="muted">—</span>') + '</div></div>' +
        '</div>' +
        (tags ? '<div class="u-mt-06"><div class="kpi-label g1-s-9f42fc4f">Threat tags</div>' + tags + '</div>' : '') +
        ((ind.malwareFamilies || []).length ? '<div class="u-mt-06"><div class="kpi-label g1-s-0c393a5c">Malware families</div>' + x(ind.malwareFamilies.join(', ')) + '</div>' : '') +
        ((ind.adversaryNames || []).length ? '<div class="u-mt-06"><div class="kpi-label g1-s-0c393a5c">Associated actors</div>' + x(ind.adversaryNames.join(', ')) + '</div>' : '') +
      '</div>';
    return '<div class="g1-s-37461afc">' +
      '<div class="g1-display-flex g1-s-4f930f48"' + on('click', 'toggleRunIOCRow', idx) + '>' +
        '<span class="tiny g1-s-e739ad1b">' + x(IOC_TYPE_LABEL[ind.type] || ind.type) + '</span>' +
        '<code class="g1-s-7b055023">' + x(ind.value) + '</code>' +
        '<span class="tiny muted g1-s-867764b6">' + x(ind.source || '') + '</span>' +
        '<span class="g1-s-867764b6">' + _iocTierBadge(ind) + '</span>' +
        '<span class="tiny muted g1-s-867764b6">' + (expanded ? '&#9650;' : '&#9660;') + '</span>' +
      '</div>' +
      detail +
    '</div>';
  }).join('');
}

export function closeResults() { document.getElementById('results-overlay').classList.remove('open', 'run-mode'); }
export function closeResultsOnBackdrop(el, event) { if (event.target === el) closeResults(); }

// ── IOC Registry ─────────────────────────────────────────────────────────────
// Cross-run indicator search (GET /api/iocs), distinct from the per-run
// Indicators (IOCs) tab in the run drawer: this reads the deduplicated
// iocs/ioc_sightings tables (populated today from DetectionAlert.CommandLine/
// ProcessName via SubmitRunDetections), not the per-run run_iocs extraction.
// One IOC row here can span many runs/agents/scenarios via its sightings.
var _iocRegistryRows = [];
var _iocShown = M.PAGE_SIZE;   // rows painted so far; "Show more" raises it
var _iocBase = null;           // banner numbers of the UNFILTERED registry: filtering the table must not change them
var _iocBaseStale = true;
var _iocSearchTimer = null;

function iocFilterValues() {
  var v = function(id) { var e = document.getElementById(id); return e ? e.value : ''; };
  var sup = document.getElementById('ioc-filter-suppressed');
  return { type: v('ioc-filter-type'), source: v('ioc-filter-source'), origin: v('ioc-filter-origin'), status: v('ioc-filter-status'),
    search: v('ioc-filter-search').trim(), showSuppressed: !!(sup && sup.checked) };
}

function paintIOCHero() {
  var h = _iocBase || { total: null, detected: null, missed: null, observed: null };
  var v = function(k) { return k == null ? '—' : k; };
  setHeroStat('ioc-hs-total', v(h.total)); setHeroStat('ioc-hs-detected', v(h.detected));
  setHeroStat('ioc-hs-missed', v(h.missed)); setHeroStat('ioc-hs-observed', v(h.observed));
}

export function loadIOCRegistry() {
  ['ioc-import-btn', 'ioc-add-btn'].forEach(function(id) {
    var b = document.getElementById(id);
    if (b) setDisplay(b, ROLE === 'admin' ? '' : 'none');
  });

  apicallOk('/api/analytics/iocs?limit=5').then(renderIOCAnalyticsTiles).catch(function() {
    var el = document.getElementById('ioc-analytics-tiles');
    if (el) el.innerHTML = '';
  });

  var f = iocFilterValues();
  var params = [];
  if (f.type) params.push('type=' + encodeURIComponent(f.type));
  if (f.source) params.push('source=' + encodeURIComponent(f.source));
  if (f.origin) params.push('origin=' + encodeURIComponent(f.origin));
  if (f.status) params.push('status=' + encodeURIComponent(f.status));
  if (f.search) params.push('value=' + encodeURIComponent(f.search));
  params.push('limit=200');
  var narrowed = M.filtersActive(f);

  var tbody = document.getElementById('ioc-registry-body');
  tbody.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
  var clr = document.getElementById('ioc-clear-btn');
  if (clr) setDisplay(clr, (narrowed || f.showSuppressed) ? '' : 'none');
  apicallOk('/api/iocs?' + params.join('&')).then(function(rows) {
    rows = Array.isArray(rows) ? rows : [];
    // suppressed filtering happens client-side -- GetIOCs has no suppressed
    // param, and hiding suppressed-by-default (unless the box is checked)
    // is a display preference, not a query the backend needs to know about.
    _iocRegistryRows = f.showSuppressed ? rows : rows.filter(function(r) { return !r.suppressed; });
    _iocShown = M.PAGE_SIZE;
    if (!narrowed) { _iocBase = M.heroStats(_iocRegistryRows); _iocBaseStale = false; }
    renderIOCRegistryTable(narrowed);
    // Filtered view: the banner still describes the whole registry, so fetch that once (and again after a change).
    if (narrowed && (_iocBase == null || _iocBaseStale)) {
      apicallOk('/api/iocs?limit=200').then(function(all) {
        _iocBase = M.heroStats((Array.isArray(all) ? all : []).filter(function(r) { return !r.suppressed; }));
        _iocBaseStale = false;
        paintIOCHero(); paintIOCCount(narrowed);
      }).catch(function() {});
    }
  }).catch(function(e) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">Failed to load indicators: ' + x(e.message || 'unknown error') +
      '<div class="ioc-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'loadIOCRegistry') + '>Try again</button></div></td></tr>';
    ['ioc-side', 'ioc-insights'].forEach(function(id) { var el = document.getElementById(id); if (el) el.innerHTML = ''; });
    setText('ioc-count', '');
    _iocBase = null; paintIOCHero();
  });
}
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }

// Type chip beside the charts: sets the type filter (the select in the search bar) and reloads.
export function setIOCType(t) {
  var sel = document.getElementById('ioc-filter-type');
  if (sel) sel.value = t || '';
  loadIOCRegistry();
}
export function clearIOCFilters() {
  ['ioc-filter-type', 'ioc-filter-source', 'ioc-filter-origin', 'ioc-filter-status', 'ioc-filter-search'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.value = '';
  });
  var sup = document.getElementById('ioc-filter-suppressed');
  if (sup) sup.checked = false;
  loadIOCRegistry();
}
export function loadIOCRegistryOnEnter(el, event) { if (event.key === 'Enter') { clearTimeout(_iocSearchTimer); loadIOCRegistry(); } }
// Typing in the search box filters after a short pause, so the table follows without a button press.
export function iocSearchLive() {
  clearTimeout(_iocSearchTimer);
  _iocSearchTimer = setTimeout(loadIOCRegistry, 350);
}

var IOC_TYPE_LABEL_REGISTRY = M.TYPE_LABEL;
var IOC_PALETTE = ['#3b82f6', '#22d3ee', '#a78bfa', '#f59e0b', '#10b981', '#ef4444', '#60a5fa'];

// The four ranking tiles (GET /api/analytics/iocs): the top entry of each ranking, or an honest "No data yet".
function renderIOCAnalyticsTiles(result) {
  var el = document.getElementById('ioc-analytics-tiles');
  if (!el) return;
  el.innerHTML = grid(4, M.analyticsTiles(result).map(function(t) { return kpi(t); }));
}

// Indicator-type chips + sightings-by-type donut (side by side), then the by-type donut and top-sources bars.
function renderIOCInsights() {
  var side = document.getElementById('ioc-side');
  var el = document.getElementById('ioc-insights');
  if (!side || !el) return;
  if (!_iocRegistryRows.length) { side.innerHTML = ''; el.innerHTML = ''; return; }
  var typeSel = document.getElementById('ioc-filter-type');
  var active = typeSel ? typeSel.value : '';
  var chips = '<div class="ioc-chips">' + M.typeChips(_iocRegistryRows, active).map(function(c) {
    return '<button type="button" class="ioc-chip' + (c.on ? ' on' : '') + (c.count === 0 ? ' dim' : '') + '"' + on('click', 'setIOCType', c.id) + '>' + x(c.label) +
      (c.count != null ? ' <span class="ioc-chip-n">' + c.count + '</span>' : '') + '</button>';
  }).join('') + '</div>';
  var sightings = M.sightingCountsByType(_iocRegistryRows);
  var total = sightings.reduce(function(a, p) { return a + p[1]; }, 0);
  var sightBody = total
    ? chartSlot({ type: 'donut', h: 130, legendRight: false, center: total, centerSub: 'sightings', segments: M.donutSegments(sightings, IOC_PALETTE, 4, '#64748b') })
    : empty('hash', 'No sightings yet');
  side.innerHTML = '<div class="rk-grid ioc-side">' + card('Indicator types', chips) + card('Sightings by type', sightBody) + '</div>';
  el.innerHTML = grid(2, [
    card('By type', chartSlot({ type: 'donut', h: 160, legendRight: true, centerSub: 'indicators', segments: M.donutSegments(M.typeCounts(_iocRegistryRows), IOC_PALETTE, 7, '#64748b') })),
    card('Top sources', hbars(M.sourceRows(_iocRegistryRows, 6)))
  ]);
}

// "12 of 23 indicators" while filtered, "23 indicators" otherwise; says so when the server's 200-row cap is in play.
function paintIOCCount(narrowed) {
  var n = _iocRegistryRows.length;
  var t = narrowed && _iocBase && _iocBase.total != null ? n + ' of ' + _iocBase.total + ' indicators' : n + ' indicator' + (n === 1 ? '' : 's');
  if (n >= 200) t += ' (first 200 shown, narrow the filters to see others)';
  setText('ioc-count', t);
}

function renderIOCRegistryTable(narrowed) {
  var tbody = document.getElementById('ioc-registry-body');
  paintIOCHero();
  renderIOCInsights();
  paintIOCCount(narrowed);
  if (!_iocRegistryRows.length) {
    setText('ioc-count', '');
    tbody.innerHTML = '<tr><td colspan="7">' + (narrowed
      ? empty('search', 'No indicators match', 'Try different filters.') + '<div class="ioc-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'clearIOCFilters') + '>Clear filters</button></div>'
      : empty('hash', 'No indicators yet', ROLE === 'admin' ? 'Indicators appear as runs record detections. You can also add one or import a list.' : 'Indicators appear as runs record detections.')) + '</td></tr>';
    return;
  }
  var shown = _iocRegistryRows.slice(0, _iocShown);
  tbody.innerHTML = shown.map(function(row, idx) {
    var suppressedBadge = row.suppressed ? ' <span class="sbadge g1-s-3518ee58" title="' + x(row.suppressionReason || '') + '">suppressed</span>' : '';
    return '<tr class="u-pointer" tabindex="0"' + on('click', 'openIOCDetail', idx) + on('keydown', 'iocRowKeydown', idx) + '>' +
      '<td class="ioc-val"><code class="g1-s-51a7b72a"><span class="ioc-clamp" title="' + x(row.value) + '">' + x(row.value) + '</span></code>' + suppressedBadge + '</td>' +
      '<td>' + chip(IOC_TYPE_LABEL_REGISTRY[row.type] || row.type, 'muted') + '</td>' +
      '<td class="muted">' + x(M.sourceLabel(row.source) || '—') + '</td>' +
      '<td class="ioc-sight"><div class="ioc-sight-in">' + bar(M.sightingPct(row, _iocRegistryRows), 'accent') + '<span class="mono muted">' + (row.sightingCount || 0) + '</span></div></td>' +
      '<td>' + (row.status ? pill(row.status, M.statusTone(row.status)) : '<span class="tiny muted">—</span>') + '</td>' +
      '<td class="muted" title="' + x(row.lastSeen || '') + '">' + x(M.agoText(row.lastSeen)) + '</td>' +
      '<td' + on('click', 'stopEvent') + '>' +
        (ROLE === 'admin' ?
          '<button class="btn btn-outline btn-sm g1-s-765a0fbc"' + on('click', 'toggleIOCSuppressed', idx) + '>' + (row.suppressed ? 'Unsuppress' : 'Suppress') + '</button>'
          : '') +
      '</td>' +
    '</tr>';
  }).join('') + (_iocRegistryRows.length > shown.length
    ? '<tr class="ioc-more"><td colspan="7"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'iocShowMore') + '>Show more (' + (_iocRegistryRows.length - shown.length) + ' left)</button></td></tr>'
    : '');
}
export function iocShowMore() { _iocShown += M.PAGE_SIZE; renderIOCRegistryTable(M.filtersActive(iocFilterValues())); }

// A row has one shared data-args list (its index), so the handler receives (idx, element, event).
export function iocRowKeydown(idx, el, event) {
  if (!(event && (event.key === 'Enter' || event.key === ' ') && event.target === el)) return;
  event.preventDefault();
  el.click();
}

// ── Suppress ──
var _iocSupIdx = -1;

export function toggleIOCSuppressed(idx) {
  var row = _iocRegistryRows[idx];
  if (!row) return;
  if (row.suppressed) setIOCSuppressed(idx, false, '');
  else openIOCSuppress(idx);
}
function openIOCSuppress(idx) {
  var row = _iocRegistryRows[idx];
  if (!row) return;
  _iocSupIdx = idx;
  setText('ioc-sup-value', row.value);
  document.getElementById('ioc-sup-reason').value = '';
  setDisplay(document.getElementById('ioc-sup-err'), 'none');
  document.getElementById('ioc-sup-overlay').classList.add('open');
  setTimeout(function() { var r = document.getElementById('ioc-sup-reason'); if (r) r.focus(); }, 50);
}
export function closeIOCSuppress() { document.getElementById('ioc-sup-overlay').classList.remove('open'); _iocSupIdx = -1; }
export function closeIOCSuppressOnBackdrop(el, event) { if (event.target === el) closeIOCSuppress(); }
export function iocSupPreset(text) { var r = document.getElementById('ioc-sup-reason'); if (r) { r.value = text; r.focus(); } }
export function submitIOCSuppress() {
  var reason = document.getElementById('ioc-sup-reason').value.trim();
  var errEl = document.getElementById('ioc-sup-err');
  if (!reason) { errEl.textContent = 'Give a reason, so others can see why this indicator was suppressed.'; setDisplay(errEl, ''); return; }
  setDisplay(errEl, 'none');
  setIOCSuppressed(_iocSupIdx, true, reason);
}
function setIOCSuppressed(idx, next, reason) {
  var row = _iocRegistryRows[idx];
  if (!row) return;
  apicallOk('/api/iocs/' + encodeURIComponent(row.id) + '/suppress', {
    method: 'POST',
    body: JSON.stringify({ suppressed: next, reason: reason })
  }).then(function() {
    showToast(next ? 'Indicator suppressed. It is hidden from this list; tick "Show suppressed" to see it.' : 'Indicator restored', 'ok');
    _iocBaseStale = true;
    closeIOCSuppress();
    closeIOCDrawer();
    loadIOCRegistry();
  }).catch(function(e) { showToast('Could not update the indicator: ' + (e.message || 'error'), 'err'); });
}

// ── Detail drawer ──
// openIOCDetail reuses the shared results-overlay drawer (the same one
// run-results/technique/finding detail views use) rather than a new
// component -- populates from the already-loaded row (no re-fetch needed
// for the IOC's own fields) plus a fetch of its 1-hop relationship
// neighborhood (scenarios/runs/agents/techniques it was observed in).
export function openIOCDetail(idx) {
  var row = _iocRegistryRows[idx];
  if (!row) return;
  var set = function(id, t) { var el = document.getElementById(id); if (el) el.textContent = t; };
  set('ioc-drawer-title', row.value);
  set('ioc-drawer-sub', (IOC_TYPE_LABEL_REGISTRY[row.type] || row.type) + ' · ' + (M.sourceLabel(row.source) || '—'));
  var fmt = function(t) { return new Date(t).toLocaleString(); };
  var body = document.getElementById('ioc-drawer-body');
  body.innerHTML =
    '<div class="ioc-dr-top">' + (row.status ? pill(row.status, M.statusTone(row.status)) : '') + (row.suppressed ? pill('suppressed', 'warn') : '') +
      '<span class="muted">' + (row.sightingCount || 0) + ' sighting' + (row.sightingCount === 1 ? '' : 's') + '</span></div>' +
    bar(M.sightingPct(row, _iocRegistryRows), 'accent') +
    '<div class="ioc-dr-val"><code>' + x(row.value) + '</code><button type="button" class="btn btn-outline btn-sm"' + on('click', 'copyIOCValue', idx) + '>Copy value</button></div>' +
    '<div class="ioc-dr-kv">' + kv(M.drawerFacts(row, fmt)) + '</div>' +
    (ROLE === 'admin' ? '<div class="ioc-dr-sec"><h4>Suppression</h4><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleIOCSuppressed', idx) + '>' + (row.suppressed ? 'Unsuppress' : 'Suppress') + '</button></div>' : '') +
    '<div id="ioc-detail-relationships" class="ioc-dr-sec"><div class="tiny muted">Loading relationships…</div></div>';
  document.getElementById('ioc-drawer-overlay').classList.add('open');

  apicallOk('/api/knowledge-graph/ioc/' + encodeURIComponent(row.id)).then(function(nbh) {
    var el = document.getElementById('ioc-detail-relationships');
    if (!el) return;
    var nodes = (nbh && nbh.nodes) || [];
    var byType = { scenario: [], run: [], agent: [], technique: [] };
    nodes.forEach(function(n) {
      if (n.type !== 'ioc' && byType[n.type]) byType[n.type].push(n.label);
    });
    var groupLabels = { scenario: 'Seen in scenarios', run: 'Seen in runs', agent: 'Seen on agents', technique: 'Seen with techniques' };
    var sections = Object.keys(groupLabels).map(function(t) {
      if (!byType[t].length) return '';
      return '<div class="ioc-rel"><h4>' + groupLabels[t] + ' (' + byType[t].length + ')</h4>' +
        '<div class="ioc-rel-chips">' +
        byType[t].map(function(l) { return chip(l, 'muted'); }).join('') +
        '</div></div>';
    }).join('');
    el.innerHTML = '<h4>Related</h4>' + (sections || '<div class="tiny muted">No relationships recorded.</div>');
  }).catch(function() {
    var el = document.getElementById('ioc-detail-relationships');
    if (el) el.innerHTML = '<div class="tiny muted">Relationships unavailable.</div>';
  });
}

export function copyIOCValue(idx) {
  var row = _iocRegistryRows[idx];
  if (!row) return;
  var done = function() { showToast('Copied the indicator value', 'ok'); };
  var fallback = function() {
    var ta = document.createElement('textarea');
    ta.value = row.value; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    var ok = false; try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    if (ok) done(); else showToast('Could not copy. Select the value and copy it by hand.', 'warn');
  };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(row.value).then(done).catch(fallback);
  else fallback();
}

export function closeIOCDrawer() {
  var o = document.getElementById('ioc-drawer-overlay');
  if (o) o.classList.remove('open');
}
export function closeIOCDrawerOnBackdrop(el, event) { if (event.target === el) closeIOCDrawer(); }

// ── Add / import ──
var _iocAddTypeChosen = false;
export function iocAddTypeTouched() { _iocAddTypeChosen = true; }
// While the type has not been picked by hand, follow what the pasted value looks like.
export function iocAddValueInput(el) {
  if (_iocAddTypeChosen) return;
  var g = M.guessType(el && el.value);
  var sel = document.getElementById('ioc-add-type');
  if (g && sel) sel.value = g;
}

export function openIOCAddModal() {
  _iocAddTypeChosen = false;
  document.getElementById('ioc-add-value').value = '';
  setDisplay(document.getElementById('ioc-add-err'), 'none');
  document.getElementById('ioc-add-overlay').classList.add('open');
  setTimeout(function() { var v = document.getElementById('ioc-add-value'); if (v) v.focus(); }, 50);
}
export function closeIOCAddModal() { document.getElementById('ioc-add-overlay').classList.remove('open'); }
export function closeIOCAddOnBackdrop(el, event) { if (event.target === el) closeIOCAddModal(); }

// Add IOC: one indicator through the same admin-only import endpoint (customer origin, draft status).
export function submitIOCAdd() {
  var errEl = document.getElementById('ioc-add-err');
  setDisplay(errEl, 'none');
  var fail = function(m) { errEl.textContent = m; setDisplay(errEl, ''); };
  var parsed = M.parseEntry(document.getElementById('ioc-add-type').value, document.getElementById('ioc-add-value').value);
  if (parsed.error) { fail(parsed.error); return; }
  var dup = M.isDuplicate(_iocRegistryRows, parsed.entry.type, parsed.entry.value);
  if (dup) { fail('This indicator is already in the registry' + (dup.status ? ' (status: ' + dup.status + ')' : '') + '.'); return; }
  var btn = document.getElementById('ioc-add-submit-btn');
  btn.disabled = true;
  apicallOk('/api/iocs/import', { method: 'POST', body: JSON.stringify({ entries: [parsed.entry] }) })
    .then(function(res) {
      btn.disabled = false;
      if (!(res && res.written)) { fail('The registry did not add this indicator.'); return; }
      showToast('Indicator added as a draft. Filters can hide it; clear them to see it.', 'ok');
      _iocBaseStale = true;
      closeIOCAddModal();
      loadIOCRegistry();
    })
    .catch(function(e) { btn.disabled = false; fail(e.message || 'Add failed'); });
}

export function openIOCImportModal() {
  document.getElementById('ioc-import-text').value = '';
  setDisplay(document.getElementById('ioc-import-err'), 'none');
  document.getElementById('ioc-import-overlay').classList.add('open');
  setTimeout(function() { var t = document.getElementById('ioc-import-text'); if (t) t.focus(); }, 50);
}
export function closeIOCImportModal() { document.getElementById('ioc-import-overlay').classList.remove('open'); }
export function closeIOCImportOnBackdrop(el, event) { if (event.target === el) closeIOCImportModal(); }

export function submitIOCImport() {
  var errEl = document.getElementById('ioc-import-err');
  setDisplay(errEl, 'none');
  var parsed = M.parseImportLines(document.getElementById('ioc-import-text').value);
  if (parsed.error) { errEl.textContent = parsed.error; setDisplay(errEl, ''); return; }
  var entries = parsed.entries;
  var btn = document.getElementById('ioc-import-submit-btn');
  btn.disabled = true;
  apicallOk('/api/iocs/import', { method: 'POST', body: JSON.stringify({ entries: entries }) })
    .then(function(res) {
      btn.disabled = false;
      var w = (res && res.written) || 0;
      showToast(w + ' of ' + entries.length + ' indicator' + (entries.length === 1 ? '' : 's') + ' imported as drafts', w === entries.length ? 'ok' : 'warn');
      _iocBaseStale = true;
      closeIOCImportModal();
      loadIOCRegistry();
    })
    .catch(function(e) {
      btn.disabled = false;
      // The server writes the good lines before it stops on a bad one, so the list may have changed.
      errEl.textContent = (e.message || 'Import failed') + ' Lines before the failure may already have been imported; the list was refreshed.';
      setDisplay(errEl, '');
      _iocBaseStale = true;
      loadIOCRegistry();
    });
}
