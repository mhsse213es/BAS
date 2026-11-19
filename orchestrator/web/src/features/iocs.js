import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
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

export function loadIOCRegistry() {
  ['ioc-import-btn', 'ioc-import-btn2', 'ioc-add-btn'].forEach(function(id) {
    var b = document.getElementById(id);
    if (b) setDisplay(b, ROLE === 'admin' ? '' : 'none');
  });

  apicall('/api/analytics/iocs?limit=5').then(renderIOCAnalyticsTiles).catch(function() {
    var el = document.getElementById('ioc-analytics-tiles');
    if (el) el.innerHTML = '';
  });

  var params = [];
  var type = document.getElementById('ioc-filter-type').value;
  var source = document.getElementById('ioc-filter-source').value;
  var origin = document.getElementById('ioc-filter-origin').value;
  var status = document.getElementById('ioc-filter-status').value;
  var search = document.getElementById('ioc-filter-search').value.trim();
  var showSuppressed = document.getElementById('ioc-filter-suppressed').checked;
  if (type) params.push('type=' + encodeURIComponent(type));
  if (source) params.push('source=' + encodeURIComponent(source));
  if (origin) params.push('origin=' + encodeURIComponent(origin));
  if (status) params.push('status=' + encodeURIComponent(status));
  if (search) params.push('value=' + encodeURIComponent(search));
  params.push('limit=200');

  var tbody = document.getElementById('ioc-registry-body');
  tbody.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
  var clr = document.getElementById('ioc-clear-btn');
  if (clr) setDisplay(clr, (type || source || origin || status || search || showSuppressed) ? '' : 'none');
  apicall('/api/iocs?' + params.join('&')).then(function(rows) {
    rows = rows || [];
    // suppressed filtering happens client-side -- GetIOCs has no suppressed
    // param, and hiding suppressed-by-default (unless the box is checked)
    // is a display preference, not a query the backend needs to know about.
    _iocRegistryRows = showSuppressed ? rows : rows.filter(function(r) { return !r.suppressed; });
    renderIOCRegistryTable();
  }).catch(function(e) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">Failed to load: ' + x(e.message || 'unknown error') + '</td></tr>';
    ['ioc-side', 'ioc-insights'].forEach(function(id) { var el = document.getElementById(id); if (el) el.innerHTML = ''; });
    ['total', 'detected', 'missed', 'observed'].forEach(function(k) { setHeroStat('ioc-hs-' + k, '—'); });
  });
}
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
export function loadIOCRegistryOnEnter(el, event) { if (event.key === 'Enter') loadIOCRegistry(); }

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
    return '<button type="button" class="ioc-chip' + (c.on ? ' on' : '') + '"' + on('click', 'setIOCType', c.id) + '>' + x(c.label) + '</button>';
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

function renderIOCRegistryTable() {
  var tbody = document.getElementById('ioc-registry-body');
  var h = M.heroStats(_iocRegistryRows);
  setHeroStat('ioc-hs-total', h.total); setHeroStat('ioc-hs-detected', h.detected);
  setHeroStat('ioc-hs-missed', h.missed); setHeroStat('ioc-hs-observed', h.observed);
  renderIOCInsights();
  if (!_iocRegistryRows.length) {
    tbody.innerHTML = '<tr><td colspan="7">' + empty('search', 'No indicators match', 'Clear the filters.') + '</td></tr>';
    return;
  }
  tbody.innerHTML = _iocRegistryRows.map(function(row, idx) {
    var suppressedBadge = row.suppressed ? ' <span class="sbadge g1-s-3518ee58" title="' + x(row.suppressionReason || '') + '">suppressed</span>' : '';
    return '<tr class="u-pointer"' + on('click', 'openIOCDetail', idx) + '>' +
      '<td class="ioc-val"><code class="g1-s-51a7b72a">' + x(row.value) + '</code>' + suppressedBadge + '</td>' +
      '<td>' + chip(IOC_TYPE_LABEL_REGISTRY[row.type] || row.type, 'muted') + '</td>' +
      '<td class="muted">' + x(M.sourceLabel(row.source) || '—') + '</td>' +
      '<td class="ioc-sight"><div class="ioc-sight-in">' + bar(M.sightingPct(row, _iocRegistryRows), 'accent') + '<span class="mono muted">' + (row.sightingCount || 0) + '</span></div></td>' +
      '<td>' + (row.status ? pill(row.status, M.statusTone(row.status)) : '<span class="tiny muted">—</span>') + '</td>' +
      '<td class="muted">' + (row.lastSeen ? ago(row.lastSeen) : '—') + '</td>' +
      '<td' + on('click', 'stopEvent') + '>' +
        (ROLE === 'admin' ?
          '<button class="btn btn-outline btn-sm g1-s-765a0fbc"' + on('click', 'toggleIOCSuppressed', idx) + '>' + (row.suppressed ? 'Unsuppress' : 'Suppress') + '</button>'
          : '') +
      '</td>' +
    '</tr>';
  }).join('');
}

export function toggleIOCSuppressed(idx) {
  var row = _iocRegistryRows[idx];
  if (!row) return;
  var next = !row.suppressed;
  var reason = '';
  if (next) {
    reason = prompt('Reason for suppressing this indicator (e.g. known lab tool):') || '';
    if (!reason) return; // cancelled or empty -- don't suppress without a reason
  }
  apicall('/api/iocs/' + encodeURIComponent(row.id) + '/suppress', {
    method: 'POST',
    body: JSON.stringify({ suppressed: next, reason: reason })
  }).then(function() {
    showToast(next ? 'Indicator suppressed' : 'Indicator unsuppressed', 'ok');
    closeIOCDrawer();
    loadIOCRegistry();
  }).catch(function(e) { showToast(e.message || 'Failed to update', 'err'); });
}

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
    '<div class="ioc-dr-top">' + (row.status ? pill(row.status, M.statusTone(row.status)) : '') +
      '<span class="muted">' + (row.sightingCount || 0) + ' sighting' + (row.sightingCount === 1 ? '' : 's') + '</span></div>' +
    bar(M.sightingPct(row, _iocRegistryRows), 'accent') +
    '<div class="ioc-dr-kv">' + kv(M.drawerFacts(row, fmt)) + '</div>' +
    (ROLE === 'admin' ? '<div class="ioc-dr-sec"><h4>Suppression</h4><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleIOCSuppressed', idx) + '>' + (row.suppressed ? 'Unsuppress' : 'Suppress') + '</button></div>' : '') +
    '<div id="ioc-detail-relationships" class="ioc-dr-sec"><div class="tiny muted">Loading relationships…</div></div>';
  document.getElementById('ioc-drawer-overlay').classList.add('open');

  apicall('/api/knowledge-graph/ioc/' + encodeURIComponent(row.id)).then(function(nbh) {
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

export function closeIOCDrawer() {
  var o = document.getElementById('ioc-drawer-overlay');
  if (o) o.classList.remove('open');
}
export function closeIOCDrawerOnBackdrop(el, event) { if (event.target === el) closeIOCDrawer(); }

export function openIOCAddModal() {
  document.getElementById('ioc-add-value').value = '';
  setDisplay(document.getElementById('ioc-add-err'), 'none');
  document.getElementById('ioc-add-overlay').classList.add('open');
}
export function closeIOCAddModal() { document.getElementById('ioc-add-overlay').classList.remove('open'); }
export function closeIOCAddOnBackdrop(el, event) { if (event.target === el) closeIOCAddModal(); }

// Add IOC: one indicator through the same admin-only import endpoint (customer origin, draft status).
export function submitIOCAdd() {
  var errEl = document.getElementById('ioc-add-err');
  setDisplay(errEl, 'none');
  var parsed = M.parseEntry(document.getElementById('ioc-add-type').value, document.getElementById('ioc-add-value').value);
  if (parsed.error) { errEl.textContent = parsed.error; setDisplay(errEl, ''); return; }
  var btn = document.getElementById('ioc-add-submit-btn');
  btn.disabled = true;
  apicall('/api/iocs/import', { method: 'POST', body: JSON.stringify({ entries: [parsed.entry] }) })
    .then(function(res) {
      btn.disabled = false;
      if (!(res && res.written)) { errEl.textContent = 'Indicator was not added.'; setDisplay(errEl, ''); return; }
      showToast('Indicator added', 'ok');
      closeIOCAddModal();
      loadIOCRegistry();
    })
    .catch(function(e) { btn.disabled = false; errEl.textContent = e.message || 'Add failed'; setDisplay(errEl, ''); });
}

export function openIOCImportModal() {
  document.getElementById('ioc-import-text').value = '';
  setDisplay(document.getElementById('ioc-import-err'), 'none');
  document.getElementById('ioc-import-overlay').classList.add('open');
}
export function closeIOCImportModal() { document.getElementById('ioc-import-overlay').classList.remove('open'); }
export function closeIOCImportOnBackdrop(el, event) { if (event.target === el) closeIOCImportModal(); }

export function submitIOCImport() {
  var raw = document.getElementById('ioc-import-text').value;
  var errEl = document.getElementById('ioc-import-err');
  setDisplay(errEl, 'none');

  var lines = raw.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l; });
  if (!lines.length) { errEl.textContent = 'Enter at least one type,value line.'; setDisplay(errEl, ''); return; }

  var entries = [];
  for (var i = 0; i < lines.length; i++) {
    var parts = lines[i].split(',');
    if (parts.length < 2 || !parts[0].trim() || !parts.slice(1).join(',').trim()) {
      errEl.textContent = 'Line ' + (i + 1) + ' is not "type,value": ' + lines[i];
      setDisplay(errEl, '');
      return;
    }
    entries.push({ type: parts[0].trim(), value: parts.slice(1).join(',').trim() });
  }

  var btn = document.getElementById('ioc-import-submit-btn');
  btn.disabled = true;
  apicall('/api/iocs/import', { method: 'POST', body: JSON.stringify({ entries: entries }) })
    .then(function(res) {
      btn.disabled = false;
      showToast((res.written || 0) + ' of ' + entries.length + ' indicator(s) imported', 'ok');
      closeIOCImportModal();
      loadIOCRegistry();
    })
    .catch(function(e) { btn.disabled = false; errEl.textContent = e.message || 'Import failed'; setDisplay(errEl, ''); });
}