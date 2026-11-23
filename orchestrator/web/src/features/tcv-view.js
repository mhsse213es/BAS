// Technique Coverage page view: the actor card (picker + chips), the two summary cards, the search / select
// bar and the technique table card (the design demo's table chrome). Pure helpers live in tcv-model.js.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { apicallOk } from '../core/api.js';
import { ROLE } from './shell.js';
import { showToast } from '../core/util.js';
import { grid, card, hbars, bar, pill, empty, icon, searchBox, kv } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import { covStats } from './rich-g4.js';
import * as M from './tcv-model.js';

var _rows = [];
var _actors = [];
var _actor = '';
var F = { q: '', result: '' };
var T = { q: '', col: 2, dir: 1, page: 0, per: 25, sel: {}, hidden: {} }; // lowest coverage first: the page exists to find gaps
var _lib = null;      // techniqueId -> { name, tactic } from the unified library (optional)
var _libFailed = false;
var _actorsErr = '';

function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }

// ── Actor card ──
function paintActors() {
  var sel = document.getElementById('cov-actor-select');
  if (sel && sel.options.length - 1 !== _actors.length) {
    sel.innerHTML = '<option value="">' + M.ALL_ACTORS + '</option>' + _actors.map(function(a) { return '<option value="' + x(a) + '">' + x(a) + '</option>'; }).join('');
  }
  if (sel) sel.value = _actor;
  var chips = document.getElementById('cov-actor-chips');
  if (chips) {
    chips.innerHTML = [''].concat(M.chipActors(_actors, _actor)).map(function(a) {
      return '<button type="button" class="tcv-chip' + (a === _actor ? ' on' : '') + '"' + on('click', 'setCoverageActor', a) + '>' + x(a || M.ALL_ACTORS) + '</button>';
    }).join('');
  }
}

export function loadCoverageActors() {
  apicallOk('/api/coverage/actors')
    .then(function(data) { _actors = (data && data.actors) || []; _actorsErr = ''; paintActors(); paintActorErr(); })
    .catch(function(e) { _actorsErr = e.message || 'unknown error'; paintActorErr(); });
}
function paintActorErr() {
  var el = document.getElementById('cov-actor-err');
  if (!el) return;
  if (!_actorsErr) { el.innerHTML = ''; return; }
  el.innerHTML = '<span class="tcv-err">Could not load the actor list: ' + x(_actorsErr) + '</span> <button type="button" class="btn btn-outline btn-sm"' + on('click', 'loadCoverageActors') + '>Try again</button>';
}

export function setCoverageActor(name) {
  var sel = document.getElementById('cov-actor-select');
  if (sel) sel.value = name || '';
  loadCoverageMatrix();
}

// ── Summary cards ──
var BAND_COLOR = { ok: CHART_COLORS.ok, info: CHART_COLORS.info, warn: CHART_COLORS.warn, bad: CHART_COLORS.bad };
function summaryHtml() {
  var st = covStats(_rows);
  if (!st.total) return '';
  var tone = function(d) { return d.applicable ? M.covTone(d.pct) : 'muted'; };
  return grid(2, [
    card('Coverage by dimension', hbars(st.dims.filter(function(d) { return d.applicable; }).map(function(d) { return [d.label, d.pct, tone(d), d.have + '/' + d.applicable]; })), { sub: 'N/A techniques are excluded' }),
    card('Coverage bands', '<div class="donut-wrap">' + chartSlot({ type: 'donut', segments: M.bands(_rows).filter(function(b) { return b.value; }).map(function(b) { return { label: b.label, value: b.value, color: BAND_COLOR[b.tone] }; }), center: st.total, centerSub: 'techniques', h: 150 }) + '</div>', { sub: 'Share of applicable dimensions each technique has' }),
  ]);
}

// ── Filter bar ──
function filtersHtml() {
  return '<div class="rk-filters tcv-filters">' +
    searchBox('cov-search', 'Search by ID, name or tactic...', 'covSearch') +
    '<select id="cov-f-result" aria-label="Result"' + on('change', 'covSetResult') + '><option value="">All results</option>' +
      M.RESULTS.map(function(r) { return '<option value="' + r[0] + '"' + (F.result === r[0] ? ' selected' : '') + '>' + r[1] + '</option>'; }).join('') + '</select>' +
    '<button type="button" id="cov-clear" class="btn btn-ghost" hidden' + on('click', 'covClearFilters') + '>' + icon('x') + 'Clear</button></div>';
}
export function covSearch(el) { F.q = String((el && el.value) || ''); T.page = 0; T.sel = {}; paintHost(); }
export function covSetResult(el) { F.result = String((el && el.value) || ''); T.page = 0; T.sel = {}; paintHost(); }
export function setCoverageFilter(id) { F.result = id === 'gaps' || id === 'covered' ? id : ''; T.page = 0; T.sel = {}; paintHost(); }
export function covClearFilters() {
  F = { q: '', result: '' };
  T.page = 0; T.sel = {};
  var q = document.getElementById('cov-search'); if (q) q.value = '';
  var r = document.getElementById('cov-f-result'); if (r) r.value = '';
  paintHost();
}

// ── Table ──
function skeletonHtml() {
  return '<div class="rk-card runs-card tcv-card"><div class="runs-dt">' +
    '<div class="dt-toolbar" id="tcv-dt-toolbar">' +
      '<span class="dt-count muted" id="tcv-dt-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'toggleTcvCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="tcv-cols" hidden></div></div>' +
      '<select id="tcv-dt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'setTcvPer') + '>' + M.PAGE_SIZES.map(function(n) { return '<option value="' + n + '">' + n + ' / page</option>'; }).join('') + '<option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportTcvCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="tcv-bulk" hidden><b id="tcv-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'exportTcvSelected') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'clearTcvSelection') + '>Clear selection</button></div>' +
    '<div class="tbl-wrap dt-scroll" id="tcv-table-wrap"><table><thead id="tcv-thead"></thead><tbody id="tcv-body"></tbody></table></div>' +
    '<div class="dt-empty" id="tcv-empty" hidden></div>' +
    '<div class="dt-foot" id="tcv-dt-foot"><span class="dt-range muted" id="tcv-dt-range"></span><div class="dt-pager" id="tcv-dt-pager"></div></div>' +
    '</div></div>';
}

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function pageRows() { return M.filterRows(_rows, F); }
function currentList() { return M.sortRows(M.tableFilter(pageRows(), T.q), T.col, T.dir); }

function dimCell(r, col) {
  var t = M.cellText(r, col);
  return '<td>' + (t === 'N/A' ? '<span class="muted">N/A</span>' : t === 'Yes' ? pill('Yes', 'ok') : pill('No', 'warn')) + '</td>';
}

function cellHtml(col, r) {
  if (col === 0) return '<td><b class="mono">' + x(r.techniqueId) + '</b></td>';
  if (col === 1) return '<td class="tcv-name">' + (r.name ? '<div class="tcv-nm" title="' + x(r.name) + '">' + x(r.name) + '</div>' + (r.tactic ? '<div class="tiny muted">' + x(M.prettyTactic(r.tactic)) + '</div>' : '') : '<span class="muted">' + (_libFailed ? 'Name unavailable' : '—') + '</span>') + '</td>';
  if (col === 2) {
    var c = M.rowCov(r);
    if (!c.applicable) return '<td><span class="muted">N/A</span></td>';
    return '<td class="tcv-covcol"><div class="tcv-cov">' + bar(c.pct, M.covTone(c.pct)) + '<span class="mono muted tcv-cov-n">' + c.have + ' / ' + c.applicable + '</span></div></td>';
  }
  return dimCell(r, col);
}

function paintHost() {
  var host = document.getElementById('cov-table');
  if (!host) return;
  setHidden('cov-clear', !(F.q || F.result));
  if (!_rows.length) {
    host.innerHTML = card('', empty('technique', 'No techniques to show', _actor ? 'No techniques are attributed to ' + _actor + ' in the ATT&CK data.' : 'The server returned no ATT&CK group techniques.'));
    return;
  }
  if (!pageRows().length) {
    host.innerHTML = card('', empty('search', 'No techniques match', 'Try a different search or result filter.') + '<div class="tcv-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'covClearFilters') + '>Clear filters</button></div>');
    return;
  }
  host.innerHTML = skeletonHtml();
  var per = document.getElementById('tcv-dt-per'); if (per) per.value = String(T.per);
  paintTable();
}

function paintTable() {
  var tbody = document.getElementById('tcv-body');
  if (!tbody) return;
  var base = pageRows();
  var list = currentList();
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var idx = function(r) { return _rows.indexOf(r); };
  var onList = list.filter(function(r) { return T.sel[idx(r)]; }).length;
  document.getElementById('tcv-thead').innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="tcv-sel-all" title="Select all on this table"' + on('change', 'tcvSelectAll') + '></th>' +
    cols.map(function(c) {
      return '<th class="dt-th' + (T.col === c ? ' sorted' : '') + '"' + on('click', 'tcvSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '</tr>';
  var all = document.getElementById('tcv-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(r) {
    var i = idx(r);
    return '<tr class="dt-click" tabindex="0"' + on('click', 'openTcvTechnique', r.techniqueId) + on('keydown', 'tcvRowKeydown', r.techniqueId) + '><td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select technique"' + (T.sel[i] ? ' checked' : '') + on('change', 'tcvSelectRow', i) + '></td>' +
      cols.map(function(c) { return cellHtml(c, r); }).join('') + '</tr>';
  }).join('');
  var menu = document.getElementById('tcv-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'tcvColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('tcv-bulk', selN === 0);
  setText('tcv-bulk-n', String(selN));
  setText('tcv-dt-count', list.length + ' of ' + base.length + ' rows');
  setText('tcv-dt-range', M.rangeText(list.length, T.page, T.per));
  var pager = document.getElementById('tcv-dt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'tcvPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'tcvPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('tcv-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try different filters.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'covClearFilters') + '>Clear filters</button></div>';
  }
  setHidden('tcv-table-wrap', !list.length);
  setHidden('tcv-dt-foot', !list.length);
}

// ── Loader ──
function heroDash() {
  ['tcv-hs-total', 'tcv-hs-avg', 'tcv-hs-covered', 'tcv-hs-gaps'].forEach(function(id) { setHeroStat(id, '—'); });
}

// Names and tactics come from the unified technique library. They are a nicety: when that call fails the table still
// works from the IDs and says the names are unavailable.
function loadLib() {
  if (_lib) return Promise.resolve(_lib);
  return apicallOk('/api/techniques/unified').then(function(list) {
    var m = {};
    (Array.isArray(list) ? list : []).forEach(function(t) { if (t && t.techniqueId) m[t.techniqueId] = { name: t.name || '', tactic: t.tactic || '' }; });
    _lib = m; _libFailed = false;
    return m;
  }).catch(function() { _libFailed = true; return {}; });
}

export function loadCoverageMatrix() {
  var sel = document.getElementById('cov-actor-select');
  _actor = sel ? sel.value : '';
  paintActors();
  var host = document.getElementById('cov-table');
  var sum = document.getElementById('cov-summary');
  var flt = document.getElementById('cov-filters');
  if (host) host.innerHTML = card('', '<div class="tcv-state muted">Loading…</div>');
  Promise.all([apicallOk('/api/coverage/matrix' + (_actor ? '?actor=' + encodeURIComponent(_actor) : '')), loadLib()])
    .then(function(res) {
      _rows = M.withNames(Array.isArray(res[0]) ? res[0] : [], res[1]);
      T.page = 0; T.sel = {};
      var h = M.heroStats(_rows);
      setHeroStat('tcv-hs-total', h.total);
      setHeroStat('tcv-hs-avg', h.avg == null ? '—' : h.avg + '%');
      setHeroStat('tcv-hs-covered', h.covered);
      setHeroStat('tcv-hs-gaps', h.gaps);
      setText('cov-actor-note', M.actorNote(_actor, _rows));
      if (sum) sum.innerHTML = summaryHtml();
      if (flt) flt.innerHTML = filtersHtml();
      var q = document.getElementById('cov-search'); if (q) q.value = F.q;
      paintHost();
    })
    .catch(function(e) {
      _rows = [];
      heroDash();
      setText('cov-actor-note', '');
      if (sum) sum.innerHTML = '';
      if (flt) flt.innerHTML = '';
      if (host) host.innerHTML = card('', empty('alert', 'Could not load technique coverage', e.message || 'unknown error') + '<div class="tcv-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'loadCoverageMatrix') + '>Try again</button></div>');
    });
}

// ── Technique drawer ──
// Shows each dimension with what it means and what is missing, then the ATT&CK facts. It reuses the shared technique
// drawer shell. Coverage here is whether Audspect has the content, not whether anything detected or blocked a run.
function dimIcon(state) { return state === 'yes' ? '&#10003;' : state === 'no' ? '&#10005;' : '&ndash;'; }

export function openTcvTechnique(id) {
  var r = _rows.filter(function(t) { return t.techniqueId === id; })[0];
  if (!r) return;
  var set = function(eid, t) { var el = document.getElementById(eid); if (el) el.textContent = t; };
  set('cov-drawer-title', r.name || id);
  set('cov-drawer-sub', id + (r.tactic ? ' · ' + M.prettyTactic(r.tactic) : ''));
  var c = M.rowCov(r);
  var dims = M.dimRows(r);
  var canRun = (ROLE === 'admin' || ROLE === 'analyst') && r.simulationExists === true;
  var body = document.getElementById('cov-drawer-body');
  if (!body) return;
  body.innerHTML =
    '<div class="tcv-dr-top">' + (c.applicable ? pill(c.pct + '% covered', M.covTone(c.pct)) + '<span class="muted">' + c.have + ' of ' + c.applicable + ' dimensions</span>' : pill('Not measurable', 'muted')) + '</div>' +
    (c.applicable ? bar(c.pct, M.covTone(c.pct)) : '') +
    '<h4 class="sec-label tcv-dr-h">What Audspect has for this technique</h4>' +
    dims.map(function(d) {
      return '<div class="tcv-dim s-' + d.state + '"><span class="tcv-dim-i" aria-hidden="true">' + dimIcon(d.state) + '</span>' +
        '<div class="tcv-dim-b"><div class="tcv-dim-t"><b>' + x(d.label) + '</b>' + (d.state === 'na' ? '<span class="muted">N/A</span>' : '') + '</div>' +
        '<div class="tiny muted">' + x(d.meaning) + '</div>' + (d.todo ? '<div class="tcv-dim-todo">' + x(d.todo) + '</div>' : '') + '</div></div>';
    }).join('') +
    '<div class="tcv-dr-note">This counts content that exists, not results. It does not say whether a control detected or blocked the technique in a run.</div>' +
    '<div class="tcv-dr-acts">' +
      (canRun ? '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'revalidateRemediation', id) + '>&#9654; Run this technique</button>' : '') +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'tcvSeeResults', id) + '>See validated results</button>' +
    '</div>' +
    '<h4 class="sec-label tcv-dr-h">About the technique</h4><div id="tcv-dr-about" class="muted tiny">Loading…</div>';
  var o = document.getElementById('cov-drawer-overlay');
  if (o) o.classList.add('open');
  apicallOk('/api/attack/technique/' + encodeURIComponent(id)).then(function(e) {
    var host = document.getElementById('tcv-dr-about');
    if (!host) return;
    e = e || {};
    var list = function(a) { return (a || []).map(M.prettyTactic).join(', '); };
    var facts = [['Tactics', list(e.tactics)], ['Platforms', list(e.platforms)], ['Known actors', (e.groups || []).join(', ')], ['Data sources', (e.dataSources || []).join(', ')]].filter(function(p) { return p[1]; });
    var link = e.url && /^https?:\/\//i.test(e.url) ? '<p><a class="btn btn-outline btn-sm" href="' + x(e.url) + '" target="_blank" rel="noopener">View on attack.mitre.org &rarr;</a></p>' : '';
    host.className = '';
    host.innerHTML = (facts.length ? kv(facts) : '') + (e.description ? '<p class="cov-dr-desc">' + x(e.description) + '</p>' : '') + link || '<span class="muted tiny">No ATT&amp;CK detail recorded.</span>';
  }).catch(function(err) {
    var host = document.getElementById('tcv-dr-about');
    if (host) host.innerHTML = '<span class="tcv-err">Could not load the ATT&amp;CK detail: ' + x(err.message || 'error') + '</span>';
  });
}
// The validated results live on the MITRE ATT&CK Coverage page; close the drawer and go there.
export function tcvSeeResults() {
  var o = document.getElementById('cov-drawer-overlay'); if (o) o.classList.remove('open');
  var nav = document.querySelector('[data-on-click="showTab"][data-args=\'["coverage"]\']');
  if (nav) nav.click();
}
export function tcvRowKeydown(id, el, event) {
  if (event && (event.key === 'Enter' || event.key === ' ') && event.target === el) { event.preventDefault(); openTcvTechnique(id); }
}

// ── Table controls ──
export function tcvTableQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; paintTable(); }
export function clearTcvTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('tcv-dt-q'); if (q) q.value = ''; paintTable(); }
export function setTcvPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paintTable(); }
export function tcvPage(d) { T.page += Number(d) || 0; paintTable(); }
export function tcvSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function toggleTcvCols() { var m = document.getElementById('tcv-cols'); if (m) m.hidden = !m.hidden; }
export function tcvColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function tcvSelectRow(i, el) { if (el && el.checked) T.sel[i] = true; else delete T.sel[i]; paintTable(); }
export function tcvSelectAll(el) {
  currentList().forEach(function(r) { var i = _rows.indexOf(r); if (el && el.checked) T.sel[i] = true; else delete T.sel[i]; });
  paintTable();
}
export function clearTcvSelection() { T.sel = {}; paintTable(); }

function exportTcv(onlySelected) {
  var rows = onlySelected ? _rows.filter(function(r, i) { return T.sel[i]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(cols.map(function(c) { return M.COLUMNS[c]; }), rows.map(function(r) { return M.csvRow(r, cols); }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'technique-coverage.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportTcvCsv() { exportTcv(false); }
export function exportTcvSelected() { exportTcv(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('tcv-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});
