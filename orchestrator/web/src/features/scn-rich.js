// Renderers for the redesigned Scenarios page: category sidebar, toolbar, grid/list cards and the
// scenario drawer. The page skeleton lives in index.html; renderScenarios() (attack-path.js) reads the
// toolbar, then hands the rows to the painters here. Every figure comes from rows the page already
// loaded (/api/scenarios, /api/scenarios/library, /api/adversary-templates) or from
// /api/scenarios/runs for the drawer's History tab. Nothing here invents a number.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { icon, bar, tabs as kitTabs, empty } from '../core/kit.js';
import { chartSlot } from '../core/charts.js';
import { setDisplay } from '../core/inline-style.js';
import { fmtDate } from '../core/util.js';
import { ROLE } from './shell.js';
import * as M from './scn-model.js';

var BOX = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l9 5v8l-9 5-9-5V8z"/><path d="M3 8l9 5 9-5M12 13v8"/></svg>';
var LIST = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/></svg>';
var GRID = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>';

var CAT_ICON = {
  all: 'layers', av: 'shield', waf: 'shield', network: 'globe', email: 'mail', dlp: 'lock', phishing: 'flag', killchain: 'path',
  ransomware: 'alert', webgw: 'globe', cloud: 'cloud', apibas: 'bolt', ad: 'key', dbsim: 'database', common: 'box', intel: 'technique', templates: 'user',
};
export function catIcon(key) { var n = CAT_ICON[key] || 'layers'; return n === 'box' ? BOX : icon(n); }
var sm = function(name) { return icon(name).replace('width="16" height="16"', 'width="13" height="13"'); };

// Page-level view state: grid or list, sort mode, sidebar collapsed.
var UI = { view: 'grid', sort: 'default', catOff: false };
export function scnUi() { return UI; }
export function setScenarioViewMode(v) { UI.view = v === 'list' ? 'list' : 'grid'; }
export function setScenarioSortMode(v) { UI.sort = v === 'name' || v === 'tech' ? v : 'default'; }
export function setScenarioCatOffMode(v) { UI.catOff = !!v; }

// ── Sidebar ────────────────────────────────────────────────────────────────
export function catsHtml(rows, active) {
  return '<div class="sc-cats-hd"><h4>Scenario Categories</h4>' +
    '<button type="button" class="sc-icon-btn" title="Collapse categories" aria-label="Collapse categories"' + on('click', 'setScenarioCatOff', true) + '>' + icon('chevron') + '</button></div>' +
    '<div class="sc-cat-list">' + rows.map(function(r) {
      return '<div class="sc-cat-item' + (r.key === active ? ' on' : '') + '" tabindex="0" role="button"' +
        on('click', 'openScenarioCategory', r.key) + on('keydown', 'scenarioCategoryKeydown', r.key) + '>' +
        catIcon(r.key) + '<span>' + x(r.label) + '</span><span class="n">' + x(r.n) + '</span></div>' +
        (r.sub ? '<div class="sc-cat-sub">' + x(r.sub) + '</div>' : '');
    }).join('') + '</div>';
}

// ── Toolbar (above the grid): show-categories, grid/list toggle, sort ───────
export function toolbarHtml(minimal) {
  var opt = function(v, l) { return '<option value="' + v + '"' + (UI.sort === v ? ' selected' : '') + '>' + l + '</option>'; };
  var showCats = UI.catOff ? '<button type="button" class="btn btn-outline btn-sm sc-showcats"' + on('click', 'setScenarioCatOff', false) + '>' + sm('layers') + 'Show categories</button>' : '';
  if (minimal) return showCats;
  return showCats +
    '<div class="sc-seg" role="group" aria-label="View">' +
      '<button type="button" class="' + (UI.view === 'grid' ? 'on' : '') + '" title="Grid" aria-label="Grid view"' + on('click', 'setScenarioView', 'grid') + '>' + GRID + '</button>' +
      '<button type="button" class="' + (UI.view === 'list' ? 'on' : '') + '" title="List" aria-label="List view"' + on('click', 'setScenarioView', 'list') + '>' + LIST + '</button>' +
    '</div>' +
    '<span class="muted">Sort by:</span>' +
    '<select id="sc-sort" aria-label="Sort by"' + on('change', 'setScenarioSort') + '>' + opt('default', 'Default order') + opt('name', 'Name') + opt('tech', 'Most techniques') + '</select>';
}

// ── Cards ──────────────────────────────────────────────────────────────────
function catalogs() { return { art: (state.artCatalog || []).length, caldera: (state.calderaCatalog || []).length }; }

export function cardHtml(s) {
  var src = M.sourceOf(s), av = M.availOf(s), foot = M.footOf(s, catalogs()), r = s.registry;
  var phase = (s.mitrePhases || [])[0];
  var more = (s.mitrePhases || []).length > 1 ? ' +' + ((s.mitrePhases || []).length - 1) : '';
  var pending = r && r.executableVersion && r.latestVersion > r.executableVersion
    ? '<span class="sc-avail pending" title="Newer version awaiting approval">&#9679; v' + x(r.latestVersion) + ' ' + x(String(r.latestLifecycle || '').toLowerCase().replace(/_/g, ' ')) + '</span>' : '';
  return '<div class="sc-card src-' + x(src) + (av.key === 'ok' ? '' : ' unavail') + '" tabindex="0" role="button" data-sid="' + x(s.id) + '"' +
      on('click', 'openScenarioDrawer', s.id) + on('keydown', 'scenarioCardKeydown', s.id) + '>' +
    '<div class="sc-tags"><span class="sc-tag blue">' + x(M.SOURCE_LABEL[src] || src) + '</span>' +
      '<span class="sc-tag">' + sm('mapped') + x(M.osLabel(s.supportedOs)) + '</span>' +
      (phase ? '<span class="sc-tag purple" title="' + x((s.mitrePhases || []).join(', ')) + '">' + sm('shield') + x(phase) + x(more) + '</span>' : '') + '</div>' +
    '<h3>' + x(s.name) + '</h3><p>' + x(s.description) + '</p>' +
    '<div class="sc-foot"><span>' + sm('mapped') + ' ' + x(foot.left) + '</span>' + (foot.right ? '<span>' + sm('clock') + ' ' + x(foot.right) + '</span>' : '') + '</div>' +
    '<div class="sc-actions"><span class="sc-avail ' + av.key + '" title="' + x(av.title) + '">&#9679; ' + x(av.label) + '</span>' + pending +
      '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'runScenarioCard', s.id) + '>' + sm('play') + 'Run</button></div>' +
  '</div>';
}

export function gridHtml(list) {
  return '<div class="sc-grid' + (UI.view === 'list' ? ' sc-list' : '') + '">' + list.map(cardHtml).join('') + '</div>';
}

export function emptyHtml() {
  return '<div class="rk-card sc-empty">' + empty('search', 'No scenarios match these filters', 'Try a different keyword or clear the filters.') +
    '<div class="sc-empty-act"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'clearScenarioFilters') + '>Clear all filters</button></div></div>';
}

// ── Drawer ─────────────────────────────────────────────────────────────────
var DR = { id: null, tab: 'overview', runs: null, runsFor: null };
var TABS = [{ id: 'overview', label: 'Overview' }, { id: 'steps', label: 'Steps' }, { id: 'techniques', label: 'Techniques' }, { id: 'requirements', label: 'Requirements' }, { id: 'history', label: 'History' }];

function find(id) { return (state.scenarios || []).filter(function(s) { return s.id === id; })[0] || null; }
export function drawerScenarioId() { return DR.id; }

function registryLabel(s) {
  var r = s.registry;
  if (!r) return 'Unregistered';
  if (r.executableVersion) {
    var t = r.executableTrust === 'VENDOR_SIGNED' ? 'Vendor signed' : (r.executableTrust === 'LOCAL_TRUSTED' ? 'Approved locally' : 'Dev-unsigned');
    return t + ' v' + r.executableVersion;
  }
  return 'v' + r.latestVersion + ' ' + String(r.latestLifecycle || '').toLowerCase().replace(/_/g, ' ');
}

export function requirementsOf(s) {
  var out = [], os = s.supportedOs || [];
  out.push(os.length && os.length < 3 ? M.osLabel(os) + ' agent online' : 'An online agent (any supported platform)');
  if (s.localCheck) out.push('Posture check: runs read-only on the agent, no extra content needed');
  if (s.executable) out.push('Supports opt-in live execution (telemetry or lab mode) with self-cleaning steps');
  if (s.artAllWindows || s.artAllPlatform || s.artSelectiveWindows || s.artSelectivePlatform || (s.artTechniques || []).length) out.push('Atomic Red Team content loaded on the server');
  if (s.calderaAllWindows || (s.calderaAbilities || []).length || s.calderaAdversaryId) out.push('A reachable Caldera server');
  if (!s.registry || !s.registry.executableVersion) out.push('An approved version (this scenario is not executable until one exists)');
  return out;
}

function kvRows(rows) { return '<dl class="sc-kv">' + rows.map(function(r) { return '<dt>' + x(r[0]) + '</dt><dd' + (r[2] ? ' class="mono"' : '') + '>' + x(r[1]) + '</dd>'; }).join('') + '</dl>'; }

function relHtml(s) {
  var rows = DR.runs && DR.runsFor === s.id ? M.historyOf(DR.runs, s.id) : null;
  if (!rows || !rows.length) return '';
  return '<h4 class="sc-h4">Related</h4><div class="sc-rel-list">' + rows.slice(0, 4).map(function(r) {
    return '<div class="sc-rel" tabindex="0" role="button"' + on('click', 'openScenarioRun', r.id) + '>' + icon('play') +
      '<div class="grow"><b>' + x(r.id) + (r.agent ? ' &mdash; ' + x(r.agent) : '') + '</b><em>' + x(r.status) + '</em></div>' + icon('chevron') + '</div>';
  }).join('') + '</div>';
}

function overviewHtml(s) {
  var rows = [['Author', s.author || '—'], ['Signature', registryLabel(s)], ['Source', M.SOURCE_LABEL[M.sourceOf(s)] || M.sourceOf(s)],
    ['Platform', M.osLabel(s.supportedOs)], ['Run mode', M.modeLabel(s, catalogs())], ['Steps', String((s.steps || []).length)]];
  var tech = M.techniquesOf(s);
  rows.push(['Techniques', tech.length ? tech.join(', ') : '—', true]);
  if (s.intelSource) { rows.push(['Intel actor', s.intelActor || '—']); rows.push(['Intel feed', String(s.intelSource).toUpperCase() + (s.intelConfidence ? ' · ' + s.intelConfidence + ' confidence' : '')]); }
  return '<p class="sc-ov">' + x(s.description) + '</p>' + kvRows(rows) +
    '<h4 class="sc-h4">Requirements</h4><ul class="sc-reqs-plain">' + requirementsOf(s).map(function(p) { return '<li>' + x(p) + '</li>'; }).join('') + '</ul>' +
    '<div id="sc-drawer-rel">' + relHtml(s) + '</div>';
}

function stepsHtml(s) {
  var st = s.steps || [];
  if (!st.length) return empty('layers', 'Steps are resolved when the scenario runs', M.modeLabel(s, catalogs()) + ' scenarios pick their steps on the server.');
  return '<div class="sc-sub">' + st.length + (st.length === 1 ? ' step' : ' steps') + ' &middot; run in order</div><div class="sd-steps">' + st.map(function(p, i) {
    var meta = [p.techniqueId, p.framework, p.executor].filter(Boolean).join(' · ');
    return '<div class="sd-step"><span class="sd-n">' + (i + 1) + '</span><div class="grow"><b>' + x(p.name || ('Step ' + (i + 1))) + '</b>' +
      (meta ? '<div class="sc-sub">' + x(meta) + '</div>' : '') + '</div>' + (p.timeoutSec ? '<span class="mono sc-sub">' + x(p.timeoutSec) + 's</span>' : '') + '</div>';
  }).join('') + '</div>';
}

function techniquesHtml(s) {
  var ids = M.techniquesOf(s), steps = s.steps || [];
  if (!ids.length) return empty('mapped', 'No explicit techniques', M.modeLabel(s, catalogs()) + ' scenarios resolve their technique list on the server.');
  var phases = (s.mitrePhases || []).map(function(p) { return '<span class="sc-tag purple">' + x(p) + '</span>'; }).join(' ');
  return '<div class="sc-tbl-wrap"><table class="sc-tbl"><thead><tr><th>Technique</th><th>Used by</th><th>Phase</th></tr></thead><tbody>' + ids.map(function(id) {
    var by = steps.filter(function(p) { return p.techniqueId === id; }).map(function(p) { return p.name; }).filter(Boolean);
    return '<tr><td class="mono">' + x(id) + '</td><td>' + (by.length ? x(by.join(', ')) : '<span class="muted">ART technique list</span>') + '</td><td>' + (phases || '<span class="muted">—</span>') + '</td></tr>';
  }).join('') + '</tbody></table></div><div class="sc-sub sc-note">' + ids.length + ' ATT&amp;CK technique' + (ids.length === 1 ? '' : 's') + ' mapped</div>';
}

function requirementsTab(s) {
  var modes = 'Posture' + (s.executable ? ' · Telemetry · Lab' : '');
  return '<h4 class="sc-h4 first">Prerequisites</h4><ul class="sd-req">' + requirementsOf(s).map(function(p) { return '<li>' + sm('check') + x(p) + '</li>'; }).join('') + '</ul>' +
    kvRows([['Platform', M.osLabel(s.supportedOs)], ['Execution modes', modes], ['Signature', registryLabel(s)], ['Scenario ID', s.id, true]]);
}

function historyTab(s) {
  if (!DR.runs || DR.runsFor !== s.id) return '<div class="sc-sub">Loading run history&hellip;</div>';
  var rows = M.historyOf(DR.runs, s.id);
  if (!rows.length) return empty('clock', 'No runs yet', 'Run this scenario and its results will be listed here.');
  var series = M.historySeries(rows);
  var tone = function(p) { return p >= 80 ? 'ok' : p >= 50 ? 'warn' : 'bad'; };
  return (series.length > 1 ? '<div class="rk-card sc-spark"><div class="sc-lbl">PREVENTION &middot; LAST ' + series.length + ' SCORED RUNS</div>' + chartSlot({ type: 'spark', data: series, color: 'var(--success)', h: 46 }) + '</div>' : '') +
    '<div class="sc-tbl-wrap"><table class="sc-tbl sc-click"><thead><tr><th>Run</th><th>Result</th><th>Agent</th><th>Started</th><th>Score</th></tr></thead><tbody>' + rows.map(function(r) {
      return '<tr tabindex="0"' + on('click', 'openScenarioRun', r.id) + '><td class="mono">' + x(r.id) + '</td><td>' + x(r.status) + '</td><td>' + x(r.agent || '—') + '</td>' +
        '<td class="muted">' + x(r.startedAt ? fmtDate(r.startedAt) : '—') + '</td><td class="sc-score">' + (r.pct != null ? bar(r.pct, tone(r.pct)) + '<span>' + r.pct + '%</span>' : '<span class="muted">—</span>') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

function bodyHtml(s) {
  var inner = DR.tab === 'steps' ? stepsHtml(s) : DR.tab === 'techniques' ? techniquesHtml(s) : DR.tab === 'requirements' ? requirementsTab(s) : DR.tab === 'history' ? historyTab(s) : overviewHtml(s);
  return kitTabs(TABS, DR.tab, 'scenarioDrawerTab') + '<div id="sc-tab-body">' + inner + '</div>';
}

// Footer: Close, then the same management actions the old detail panel offered, then Run.
export function footHtml(s, approveBtn) {
  var canEdit = ROLE === 'admin' || ROLE === 'analyst';
  var stepN = (s.steps || []).length;
  var fw = (s.artAllWindows || s.artAllPlatform || s.artSelectiveWindows || s.artSelectivePlatform || (s.artTechniques || []).length) ? 'art'
    : (s.calderaAllWindows || (s.calderaAbilities || []).length) ? 'caldera' : (!s.localCheck && stepN) ? 'steps' : '';
  var noun = fw === 'art' ? 'techniques' : fw === 'caldera' ? 'abilities' : 'steps';
  var b = function(label, action, args, title) { return '<button type="button" class="btn btn-outline btn-sm"' + on.apply(null, ['click', action].concat(args || [])) + (title ? ' title="' + x(title) + '"' : '') + '>' + label + '</button>'; };
  var left = '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'closeScenarioDrawer') + '>Close</button>';
  var mid = approveBtn || '';
  if (!s.intelSource) {
    if (canEdit) {
      mid += b('Clone', 'cloneScenario', [s.id], 'Clone into an editable custom scenario');
      if (s.source === 'custom') { mid += b('Edit', 'openBuilder', [s.id], 'Edit'); mid += b('Delete', 'deleteCustomScenario', [s.id], 'Delete'); }
    }
    if (s.artAllWindows || s.artAllPlatform) mid += b('Detailed view', 'openDetailedViewForScenario', [s.id], 'Every atomic test that will run');
    else if (fw) mid += b('Customize', 'openPicker', [s.id, fw], 'Choose which ' + noun + ' to run');
  }
  return left + '<span class="grow"></span>' + mid + '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'runScenarioFromDrawer', s.id) + '>' + sm('play') + 'Run Scenario</button>';
}

function headHtml(s) {
  return '<span class="sc-dh-ico">' + icon('technique') + '</span><div><div class="sc-dh-t">' + x(s.name) + '</div>' +
    '<div class="sc-dh-s">' + x(s.id) + ' · ' + x(M.SOURCE_LABEL[M.sourceOf(s)] || M.sourceOf(s)) + ' · ' + x(M.osLabel(s.supportedOs)) + '</div></div>';
}

// paintDrawer redraws the open drawer from the current scenario list (also after Approve reloads it).
export function paintDrawer(approveBtnFor) {
  var ov = document.getElementById('sc-drawer-overlay');
  if (!ov || !DR.id) return;
  var s = find(DR.id);
  if (!s) { closeDrawer(); return; }
  document.getElementById('sc-drawer-head').innerHTML = headHtml(s);
  document.getElementById('sc-drawer-body').innerHTML = bodyHtml(s);
  document.getElementById('sc-drawer-foot').innerHTML = footHtml(s, approveBtnFor ? approveBtnFor(s) : '');
}
var _approveFor = null;
export function bindApproveButton(fn) { _approveFor = fn; }

export function openDrawer(id) {
  var s = find(id);
  if (!s) return;
  DR.id = id; DR.tab = 'overview';
  if (DR.runsFor !== id) { DR.runs = null; DR.runsFor = null; }
  paintDrawer(_approveFor);
  document.getElementById('sc-drawer-overlay').classList.add('open');
  var body = document.getElementById('sc-drawer-body'); if (body) body.scrollTop = 0;
  loadRuns(id);
}
export function closeDrawer() {
  DR.id = null;
  var ov = document.getElementById('sc-drawer-overlay');
  if (ov) ov.classList.remove('open');
}
export function drawerTab(t) {
  if (!DR.id) return;
  DR.tab = TABS.some(function(p) { return p.id === t; }) ? t : 'overview';
  paintDrawer(_approveFor);
}
function loadRuns(id) {
  if (DR.runsFor === id && DR.runs) return;
  apicall('/api/scenarios/runs?scenarioId=' + encodeURIComponent(id)).then(function(runs) {
    if (DR.id !== id) return;
    DR.runs = Array.isArray(runs) ? runs : [];
    DR.runsFor = id;
    var s = find(id); if (!s) return;
    if (DR.tab === 'history') document.getElementById('sc-tab-body').innerHTML = historyTab(s);
    else if (DR.tab === 'overview') { var rel = document.getElementById('sc-drawer-rel'); if (rel) rel.innerHTML = relHtml(s); }
  }).catch(function() {
    if (DR.id !== id) return;
    DR.runs = []; DR.runsFor = id;
    var s = find(id);
    if (s && DR.tab === 'history') document.getElementById('sc-tab-body').innerHTML = historyTab(s);
  });
}
// The full run object, for the results workspace.
export function runById(runId) {
  var rows = DR.runs || [];
  for (var i = 0; i < rows.length; i++) if (rows[i].id === runId) return rows[i];
  return null;
}

// Filters row helpers used by renderScenarios.
export function hideFilterSelects(hide) {
  ['sc-filter-source', 'sc-filter-os', 'sc-filter-product'].forEach(function(id) { setDisplay(document.getElementById(id), hide ? 'none' : ''); });
}
