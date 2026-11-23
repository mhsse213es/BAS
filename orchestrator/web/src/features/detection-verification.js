import { apicall, apicallOk } from '../core/api.js';
import { openConfirmDiffModal } from './compliance.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { card, grid, hbars, pill, empty, kv, icon, searchBox } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { hbarRows } from './rich-g3.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './ver-model.js';
import { setDisplay } from '../core/inline-style.js';
import * as DC from './dc-model.js';
import { dcShow, dcEnabledCount, dcReveal } from './detection-connectors.js';
import { gapLoad } from './detection-gaps.js';


// ── Detection Verification (SP2) ───────────────────────────────────────────
// Manual-attestation queue: turn off-host Pending expectations into analyst-
// verified Detected/NotDetected results backed by hashed evidence. Reads/writes
// the independent Verification Store; every action is audited server-side.
var VF = { runId:'', items:[], perms:null, selected:'', f:{ q:'', status:'', domain:'' } };
var T = { q:'', col:-1, dir:1, page:0, per:8, sel:{}, hidden:{} };

function vfCan(p) { return VF.perms && VF.perms.indexOf(p) !== -1; }

export function vfStatusColor(s) {
  switch (s) {
    case 'Detected': return 'var(--success)';
    case 'NotDetected': return 'var(--danger)';
    case 'NotApplicable': return 'var(--muted)';
    case 'Approved': return 'var(--success)';
    case 'Rejected': return 'var(--danger)';
    case 'NeedsReview': return 'var(--warning)';
    default: return 'var(--warning)'; // Pending
  }
}
function vfStatusLabel(s) {
  switch (s) {
    case 'Detected': return 'DETECTED';
    case 'NotDetected': return 'SILENT';
    case 'NotApplicable': return 'N/A';
    case 'NeedsReview': return 'NEEDS REVIEW';
    default: return x((s || 'Pending').toUpperCase());
  }
}

export function loadVerificationTab() {
  // Load caller permissions once so controls can be enabled/disabled.
  var permsReady = VF.perms ? Promise.resolve() : apicall('/api/me/permissions').then(function(d) {
    VF.perms = (d && d.permissions) || [];
  }).catch(function(){ VF.perms = []; });
  // The connectors card and the Verify now button depend on what the caller may do.
  permsReady.then(function() { dcShow(VF.perms); vfSyncVerifyNow(); });
  loadRuns();
}

function queueError(title, msg, retryAction) {
  return card('', empty('alert', title, msg) + '<div class="vf-retry"><button type="button" class="btn btn-outline btn-sm"' + on('click', retryAction) + '>Try again</button></div>');
}

// The run selector. A failed list is shown where the queue would be, with a retry, not as a vanishing toast.
function loadRuns() {
  var box = document.getElementById('vf-queue');
  apicallOk('/api/scenarios/runs').then(function(runs) {
    var sel = document.getElementById('vf-run');
    if (!sel) return;
    runs = Array.isArray(runs) ? runs : [];
    VF.runs = runs;
    var cur = VF.runId;
    sel.innerHTML = '<option value="">' + (runs.length ? 'Select a run…' : 'No runs yet') + '</option>' + runs.map(function(r) {
      var label = (r.name || r.id) + ' · ' + (r.agentId || '') + ' · ' + fmtDate(r.startedAt);
      return '<option value="' + x(r.id) + '"' + (r.id === cur ? ' selected' : '') + '>' + x(label) + '</option>';
    }).join('');
    if (cur) vfLoadQueue();
    else if (box && !runs.length) box.innerHTML = card('', empty('check', 'No runs yet', 'Run a scenario first. Its off-host expectations then appear here to be verified.'));
  }).catch(function(e) {
    if (box && !VF.runId) box.innerHTML = queueError('Could not load runs', e.message || 'unknown error', 'loadVerificationTab');
    else showToast('Could not refresh the run list: ' + (e.message || 'error'), 'err');
  });
}

// Verify now is offered only to someone allowed to run it, and only once a run is picked.
function vfSyncVerifyNow() {
  var b = document.getElementById('vf-verify-now');
  if (b) setDisplay(b, (DC.canRun(VF.perms) && VF.runId) ? '' : 'none');
}

// Asks the server to check the picked run against the enabled detection connectors. The server does it in the
// background and attests what it finds, so the queue is reloaded once after a short wait instead of at once.
function vfVerifyBusy(on_) {
  var b = document.getElementById('vf-verify-now');
  if (!b) return;
  b.disabled = !!on_;
  b.textContent = on_ ? 'Checking…' : 'Verify now';
}
export function vfVerifyNow() {
  var runId = VF.runId;
  if (!runId) { showToast('Pick a run first.', 'err'); return; }
  if (dcEnabledCount() === 0) { showToast('No detection connector is enabled. Add or enable one under Detection connectors.', 'err'); dcReveal(); return; }
  vfVerifyBusy(true);
  apicallOk('/api/detectverify/run/' + encodeURIComponent(runId), { method: 'POST' }).then(function(d) {
    showToast(((d && d.message) || 'Verification started.') + ' The list refreshes in a few seconds.', 'ok');
    setTimeout(function() {
      vfVerifyBusy(false);
      if (VF.runId === runId) vfReloadQuiet();
    }, 10000);
  }).catch(function(e) { vfVerifyBusy(false); showToast('Could not start verification: ' + (e.message || 'error'), 'err'); });
}

// The banner numbers; with no run (or a failed load) every chip shows an em dash.
function vfHero(items) {
  var h = M.heroStats(items);
  var dash = function(v) { return v == null ? '—' : v; };
  setHeroStat('vf-hs-checks', dash(h.checks));
  setHeroStat('vf-hs-detected', dash(h.detected));
  setHeroStat('vf-hs-outstanding', dash(h.outstanding));
  setHeroStat('vf-hs-silent', dash(h.silent));
}

// A domain change filters the loaded items on the page (no new request).
export function vfSetDomain(d) {
  VF.f.domain = String((d && d.value !== undefined) ? d.value : (d || ''));
  T.page = 0; T.sel = {};
  vfPaintHost();
}
export function vfSetStatus(el) { VF.f.status = String((el && el.value) || ''); T.page = 0; T.sel = {}; vfPaintHost(); }
export function vfSearch(el) { VF.f.q = String((el && el.value) || ''); T.page = 0; T.sel = {}; vfPaintHost(); }
export function vfClearFilters() {
  VF.f = { q: '', status: '', domain: '' };
  T.page = 0; T.sel = {};
  var q = document.getElementById('vf-search'); if (q) q.value = '';
  var a = document.getElementById('vf-f-status'); if (a) a.value = '';
  var b = document.getElementById('vf-f-domain'); if (b) b.value = '';
  vfPaintHost();
}

var VF_URL = function() { return '/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications'; };

export function vfLoadQueue() {
  var sel = document.getElementById('vf-run');
  var runId = sel ? sel.value : '';
  if (runId !== VF.runId) {
    VF.f = { q: '', status: '', domain: '' };
    T = { q: '', col: -1, dir: 1, page: 0, per: T.per, sel: {}, hidden: T.hidden };
  }
  VF.runId = runId;
  gapLoad(runId);
  vfSyncVerifyNow();
  VF.selected = '';
  vfCloseDetail();
  var box = document.getElementById('vf-queue');
  if (!box) return;
  if (!VF.runId) { vfHero(null); box.innerHTML = card('', empty('check', 'Select a run', 'Pick a run above to load its pending verifications.')); return; }
  box.innerHTML = card('', empty('refresh', 'Loading…'));
  apicallOk(VF_URL()).then(function(d) {
    VF.items = (d && d.items) || [];
    vfRenderQueue();
  }).catch(function(e) { vfHero(null); VF.items = []; box.innerHTML = queueError('Could not load verifications', e.message || 'unknown error', 'vfLoadQueue'); });
}

// Reloads the items and repaints the page without closing the drawer or resetting filters (after a save, an upload
// or Verify now). A failure leaves what is on screen alone and says so.
function vfReloadQuiet() {
  if (!VF.runId) return Promise.resolve();
  var runId = VF.runId;
  return apicallOk(VF_URL()).then(function(d) {
    if (runId !== VF.runId) return;
    VF.items = (d && d.items) || [];
    vfRenderQueue();
    if (VF.selected) vfPaintFacts();
  }).catch(function(e) { showToast('Could not refresh the list: ' + (e.message || 'error'), 'err'); });
}

var VF_COLOR = { Detected: CHART_COLORS.ok, NotDetected: CHART_COLORS.bad, NotApplicable: CHART_COLORS.muted, NeedsReview: CHART_COLORS.warn, Pending: CHART_COLORS.info };

function vfSelectHtml(id, action, label, all, opts, cur) {
  return '<select id="' + id + '" aria-label="' + x(label) + '"' + on('change', action) + '><option value="">' + x(all) + '</option>' +
    opts.map(function(o) { return '<option value="' + x(o[0]) + '"' + (o[0] === cur ? ' selected' : '') + '>' + x(o[1]) + '</option>'; }).join('') + '</select>';
}

function vfRenderQueue() {
  var box = document.getElementById('vf-queue');
  var items = VF.items;
  vfHero(items);
  if (!items.length) {
    box.innerHTML = card('', empty('check', 'No off-host expectations for this run', 'Endpoint controls are verified automatically.'));
    return;
  }
  var stSegs = M.outcomeSegments(items).map(function(p) {
    return { label: p.label, value: p.value, color: VF_COLOR[p.key] || CHART_COLORS.muted };
  });
  var ctl = M.controlRows(items).map(function(r) { return [r.label, r.pct, r.tone, r.text]; });
  var doms = M.domainOptions(items).map(function(d) { return [d, d.charAt(0).toUpperCase() + d.slice(1)]; });
  box.innerHTML =
    '<div class="rk-grid vf-side">' +
      card('Result by control', hbars(ctl)) +
      card('Outcome', chartSlot({ type: 'donut', h: 150, legendRight: true, centerSub: 'checks', segments: stSegs })) +
    '</div>' +
    '<div class="rk-filters vf-filters">' +
      searchBox('vf-search', 'Search techniques or controls...', 'vfSearch') +
      vfSelectHtml('vf-f-status', 'vfSetStatus', 'Result', 'All results', M.statusOptions(items), VF.f.status) +
      vfSelectHtml('vf-f-domain', 'vfSetDomain', 'Control', 'All controls', doms, VF.f.domain) +
      '<button type="button" id="vf-clear" class="btn btn-ghost" hidden' + on('click', 'vfClearFilters') + '>' + icon('x') + 'Clear</button>' +
    '</div>' +
    '<div id="vf-table-host"></div>';
  var s = document.getElementById('vf-search'); if (s) s.value = VF.f.q;
  vfPaintHost();
}

// ── Table ────────────────────────────────────────────────────────────────────
function ico(d) { return '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>'; }

function skeletonHtml() {
  return '<div class="rk-card runs-card vf-card"><div class="runs-dt">' +
    '<div class="dt-toolbar" id="vf-dt-toolbar">' +
      '<span class="dt-count muted" id="vf-dt-count"></span><span class="grow"></span>' +
      '<div class="dt-colwrap"><button type="button" class="btn btn-outline btn-sm"' + on('click', 'vfToggleCols') + '>' + ico('<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>') + 'Columns</button><div class="dt-cols" id="vf-cols" hidden></div></div>' +
      '<select id="vf-dt-per" class="dt-per" aria-label="Rows per page"' + on('change', 'vfSetPer') + '><option value="5">5 / page</option><option value="8">8 / page</option><option value="15">15 / page</option><option value="9999">All rows</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'vfExportCsv') + '>' + ico('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export CSV</button></div>' +
    '<div class="dt-bulk" id="vf-bulk" hidden><b id="vf-bulk-n">0</b><span>selected</span><span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'vfExportSelected') + '>Export selected</button><button type="button" class="btn btn-ghost btn-sm"' + on('click', 'vfClearSelection') + '>Clear selection</button></div>' +
    '<div class="tbl-wrap dt-scroll" id="vf-table-wrap"><table class="g3-vf"><thead id="vf-thead"></thead><tbody id="vf-body"></tbody></table></div>' +
    '<div class="dt-empty" id="vf-empty" hidden></div>' +
    '<div class="dt-foot" id="vf-dt-foot"><span class="dt-range muted" id="vf-dt-range"></span><div class="dt-pager" id="vf-dt-pager"></div></div>' +
    '</div></div>';
}

function visibleCols() { return M.COLUMNS.map(function(c, i) { return i; }).filter(function(i) { return !T.hidden[i]; }); }
function pageItems() { return M.filterItems(VF.items, VF.f); }
function currentList() { return M.sortItems(M.tableFilter(pageItems(), T.q), T.col, T.dir); }
function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function setText(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; }

function cellHtml(col, i) {
  switch (col) {
    case 0: {
      var wf = i.workflowState === 'Rejected' ? '<div class="tiny muted">Rejected by reviewer</div>' : '';
      return '<td>' + pill(M.statusText(i.status), M.TONE[i.status] || 'warn') + wf + '</td>';
    }
    case 1: return '<td class="mono muted">' + x(i.techniqueId) + '</td>';
    case 2: return '<td><b>' + x(i.providerDisplay || i.provider) + '</b></td>';
    case 3: return '<td class="cap muted">' + x(i.domain) + '</td>';
    case 4: return '<td class="cap">' + x(i.confidence) + '</td>';
    case 5: return '<td>' + (i.verifiedBy ? x(i.verifiedBy) : '<span class="muted">—</span>') + '</td>';
    default: return '<td>' + (i.evidenceCount ? '<span class="rk-chip tone-accent">' + x(i.evidenceCount) + ' file' + (i.evidenceCount === 1 ? '' : 's') + '</span>' : '<span class="muted">—</span>') + '</td>';
  }
}

// Page filters changed: rebuild the table card (the search / select bar above it is left alone).
function vfPaintHost() {
  var host = document.getElementById('vf-table-host');
  if (!host) return;
  setHidden('vf-clear', !(VF.f.q || VF.f.status || VF.f.domain));
  if (!pageItems().length) {
    host.innerHTML = card('', empty('search', 'No checks match', 'Clear the filters.'));
    return;
  }
  host.innerHTML = skeletonHtml();
  var per = document.getElementById('vf-dt-per'); if (per) per.value = String(T.per);
  paintTable();
}

function paintTable() {
  var tbody = document.getElementById('vf-body');
  if (!tbody) return;
  var base = pageItems();
  var list = currentList();
  var pages = M.pageCount(list.length, T.per);
  T.page = Math.min(Math.max(0, T.page), pages - 1);
  var start = T.page * T.per;
  var rows = list.slice(start, start + T.per);
  var cols = visibleCols();
  var idx = function(i) { return VF.items.indexOf(i); };
  var onList = list.filter(function(i) { return T.sel[idx(i)]; }).length;
  document.getElementById('vf-thead').innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="vf-sel-all" title="Select all on this table"' + on('change', 'vfSelectAll') + '></th>' +
    cols.map(function(c) {
      return '<th class="dt-th' + (c === 6 ? ' num' : '') + (T.col === c ? ' sorted' : '') + '"' + on('click', 'vfSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '<th></th></tr>';
  var all = document.getElementById('vf-sel-all');
  if (all) { all.checked = list.length > 0 && onList === list.length; all.indeterminate = onList > 0 && onList < list.length; }
  tbody.innerHTML = rows.map(function(i) {
    var k = idx(i);
    return '<tr class="vf-row dt-click' + (VF.selected === i.expectationId ? ' vf-sel' : '') + '" tabindex="0"' + on('click', 'vfSelect', i.expectationId) + on('keydown', 'vfRowKeydown', i.expectationId) + '>' +
      '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select expectation"' + (T.sel[k] ? ' checked' : '') + on('change', 'vfSelectRow', k) + '></td>' +
      cols.map(function(c) { return cellHtml(c, i); }).join('') +
      '<td class="r"><button type="button" class="btn btn-outline btn-sm">' + (i.verificationId ? 'Review' : 'Verify') + '</button></td></tr>';
  }).join('');
  var menu = document.getElementById('vf-cols');
  if (menu) {
    menu.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'vfColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = Object.keys(T.sel).length;
  setHidden('vf-bulk', selN === 0);
  setText('vf-bulk-n', String(selN));
  setText('vf-dt-count', list.length + ' of ' + base.length + ' rows');
  setText('vf-dt-range', M.rangeText(list.length, T.page, T.per));
  var pager = document.getElementById('vf-dt-pager');
  if (pager) {
    pager.innerHTML = pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'vfPage', -1) + (T.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (T.page + 1) + ' / ' + pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'vfPage', 1) + (T.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('vf-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try different filters.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'vfClearFilters') + '>Clear filters</button></div>';
  }
  setHidden('vf-table-wrap', !list.length);
  setHidden('vf-dt-foot', !list.length);
}

// ── Table controls ──
export function vfTableQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; paintTable(); }
export function vfClearTableQuery() { T.q = ''; T.page = 0; var q = document.getElementById('vf-dt-q'); if (q) q.value = ''; paintTable(); }
export function vfSetPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; paintTable(); }
export function vfPage(d) { T.page += Number(d) || 0; paintTable(); }
export function vfSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  paintTable();
}
export function vfToggleCols() { var m = document.getElementById('vf-cols'); if (m) m.hidden = !m.hidden; }
export function vfColToggle(col, el) {
  col = Number(col);
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  paintTable();
}
export function vfSelectRow(k, el) { if (el && el.checked) T.sel[k] = true; else delete T.sel[k]; paintTable(); }
export function vfSelectAll(el) {
  currentList().forEach(function(i) { var k = VF.items.indexOf(i); if (el && el.checked) T.sel[k] = true; else delete T.sel[k]; });
  paintTable();
}
export function vfClearSelection() { T.sel = {}; paintTable(); }
export function vfRowKeydown(expId, el, event) {
  if (event && (event.key === 'Enter' || event.key === ' ') && event.target === el) { event.preventDefault(); vfSelect(expId); }
}

function exportVf(onlySelected) {
  var rows = onlySelected ? VF.items.filter(function(i, k) { return T.sel[k]; }) : currentList();
  var cols = visibleCols();
  var csv = M.csvText(cols.map(function(c) { return M.COLUMNS[c]; }), rows.map(function(i) {
    return cols.map(function(c) { return M.cellText(i, c); });
  }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'verification-expectations.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function vfExportCsv() { exportVf(false); }
export function vfExportSelected() { exportVf(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('vf-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});

function vfItem(expId) { for (var i=0;i<VF.items.length;i++){ if (VF.items[i].expectationId===expId) return VF.items[i]; } return null; }

// What the reviewer's state means, in words: Approved is final, Needs review waits for a reviewer, Rejected was sent back.
function vfStateNote(i) {
  if (i.workflowState === 'NeedsReview') return 'Waiting for a reviewer' + (i.verifiedBy ? ' · submitted by ' + i.verifiedBy : '');
  if (i.workflowState === 'Rejected') return 'Rejected by a reviewer' + (i.verifiedBy ? ' · attested by ' + i.verifiedBy : '');
  return i.verifiedBy ? 'Attested by ' + i.verifiedBy : 'Not attested yet';
}

// The key / value block; repainted alone after an upload so the evidence count is never stale.
function vfPaintFacts() {
  var i = vfItem(VF.selected);
  var host = document.getElementById('vf-facts');
  if (!i || !host) return;
  host.innerHTML = '<div class="vf-dr-state">' + pill(M.statusText(i.status), M.TONE[i.status] || 'warn') + '<span class="muted">' + x(vfStateNote(i)) + '</span></div>' + kv(M.drawerRows(i));
}

// The detail drawer: one expectation's facts plus the attestation form, evidence and history.
export function vfSelect(expId) {
  VF.selected = expId;
  var i = vfItem(expId);
  var host = document.getElementById('vf-detail');
  if (!i || !host) return;
  var canVerify = vfCan('verification:verify');
  var canReview = vfCan('verification:review');
  var resultBtn = function(val, label, tone) {
    return '<button type="button" id="vf-res-' + val + '"' + on('click', 'vfPickResult', val) + ' class="vf-res-btn tone-' + tone + '" aria-pressed="false">' + label + '</button>';
  };
  var evSection = i.verificationId
    ? '<h4 class="sec-label">Evidence <span class="vf-sec-note">SHA-256 recorded at upload</span></h4>' +
        '<div id="vf-evlist" class="vf-evlist"></div>' +
        (vfCan('verification:evidence:upload')
          ? '<div class="vf-up"><label class="vf-file"><input type="file" id="vf-evfile"' + on('change', 'vfFileChosen') + '><span class="btn btn-outline btn-sm">Choose file</span><span class="vf-fname muted" id="vf-evname">No file chosen. Up to 25 MB.</span></label>' +
            '<button type="button" id="vf-attach" class="btn btn-primary btn-sm" disabled' + on('click', 'vfUploadEvidence', i.verificationId) + '>Attach</button></div>'
          : '<div class="vf-help">You do not have permission to upload evidence.</div>')
    : '<h4 class="sec-label">Evidence</h4><div class="vf-help">Save the attestation first, then attach evidence here (screenshots, exported alerts, KQL, CSV).</div>';
  var set = function(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; };
  set('vf-drawer-title', i.providerDisplay || i.provider || 'Expectation');
  set('vf-drawer-sub', (i.techniqueId || '') + ' · ' + (i.domain || ''));
  host.innerHTML =
    '<div id="vf-facts"></div>' +
    (i.profileName ? '<div class="vf-help">Validated against <strong>' + x(i.profileName) + '</strong> v' + (i.profileVersion||1) + ' · expectation <code>' + x(i.expectationId) + '</code></div>' : '') +
    '<h4 class="sec-label">Attestation</h4>' +
    (canVerify
      ? '<div class="vf-lbl">Result</div>' +
        '<div class="vf-res">' + resultBtn('Detected', 'Detected', 'ok') + resultBtn('NotDetected', 'Not detected', 'bad') + resultBtn('NotApplicable', 'Not applicable', 'muted') + '</div>' +
        '<label class="vf-lbl" for="vf-alert">Linked alert or ticket ID <span class="vf-opt">optional</span></label>' +
        '<input id="vf-alert" class="inp-sm u-w100" autocomplete="off" placeholder="e.g. INC-1042" value="' + x(i.alertId||'') + '">' +
        '<label class="vf-lbl" for="vf-note">Analyst note</label>' +
        '<textarea id="vf-note" class="vf-note" placeholder="What did you check, and what did you see?">' + x(i.note||'') + '</textarea>' +
        '<input type="hidden" id="vf-result" value="' + x(i.result||'') + '">' +
        '<div class="vf-actions">' +
          (canReview
            ? '<button type="button" class="btn btn-primary btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'Approved') + '>Approve &amp; save</button>' +
              '<button type="button" class="btn btn-outline btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'NeedsReview') + '>Submit for review</button>' +
              '<button type="button" class="btn btn-outline-red btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'Rejected') + '>Reject</button>'
            : '<button type="button" class="btn btn-primary btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'NeedsReview') + '>Submit for review</button>') +
        '</div>' +
        '<div class="vf-help">' + (canReview
          ? '<b>Approve</b> records this result as final. <b>Submit for review</b> asks another reviewer to confirm it. <b>Reject</b> sends it back as not accepted.'
          : 'A reviewer approves your result before it counts as final.') + ' Every attestation is kept in the history.</div>'
      : '<div class="vf-help">You do not have permission to attest this result.</div>') +
    evSection +
    '<h4 class="sec-label">History <span class="vf-sec-note">immutable</span></h4><div id="vf-history"><div class="vf-help">Loading history…</div></div>';
  vfPaintFacts();
  if (i.result) vfPickResult(i.result);
  if (i.verificationId) vfLoadEvidence(i.verificationId);
  vfLoadHistory(i.expectationId);
  var o = document.getElementById('vf-drawer-overlay');
  if (o) o.classList.add('open');
  // keep the open row highlighted without repainting the table
  Array.prototype.forEach.call(document.querySelectorAll('#vf-body tr.vf-row'), function(tr) { tr.classList.remove('vf-sel'); });
  var rows = document.querySelectorAll('#vf-body tr.vf-row');
  Array.prototype.forEach.call(rows, function(tr) { if (tr.getAttribute('data-args') === JSON.stringify([expId])) tr.classList.add('vf-sel'); });
}

export function vfCloseDetail() {
  VF.selected = '';
  var h = document.getElementById('vf-detail'); if (h) h.innerHTML = '';
  var o = document.getElementById('vf-drawer-overlay'); if (o) o.classList.remove('open');
  Array.prototype.forEach.call(document.querySelectorAll('#vf-body tr.vf-sel'), function(tr) { tr.classList.remove('vf-sel'); });
}
export function vfDrawerBackdrop(el, event) { if (event.target === el) vfCloseDetail(); }

export function vfPickResult(val) {
  var hid = document.getElementById('vf-result');
  if (hid) hid.value = val;
  ['Detected','NotDetected','NotApplicable'].forEach(function(v) {
    var b = document.getElementById('vf-res-' + v);
    if (!b) return;
    b.classList.toggle('on', v === val);
    b.setAttribute('aria-pressed', v === val ? 'true' : 'false');
  });
}

var vfSaving = false;
export function vfSubmit(expId, workflowState) {
  if (vfSaving) return;
  var result = (document.getElementById('vf-result') || {}).value || '';
  if (!result) { showToast('Pick a result (Detected, Not detected or Not applicable) first.', 'err'); return; }
  var note = (document.getElementById('vf-note') || {}).value || '';
  var alertId = (document.getElementById('vf-alert') || {}).value || '';
  var hadEvidence = !!(vfItem(expId) || {}).verificationId;
  vfSaving = true;
  var btns = document.querySelectorAll('#vf-detail .vf-actions button');
  Array.prototype.forEach.call(btns, function(b) { b.disabled = true; });
  apicallOk('/api/verifications', { method:'POST', body: JSON.stringify({
    runId: VF.runId, expectationId: expId, result: result,
    workflowState: workflowState, note: note, alertId: alertId
  })}).then(function() {
    vfSaving = false;
    var verb = workflowState === 'Approved' ? 'Attestation approved and saved.' : workflowState === 'Rejected' ? 'Attestation rejected.' : 'Submitted for review.';
    showToast(verb + (hadEvidence ? '' : ' You can attach evidence below.'), 'ok');
    // Reload in place and reopen the same expectation, so evidence can be attached straight away.
    return vfReloadQuiet().then(function() { if (VF.runId && vfItem(expId)) vfSelect(expId); });
  }).catch(function(e) {
    vfSaving = false;
    Array.prototype.forEach.call(btns, function(b) { b.disabled = false; });
    showToast('Could not save: ' + (e.message || 'error'), 'err');
  });
}

export function vfFileChosen(el) {
  var f = el && el.files && el.files[0];
  var n = document.getElementById('vf-evname'); if (n) n.textContent = f ? f.name + ' · ' + vfBytes(f.size) : 'No file chosen. Up to 25 MB.';
  var b = document.getElementById('vf-attach'); if (b) b.disabled = !f;
}

var vfUploading = false;
export function vfUploadEvidence(verificationId) {
  var inp = document.getElementById('vf-evfile');
  if (!inp || !inp.files || !inp.files.length) { showToast('Choose a file first.', 'err'); return; }
  if (vfUploading) return;
  if (inp.files[0].size > 25 * 1024 * 1024) { showToast(inp.files[0].name + ' is ' + vfBytes(inp.files[0].size) + '. The limit is 25 MB.', 'err'); return; }
  vfUploading = true;
  var btn = document.getElementById('vf-attach'); if (btn) { btn.disabled = true; btn.textContent = 'Uploading…'; }
  var fd = new FormData();
  fd.append('file', inp.files[0]);
  fetch('/api/verifications/' + encodeURIComponent(verificationId) + '/evidence', {
    method:'POST', credentials:'same-origin', body: fd
  }).then(function(r) {
    // A proxy may answer an oversized upload with a non-JSON page, so the body is read as text first.
    return r.text().then(function(t) { var j = null; try { j = JSON.parse(t); } catch (e) { j = null; } return { ok: r.ok, status: r.status, j: j }; });
  }).then(function(res) {
    vfUploading = false;
    if (btn) btn.textContent = 'Attach';
    if (!res.ok) {
      if (btn) btn.disabled = false;
      showToast('Upload failed: ' + ((res.j && res.j.error) || ('the server answered ' + res.status)), 'err');
      return;
    }
    showToast('Evidence attached. SHA-256 ' + ((res.j && res.j.contentHash) || '').substring(0, 12) + '…', 'ok');
    inp.value = ''; vfFileChosen(inp);
    vfLoadEvidence(verificationId);
    vfReloadQuiet();
  }).catch(function(e) {
    vfUploading = false;
    if (btn) { btn.disabled = false; btn.textContent = 'Attach'; }
    showToast('Upload failed: ' + (e.message || 'network error'), 'err');
  });
}

function vfLoadEvidence(verificationId) {
  var host = document.getElementById('vf-evlist');
  if (!host) return;
  apicallOk('/api/verifications/' + encodeURIComponent(verificationId) + '/evidence').then(function(d) {
    var list = (d && d.evidence) || [];
    if (!list.length) { host.innerHTML = '<div class="vf-help">No evidence attached yet.</div>'; return; }
    var canDel = vfCan('verification:evidence:delete');
    host.innerHTML = list.map(function(e) {
      var name = e.displayFilename || e.originalFilename;
      return '<div class="vf-ev">' +
        '<span class="vf-ev-ok" aria-hidden="true">&#10003;</span>' +
        '<div class="vf-ev-main"><a href="/api/evidence/' + encodeURIComponent(e.id) + '/download" class="vf-ev-name" title="' + x(name) + '">' + x(name) + '</a>' +
          '<div class="tiny muted">' + vfBytes(e.size) + ' · <span class="mono" title="' + x(e.hashAlgorithm) + ': ' + x(e.contentHash) + '">' + x((e.contentHash||'').substring(0,12)) + '…</span>' + (e.uploadedBy ? ' · ' + x(e.uploadedBy) : '') + '</div></div>' +
        (canDel ? '<button type="button" class="btn btn-outline-red btn-sm"' + on('click', 'vfDeleteEvidence', e.id, verificationId, name) + '>Delete</button>' : '') +
        '</div>';
    }).join('');
  }).catch(function(e) { host.innerHTML = '<div class="vf-help vf-bad">Failed to load evidence: ' + x(e.message || 'error') + '</div>'; });
}

function vfBytes(n) {
  n = n || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/1024/1024).toFixed(1) + ' MB';
}

export function vfDeleteEvidence(id, verificationId, name) {
  openConfirmDiffModal('Delete this evidence file?',
    '<p class="tiny"><b>' + x(name || 'This file') + '</b> is hidden from the report and from this list. It is retained for audit, so the deletion is recorded.</p>',
    function() {
      apicallOk('/api/evidence/' + encodeURIComponent(id), { method:'DELETE' }).then(function() {
        showToast('Evidence deleted.', 'ok');
        vfLoadEvidence(verificationId);
        vfReloadQuiet();
      }).catch(function(e) { showToast('Could not delete: ' + (e.message || 'error'), 'err'); });
    }, { sub: 'The file stays in the audit trail.', confirmLabel: 'Delete file', danger: true });
}

// History loads with the drawer (it is short, and an analyst needs to see it before attesting again).
function vfLoadHistory(expId) {
  var host = document.getElementById('vf-history');
  if (!host) return;
  apicallOk('/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications/' + encodeURIComponent(expId) + '/history').then(function(d) {
    if (VF.selected !== expId) return;
    var h = (d && d.history) || [];
    if (!h.length) { host.innerHTML = '<div class="vf-help">No attestations recorded yet.</div>'; return; }
    host.innerHTML = h.map(function(r) {
      return '<div class="vf-hist' + (r.active ? ' cur' : '') + '">' +
        '<span class="vf-hist-res" style="color:' + vfStatusColor(r.active ? (r.workflowState==='Approved'?r.result:r.workflowState) : r.result) + '">' + x(M.statusText(r.result)) + '</span>' +
        '<span class="muted">' + x(r.workflowState === 'NeedsReview' ? 'Needs review' : r.workflowState) + (r.source ? ' · ' + x(r.source) : '') + '</span>' +
        '<span class="vf-hist-who muted">' + x(r.verifiedBy||'') + ' · ' + fmtDate(r.verifiedAt) + '</span>' +
        '<span class="' + (r.active ? 'u-success' : 'muted') + '">' + (r.active ? 'current' : 'superseded') + '</span>' +
        '</div>';
    }).join('');
  }).catch(function(e) { host.innerHTML = '<div class="vf-help vf-bad">Failed to load history: ' + x(e.message || 'error') + '</div>'; });
}
// Kept for the action registry; the history is always shown now.
export function vfToggleHistory() {}
