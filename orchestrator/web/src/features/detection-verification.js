import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { card, grid, hbars, pill, empty, kv, icon, searchBox } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { hbarRows } from './rich-g3.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './ver-model.js';


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
  if (!VF.perms) {
    apicall('/api/me/permissions').then(function(d) {
      VF.perms = (d && d.permissions) || [];
    }).catch(function(){ VF.perms = []; });
  }
  // Populate the run selector (reuse the runs list).
  apicall('/api/scenarios/runs').then(function(runs) {
    var sel = document.getElementById('vf-run');
    if (!sel) return;
    var cur = VF.runId;
    var opts = '<option value="">Select a run…</option>' + (runs || []).map(function(r) {
      var label = (r.name || r.id) + ' · ' + (r.agentId || '') + ' · ' + fmtDate(r.startedAt);
      return '<option value="' + x(r.id) + '"' + (r.id === cur ? ' selected' : '') + '>' + x(label) + '</option>';
    }).join('');
    sel.innerHTML = opts;
    if (cur) vfLoadQueue();
  }).catch(function(e){ showToast(e.message, 'err'); });
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

export function vfLoadQueue() {
  var sel = document.getElementById('vf-run');
  var runId = sel ? sel.value : '';
  if (runId !== VF.runId) {
    VF.f = { q: '', status: '', domain: '' };
    T = { q: '', col: -1, dir: 1, page: 0, per: T.per, sel: {}, hidden: T.hidden };
  }
  VF.runId = runId;
  VF.selected = '';
  vfCloseDetail();
  var box = document.getElementById('vf-queue');
  if (!box) return;
  if (!VF.runId) { vfHero(null); box.innerHTML = card('', empty('check', 'Select a run', 'Pick a run above to load its pending verifications.')); return; }
  box.innerHTML = card('', empty('refresh', 'Loading…'));
  var q = '/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications';
  apicall(q).then(function(d) {
    if (d && d.error) { vfHero(null); box.innerHTML = card('', empty('alert', 'Could not load verifications', d.error)); return; }
    VF.items = (d && d.items) || [];
    vfRenderQueue();
  }).catch(function(e){ vfHero(null); box.innerHTML = card('', empty('alert', 'Could not load verifications', e.message)); });
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
      '<label class="dt-search">' + ico('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>') + '<input type="search" id="vf-dt-q" placeholder="Filter rows…" aria-label="Filter rows"' + on('input', 'vfTableQuery') + '></label>' +
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
      var wf = (i.workflowState && i.workflowState !== 'Approved' && i.workflowState !== 'Pending') ? '<div class="tiny muted">' + x(i.workflowState) + '</div>' : '';
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
  var q = document.getElementById('vf-dt-q'); if (q) q.value = T.q;
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
    return '<tr class="vf-row dt-click" tabindex="0"' + on('click', 'vfSelect', i.expectationId) + on('keydown', 'vfRowKeydown', i.expectationId) + '>' +
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
    if (!list.length) emp.innerHTML = empty('search', 'No matching rows', 'Try a different search term, or clear the filter.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'vfClearTableQuery') + '>Clear filter</button></div>';
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

// The detail drawer: one expectation's facts plus the attestation form, evidence and history.
export function vfSelect(expId) {
  VF.selected = expId;
  var i = vfItem(expId);
  var host = document.getElementById('vf-detail');
  if (!i || !host) return;
  var canVerify = vfCan('verification:verify');
  var canReview = vfCan('verification:review');
  var resultBtn = function(val, label, col) {
    return '<button type="button" id="vf-res-' + val + '"' + on('click', 'vfPickResult', val) + ' class="btn btn-outline btn-sm" style="border-color:' + col + ';color:' + col + '">' + label + '</button>';
  };
  var evSection = i.verificationId
    ? '<div style="margin-top:0.9rem"><div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.04em;color:var(--muted);margin-bottom:0.4rem">Evidence <span style="text-transform:none;color:var(--muted)">— SHA-256 recorded at upload</span></div>' +
        '<div id="vf-evlist" style="margin-bottom:0.5rem"></div>' +
        (vfCan('verification:evidence:upload')
          ? '<input type="file" id="vf-evfile" style="font-size:0.78rem"> <button class="btn btn-outline btn-sm"' + on('click', 'vfUploadEvidence', i.verificationId) + '>Attach</button>'
          : '<div style="font-size:0.74rem;color:var(--muted)">You do not have permission to upload evidence.</div>') +
        '</div>'
    : '<div style="margin-top:0.9rem;font-size:0.74rem;color:var(--muted)">Save a verification first, then attach evidence (screenshots, exported alerts, KQL, CSV).</div>';
  var set = function(id, t) { var e = document.getElementById(id); if (e) e.textContent = t; };
  set('vf-drawer-title', i.providerDisplay || i.provider || 'Expectation');
  set('vf-drawer-sub', (i.techniqueId || '') + ' · ' + (i.domain || ''));
  host.innerHTML =
    '<div class="vf-dr-state">' + pill(M.statusText(i.status), M.TONE[i.status] || 'warn') + '<span class="muted">' + x(i.workflowState && i.workflowState !== 'Approved' && i.workflowState !== 'Pending' ? i.workflowState : (i.verifiedBy ? 'Attested by ' + i.verifiedBy : 'Not attested yet')) + '</span></div>' +
    kv(M.drawerRows(i)) +
    (i.profileName ? '<div style="font-size:0.7rem;color:var(--muted);margin:0.6rem 0">Validated against <strong>' + x(i.profileName) + '</strong> v' + (i.profileVersion||1) + ' · expectation <code>' + x(i.expectationId) + '</code></div>' : '') +
    '<h4 class="sec-label">Attestation</h4>' +
    (canVerify
      ? '<div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.7rem">' + resultBtn('Detected','Detected','var(--success)') + resultBtn('NotDetected','Not Detected','var(--danger)') + resultBtn('NotApplicable','N/A','var(--muted)') + '</div>' +
        '<input id="vf-alert" placeholder="Linked alert / ticket ID (optional)" value="' + x(i.alertId||'') + '" style="width:100%;padding:0.45rem 0.6rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;font-size:0.8rem;margin-bottom:0.5rem">' +
        '<textarea id="vf-note" placeholder="Analyst note — what did you check, what did you see?" style="width:100%;min-height:56px;padding:0.45rem 0.6rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;font-size:0.8rem;margin-bottom:0.5rem">' + x(i.note||'') + '</textarea>' +
        '<input type="hidden" id="vf-result" value="' + x(i.result||'') + '">' +
        '<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">' +
          (canReview
            ? '<button class="btn btn-primary btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'Approved') + '>Approve &amp; Save</button>' +
              '<button class="btn btn-outline btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'NeedsReview') + '>Submit for Review</button>' +
              '<button class="btn btn-outline-red btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'Rejected') + '>Reject</button>'
            : '<button class="btn btn-primary btn-sm" ' + on('click', 'vfSubmit', i.expectationId, 'NeedsReview') + '>Submit for Review</button>') +
          '<span class="u-flex1"></span>' +
          '<button class="btn btn-outline btn-sm"' + on('click', 'vfToggleHistory', i.expectationId) + '>History</button>' +
        '</div>'
      : '<div style="font-size:0.78rem;color:var(--muted)">You do not have permission to verify. <button class="btn btn-outline btn-sm"' + on('click', 'vfToggleHistory', i.expectationId) + '>View History</button></div>') +
    evSection +
    '<div id="vf-history" style="margin-top:0.8rem"></div>';
  if (i.result) vfPickResult(i.result);
  if (i.verificationId) vfLoadEvidence(i.verificationId);
  var o = document.getElementById('vf-drawer-overlay');
  if (o) o.classList.add('open');
}

export function vfCloseDetail() {
  VF.selected = '';
  var h = document.getElementById('vf-detail'); if (h) h.innerHTML = '';
  var o = document.getElementById('vf-drawer-overlay'); if (o) o.classList.remove('open');
}
export function vfDrawerBackdrop(el, event) { if (event.target === el) vfCloseDetail(); }

export function vfPickResult(val) {
  var hid = document.getElementById('vf-result');
  if (hid) hid.value = val;
  ['Detected','NotDetected','NotApplicable'].forEach(function(v) {
    var b = document.getElementById('vf-res-' + v);
    if (b) b.style.background = v === val ? 'rgba(79,142,247,0.14)' : 'transparent';
    if (b) b.style.fontWeight = v === val ? '700' : '';
  });
}

export function vfSubmit(expId, workflowState) {
  var result = (document.getElementById('vf-result') || {}).value || '';
  if (!result) { showToast('Pick a result (Detected / Not Detected / N/A) first.', 'err'); return; }
  var note = (document.getElementById('vf-note') || {}).value || '';
  var alertId = (document.getElementById('vf-alert') || {}).value || '';
  apicall('/api/verifications', { method:'POST', body: JSON.stringify({
    runId: VF.runId, expectationId: expId, result: result,
    workflowState: workflowState, note: note, alertId: alertId
  })}).then(function(d) {
    if (d && d.error) { showToast(d.error, 'err'); return; }
    showToast('Verification saved.', 'ok');
    vfLoadQueue();
  }).catch(function(e){ showToast(e.message, 'err'); });
}

export function vfUploadEvidence(verificationId) {
  var inp = document.getElementById('vf-evfile');
  if (!inp || !inp.files || !inp.files.length) { showToast('Choose a file first.', 'err'); return; }
  var fd = new FormData();
  fd.append('file', inp.files[0]);
  fetch('/api/verifications/' + encodeURIComponent(verificationId) + '/evidence', {
    method:'POST', credentials:'same-origin', body: fd
  }).then(function(r){ return r.json().then(function(j){ return {ok:r.ok, j:j}; }); })
    .then(function(res) {
      if (!res.ok) { showToast((res.j && res.j.error) || 'Upload failed', 'err'); return; }
      showToast('Evidence attached — SHA-256 ' + (res.j.contentHash||'').substring(0,12) + '…', 'ok');
      inp.value = '';
      vfLoadEvidence(verificationId);
      // refresh counts in the queue silently
      vfLoadQueueQuiet();
    }).catch(function(e){ showToast(e.message, 'err'); });
}

function vfLoadQueueQuiet() {
  if (!VF.runId) return;
  var q = '/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications';
  apicall(q).then(function(d){ if (d && d.items) { VF.items = d.items; } }).catch(function(){});
}

function vfLoadEvidence(verificationId) {
  var host = document.getElementById('vf-evlist');
  if (!host) return;
  apicall('/api/verifications/' + encodeURIComponent(verificationId) + '/evidence').then(function(d) {
    var list = (d && d.evidence) || [];
    if (!list.length) { host.innerHTML = '<div style="font-size:0.74rem;color:var(--muted)">No evidence attached yet.</div>'; return; }
    var canDel = vfCan('verification:evidence:delete');
    host.innerHTML = list.map(function(e) {
      return '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.4rem 0.55rem;border:1px solid var(--border);border-radius:6px;margin-bottom:0.35rem;font-size:0.76rem">' +
        '<span class="u-success">&#10003;</span>' +
        '<a href="/api/evidence/' + encodeURIComponent(e.id) + '/download" style="color:var(--accent);text-decoration:none">' + x(e.displayFilename || e.originalFilename) + '</a>' +
        '<span class="u-muted">' + vfBytes(e.size) + '</span>' +
        '<span style="color:var(--muted);font-family:monospace;font-size:0.66rem" title="' + x(e.hashAlgorithm) + ': ' + x(e.contentHash) + '">' + x((e.contentHash||'').substring(0,12)) + '…</span>' +
        '<span class="u-flex1"></span>' +
        '<span style="color:var(--muted);font-size:0.68rem">' + x(e.uploadedBy||'') + '</span>' +
        (canDel ? '<button class="btn btn-outline-red btn-sm"' + on('click', 'vfDeleteEvidence', e.id, verificationId) + '>Delete</button>' : '') +
        '</div>';
    }).join('');
  }).catch(function(){ host.innerHTML = '<div style="font-size:0.74rem;color:var(--danger)">Failed to load evidence.</div>'; });
}

function vfBytes(n) {
  n = n || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/1024/1024).toFixed(1) + ' MB';
}

export function vfDeleteEvidence(id, verificationId) {
  if (!confirm('Soft-delete this evidence file? It is retained for audit but hidden from the report.')) return;
  apicall('/api/evidence/' + encodeURIComponent(id), { method:'DELETE' }).then(function(d) {
    if (d && d.error) { showToast(d.error, 'err'); return; }
    showToast('Evidence deleted.', 'ok');
    vfLoadEvidence(verificationId);
    vfLoadQueueQuiet();
  }).catch(function(e){ showToast(e.message, 'err'); });
}

export function vfToggleHistory(expId) {
  var host = document.getElementById('vf-history');
  if (!host) return;
  if (host.getAttribute('data-open') === expId) { host.innerHTML=''; host.removeAttribute('data-open'); return; }
  host.setAttribute('data-open', expId);
  host.innerHTML = '<div style="font-size:0.74rem;color:var(--muted)">Loading history…</div>';
  apicall('/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications/' + encodeURIComponent(expId) + '/history').then(function(d) {
    var h = (d && d.history) || [];
    if (!h.length) { host.innerHTML = '<div style="font-size:0.74rem;color:var(--muted)">No attestations recorded yet.</div>'; return; }
    host.innerHTML = '<div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.04em;color:var(--muted);margin-bottom:0.4rem">Attestation history (immutable)</div>' +
      h.map(function(r) {
        return '<div style="display:flex;gap:0.6rem;font-size:0.74rem;padding:0.35rem 0;border-bottom:1px solid var(--border)">' +
          '<span style="font-weight:700;color:' + vfStatusColor(r.active ? (r.workflowState==='Approved'?r.result:r.workflowState) : r.result) + '">' + x(r.result) + '</span>' +
          '<span class="u-muted">' + x(r.workflowState) + '</span>' +
          '<span class="u-muted">' + x(r.source) + '</span>' +
          '<span class="u-flex1"></span>' +
          '<span class="u-muted">' + x(r.verifiedBy||'') + '</span>' +
          '<span class="u-muted">' + fmtDate(r.verifiedAt) + '</span>' +
          (r.active ? '<span class="u-success">current</span>' : '<span class="u-muted">superseded</span>') +
          '</div>';
      }).join('');
  }).catch(function(){ host.innerHTML = '<div style="font-size:0.74rem;color:var(--danger)">Failed to load history.</div>'; });
}