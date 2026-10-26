import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { closeAllRowMenus } from './attack-path.js';
import { ROLE } from './shell.js';
import { kpi, grid, card, hbars, pill, empty, bar } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';


// ── Initiative Layer ─────────────────────────────────────────────────────
// Frontend for docs/superpowers/specs/2026-08-22-initiative-layer-ui-design.md.
// Field-casing note: the `initiative` and `progress` objects serialize with
// capitalized Go field names (no json tags, matching internal/jobs.Job's
// established convention) -- e.g. it.ID, it.State, progress.PercentComplete.
// The `jobs` array inside GET /api/initiatives/{id} is the one exception:
// it has explicit lowercase camelCase json tags (id/type/state/createdAt/
// completedAt). Verified against the actual Go source, not assumed.
var INITIATIVES = { list: [], all: null, filter: 'active' };

function initiativeTone(initState) {
  return initState === 'active' ? 'ok' : initState === 'closed' ? 'info' : 'muted';
}
// initiativeCounts: initiatives per state, for the summary strip.
export function initiativeCounts(list) {
  var c = { total: 0, active: 0, closed: 0, archived: 0, other: 0, byCreator: {} };
  (list || []).forEach(function(it) {
    c.total++;
    if (it.State === 'active' || it.State === 'closed' || it.State === 'archived') c[it.State]++; else c.other++;
    var who = it.CreatedBy || 'unknown';
    c.byCreator[who] = (c.byCreator[who] || 0) + 1;
  });
  return c;
}
export function initiativeStateLabel(initState) {
  if (initState === 'active') return 'Active';
  if (initState === 'closed') return 'Closed';
  if (initState === 'archived') return 'Archived';
  return x(initState);
}

export function initiativeSetFilter(initState) {
  INITIATIVES.filter = initState;
  document.querySelectorAll('#init-filter [data-init-filter]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-init-filter') === initState);
  });
  loadInitiatives();
}

export function loadInitiatives() {
  var q = INITIATIVES.filter === 'all' ? '' : ('?state=' + INITIATIVES.filter);
  apicall('/api/initiatives' + q).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    INITIATIVES.list = (res && res.initiatives) || [];
    INITIATIVES.all = INITIATIVES.filter === 'all' ? INITIATIVES.list : null;
    renderInitiativesList();
    if (INITIATIVES.filter !== 'all') {
      // The summary strip counts every state, so fetch the unfiltered list for it.
      apicall('/api/initiatives').then(function(all) {
        INITIATIVES.all = (all && all.initiatives) || INITIATIVES.list;
        renderInitiativesSummary();
      }).catch(function() { INITIATIVES.all = INITIATIVES.list; renderInitiativesSummary(); });
    }
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function renderInitiativesSummary() {
  var el = document.getElementById('init-summary');
  if (!el) return;
  var all = INITIATIVES.all || INITIATIVES.list;
  var c = initiativeCounts(all);
  if (!c.total) { el.innerHTML = ''; return; }
  var segs = [
    { label: 'Active', value: c.active, color: CHART_COLORS.ok },
    { label: 'Closed', value: c.closed, color: CHART_COLORS.info },
    { label: 'Archived', value: c.archived, color: CHART_COLORS.muted },
    { label: 'Other', value: c.other, color: CHART_COLORS.warn },
  ].filter(function(g) { return g.value > 0; });
  var creators = Object.keys(c.byCreator).sort(function(p, q) { return c.byCreator[q] - c.byCreator[p]; }).slice(0, 5);
  el.innerHTML = grid(4, [
    kpi({ label: 'Initiatives', value: c.total, icon: 'flag', tone: 'accent' }),
    kpi({ label: 'Active', value: c.active, icon: 'play', tone: 'ok' }),
    kpi({ label: 'Closed', value: c.closed, icon: 'ok', tone: 'info' }),
    kpi({ label: 'Archived', value: c.archived, icon: 'file', tone: 'muted' }),
  ]) + grid(2, [
    card('By state', chartSlot({ type: 'donut', segments: segs, center: String(c.total), centerSub: 'initiatives', legend: true, h: 150 })),
    card('Created by', hbars(creators.map(function(n) { return [n, c.byCreator[n] / c.total * 100, 'accent', c.byCreator[n]]; }))),
  ]);
}

function renderInitiativesList() {
  document.getElementById('init-cnt').textContent = INITIATIVES.list.length;
  renderInitiativesSummary();
  var tbody = document.getElementById('init-body');
  if (!INITIATIVES.list.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">' + empty('flag', 'No initiatives yet', 'An initiative groups related remediation jobs and tracks their overall progress.') + '</td></tr>';
    return;
  }
  tbody.innerHTML = INITIATIVES.list.map(function(it, idx) {
    var menuId = 'init-menu-' + idx;
    var canDelete = it.State === 'archived' && ROLE === 'admin';
    return '<tr' + on('click', 'openInitiativeDrawer', it.ID) + ' class="u-pointer">' +
      '<td><span class="rg2-cell-main">' + x(it.Name) + '</span></td>' +
      '<td>' + pill(initiativeStateLabel(it.State), initiativeTone(it.State)) + '</td>' +
      '<td>' + x(it.CreatedBy || '—') + '</td>' +
      '<td>' + x(fmtDate(it.CreatedAt)) + '</td>' +
      '<td' + on('click', 'stopEvent') + '>' +
        (canDelete ?
          '<div class="row-menu-wrap">' +
          '<button class="btn btn-outline btn-sm row-menu-btn"' + on('click', 'toggleRowMenuById', menuId) + ' title="Actions" aria-haspopup="true">&#8942;</button>' +
          '<div class="row-menu-panel" id="' + menuId + '">' +
            '<button class="row-menu-item row-menu-item-danger"' + on('click', 'initiativeDeleteFromMenu', it.ID, it.Name) + '>&#128465; Delete</button>' +
          '</div>' +
          '</div>' : '') +
      '</td>' +
    '</tr>';
  }).join('');
}

var INIT_CURRENT = null; // the currently-open drawer's Initiative object, or null

export function closeInitiativeDrawer() {
  document.getElementById('init-drawer-overlay').classList.remove('open');
  INIT_CURRENT = null;
}
export function closeInitiativeDrawerOnBackdrop(el, event) { if (event.target === el) closeInitiativeDrawer(); }

export function openInitiativeDrawer(id) {
  apicall('/api/initiatives/' + encodeURIComponent(id)).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    INIT_CURRENT = res.initiative;
    renderInitiativeDrawer(res.initiative, res.progress, res.jobs || []);
    document.getElementById('init-drawer-overlay').classList.add('open');
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function initiativeProgressCounts(p) {
  var parts = [p.Total + ' total'];
  if (p.Completed)  parts.push(p.Completed + ' completed');
  if (p.Running)    parts.push(p.Running + ' running');
  if (p.Requested)  parts.push(p.Requested + ' requested');
  if (p.Partial)    parts.push(p.Partial + ' partial');
  if (p.Failed)     parts.push(p.Failed + ' failed');
  if (p.Cancelled)  parts.push(p.Cancelled + ' cancelled');
  return parts.join(' · ');
}

function renderInitiativeDrawer(it, progress, jobs) {
  document.getElementById('init-drawer-title').textContent = it.Name;
  var pct = Math.round(progress.PercentComplete || 0);

  var canDetach = it.State !== 'archived';
  var jobRows = jobs.length
    ? jobs.map(function(j) {
        return '<tr>' +
          '<td class="tiny muted g1-s-82cece3f">' + x(j.id.slice(0, 8)) + '</td>' +
          '<td>' + x(j.type) + '</td>' +
          '<td><span class="badge">' + x(j.state) + '</span></td>' +
          '<td>' + x(fmtDate(j.createdAt)) + '</td>' +
          '<td>' + (j.completedAt ? x(fmtDate(j.completedAt)) : '—') + '</td>' +
          '<td>' + (canDetach ? '<button class="btn btn-outline btn-sm"' + on('click', 'initiativeDetachJob', j.id) + '>Detach</button>' : '') + '</td>' +
        '</tr>';
      }).join('')
    : '<tr><td colspan="6" class="empty">No jobs attached yet. This initiative tracks related remediation jobs and their overall progress.</td></tr>';

  document.getElementById('init-drawer-body').innerHTML =
    '<div class="u-mb-1">' +
      pill(initiativeStateLabel(it.State), initiativeTone(it.State)) + ' ' +
      '<span class="tiny muted">Created by ' + x(it.CreatedBy || '—') + ' · ' + x(fmtDate(it.CreatedAt)) + '</span>' +
    '</div>' +
    '<div class="g1-display-flex g1-s-de98f8b6">' +
      (it.State === 'active' ? '<button class="btn btn-outline btn-sm"' + on('click', 'initiativeCloseAction') + '>Close Initiative</button>' : '') +
      (it.State === 'closed' ? '<button class="btn btn-outline btn-sm"' + on('click', 'initiativeArchiveAction') + '>Archive Initiative</button>' : '') +
    '</div>' +
    '<div id="init-drawer-error" class="g1-s-6d6ac12c"></div>' +
    (it.Description ? '<p class="g1-s-691a68f3">' + x(it.Description) + '</p>' : '') +
    '<div class="rg2-gap">' +
      '<div class="rg2-progress"><span>Progress</span><b>' + pct + '%</b></div>' + bar(pct, pct >= 100 ? 'ok' : 'accent', true) +
      '<div class="tiny muted rg2-gap">' + x(initiativeProgressCounts(progress)) + '</div>' +
    '</div>' +
    '<div class="g1-display-flex g1-s-1bb6b069">' +
      '<h4 class="g1-s-4e9a1212">Jobs</h4>' +
      (it.State === 'active' ? '<button class="btn btn-outline btn-sm"' + on('click', 'openInitiativeAttachDrawer') + '>+ Attach Job</button>' : '') +
    '</div>' +
    '<div class="tbl-wrap"><table><thead><tr>' +
      '<th>ID</th><th>Type</th><th>State</th><th>Created</th><th>Completed</th><th></th>' +
    '</tr></thead><tbody>' + jobRows + '</tbody></table></div>';
}

export function initiativeDetachJob(jobId) {
  if (!INIT_CURRENT) return;
  if (!confirm('Detach this job from "' + INIT_CURRENT.Name + '"?')) return;
  initiativeShowDrawerError('');
  apicall('/api/jobs/' + encodeURIComponent(jobId) + '/initiative', {
    method: 'PATCH', body: JSON.stringify({ initiativeId: '' })
  }).then(function(res) {
    if (res && res.error) { initiativeShowDrawerError(res.error); return; }
    showToast('Job detached', 'ok');
    openInitiativeDrawer(INIT_CURRENT.ID); // re-fetch to refresh the jobs table + progress
  }).catch(function(e) { initiativeShowDrawerError(e.message); });
}

function initiativeShowDrawerError(msg) {
  var el = document.getElementById('init-drawer-error');
  if (el) el.innerHTML = msg ? '<div class="tiny u-danger">' + x(msg) + '</div>' : '';
}

export function initiativeCloseAction() {
  if (!INIT_CURRENT) return;
  initiativeShowDrawerError('');
  apicall('/api/initiatives/' + encodeURIComponent(INIT_CURRENT.ID) + '/close', { method: 'POST' }).then(function(res) {
    if (res && res.error) { initiativeShowDrawerError(res.error); return; }
    showToast('Initiative closed', 'ok');
    openInitiativeDrawer(INIT_CURRENT.ID); // re-fetch to refresh drawer state/buttons
    loadInitiatives(); // refresh the underlying list row
  }).catch(function(e) { initiativeShowDrawerError(e.message); });
}

export function initiativeArchiveAction() {
  if (!INIT_CURRENT) return;
  initiativeShowDrawerError('');
  apicall('/api/initiatives/' + encodeURIComponent(INIT_CURRENT.ID) + '/archive', { method: 'POST' }).then(function(res) {
    if (res && res.error) { initiativeShowDrawerError(res.error); return; }
    showToast('Initiative archived', 'ok');
    openInitiativeDrawer(INIT_CURRENT.ID);
    loadInitiatives();
  }).catch(function(e) { initiativeShowDrawerError(e.message); });
}

export function openInitiativeCreateDrawer() {
  document.getElementById('init-create-name').value = '';
  document.getElementById('init-create-desc').value = '';
  document.getElementById('init-create-error').innerHTML = '';
  document.getElementById('init-create-overlay').classList.add('open');
}

export function closeInitiativeCreateDrawer() {
  document.getElementById('init-create-overlay').classList.remove('open');
}
export function closeInitiativeCreateDrawerOnBackdrop(el, event) { if (event.target === el) closeInitiativeCreateDrawer(); }

export function submitInitiativeCreate() {
  var name = document.getElementById('init-create-name').value.trim();
  var errEl = document.getElementById('init-create-error');
  if (!name) {
    errEl.innerHTML = '<div class="tiny u-danger">Name is required.</div>';
    return;
  }
  errEl.innerHTML = '';
  var desc = document.getElementById('init-create-desc').value.trim();
  apicall('/api/initiatives', { method: 'POST', body: JSON.stringify({ name: name, description: desc }) }).then(function(res) {
    if (res && res.error) { errEl.innerHTML = '<div class="tiny u-danger">' + x(res.error) + '</div>'; return; }
    showToast('Initiative created', 'ok');
    closeInitiativeCreateDrawer();
    loadInitiatives();
    openInitiativeDrawer(res.initiative.ID); // jump straight in -- an empty just-created record has nothing useful to show on the list
  }).catch(function(e) { errEl.innerHTML = '<div class="tiny u-danger">' + x(e.message) + '</div>'; });
}

export function initiativeDeleteFromMenu(id, name) {
  closeAllRowMenus();
  initiativeDeleteAction(id, name);
}

export function initiativeAttachSelect(el) { state.INIT_ATTACH_SELECTED = el.value; }

export function initiativeDeleteAction(id, name) {
  if (!confirm('Delete "' + name + '"? This cannot be undone.')) return;
  apicall('/api/initiatives/' + encodeURIComponent(id), { method: 'DELETE' }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Initiative deleted', 'ok');
    loadInitiatives();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// Attach Job: fetches the unassigned-job pool once when the picker opens
// (INIT_ATTACH_POOL), then initiativeRenderAttachList() re-filters that
// already-fetched list in-memory on every keystroke -- no per-keystroke
// network call.
var INIT_ATTACH_POOL = [];


export function openInitiativeAttachDrawer() {
  if (!INIT_CURRENT) return;
  state.INIT_ATTACH_SELECTED = '';
  document.getElementById('init-attach-search').value = '';
  document.getElementById('init-attach-error').innerHTML = '';
  document.getElementById('init-attach-list').innerHTML = '<div class="tiny muted g1-s-d1aafd03">Loading…</div>';
  document.getElementById('init-attach-overlay').classList.add('open');
  apicall('/api/jobs?initiativeId=').then(function(res) {
    if (res && res.error) { document.getElementById('init-attach-list').innerHTML = '<div class="tiny g1-s-1bf97088">' + x(res.error) + '</div>'; return; }
    INIT_ATTACH_POOL = (res && res.jobs) || [];
    initiativeRenderAttachList();
  }).catch(function(e) { document.getElementById('init-attach-list').innerHTML = '<div class="tiny g1-s-1bf97088">' + x(e.message) + '</div>'; });
}

export function closeInitiativeAttachDrawer() {
  document.getElementById('init-attach-overlay').classList.remove('open');
}
export function closeInitiativeAttachDrawerOnBackdrop(el, event) { if (event.target === el) closeInitiativeAttachDrawer(); }

export function initiativeRenderAttachList() {
  var q = document.getElementById('init-attach-search').value.trim().toLowerCase();
  var filtered = INIT_ATTACH_POOL.filter(function(j) {
    return !q || j.id.toLowerCase().indexOf(q) !== -1 || j.type.toLowerCase().indexOf(q) !== -1;
  });
  var list = document.getElementById('init-attach-list');
  if (!filtered.length) {
    list.innerHTML = '<div class="tiny muted g1-s-d1aafd03">No unassigned jobs found.</div>';
    return;
  }
  list.innerHTML = filtered.map(function(j) {
    var checked = j.id === state.INIT_ATTACH_SELECTED ? 'checked' : '';
    return '<label class="g1-display-flex g1-s-870226af">' +
      '<input type="radio" name="init-attach-radio" value="' + x(j.id) + '" ' + checked + on('change', 'initiativeAttachSelect') + '>' +
      '<span class="g1-s-dbdd527f">' + x(j.id.slice(0, 8)) + '</span>' +
      '<span>' + x(j.type) + '</span>' +
      '<span class="badge">' + x(j.state) + '</span>' +
    '</label>';
  }).join('');
}

export function submitInitiativeAttach() {
  var errEl = document.getElementById('init-attach-error');
  if (!state.INIT_ATTACH_SELECTED) {
    errEl.innerHTML = '<div class="tiny u-danger">Select a job to attach.</div>';
    return;
  }
  errEl.innerHTML = '';
  apicall('/api/jobs/' + encodeURIComponent(state.INIT_ATTACH_SELECTED) + '/initiative', {
    method: 'PATCH', body: JSON.stringify({ initiativeId: INIT_CURRENT.ID })
  }).then(function(res) {
    if (res && res.error) { errEl.innerHTML = '<div class="tiny u-danger">' + x(res.error) + '</div>'; return; }
    showToast('Job attached', 'ok');
    closeInitiativeAttachDrawer();
    openInitiativeDrawer(INIT_CURRENT.ID);
  }).catch(function(e) { errEl.innerHTML = '<div class="tiny u-danger">' + x(e.message) + '</div>'; });
}