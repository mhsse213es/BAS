import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { closeAllRowMenus } from './attack-path.js';
import { ROLE } from './shell.js';
import { kpi, grid, bar, hbars, chip, pill, seg, empty, icon } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import { fmtStamp } from './sched-model.js';
import * as M from './init-model.js';


// ── Initiative Layer ─────────────────────────────────────────────────────
// Frontend for docs/superpowers/specs/2026-08-22-initiative-layer-ui-design.md.
// Field-casing note: the `initiative` and `progress` objects serialize with
// capitalized Go field names (no json tags, matching internal/jobs.Job's
// established convention) -- e.g. it.ID, it.State, progress.PercentComplete.
// The `jobs` array inside GET /api/initiatives/{id} is the one exception:
// it has explicit lowercase camelCase json tags (id/type/state/createdAt/
// completedAt). Verified against the actual Go source, not assumed.
//
// The cards show each initiative's job progress, which only GET /api/initiatives/{id} returns, so the
// page reads that endpoint for every initiative it lists (INITIATIVES.detail, newest answer wins).
var INITIATIVES = { list: [], all: null, filter: 'active', q: '', detail: {} };

function initiativeTone(initState) { return M.stateTone(initState); }
// initiativeCounts: initiatives per state (kept for callers and tests).
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
  loadInitiatives();
}
export function initiativeSearch(el) { INITIATIVES.q = (el && el.value) || ''; renderInitiativesList(); }
export function initiativeClearFilters() {
  INITIATIVES.q = '';
  var s = document.getElementById('init-search'); if (s) s.value = '';
  if (INITIATIVES.filter !== 'all') { initiativeSetFilter('all'); return; }
  renderInitiativesList();
}

export function loadInitiatives() {
  var q = INITIATIVES.filter === 'all' ? '' : ('?state=' + INITIATIVES.filter);
  apicall('/api/initiatives' + q).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    INITIATIVES.list = (res && res.initiatives) || [];
    INITIATIVES.all = INITIATIVES.filter === 'all' ? INITIATIVES.list : null;
    renderInitiativesList();
    if (INITIATIVES.filter !== 'all') {
      // The chips and the banner count every state, so fetch the unfiltered list for them.
      apicall('/api/initiatives').then(function(all) {
        INITIATIVES.all = (all && all.initiatives) || INITIATIVES.list;
        renderInitiativesList();
        loadProgress();
      }).catch(function() { INITIATIVES.all = INITIATIVES.list; renderInitiativesList(); loadProgress(); });
    } else {
      loadProgress();
    }
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// loadProgress: the job progress of every listed initiative (up to 60), then a repaint.
function loadProgress() {
  var seen = {};
  (INITIATIVES.all || INITIATIVES.list).concat(INITIATIVES.list).forEach(function(it) { seen[it.ID] = 1; });
  var ids = Object.keys(seen).slice(0, 60);
  if (!ids.length) return;
  Promise.all(ids.map(function(id) {
    return apicall('/api/initiatives/' + encodeURIComponent(id)).then(function(r) {
      if (r && r.progress) INITIATIVES.detail[id] = r.progress;
    }).catch(function() { /* a card without progress shows an em dash */ });
  })).then(renderInitiativesList);
}

function factsOf(it) { return M.facts(INITIATIVES.detail[it.ID]); }

function detailsFacts(list) {
  var out = {};
  (list || []).forEach(function(it) { var f = factsOf(it); if (f) out[it.ID] = f; });
  return out;
}

function renderInitiativesHero(all) {
  var h = M.heroStats(all, detailsFacts(all));
  setHeroStat('init-cnt', h.active);
  setHeroStat('init-hs-progress', h.avg === null ? '—' : h.avg + '%');
  setHeroStat('init-hs-risk', h.atRisk);
  setHeroStat('init-hs-jobs', h.jobs);
}

function renderInitiativesFilters(all) {
  var bar2 = document.getElementById('init-filters');
  if (bar2) bar2.hidden = !all.length;
  var el = document.getElementById('init-filter');
  if (el) {
    var c = M.chipCounts(all);
    el.innerHTML = all.length ? seg([
      { id: 'active', label: 'Active', count: c.active }, { id: 'closed', label: 'Closed', count: c.closed },
      { id: 'archived', label: 'Archived', count: c.archived }, { id: 'all', label: 'All', count: c.all },
    ], INITIATIVES.filter, 'initiativeSetFilter') : '';
  }
  var clr = document.getElementById('init-clear');
  if (clr) clr.hidden = !(INITIATIVES.q || INITIATIVES.filter !== 'active');
}

function avatar(name) { return '<span class="init-av">' + x(M.initials(name)) + '</span>'; }

function initiativeCard(it) {
  var f = factsOf(it);
  var st = M.status(it, f);
  var segs = M.strip(f, 36);
  var strip = '<div class="init-strip">' + (segs.length ? segs.map(function(k) { return '<i class="' + k + '"></i>'; }).join('') : '<i></i>') + '</div>';
  var line = f ? (f.completed + ' of ' + f.total + (f.total === 1 ? ' job' : ' jobs') + ' completed') : 'Progress loading…';
  var side = f ? (f.running ? icon('play') + ' ' + f.running + ' running' : icon('ok') + ' ' + f.completed + ' completed') : '';
  return '<div class="rk-card init-card" role="button" tabindex="0"' + on('click', 'openInitiativeDrawer', it.ID) + on('keydown', 'initiativeCardKeydown', it.ID) + '>' +
    '<div class="init-hd"><div class="init-hd-l"><h2>' + x(it.Name) + '</h2>' +
      '<div class="init-sub muted"><span class="mono">' + x(M.shortId(it.ID)) + '</span> · ' + avatar(it.CreatedBy) + ' ' + x(it.CreatedBy || '—') + '</div></div>' +
      '<div class="init-tags">' + chip(M.stateLabel(it.State), initiativeTone(it.State)) + (st ? pill(st.label, st.tone) : '') + '</div></div>' +
    '<p class="init-desc' + (it.Description ? '' : ' muted') + '">' + x(it.Description || 'No description.') + '</p>' +
    strip +
    '<div class="init-prog"><span>' + x(line) + '</span><span>' + (f ? f.pct + '%' : '—') + '</span></div>' +
    bar(f ? f.pct : 0, M.barTone(it, f)) +
    '<div class="init-facts"><span>' + icon('box') + ' ' + (f ? f.total + (f.total === 1 ? ' job' : ' jobs') : '— jobs') + '</span><span>' + side + '</span></div>' +
    '<div class="init-meta"><span>' + avatar(it.CreatedBy) + ' Created by ' + x(it.CreatedBy || '—') + '</span><span class="muted">' + x(fmtStamp(it.CreatedAt ? new Date(it.CreatedAt).getTime() : null)) + '</span></div>' +
    '</div>';
}

export function initiativeCardKeydown(id, el, e) {
  if (e && e.target !== el) return;
  if (e && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openInitiativeDrawer(id); }
}

function renderInitiativesList() {
  var all = INITIATIVES.all || INITIATIVES.list;
  renderInitiativesHero(all);
  renderInitiativesFilters(all);
  var list = M.search(INITIATIVES.list, INITIATIVES.q);
  var body = document.getElementById('init-body');
  var emp = document.getElementById('init-empty');
  if (!body) return;
  if (!list.length) {
    body.innerHTML = '';
    body.hidden = true;
    if (emp) {
      emp.hidden = false;
      emp.innerHTML = all.length
        ? empty('search', 'No initiatives match', 'Clear the filters to see everything.') + '<div class="init-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'initiativeClearFilters') + '>Clear filters</button></div>'
        : empty('flag', 'No initiatives yet', 'An initiative groups related remediation jobs and tracks their overall progress.');
    }
    return;
  }
  body.hidden = false;
  if (emp) { emp.hidden = true; emp.innerHTML = ''; }
  body.innerHTML = list.map(initiativeCard).join('');
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
    if (res.progress) { INITIATIVES.detail[res.initiative.ID] = res.progress; renderInitiativesList(); }
    renderInitiativeDrawer(res.initiative, res.progress, res.jobs || []);
    document.getElementById('init-drawer-overlay').classList.add('open');
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function renderInitiativeDrawer(it, progress, jobs) {
  var f = M.facts(progress) || M.facts({});
  var st = M.status(it, f);
  document.getElementById('init-drawer-title').textContent = it.Name;
  document.getElementById('init-drawer-sub').textContent = M.shortId(it.ID) + ' · ' + (it.CreatedBy || '—');

  var canDetach = it.State !== 'archived';
  var jobRows = jobs.length
    ? jobs.map(function(j) {
        return '<tr>' +
          '<td><b>' + x(j.type) + '</b><div class="mono muted init-jid">' + x(j.id.slice(0, 8)) + '</div></td>' +
          '<td>' + pill(M.stateLabel(j.state), M.jobTone(j.state)) + '</td>' +
          '<td class="muted">' + (j.completedAt ? x(fmtDate(j.completedAt)) : '—') + '</td>' +
          '<td class="init-jact">' + (canDetach ? '<button class="btn btn-outline btn-sm"' + on('click', 'initiativeDetachJob', j.id) + '>Detach</button>' : '') + '</td>' +
        '</tr>';
      }).join('')
    : '<tr><td colspan="4" class="empty">No jobs attached yet. This initiative tracks related remediation jobs and their overall progress.</td></tr>';

  var rows = M.stateRows(f);
  document.getElementById('init-drawer-body').innerHTML =
    '<div class="k8s-dr-top init-dr-top"><div class="init-dr-tags">' + pill(M.stateLabel(it.State), initiativeTone(it.State)) + (st ? pill(st.label, st.tone) : '') + '</div>' +
      '<span class="tiny muted">Created by ' + x(it.CreatedBy || '—') + ' · ' + x(fmtStamp(it.CreatedAt ? new Date(it.CreatedAt).getTime() : null)) + '</span></div>' +
    (it.Description ? '<p class="init-dr-desc">' + x(it.Description) + '</p>' : '') +
    '<div id="init-drawer-error" class="init-dr-err"></div>' +
    grid(3, [
      kpi({ label: 'Progress', value: f.pct + '%', icon: 'trend', tone: f.failed || f.partial ? 'warn' : 'accent' }),
      kpi({ label: 'Jobs', value: f.total, icon: 'box', tone: 'info' }),
      kpi({ label: 'Created', value: M.shortDate(it.CreatedAt), icon: 'clock', tone: 'warn' }),
    ]) +
    '<h4 class="sc-h4">Job states</h4>' +
    (rows.length ? hbars(rows) : '<div class="sc-sub">No jobs attached yet.</div>') +
    '<h4 class="sc-h4">Attached jobs</h4>' +
    '<div class="tbl-wrap init-dr-tbl"><table><thead><tr><th>Job</th><th>Status</th><th>Finished</th><th></th></tr></thead><tbody>' + jobRows + '</tbody></table></div>';

  var foot = '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'closeInitiativeDrawer') + '>Close</button><span class="grow"></span>';
  if (it.State === 'active') foot += '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'initiativeCloseAction') + '>Close Initiative</button>';
  if (it.State === 'closed') foot += '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'initiativeArchiveAction') + '>Archive Initiative</button>';
  if (it.State === 'archived' && ROLE === 'admin') foot += '<button type="button" class="btn btn-outline btn-sm init-del"' + on('click', 'initiativeDeleteFromMenu', it.ID, it.Name) + '>Delete</button>';
  if (it.State === 'active') foot += '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'openInitiativeAttachDrawer') + '>' + icon('plus') + 'Attach Job</button>';
  document.getElementById('init-drawer-foot').innerHTML = foot;
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
    loadInitiatives(); // refresh the underlying list
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
    closeInitiativeDrawer();
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
  document.getElementById('init-attach-list').innerHTML = '<div class="tiny muted init-attach-note">Loading…</div>';
  document.getElementById('init-attach-overlay').classList.add('open');
  apicall('/api/jobs?initiativeId=').then(function(res) {
    if (res && res.error) { document.getElementById('init-attach-list').innerHTML = '<div class="tiny u-danger init-attach-note">' + x(res.error) + '</div>'; return; }
    INIT_ATTACH_POOL = (res && res.jobs) || [];
    initiativeRenderAttachList();
  }).catch(function(e) { document.getElementById('init-attach-list').innerHTML = '<div class="tiny u-danger init-attach-note">' + x(e.message) + '</div>'; });
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
    list.innerHTML = '<div class="tiny muted init-attach-note">No unassigned jobs found.</div>';
    return;
  }
  list.innerHTML = filtered.map(function(j) {
    var checked = j.id === state.INIT_ATTACH_SELECTED ? 'checked' : '';
    return '<label class="init-attach-row">' +
      '<input type="radio" name="init-attach-radio" value="' + x(j.id) + '" ' + checked + on('change', 'initiativeAttachSelect') + '>' +
      '<span class="mono muted">' + x(j.id.slice(0, 8)) + '</span>' +
      '<span class="init-attach-type">' + x(j.type) + '</span>' +
      pill(M.stateLabel(j.state), M.jobTone(j.state)) +
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
