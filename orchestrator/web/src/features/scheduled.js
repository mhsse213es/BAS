import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { fmtDate, showToast } from '../core/util.js';
import { ROLE } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { kpi, grid, card, chip, pill, seg, empty, icon } from '../core/kit.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './sched-model.js';


// ── Scheduled Assessments ──────────────────────────────────────────────────
// List + create + cancel for POST/GET /api/scheduled-assessments and
// POST /api/scheduled-assessments/{id}/cancel. jobs.Schedule has no JSON
// struct tags server-side, so every field read off a schedule object below
// uses the exact Go field name (PascalCase), not camelCase.
export var SCHED = {
  schedules: [],   // raw list from GET /api/scheduled-assessments
  groups: [],      // nested group tree, fetched fresh when the wizard opens
  groupsById: {},  // flat id -> name, built from `groups`
  agentsAll: [],   // flat agent list, fetched fresh when the wizard opens
  selGroups: {},   // groupId -> true for wizard checkbox state
  selAgents: {},   // agentId -> true for wizard checkbox state
  groupsAccessDenied: false, // true when /api/agent-groups 403'd (Analyst), not just empty
  step: 1,
  editingId: null,        // null when creating; the schedule's ID when editing
  editPrefillMode: '',    // consumed once by renderSchedModeRecurrencePane's first render --
  editPrefillTimezone: '', // see that function for why Mode/Timezone need this indirection
  initiativesActive: [],   // GET /api/initiatives?state=active, fetched fresh when the wizard opens
  editPrefillInitiativeId: '' // same indirection as editPrefillMode -- #sched-initiative has no
                               // <option>s until initiativesActive's fetch resolves and populates it
};

export function loadScheduledAssessments() {
  Promise.all([
    apicall('/api/scheduled-assessments'),
    apicall('/api/agent-groups')
  ]).then(function(res) {
    if (res[0] && res[0].error) { showToast(res[0].error, 'err'); return; }
    SCHED.schedules = (res[0] && res[0].schedules) || [];
    var groups = Array.isArray(res[1]) ? res[1] : [];
    SCHED.groupsById = schedFlattenGroupNames(groups, {});
    renderScheduledAssessmentsList();
    loadLastRuns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// The outcome of each schedule's most recent run: the state of the job it last spawned
// (GET /api/jobs/{id}). A schedule that never ran, or a job that cannot be read, shows no outcome.
var LAST_JOBS = {}; // jobId -> job object, or null when unreadable
function loadLastRuns() {
  var ids = {};
  SCHED.schedules.forEach(function(s) { if (s.LastSpawnedJobID) ids[s.LastSpawnedJobID] = 1; });
  var list = Object.keys(ids).slice(0, 60);
  if (!list.length) return;
  Promise.all(list.map(function(id) {
    return apicall('/api/jobs/' + encodeURIComponent(id)).then(function(b) {
      LAST_JOBS[id] = b && b.job ? b.job : null;
    }).catch(function() { LAST_JOBS[id] = null; });
  })).then(renderScheduledAssessmentsList);
}

function schedFlattenGroupNames(nodes, map) {
  (nodes || []).forEach(function(n) {
    map[n.id] = n.name;
    if (n.children && n.children.length) schedFlattenGroupNames(n.children, map);
  });
  return map;
}

var SCHED_DOW = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];

function schedRecurrenceText(sch) {
  var tz = sch.Timezone || 'UTC';
  var type = sch.RecurrenceType || 'weekly';
  if (type === 'once') {
    return 'Once · ' + (sch.RunAt ? new Date(sch.RunAt).toLocaleString() : '—') + ' · ' + tz;
  }
  if (type === 'daily') {
    return 'Daily · ' + (sch.TimeOfDay || '—') + ' · ' + tz;
  }
  if (type === 'monthly') {
    return 'Monthly · Day ' + sch.DayOfMonth + ' · ' + (sch.TimeOfDay || '—') + ' · ' + tz;
  }
  // '' aliases to weekly, matching the backend's nextOccurrenceSince aliasing.
  return 'Weekly · ' + (SCHED_DOW[sch.DayOfWeek] || '—') + ' · ' + (sch.TimeOfDay || '—') + ' · ' + tz;
}

function schedTargetsText(sch) {
  var parts = [];
  var groupIds = sch.GroupIDs || [];
  if (groupIds.length) {
    var names = groupIds.map(function(id) { return SCHED.groupsById[id] || ('#' + id); });
    parts.push(names.join(', '));
  }
  var agentCount = (sch.AgentIDs || []).length;
  if (agentCount) parts.push(agentCount + ' agent' + (agentCount === 1 ? '' : 's'));
  return parts.length ? parts.join(' + ') : '—';
}

// schedStatus: Completed (a one-time schedule that fired), Enabled, or Cancelled.
export function schedStatus(sch) {
  var onceCompleted = sch.RecurrenceType === 'once' && !!sch.LastOccurrenceAt;
  if (onceCompleted) return { key: 'completed', label: 'Completed', tone: 'info', onceCompleted: true };
  if (sch.Enabled) return { key: 'enabled', label: 'Enabled', tone: 'ok', onceCompleted: false };
  return { key: 'cancelled', label: 'Cancelled', tone: 'muted', onceCompleted: false };
}

// schedSummary: counts by status, mode and recurrence for the summary strip.
export function schedSummary(list) {
  var out = { total: 0, enabled: 0, completed: 0, cancelled: 0, telemetry: 0, posture: 0, byRecurrence: {} };
  (list || []).forEach(function(sch) {
    out.total++;
    out[schedStatus(sch).key]++;
    if (sch.Mode === 'telemetry') out.telemetry++; else out.posture++;
    var r = sch.RecurrenceType || 'weekly';
    out.byRecurrence[r] = (out.byRecurrence[r] || 0) + 1;
  });
  return out;
}

// ── Page state: filter chips, the table's own controls, the open drawer ─────
var F = { status: 'all', q: '' };
var T = { q: '', col: -1, dir: 1, page: 0, per: 8, hidden: {}, sel: {} };
var DR = { id: null, run: null }; // run: { status: 'loading' | 'ok' | 'none' | 'err', targets: [] }

export function setSchedFilter(v) { F.status = v; T.page = 0; renderScheduledAssessmentsList(); }
export function schedSearch(el) { F.q = (el && el.value) || ''; T.page = 0; renderScheduledAssessmentsList(); }
export function schedClearFilters() {
  F.status = 'all'; F.q = ''; T.q = ''; T.page = 0;
  var s = document.getElementById('sched-search'); if (s) s.value = '';
  var q = document.getElementById('sched-dt-q'); if (q) q.value = '';
  renderScheduledAssessmentsList();
}

function scheduleName(sch) {
  // sch.Payload is a Go json.RawMessage with no json:"..." tag override, so
  // it arrives already embedded as a real object in the outer response --
  // NOT as a JSON string needing a second JSON.parse.
  var payload = sch.Payload || {};
  var sc = state.scenarios.find(function(s) { return s.id === payload.scenarioId; });
  return sc ? sc.name : (payload.scenarioId || '—');
}

function lastResult(sch) {
  if (!sch.LastSpawnedJobID) return M.resultOf(null);
  return M.resultOf(LAST_JOBS[sch.LastSpawnedJobID]);
}

// One table row's worth of values per schedule: what the table shows, sorts, filters and exports.
function buildRows(nowTs) {
  return SCHED.schedules.map(function(sch) {
    var st = schedStatus(sch);
    var last = sch.LastOccurrenceAt ? new Date(sch.LastOccurrenceAt).getTime() : null;
    return {
      sch: sch, id: sch.ID, name: scheduleName(sch),
      mode: sch.Mode === 'telemetry' ? 'Telemetry' : 'Posture',
      targets: schedTargetsText(sch), recurrence: schedRecurrenceText(sch),
      lastTs: last, lastText: last !== null && !isNaN(last) ? M.fmtStamp(last) : 'Never',
      nextTs: M.nextRun(sch, nowTs), result: lastResult(sch), status: st,
    };
  });
}

function renderSchedHero(nowTs) {
  var h = M.heroStats(SCHED.schedules, nowTs);
  setHeroStat('sched-cnt', h.total);
  setHeroStat('sched-hs-enabled', h.enabled);
  setHeroStat('sched-hs-cancelled', h.cancelled);
  setHeroStat('sched-hs-next', h.nextTs === null ? '—' : M.fmtWhen(h.nextTs));
}

// Four tiles under the banner. Every number is counted from the schedules; the next run is worked out
// from each schedule's recurrence; the last tile counts the schedules whose most recent run finished.
function renderSchedSummary(nowTs, rows) {
  var el = document.getElementById('sched-summary');
  if (!el) return;
  var sm = schedSummary(SCHED.schedules);
  if (!sm.total) { el.innerHTML = ''; return; }
  var next = M.nextAcross(SCHED.schedules, nowTs);
  var lr = M.lastRunsCompleted(rows.map(function(r) { return r.result; }));
  el.innerHTML = '<div class="sched-tiles">' + grid(4, [
    kpi({ label: 'Active schedules', value: sm.enabled, sub: 'of ' + sm.total + ' defined', icon: 'clock', tone: 'ok' }),
    kpi({ label: 'Cancelled', value: sm.cancelled, sub: 'will not run', icon: 'x', tone: 'bad' }),
    kpi({ label: 'Next run', value: next ? M.fmtDayTime(next.ts) : '—', sub: next ? scheduleName(next.sch) : 'nothing scheduled', icon: 'play', tone: 'accent' }),
    kpi({ label: 'Last runs completed', value: lr.pct === null ? '—' : lr.pct + '%', sub: lr.total ? lr.done + ' of ' + lr.total + ' finished runs' : 'no finished runs yet', icon: 'check', tone: lr.pct === null ? 'muted' : lr.pct >= 80 ? 'ok' : lr.pct >= 50 ? 'warn' : 'bad' }),
  ]) + '</div>';
}

// "Next 7 days": the runs each enabled schedule will fire, by day, from its recurrence.
function renderSchedWeek(nowTs) {
  var el = document.getElementById('sched-week');
  if (!el) return;
  if (!SCHED.schedules.length) { el.innerHTML = ''; return; }
  var plan = M.weekPlan(SCHED.schedules, nowTs, scheduleName);
  var body = '<div class="week">' + plan.days.map(function(d) {
    return '<div class="wk-day' + (d.today ? ' today' : '') + '"><div class="wk-h">' + x(d.label) + '</div>' +
      (d.events.length ? d.events.map(function(e) { return '<div class="wk-ev"><b>' + x(e.time) + '</b>' + x(e.name) + '</div>'; }).join('') : '<div class="muted wk-none">—</div>') + '</div>';
  }).join('') + '</div>';
  el.innerHTML = card('Next 7 days', body, { sub: plan.planned + (plan.planned === 1 ? ' run' : ' runs') + ' planned · your local time', cls: 'sched-week-card' });
}

function renderSchedFilters() {
  var fEl = document.getElementById('sched-filter');
  var bar = document.getElementById('sched-filters');
  if (bar) bar.hidden = !SCHED.schedules.length;
  if (!fEl) return;
  var sm = schedSummary(SCHED.schedules);
  var opts = [{ id: 'all', label: 'All', count: sm.total }, { id: 'enabled', label: 'Enabled', count: sm.enabled }];
  if (sm.completed) opts.push({ id: 'completed', label: 'Completed', count: sm.completed });
  opts.push({ id: 'cancelled', label: 'Cancelled', count: sm.cancelled });
  fEl.innerHTML = SCHED.schedules.length ? seg(opts, F.status, 'setSchedFilter') : '';
}

function visibleCols() {
  var out = [];
  M.COLUMNS.forEach(function(c, i) { if (!T.hidden[i]) out.push(i); });
  return out;
}

function cellHtml(col, r) {
  var sch = r.sch;
  switch (col) {
    case 0: return '<td class="sched-name"><div><b>' + x(r.name) + '</b></div><div class="mono muted sched-id">' + x(r.id) + '</div></td>';
    case 1: return '<td>' + chip(r.mode, sch.Mode === 'telemetry' ? 'violet' : 'info') + '</td>';
    case 2: return '<td>' + x(r.targets) + '</td>';
    case 3: return '<td class="muted">' + x(r.recurrence) + '</td>';
    case 4: return '<td class="mono muted">' + x(r.lastText) + '</td>';
    case 5: return '<td>' + (r.nextTs === null ? '<span class="muted">—</span>' : x(M.fmtWhen(r.nextTs))) + '</td>';
    case 6: return '<td>' + (r.result.key === 'none' ? '<span class="muted">—</span>' : pill(r.result.label, r.result.tone)) + '</td>';
    default: return '<td>' + pill(r.status.label, r.status.tone) + '</td>';
  }
}

function rowActions(r) {
  if (r.status.onceCompleted) return '<span class="tiny muted">Ran once — nothing to edit or cancel</span>';
  return '<button class="btn btn-outline btn-sm"' + on('click', 'openSchedWizardForEdit', r.id) + '>Edit</button>' +
    (r.sch.Enabled ? ' <button class="btn btn-outline btn-sm sched-cancel"' + on('click', 'cancelScheduledAssessment', r.id) + '>Cancel</button>' : '');
}

function renderSchedHead(listIds) {
  var th = document.getElementById('sched-thead');
  if (!th) return;
  var onList = listIds.filter(function(id) { return T.sel[id]; }).length;
  th.innerHTML = '<tr><th class="dt-selcol"><input type="checkbox" class="dt-cb" id="sched-sel-all" title="Select all on this table"' + on('change', 'schedSelectAll') + '></th>' +
    visibleCols().map(function(c) {
      return '<th class="dt-th' + (T.col === c ? ' sorted' : '') + '"' + on('click', 'schedSortBy', c) + '>' + x(M.COLUMNS[c]) + '<span class="dt-arrow">' + (T.col === c ? (T.dir > 0 ? '▲' : '▼') : '') + '</span></th>';
    }).join('') + '<th></th></tr>';
  var all = document.getElementById('sched-sel-all');
  if (all) { all.checked = listIds.length > 0 && onList === listIds.length; all.indeterminate = onList > 0 && onList < listIds.length; }
}

function setHidden(id, hidden) { var el = document.getElementById(id); if (el) el.hidden = hidden; }
function setText(id, t) { var el = document.getElementById(id); if (el) el.textContent = t; }

// The rows after the chips, the search box and the table's own filter, in the chosen order.
function currentList(rows) {
  return M.sortRows(M.filterRows(rows, { status: F.status, q: F.q, tq: T.q }), T.col, T.dir);
}

export function renderScheduledAssessmentsList() {
  var nowTs = Date.now();
  var rows = buildRows(nowTs);
  renderSchedHero(nowTs);
  renderSchedSummary(nowTs, rows);
  renderSchedWeek(nowTs);
  renderSchedFilters();
  var tbody = document.getElementById('sched-body');
  var none = !rows.length;
  var byChips = M.filterRows(rows, { status: F.status, q: F.q });
  var list = currentList(rows);
  var pg = M.pageSlice(list, T.page, T.per);
  T.page = pg.page;
  setHidden('sched-dt-toolbar', none);
  setHidden('sched-table-wrap', !list.length);
  setHidden('sched-dt-foot', !list.length);
  var clr = document.getElementById('sched-clear'); if (clr) clr.hidden = !(F.q || F.status !== 'all');
  var cols = document.getElementById('sched-cols');
  if (cols) {
    cols.innerHTML = M.COLUMNS.map(function(h, i) {
      return '<label class="dt-colitem"><input type="checkbox" class="dt-colchk"' + (T.hidden[i] ? '' : ' checked') + on('change', 'schedColToggle', i) + '><span>' + x(h) + '</span></label>';
    }).join('');
  }
  var selN = rows.filter(function(r) { return T.sel[r.id]; }).length;
  setHidden('sched-bulk', selN === 0);
  setText('sched-bulk-n', String(selN));
  setText('sched-dt-count', list.length + ' of ' + byChips.length + ' rows');
  setText('sched-dt-range', M.rangeText(list.length, pg.page, T.per));
  var pager = document.getElementById('sched-dt-pager');
  if (pager) {
    pager.innerHTML = pg.pages > 1
      ? '<button class="btn btn-ghost btn-sm"' + on('click', 'schedPage', -1) + (pg.page === 0 ? ' disabled' : '') + '>‹ Prev</button><span class="mono muted">' + (pg.page + 1) + ' / ' + pg.pages + '</span><button class="btn btn-ghost btn-sm"' + on('click', 'schedPage', 1) + (pg.page >= pg.pages - 1 ? ' disabled' : '') + '>Next ›</button>'
      : '';
  }
  var emp = document.getElementById('sched-empty');
  if (emp) {
    emp.hidden = list.length > 0;
    if (none) emp.innerHTML = empty('calendar', 'No scheduled assessments yet', 'Create a schedule to run an assessment on a recurrence.');
    else if (!list.length) emp.innerHTML = empty('search', 'No schedules match', 'Clear the filters to see all schedules.') + '<div class="dt-empty-act"><button class="btn btn-outline btn-sm"' + on('click', 'schedClearFilters') + '>Clear filters</button></div>';
  }
  renderSchedHead(list.map(function(r) { return r.id; }));
  if (tbody) {
    tbody.innerHTML = pg.rows.map(function(r) {
      return '<tr class="dt-click" tabindex="0"' + on('click', 'schedOpen', r.id) + on('keydown', 'schedRowKeydown', r.id) + '>' +
        '<td class="dt-selcol"' + on('click', 'stopEvent') + '><input type="checkbox" class="dt-cb" aria-label="Select schedule"' + (T.sel[r.id] ? ' checked' : '') + on('change', 'schedSelectRow', r.id) + '></td>' +
        visibleCols().map(function(c) { return cellHtml(c, r); }).join('') +
        '<td class="sched-actions"' + on('click', 'stopEvent') + '><div class="rg2-row-actions">' + rowActions(r) + '</div></td></tr>';
    }).join('');
  }
  if (DR.id) paintSchedDrawer();
}

// ── Table controls ──────────────────────────────────────────────────────────
export function schedTableQuery(el) { T.q = String((el && el.value) || ''); T.page = 0; renderScheduledAssessmentsList(); }
export function setSchedPer(el) { T.per = Number(el && el.value) || 8; T.page = 0; renderScheduledAssessmentsList(); }
export function schedPage(d) { T.page += Number(d) || 0; renderScheduledAssessmentsList(); }
export function schedSortBy(col) {
  col = Number(col);
  if (T.col === col) T.dir = -T.dir; else { T.col = col; T.dir = 1; }
  T.page = 0;
  renderScheduledAssessmentsList();
}
export function toggleSchedCols() { var m = document.getElementById('sched-cols'); if (m) m.hidden = !m.hidden; }
export function schedColToggle(col, el) {
  if (el && el.checked) delete T.hidden[col]; else T.hidden[col] = true;
  if (T.hidden[T.col]) T.col = -1;
  renderScheduledAssessmentsList();
}
export function schedSelectRow(id, el) { if (el && el.checked) T.sel[id] = true; else delete T.sel[id]; renderScheduledAssessmentsList(); }
export function schedSelectAll(el) {
  currentList(buildRows(Date.now())).forEach(function(r) { if (el && el.checked) T.sel[r.id] = true; else delete T.sel[r.id]; });
  renderScheduledAssessmentsList();
}
export function clearSchedSelection() { T.sel = {}; renderScheduledAssessmentsList(); }

function exportSched(onlySelected) {
  var rows = onlySelected ? buildRows(Date.now()).filter(function(r) { return T.sel[r.id]; }) : currentList(buildRows(Date.now()));
  var cols = visibleCols();
  var csv = M.csvText(cols.map(function(c) { return M.COLUMNS[c]; }).concat(['ID']), rows.map(function(r) {
    return cols.map(function(c) {
      return [r.name, r.mode, r.targets, r.recurrence, r.lastText, r.nextTs === null ? '—' : M.fmtWhen(r.nextTs), r.result.label, r.status.label][c];
    }).concat([r.id]);
  }));
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'scheduled-assessments.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  showToast('CSV exported — ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
export function exportSchedCsv() { exportSched(false); }
export function exportSchedSelected() { exportSched(true); }

document.addEventListener('click', function(e) {
  var m = document.getElementById('sched-cols');
  if (m && !m.hidden && !(e.target.closest && e.target.closest('.dt-colwrap'))) m.hidden = true;
});

// ── Schedule drawer ─────────────────────────────────────────────────────────
function findSched(id) { return SCHED.schedules.filter(function(s) { return s.ID === id; })[0] || null; }

function kvRows(rows) {
  return '<dl class="sc-kv">' + rows.map(function(p) { return '<dt>' + x(p[0]) + '</dt><dd' + (p[2] ? ' class="mono"' : '') + '>' + x(p[1]) + '</dd>'; }).join('') + '</dl>';
}

function runSection() {
  var run = DR.run;
  if (!run || run.status === 'none') return '<div class="sc-sub">This schedule has not started a run yet.</div>';
  if (run.status === 'loading') return '<div class="sc-sub">Loading the last run…</div>';
  if (run.status === 'err') return '<div class="sc-sub">The last run could not be read.</div>';
  var targets = run.targets;
  if (!targets.length) return '<div class="sc-sub">The last run has no targets.</div>';
  var counts = {};
  targets.forEach(function(t) { var k = String(t.State || 'unknown').toLowerCase(); counts[k] = (counts[k] || 0) + 1; });
  var colors = { completed: CHART_COLORS.ok, failed: CHART_COLORS.bad, cancelled: CHART_COLORS.muted, pending: CHART_COLORS.info, dispatched: CHART_COLORS.accent, deferred: CHART_COLORS.warn };
  var segs = Object.keys(counts).map(function(k) { return { label: k.charAt(0).toUpperCase() + k.slice(1), value: counts[k], color: colors[k] || CHART_COLORS.muted }; });
  var tone = { completed: 'ok', failed: 'bad', cancelled: 'muted', pending: 'info', dispatched: 'info', deferred: 'warn' };
  var shown = targets.slice(0, 25);
  return chartSlot({ type: 'donut', segments: segs, center: String(targets.length), centerSub: targets.length === 1 ? 'target' : 'targets', legend: true, h: 140 }) +
    '<div class="tbl-wrap sched-dr-tbl"><table><thead><tr><th>Agent</th><th>State</th><th>Finished</th></tr></thead><tbody>' +
    shown.map(function(t) {
      var k = String(t.State || '').toLowerCase();
      return '<tr><td class="mono">' + x(t.AgentID) + '</td><td>' + pill(k ? k.charAt(0).toUpperCase() + k.slice(1) : '—', tone[k] || 'muted') + (t.Error ? '<div class="tiny muted">' + x(t.Error) + '</div>' : '') + '</td><td class="muted">' + x(t.CompletedAt ? M.fmtStamp(new Date(t.CompletedAt).getTime()) : '—') + '</td></tr>';
    }).join('') + '</tbody></table></div>' +
    (targets.length > shown.length ? '<div class="sc-sub">+ ' + (targets.length - shown.length) + ' more targets</div>' : '');
}

function drawerBody(sch) {
  var st = schedStatus(sch);
  var last = lastResult(sch);
  var next = M.nextRun(sch, Date.now());
  var rows = [['Scope', schedTargetsText(sch)], ['Recurrence', schedRecurrenceText(sch)], ['Next run', next === null ? '—' : M.fmtWhen(next)],
    ['Jitter', 'Up to ±2 min, fixed for this schedule'], ['Mode', sch.Mode === 'telemetry' ? 'Telemetry' : 'Posture'],
    ['Concurrency', sch.ConcurrencyLimit ? String(sch.ConcurrencyLimit) : 'Unlimited']];
  if (sch.EndDate) rows.push(['Ends', new Date(sch.EndDate).toLocaleDateString()]);
  if (sch.InitiativeID) rows.push(['Initiative', sch.InitiativeID, true]);
  if (sch.Reason) rows.push(['Reason', sch.Reason]);
  if (sch.ApprovedBy) rows.push(['Approved by', sch.ApprovedBy]);
  if (sch.CreatedBy) rows.push(['Created by', sch.CreatedBy]);
  if (sch.CreatedAt) rows.push(['Created', M.fmtStamp(new Date(sch.CreatedAt).getTime())]);
  return '<div class="k8s-dr-top">' + pill(st.label, st.tone) + (last.key === 'none' ? '' : pill('Last run: ' + last.label, last.tone)) + '</div>' +
    kvRows(rows) + '<h4 class="sc-h4">Last run</h4>' + runSection();
}

function paintSchedDrawer() {
  var sch = findSched(DR.id);
  var head = document.getElementById('sched-drawer-head');
  if (!sch || !head) { closeSchedDrawer(); return; }
  head.innerHTML = '<span class="sc-dh-ico">' + icon('clock') + '</span><div><div class="sc-dh-t">' + x(scheduleName(sch)) + '</div>' +
    '<div class="sc-dh-s">' + x(sch.ID) + ' · ' + x(schedTargetsText(sch)) + '</div></div>';
  document.getElementById('sched-drawer-body').innerHTML = drawerBody(sch);
  var st = schedStatus(sch);
  document.getElementById('sched-drawer-foot').innerHTML =
    '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'closeSchedDrawer') + '>Close</button><span class="grow"></span>' +
    (st.onceCompleted ? '<span class="tiny muted">Ran once — nothing to edit or cancel</span>' :
      (sch.Enabled ? '<button type="button" class="btn btn-outline btn-sm sched-cancel"' + on('click', 'schedCancelFromDrawer', sch.ID) + '>Cancel schedule</button>' : '') +
      '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'schedEditFromDrawer', sch.ID) + '>Edit</button>');
}

export function schedOpen(id) {
  var sch = findSched(id);
  if (!sch) return;
  DR.id = id;
  DR.run = sch.LastSpawnedJobID ? { status: 'loading', targets: [] } : { status: 'none', targets: [] };
  paintSchedDrawer();
  var ov = document.getElementById('sched-drawer-overlay');
  if (ov) ov.classList.add('open');
  var b = document.getElementById('sched-drawer-body'); if (b) b.scrollTop = 0;
  if (!sch.LastSpawnedJobID) return;
  apicall('/api/jobs/' + encodeURIComponent(sch.LastSpawnedJobID)).then(function(body) {
    if (DR.id !== id) return;
    DR.run = body && body.job ? { status: 'ok', targets: Array.isArray(body.targets) ? body.targets : [] } : { status: 'err', targets: [] };
    paintSchedDrawer();
  }).catch(function() {
    if (DR.id !== id) return;
    DR.run = { status: 'err', targets: [] };
    paintSchedDrawer();
  });
}
export function schedRowKeydown(id, el, e) {
  if (e && e.target !== el) return;
  if (e && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); schedOpen(id); }
}
export function closeSchedDrawer() {
  DR.id = null; DR.run = null;
  var ov = document.getElementById('sched-drawer-overlay');
  if (ov) ov.classList.remove('open');
}
export function closeSchedDrawerOnBackdrop(el, event) { if (event.target === el) closeSchedDrawer(); }
export function schedEditFromDrawer(id) { closeSchedDrawer(); openSchedWizardForEdit(id); }
export function schedCancelFromDrawer(id) { cancelScheduledAssessment(id); }

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && DR.id) closeSchedDrawer();
});

export function cancelScheduledAssessment(id) {
  if (!confirm('Cancel this scheduled assessment? It will stop firing future runs; the schedule stays visible in this list as Cancelled.')) return;
  apicall('/api/scheduled-assessments/' + encodeURIComponent(id) + '/cancel', { method: 'POST' }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Schedule cancelled', 'ok');
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function openSchedWizard() {
  SCHED.selGroups = {}; SCHED.selAgents = {};
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  SCHED.editingId = null;
  SCHED.editPrefillMode = '';
  SCHED.editPrefillTimezone = '';
  SCHED.editPrefillInitiativeId = '';
  document.getElementById('sched-wz-title').textContent = 'New Scheduled Assessment';
  document.getElementById('sched-create-btn').textContent = 'Create Schedule';
  document.getElementById('sched-group-cnt').textContent = '(0 selected)';
  document.getElementById('sched-agent-cnt').textContent = '(0 selected)';
  document.getElementById('sched-reason').value = '';
  document.getElementById('sched-recurrence-type').value = 'weekly';
  document.getElementById('sched-runat').value = '';
  document.getElementById('sched-dow').value = '0';
  document.getElementById('sched-dom').value = '1';
  document.getElementById('sched-timeofday').value = '02:00';
  document.getElementById('sched-enddate').value = '';
  document.getElementById('sched-concurrency').value = '';
  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = state.scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  Promise.all([apicall('/api/agent-groups'), apicall('/api/agents'), apicall('/api/initiatives?state=active')]).then(function(res) {
    SCHED.groupsAccessDenied = !!(res[0] && res[0].error);
    SCHED.groups = Array.isArray(res[0]) ? res[0] : [];
    SCHED.groupsById = schedFlattenGroupNames(SCHED.groups, {});
    SCHED.agentsAll = Array.isArray(res[1]) ? res[1] : [];
    SCHED.initiativesActive = (res[2] && res[2].initiatives) || [];
    renderSchedGroupTree();
    renderSchedAgentList();
    renderSchedInitiativeSelect();
  }).catch(function(e) { showToast(e.message, 'err'); });
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}

// openSchedWizardForEdit prefills the same wizard openSchedWizard() uses,
// from an existing schedule's current values. Every field can be set with a
// direct .value assignment at this point EXCEPT Mode and Timezone -- #sched-mode
// starts with zero <option> elements (entirely built by
// renderSchedModeRecurrencePane() the first time step 3 renders) and that
// same function's first-render branch unconditionally resets Timezone to the
// browser's local zone. SCHED.editPrefillMode/editPrefillTimezone route
// around that -- see renderSchedModeRecurrencePane's updated first-render
// branch below.
export function openSchedWizardForEdit(id) {
  var sch = SCHED.schedules.find(function(s) { return s.ID === id; });
  if (!sch) { showToast('Schedule not found', 'err'); return; }
  // sch.Payload arrives already parsed (json.RawMessage embeds as a real
  // object, not a JSON string) -- see renderScheduledAssessmentsList's
  // matching fix for the full explanation.
  var payload = sch.Payload || {};

  SCHED.selGroups = {};
  (sch.GroupIDs || []).forEach(function(gid) { SCHED.selGroups[gid] = true; });
  SCHED.selAgents = {};
  (sch.AgentIDs || []).forEach(function(aid) { SCHED.selAgents[aid] = true; });
  SCHED.modeInitialized = false;
  SCHED.groupsAccessDenied = false;
  SCHED.editingId = sch.ID;
  SCHED.editPrefillMode = sch.Mode || 'posture';
  SCHED.editPrefillTimezone = sch.Timezone || '';
  SCHED.editPrefillInitiativeId = sch.InitiativeID || '';

  document.getElementById('sched-wz-title').textContent = 'Edit Scheduled Assessment';
  document.getElementById('sched-create-btn').textContent = 'Save Changes';
  document.getElementById('sched-group-cnt').textContent = '(' + Object.keys(SCHED.selGroups).length + ' selected)';
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
  document.getElementById('sched-reason').value = sch.Reason || '';
  document.getElementById('sched-recurrence-type').value = sch.RecurrenceType || 'weekly';
  document.getElementById('sched-runat').value = sch.RunAt ? new Date(sch.RunAt).toISOString().slice(0, 16) : '';
  document.getElementById('sched-dow').value = String(sch.DayOfWeek || 0);
  document.getElementById('sched-dom').value = String(sch.DayOfMonth || 1);
  document.getElementById('sched-timeofday').value = sch.TimeOfDay || '02:00';
  document.getElementById('sched-enddate').value = sch.EndDate ? new Date(sch.EndDate).toISOString().slice(0, 10) : '';
  document.getElementById('sched-concurrency').value = sch.ConcurrencyLimit || '';

  var sel = document.getElementById('sched-scenario');
  sel.innerHTML = state.scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('');
  sel.value = payload.scenarioId || '';

  Promise.all([apicall('/api/agent-groups'), apicall('/api/agents'), apicall('/api/initiatives?state=active')]).then(function(res) {
    SCHED.groupsAccessDenied = !!(res[0] && res[0].error);
    SCHED.groups = Array.isArray(res[0]) ? res[0] : [];
    SCHED.groupsById = schedFlattenGroupNames(SCHED.groups, {});
    SCHED.agentsAll = Array.isArray(res[1]) ? res[1] : [];
    SCHED.initiativesActive = (res[2] && res[2].initiatives) || [];
    renderSchedGroupTree();
    renderSchedAgentList();
    renderSchedInitiativeSelect();
  }).catch(function(e) { showToast(e.message, 'err'); });
  document.getElementById('sched-overlay').classList.add('open');
  schedWizardSet(1);
}

export function closeSchedWizard() {
  document.getElementById('sched-overlay').classList.remove('open');
}

function schedWizardSet(step) {
  if (step < 1) step = 1;
  if (step > 4) step = 4;
  SCHED.step = step;
  var stepLbl = document.getElementById('sched-wz-step');
  if (stepLbl) stepLbl.textContent = 'Step ' + step + ' of 4';
  [1, 2, 3, 4].forEach(function(n) {
    var pane = document.querySelector('[data-sched-pane="' + n + '"]');
    if (pane) setDisplay(pane, (n === step) ? 'block' : 'none');
    var pip = document.querySelector('[data-sched-pip="' + n + '"]');
    if (pip) { pip.classList.toggle('active', n === step); pip.classList.toggle('done', n < step); }
  });
  setDisplay(document.getElementById('sched-wz-back'), (step > 1) ? '' : 'none');
  setDisplay(document.getElementById('sched-wz-next'), (step < 4) ? '' : 'none');
  setDisplay(document.getElementById('sched-create-btn'), (step === 4) ? '' : 'none');
  // Re-evaluate agent platform compatibility every time step 2 is entered --
  // covers Back-then-forward after switching the step-1 scenario selection.
  if (step === 2) renderSchedAgentList();
  if (step === 3) renderSchedModeRecurrencePane();
  if (step === 4) renderSchedReview();
}

export function schedWizardNav(dir) { schedWizardSet(SCHED.step + dir); }

export function schedAuthCheckChange(el) {
  document.getElementById('sched-create-btn').disabled = !el.checked;
}

export function schedToggleGroupFromChecked(id, el) { schedToggleGroup(id, el.checked); }
export function schedToggleAgentFromChecked(id, el) { schedToggleAgent(id, el.checked); }

export function schedToggleGroup(id, checked) {
  if (checked) SCHED.selGroups[id] = true; else delete SCHED.selGroups[id];
  document.getElementById('sched-group-cnt').textContent = '(' + Object.keys(SCHED.selGroups).length + ' selected)';
}

export function schedToggleAgent(id, checked) {
  if (checked) SCHED.selAgents[id] = true; else delete SCHED.selAgents[id];
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
}

function renderSchedGroupTree() {
  var root = document.getElementById('sched-group-tree');
  if (!root) return;
  if (!SCHED.groups.length) {
    root.innerHTML = SCHED.groupsAccessDenied
      ? '<div class="empty">Group targeting requires Administrator access — select individual agents instead.</div>'
      : '<div class="empty">No agent groups defined.</div>';
    return;
  }
  root.innerHTML = SCHED.groups.map(renderSchedGroupNode).join('');
}

function renderSchedGroupNode(node) {
  var hasChildren = node.children && node.children.length;
  var checked = SCHED.selGroups[node.id] ? ' checked' : '';
  var html = '<div class="at-node">' +
    '<label class="g1-display-flex g1-s-16487d2d">' +
    '<input type="checkbox"' + checked + on('change', 'schedToggleGroupFromChecked', node.id) + '>' +
    '<span class="at-name">' + x(node.name) + '</span>' +
    '<span class="at-count">' + node.totalAgentCount + '</span>' +
    '</label></div>';
  if (hasChildren) {
    html += '<div class="at-children">' + node.children.map(renderSchedGroupNode).join('') + '</div>';
  }
  return html;
}

// schedClassifyOS mirrors the server's classifyAgentOS (internal/api/handlers.go)
// exactly, so an agent's compatibility badge in this wizard never disagrees
// with the server-side scheduleOSCompatibilityError backstop that actually
// enforces it.
export function schedClassifyOS(osVersion) {
  var lower = (osVersion || '').toLowerCase();
  if (lower.indexOf('windows') !== -1) return 'windows';
  if (lower.indexOf('darwin') !== -1 || lower.indexOf('macos') !== -1 || lower.indexOf('mac os') !== -1) return 'darwin';
  if (lower.indexOf('linux') !== -1 || lower.indexOf('ubuntu') !== -1 || lower.indexOf('debian') !== -1 ||
      lower.indexOf('centos') !== -1 || lower.indexOf('rhel') !== -1 || lower.indexOf('fedora') !== -1 ||
      lower.indexOf('kali') !== -1 || lower.indexOf('arch') !== -1) return 'linux';
  return '';
}

// schedAgentCompatible mirrors revalOSCompatible's "empty = unrestricted" rule:
// an empty supportedOS list, or an agent whose OS string doesn't classify to
// anything recognized, is treated as compatible rather than blocked.
export function schedAgentCompatible(agent, supportedOS) {
  if (!supportedOS || !supportedOS.length) return true;
  var agentOS = schedClassifyOS(agent.osVersion);
  if (!agentOS) return true;
  return supportedOS.some(function(o) { return o.toLowerCase() === agentOS; });
}

// vexFilterWindowsAgents drops non-Windows agents from a resolved
// group/all-agent target list -- every variant Template is Windows-only
// PowerShell (internal/variant/generator.go), so this is a flat filter, not
// a per-scenario compatibility check like schedAgentCompatible. An agent
// whose OS string doesn't classify to anything recognized stays included
// (same "unrestricted when unclassified" convention used throughout).
export function vexFilterWindowsAgents(list) {
  return (list || []).filter(function(a) {
    var os = schedClassifyOS(a.osVersion);
    return os !== 'linux' && os !== 'darwin';
  });
}

function schedSelectedScenarioSupportedOS() {
  var sc = state.scenarios.find(function(s) { return s.id === document.getElementById('sched-scenario').value; });
  return (sc && sc.supportedOs) || [];
}

function renderSchedAgentList() {
  var root = document.getElementById('sched-agent-list');
  if (!root) return;
  if (!SCHED.agentsAll.length) { root.innerHTML = '<div class="empty">No agents registered.</div>'; return; }
  var supportedOS = schedSelectedScenarioSupportedOS();
  root.innerHTML = SCHED.agentsAll.map(function(a) {
    var compatible = schedAgentCompatible(a, supportedOS);
    // A previously-checked agent that's now incompatible (scenario changed
    // after selection) must not stay silently selected.
    if (!compatible && SCHED.selAgents[a.agentId]) delete SCHED.selAgents[a.agentId];
    var checked = SCHED.selAgents[a.agentId] ? ' checked' : '';
    var disabled = compatible ? '' : ' disabled';
    var warn = compatible ? '' : ' <span class="tiny u-danger">Platform mismatch</span>';
    return '<label class="g1-display-flex g1-s-199650cf ' + (compatible ? 'g1-s-46d9ceb8' : 'g1-s-3b456e9f') + '">' +
      '<input type="checkbox"' + checked + disabled + on('change', 'schedToggleAgentFromChecked', a.agentId) + '>' +
      '<code class="g1-s-8f55e862">' + x(a.agentId) + '</code><span class="tiny muted">' + x(a.hostname) + ' — ' + x(a.osVersion || 'Unknown OS') + '</span>' + warn + '</label>';
  }).join('');
  document.getElementById('sched-agent-cnt').textContent = '(' + Object.keys(SCHED.selAgents).length + ' selected)';
}

// renderSchedInitiativeSelect populates #sched-initiative from
// SCHED.initiativesActive, applying SCHED.editPrefillInitiativeId the same
// way renderSchedModeRecurrencePane applies editPrefillMode -- the fetch
// that fills initiativesActive resolves after schedWizardSet(1) has already
// run, so an earlier direct .value= assignment would be a no-op. If the
// schedule's current initiative isn't in the active list (closed/archived
// since scheduling, or simply not yet loaded), the assignment silently
// fails and the select falls back to "None" -- same fallback behavior
// #sched-mode already has for a no-longer-valid previous selection.
function renderSchedInitiativeSelect() {
  var sel = document.getElementById('sched-initiative');
  if (!sel) return;
  sel.innerHTML = '<option value="">— None —</option>' +
    SCHED.initiativesActive.map(function(it) { return '<option value="' + x(it.ID) + '">' + x(it.Name) + '</option>'; }).join('');
  sel.value = SCHED.editPrefillInitiativeId || '';
}

function renderSchedModeRecurrencePane() {
  var modeSel = document.getElementById('sched-mode');
  var prevMode = modeSel.value;
  var sc = state.scenarios.find(function(s) { return s.id === document.getElementById('sched-scenario').value; });
  var opts = '<option value="posture">Posture — read-only, safe on any host</option>';
  if (ROLE === 'admin' && sc && sc.executable) {
    opts += '<option value="telemetry">Telemetry — real identity-safe techniques (requires authorization)</option>';
  }
  modeSel.innerHTML = opts;
  if (SCHED.modeInitialized) {
    modeSel.value = prevMode;
    // If the previously-selected mode's option no longer exists (e.g. Back-navigated
    // to step 1 and picked a non-executable scenario while Telemetry was selected),
    // the assignment above silently fails to select anything -- fall back to Posture.
    if (modeSel.value !== prevMode) modeSel.value = 'posture';
  } else {
    // First render: default to Posture + the browser's local timezone, UNLESS
    // openSchedWizardForEdit() stashed a prefill (SCHED.editPrefillMode/
    // editPrefillTimezone) -- #sched-mode has no <option> elements until this
    // function builds them above, so an earlier direct .value= assignment at
    // wizard-open time would have been a no-op; this indirection is required.
    var wantMode = SCHED.editPrefillMode || 'posture';
    modeSel.value = wantMode;
    if (modeSel.value !== wantMode) modeSel.value = 'posture';
    document.getElementById('sched-timezone').value = SCHED.editPrefillTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    SCHED.modeInitialized = true;
  }
  schedOnModeChange();
  schedOnRecurrenceChange();
}

export function schedOnModeChange() {
  var mode = document.getElementById('sched-mode').value;
  var isTelemetry = mode === 'telemetry';
  setDisplay(document.getElementById('sched-mode-warn'), isTelemetry ? 'block' : 'none');
  setDisplay(document.getElementById('sched-reason-wrap'), isTelemetry ? 'block' : 'none');
}

export function schedOnRecurrenceChange() {
  var type = document.getElementById('sched-recurrence-type').value;
  setDisplay(document.getElementById('sched-once-wrap'), (type === 'once') ? 'block' : 'none');
  setDisplay(document.getElementById('sched-dow-wrap'), (type === 'weekly') ? 'block' : 'none');
  setDisplay(document.getElementById('sched-dom-wrap'), (type === 'monthly') ? 'block' : 'none');
  setDisplay(document.getElementById('sched-time-wrap'), (type === 'once') ? 'none' : 'block');
}

// schedBuildPayload assembles the exact POST body scheduled_assessment_handlers.go
// expects. Techniques/steps are intentionally omitted -- V1 always schedules the
// full scenario. runAt/endDate are sent as ISO 8601 (RFC3339), matching Go's
// *time.Time JSON unmarshalling.
function schedBuildPayload() {
  var mode = document.getElementById('sched-mode').value;
  var type = document.getElementById('sched-recurrence-type').value;
  var body = {
    scenarioId: document.getElementById('sched-scenario').value,
    mode: mode,
    agentIds: Object.keys(SCHED.selAgents),
    groupIds: Object.keys(SCHED.selGroups).map(Number),
    recurrenceType: type,
    timezone: document.getElementById('sched-timezone').value
  };
  if (mode === 'telemetry') body.reason = document.getElementById('sched-reason').value.trim();
  if (type === 'once') {
    var runAt = document.getElementById('sched-runat').value;
    body.runAt = runAt ? new Date(runAt).toISOString() : null;
  } else {
    body.timeOfDay = document.getElementById('sched-timeofday').value;
    if (type === 'weekly') body.dayOfWeek = Number(document.getElementById('sched-dow').value);
    if (type === 'monthly') body.dayOfMonth = Number(document.getElementById('sched-dom').value);
  }
  var endDate = document.getElementById('sched-enddate').value;
  if (endDate) body.endDate = new Date(endDate).toISOString();
  var conc = document.getElementById('sched-concurrency').value;
  if (conc) body.concurrencyLimit = Number(conc);
  var initiativeId = document.getElementById('sched-initiative').value;
  if (initiativeId) body.initiativeId = initiativeId;
  return body;
}

function renderSchedReview() {
  var payload = schedBuildPayload();
  var sc = state.scenarios.find(function(s) { return s.id === payload.scenarioId; });
  var groupNames = (payload.groupIds || []).map(function(id) { return SCHED.groupsById[id] || ('#' + id); });
  var targetsLine = [groupNames.join(', '), payload.agentIds.length ? (payload.agentIds.length + ' agent(s)') : '']
    .filter(function(s) { return s; }).join(' + ') || '—';
  var recurrenceLine = payload.recurrenceType === 'once'
    ? 'Once · ' + (payload.runAt ? new Date(payload.runAt).toLocaleString() : '—')
    : payload.recurrenceType === 'daily' ? 'Daily · ' + payload.timeOfDay
    : payload.recurrenceType === 'monthly' ? 'Monthly · Day ' + payload.dayOfMonth + ' · ' + payload.timeOfDay
    : 'Weekly · ' + SCHED_DOW[payload.dayOfWeek] + ' · ' + payload.timeOfDay;
  var initiative = SCHED.initiativesActive.find(function(it) { return it.ID === payload.initiativeId; });

  var html = '<div class="g1-s-1662da4e">' +
    '<div><strong>Scenario:</strong> ' + x(sc ? sc.name : payload.scenarioId) + '</div>' +
    '<div><strong>Mode:</strong> ' + x(payload.mode === 'telemetry' ? 'Telemetry' : 'Posture') + '</div>' +
    '<div><strong>Targets:</strong> ' + x(targetsLine) + '</div>' +
    '<div><strong>Recurrence:</strong> ' + x(recurrenceLine) + ' · ' + x(payload.timezone) + '</div>' +
    '<div><strong>Concurrency:</strong> ' + x(payload.concurrencyLimit || 'Unlimited') + '</div>' +
    '<div><strong>End date:</strong> ' + x(payload.endDate ? new Date(payload.endDate).toLocaleDateString() : 'None') + '</div>' +
    '<div><strong>Initiative:</strong> ' + x(initiative ? initiative.Name : 'None') + '</div>' +
    '</div>';

  var authWrap = '';
  if (payload.mode === 'telemetry') {
    authWrap = '<div class="g1-s-8b8a9186">' +
      '<div class="g1-s-0f7fb8b9">&#9888; Unattended Telemetry Authorization</div>' +
      '<div class="g1-s-e761abd2">This schedule will execute real techniques that may generate security alerts on the selected targets, on every future occurrence, with no further confirmation.</div>' +
      '<div class="g1-s-13741987"><strong>Reason:</strong> ' + x(payload.reason || '(none entered)') + '</div>' +
      '<label class="g1-display-flex g1-s-5914e41c">' +
      '<input type="checkbox" id="sched-auth-check"' + on('change', 'schedAuthCheckChange') + '>' +
      'I authorize this recurring unattended execution</label>' +
      '</div>';
  }

  document.getElementById('sched-review').innerHTML = html + authWrap;
  var createBtn = document.getElementById('sched-create-btn');
  createBtn.disabled = (payload.mode === 'telemetry'); // re-enabled by the checkbox above once checked
}

export function submitScheduledAssessment() {
  var payload = schedBuildPayload();
  if (!payload.scenarioId) { showToast('Select a scenario', 'err'); return; }
  if (!payload.agentIds.length && !payload.groupIds.length) { showToast('Select at least one target group or agent', 'err'); return; }
  if (payload.mode === 'telemetry' && !payload.reason) { showToast('Reason is required for a telemetry-mode schedule', 'err'); return; }
  // Defensive backstop -- the wizard already disables incompatible agent
  // checkboxes, but re-check here in case the scenario changed after step 2
  // without a re-render, or a group's membership includes one at submit time
  // (groups aren't filtered client-side; the server does the real check).
  var supportedOS = schedSelectedScenarioSupportedOS();
  var incompatible = SCHED.agentsAll.filter(function(a) {
    return payload.agentIds.indexOf(a.agentId) !== -1 && !schedAgentCompatible(a, supportedOS);
  });
  if (incompatible.length) {
    showToast('Selected agent(s) do not support the platform required by this scenario.', 'err');
    return;
  }

  var btn = document.getElementById('sched-create-btn');
  btn.disabled = true;
  var isEdit = !!SCHED.editingId;
  var url = isEdit ? '/api/scheduled-assessments/' + encodeURIComponent(SCHED.editingId) : '/api/scheduled-assessments';
  var method = isEdit ? 'PUT' : 'POST';
  apicall(url, { method: method, body: JSON.stringify(payload) }).then(function(res) {
    if (res && res.error) { showToast(res.error, 'err'); btn.disabled = false; return; }
    showToast(isEdit ? 'Scheduled assessment updated' : 'Scheduled assessment created', 'ok');
    closeSchedWizard();
    loadScheduledAssessments();
  }).catch(function(e) { showToast(e.message, 'err'); btn.disabled = false; });
}
