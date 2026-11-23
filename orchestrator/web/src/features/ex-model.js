// Pure helpers for the redesigned Exercises page: banner numbers, the column sets of the three tables
// (OpenAEV scenarios, OpenAEV exercises, Executions), filter / sort / CSV text and the plan-row caption.
// No DOM, no network. Data: GET /api/openaev/scenarios?type=scenario|exercise, /api/exercises/plans and
// /api/exercises/executions. The demo's tabletop list (Date, Participants, Score, Outcome, "Upcoming")
// has no source in those APIs, so none of it is shown.

export var SCEN_COLUMNS = ['Name', 'Category', 'Severity', 'Techniques', 'Injects', 'Synced'];
export var EXEC_COLUMNS = ['Name', 'Status', 'Progress', 'Started'];
export var NUM_COLS = { scen: { 3: true, 4: true }, exs: { 3: true, 4: true }, execs: {} };

// The demo gives a table the full toolbar (filter, columns, page size, CSV, selection, pager) from 8 rows
// up and only sortable headers below that.
export var FULL_FROM = 8;
export function isFull(n) { return n >= FULL_FROM; }

export function columnsOf(kind) { return kind === 'execs' ? EXEC_COLUMNS : SCEN_COLUMNS; }

function n(v) { var k = Number(v); return isFinite(k) ? k : 0; }
function list(v) { return Array.isArray(v) ? v : []; }

// heroStats: the four banner numbers; null means that list has not loaded (shown as a dash).
export function heroStats(st) {
  st = st || {};
  var execs = Array.isArray(st.execs) ? st.execs : null;
  return {
    scen: Array.isArray(st.scen) ? st.scen.length : null,
    plans: Array.isArray(st.plans) ? st.plans.length : null,
    execs: execs ? execs.length : null,
    done: execs ? execs.filter(function(e) { return e.status === 'completed'; }).length : null,
  };
}

export function sevTone(s) {
  var v = String(s || '').toLowerCase();
  return v === 'critical' ? 'bad' : v === 'high' ? 'warn' : 'info';
}
export function statusTone(s) {
  return s === 'completed' ? 'ok' : s === 'running' ? 'info' : s === 'paused' || s === 'waiting' ? 'warn' : s === 'failed' || s === 'aborted' ? 'bad' : 'muted';
}
export function isLive(e) { return !!e && (e.status === 'running' || e.status === 'paused'); }

// stamp: "2026-10-15T17:30:00Z" -> "2026-10-15 17:30"; anything else is shown as given.
export function stamp(s) {
  var v = String(s == null ? '' : s);
  var m = v.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
  return m ? m[1] + ' ' + m[2] : v;
}
export function dayOf(s) {
  var v = String(s == null ? '' : s);
  var m = v.match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : v;
}

export function techCount(r) { return list(r && r.TechniqueIDs).length; }
export function progressPct(e) {
  var t = n(e && e.steps_total);
  return t ? Math.round((n(e.steps_done) / t) * 100) : null;
}
export function startedOf(e) { return stamp((e && (e.started_at || e.created_at)) || ''); }

// planSub: the caption under a plan name.
export function planSub(p) {
  var c = list(p && p.steps).length;
  var d = dayOf((p && p.created_at) || '');
  return c + ' step' + (c === 1 ? '' : 's') + (d ? ' · created ' + d : '');
}

// cellText: the text of one cell, used for the filter, the sort fallback and the CSV.
export function cellText(kind, r, col) {
  if (kind === 'execs') {
    switch (col) {
      case 0: return String(r.name || r.plan_id || '');
      case 1: return String(r.status || '') + (isLive(r) ? ' · live' : '');
      case 2: return n(r.steps_total) ? n(r.steps_done) + ' / ' + n(r.steps_total) + ' steps' : '';
      default: return startedOf(r);
    }
  }
  switch (col) {
    case 0: return String(r.Name || '');
    case 1: return String(r.Category || '');
    case 2: return String(r.Severity || '');
    case 3: return String(techCount(r));
    case 4: return r.InjectsCount == null ? '' : String(r.InjectsCount);
    default: return stamp(r.SourceUpdatedAt || '');
  }
}

export function filterRows(kind, rows, q) {
  var s = String(q || '').trim().toLowerCase();
  if (!s) return rows.slice();
  var cols = columnsOf(kind);
  return rows.filter(function(r) {
    return cols.map(function(c, i) { return cellText(kind, r, i); }).join(' ').toLowerCase().indexOf(s) !== -1;
  });
}

function sortKey(kind, r, col) {
  if (kind === 'execs') {
    if (col === 2) return progressPct(r);
    var t = cellText(kind, r, col);
    return t === '' ? null : t;
  }
  if (col === 3) return techCount(r);
  if (col === 4) return r.InjectsCount == null ? null : n(r.InjectsCount);
  var v = cellText(kind, r, col);
  return v === '' ? null : v;
}

// sortRows: stable; empty values always sort last.
export function sortRows(kind, rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = sortKey(kind, a.r, col), v = sortKey(kind, b.r, col);
    var ue = u == null, ve = v == null;
    if (ue || ve) return ue && ve ? a.i - b.i : ue ? 1 : -1;
    var c = typeof u === 'number' && typeof v === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

export function csvRow(kind, r, cols) { return cols.map(function(c) { return cellText(kind, r, c); }); }

export function rangeCounts(shown, total) { return shown + ' of ' + total + ' rows'; }

export { pageCount, rangeText, csvText } from './runs-model.js';

// ── Execution drawer helpers ────────────────────────────────────────────────────────────────────────────────────

export var STEP_LABEL = { approval: 'Approval gate', wait: 'Wait', send_email: 'Send email', send_sms: 'Send SMS', agent_task: 'Agent task', webhook: 'Webhook', notify: 'Notification', slack: 'Slack message' };
// What each step type really does, so a row of "completed" cannot be mistaken for "something was tested".
// Approval and wait perform no technical action at all, by design.
export var STEP_WHAT = {
  approval: 'Human approval gate: pauses until a person approves. Performs no technical action.',
  wait: 'Timed delay. Performs no technical action.',
  send_email: 'Sends an email inject to the targets.',
  send_sms: 'Sends an SMS inject to the targets.',
  agent_task: 'Dispatches a task to the BAS agent on the endpoint.',
  webhook: 'Calls an external HTTP endpoint.',
  notify: 'Sends a notification.',
  slack: 'Sends a Slack message.',
};
export function stepLabel(t) { return STEP_LABEL[t] || String(t || 'Step'); }
export function stepWhat(t) { return STEP_WHAT[t] || ''; }
export function stepTone(status) {
  return status === 'completed' ? 'ok' : status === 'running' ? 'info' : status === 'waiting' ? 'warn' : status === 'failed' || status === 'aborted' ? 'bad' : 'muted';
}

// runSummary: where an execution is, from its steps. `current` is the step in progress, `waiting` the approval it is
// stuck on, `failed` the step that stopped it.
export function runSummary(execution, steps) {
  steps = list(steps);
  var total = steps.length || n(execution && execution.steps_total);
  var done = steps.length ? steps.filter(function(s) { return s.status === 'completed'; }).length : n(execution && execution.steps_done);
  var find = function(st) { return steps.filter(function(s) { return s.status === st; })[0] || null; };
  return { done: done, total: total, pct: total ? Math.round(done / total * 100) : null, current: find('running'), waiting: find('waiting'), failed: find('failed') };
}

// scoreTone: higher is better, so 75+ is good and under 50 is poor.
export function scoreTone(v) { var k = Number(v); return !isFinite(k) ? 'muted' : k >= 75 ? 'ok' : k >= 50 ? 'warn' : 'bad'; }

// resultPairs: a step's result object as [label, text] pairs; nested values are shown as compact JSON.
export function resultPairs(res) {
  if (!res || typeof res !== 'object') return [];
  return Object.keys(res).map(function(k) {
    var v = res[k];
    return [k.replace(/_/g, ' '), v !== null && typeof v === 'object' ? JSON.stringify(v) : String(v)];
  });
}

// stateNote: the one-line "what is happening" callout at the top of the drawer; null when there is nothing to add.
export function stateNote(execution, steps) {
  var st = execution && execution.status, s = runSummary(execution, steps);
  if (st === 'paused' && s.waiting) return { tone: 'warn', title: 'Waiting for approval', text: 'The exercise is paused at "' + (s.waiting.step_id || 'an approval step') + '". Nothing further runs until someone approves it.' };
  if (st === 'paused') return { tone: 'warn', title: 'Paused', text: 'The exercise is paused and will not continue until it is resumed.' };
  if (st === 'running') return { tone: 'info', title: 'Running', text: s.current ? 'Now on "' + (s.current.step_id || 'a step') + '" (' + stepLabel(s.current.step_type).toLowerCase() + '). This page refreshes by itself.' : 'The exercise is in progress. This page refreshes by itself.' };
  if (st === 'created') return { tone: 'muted', title: 'Not started', text: 'This execution was created but has not been launched, so no step has run.' };
  if (st === 'failed') return { tone: 'bad', title: 'Stopped by a failure', text: s.failed ? 'Step "' + (s.failed.step_id || 'a step') + '" failed, so the remaining steps did not run.' : 'A step failed, so the remaining steps did not run.' };
  if (st === 'aborted') return { tone: 'bad', title: 'Aborted', text: 'An operator stopped this exercise. Steps that had not run were skipped, and nothing already done was undone.' };
  return null;
}

export function planSteps(p) { return list(p && p.steps).length; }
