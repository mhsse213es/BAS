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
