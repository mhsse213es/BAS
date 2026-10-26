// Pure helpers for the redesigned Scheduled Assessments page: next occurrences worked out from each
// schedule's recurrence fields, the next-7-days plan, the last-run outcome, the table filter, sort
// and paging. No DOM, no network: everything comes from the rows GET /api/scheduled-assessments
// returned (plus, for the last-run outcome, GET /api/jobs/{id} for the job a schedule last spawned).
//
// Times are worked out in each schedule's own IANA time zone and shown in the viewer's zone. The
// server nudges each occurrence by up to +/-2 minutes (a fixed offset per schedule); the nominal time
// is what these helpers report.

import { pageCount, rangeText, csvText } from './runs-model.js';

export { pageCount, rangeText, csvText };

var DAY = 86400000;

export function localZone() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (e) { return 'UTC'; }
}

// tzParts: the wall-clock fields of an instant in a zone. Throws RangeError for an unknown zone.
export function tzParts(ts, tz) {
  var f = new Intl.DateTimeFormat('en-US', { timeZone: tz || 'UTC', hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' });
  var o = {};
  f.formatToParts(new Date(ts)).forEach(function(p) { if (p.type !== 'literal') o[p.type] = parseInt(p.value, 10); });
  return { y: o.year, m: o.month, d: o.day, h: o.hour === 24 ? 0 : o.hour, mi: o.minute, s: o.second };
}

// zonedToUtc: the instant at which a zone's wall clock shows y-m-d hh:mm.
export function zonedToUtc(y, m, d, hh, mm, tz) {
  var want = Date.UTC(y, m - 1, d, hh, mm);
  var guess = want;
  for (var i = 0; i < 3; i++) {
    var p = tzParts(guess, tz);
    guess += want - Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s);
  }
  return guess;
}

function timeOfDay(s) {
  var m = /^(\d{1,2}):(\d{2})$/.exec(String(s || ''));
  if (!m) return null;
  var h = +m[1], mi = +m[2];
  return h > 23 || mi > 59 ? null : { h: h, mi: mi };
}

function ms(v) { var t = v ? new Date(v).getTime() : NaN; return isNaN(t) ? null : t; }

// statusKey: enabled / completed (a one-time schedule that fired) / cancelled. Same rule as schedStatus.
export function statusKey(sch) {
  if (sch.RecurrenceType === 'once' && sch.LastOccurrenceAt) return 'completed';
  return sch.Enabled ? 'enabled' : 'cancelled';
}

// occurrences: the nominal fire times of a schedule inside [fromTs, toTs), oldest first.
export function occurrences(sch, fromTs, toTs) {
  if (!sch || statusKey(sch) !== 'enabled') return [];
  var type = sch.RecurrenceType || 'weekly';
  var end = ms(sch.EndDate);
  var tz = sch.Timezone || 'UTC';
  var out = [];
  if (type === 'once') {
    var at = ms(sch.RunAt);
    if (at !== null && at >= fromTs && at < toTs && (end === null || at <= end)) out.push(at);
    return out;
  }
  var tod = timeOfDay(sch.TimeOfDay);
  if (!tod) return [];
  try {
    var seen = '';
    for (var t = fromTs - DAY; t <= toTs + DAY; t += DAY / 2) {
      var p = tzParts(t, tz);
      var key = p.y + '-' + p.m + '-' + p.d;
      if (key === seen) continue;
      seen = key;
      var dow = new Date(Date.UTC(p.y, p.m - 1, p.d)).getUTCDay();
      var hit = type === 'daily' || (type === 'weekly' && dow === (sch.DayOfWeek || 0)) || (type === 'monthly' && p.d === sch.DayOfMonth);
      if (!hit) continue;
      var inst = zonedToUtc(p.y, p.m, p.d, tod.h, tod.mi, tz);
      if (inst >= fromTs && inst < toTs && (end === null || inst <= end)) out.push(inst);
    }
  } catch (e) { return []; }
  return out.sort(function(a, b) { return a - b; });
}

// nextRun: the next fire time at or after nowTs, or null (cancelled, completed, ended, or unparseable).
export function nextRun(sch, nowTs) {
  var spans = [8, 40, 400];
  for (var i = 0; i < spans.length; i++) {
    var o = occurrences(sch, nowTs, nowTs + spans[i] * DAY);
    if (o.length) return o[0];
  }
  return null;
}

// ── formatting in the viewer's zone ────────────────────────────────────────
var WD = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function two(n) { return (n < 10 ? '0' : '') + n; }
function wall(ts, tz) {
  var p = tzParts(ts, tz);
  return { p: p, wd: WD[new Date(Date.UTC(p.y, p.m - 1, p.d)).getUTCDay()], hm: two(p.h) + ':' + two(p.mi) };
}
// fmtWhen: "Wed 29 Oct, 22:00"
export function fmtWhen(ts, tz) {
  if (ts == null) return '—';
  var w = wall(ts, tz || localZone());
  return w.wd + ' ' + w.p.d + ' ' + MON[w.p.m - 1] + ', ' + w.hm;
}
// fmtDayTime: "Mon 09:00"
export function fmtDayTime(ts, tz) {
  if (ts == null) return '—';
  var w = wall(ts, tz || localZone());
  return w.wd + ' ' + w.hm;
}
export function fmtTime(ts, tz) { return wall(ts, tz || localZone()).hm; }

// weekPlan: seven day columns starting today (viewer's zone) with the runs planned in them.
export function weekPlan(list, nowTs, nameOf, tz) {
  tz = tz || localZone();
  var start = wall(nowTs, tz).p;
  var days = [];
  var byKey = {};
  for (var i = 0; i < 7; i++) {
    var d = new Date(Date.UTC(start.y, start.m - 1, start.d + i));
    var day = { key: d.getUTCFullYear() + '-' + (d.getUTCMonth() + 1) + '-' + d.getUTCDate(), label: WD[d.getUTCDay()] + ' ' + d.getUTCDate(), today: i === 0, events: [] };
    days.push(day);
    byKey[day.key] = day;
  }
  var planned = 0;
  (list || []).forEach(function(sch) {
    occurrences(sch, nowTs, nowTs + 8 * DAY).forEach(function(ts) {
      var p = tzParts(ts, tz);
      var day = byKey[p.y + '-' + p.m + '-' + p.d];
      if (!day) return;
      day.events.push({ ts: ts, time: two(p.h) + ':' + two(p.mi), name: nameOf ? nameOf(sch) : sch.ID });
      planned++;
    });
  });
  days.forEach(function(d) { d.events.sort(function(a, b) { return a.ts - b.ts; }); });
  return { days: days, planned: planned };
}

// nextAcross: the schedule that fires next, as { sch, ts } (null when nothing is scheduled).
export function nextAcross(list, nowTs) {
  var best = null;
  (list || []).forEach(function(sch) {
    var ts = nextRun(sch, nowTs);
    if (ts !== null && (!best || ts < best.ts)) best = { sch: sch, ts: ts };
  });
  return best;
}

// ── last-run outcome (from the job a schedule last spawned) ────────────────
var RESULT = {
  completed: { key: 'completed', label: 'Completed', tone: 'ok' },
  partial: { key: 'partial', label: 'Partial', tone: 'warn' },
  failed: { key: 'failed', label: 'Failed', tone: 'bad' },
  running: { key: 'running', label: 'Running', tone: 'info' },
  requested: { key: 'running', label: 'Queued', tone: 'info' },
  cancelled: { key: 'cancelled', label: 'Cancelled', tone: 'muted' },
};
export function resultOf(job) {
  var s = String((job && (job.State || job.state)) || '').toLowerCase();
  return RESULT[s] || { key: 'none', label: '—', tone: 'muted' };
}

// lastRunsCompleted: how many of the schedules whose last run finished ended fully completed.
export function lastRunsCompleted(results) {
  var done = 0, total = 0;
  (results || []).forEach(function(r) {
    if (!r || r.key === 'none' || r.key === 'running') return;
    total++;
    if (r.key === 'completed') done++;
  });
  return { done: done, total: total, pct: total ? Math.round(done / total * 100) : null };
}

// ── table: filter, sort, page ──────────────────────────────────────────────
// A row is { id, name, mode, targets, recurrence, lastTs, nextTs, result:{label}, status:{key,label} }.
export function filterRows(rows, f) {
  var q = String((f && f.q) || '').trim().toLowerCase();
  var tq = String((f && f.tq) || '').trim().toLowerCase();
  return (rows || []).filter(function(r) {
    if (f && f.status && f.status !== 'all' && r.status.key !== f.status) return false;
    var hay = [r.name, r.id, r.mode, r.targets, r.recurrence, r.result.label, r.status.label].join(' ').toLowerCase();
    if (q && hay.indexOf(q) === -1) return false;
    return !tq || hay.indexOf(tq) !== -1;
  });
}

export var COLUMNS = ['Assessment', 'Mode', 'Targets', 'Recurrence', 'Last run', 'Next run', 'Last result', 'Status'];

export function sortValue(r, col) {
  switch (col) {
    case 0: return r.name;
    case 1: return r.mode;
    case 2: return r.targets;
    case 3: return r.recurrence;
    case 4: return r.lastTs;
    case 5: return r.nextTs;
    case 6: return r.result.label;
    default: return r.status.label;
  }
}

// sortRows: stable; empty values (never run, no next run) always sort last.
export function sortRows(rows, col, dir) {
  if (col < 0) return rows.slice();
  var d = dir < 0 ? -1 : 1;
  return rows.map(function(r, i) { return { r: r, i: i }; }).sort(function(a, b) {
    var u = sortValue(a.r, col), v = sortValue(b.r, col);
    var ue = u == null || u === '' || u === '—', ve = v == null || v === '' || v === '—';
    if (ue || ve) return ue && ve ? a.i - b.i : ue ? 1 : -1;
    var c = typeof u === 'number' && typeof v === 'number' ? u - v : String(u).localeCompare(String(v), undefined, { numeric: true });
    return c * d || a.i - b.i;
  }).map(function(o) { return o.r; });
}

export function pageSlice(rows, page, per) {
  var pages = pageCount(rows.length, per);
  var p = Math.min(Math.max(0, page), pages - 1);
  return { page: p, pages: pages, rows: rows.slice(p * per, p * per + per) };
}

// heroStats: the four banner chips.
export function heroStats(list, nowTs) {
  var enabled = 0, cancelled = 0;
  (list || []).forEach(function(s) { var k = statusKey(s); if (k === 'enabled') enabled++; else if (k === 'cancelled') cancelled++; });
  var n = nextAcross(list, nowTs);
  return { total: (list || []).length, enabled: enabled, cancelled: cancelled, nextTs: n ? n.ts : null };
}

// fmtStamp: "21/10/2026, 17:30" in the viewer's zone, like the design's date columns.
export function fmtStamp(ts, tz) {
  if (ts == null) return '—';
  var p = tzParts(ts, tz || localZone());
  return two(p.d) + '/' + two(p.m) + '/' + p.y + ', ' + two(p.h) + ':' + two(p.mi);
}
