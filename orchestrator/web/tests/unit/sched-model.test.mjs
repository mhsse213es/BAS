import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusKey, zonedToUtc, occurrences, nextRun, nextAcross, weekPlan, fmtWhen, fmtDayTime, resultOf, lastRunsCompleted, filterRows, sortRows, pageSlice, heroStats } from '../../src/features/sched-model.js';

// Monday 2026-10-26 09:30 UTC
const NOW = Date.UTC(2026, 9, 26, 9, 30);
const H = 3600000;
const D = 24 * H;
const S = (o) => Object.assign({ ID: 's', Enabled: true, RecurrenceType: 'weekly', DayOfWeek: 1, TimeOfDay: '10:00', Timezone: 'UTC', LastOccurrenceAt: null }, o);

test('status: a fired one-time schedule is completed, a disabled one cancelled', () => {
  assert.equal(statusKey(S({ RecurrenceType: 'once', LastOccurrenceAt: '2026-01-01T00:00:00Z' })), 'completed');
  assert.equal(statusKey(S({})), 'enabled');
  assert.equal(statusKey(S({ Enabled: false })), 'cancelled');
});

test('zonedToUtc converts a wall-clock time in a zone (no DST in Kolkata, DST in New York)', () => {
  assert.equal(zonedToUtc(2026, 10, 27, 9, 0, 'Asia/Kolkata'), Date.UTC(2026, 9, 27, 3, 30));
  assert.equal(zonedToUtc(2026, 7, 1, 9, 0, 'America/New_York'), Date.UTC(2026, 6, 1, 13, 0));
  assert.equal(zonedToUtc(2026, 12, 1, 9, 0, 'America/New_York'), Date.UTC(2026, 11, 1, 14, 0));
});

test('weekly: next run is this Monday later today, or next Monday once it has passed', () => {
  assert.equal(nextRun(S({}), NOW), Date.UTC(2026, 9, 26, 10, 0));
  assert.equal(nextRun(S({ TimeOfDay: '09:00' }), NOW), Date.UTC(2026, 10, 2, 9, 0));
});

test('weekly in another zone lands on the right UTC instant', () => {
  const s = S({ Timezone: 'Asia/Kolkata', DayOfWeek: 3, TimeOfDay: '22:00' });
  assert.equal(nextRun(s, NOW), Date.UTC(2026, 9, 28, 16, 30));
});

test('daily gives one run per day and monthly the matching day', () => {
  assert.equal(occurrences(S({ RecurrenceType: 'daily', TimeOfDay: '23:00' }), NOW, NOW + 7 * D).length, 7);
  const m = occurrences(S({ RecurrenceType: 'monthly', DayOfMonth: 1, TimeOfDay: '01:00' }), NOW, NOW + 30 * D);
  assert.deepEqual(m, [Date.UTC(2026, 10, 1, 1, 0)]);
});

test('once fires only when still pending, and not past its end date', () => {
  const at = new Date(NOW + 2 * D).toISOString();
  assert.deepEqual(occurrences(S({ RecurrenceType: 'once', RunAt: at }), NOW, NOW + 7 * D), [NOW + 2 * D]);
  assert.deepEqual(occurrences(S({ RecurrenceType: 'once', RunAt: at, LastOccurrenceAt: at }), NOW, NOW + 7 * D), []);
  assert.deepEqual(occurrences(S({ RecurrenceType: 'daily', EndDate: new Date(NOW + 2 * D).toISOString() }), NOW, NOW + 7 * D).length, 2);
});

test('cancelled schedules and bad data have no next run', () => {
  assert.equal(nextRun(S({ Enabled: false }), NOW), null);
  assert.equal(nextRun(S({ TimeOfDay: 'soon' }), NOW), null);
  assert.equal(nextRun(S({ Timezone: 'Not/AZone' }), NOW), null);
});

test('next across schedules picks the earliest', () => {
  const a = S({ ID: 'a', TimeOfDay: '12:00' }), b = S({ ID: 'b', TimeOfDay: '10:00' });
  assert.equal(nextAcross([a, b], NOW).sch.ID, 'b');
  assert.equal(nextAcross([S({ Enabled: false })], NOW), null);
});

test('week plan has seven days, today first, with each run in its day', () => {
  const list = [S({ ID: 'a', RecurrenceType: 'daily', TimeOfDay: '23:00' }), S({ ID: 'b', TimeOfDay: '10:00' })];
  const w = weekPlan(list, NOW, (s) => 'name-' + s.ID, 'UTC');
  assert.equal(w.days.length, 7);
  assert.equal(w.days[0].label, 'Mon 26');
  assert.equal(w.days[0].today, true);
  assert.deepEqual(w.days[0].events.map((e) => e.time + ' ' + e.name), ['10:00 name-b', '23:00 name-a']);
  assert.equal(w.days[1].events.length, 1);
  assert.equal(w.planned, 8);
});

test('times are written like the design', () => {
  assert.equal(fmtWhen(Date.UTC(2026, 9, 29, 22, 0), 'UTC'), 'Thu 29 Oct, 22:00');
  assert.equal(fmtDayTime(Date.UTC(2026, 9, 26, 9, 0), 'UTC'), 'Mon 09:00');
  assert.equal(fmtWhen(null, 'UTC'), '—');
});

test('last run outcome comes from the spawned job state', () => {
  assert.equal(resultOf({ State: 'completed' }).tone, 'ok');
  assert.equal(resultOf({ State: 'partial' }).tone, 'warn');
  assert.equal(resultOf({ State: 'failed' }).tone, 'bad');
  assert.equal(resultOf({ State: 'requested' }).label, 'Queued');
  assert.equal(resultOf(null).key, 'none');
  assert.deepEqual(lastRunsCompleted([resultOf({ State: 'completed' }), resultOf({ State: 'failed' }), resultOf(null), resultOf({ State: 'running' })]), { done: 1, total: 2, pct: 50 });
  assert.equal(lastRunsCompleted([]).pct, null);
});

const R = (id, name, o) => Object.assign({ id, name, mode: 'Posture', targets: 'g', recurrence: 'Weekly', lastTs: null, nextTs: null, result: { label: '—' }, status: { key: 'enabled', label: 'Enabled' } }, o);
const rows = [R('1', 'Beta', { lastTs: 5, nextTs: 30 }), R('2', 'alpha', { lastTs: 9, status: { key: 'cancelled', label: 'Cancelled' } }), R('3', 'Gamma', { lastTs: 1, nextTs: 10 })];

test('filter by status, search and table query', () => {
  assert.deepEqual(filterRows(rows, { status: 'cancelled' }).map((r) => r.id), ['2']);
  assert.deepEqual(filterRows(rows, { q: 'gam' }).map((r) => r.id), ['3']);
  assert.deepEqual(filterRows(rows, { status: 'enabled', tq: 'beta' }).map((r) => r.id), ['1']);
  assert.equal(filterRows(rows, {}).length, 3);
});

test('sort handles text, numbers and keeps empty values last in both directions', () => {
  assert.deepEqual(sortRows(rows, 0, 1).map((r) => r.id), ['2', '1', '3']);
  assert.deepEqual(sortRows(rows, 5, 1).map((r) => r.id), ['3', '1', '2']);
  assert.deepEqual(sortRows(rows, 5, -1).map((r) => r.id), ['1', '3', '2']);
  assert.deepEqual(sortRows(rows, -1, 1).map((r) => r.id), ['1', '2', '3']);
});

test('paging clamps to the last page', () => {
  const p = pageSlice([1, 2, 3, 4, 5], 9, 2);
  assert.deepEqual([p.page, p.pages, p.rows], [2, 3, [5]]);
});

test('banner numbers are counted from the schedules', () => {
  const h = heroStats([S({ ID: 'a' }), S({ ID: 'b', Enabled: false }), S({ ID: 'c', RecurrenceType: 'once', LastOccurrenceAt: '2026-01-01T00:00:00Z' })], NOW);
  assert.deepEqual([h.total, h.enabled, h.cancelled], [3, 1, 1]);
  assert.equal(h.nextTs, Date.UTC(2026, 9, 26, 10, 0));
});
