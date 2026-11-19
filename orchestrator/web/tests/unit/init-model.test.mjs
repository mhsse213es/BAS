import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stateLabel, stateTone, shortId, initials, facts, status, barTone, strip, stateRows, jobTone, heroStats, chipCounts, search, shortDate } from '../../src/features/init-model.js';

const P = (o) => Object.assign({ Total: 0, Completed: 0, Running: 0, Requested: 0, Partial: 0, Failed: 0, Cancelled: 0, PercentComplete: 0 }, o);
const IT = (o) => Object.assign({ ID: 'init-1', Name: 'A', State: 'active', CreatedBy: 'asha.nair', Description: '' }, o);

test('labels, tones and ids', () => {
  assert.equal(stateLabel('active'), 'Active');
  assert.equal(stateLabel(''), '—');
  assert.equal(stateTone('active'), 'ok');
  assert.equal(stateTone('closed'), 'info');
  assert.equal(stateTone('archived'), 'muted');
  assert.equal(shortId('0123456789abcdef'), '01234567');
  assert.equal(shortId('init-1'), 'init-1');
  assert.equal(initials('asha.nair'), 'AN');
  assert.equal(initials('admin@preview.local'), 'AP');
  assert.equal(initials(''), '?');
});

test('facts: null until progress loads, running folds in requested', () => {
  assert.equal(facts(null), null);
  const f = facts(P({ Total: 5, Completed: 2, Running: 1, Requested: 1, Failed: 1, PercentComplete: 40.4 }));
  assert.deepEqual([f.total, f.completed, f.running, f.failed, f.pct], [5, 2, 2, 1, 40]);
});

test('status is derived from the jobs and only for active initiatives', () => {
  assert.equal(status(IT({}), null), null);
  assert.equal(status(IT({ State: 'closed' }), facts(P({ Total: 1 }))), null);
  assert.equal(status(IT({}), facts(P({}))).label, 'No jobs yet');
  assert.equal(status(IT({}), facts(P({ Total: 3, Completed: 3 }))).label, 'On track');
  assert.equal(status(IT({}), facts(P({ Total: 3, Failed: 1 }))).label, 'At risk');
  assert.equal(status(IT({}), facts(P({ Total: 3, Partial: 1 }))).tone, 'warn');
});

test('bar tone', () => {
  assert.equal(barTone(IT({}), facts(P({ Total: 2, Failed: 1 }))), 'warn');
  assert.equal(barTone(IT({}), facts(P({ Total: 2, Completed: 2 }))), 'ok');
  assert.equal(barTone(IT({}), facts(P({ Total: 2, Completed: 1 }))), 'accent');
  assert.equal(barTone(IT({ State: 'closed' }), null), 'ok');
});

test('strip: one segment per job, scaled down when there are many', () => {
  assert.deepEqual(strip(null), []);
  assert.deepEqual(strip(facts(P({}))), []);
  assert.deepEqual(strip(facts(P({ Total: 5, Completed: 2, Running: 1, Failed: 1, Cancelled: 1 }))), ['done', 'done', 'run', 'fail', '']);
  const big = strip(facts(P({ Total: 200, Completed: 150, Failed: 50 })), 20);
  assert.ok(big.length <= 20 && big.length >= 18);
  assert.equal(big[0], 'done');
  assert.equal(big[big.length - 1], 'fail');
  const tiny = strip(facts(P({ Total: 100, Completed: 99, Failed: 1 })), 10);
  assert.ok(tiny.includes('fail'), 'a single failure still shows');
});

test('stateRows leaves out empty states and sums to the whole', () => {
  assert.deepEqual(stateRows(null), []);
  const rows = stateRows(facts(P({ Total: 4, Completed: 2, Failed: 2 })));
  assert.deepEqual(rows.map((r) => r[0]), ['Completed', 'Failed']);
  assert.equal(rows[0][1], 50);
  assert.equal(rows[1][3], 2);
});

test('job tones', () => {
  assert.equal(jobTone('completed'), 'ok');
  assert.equal(jobTone('FAILED'), 'bad');
  assert.equal(jobTone('partial'), 'warn');
  assert.equal(jobTone('running'), 'info');
  assert.equal(jobTone('cancelled'), 'muted');
});

test('heroStats counts active, averages loaded progress, flags at-risk, sums jobs', () => {
  const all = [IT({ ID: 'a' }), IT({ ID: 'b' }), IT({ ID: 'c', State: 'closed' }), IT({ ID: 'd' })];
  const d = { a: facts(P({ Total: 4, Completed: 4, PercentComplete: 100 })), b: facts(P({ Total: 2, Failed: 1, PercentComplete: 50 })), c: facts(P({ Total: 3, Completed: 3, PercentComplete: 100 })) };
  assert.deepEqual(heroStats(all, d), { active: 3, avg: 75, atRisk: 1, jobs: 9 });
  assert.deepEqual(heroStats([], {}), { active: 0, avg: null, atRisk: 0, jobs: 0 });
  assert.equal(heroStats(all, {}).avg, null);
});

test('chip counts and search', () => {
  const all = [IT({ State: 'active' }), IT({ State: 'closed' }), IT({ State: 'archived' }), IT({ State: 'weird' })];
  assert.deepEqual(chipCounts(all), { active: 1, closed: 1, archived: 1, all: 4 });
  const list = [IT({ Name: 'Ransomware', CreatedBy: 'asha' }), IT({ Name: 'Domain', CreatedBy: 'rohan', Description: 'LSASS hardening' })];
  assert.equal(search(list, '').length, 2);
  assert.equal(search(list, 'RANSOM').length, 1);
  assert.equal(search(list, 'rohan').length, 1);
  assert.equal(search(list, 'lsass').length, 1);
  assert.equal(search(list, 'zzz').length, 0);
});

test('shortDate', () => {
  assert.equal(shortDate(''), '—');
  assert.equal(shortDate('nope'), '—');
  assert.match(shortDate('2026-09-15T12:00:00Z'), /^1[45] Sep 2026$/);
});
