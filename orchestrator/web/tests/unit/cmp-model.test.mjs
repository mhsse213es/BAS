import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusInfo, mix, startedDay, startedStamp, agentsLine, cardFacts, runsLine, timeline, tagTone, chipCounts, filter, heroStats } from '../../src/features/cmp-model.js';

const C = (status, o, s) => Object.assign({ id: 'camp-1', name: 'APT29 Emulation', scenarioName: 'Apt29 Kill Chain', createdBy: 'asha.nair', startedAt: '2026-10-20T12:00:00Z', summary: Object.assign({ status, targets: 5, dispatched: 5 }, s) }, o);

test('statusInfo folds the paused overlay and tolerates unknown values', () => {
  assert.deepEqual([statusInfo({ status: 'completed' }).label, statusInfo({ status: 'completed' }).tone], ['Completed', 'ok']);
  assert.equal(statusInfo({ status: 'running' }).live, true);
  const p = statusInfo({ status: 'running', paused: true });
  assert.deepEqual([p.key, p.label, p.live], ['paused', 'Paused', false]);
  assert.equal(statusInfo({ status: 'weird' }).label, 'Weird');
  assert.equal(statusInfo(null).label, '—');
});

test('mix shares and the prevented rate', () => {
  const m = mix({ prevented: 3, detected: 1, missed: 1 });
  assert.equal(m.total, 5);
  assert.equal(m.preventedPct, 60);
  assert.deepEqual(m.segs.map((s) => s.pct), [60, 20, 20]);
  assert.equal(mix({}).preventedPct, null);
  assert.equal(mix(undefined).total, 0);
});

test('dates and the agents line', () => {
  assert.equal(startedDay(null), '—');
  assert.equal(startedDay('nope'), '—');
  assert.match(startedDay('2026-10-20T12:00:00Z'), /^\d{2}\/10\/2026$/);
  assert.match(startedStamp('2026-10-20T12:00:00Z'), /^\d{1,2} Oct 2026, \d{2}:\d{2}$/);
  assert.equal(agentsLine({ dispatched: 2, targets: 3, skipped: 1 }), '2/3 agents · 1 skipped');
  assert.equal(agentsLine({}), '0/0 agents');
});

test('cardFacts and runsLine', () => {
  const f = cardFacts(C('completed', {}, { prevented: 4, detected: 1 }));
  assert.equal(f.runs, 5);
  assert.equal(f.rate, 80);
  assert.equal(cardFacts({}).rate, null);
  assert.equal(runsLine(C('completed', {}, { prevented: 4, detected: 1 })), '5 runs · 80% prevented');
  assert.equal(runsLine(C('running', {}, { dispatched: 1 })), '1 run · no results yet');
});

test('timeline: dispatch, execution and results from the real counts', () => {
  const done = timeline(C('completed', { runs: [{ status: 'completed' }, { status: 'completed' }] }, { dispatched: 2, targets: 2, prevented: 5, detected: 0, missed: 0 }));
  assert.deepEqual(done.map((t) => t.state), ['done', 'done', 'done']);
  assert.equal(done[2].tag, '100%');
  const live = timeline(C('running', { runs: [{ status: 'completed' }, { status: 'running' }] }, { dispatched: 2, targets: 4, prevented: 1, missed: 1 }));
  assert.deepEqual(live.map((t) => t.state), ['run', 'run', 'run']);
  assert.equal(live[1].pct, 50);
  const bad = timeline(C('failed', { runs: [{ status: 'failed' }] }, { dispatched: 1, targets: 1 }));
  assert.equal(bad[1].state, 'fail');
  assert.equal(bad[2].state, 'wait');
  assert.equal(bad[2].tag, null);
  const none = timeline({});
  assert.deepEqual(none.map((t) => t.state), ['wait', 'wait', 'wait']);
  assert.equal(tagTone(90), 'ok');
  assert.equal(tagTone(60), 'warn');
});

test('chipCounts lists All plus the states that exist', () => {
  const list = [C('completed'), C('completed'), C('partial'), C('odd')];
  assert.deepEqual(chipCounts(list).map((c) => [c.id, c.count]), [['all', 4], ['completed', 2], ['partial', 1], ['odd', 1]]);
  assert.deepEqual(chipCounts([]).map((c) => c.id), ['all']);
});

test('filter by chip and search text', () => {
  const list = [C('completed'), C('partial', { id: 'camp-2', name: 'Finance Sweep', scenarioName: 'Lolbin', createdBy: 'rohan' })];
  assert.equal(filter(list, 'all', '').length, 2);
  assert.equal(filter(list, 'partial', '').length, 1);
  assert.equal(filter(list, 'all', 'lolbin').length, 1);
  assert.equal(filter(list, 'all', 'ROHAN').length, 1);
  assert.equal(filter(list, 'completed', 'finance').length, 0);
  assert.equal(filter(null, 'all', '').length, 0);
});

test('heroStats', () => {
  const h = heroStats([C('completed', {}, { dispatched: 5 }), C('partial', {}, { dispatched: 3 }), { name: 'x' }]);
  assert.deepEqual(h, { total: 3, completed: 1, partial: 1, runs: 8 });
});
