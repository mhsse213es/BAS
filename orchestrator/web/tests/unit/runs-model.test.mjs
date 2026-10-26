import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/runs-model.js';

const R = (o) => ({ id: 'r', name: 'N', status: 'completed', agentId: 'a-1', ...o });
const AG = [{ agentId: 'a-1', hostname: 'HOST-1' }, { agentId: 'a-2', hostname: 'HOST-2' }];

test('heroStats counts running and queued apart, ignores unfinished runs in the pass rate', () => {
  const h = M.heroStats([R({ status: 'running' }), R({ status: 'pending', agentId: 'a-2' }), R({ status: 'completed' }), R({ status: 'failed' }), R({ status: 'completed' })], AG);
  assert.equal(h.running, 1); assert.equal(h.queued, 1); assert.equal(h.passRate, '67%'); assert.equal(h.agentsBusy, '2 / 2');
  assert.equal(M.heroStats([], []).passRate, '—');
  assert.equal(M.heroStats([R({ status: 'running' })], []).agentsBusy, '1');
});

test('liveRuns skips sweep children and orders newest first', () => {
  const l = M.liveRuns([R({ id: 'a', status: 'running', startedAt: '2026-10-26T01:00:00Z' }), R({ id: 'b', status: 'running', sweepId: 's' }), R({ id: 'c', status: 'queued', startedAt: '2026-10-26T02:00:00Z' }), R({ id: 'd' })]);
  assert.deepEqual(l.map((r) => r.id), ['c', 'a']);
});

test('liveCard words each state and never invents a percentage', () => {
  const c = M.liveCard(R({ status: 'running', progress: { stepsTotal: 4, stepsDone: 1, stepsPassed: 1, stepsFailed: 0 } }), AG);
  assert.equal(c.pct, 25); assert.equal(c.step, 'Step 2 of 4'); assert.equal(c.target, 'HOST-1'); assert.equal(c.tag, '0 fail / 1 pass');
  assert.equal(M.liveCard(R({ status: 'pending' }), AG).step, 'Waiting to start');
  assert.equal(M.liveCard(R({ status: 'running', paused: true, progress: { stepsTotal: 4, stepsDone: 2 } }), AG).label, 'Paused');
  assert.equal(M.liveCard(R({ status: 'running', agentDisconnected: true }), AG).label, 'Agent Disconnected');
  assert.equal(M.liveCard(R({ status: 'running' }), AG).pct, 0);
  assert.equal(M.liveCard(R({ status: 'running' }), AG).tag, '');
});

test('weekSeries ends on the newest run day and counts only completed and failed', () => {
  const w = M.weekSeries([R({ startedAt: '2026-10-26T10:00:00' }), R({ status: 'failed', startedAt: '2026-10-26T11:00:00' }), R({ status: 'running', startedAt: '2026-10-26T11:00:00' }), R({ startedAt: '2026-10-01T11:00:00' })]);
  assert.equal(w.labels.length, 7); assert.equal(w.total, 2); assert.equal(w.passed[6], 1); assert.equal(w.failed[6], 1); assert.equal(w.peak, 2);
  assert.deepEqual(M.weekSeries([]).labels, []);
});

test('status and target options come from the data, in a fixed order', () => {
  const runs = [R({ status: 'failed' }), R({ status: 'pending' }), R({ status: 'completed', agentId: 'a-2' }), R({ status: 'weird' })];
  assert.deepEqual(M.statusOptions(runs).map((o) => o.id), ['queued', 'completed', 'failed', 'weird']);
  assert.equal(M.statusOptions(runs)[0].label, 'Queued');
  assert.deepEqual(M.targetOptions(runs, AG).map((o) => o.id), ['HOST-1', 'HOST-2']);
});

test('matchRun applies status, target and free text together', () => {
  const r = R({ id: 'abc123', name: 'Shadow Copy', initiatedBy: 'asha' });
  assert.ok(M.matchRun(r, { q: 'shadow' }, AG));
  assert.ok(M.matchRun(r, { q: 'HOST-1' }, AG));
  assert.ok(!M.matchRun(r, { q: 'nope' }, AG));
  assert.ok(!M.matchRun(r, { status: 'failed' }, AG));
  assert.ok(M.matchRun(R({ status: 'pending' }), { status: 'queued' }, AG));
  assert.ok(!M.matchRun(r, { target: 'HOST-2' }, AG));
});

test('outcomeSegments keeps one slice per status present', () => {
  const s = M.outcomeSegments([R(), R(), R({ status: 'failed' }), R({ status: 'pending' })]);
  assert.deepEqual(s.map((x) => [x.key, x.value]), [['queued', 1], ['completed', 2], ['failed', 1]]);
});

test('fmtWhen: time today, Yesterday, then day and month', () => {
  const now = new Date('2026-10-26T12:00:00').getTime();
  assert.equal(M.fmtWhen('2026-10-26T09:05:00', now), '09:05');
  assert.equal(M.fmtWhen('2026-10-25T23:40:00', now), 'Yesterday 23:40');
  assert.equal(M.fmtWhen('2026-10-20T08:00:00', now), '20 Oct 08:00');
  assert.equal(M.fmtWhen('', now), '—'); assert.equal(M.fmtWhen('nope', now), '—');
});

test('shortRunId shortens uuids and long ids, leaves short ones', () => {
  assert.equal(M.shortRunId('922b1b2b-42e6-4c1a-9d3e-aaaaaaaaaaaa'), '922b1b2b-42e6…');
  assert.equal(M.shortRunId('run-1'), 'run-1');
  assert.equal(M.shortRunId('18cea85f279812f5aa'), '18cea85f279812…');
});

test('csvText quotes every field and neutralises formulas', () => {
  assert.equal(M.csvText(['A', 'B'], [['=1+1', 'say "hi"']]), '"A","B"\n"\'=1+1","say ""hi"""');
});

test('table helpers: numeric detection, sorting numbers, paging text', () => {
  assert.ok(M.allNumeric(['12%', '', '—', '3']));
  assert.ok(!M.allNumeric(['a', '1']));
  assert.equal(M.cellNumber('50% prev'), 50);
  assert.equal(M.pageCount(17, 8), 3); assert.equal(M.pageCount(0, 8), 1);
  assert.equal(M.rangeText(13, 1, 8), 'Showing 9–13 of 13');
  assert.equal(M.rangeText(0, 0, 8), 'No rows match the filter');
});
