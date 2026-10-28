import test from 'node:test';
import assert from 'node:assert/strict';
import * as L from '../../src/features/live-run-model.js';

const T0 = Date.parse('2026-10-28T14:02:00Z');

test('fmtDuration prints seconds, minutes and hours the way an operator reads them', () => {
  assert.equal(L.fmtDuration(0), '0s');
  assert.equal(L.fmtDuration(42000), '42s');
  assert.equal(L.fmtDuration(18 * 60000 + 40000), '18m 40s');
  assert.equal(L.fmtDuration(3600000 + 5 * 60000), '1h 05m');
  assert.equal(L.fmtDuration(-5000), '0s', 'a start time ahead of this browser clock never prints a negative');
  assert.equal(L.fmtDuration(NaN), '—');
});

test('runDuration counts to now while running and stops at the completion time once finished', () => {
  const live = { status: 'running', startedAt: '2026-10-28T14:02:00Z' };
  assert.equal(L.runDuration(live, T0 + 90000), '1m 30s');
  const done = { status: 'completed', startedAt: '2026-10-28T14:02:00Z', completedAt: '2026-10-28T14:10:05Z' };
  assert.equal(L.runDuration(done, T0 + 99999999), '8m 05s');
  assert.equal(L.runDuration(null, T0), '—', 'no run record means no invented number');
  assert.equal(L.runDuration({ status: 'running' }, T0), '—');
});

test('liveStatus follows the run record: queued, running, paused, disconnected, finished', () => {
  assert.deepEqual(L.liveStatus({ status: 'pending' }, {}), { key: 'queued', label: 'Queued', tone: 'warn', live: true });
  assert.deepEqual(L.liveStatus({ status: 'running' }, {}), { key: 'running', label: 'Running', tone: 'info', live: true });
  assert.equal(L.liveStatus({ status: 'running', paused: true }, {}).label, 'Paused');
  assert.equal(L.liveStatus({ status: 'running', agentDisconnected: true }, {}).label, 'Agent Disconnected');
  assert.equal(L.liveStatus({ status: 'completed' }, {}).tone, 'ok');
  assert.equal(L.liveStatus({ status: 'completed' }, {}).live, false);
  assert.equal(L.liveStatus({ status: 'partial' }, {}).tone, 'warn');
  assert.equal(L.liveStatus({ status: 'failed' }, {}).tone, 'bad');
});

test('liveStatus uses a paused or resumed event ahead of a run record that has not refreshed yet', () => {
  assert.equal(L.liveStatus({ status: 'running', paused: false }, { paused: true }).label, 'Paused');
  assert.equal(L.liveStatus({ status: 'running', paused: true }, { paused: false }).label, 'Running');
});

test('liveStatus with no run record at all is honest: Running only if steps are streaming', () => {
  assert.equal(L.liveStatus(null, { running: 2, done: 0, total: 5 }).label, 'Running');
  assert.equal(L.liveStatus(null, { running: 0, done: 5, total: 5 }).label, 'Finished');
  assert.equal(L.liveStatus(null, { running: 0, done: 0, total: 0 }).label, 'Waiting');
});

test('progressPct is bounded and zero when the total is not known yet', () => {
  assert.equal(L.progressPct({ done: 3, total: 12 }), 25);
  assert.equal(L.progressPct({ done: 0, total: 0 }), 0);
  assert.equal(L.progressPct({ done: 15, total: 12 }), 100);
});

test('stepNote is one plain line: the verdict, else the state, with the duration when known', () => {
  assert.equal(L.stepNote({ state: 'done', verdict: 'pass', durationMs: 1200 }), 'Prevented · 1.2 s');
  assert.equal(L.stepNote({ state: 'done', verdict: 'fail', durationMs: 90 }), 'Not Prevented · 90 ms');
  assert.equal(L.stepNote({ state: 'running' }), 'Running…');
  assert.equal(L.stepNote({ state: 'queued' }), 'Pending');
  assert.equal(L.stepNote({ state: 'timeout' }), 'Timed out');
  assert.equal(L.stepNote({ state: 'killed' }), 'Stopped');
  assert.equal(L.stepNote({ state: 'done', verdict: 'vetoed' }), 'Vetoed (Policy)');
});

test('stepMark picks the timeline marker: done, fail, running or waiting', () => {
  assert.equal(L.stepMark({ state: 'done', verdict: 'pass' }), 'done');
  assert.equal(L.stepMark({ state: 'done', verdict: 'fail' }), 'fail');
  assert.equal(L.stepMark({ state: 'done', verdict: 'blocked' }), 'warn');
  assert.equal(L.stepMark({ state: 'timeout' }), 'fail');
  assert.equal(L.stepMark({ state: 'running' }), 'run');
  assert.equal(L.stepMark({ state: 'queued' }), 'wait');
});

test('logLine turns a persisted run event into one dated line and ignores noise', () => {
  const at = '2026-10-28T14:03:07Z';
  const q = L.logLine({ type: 'queued', stepName: 'Encoded PowerShell', techniqueId: 'T1059.001', ts: at });
  assert.equal(q, null, 'queueing every step would drown the log');
  const s = L.logLine({ type: 'started', stepName: 'Encoded PowerShell', techniqueId: 'T1059.001', ts: at });
  assert.equal(s.tone, 'inf');
  assert.match(s.text, /Started T1059\.001/);
  assert.match(s.text, /Encoded PowerShell/);
  const c = L.logLine({ type: 'completed', stepName: 'x', techniqueId: 'T1', payload: { verdict: 'fail', durationMs: 50 }, ts: at });
  assert.equal(c.tone, 'bad');
  assert.match(c.text, /Not Prevented/);
  assert.equal(L.logLine({ type: 'completed', techniqueId: 'T1', payload: { verdict: 'pass' }, ts: at }).tone, 'ok');
  assert.equal(L.logLine({ type: 'timeout', techniqueId: 'T2', ts: at }).tone, 'bad');
  assert.equal(L.logLine({ type: 'paused', ts: at }).text.includes('Paused'), true);
  assert.equal(L.logLine({ type: 'resumed', ts: at }).text.includes('Resumed'), true);
  assert.equal(L.logLine({ type: 'something-new', ts: at }), null, 'an unknown event type is skipped, never printed raw');
  assert.equal(L.logLine(null), null);
});

test('logLine carries a time only when the event has a valid timestamp', () => {
  assert.match(L.logLine({ type: 'paused', ts: '2026-10-28T14:03:07Z' }).time, /^\d\d:\d\d:\d\d$/);
  assert.equal(L.logLine({ type: 'paused' }).time, '');
  assert.equal(L.logLine({ type: 'paused', ts: 'not a date' }).time, '');
});

test('appendLog keeps only the newest lines so a long sweep cannot grow the panel without limit', () => {
  let lines = [];
  for (let i = 0; i < 500; i++) lines = L.appendLog(lines, { time: '', text: 'line ' + i, tone: 'inf' });
  assert.equal(lines.length, L.LOG_LIMIT);
  assert.equal(lines[lines.length - 1].text, 'line 499');
  assert.equal(lines[0].text, 'line ' + (500 - L.LOG_LIMIT));
  assert.deepEqual(L.appendLog([], null), [], 'null lines are ignored');
});
