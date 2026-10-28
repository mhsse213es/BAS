// The Live Run drawer resolves technique names from the shared ART catalog
// (core/state.js). Its IIFE keeps a local per-run `state`; this pins that the
// catalog lookup still reaches the shared one (G1c final review, Critical 1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';
import { state } from '../../src/core/state.js';

setupDom();
const { __init_L16159, openRunPanel, onRunEvent } = await load(['__init_L16159', 'openRunPanel', 'onRunEvent']);
__init_L16159();

const events = [
  { type: 'queued', taskId: 't1', techniqueId: 'T1059', stepName: 'step one' },
  { type: 'started', taskId: 't1', techniqueId: 'T1059' },
];

test('openRunPanel replays technique steps and takes their tactic from the shared ART catalog', async () => {
  state.artCatalog = [{ id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution' }];
  globalThis.fetch = async () => ({ ok: true, json: async () => events });
  await openRunPanel('run-1', 'Run', 1);
  const timeline = document.getElementById('run-live-timeline').textContent;
  assert.match(timeline, /T1059/, 'replayed step was not rendered');
  assert.match(timeline, /Execution/, 'tactic not resolved from the ART catalog');
});

test('onRunEvent renders a live technique step without throwing', async () => {
  state.artCatalog = [];
  globalThis.fetch = async () => ({ ok: true, json: async () => [] });
  await openRunPanel('run-2', 'Run', 1);
  onRunEvent({ type: 'run_event', data: { runId: 'run-2', events: [{ type: 'queued', taskId: 't9', techniqueId: 'T1082', stepName: 'live step' }] } });
  assert.match(document.getElementById('run-live-timeline').textContent, /T1082/);
});

// ── Redesigned panel: status, actions, started/duration, log, footer ─────────────────────────────
const { renderRunsSummary, closeRunLive } = await load(['renderRunsSummary', 'closeRunLive']);

const stepEvents = [
  { type: 'queued', taskId: 't1', techniqueId: 'T1059.001', stepName: 'Encoded PowerShell' },
  { type: 'queued', taskId: 't2', techniqueId: 'T1087', stepName: 'Account discovery' },
  { type: 'started', taskId: 't1', techniqueId: 'T1059.001', ts: '2026-10-28T14:03:07Z' },
  { type: 'completed', taskId: 't1', techniqueId: 'T1059.001', payload: { verdict: 'pass', durationMs: 1200 }, ts: '2026-10-28T14:03:09Z' },
];
const runRecord = (o) => ({ id: 'run-live', name: 'APT29 Kill Chain', scenarioId: 'SC-APT29', agentId: 'a-1', status: 'running', paused: false,
  startedAt: new Date(Date.now() - 90000).toISOString(), progress: { stepsTotal: 4, stepsDone: 1 }, ...o });
const q = (sel) => document.querySelector(sel);
const attrs = (sel) => [...document.querySelectorAll(sel)].map((b) => b.getAttribute('data-on-click'));

async function open(run, events = stepEvents, id = 'run-live') {
  renderRunsSummary(run ? [run] : []);
  globalThis.fetch = async () => ({ ok: true, json: async () => events });
  await openRunPanel(id, 'APT29 Kill Chain', 4);
}

test('a running run shows its status, a percent bar, and Pause and Stop in the panel', async () => {
  await open(runRecord());
  assert.match(q('#run-live-status').textContent, /Running/);
  const acts = attrs('#run-live-status [data-on-click]');
  assert.ok(acts.includes('pauseRun') && acts.includes('stopRun'), 'Pause and Stop must be offered: ' + acts);
  assert.ok(!acts.includes('resumeRun'));
  assert.match(q('#run-live-progress').textContent, /25%/);
  assert.ok(q('#run-live-progress .rk-bar'), 'the shared progress bar is used');
});

test('a paused run offers Resume instead of Pause', async () => {
  await open(runRecord({ paused: true }));
  assert.match(q('#run-live-status').textContent, /Paused/);
  const acts = attrs('#run-live-status [data-on-click]');
  assert.ok(acts.includes('resumeRun') && !acts.includes('pauseRun'));
});

test('a finished run has no Pause or Stop, and shows its real duration', async () => {
  await open(runRecord({ status: 'completed', startedAt: '2026-10-28T14:02:00Z', completedAt: '2026-10-28T14:10:05Z' }));
  assert.match(q('#run-live-status').textContent, /Completed/);
  assert.deepEqual(attrs('#run-live-status [data-on-click]'), []);
  assert.equal(q('#run-live-duration').textContent, '8m 05s');
});

test('Started and Duration come from the run record while it is live', async () => {
  await open(runRecord());
  assert.notEqual(q('#run-live-started').textContent, '—');
  assert.match(q('#run-live-duration').textContent, /^1m \d\ds$/);
});

test('with no run record the panel shows dashes and offers no Pause or Stop it cannot honour', async () => {
  await open(null, stepEvents, 'unknown-run');
  assert.equal(q('#run-live-started').textContent, '—');
  assert.equal(q('#run-live-duration').textContent, '—');
  assert.deepEqual(attrs('#run-live-status [data-on-click]'), []);
  assert.match(q('#run-live-timeline').textContent, /T1059\.001/, 'the timeline still works from the events');
});

test('timeline rows carry a marker and a one-line result', async () => {
  await open(runRecord());
  const rows = [...document.querySelectorAll('#run-live-timeline li.lv-step')];
  assert.equal(rows.length, 2);
  const done = rows.find((r) => r.textContent.includes('T1059.001'));
  assert.ok(done.querySelector('.lv-mark.done'), 'a finished passing step is marked done');
  assert.match(done.textContent, /Prevented · 1\.2 s/);
  const wait = rows.find((r) => r.textContent.includes('T1087'));
  assert.ok(wait.querySelector('.lv-mark.wait'));
  assert.match(wait.textContent, /Pending/);
});

test('the live log lists replayed events and takes new frames as they arrive', async () => {
  await open(runRecord());
  const log = q('#run-live-log').textContent;
  assert.match(log, /Started T1059\.001/);
  assert.match(log, /Prevented/);
  assert.doesNotMatch(log, /queued/i, 'queueing a step is not a log line');
  onRunEvent({ type: 'run_event', data: { runId: 'run-live', events: [{ type: 'started', taskId: 't2', techniqueId: 'T1087', stepName: 'Account discovery' }] } });
  assert.match(q('#run-live-log').textContent, /Started T1087/);
});

test('a paused event on the stream flips the chip and the button without a reload', async () => {
  await open(runRecord());
  onRunEvent({ type: 'run_event', data: { runId: 'run-live', events: [{ type: 'paused' }] } });
  assert.match(q('#run-live-status').textContent, /Paused/);
  assert.ok(attrs('#run-live-status [data-on-click]').includes('resumeRun'));
  onRunEvent({ type: 'run_event', data: { runId: 'run-live', events: [{ type: 'resumed' }] } });
  assert.match(q('#run-live-status').textContent, /Running/);
});

test('the log of one run never shows lines from the run opened before it', async () => {
  await open(runRecord());
  await open(runRecord({ id: 'run-two' }), [{ type: 'started', taskId: 'x', techniqueId: 'T1082', stepName: 'other' }], 'run-two');
  const log = q('#run-live-log').textContent;
  assert.match(log, /T1082/);
  assert.doesNotMatch(log, /T1059/);
});

test('the footer offers Close, the PDF report and the scenario', async () => {
  await open(runRecord());
  const acts = attrs('#run-live-footer [data-on-click]');
  assert.deepEqual(acts.sort(), ['closeRunLive', 'downloadRunReport', 'openRunScenarioAction'].sort());
  assert.match(q('#run-live-footer').textContent, /Report/);
});

test('without a scenario id the footer has no scenario button', async () => {
  await open(runRecord({ scenarioId: '' }));
  assert.ok(!attrs('#run-live-footer [data-on-click]').includes('openRunScenarioAction'));
});

test('closing the panel closes the overlay', async () => {
  await open(runRecord());
  closeRunLive();
  assert.ok(!q('#run-live-overlay').classList.contains('open'));
});

test('run names, step names and log text are escaped, never inserted as markup', async () => {
  await open(runRecord(), [{ type: 'started', taskId: 'z', techniqueId: 'T9', stepName: '<img src=x onerror=alert(1)>' }]);
  assert.equal(document.querySelectorAll('#run-live-timeline img, #run-live-log img').length, 0);
});
