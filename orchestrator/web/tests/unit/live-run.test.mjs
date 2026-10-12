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
