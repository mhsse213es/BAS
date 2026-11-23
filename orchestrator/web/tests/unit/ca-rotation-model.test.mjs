import test from 'node:test';
import assert from 'node:assert/strict';
import { describeRotation } from '../../src/features/ca-rotation-model.js';

test('no rotation in progress says so and offers no step', () => {
  const d = describeRotation({ state: 'stable' });
  assert.equal(d.state, 'stable');
  assert.equal(d.step, null);
  assert.equal(d.progress, null);
  assert.match(d.headline, /No CA rotation in progress/);
});

test('prepared: counts agents that trust the new root and names who is pending', () => {
  const d = describeRotation({ state: 'prepared', agentsTotal: 3, agentsWithNewRoot: 2, agentsPending: ['agent-c'], readyToPromote: false });
  assert.equal(d.step, 'promote');
  assert.deepEqual(d.progress, { done: 2, total: 3, label: 'trust the new root' });
  assert.deepEqual(d.pending, ['agent-c']);
  assert.equal(d.ready, false);
  assert.match(d.next, /distribute/i);
});

test('prepared and ready tells the operator the CLI step to run', () => {
  const d = describeRotation({ state: 'prepared', agentsTotal: 2, agentsWithNewRoot: 2, agentsPending: [], readyToPromote: true });
  assert.equal(d.ready, true);
  assert.match(d.next, /ca-rotation promote/);
});

test('promoted: counts agents holding a certificate from the new CA', () => {
  const d = describeRotation({ state: 'promoted', agentsTotal: 4, agentsOnNewCA: 1, agentsPendingRenewal: ['a', 'b', 'c'], readyToRetire: false });
  assert.equal(d.step, 'retire');
  assert.deepEqual(d.progress, { done: 1, total: 4, label: 'hold a certificate from the new CA' });
  assert.equal(d.pending.length, 3);
  assert.match(d.next, /not safe to retire/i);
});

test('promoted and ready says retire is safe, never that it has happened', () => {
  const d = describeRotation({ state: 'promoted', agentsTotal: 2, agentsOnNewCA: 2, agentsPendingRenewal: [], readyToRetire: true });
  assert.equal(d.ready, true);
  assert.match(d.next, /ca-rotation retire/);
});

test('zero agents is never presented as ready', () => {
  const d = describeRotation({ state: 'prepared', agentsTotal: 0, agentsWithNewRoot: 0, agentsPending: [], readyToPromote: false });
  assert.equal(d.ready, false);
  assert.match(d.next, /no agents/i);
});

test('a missing or malformed response is unavailable, not stable', () => {
  for (const bad of [null, undefined, {}, { state: 5 }]) {
    const d = describeRotation(bad);
    assert.equal(d.state, 'unavailable');
    assert.equal(d.step, null);
  }
});

test('an unknown state is shown as unknown, not guessed', () => {
  assert.equal(describeRotation({ state: 'frobnicated' }).state, 'unavailable');
});
