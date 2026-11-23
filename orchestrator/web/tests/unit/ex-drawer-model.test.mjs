import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/ex-model.js';

test('runSummary counts completed steps and finds the current, waiting and failed ones', () => {
  const steps = [{ status: 'completed' }, { status: 'waiting', step_id: 'a' }, { status: 'running', step_id: 'r' }, { status: 'failed', step_id: 'f' }, { status: 'pending' }];
  const s = M.runSummary({}, steps);
  assert.equal(s.done, 1); assert.equal(s.total, 5); assert.equal(s.pct, 20);
  assert.equal(s.waiting.step_id, 'a'); assert.equal(s.current.step_id, 'r'); assert.equal(s.failed.step_id, 'f');
});

test('runSummary falls back to the execution counts and has no percent without a total', () => {
  assert.equal(M.runSummary({ steps_done: 2, steps_total: 4 }, []).pct, 50);
  assert.equal(M.runSummary({}, []).pct, null);
});

test('stateNote explains each non-finished state and stays silent when completed', () => {
  assert.match(M.stateNote({ status: 'paused' }, [{ status: 'waiting', step_id: 'ok' }]).text, /"ok"/);
  assert.equal(M.stateNote({ status: 'paused' }, [{ status: 'waiting' }]).title, 'Waiting for approval');
  assert.equal(M.stateNote({ status: 'created' }, []).title, 'Not started');
  assert.equal(M.stateNote({ status: 'failed' }, [{ status: 'failed', step_id: 'x' }]).tone, 'bad');
  assert.equal(M.stateNote({ status: 'aborted' }, []).title, 'Aborted');
  assert.equal(M.stateNote({ status: 'completed' }, []), null);
});

test('scoreTone: higher is better', () => {
  assert.equal(M.scoreTone(80), 'ok'); assert.equal(M.scoreTone(60), 'warn'); assert.equal(M.scoreTone(20), 'bad'); assert.equal(M.scoreTone('x'), 'muted');
});

test('step labels, tones and result pairs', () => {
  assert.equal(M.stepLabel('agent_task'), 'Agent task'); assert.equal(M.stepLabel('weird'), 'weird');
  assert.match(M.stepWhat('approval'), /no technical action/i);
  assert.equal(M.stepTone('failed'), 'bad'); assert.equal(M.stepTone('pending'), 'muted');
  assert.deepEqual(M.resultPairs({ sent_count: 24, nested: { a: 1 } }), [['sent count', '24'], ['nested', '{"a":1}']]);
  assert.deepEqual(M.resultPairs(null), []);
});

test('planSteps counts steps', () => { assert.equal(M.planSteps({ steps: [1, 2] }), 2); assert.equal(M.planSteps({}), 0); });
