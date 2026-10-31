import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describePhishingRun, verdictTone } from '../../src/features/phishing-run-view.js';

const future = new Date(Date.now() + 3600_000).toISOString();
const past = new Date(Date.now() - 3600_000).toISOString();

test('PH-ID-001 observed behavior is labelled as behavior, never as a control verdict', () => {
  const run = { id: 'r1', scenarioId: 'PH-ID-001', status: 'completed', result: {
    UserInteraction: { Verdict: 'not_applicable', Reason: 'observed user behavior: clicked' },
  } };
  const ui = describePhishingRun(run).rows.find((r) => r.label === 'Observed user behavior');
  assert.ok(ui, 'a behavior row exists');
  assert.equal(ui.tone, 'behavior');
  assert.match(ui.text, /not a control verdict/);
  assert.notEqual(ui.tone, 'pass');
  assert.notEqual(ui.tone, 'fail');
});

test('Inconclusive is visibly different from pass and fail', () => {
  const inc = verdictTone('inconclusive');
  assert.equal(inc.tone, 'inconclusive');
  assert.match(inc.label, /not graded/);
  assert.notEqual(inc.tone, verdictTone('pass').tone);
  assert.notEqual(inc.tone, verdictTone('fail').tone);
});

test('an inconclusive behavior row says it is not graded', () => {
  const run = { id: 'r2', scenarioId: 'PH-ID-001', status: 'completed', result: {
    UserInteraction: { Verdict: 'inconclusive', Reason: 'telemetry could not be read' },
  } };
  const ui = describePhishingRun(run).rows[0];
  assert.equal(ui.tone, 'inconclusive');
  assert.match(ui.label, /inconclusive, not graded/);
});

test('an open observation window is labelled provisional', () => {
  const run = { id: 'r3', scenarioId: 'PH-ID-001', status: 'completed', result: {
    UserInteraction: { Verdict: 'inconclusive', Reason: 'still open' },
    Collection: { windowEnd: future },
  } };
  const view = describePhishingRun(run);
  assert.equal(view.provisional, true);
  assert.match(view.note, /Provisional/);
});

test('a closed observation window is not labelled provisional', () => {
  const run = { id: 'r4', scenarioId: 'PH-ID-001', status: 'completed', result: {
    UserInteraction: { Verdict: 'not_applicable', Reason: 'final' },
    Collection: { windowEnd: past },
  } };
  assert.equal(describePhishingRun(run).provisional, false);
});

test('a running run shows no result', () => {
  const view = describePhishingRun({ id: 'r5', scenarioId: 'PH-DET-002', status: 'running', result: null });
  assert.match(view.note, /Still running/);
  assert.equal(view.rows.length, 0);
});

test('a failed run states the reason and grades nothing', () => {
  const view = describePhishingRun({ id: 'r6', scenarioId: 'PH-BEC-001', status: 'failed', error: 'send refused', result: null });
  assert.match(view.note, /Not graded: send refused/);
  assert.equal(view.rows.length, 0);
});

test('a dispatched run without a result is waiting, not graded', () => {
  const view = describePhishingRun({ id: 'r7', scenarioId: 'PH-BEC-001', status: 'completed',
    result: { dispatch: { emailGwRunId: 'eg-1' } } });
  assert.match(view.note, /Waiting for its result/);
});

test('an unknown verdict is neutral, never a pass', () => {
  assert.equal(verdictTone('something-new').tone, 'neutral');
});

test('a PH-ID-004 result is labelled best-effort, never a confirmed verdict', () => {
  const run = {
    id: 'r-id004',
    scenarioId: 'PH-ID-004',
    status: 'completed',
    result: JSON.stringify({ Enforcement: { Verdict: 'pass', Reason: 'denials under threshold' } }),
  };
  const view = describePhishingRun(run);
  const label = view.rows.find((r) => r.label === 'Best-effort heuristic');
  assert.ok(label, 'expected a best-effort row');
  assert.match(label.text, /not a confirmed control verdict/);
});

test('a non-experimental result gets no best-effort label', () => {
  const run = {
    id: 'r-id001',
    scenarioId: 'PH-ID-001',
    status: 'completed',
    result: JSON.stringify({ UserInteraction: { Verdict: 'inconclusive', Reason: 'window open' } }),
  };
  const view = describePhishingRun(run);
  assert.equal(view.rows.some((r) => r.label === 'Best-effort heuristic'), false);
});
