import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contentAxis, execAxis, detAxis, riskAxis, compositionAxis, heroStats, summaryTiles, distribution, familyOptions, applyFilter } from '../../src/features/adc-model.js';

test('axis labels and tones; unknown values are kept verbatim and neutral', () => {
  assert.deepEqual(contentAxis('model-only'), { label: 'Model-only', tone: 'warn' });
  assert.equal(execAxis(undefined).label, 'Not executed');
  assert.equal(detAxis(undefined).label, 'Not validated');
  assert.equal(riskAxis('potentially_destructive').tone, 'bad');
  assert.deepEqual(contentAxis('future-state'), { label: 'future-state', tone: 'muted' });
  assert.equal(compositionAxis({ scenarioComposed: true }).label, 'Composed');
  assert.equal(compositionAxis({}).label, 'Not composed');
});

test('heroStats and summaryTiles use only report numbers', () => {
  assert.deepEqual(heroStats({ total: 28, scenarioComposed: 10 }), { capabilities: 28, composed: 10, executed: 0, detected: 0 });
  assert.equal(heroStats(null).capabilities, null);
  const t = summaryTiles({ total: 28, modeled: 28, scenarioComposed: 10, executed: 0, detectionValidated: 0 }, { reusableUnmapped: 1 });
  assert.deepEqual(t.map((k) => k.value), [28, 28, 10, 0, 0, 1]);
  assert.equal(summaryTiles({}, {})[5].value, '—');
});

test('distribution, familyOptions and applyFilter', () => {
  const caps = [
    { family: 'ACL', contentAvailability: 'model-only' },
    { family: 'DCSync', contentAvailability: 'scenario-composable', executionValidation: 'execution_completed' },
    { family: 'ACL' },
  ];
  assert.deepEqual(distribution(caps, 'family'), { ACL: 2, DCSync: 1 });
  assert.deepEqual(familyOptions(caps).map((o) => o[0]), ['all', 'ACL', 'DCSync']);
  assert.equal(applyFilter(caps, { family: 'ACL', content: 'all', exec: 'all' }).length, 2);
  assert.equal(applyFilter(caps, { family: 'all', content: 'scenario-composable', exec: 'all' }).length, 1);
  assert.equal(applyFilter(caps, { family: 'all', content: 'all', exec: 'not_executed' }).length, 2);
});
