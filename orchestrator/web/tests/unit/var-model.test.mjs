import { test } from 'node:test';
import assert from 'node:assert/strict';
import { coverageRows, preventionTone, heroStats } from '../../src/features/var-model.js';

const R = [
  { techniqueId: 'T1059.001', tactic: 'execution', totalTested: 10, prevented: 8, allowed: 2, errored: 0, firstBypass: 'Remote System Discovery' },
  { techniqueId: 'T1105', tactic: '', totalTested: 0, prevented: 0, allowed: 0, errored: 0 },
];

test('coverageRows computes prevention percent and tolerates empty totals', () => {
  const rows = coverageRows(R);
  assert.equal(rows[0].pct, 80);
  assert.equal(rows[0].firstBypass, 'Remote System Discovery');
  assert.equal(rows[1].pct, 0);
  assert.equal(rows[1].firstBypass, '');
  assert.deepEqual(coverageRows(null), []);
});

test('preventionTone thresholds', () => {
  assert.equal(preventionTone(75), 'ok');
  assert.equal(preventionTone(40), 'warn');
  assert.equal(preventionTone(39), 'bad');
});

test('heroStats uses only returned numbers and null when nothing ran', () => {
  assert.deepEqual(heroStats(R), { techniques: 2, variants: 10, prevented: '80%', bypassed: 2 });
  assert.deepEqual(heroStats([]), { techniques: null, variants: null, prevented: null, bypassed: null });
});
