import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const R = await import('../../src/features/ransomware.js');

const run = { id: 'run-1', name: 'Akira drill', scenarioId: 'akira-kill-chain', startedAt: '2026-11-18T10:00:00Z' };
const score = { overall: 72, rating: 'at_risk', dimensions: [], gateTriggered: false, criticalFailures: [] };

test('readiness model carries the efficacy line for the same run when it loaded', () => {
  const eff = { label: 'Gaps found', tone: 'bad', runId: 'run-1' };
  const m = R.ransomwareModel(run, score, eff);
  assert.deepEqual(m.efficacy, eff);
  assert.equal(m.score, 72);
});

test('a missing efficacy statement leaves the score card intact with efficacy null', () => {
  const m = R.ransomwareModel(run, score, null);
  assert.equal(m.efficacy, null);
  assert.equal(m.score, 72);
  assert.equal(m.label, 'At Risk');
});
