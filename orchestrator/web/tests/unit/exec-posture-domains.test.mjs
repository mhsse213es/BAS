import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const M = await import('../../src/features/dash-model.js');
const E = await import('../../src/features/dash-exec.js');

const f = (id, controlClass, severity, status = 'open') => ({ id, controlClass, severity, status });

test('domain breakdown counts only open findings, per control class, worst severity first', () => {
  const rows = M.domainBreakdown([
    f('1', 'Identity', 'high'), f('2', 'Identity', 'critical'), f('3', 'Identity', 'low', 'resolved'),
    f('4', 'Endpoint', 'medium'), f('5', 'Cloud', 'low'),
  ]);
  assert.deepEqual(rows.map(r => [r.domain, r.open, r.worst]), [
    ['Identity', 2, 'critical'],
    ['Endpoint', 1, 'medium'],
    ['Cloud', 1, 'low'],
  ]);
});

test('domain breakdown groups a missing control class under Unclassified and tolerates no findings', () => {
  assert.deepEqual(M.domainBreakdown([f('1', '', 'high')]).map(r => r.domain), ['Unclassified']);
  assert.deepEqual(M.domainBreakdown(null), []);
  assert.deepEqual(M.domainBreakdown([f('1', 'Network', 'high', 'resolved')]), []);
});

function renderPosture(current, forecast, findings) {
  document.body.innerHTML = '<div id="ed-posture"></div>';
  E.renderExecPosture(current, forecast, findings);
  return document.getElementById('ed-posture').innerHTML;
}

test('overall posture: the gauge, a 30-day trend and the open findings per domain sit in one card', () => {
  const fc = { history: Array.from({ length: 30 }, (_, i) => ({ dayIndex: i, score: 60 + (i % 5) })) };
  const html = renderPosture({ riskMeasurable: true, avgRiskScore: 55 }, fc, [f('1', 'Identity', 'critical'), f('2', 'Cloud', 'low')]);
  assert.match(html, /Overall posture/);
  assert.match(html, /dp-gauge t-warn[\s\S]*>Moderate risk</);
  assert.match(html, /<svg|chart/i, 'the trend is drawn');
  assert.match(html, />Identity</);
  assert.match(html, />Cloud</);
  assert.match(html, /1 open/);
  assert.match(html, /critical/);
});

test('overall posture: with no open findings the domain area says so, and an empty trend does not break the card', () => {
  const html = renderPosture({ riskMeasurable: true, avgRiskScore: 22 }, null, []);
  assert.match(html, /dp-gauge t-ok/);
  assert.match(html, /No open findings/);
});

test('overall posture: while findings are still loading the domain area says so, not that nothing is open', () => {
  const html = renderPosture({ riskMeasurable: true, avgRiskScore: 22 }, null, null);
  assert.match(html, /Loading/);
  assert.doesNotMatch(html, /No open findings/);
});
