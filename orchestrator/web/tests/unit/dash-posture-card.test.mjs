import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const R = await import('../../src/features/dash-rich.js');

const sc = (p, trend) => ({ id: 'r' + p, startedAt: '2026-11-01T10:00:00Z', score: { preventionScore: p, passedTechniques: 5, failedTechniques: 5, trend } });
function render(runs) {
  document.body.innerHTML = '<div id="dop-posture"></div>';
  R.setDashRuns(runs);
  return document.getElementById('dop-posture').innerHTML;
}

test('posture card: a strong score shows the verdict, the trend, an 80% guide and no target', () => {
  const html = render([sc(92, 'Improving'), sc(90, 'Stable')]);
  assert.match(html, /dp-gauge t-ok/);
  assert.match(html, />Strong</, 'the gauge names the band, not just a number');
  assert.match(html, /Improving/);
  assert.match(html, /Not set/, 'no target is configured, and the card says so');
  assert.match(html, /dp-thr/, 'bars are drawn against a guide at the 80% cut-off used for their colours');
  assert.match(html, /dashed line is 80%/, 'the caption explains the guide');
  assert.match(html, /last 2 validated runs/);
});

test('posture card: the band follows the same cut-offs as the bar colours', () => {
  assert.match(render([sc(65, 'Stable')]), /dp-gauge t-warn[\s\S]*>Moderate</);
  assert.match(render([sc(30, 'Degrading')]), /dp-gauge t-bad[\s\S]*>At risk</);
});

test('posture card: nothing scored yet keeps the empty state', () => {
  const html = render([{ id: 'x', score: { preventionScore: 0, passedTechniques: 0, failedTechniques: 0 } }]);
  assert.match(html, /No scored runs yet/);
  assert.doesNotMatch(html, /dp-gauge/);
});
