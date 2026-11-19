import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

async function render(p) {
  setupDom();
  const { purpleDebriefHtml } = await load(['purpleDebriefHtml']);
  const d = document.createElement('div');
  d.innerHTML = purpleDebriefHtml(p);
  return d;
}

test('no debrief data renders nothing', async () => {
  assert.equal((await render(null)).textContent, '');
});

test('nothing judged says so instead of showing a rate', async () => {
  const d = await render({ detectionRate: null, detected: 0, missed: 0, unresolved: 2,
    techniques: [{ techniqueId: 'T1003', outcome: 'unresolved', providers: ['sentinel'] }] });
  assert.match(d.textContent, /Not yet judged/);
  assert.doesNotMatch(d.textContent, /\d+%/);
  assert.match(d.textContent, /Awaiting an approved verdict: 2/);
});

test('a judged exercise shows the rate, the misses and the unexpected-technique note', async () => {
  const d = await render({ detectionRate: 50, detected: 1, missed: 1, unresolved: 0,
    techniques: [{ techniqueId: 'T1003', outcome: 'detected' }, { techniqueId: 'T1558.003', outcome: 'missed' }],
    gaps: ['T1558.003: sentinel did not detect it'], noExpectation: ['T1048'] });
  assert.match(d.textContent, /50% \(1 of 2\)/);
  assert.match(d.textContent, /Gaps to close: T1558\.003: sentinel did not detect it/);
  assert.match(d.textContent, /T1048, so these were not judged either way/);
});

test('hostile technique text is escaped', async () => {
  const d = await render({ detectionRate: null, detected: 0, missed: 0, unresolved: 1,
    techniques: [{ techniqueId: '<img src=x onerror=alert(1)>', outcome: 'unresolved' }] });
  assert.equal(d.querySelector('img'), null);
});
