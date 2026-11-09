import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const R = await import('../../src/features/runs-refresh.js');

function clock() {
  let t = 0, nextId = 1; const pending = new Map();
  return {
    now: () => t,
    setTimeout: (fn, ms) => { const id = nextId++; pending.set(id, { fn, at: t + ms }); return id; },
    advance(ms) {
      t += ms;
      for (const [id, p] of [...pending]) if (p.at <= t) { pending.delete(id); p.fn(); }
    },
    pendingCount: () => pending.size,
  };
}

test('the first run event refreshes at once, not after the gap', () => {
  const c = clock(); let n = 0;
  const request = R.createThrottledRefresh(() => n++, 2000, c);
  request();
  c.advance(0);
  assert.equal(n, 1);
});

test('a burst of events costs one fetch, then at most one per gap', () => {
  const c = clock(); let n = 0;
  const request = R.createThrottledRefresh(() => n++, 2000, c);
  request(); c.advance(0);                 // first: 1 fetch
  for (let i = 0; i < 25; i++) request();  // 25 events in a burst
  assert.equal(c.pendingCount(), 1, 'folded into one scheduled fetch');
  c.advance(1999); assert.equal(n, 1, 'not before the gap has passed');
  c.advance(1);    assert.equal(n, 2, 'one fetch once it has');
  request(); c.advance(2000);
  assert.equal(n, 3, 'a later event is served after a full gap');
});

test('an event after a quiet period is served at once', () => {
  const c = clock(); let n = 0;
  const request = R.createThrottledRefresh(() => n++, 2000, c);
  request(); c.advance(0);
  c.advance(60000);
  request(); c.advance(0);
  assert.equal(n, 2);
});

test('isRunsTabActive follows the sidebar item for Live Runs', () => {
  document.body.innerHTML = '<a data-tab="runs" class="nav-item"></a>';
  assert.equal(R.isRunsTabActive(document), false);
  document.querySelector('[data-tab="runs"]').classList.add('active');
  assert.equal(R.isRunsTabActive(document), true);
  document.body.innerHTML = '';
  assert.equal(R.isRunsTabActive(document), false, 'no sidebar item: not active, never throws');
});
