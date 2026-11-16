import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

const rows = [{ id: 'a1', host: 'HOST-1', lastName: 'APT29', last: '2026-11-04T00:00:00Z', runs: 2, failed: 1, list: [
  { id: 'run-ok', name: 'APT29', status: 'completed', at: '2026-11-04T00:00:00Z', reportable: true },
  { id: 'run-bad', name: 'AV/NGAV <b>x</b>', status: 'failed', at: '2026-11-02T00:00:00Z', reportable: false },
] }];

// The page remembers which agents are open, and the module is shared between tests, so start each one collapsed.
async function ready() {
  setupDom();
  const fns = await load(['paintAvailable', 'toggleRepRuns']);
  fns.paintAvailable(rows);
  if (body().querySelector('.rpt-runs')) { fns.toggleRepRuns('a1'); }
  return fns;
}
const body = () => document.getElementById('rep-available');

test('an agent row shows its counts and stays collapsed until opened', async () => {
  await ready();
  assert.match(body().textContent, /HOST-1/);
  assert.match(body().textContent, /2 \+ 1 failed|2\s*\+ 1 failed/);
  assert.equal(body().querySelector('.rpt-runs'), null);
});

test('opening the agent lists every run, with report buttons only on the ones that finished', async () => {
  const f = await ready();
  f.toggleRepRuns('a1');
  const runs = [...body().querySelectorAll('.rpt-runs tbody tr')];
  assert.equal(runs.length, 2);
  const ok = runs.find((r) => r.textContent.includes('APT29'));
  assert.deepEqual([...ok.querySelectorAll('button')].map((b) => b.getAttribute('data-on-click')), ['downloadRunReport', 'openRunReport']);
  assert.equal(JSON.parse(ok.querySelector('button').getAttribute('data-args'))[0], 'run-ok');
  const bad = runs.find((r) => r.textContent.includes('failed'));
  assert.equal(bad.querySelector('button'), null, 'a failed run has no report button');
  assert.match(bad.textContent, /no report for a failed run/);
  assert.equal(bad.querySelector('b'), null, 'run names are escaped');
});

test('toggling again collapses it', async () => {
  const f = await ready();
  f.toggleRepRuns('a1'); f.toggleRepRuns('a1');
  assert.equal(body().querySelector('.rpt-runs'), null);
});
