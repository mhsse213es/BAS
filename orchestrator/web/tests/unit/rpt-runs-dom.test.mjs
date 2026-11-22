import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

const rows = [{ id: 'a1', host: 'HOST-1', os: 'windows', online: true, recent: true, lastName: 'APT29', last: '2026-11-04T00:00:00Z', runs: 2, failed: 1, total: 2, scenarios: 2, list: [
  { id: 'run-ok', name: 'APT29', status: 'completed', at: '2026-11-04T00:00:00Z', reportable: true, verdict: { result: 'FAIL', pass: 3, fail: 2, error: 0, skipped: 0 } },
  { id: 'run-bad', name: 'AV/NGAV <b>x</b>', status: 'failed', at: '2026-11-02T00:00:00Z', reportable: false, verdict: { result: '' } },
] }];
rows[0].recentExecutions = rows[0].list;

// The page remembers which agents are open, and the module is shared between tests, so start each one collapsed.
async function ready() {
  setupDom();
  const fns = await load(['paintAvailable', 'toggleRepRuns']);
  fns.paintAvailable(rows);
  if (body().querySelector('.rpt-runs')) { fns.toggleRepRuns('a1'); }
  return fns;
}
const body = () => document.getElementById('rep-available');

test('an agent card shows its host, latest scenario, counts and status, and stays collapsed until opened', async () => {
  await ready();
  const txt = body().textContent;
  assert.match(txt, /HOST-1/);
  assert.match(txt, /APT29/);
  assert.match(txt, /2\s*Total runs · 1 failed/);
  assert.match(txt, /2\s*Scenarios/);
  assert.match(txt, /Recent executions/);
  assert.match(txt, /2 fail · 3 pass/);
  assert.match(txt, /FAIL/);
  assert.match(txt, /Recent activity/);
  assert.ok(body().querySelector('.rpt-dot.on'), 'an online agent has a green dot');
  assert.ok(body().querySelector('.rpt-os.os-windows svg'));
  assert.equal(body().querySelector('.rpt-runs'), null);
});

test('an offline agent with no recent run shows neither the green dot nor the recent badge', async () => {
  setupDom();
  const { paintAvailable } = await load(['paintAvailable']);
  paintAvailable([{ ...rows[0], online: false, recent: false }]);
  assert.ok(body().querySelector('.rpt-dot.off'));
  assert.doesNotMatch(body().textContent, /Recent activity/);
});

test('opening the agent lists every run, with report buttons only on the ones that finished', async () => {
  const f = await ready();
  f.toggleRepRuns('a1');
  const runs = [...body().querySelectorAll('.rpt-runs tbody tr')];
  assert.equal(runs.length, 2);
  const ok = runs.find((r) => r.textContent.includes('APT29'));
  assert.deepEqual([...ok.querySelectorAll('button')].map((b) => b.getAttribute('data-on-click')), ['downloadRunReport'], 'a finished run offers a download and no preview');
  assert.equal(JSON.parse(ok.querySelector('button').getAttribute('data-args'))[0], 'run-ok');
  const bad = runs.find((r) => r.textContent.includes('failed'));
  assert.equal(bad.querySelector('button'), null, 'a failed run has no report button');
  assert.match(bad.textContent, /no report for a failed run/);
  assert.equal(bad.querySelector('b'), null, 'run names are escaped');
});

test('opening an agent keeps the whole-agent report buttons', async () => {
  const f = await ready();
  f.toggleRepRuns('a1');
  const acts = [...body().querySelectorAll('.rpt-more-hd button')].map((b) => b.getAttribute('data-on-click'));
  assert.deepEqual(acts, ['genAgentReport', 'genAgentReport', 'genAgentReport']);
  assert.equal(body().querySelector('[data-on-click="openRunReport"]'), null);
});

test('toggling again collapses it', async () => {
  const f = await ready();
  f.toggleRepRuns('a1'); f.toggleRepRuns('a1');
  assert.equal(body().querySelector('.rpt-runs'), null);
});
