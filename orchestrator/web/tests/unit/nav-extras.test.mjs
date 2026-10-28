import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const nav = await import('../../src/features/nav-extras.js');

test('parseList keeps only well-formed tab ids', () => {
  assert.deepEqual(nav.parseList('["findings","a b","<x>",3,"agents"]'), ['findings', 'agents']);
  assert.deepEqual(nav.parseList('{"a":1}'), []);
  assert.deepEqual(nav.parseList('not json'), []);
  assert.deepEqual(nav.parseList(null), []);
});

test('nextRecent puts the tab first, drops duplicates and pinned tabs, and caps the list', () => {
  assert.deepEqual(nav.nextRecent(['b', 'a', 'c'], 'a', [], 3), ['a', 'b', 'c']);
  assert.deepEqual(nav.nextRecent(['b', 'c', 'd'], 'a', [], 3), ['a', 'b', 'c']);
  assert.deepEqual(nav.nextRecent(['b'], 'a', ['b'], 3), ['a']);
});

test('badges appear only for data that is really loaded', () => {
  assert.deepEqual(nav.navBadgeCounts({}), {});
  assert.deepEqual(nav.navBadgeCounts({ agentTotals: { online: 5, degraded: 0, offline: 0 } }), {});
  const c = nav.navBadgeCounts({
    agentTotals: { online: 3, degraded: 2, offline: 1 },
    _findings: [{ status: 'open', severity: 'critical' }, { status: 'open', severity: 'low' }, { status: 'verified' }],
    _campaigns: [{ status: 'running' }, { status: 'paused' }],
  });
  assert.equal(c.agents.n, 3); assert.equal(c.agents.tone, 'bad');
  assert.equal(c.findings.n, 2); assert.equal(c.findings.tone, 'bad');
  assert.equal(c.campaigns.n, 1);
});

test('a degraded-only fleet is a warning, not an error', () => {
  assert.equal(nav.navBadgeCounts({ agentTotals: { degraded: 2, offline: 0 } }).agents.tone, 'warn');
});

test('pinning a tab shows it in a Pinned group (without a data-tab twin) and unpinning removes it', () => {
  nav.initNavExtras();
  const stars = document.querySelectorAll('.sidebar-nav .nav-item[data-tab] .nav-pin');
  assert.ok(stars.length > 10);
  nav.toggleNavPin('findings');
  const grp = document.getElementById('nav-pinned');
  assert.ok(grp, 'no Pinned group');
  const item = grp.querySelector('[data-nav-clone="findings"]');
  assert.ok(item && !item.hasAttribute('data-tab') && !item.querySelector('.nav-pin'));
  assert.equal(JSON.parse(localStorage.getItem('bas_nav_pins')).join(), 'findings');
  nav.toggleNavPin('findings');
  assert.equal(document.getElementById('nav-pinned'), null);
});

test('a tab that is hidden for this role is never pinned into the sidebar', () => {
  const src = document.querySelector('.sidebar-nav .nav-item[data-tab="settings"]');
  src.style.display = 'none';
  nav.toggleNavPin('settings');
  assert.equal(document.getElementById('nav-pinned'), null);
  nav.toggleNavPin('settings');
  src.style.display = '';
});

test('toggleNavPin ignores a malformed id', () => {
  nav.toggleNavPin('"><img src=x>');
  assert.equal(document.getElementById('nav-pinned'), null);
});

test('the Findings count is loaded without opening the Findings page', async () => {
  const st = {};
  await nav.refreshBadgeData(() => Promise.resolve([{ status: 'open', severity: 'high' }, { status: 'open', severity: 'critical' }, { status: 'remediated' }]), st, () => true);
  assert.equal(st._findings.length, 3);
  assert.deepEqual(nav.navBadgeCounts(st).findings, { n: 2, tone: 'bad', label: '2 open findings' });
});

test('nothing is fetched while signed out, and a bad or failed answer changes nothing', async () => {
  let calls = 0;
  const st = { _findings: [{ status: 'open' }] };
  await nav.refreshBadgeData(() => { calls++; return Promise.resolve([]); }, st, () => false);
  assert.equal(calls, 0, 'no request on the login screen');
  await nav.refreshBadgeData(() => Promise.resolve({ error: 'x' }), st, () => true);
  assert.equal(st._findings.length, 1, 'a non-list answer is ignored');
  await nav.refreshBadgeData(() => Promise.reject(new Error('down')), st, () => true);
  assert.equal(st._findings.length, 1, 'a failed request keeps the last known list');
});
