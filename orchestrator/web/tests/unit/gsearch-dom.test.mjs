import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

const json = (b) => Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(b), text: () => Promise.resolve(JSON.stringify(b)) });
const CLOUD = { scenarios: [
  { id: 'aws-backup', name: 'AWS Backup: destroy recovery points and plans', provider: 'aws', description: 'Can an identity inhibit recovery?', steps: [{}, {}, {}, {}] },
  { id: 's3', name: 'S3 data access and exposure', provider: 'aws', description: 'List, read, expose a bucket.', steps: [{}] },
  { id: 'az-rs', name: 'Azure Recovery Services', provider: 'azure', description: 'Protected items.', steps: [{}, {}] },
  { id: 'gcs', name: 'GCS data access', provider: 'gcp', description: 'Objects.', steps: [{}] },
] };

function mockFetch(extra) {
  globalThis.fetch = (url) => {
    const u = String(url);
    if (u.startsWith('/api/cloud-scenarios')) return json(CLOUD);
    if (u.startsWith('/api/cloud-runs')) return json([]);
    if (u.startsWith('/api/reports')) return json([{ id: 'rep-1', reportType: 'posture', agentId: 'ag-1', format: 'pdf', generatedBy: 'admin', generatedAt: '2026-11-10T00:00:00Z' }]);
    if (u.startsWith('/api/scenarios/library')) return json([{ type: 'phishing', id: 'PH-ID-001', name: 'Credential harvest lure', status: 'available' }]);
    if (u.startsWith('/api/search/recents')) return json([]);
    if (u.startsWith('/api/search/operators')) return json({ operators: [{ name: 'type', values: ['scenario'] }] });
    if (u.startsWith('/api/search?')) return json(extra && extra.search && u.includes('q=ransom') ? extra.search : []);
    return json({});
  };
}
const tick = (ms = 30) => new Promise((r) => setTimeout(r, ms));

test('the cloud page shows a card per scenario with a provider mark, counts in the hero, and filters by provider and words', async () => {
  setupDom(); localStorage.setItem('bas_role', 'admin'); mockFetch();
  const { loadCloudScenarios, cloudSetProvider, cloudFilterInput } = await load(['loadCloudScenarios', 'cloudSetProvider', 'cloudFilterInput']);
  loadCloudScenarios(); await tick(60);
  const cards = () => [...document.querySelectorAll('#cloud-scen-cards .cloud-scn')];
  assert.equal(cards().length, 4);
  assert.ok(cards()[0].querySelector('.cloud-mark svg'), 'provider mark');
  assert.match(cards()[0].textContent, /4 steps/);
  assert.equal(document.getElementById('cloud-hs-total').textContent, '4');
  assert.equal(document.getElementById('cloud-hs-aws').textContent, '2');
  assert.match(document.getElementById('cloud-chips').textContent, /All4/);
  cloudSetProvider('azure');
  assert.equal(cards().length, 1);
  cloudSetProvider('all');
  cloudFilterInput({ value: 'bucket' });
  assert.deepEqual(cards().map((c) => c.id), ['cloud-scn-s3']);
  cloudFilterInput({ value: 'zzz' });
  assert.match(document.getElementById('cloud-scen-cards').textContent, /No scenario matches/);
});

test('the palette lists pages first, then finds cloud scenarios, reports and server results by scope', async () => {
  setupDom(); localStorage.setItem('bas_role', 'admin');
  mockFetch({ search: [{ docType: 'technique', sourceId: 'T1486', title: 'T1486 Data Encrypted for Impact', description: 'Ransomware', favorited: false }] });
  const { openCmdk } = await load(['openCmdk']);
  openCmdk(); await tick(60);
  const list = () => document.getElementById('cmdk-list');
  assert.ok(list().querySelectorAll('.gs-row').length > 0, 'pages listed with an empty query');
  const input = document.getElementById('cmdk-input');
  const type = async (v) => { input.value = v; input.dispatchEvent(new window.Event('input', { bubbles: true })); await tick(260); };
  await type('backup');
  assert.match(list().textContent, /AWS Backup: destroy recovery points/);
  assert.ok(list().querySelector('mark'), 'matches are highlighted');
  assert.match(document.getElementById('gs-chips').textContent, /Scenarios/);
  await type('ransom');
  assert.match(list().textContent, /Data Encrypted for Impact/);
  assert.match(list().textContent, /Technique/);
  await type('harvest');
  assert.match(list().textContent, /Credential harvest lure/);
  assert.match(list().textContent, /Phishing/);
  await type('posture');
  assert.match(list().textContent, /Posture report/);
  await type('<img src=x onerror=1>');
  assert.equal(list().querySelector('img'), null, 'a query never becomes markup');
  assert.match(list().textContent, /No matches/);
  document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  assert.equal(document.getElementById('cmdk-input'), null, 'Escape closes it');
});

test('Tab moves to the next scope that has results and Escape closes', async () => {
  setupDom(); localStorage.setItem('bas_role', 'admin'); mockFetch();
  const { openCmdk } = await load(['openCmdk']);
  openCmdk(); await tick(60);
  const input = document.getElementById('cmdk-input');
  input.value = 'backup'; input.dispatchEvent(new window.Event('input', { bubbles: true })); await tick(260);
  document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
  assert.equal(document.querySelector('.gs-chip.on').dataset.scope, 'scenario');
  document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
});
