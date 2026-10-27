import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/int-model.js';

const NOW = Date.parse('2026-10-27T12:00:00Z');
const ITSM = [
  { id: 'i1', name: 'ServiceNow prod', provider: 'servicenow', enabled: true, lastTestOk: true, lastTestAt: '2026-10-27T11:58:00Z', autoCreate: 'critical_high' },
  { id: 'i2', name: 'Jira', provider: 'jira', enabled: true, lastTestOk: false, lastTestAt: '2026-10-27T09:00:00Z', lastTestError: '401 unauthorized' },
  { id: 'i3', name: 'Hook', provider: 'webhook', enabled: true, lastTestOk: null },
  { id: 'i4', name: 'Old', provider: 'jira', enabled: false, lastTestOk: true, lastTestAt: '2026-10-20T00:00:00Z' },
];
const EPP = [{ id: 'e1', name: 'Prod CS', provider: 'crowdstrike', enabled: true, baseUrl: 'https://api.crowdstrike.com' }, { id: 'e2', name: 'Def', provider: 'microsoft_defender', enabled: false, tenantId: 't-1' }];

test('itsm status keeps the four honest states', () => {
  assert.deepEqual(ITSM.map((c) => M.itsmStatus(c).label), ['Connected', 'Connection error', 'Not tested', 'Disabled']);
  assert.equal(M.itsmStatus(ITSM[1]).title, '401 unauthorized');
  assert.equal(M.eppStatus(EPP[0]).label, 'Enabled');
  assert.equal(M.eppStatus(EPP[1]).tone, 'muted');
  assert.equal(M.itsmStatus(null).label, 'Disabled');
});

test('connectorRows merges ITSM then EPP and describes each honestly', () => {
  const r = M.connectorRows(ITSM, EPP);
  assert.equal(r.length, 6);
  assert.deepEqual(r.map((x) => x.kind), ['itsm', 'itsm', 'itsm', 'itsm', 'epp', 'epp']);
  assert.equal(r[0].detail, 'Auto-create: critical+high');
  assert.equal(r[1].detail, '401 unauthorized');
  assert.equal(r[2].detail, 'Auto-create: Manual only');
  assert.equal(r[4].detail, 'https://api.crowdstrike.com');
  assert.equal(r[5].detail, 'Tenant t-1');
  assert.equal(r[4].tested, null);
  assert.deepEqual(M.connectorRows(null, undefined), []);
});

test('card meta: tested time for ITSM, none invented for EPP', () => {
  const r = M.connectorRows(ITSM, EPP);
  assert.equal(M.cardMeta(r[0], NOW), 'ITSM · ServiceNow · last tested 2 min ago');
  assert.equal(M.cardMeta(r[2], NOW), 'ITSM · Webhook · never tested');
  assert.equal(M.cardMeta(r[4], NOW), 'EPP · CrowdStrike Falcon');
});

test('hero stats count only what the APIs return', () => {
  const s = M.heroStats(M.connectorRows(ITSM, EPP));
  assert.equal(s.total, 6); assert.equal(s.connected, 1); assert.equal(s.attention, 2);
  assert.equal(M.since(s.freshest, NOW), '2 min');
  assert.equal(M.since(Date.parse('2026-10-27T11:58:00Z'), NOW), '2 min');
  assert.equal(M.since(null), '—');
  assert.equal(M.heroStats([]).total, 0);
  assert.equal(M.heroStats(M.connectorRows([], EPP)).freshest, null);
});

test('since formats seconds, minutes, hours, days', () => {
  assert.equal(M.since(NOW - 5000, NOW), '5 s');
  assert.equal(M.since(NOW - 3 * 3600e3, NOW), '3 h');
  assert.equal(M.since(NOW - 4 * 86400e3, NOW), '4 d');
  assert.equal(M.sinceAgo(null), '');
});

test('filterRows by category and text', () => {
  const r = M.connectorRows(ITSM, EPP);
  assert.equal(M.filterRows(r, '', 'epp').length, 2);
  assert.equal(M.filterRows(r, 'jira', '').length, 2);
  assert.equal(M.filterRows(r, 'crowdstrike', 'itsm').length, 0);
  assert.equal(M.filterRows(r, 'DISABLED', '').length, 2);
  assert.equal(M.filterRows(null, 'x', '').length, 0);
  assert.deepEqual(M.kindCounts(r), { '': 6, itsm: 4, epp: 2 });
});

test('TAXII rows: status, last poll, never throws', () => {
  const r = M.taxiiRows([{ name: 'a', serverUrl: 'https://x', enabled: true, lastPollStatus: 'ok', lastPollAt: '2026-10-27T11:00:00Z' }, { name: 'b', enabled: true, lastPollStatus: 'error' }, { name: 'c', enabled: false }, { name: 'd', enabled: true }], NOW);
  assert.deepEqual(r.map((x) => x.status.label), ['Active', 'Error', 'Disabled', 'Not polled']);
  assert.equal(r[0].last, '1 h ago'); assert.equal(r[1].last, 'Never');
  assert.deepEqual(M.taxiiRows(null), []);
});
