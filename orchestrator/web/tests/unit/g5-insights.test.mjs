import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const ai = await import('../../src/features/agents-insights.js');
const si = await import('../../src/features/settings-insights.js');
const ii = await import('../../src/features/integrations-insights.js');

test('osFamily collapses versions and survives odd input', () => {
  assert.equal(ai.osFamily('Windows 11 23H2'), 'Windows');
  assert.equal(ai.osFamily('Windows Server 2022'), 'Windows Server');
  assert.equal(ai.osFamily('macOS 14.6'), 'macOS');
  assert.equal(ai.osFamily('Ubuntu 22.04'), 'Ubuntu');
  assert.equal(ai.osFamily(null), 'Unknown');
});

test('agentInsightStats counts only real rows and never divides by zero', () => {
  const e = ai.agentInsightStats([], {});
  assert.equal(e.fleet, 0); assert.equal(e.onlinePct, 0);
  const s = ai.agentInsightStats([{ status: 'online', wsConnected: false, transport: 'legacy', osVersion: 'Ubuntu 22', groupName: 'G' }, { status: 'offline' }], { online: 1, offline: 1, retired: 2 });
  assert.equal(s.fleet, 2); assert.equal(s.channelDown, 1); assert.equal(s.legacy, 1); assert.equal(s.attention, 1);
  assert.deepEqual(s.groups[0], ['G', 1]);
});

test('agent insight html escapes group names', () => {
  const h = ai.agentInsightsHtml([{ status: 'online', wsConnected: true, groupName: '<img src=x onerror=1>' }], { online: 1 });
  assert.ok(!/<img/.test(h));
  assert.ok(ai.agentInsightsHtml([], undefined).length > 0);
});

test('risk stats treat unmeasured endpoints as no data, not a score', () => {
  const s = ai.riskInsightStats([{ measurable: false, healthScore: 0 }, { measurable: true, healthScore: 90, trend: 'Declining', openFindingsCount: 3, topDeficitCategory: 'X' }]);
  assert.equal(s.avg, 90); assert.equal(s.noData, 1); assert.equal(s.declining, 1); assert.equal(s.findings, 3);
  assert.equal(ai.agentRiskInsightsHtml([]), '');
  assert.equal(ai.riskInsightStats(null).avg, null);
});

test('migration panel escapes hostnames', () => {
  const h = ai.migrationPanelHtml({ daysClean: 1, daysRequired: 30, blockingAgents: [{ hostname: '<b>h</b>', lastSeen: 0 }] }, () => 't');
  assert.ok(!/<b>h/.test(h));
});

test('user and backup stats handle empty and odd data', () => {
  assert.equal(si.userStats(null).total, 0);
  const u = si.userStats([{ role: 'admin', isActive: true }, { role: 'weird', isActive: false, mustChangePw: true }]);
  assert.equal(u.by.admin, 1); assert.equal(u.disabled, 1); assert.equal(u.pwReset, 1);
  assert.ok(!/<script/.test(si.usersInsightsHtml([{ role: '<script>' }])));
  assert.equal(si.backupStats(undefined).total, 0);
  assert.ok(si.backupInsightsHtml([]).includes('no backups yet'));
});

test('daysUntil and license html', () => {
  assert.equal(si.daysUntil('nope'), null);
  assert.equal(si.daysUntil('2026-01-11', Date.parse('2026-01-01')), 10);
  assert.ok(si.licenseInsightsHtml({}).includes('n/a'));
});

test('caldera, art, intel and audit builders tolerate empty input', () => {
  assert.ok(si.calderaInsightsHtml(null).includes('Unreachable'));
  assert.ok(si.artInsightsHtml({}).length > 0);
  assert.ok(si.intelInsightsHtml({}).length > 0);
  assert.equal(si.auditInsightsHtml([]), '');
  assert.equal(si.auditStats([{ action: 'a', outcome: 'denied', actorName: 'u' }]).failed, 1);
  assert.equal(si.simMixHtml([['a', 0]]), '');
});

test('connector stats', () => {
  assert.equal(ii.integrationsInsightsHtml([], []), '');
  const s = ii.connectorStats([{ enabled: true, lastTestOk: true, provider: 'jira', autoCreate: 'critical_high' }, { enabled: true, lastTestOk: false }, { enabled: false }], [{ enabled: true, provider: 'x<y' }]);
  assert.equal(s.connected, 1); assert.equal(s.failed, 1); assert.equal(s.disabled, 1); assert.equal(s.auto, 1); assert.equal(s.eppEnabled, 1);
  assert.ok(!/x<y/.test(ii.integrationsInsightsHtml([], [{ enabled: true, provider: 'x<y' }])));
});
