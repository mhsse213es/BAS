import { test } from 'node:test';
import assert from 'node:assert/strict';
import { typeLabel, formatsFor, historyRows, typeOptions, filterHistory, heroStats, agentRows, frameworkCards, medianDays, daysText, slaKpis, slaSeverityRows, slaTrend, slaTone } from '../../src/features/rpt-model.js';

test('typeLabel and formatsFor follow the report endpoint', () => {
  assert.equal(typeLabel('audit'), 'Audit pack');
  assert.equal(typeLabel('weird'), 'weird');
  assert.deepEqual(formatsFor('audit'), [{ value: '', label: 'Package' }]);
  assert.deepEqual(formatsFor('compliance').map(f => f.value), ['html', 'csv']);
  assert.equal(formatsFor('posture')[1].label, 'CSV (forensic)');
});

const list = [
  { id: 'abcdef123456', reportType: 'posture', format: 'html', scopeLabel: 'agent-1', generatedBy: 'admin', generatedAt: '2026-10-20T10:00:00Z', status: 'generated', downloadPath: '/api/report/full/html?agentId=agent-1' },
  { id: '99887766aabb', reportType: 'compliance', format: 'csv', scopeLabel: 'pci · agent-2', generatedBy: 'analyst', generatedAt: '2026-10-19T10:00:00Z', status: 'failed', downloadPath: '/x' },
  { id: '11223344ffee', reportType: 'audit', format: '', scopeLabel: 'agent-1', generatedBy: '', generatedAt: '2026-10-18T10:00:00Z', status: 'generated', downloadPath: '/p' },
];

test('historyRows maps type, format, failure and preview', () => {
  const r = historyRows(list);
  assert.equal(r[0].name, 'Posture report');
  assert.equal(r[0].shortId, 'abcdef12');
  assert.equal(r[0].fmt, 'HTML');
  assert.equal(r[0].canPreview, true);
  assert.equal(r[1].failed, true);
  assert.equal(r[1].canPreview, false);
  assert.equal(r[2].fmt, 'PACKAGE');
  assert.equal(r[2].by, '—');
  assert.deepEqual(historyRows(null), []);
});

test('typeOptions and filterHistory', () => {
  const rows = historyRows(list);
  assert.deepEqual(typeOptions(rows), [['posture', 'Posture report'], ['compliance', 'Compliance evidence'], ['audit', 'Audit pack']]);
  assert.equal(filterHistory(rows, '', '').length, 3);
  assert.equal(filterHistory(rows, 'pci', '').length, 1);
  assert.equal(filterHistory(rows, '', 'audit').length, 1);
  assert.equal(filterHistory(rows, 'agent-1', 'audit').length, 1);
  assert.equal(filterHistory(rows, 'nomatch', '').length, 0);
});

test('heroStats is null until data arrives', () => {
  assert.deepEqual(heroStats(list, [{}, {}]), { reports: 3, frameworks: 2 });
  assert.deepEqual(heroStats(null, undefined), { reports: null, frameworks: null });
});

test('agentRows counts completed and partial runs per agent', () => {
  const runs = [
    { agentId: 'a1', status: 'completed', name: 'S1', completedAt: '2026-10-20T00:00:00Z' },
    { agentId: 'a1', status: 'running', name: 'S2' },
    { agentId: 'a1', status: 'partial', name: 'S3' },
    { agentId: 'a2', status: 'failed' },
    { status: 'completed' },
  ];
  const r = agentRows(runs, { a1: 'host-1' });
  assert.equal(r.length, 1);
  assert.deepEqual([r[0].host, r[0].runs, r[0].lastName], ['host-1', 2, 'S1']);
});

test('frameworkCards: tone and honest zero state', () => {
  const c = frameworkCards([
    { frameworkId: 'pci', frameworkName: 'PCI-DSS', compliancePct: 86.4, testedControls: 14, passingControls: 12, failingControls: 2, testableControls: 20 },
    { frameworkId: 'iso', frameworkName: 'ISO 27001', compliancePct: 0, testedControls: 0 },
  ]);
  assert.deepEqual([c[0].pct, c[0].tone], [86, 'ok']);
  assert.match(c[0].detail, /12 of 14 tested controls passing · 2 failing · 6 untested/);
  assert.deepEqual([c[1].pct, c[1].tone, c[1].detail], [null, 'muted', 'No controls tested yet.']);
});

test('medianDays, daysText', () => {
  const rec = [
    { startedAt: '2026-10-01T00:00:00Z', resolvedAt: '2026-10-03T00:00:00Z' },
    { startedAt: '2026-10-01T00:00:00Z', resolvedAt: '2026-10-11T00:00:00Z' },
    { startedAt: 'bad', resolvedAt: '2026-10-11T00:00:00Z' },
  ];
  assert.equal(medianDays(rec), 6);
  assert.equal(medianDays([]), null);
  assert.equal(daysText(6), '6 d');
  assert.equal(daysText(0.25), '6 h');
  assert.equal(daysText(null), '—');
  assert.equal(daysText(12.4), '12 d');
});

test('slaKpis shows dashes before anything resolved', () => {
  const k = slaKpis({ onTime: 9, late: 1, complianceRate: 90, currentlyOpen: 4, totalEpisodes: 14 }, []);
  assert.deepEqual([k.rate, k.rateTone, k.late, k.open, k.median], ['90.0%', 'ok', 1, 4, '—']);
  assert.equal(k.rateSub, '9 of 10 resolved on time');
  const e = slaKpis({ onTime: 0, late: 0, complianceRate: 0, currentlyOpen: 2, totalEpisodes: 2 }, []);
  assert.deepEqual([e.rate, e.rateTone], ['—', 'muted']);
});

test('slaSeverityRows orders Critical first and keeps unresolved muted', () => {
  const r = slaSeverityRows([
    { severity: 'Low', onTime: 0, late: 0, complianceRate: 0 },
    { severity: 'Critical', onTime: 3, late: 1, complianceRate: 75 },
  ]);
  assert.equal(r[0][0].startsWith('Critical'), true);
  assert.deepEqual([r[0][1], r[0][2], r[0][3]], [75, 'warn', '75%']);
  assert.deepEqual([r[1][1], r[1][2], r[1][3]], [0, 'muted', '—']);
});

test('slaTrend sorts by month; slaTone thresholds', () => {
  assert.deepEqual(slaTrend([{ month: '2026-10', complianceRate: 80 }, { month: '2026-09', complianceRate: 90 }]).map(m => m.month), ['2026-09', '2026-10']);
  assert.equal(slaTone(90), 'ok'); assert.equal(slaTone(75), 'warn'); assert.equal(slaTone(74), 'bad');
});
