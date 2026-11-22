import { test } from 'node:test';
import assert from 'node:assert/strict';
import { typeLabel, formatsFor, historyRows, typeOptions, filterHistory, heroStats, agentRows, frameworkCards, medianDays, daysText, slaKpis, slaSeverityRows, slaTrend, slaTone, runResult } from '../../src/features/rpt-model.js';

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
  assert.deepEqual(heroStats(list, [{}, {}]), { reports: 3, frameworks: 2, latest: '2026-10-20T10:00:00Z' });
  assert.deepEqual(heroStats(null, undefined), { reports: null, frameworks: null, latest: '' });
});

test('agentRows counts reportable runs per agent and lists every finished run', () => {
  const runs = [
    { id: 'r1', agentId: 'a1', status: 'completed', name: 'S1', completedAt: '2026-10-20T00:00:00Z' },
    { id: 'r2', agentId: 'a1', status: 'running', name: 'S2' },
    { id: 'r3', agentId: 'a1', status: 'partial', name: 'S3' },
    { id: 'r4', agentId: 'a2', status: 'failed', name: 'S4' },
    { id: 'r5', agentId: 'a1', status: 'completed', name: 'sweep step', sweepId: 'sw1' },
    { status: 'completed' },
  ];
  const r = agentRows(runs, { a1: 'host-1' });
  assert.equal(r.length, 2, 'an agent with only a failed run is still listed');
  assert.deepEqual([r[0].host, r[0].runs, r[0].lastName, r[0].list.map(x => x.id)], ['host-1', 2, 'S1', ['r1', 'r3']]);
  assert.deepEqual([r[1].runs, r[1].failed, r[1].list[0].reportable], [0, 1, false]);
});

test('agentRows reports only on runs that finished, and takes the latest finished run as the headline', () => {
  const r = agentRows([
    { id: 'f', agentId: 'a', status: 'failed', name: 'Newest but failed' },
    { id: 'c', agentId: 'a', status: 'completed', name: 'Latest good', completedAt: '2026-10-01T00:00:00Z' },
  ], {});
  assert.equal(r[0].lastName, 'Latest good');
  assert.deepEqual(r[0].list.map(x => [x.id, x.reportable]), [['f', false], ['c', true]]);
});

test('frameworkCards: tone and honest zero state', () => {
  const c = frameworkCards([
    { frameworkId: 'pci', frameworkName: 'PCI-DSS', compliancePct: 86.4, testedControls: 14, passingControls: 12, failingControls: 2, testableControls: 20 },
    { frameworkId: 'iso', frameworkName: 'ISO 27001', compliancePct: 0, testedControls: 0 },
  ]);
  assert.deepEqual([c[0].pct, c[0].tone], [86, 'ok']);
  assert.match(c[0].detail, /12 of 14 tested controls resisted the executed techniques · 2 failing · 6 untested/);
  assert.match(c[0].coverage, /Control coverage 14 of 20 \(70%\)/);
  assert.equal(c[0].note, '');
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

test('frameworkCards: a high rate on little testing is never shown as good, and carries its caveats', () => {
  const [c] = frameworkCards([
    { frameworkId: 'rbi', frameworkName: 'RBI', compliancePct: 100, coveragePct: 0.85, testedControls: 1, passingControls: 1, failingControls: 0,
      testableControls: 117, mappingWarning: 'Reviewed against the 2026 directions; technique links are our own.' },
  ]);
  assert.equal(c.pct, 100);
  assert.equal(c.tone, 'warn', 'a 100% rate over 1 of 117 controls must not be green');
  assert.match(c.coverage, /Control coverage 1 of 117/);
  assert.match(c.note, /Insufficient coverage for framework-level conclusions/);
  assert.match(c.warning, /our own/);
  assert.doesNotMatch(c.detail, /compliant/i);
});

import { sortHistory, agentOptions, osKind, DATE_RANGES } from '../../src/features/rpt-model.js';

const hist = historyRows([
  { id: 'aaaaaaaa-1111-2222-3333-444444444444', reportType: 'posture', format: 'pdf', scopeLabel: 'a1', agentId: 'a1', generatedBy: 'admin', generatedAt: '2026-11-16T10:00:00Z', status: 'generated', downloadPath: '/x' },
  { id: 'bbbbbbbb-1111-2222-3333-444444444444', reportType: 'compliance', format: 'csv', scopeLabel: 'pci · a2', generatedBy: 'analyst', generatedAt: '2026-08-01T10:00:00Z', status: 'generated', downloadPath: '/y' },
]);

test('history rows carry the agent id, from the server or from an older scope label, and a short id', () => {
  assert.equal(hist[0].agentId, 'a1');
  assert.equal(hist[1].agentId, 'a2');
  assert.equal(hist[0].idShort, 'aaaaaa…4444');
});

test('the date range hides older reports, the agent filter narrows, and nothing else is dropped', () => {
  const now = Date.parse('2026-11-16T12:00:00Z');
  assert.deepEqual(filterHistory(hist, '', '', { days: '30', now }).map(r => r.agentId), ['a1']);
  assert.equal(filterHistory(hist, '', '', { days: 'all', now }).length, 2);
  assert.deepEqual(filterHistory(hist, '', '', { agent: 'a2', days: 'all', now }).map(r => r.agentId), ['a2']);
  assert.equal(filterHistory(hist, '', '', { days: '30', now: Date.parse('2026-12-30T00:00:00Z') }).length, 0);
  assert.deepEqual(DATE_RANGES.map(r => r[0]), ['all', '7', '30', '90']);
});

test('sorting by newest, oldest and type', () => {
  assert.deepEqual(sortHistory(hist, 'new').map(r => r.agentId), ['a1', 'a2']);
  assert.deepEqual(sortHistory(hist, 'old').map(r => r.agentId), ['a2', 'a1']);
  assert.equal(sortHistory(hist, 'type').length, 2);
});

test('agent options use the host name when known and the id otherwise', () => {
  assert.deepEqual(agentOptions(hist, { a1: 'WIN-1' }), [['a2', 'a2'], ['a1', 'WIN-1']].sort((a, b) => a[1] < b[1] ? -1 : 1));
});

test('osKind picks the icon family', () => {
  assert.deepEqual(['Windows 11', 'Ubuntu 22.04', 'macOS 14', '', 'FreeBSD'].map(osKind), ['windows', 'linux', 'mac', 'other', 'other']);
});

test('agentRows marks online agents and a run in the last day as recent', () => {
  const now = Date.parse('2026-11-16T12:00:00Z');
  const r = agentRows([
    { id: 'r1', agentId: 'a1', status: 'completed', name: 'S', completedAt: '2026-11-16T11:00:00Z' },
    { id: 'r2', agentId: 'a2', status: 'completed', name: 'S', completedAt: '2026-11-10T11:00:00Z' },
  ], {}, { a1: { os: 'Windows 11', status: 'idle' }, a2: { os: 'Ubuntu', status: 'offline' } }, now);
  assert.deepEqual([r[0].os, r[0].online, r[0].recent], ['windows', true, true]);
  assert.deepEqual([r[1].os, r[1].online, r[1].recent], ['linux', false, false]);
});

test('agentRows lists executions newest first, counts executions (not scenarios), and keeps list order', () => {
  const r = agentRows([
    { id: 'a', agentId: 'x', status: 'completed', name: 'Same', completedAt: '2026-10-01T00:00:00Z' },
    { id: 'b', agentId: 'x', status: 'completed', name: 'Same', completedAt: '2026-10-03T00:00:00Z' },
    { id: 'c', agentId: 'x', status: 'failed', name: 'Other', completedAt: '2026-10-02T00:00:00Z' },
    { id: 'd', agentId: 'x', status: 'completed', name: 'Undated' },
  ], {})[0];
  assert.equal(r.total, 4, 'three runs of two scenarios plus one more is four executions');
  assert.equal(r.scenarios, 3);
  assert.deepEqual(r.recentExecutions.map(e => e.name), ['Same', 'Other', 'Same', 'Undated'], 'newest first, undated last');
  assert.deepEqual(r.list.map(e => e.id), ['a', 'b', 'c', 'd'], 'the full list keeps the order the server sent');
});

test('runResult: errors and skips are never a pass', () => {
  const sc = (p, f, e, k) => ({ score: { totalTechniques: p + f + e + k, passedTechniques: p, failedTechniques: f, erroredTechniques: e, skippedTechniques: k } });
  assert.equal(runResult(sc(3, 0, 0, 0)).result, 'PASS');
  assert.equal(runResult(sc(3, 2, 1, 0)).result, 'FAIL');
  assert.equal(runResult(sc(0, 0, 19, 1)).result, 'ERROR', 'the 0 pass / 19 errored run must not read as a pass');
  assert.equal(runResult(sc(0, 0, 0, 4)).result, 'SKIPPED');
  assert.equal(runResult({ status: 'failed' }).result, '', 'no verdicts, no result');
  assert.equal(runResult({ results: [{ result: 'blocked' }, { result: 'fail' }] }).result, 'FAIL');
});
