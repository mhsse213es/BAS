import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/exp-model.js';

const a = (key, label, o = {}) => ({
  asset: { hostKey: key, label, managed: o.managed !== false, crownJewel: o.cj || '', internetFacing: !!o.net },
  exposureScore: o.exp, attackPathScore: o.ap, detectionCoverageScore: o.det, openFindingsCount: o.f || 0, kevExposed: !!o.kev,
});
const LIST = [
  a('dc', 'DC-01', { exp: 32, ap: 0, det: 40, f: 5, cj: 'AD', kev: true }),
  a('web', 'DMZ-WEB-01', { exp: 33, ap: 0, det: 40, f: 12, net: true }),
  a('ws', 'ENG-WS-01', { exp: 50, ap: 30, det: 40, f: 9 }),
  a('nas', 'NAS', { managed: false }),
];

test('heroStats counts only what the rows carry', () => {
  assert.deepEqual(M.heroStats(LIST), { assets: 4, internet: 1, kev: 1, findings: 26 });
  assert.deepEqual(M.heroStats(null), { assets: 0, internet: 0, kev: 0, findings: 0 });
});

test('cellText and filterRows search every column', () => {
  assert.equal(M.cellText(LIST[0], 5), 'AD');
  assert.equal(M.cellText(LIST[3], 1), 'Discovered');
  assert.equal(M.cellText(LIST[3], 2), '');
  assert.equal(M.filterRows(LIST, 'kev').length, 1);
  assert.equal(M.filterRows(LIST, 'discovered').length, 1);
  assert.equal(M.filterRows(LIST, '  ').length, 4);
  assert.equal(M.filterRows(LIST, 'zzz').length, 0);
});

test('sortRows is stable and puts empty values last in both directions', () => {
  assert.deepEqual(M.sortRows(LIST, 2, 1).map((r) => r.asset.hostKey), ['dc', 'web', 'ws', 'nas']);
  assert.deepEqual(M.sortRows(LIST, 2, -1).map((r) => r.asset.hostKey), ['ws', 'web', 'dc', 'nas']);
  assert.deepEqual(M.sortRows(LIST, 5, 1).map((r) => r.asset.hostKey)[0], 'dc');
  assert.deepEqual(M.sortRows(LIST, -1, 1), LIST);
  assert.deepEqual(M.sortRows(LIST, 0, 1).map((r) => r.asset.label), ['DC-01', 'DMZ-WEB-01', 'ENG-WS-01', 'NAS']);
});

test('hostBars keeps the most exposed hosts and says when it cut the list', () => {
  const b = M.hostBars(LIST, 2);
  assert.deepEqual(b.labels, ['DC-01', 'DMZ-WEB-01']);
  assert.deepEqual(b.data, [32, 33]);
  assert.equal(b.sub, 'lowest 2 of 3 scores');
  assert.equal(M.hostBars(LIST).sub, '');
  assert.deepEqual(M.hostBars([]).labels, []);
});

test('findingsRows ranks hosts with findings, tones above ten as bad', () => {
  const r = M.findingsRows(LIST);
  assert.deepEqual(r.map((x) => x[0]), ['DMZ-WEB-01', 'ENG-WS-01', 'DC-01']);
  assert.equal(r[0][2], 'bad');
  assert.equal(r[1][2], 'warn');
  assert.equal(r[0][1], 100);
  assert.deepEqual(M.findingsRows([a('x', 'X')]), []);
});

test('csv has the visible columns plus the host key and neutralises formulas', () => {
  const cols = [0, 2];
  assert.deepEqual(M.csvHeader(cols), ['Host', 'Exposure', 'Host key']);
  assert.deepEqual(M.csvRows([LIST[0]], cols), [['DC-01', '32', 'dc']]);
  assert.match(M.csvText(['H'], [['=cmd']]), /'=cmd/);
});

test('drawer pieces use only profile fields that exist', () => {
  assert.equal(M.drawerSub({ managed: true, crownJewel: 'ERP', os: 'Windows', ip: '10.0.0.5' }), 'Managed · crown jewel ERP · Windows · 10.0.0.5');
  assert.equal(M.drawerSub({}), 'Discovered');
  assert.deepEqual(M.chipRows({ managed: true, internetFacing: true, crownJewel: 'ERP', criticalityTier: 'Tier 0' }),
    [['Managed', 'ok'], ['Internet-facing', 'bad'], ['ERP', 'violet'], ['Tier 0', 'info']]);
  const rows = M.factRows({
    asset: { hostKey: 'h', os: 'Linux' }, scores: { vulnerabilityMeasurable: true },
    vulnerabilities: [{ kev: true }, { kev: false }], findings: { collected: true, openCount: 3, criticalCount: 1 },
  });
  assert.deepEqual(rows.slice(0, 4), [['Vulnerabilities', '2'], ['KEV-listed', '1'], ['Open findings', '3'], ['Critical findings', '1']]);
  assert.ok(rows.some((r) => r[0] === 'Operating system'));
  // not collected: no fabricated zeros
  const none = M.factRows({ asset: { hostKey: 'h' }, scores: {}, findings: { collected: false }, vulnerabilities: [] });
  assert.deepEqual(none, [['Host key', 'h']]);
  assert.equal(M.related()[0].tab, 'findings');
  assert.equal(M.related()[1].tab, 'attackpath');
});
