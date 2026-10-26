import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/fnd-model.js';

const NOW = new Date('2026-10-26T12:00:00Z').getTime();
const ago = (h) => new Date(NOW - h * 36e5).toISOString();
const L = [
  { id: 'a', status: 'open', severity: 'Critical', controlClass: 'Identity', techniqueId: 'T1', techniqueName: 'Kerberoasting', agentId: 'dc-1', firstSeen: ago(2), lastSeen: ago(1), reopenedCount: 1 },
  { id: 'b', status: 'open', severity: 'High', controlClass: 'Endpoint', techniqueId: 'T2', agentId: 'ws-1', firstSeen: ago(24 * 10), lastSeen: ago(5) },
  { id: 'c', status: 'open', severity: 'Medium', controlClass: 'Endpoint', techniqueId: 'T3', agentId: 'ws-2', firstSeen: ago(24 * 120), lastSeen: ago(5) },
  { id: 'd', status: 'remediated', severity: 'Low', controlClass: 'Network', techniqueId: 'T4', agentId: 'ws-3', firstSeen: ago(24 * 20), resolvedAt: ago(24 * 15), lastSeen: ago(24 * 15) },
  { id: 'e', status: 'risk_accepted', severity: 'High', controlClass: 'Cloud', techniqueId: 'T5', agentId: 'ws-4', firstSeen: ago(24 * 40), lastSeen: ago(24 * 40) },
];

test('ageDays and ageLabel: hours under a day, days after, fixed for remediated', () => {
  assert.equal(M.ageLabel(L[0], NOW), '2 h');
  assert.equal(M.ageLabel(L[1], NOW), '10 d');
  assert.equal(M.ageLabel(L[3], NOW), '5 d (fixed)');
  assert.equal(M.ageDays(L[3], NOW), 5);
  assert.equal(M.ageLabel({}, NOW), '—');
});

test('tileStats counts open, oldest age, critical, reopened and the 30 day remediations', () => {
  assert.deepEqual(M.tileStats(L, NOW), { total: 5, open: 3, maxAge: 120, critical: 1, reopened: 1, remediated30: 1 });
  assert.deepEqual(M.tileStats([], NOW), { total: 0, open: 0, maxAge: 0, critical: 0, reopened: 0, remediated30: 0 });
  assert.equal(M.ageTone(120), 'bad'); assert.equal(M.ageTone(30), 'warn'); assert.equal(M.ageTone(3), 'ok');
});

test('ageBuckets covers every open finding once', () => {
  const b = M.ageBuckets(M.openOf(L), NOW);
  assert.deepEqual(b.map((x) => x.label), ['0–7d', '8–14d', '15–30d', '31–90d', '90d+']);
  assert.deepEqual(b.map((x) => x.value), [1, 1, 0, 0, 1]);
});

test('controlRows scale to the largest class with tones by rank', () => {
  assert.deepEqual(M.controlRows(M.openOf(L)), [['Endpoint', 100, 'bad', '2'], ['Identity', 50, 'bad', '1']]);
  assert.deepEqual(M.controlRows([]), []);
});

test('sevSegments: fixed order, zero buckets dropped, per-card palette', () => {
  const row = M.sevSegments(M.openOf(L), 'row');
  assert.deepEqual(row.map((s) => [s.label, s.value, s.color]), [['Critical', 1, '#ef4444'], ['High', 1, '#f59e0b'], ['Medium', 1, '#3b82f6']]);
  assert.equal(M.sevSegments(M.openOf(L), 'card')[0].color, '#7f1d1d');
});

test('statusSegments and statusOptions', () => {
  assert.deepEqual(M.statusSegments(L).map((s) => [s.label, s.value]), [['Open', 3], ['Remediated', 1], ['Risk-accepted', 1]]);
  const o = M.statusOptions(L);
  assert.deepEqual(o.map((x) => [x.id, x.count]), [['all', 5], ['open', 3], ['triaged', 0], ['remediated', 1], ['risk_accepted', 1]]);
  assert.deepEqual(M.sevOptions().map((x) => x.label), ['All severities', 'Critical', 'High', 'Medium', 'Low']);
});

test('filterFindings combines status, severity and text', () => {
  assert.equal(M.filterFindings(L, {}).length, 5);
  assert.deepEqual(M.filterFindings(L, { status: 'open' }).map((f) => f.id), ['a', 'b', 'c']);
  assert.deepEqual(M.filterFindings(L, { sev: 'High' }).map((f) => f.id), ['b', 'e']);
  assert.deepEqual(M.filterFindings(L, { status: 'open', sev: 'High', q: 'WS-1' }).map((f) => f.id), ['b']);
  assert.deepEqual(M.filterFindings(L, { q: 'kerbero' }).map((f) => f.id), ['a']);
  assert.deepEqual(M.filterFindings(L, { q: 'zzz' }), []);
});

test('shortId and subline', () => {
  assert.equal(M.shortId('F-2231'), 'F-2231');
  assert.equal(M.shortId('0123456789abcdef'), '01234567');
  assert.equal(M.subline({ tactic: 'Persistence', controlClass: 'Endpoint' }), 'Persistence · Endpoint control');
  assert.equal(M.subline({}), '');
});

test('csvText quotes fields and neutralises formulas; csvRows follows the header', () => {
  assert.equal(M.csvText(['a'], [['=1+1'], ['x"y']]), '"a"\n"\'=1+1"\n"x""y"');
  const rows = M.csvRows([L[0]], NOW);
  assert.equal(rows[0].length, M.CSV_HEADER.length);
  assert.equal(rows[0][1], 'Kerberoasting'); assert.equal(rows[0][7], 'Open'); assert.equal(rows[0][10], '2 h');
});

test('drawer helpers use only fields the finding carries', () => {
  const f = { ...L[0], tactic: 'Credential Access', exposureState: 'missed', occurrenceCount: 3, reopenedCount: 2, lastRunId: 'run-9', productSnapshot: ['Defender'], variantBreakdown: { total: 5, prevented: 3 },
    enrichment: { mitigations: [{ name: 'Audit', description: 'd' }, { description: 'no name' }], detection: 'watch 4769' } };
  const facts = Object.fromEntries(M.factRows(f, NOW));
  assert.equal(facts.Technique, 'T1 Kerberoasting'); assert.equal(facts.Occurrences, '3 · reopened 2×'); assert.equal(facts['Installed product'], 'Defender');
  assert.equal(facts.Source, undefined);
  const ev = Object.fromEntries(M.evidenceLines(f));
  assert.equal(ev.variants, '3 of 5 blocked'); assert.match(ev.exposure, /^missed/); assert.equal(ev['last run'], 'run-9');
  assert.deepEqual(M.recommendation(f), { mitigations: [{ name: 'Audit', description: 'd' }], detection: 'watch 4769' });
  assert.deepEqual(M.recommendation({}), { mitigations: [], detection: '' });
  assert.deepEqual(M.related(f).map((r) => r.action), ['fndTech', 'fndGo', 'fndGo']);
  assert.deepEqual(M.related({ id: 'x' }).map((r) => r.action), ['fndGo']);
});
