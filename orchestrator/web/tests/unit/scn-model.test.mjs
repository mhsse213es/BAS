import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/scn-model.js';

const S = (o) => ({ id: 'a', name: 'A', description: '', steps: [], tags: [], mitrePhases: [], supportedOs: [], ...o });
const prod = (s) => s.productLine || 'common';

test('techniquesOf merges step and ART ids without duplicates', () => {
  const s = S({ steps: [{ techniqueId: 'T1' }, { techniqueId: 'T1' }, { techniqueId: '' }], artTechniques: ['T2', 'T1'] });
  assert.deepEqual(M.techniquesOf(s), ['T1', 'T2']);
  assert.deepEqual(M.techniquesOf(S({})), []);
});

test('osLabel names one or two platforms and calls the rest cross-platform', () => {
  assert.equal(M.osLabel(['windows']), 'Windows');
  assert.equal(M.osLabel(['windows', 'darwin']), 'Windows / macOS');
  assert.equal(M.osLabel([]), 'Cross-Platform');
  assert.equal(M.osLabel(['windows', 'linux', 'darwin']), 'Cross-Platform');
});

test('footOf shows techniques, else the run mode, plus steps', () => {
  assert.deepEqual(M.footOf(S({ steps: [{ techniqueId: 'T1' }, {}] })), { left: '+1 technique', right: '2 steps' });
  assert.equal(M.footOf(S({ artAllWindows: true }), { art: 20 }).left, 'Full ART sweep · 20 techniques');
  assert.equal(M.footOf(S({ localCheck: true })).left, 'Posture check');
  assert.equal(M.footOf(S({ steps: [{}] })).right, '1 step');
});

test('availOf reads the registry', () => {
  assert.equal(M.availOf(S({})).key, 'none');
  assert.equal(M.availOf(S({ registry: { executableVersion: 2, executableTrust: 'VENDOR_SIGNED' } })).label, 'Available');
  const p = M.availOf(S({ registry: { latestVersion: 1, latestLifecycle: 'DRAFT', executableVersion: 0 } }));
  assert.equal(p.key, 'pending');
  assert.equal(p.label, 'Draft');
});

test('filterList applies search, os, source and product', () => {
  const list = [S({ id: 'x1', name: 'LSASS dump', supportedOs: ['windows'], productLine: 'killchain', steps: [{ techniqueId: 'T1003' }] }),
    S({ id: 'x2', name: 'Cron', supportedOs: ['linux'], productLine: 'common', source: 'custom' }),
    S({ id: 'x3', name: 'Intel', intelSource: 'misp', productLine: 'common' })];
  assert.equal(M.filterList(list, { q: 't1003' }, prod).length, 1);
  assert.equal(M.filterList(list, { os: 'linux' }, prod)[0].id, 'x2');
  assert.equal(M.filterList(list, { source: 'intel' }, prod)[0].id, 'x3');
  assert.equal(M.filterList(list, { product: 'killchain' }, prod)[0].id, 'x1');
  assert.equal(M.filterList(list, { q: '', os: 'all', source: 'all', product: 'all' }, prod).length, 3);
});

test('sortList does not mutate and orders by name or technique count', () => {
  const list = [S({ id: 'b', name: 'B', steps: [{ techniqueId: 'T1' }, { techniqueId: 'T2' }] }), S({ id: 'a', name: 'A' })];
  assert.deepEqual(M.sortList(list, 'name').map((s) => s.id), ['a', 'b']);
  assert.deepEqual(M.sortList(list, 'tech').map((s) => s.id), ['b', 'a']);
  assert.deepEqual(list.map((s) => s.id), ['b', 'a']);
  assert.deepEqual(M.sortList(list, 'default').map((s) => s.id), ['b', 'a']);
});

test('heroStats counts scenarios, distinct techniques and product families', () => {
  const list = [S({ productLine: 'dlp', steps: [{ techniqueId: 'T1' }] }), S({ productLine: 'dlp', artTechniques: ['T1', 'T2'] }), S({ productLine: 'ad' })];
  assert.deepEqual(M.heroStats(list, prod), { total: 3, techniques: 2, families: 2 });
});

test('categoryRows lists All first and hides empty categories', () => {
  const rows = M.categoryRows([{ key: 'a', label: 'A', icon: 'a' }, { key: 'b', label: 'B', icon: 'b' }], 5, (k) => (k === 'a' ? 5 : 0), { a: 'sub' });
  assert.deepEqual(rows.map((r) => r.key), ['all', 'a']);
  assert.equal(rows[1].sub, 'sub');
});

test('historyOf filters by scenario, sorts newest first and extracts prevention', () => {
  const runs = [{ id: 'r1', scenarioId: 's', startedAt: '2026-10-01T00:00:00Z', score: { preventionScore: 40.4 } },
    { id: 'r2', scenarioId: 's', startedAt: '2026-10-03T00:00:00Z', hostname: 'h' },
    { id: 'r3', scenarioId: 'other', startedAt: '2026-10-04T00:00:00Z' }];
  const rows = M.historyOf(runs, 's');
  assert.deepEqual(rows.map((r) => r.id), ['r2', 'r1']);
  assert.equal(rows[1].pct, 40);
  assert.equal(rows[0].pct, null);
  assert.deepEqual(M.historySeries(rows), [40]);
});

test('showing pluralises', () => {
  assert.equal(M.showing(1, 1), 'Showing 1 of 1 scenario');
  assert.equal(M.showing(2, 5), 'Showing 2 of 5 scenarios');
});
