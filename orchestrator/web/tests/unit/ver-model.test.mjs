import { test } from 'node:test';
import assert from 'node:assert/strict';
import { heroStats, domainOptions, statusOptions, controlRows, outcomeSegments, filterItems, hasFilter, cellText, tableFilter, sortItems, summaryText, drawerRows, statusText, isOutstanding, COLUMNS } from '../../src/features/ver-model.js';

const I = [
  { expectationId: 'e1', status: 'Detected', techniqueId: 'T1003', provider: 'splunk', providerDisplay: 'Splunk', domain: 'siem', confidence: 'high', verifiedBy: 'ana', evidenceCount: 2 },
  { expectationId: 'e2', status: 'NotDetected', techniqueId: 'T1059', provider: 'okta', providerDisplay: 'Okta', domain: 'identity', confidence: 'medium', evidenceCount: 0 },
  { expectationId: 'e3', status: 'Pending', techniqueId: 'T1021', provider: 'splunk', providerDisplay: 'Splunk', domain: 'siem', confidence: 'low' },
  { expectationId: 'e4', status: 'NeedsReview', techniqueId: 'T1566', provider: 'proofpoint', domain: 'email', confidence: 'high', evidenceCount: 1 },
];

test('heroStats: counts and em-dash inputs', () => {
  assert.deepEqual(heroStats([]), { checks: null, detected: null, outstanding: null, silent: null });
  assert.deepEqual(heroStats(null), { checks: null, detected: null, outstanding: null, silent: null });
  assert.deepEqual(heroStats(I), { checks: 4, detected: '25%', outstanding: 2, silent: 1 });
});

test('status text and outstanding', () => {
  assert.equal(statusText('NotDetected'), 'Silent');
  assert.equal(statusText(undefined), 'Pending');
  assert.equal(isOutstanding(I[2]), true);
  assert.equal(isOutstanding(I[0]), false);
});

test('options are taken from the loaded items', () => {
  assert.deepEqual(domainOptions(I), ['email', 'identity', 'siem']);
  assert.deepEqual(statusOptions(I).map((o) => o[0]).sort(), ['Detected', 'NeedsReview', 'NotDetected', 'Pending']);
});

test('controlRows: detected share per domain', () => {
  const r = controlRows(I);
  assert.deepEqual(r.map((o) => [o.label, o.pct]), [['Email', 0], ['Identity', 0], ['Siem', 50]]);
  assert.equal(r[2].text, '50%');
  assert.equal(r[2].tone, 'warn');
});

test('outcomeSegments: fixed order, zero slices dropped', () => {
  assert.deepEqual(outcomeSegments(I).map((s) => [s.key, s.value]), [['Detected', 1], ['NotDetected', 1], ['NeedsReview', 1], ['Pending', 1]]);
  assert.deepEqual(outcomeSegments([]), []);
});

test('filterItems: query, status and domain combine', () => {
  assert.equal(filterItems(I, {}).length, 4);
  assert.equal(filterItems(I, { domain: 'siem' }).length, 2);
  assert.equal(filterItems(I, { domain: 'siem', status: 'Pending' }).length, 1);
  assert.equal(filterItems(I, { q: 'okta' }).length, 1);
  assert.equal(filterItems(I, { q: 'silent' }).length, 1);
  assert.equal(hasFilter({ q: '', status: '', domain: '' }), false);
  assert.equal(hasFilter({ q: 'x' }), true);
});

test('table cells, filter and sort', () => {
  assert.equal(COLUMNS.length, 7);
  assert.equal(cellText(I[0], 6), '2 files');
  assert.equal(cellText(I[3], 6), '1 file');
  assert.equal(cellText(I[1], 6), '');
  assert.equal(cellText(I[3], 2), 'proofpoint');
  assert.equal(tableFilter(I, 'identity').length, 1);
  assert.deepEqual(sortItems(I, 1, 1).map((i) => i.techniqueId), ['T1003', 'T1021', 'T1059', 'T1566']);
  assert.deepEqual(sortItems(I, 1, -1).map((i) => i.techniqueId), ['T1566', 'T1059', 'T1021', 'T1003']);
  // empty analyst values sort last in both directions
  assert.equal(sortItems(I, 5, 1)[0].expectationId, 'e1');
  assert.equal(sortItems(I, 5, -1)[0].expectationId, 'e1');
  assert.deepEqual(sortItems(I, 6, -1).map((i) => i.expectationId), ['e1', 'e4', 'e2', 'e3']);
  assert.equal(sortItems(I, -1, 1).length, 4);
});

test('summaryText and drawerRows', () => {
  assert.equal(summaryText(4, 4), '4 expectations');
  assert.equal(summaryText(1, 1), '1 expectation');
  assert.equal(summaryText(4, 2), '2 of 4 expectations');
  const d = drawerRows(I[0]);
  assert.deepEqual(d[0], ['Expected control', 'Splunk']);
  assert.deepEqual(d.find((r) => r[0] === 'Evidence'), ['Evidence', '2 files']);
  assert.deepEqual(drawerRows(I[2]).find((r) => r[0] === 'Analyst'), ['Analyst', '—']);
  assert.deepEqual(drawerRows(I[2]).find((r) => r[0] === 'Evidence'), ['Evidence', 'None attached']);
});
