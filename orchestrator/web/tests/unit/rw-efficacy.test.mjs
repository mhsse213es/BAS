import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const E = await import('../../src/features/rw-efficacy.js');

const report = {
  overall: 'gaps_found',
  dimensions: {
    detection: { status: 'gap', attempts: 2, pass: 1, fail: 1, error: 0, skipped: 0, notApplicable: 0 },
    containment: { status: 'partial', attempts: 2, pass: 1, fail: 0, error: 0, skipped: 1, notApplicable: 0 },
    recovery: { status: 'unproven', attempts: 0, pass: 0, fail: 0, error: 0, skipped: 2, notApplicable: 0 },
    prevention: { status: 'proven', attempts: 1, pass: 1, fail: 0, error: 0, skipped: 0, notApplicable: 0 }
  },
  attempts: [{ techniqueId: 'T1490', action: 'shadow copy delete', verdicts: { detection: 'FAIL', containment: 'PASS' } }]
};

test('model maps the server overall and dimension statuses without changing them', () => {
  const m = E.rwEfficacyModel(report);
  assert.equal(m.label, 'Gaps found');
  assert.equal(m.tone, 'bad');
  const det = m.dimensions.find(d => d.key === 'detection');
  assert.equal(det.status, 'Gap');
  assert.equal(det.counts.fail, 1);
  assert.equal(m.dimensions[0].key, 'detection', 'required dimensions come first');
});

test('not-proven lists required capabilities that are unproven or partly proven, not gaps', () => {
  const m = E.rwEfficacyModel(report);
  assert.deepEqual(m.notProven, [
    'Containment: some attempts were skipped or errored.',
    'Recovery: no evidence was collected.'
  ]);
});

test('unknown overall and status values are shown as-is, never coerced to a pass', () => {
  const m = E.rwEfficacyModel({ overall: 'mystery', dimensions: { detection: { status: 'weird' } }, attempts: [] });
  assert.equal(m.label, 'mystery');
  assert.equal(m.tone, 'muted');
  assert.equal(m.dimensions[0].tone, 'muted');
});

test('HTML escapes every server string, including technique ids and actions', () => {
  const hostile = { overall: 'evidenced', dimensions: {}, attempts: [
    { techniqueId: '<img src=x onerror=alert(1)>', action: '<b>a</b>', verdicts: { detection: 'PASS' } }
  ] };
  const html = E.rwEfficacyHTML(E.rwEfficacyModel(hostile));
  assert.ok(!html.includes('<img src=x'), 'technique id must be escaped');
  assert.ok(!html.includes('<b>a</b>'), 'action must be escaped');
  assert.ok(html.includes('&lt;img'));
});

test('only the ransomware scenario ids get the panel', () => {
  assert.equal(E.isRansomwareRun('akira-kill-chain'), true);
  assert.equal(E.isRansomwareRun('apt29-kill-chain-phase7'), false);
  assert.equal(E.isRansomwareRun(undefined), false);
});

test('an empty report renders the overall label and no attempts section', () => {
  const html = E.rwEfficacyHTML(E.rwEfficacyModel({ overall: 'unproven', dimensions: {}, attempts: [] }));
  assert.ok(html.includes('Unproven'));
  assert.ok(!html.includes('Attempts ('));
});
