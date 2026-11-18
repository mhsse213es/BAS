import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const E = await import('../../src/features/rw-efficacy.js');

const base = { overall: 'unproven', dimensions: {}, attempts: [] };

test('endpoint-only steps are mapped with a tone per endpoint result', () => {
  const m = E.rwEfficacyModel({ ...base, endpointOnly: [
    { techniqueId: 'T1486', stepName: 'encrypt', result: 'fail' },
    { techniqueId: 'T1490', stepName: 'vss', result: 'pass' },
    { techniqueId: 'T1135', stepName: 'shares', result: 'error' },
  ] });
  assert.deepEqual(m.endpointOnly.map(s => s.tone), ['bad', 'ok', 'warn']);
});

test('endpoint-only steps do not change the overall statement', () => {
  const plain = E.rwEfficacyModel(base);
  const withEp = E.rwEfficacyModel({ ...base, endpointOnly: [{ techniqueId: 'T1486', stepName: 'x', result: 'fail' }] });
  assert.equal(withEp.label, plain.label);
  assert.equal(withEp.tone, plain.tone);
});

test('the endpoint-only section says it is not capability evidence', () => {
  const html = E.rwEfficacyHTML(E.rwEfficacyModel({ ...base, endpointOnly: [{ techniqueId: 'T1486', stepName: 'encrypt', result: 'fail' }] }));
  assert.ok(html.includes('no capability evidence (1)'));
  assert.ok(html.includes('do not change the statement above'));
});

test('step names from the run are escaped in the endpoint-only section', () => {
  const html = E.rwEfficacyHTML(E.rwEfficacyModel({ ...base, endpointOnly: [{ techniqueId: 'T1', stepName: '<img src=x onerror=alert(1)>', result: 'pass' }] }));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;img'));
});

test('no endpoint-only section when there are none', () => {
  const html = E.rwEfficacyHTML(E.rwEfficacyModel(base));
  assert.ok(!html.includes('no capability evidence'));
});
