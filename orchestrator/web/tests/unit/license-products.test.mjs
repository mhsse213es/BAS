import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { licenseProductChips } = await load(['licenseProductChips']);

test('each licensed product is a badge with a readable name, not a comma-separated code', () => {
  const html = licenseProductChips(['apibas', 'av', 'common']);
  assert.match(html, />API BAS</);
  assert.match(html, />Antivirus</);
  assert.match(html, />Common</);
  assert.equal((html.match(/<span/g) || []).length, 3);
  assert.doesNotMatch(html, /apibas|, /);
});

test('an unknown product code is shown as-is, escaped, so nothing is hidden', () => {
  const html = licenseProductChips(['futureproduct<b>']);
  assert.match(html, /futureproduct&lt;b&gt;/);
  assert.doesNotMatch(html, /<b>/);
});

test('an empty or missing list renders nothing', () => {
  assert.equal(licenseProductChips([]), '');
  assert.equal(licenseProductChips(undefined), '');
});
