import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { formatFingerprint } = await load(['formatFingerprint']);

const FP = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

test('groups the fingerprint in uppercase blocks of 8 for visual comparison', () => {
  assert.equal(
    formatFingerprint(FP),
    '01234567 89ABCDEF 01234567 89ABCDEF 01234567 89ABCDEF 01234567 89ABCDEF'
  );
});

test('returns an empty string for a missing or malformed fingerprint so nothing misleading is shown', () => {
  for (const bad of [undefined, null, '', 'abc', FP + '00', 'g'.repeat(64), 42]) {
    assert.equal(formatFingerprint(bad), '');
  }
});

test('accepts an uppercase fingerprint', () => {
  assert.equal(formatFingerprint(FP.toUpperCase()), formatFingerprint(FP));
});
