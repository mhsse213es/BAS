import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SEP, compareStyles, validateAllowlist, isAllowed, masksFor, formatDiff } from '../visual/compare.mjs';

const props = ['color', 'margin-top'];
const row = (...v) => v.join(SEP);

test('identical snapshots produce no diffs', () => {
  const s = { body: row('rgb(0, 0, 0)', '0px'), 'body>div:0': row('red', '4px') };
  assert.deepEqual(compareStyles('tab:a', s, { ...s }, props), []);
});

test('a changed property is reported with path, property and both values', () => {
  const base = { 'body>div:0': row('red', '4px') };
  const head = { 'body>div:0': row('red', '5px') };
  assert.deepEqual(compareStyles('tab:a', base, head, props), [
    { checkpoint: 'tab:a', path: 'body>div:0', property: 'margin-top', base: '4px', head: '5px' },
  ]);
});

test('a structural difference is reported as a missing or extra element', () => {
  const d = compareStyles('tab:a', { 'body>p:0': row('a', 'b') }, { 'body>span:0': row('a', 'b') }, props);
  assert.deepEqual(d.map((x) => [x.path, x.base, x.head]), [['body>p:0', 'present', 'missing'], ['body>span:0', 'missing', 'present']]);
});

test('allowlist entries need a reason and known keys', () => {
  assert.throws(() => validateAllowlist([{ checkpoint: 'tab:a', property: 'color' }]), /reason/);
  assert.throws(() => validateAllowlist([{ checkpoint: 'tab:a', reason: 'x', colour: 'y' }]), /unknown key/);
  assert.doesNotThrow(() => validateAllowlist([{ checkpoint: 'tab:a', path: 'body>div:0', property: 'color', reason: 'subpixel AA' }]));
});

test('isAllowed matches checkpoint and the given fields only', () => {
  const d = { checkpoint: 'tab:a', path: 'body>div:0', property: 'color', base: 'a', head: 'b' };
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:a', property: 'color', reason: 'r' }]), true);
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:b', property: 'color', reason: 'r' }]), false);
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:a', path: 'body>div:1', reason: 'r' }]), false);
  assert.equal(isAllowed(d, [{ checkpoint: 'tab:a', mask: '#clock', reason: 'r' }]), false);
});

test('masksFor returns the screenshot masks of one checkpoint', () => {
  const e = [{ checkpoint: 'tab:a', mask: '#clock', reason: 'r' }, { checkpoint: 'tab:b', mask: '#x', reason: 'r' }];
  assert.deepEqual(masksFor('tab:a', e), ['#clock']);
});

test('formatDiff names everything needed to find the element', () => {
  assert.equal(formatDiff({ checkpoint: 'tab:a', path: 'body>div:0', property: 'color', base: 'red', head: 'blue' }),
    'tab:a  body>div:0  color: red -> blue');
});
