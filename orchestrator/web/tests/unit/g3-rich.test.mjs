import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normSev, sevColor, sevTone, countBy, sevSegments, hbarRows, rateTone, pctText, matchesQuery } from '../../src/features/rich-g3.js';

test('normSev canonicalises any casing and rejects unknown values', () => {
  assert.equal(normSev('critical'), 'Critical');
  assert.equal(normSev('HIGH'), 'High');
  assert.equal(normSev('Medium'), 'Medium');
  assert.equal(normSev(''), '');
  assert.equal(normSev(null), '');
  assert.equal(normSev(undefined), '');
  assert.equal(normSev('<script>'), '');
});

test('sevTone and sevColor fall back for unknown severities', () => {
  assert.equal(sevTone('Critical'), 'bad');
  assert.equal(sevTone('low'), 'info');
  assert.equal(sevTone('nope'), 'muted');
  assert.equal(sevColor('nope'), 'var(--muted)');
  assert.equal(sevColor('Critical'), 'var(--danger)');
});

test('countBy sorts by count then key and labels blanks', () => {
  const rows = [{ k: 'b' }, { k: 'a' }, { k: 'b' }, { k: '' }, {}, { k: null }];
  assert.deepEqual(countBy(rows, (r) => r.k, 'Blank'), [['Blank', 3], ['b', 2], ['a', 1]]);
  assert.deepEqual(countBy([], (r) => r.k), []);
  assert.deepEqual(countBy(null, (r) => r.k), []);
  assert.deepEqual(countBy([{ k: '<img>' }], (r) => r.k), [['<img>', 1]]);
});

test('sevSegments keeps fixed order, drops zero buckets and unknown severities', () => {
  const segs = sevSegments([{ s: 'low' }, { s: 'Critical' }, { s: 'Critical' }, { s: 'weird' }, { s: 'High' }], (r) => r.s);
  assert.deepEqual(segs.map((s) => [s.label, s.value]), [['Critical', 2], ['High', 1], ['Low', 1]]);
  assert.deepEqual(sevSegments([], (r) => r.s), []);
});

test('hbarRows scales to the largest value and survives empty or zero input', () => {
  assert.deepEqual(hbarRows([['a', 10], ['b', 5]], 'bad', 5), [['a', 100, 'bad', '10'], ['b', 50, 'bad', '5']]);
  assert.equal(hbarRows([['a', 1], ['b', 1], ['c', 1]], 'ok', 2).length, 2);
  assert.deepEqual(hbarRows([['a', 0]], 'ok'), [['a', 0, 'ok', '0']]);
  assert.deepEqual(hbarRows(null), []);
});

test('rateTone and pctText', () => {
  assert.equal(rateTone(95), 'ok');
  assert.equal(rateTone(80), 'warn');
  assert.equal(rateTone(10), 'bad');
  assert.equal(pctText(1, 4), '25%');
  assert.equal(pctText(0, 0), '—');
});

test('matchesQuery is a case-insensitive substring match over several fields', () => {
  assert.equal(matchesQuery('', ['x']), true);
  assert.equal(matchesQuery('  ', []), true);
  assert.equal(matchesQuery('cred', ['OS Credential Dumping', 'T1003']), true);
  assert.equal(matchesQuery('T1003', [null, undefined, 't1003']), true);
  assert.equal(matchesQuery('zzz', ['abc', null]), false);
  assert.equal(matchesQuery('a', null), false);
});
