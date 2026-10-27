import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACCENTS, normalizeAccent, accentVars, readDisplayPrefs } from '../../src/features/display-model.js';

test('offers the five demo accent colours, blue first', () => {
  assert.deepEqual(ACCENTS.map((a) => a[1]), ['Blue', 'Cyan', 'Green', 'Violet', 'Magenta']);
  assert.equal(ACCENTS[0][0], '#3b82f6');
});

test('normalizeAccent accepts only the offered colours, case-insensitively', () => {
  assert.equal(normalizeAccent('#10B981'), '#10b981');
  assert.equal(normalizeAccent('#123456'), null);
  assert.equal(normalizeAccent('red; background:url(x)'), null);
  assert.equal(normalizeAccent(null), null);
});

test('accentVars derives the four accent tokens from the hex value', () => {
  var v = accentVars('#10b981');
  assert.equal(v['--accent'], '#10b981');
  assert.equal(v['--accent-dim'], 'rgba(16,185,129,0.14)');
  assert.equal(v['--accent-glow'], 'rgba(16,185,129,0.25)');
  assert.equal(v['--accent-border'], 'rgba(16,185,129,0.4)');
});

test('accentVars switches the text on the accent to dark for a bright colour', () => {
  assert.equal(accentVars('#22d3ee')['--on-accent'], '#06121f');
  assert.equal(accentVars('#3b82f6')['--on-accent'], '#ffffff');
});

test('readDisplayPrefs defaults to off / off / no accent and ignores junk', () => {
  var none = readDisplayPrefs(() => null);
  assert.deepEqual(none, { compact: false, reduce: false, accent: null });
  var store = { audspect_compact: '1', audspect_reduce_motion: '1', audspect_accent: '#A78BFA' };
  assert.deepEqual(readDisplayPrefs((k) => store[k] ?? null), { compact: true, reduce: true, accent: '#a78bfa' });
  var junk = { audspect_compact: 'yes', audspect_accent: 'nope' };
  assert.deepEqual(readDisplayPrefs((k) => junk[k] ?? null), { compact: false, reduce: false, accent: null });
});
