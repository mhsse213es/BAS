import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/restore-model.js';

// The agent's post-run list mixes what it put back with what it could not ("restore incomplete: ...").
// A console that counts the second kind as "reverted" or shows 100% cleanup would tell the customer the opposite of the truth.

test('splitReverted separates what was put back from what could not be, and strips the machine prefix', () => {
  const s = M.splitReverted([
    'registry value restored: HKCU\Software\Classes\Folder',
    'restore incomplete: health: ".cpl" now opens with "explorer.exe"',
    'service removed: X',
    'restore incomplete: service could not be deleted: Y',
  ]);
  assert.deepEqual(s.reverted, ['registry value restored: HKCU\Software\Classes\Folder', 'service removed: X']);
  assert.deepEqual(s.incomplete, ['health: ".cpl" now opens with "explorer.exe"', 'service could not be deleted: Y']);
});

test('splitReverted tolerates a missing or odd list', () => {
  assert.deepEqual(M.splitReverted(undefined), { reverted: [], incomplete: [] });
  assert.deepEqual(M.splitReverted([null, 7, '']), { reverted: [], incomplete: [] });
});

test('cleanupTile: a clean run is 100% and ok; any incomplete restore is neither', () => {
  assert.deepEqual(M.cleanupTile({ reverted: ['a', 'b'], incomplete: [] }), { pct: 100, tone: 'ok', label: 'every captured change reverted' });
  const t = M.cleanupTile({ reverted: ['a', 'b', 'c'], incomplete: ['x'] });
  assert.equal(t.tone, 'bad');
  assert.equal(t.pct, 75);
  assert.match(t.label, /1 .*not .*restored/i);
  assert.equal(M.cleanupTile({ reverted: [], incomplete: ['x'] }).pct, 0);
});
