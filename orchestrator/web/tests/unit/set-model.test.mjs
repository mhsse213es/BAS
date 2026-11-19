import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/set-model.js';

const U = [
  { id: '1', username: 'zed', role: 'viewer', isActive: false, createdAt: '2026-10-01T09:00:00Z', lastLogin: '' },
  { id: '2', username: 'admin', role: 'admin', isActive: true, createdAt: '2026-09-01T09:00:00Z', lastLogin: '2026-10-25T08:12:00Z' },
  { id: '3', username: 'ana', role: 'analyst', isActive: true, createdAt: '2026-09-15T09:00:00Z', lastLogin: '2026-10-20T08:12:00Z' },
];

test('table mode switches at 8 rows', () => {
  assert.equal(M.isFull(7), false);
  assert.equal(M.isFull(8), true);
});

test('rail follows the demo order and casing', () => {
  assert.deepEqual(M.NAV.map((n) => n[1]), ['Users & roles', 'Caldera Engine', 'Threat Intel Connector', 'TAXII Connectors', 'ART Content Library', 'Audit Logs', 'Theme & Display', 'Dashboard Preferences', 'License', 'Backup & Recovery']);
});

test('role labels and tones', () => {
  assert.equal(M.roleLabel('admin'), 'Admin');
  assert.equal(M.roleLabel('weird'), 'weird');
  assert.equal(M.roleTone('admin'), 'violet');
  assert.equal(M.roleTone('analyst'), 'info');
  assert.equal(M.roleTone('viewer'), 'muted');
});

test('cell text, stamp and status', () => {
  assert.equal(M.stamp('2026-10-25T08:12:00Z'), '2026-10-25 08:12');
  assert.equal(M.cellText(U[1], 4), '2026-10-25 08:12');
  assert.equal(M.cellText(U[0], 4), 'Never');
  assert.equal(M.cellText(U[0], 2), 'Disabled');
  assert.equal(M.cellText(U[1], 1), 'Admin');
});

test('filter matches any column', () => {
  assert.equal(M.filterUsers(U, 'analyst').length, 1);
  assert.equal(M.filterUsers(U, 'disabled')[0].username, 'zed');
  assert.equal(M.filterUsers(U, '  ').length, 3);
});

test('sort is stable, reversible and puts never-signed-in last', () => {
  assert.deepEqual(M.sortUsers(U, 0, 1).map((u) => u.username), ['admin', 'ana', 'zed']);
  assert.deepEqual(M.sortUsers(U, 0, -1).map((u) => u.username), ['zed', 'ana', 'admin']);
  assert.equal(M.sortUsers(U, 4, 1).at(-1).username, 'zed');
  assert.equal(M.sortUsers(U, 4, -1).at(-1).username, 'zed');
  assert.deepEqual(M.sortUsers(U, -1, 1), U);
});

test('csv and counts', () => {
  assert.deepEqual(M.csvRow(U[1], [0, 1]), ['admin', 'Admin']);
  assert.equal(M.rangeCounts(2, 3), '2 of 3 rows');
  assert.equal(M.csvText(['A'], [['=x']]).split('\n')[1], `"'=x"`);
});
