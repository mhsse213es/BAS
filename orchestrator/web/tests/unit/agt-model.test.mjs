import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/agt-model.js';

const ag = (id, host, o = {}) => ({
  agentId: id, hostname: host, ipAddress: o.ip || '10.0.0.1', osVersion: o.os === undefined ? 'Windows 11 23H2' : o.os,
  status: o.status || 'idle', state: o.state || 'active', groupName: o.group, sims: o.sims || 0, lastUpdate: o.seen,
});
const LIST = [
  ag('a1', 'FIN-WS-01', { group: 'Finance', seen: '2026-10-27T10:00:00Z', sims: 4 }),
  ag('a2', 'DC-01', { os: 'Windows Server 2022', group: 'Domain Controllers', seen: '2026-10-27T09:00:00Z' }),
  ag('a3', 'lnx-web-08', { os: 'Ubuntu 22.04', status: 'offline', ip: '10.0.0.8' }),
  ag('a4', 'mac-01', { os: 'macOS 14.6', state: 'restricted', sims: 2, seen: '2026-10-26T10:00:00Z' }),
  ag('a5', 'old-01', { state: 'uninstalled' }),
];

test('bucketOf follows the server rule: retired, offline, degraded, online', () => {
  assert.deepEqual(LIST.map(M.bucketOf), ['online', 'online', 'offline', 'degraded', 'retired']);
  assert.equal(M.bucketOf(null), 'online');
});

test('osFamily folds Linux distributions and never throws', () => {
  assert.equal(M.osFamily('Ubuntu 22.04'), 'Linux');
  assert.equal(M.osFamily('Rocky Linux 9'), 'Linux');
  assert.equal(M.osFamily('Windows Server 2022'), 'Windows Server');
  assert.equal(M.osFamily('Windows 11'), 'Windows');
  assert.equal(M.osFamily('macOS 14.6'), 'macOS');
  assert.equal(M.osFamily('Solaris 11'), 'Solaris');
  assert.equal(M.osFamily(null), 'Unknown');
  assert.deepEqual(M.osOptions(LIST), ['Windows', 'Windows Server', 'Linux', 'macOS']);
});

test('filterRows searches every column plus ip and id; byOs narrows by family', () => {
  assert.deepEqual(M.filterRows(LIST, 'finance').map((a) => a.agentId), ['a1']);
  assert.deepEqual(M.filterRows(LIST, '10.0.0.8').map((a) => a.agentId), ['a3']);
  assert.deepEqual(M.filterRows(LIST, 'a4').map((a) => a.agentId), ['a4']);
  assert.deepEqual(M.filterRows(LIST, 'degraded').map((a) => a.agentId), ['a4']);
  assert.equal(M.filterRows(LIST, '  ').length, 5);
  assert.deepEqual(M.byOs(LIST, 'Linux').map((a) => a.agentId), ['a3']);
  assert.equal(M.byOs(LIST, '').length, 5);
});

test('sortRows is stable and puts empty values last in both directions', () => {
  assert.deepEqual(M.sortRows(LIST, 4, 1).map((a) => a.agentId), ['a4', 'a2', 'a1', 'a3', 'a5']);
  assert.deepEqual(M.sortRows(LIST, 4, -1).map((a) => a.agentId), ['a1', 'a2', 'a4', 'a3', 'a5']);
  assert.deepEqual(M.sortRows(LIST, 5, -1).map((a) => a.agentId), ['a1', 'a4', 'a2', 'a3', 'a5']);
  assert.deepEqual(M.sortRows(LIST, 3, 1).map((a) => a.agentId), ['a1', 'a2', 'a4', 'a3', 'a5']);
  assert.deepEqual(M.sortRows(LIST, -1, 1).map((a) => a.agentId), ['a1', 'a2', 'a3', 'a4', 'a5']);
});

test('csv carries the chosen columns plus ip and id, and neutralises formulas', () => {
  const cols = [0, 3];
  assert.deepEqual(M.csvHeader(cols), ['Host', 'Status', 'IP address', 'Agent ID']);
  assert.deepEqual(M.csvRows([LIST[2]], cols), [['lnx-web-08', 'Offline', '10.0.0.8', 'a3']]);
  assert.match(M.csvText(['H'], [['=cmd']]), /'=cmd/);
});

test('statusSegments uses the fleet totals and drops empty buckets', () => {
  assert.deepEqual(M.statusSegments({ online: 5, degraded: 0, offline: 2, retired: 1 }).map((s) => s.key), ['online', 'offline', 'retired']);
  assert.deepEqual(M.statusSegments(undefined), []);
  assert.equal(M.fleetCount({ online: 5, degraded: 1, offline: 2, retired: 9 }), 8);
});

test('share rows are percentages of the loaded rows; empty input gives no rows', () => {
  const os = M.osShareRows(LIST);
  assert.deepEqual(os[0], ['Windows', 40, 'info', '40%']);
  assert.equal(M.osShareRows([]).length, 0);
  assert.equal(M.groupShareRows(LIST, 2).length, 2);
  assert.equal(M.groupShareRows(LIST, 5).find((r) => r[0] === 'Ungrouped')[1], 60);
});

test('simsRows lists only agents that ran something, busiest first, bar relative to the busiest', () => {
  assert.deepEqual(M.simsRows(LIST), [['FIN-WS-01', 100, 'info', '4'], ['mac-01', 50, 'info', '2']]);
  assert.deepEqual(M.simsRows([]), []);
});

test('opTiles captions come from the totals and stay empty when there is nothing to say', () => {
  const t = M.opTiles({ online: 12, degraded: 0, offline: 2, retired: 0 });
  assert.deepEqual(t.map((x) => x.value), [14, 12, 0, 2]);
  assert.equal(t[1].caption, '86%');
  assert.equal(t[2].caption, '');
  assert.equal(M.opTiles(undefined)[1].caption, '');
});

test('migrationView caps the percentage and never divides by zero', () => {
  assert.equal(M.migrationView({ daysClean: 30, daysRequired: 30, eligible: true }).label, 'ELIGIBLE FOR REVIEW');
  assert.equal(M.migrationView({ daysClean: 40, daysRequired: 30 }).pct, 100);
  const none = M.migrationView(undefined);
  assert.equal(none.pct, 0); assert.equal(none.label, 'NOT YET ELIGIBLE'); assert.equal(none.tone, 'warn');
});

test('footNote only speaks when the server holds more pages', () => {
  assert.equal(M.footNote(100, false, 100), '');
  assert.match(M.footNote(100, true, 420), /100 of 420/);
});

test('drawer facts skip fields the agent does not carry', () => {
  const f = M.facts({ agentId: 'a1', ipAddress: '10.0.0.1', osVersion: '', groupName: null });
  assert.deepEqual(f.map((r) => r[0]), ['Agent ID', 'IP address', 'Group']);
  assert.equal(M.drawerSub({ ipAddress: '10.0.0.1', agentId: 'a1' }), '10.0.0.1 · a1');
});

// ── Tray icon (Windows agents only) ───────────────────────────────────────────────────────────────────────
test('trayEffectiveHidden: an agent override wins over the fleet default; null/undefined follows it', () => {
  assert.equal(M.trayEffectiveHidden({ trayHidden: true }, false), true);
  assert.equal(M.trayEffectiveHidden({ trayHidden: false }, true), false, 'forced visible beats a fleet hide');
  assert.equal(M.trayEffectiveHidden({ trayHidden: null }, true), true);
  assert.equal(M.trayEffectiveHidden({}, true), true);
  assert.equal(M.trayEffectiveHidden({}, undefined), false);
});

test('trayMenuEntries: Windows only; offers the opposite of the effective state, plus fleet default only when overridden', () => {
  const win = (o) => ag('w', 'WS-1', o);
  // Visible, no override: offer Hide only.
  assert.deepEqual(M.trayMenuEntries({ ...win(), trayHidden: null }, false), [{ label: 'Hide tray icon', hidden: true }]);
  // Hidden by the fleet default, no override: offer Show only.
  assert.deepEqual(M.trayMenuEntries({ ...win(), trayHidden: null }, true), [{ label: 'Show tray icon', hidden: false }]);
  // Hidden by its own override: Show, and a way back to following the fleet.
  assert.deepEqual(M.trayMenuEntries({ ...win(), trayHidden: true }, false), [
    { label: 'Show tray icon', hidden: false }, { label: 'Use fleet default for tray icon', hidden: null }]);
  // Forced visible while the fleet hides: Hide, and back to the fleet default.
  assert.deepEqual(M.trayMenuEntries({ ...win(), trayHidden: false }, true), [
    { label: 'Hide tray icon', hidden: true }, { label: 'Use fleet default for tray icon', hidden: null }]);
  assert.ok(M.trayMenuEntries({ ...win({ os: 'Windows Server 2022' }), trayHidden: null }, false).length > 0, 'Windows Server has the tray too');
  // Linux and macOS agents are headless: no tray, so no entry.
  assert.deepEqual(M.trayMenuEntries({ ...win({ os: 'Ubuntu 22.04' }), trayHidden: null }, false), []);
  assert.deepEqual(M.trayMenuEntries({ ...win({ os: 'macOS 14' }), trayHidden: null }, false), []);
  assert.deepEqual(M.trayMenuEntries({ ...win({ os: '' }), trayHidden: null }, false), [], 'unknown OS: do not offer an action that may do nothing');
});

test('fleetTrayLabel: names the action the button performs and the count it affects', () => {
  assert.equal(M.fleetTrayLabel(false), 'Hide tray icon on all agents');
  assert.equal(M.fleetTrayLabel(true), 'Show tray icon on all agents');
  assert.match(M.fleetTrayConfirm(true), /hide/i);
  assert.match(M.fleetTrayConfirm(false), /show/i);
  assert.match(M.fleetTrayConfirm(true), /per-agent/i, 'must say per-agent settings still win');
  assert.doesNotMatch(M.fleetTrayConfirm(true), /\d/, 'no count: the default covers agents that are not loaded on the page');
});
