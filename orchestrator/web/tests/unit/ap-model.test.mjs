import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/ap-model.js';
import { apFindingItems, apRichBody } from '../../src/features/rich-g4.js';

const EVIL = '<img src=x onerror=alert(1)>';
const S = { attackPathScore: 1, band: 'Critical', lateralMovementBand: 'Critical', avgBlastRadius: 13, maxBlastRadius: 13, maxBlastEntry: 'DC-01', domainCompromiseStatus: 'reachable', hosts: 14, users: 7, groups: 3, edges: 58,
  relationshipCounts: { 'admin-to': 9, 'has-session': 8 }, confidence: { missing: ['Active Directory relationships'] }, scoreDrivers: [{ label: 'Lateral', deficit: 40 }, { label: 'Scope', deficit: 0 }] };

test('freshness: under a day, under a week, older, unknown', () => {
  assert.deepEqual(M.freshness(19 * 36e5), { label: 'Fresh', tone: 'ok' });
  assert.equal(M.freshness(3 * 24 * 36e5).label, 'Aging');
  assert.equal(M.freshness(9 * 24 * 36e5).tone, 'bad');
  assert.equal(M.freshness(null).label, '—');
  assert.equal(M.freshness(-1).label, '—');
});

test('finding rows: icon square per kind, text escaped', () => {
  const items = apFindingItems(S);
  assert.deepEqual(items.map((i) => i.key), ['domain', 'lateral', 'admin', 'ad', 'sessions']);
  const h = M.findingRowsHtml(items);
  assert.equal((h.match(/class="ap-find"/g) || []).length, 5);
  assert.match(h, /ap-ico tone-bad/);
  assert.match(h, /ap-ico tone-info/);
  assert.ok(!M.findingRowsHtml([{ key: 'admin', tone: 'warn', text: EVIL }]).includes('<img'));
});

test('score card: ring, value, caption, toggle with action, drivers hidden until toggled', () => {
  const h = M.scoreCardHtml(S);
  assert.match(h, /Attack path score/);
  assert.match(h, /1 \/ 100/);
  assert.match(h, /Critical risk · higher is safer/);
  assert.match(h, /data-on-click="toggleAPScore"/);
  assert.match(h, /Score breakdown ▼/);
  assert.match(h, /id="ap-score-breakdown" class="ap-bd is-hidden"/);
  assert.match(h, /-40\.0/);
  assert.match(M.scoreCardHtml({}), /No score yet/);
  assert.match(M.scoreCardHtml({ attackPathScore: 5 }), /No score driver detail available/);
});

test('tiles: lateral, domain, scope; honest when undetermined', () => {
  const t = M.tileItems(S);
  assert.deepEqual(t.map((i) => i.label), ['Lateral movement', 'Domain compromise', 'Graph scope']);
  assert.equal(t[0].sub, 'Avg reach 13.0 hosts · max 13 (from DC-01)');
  assert.equal(t[1].value, 'Reachable');
  assert.equal(t[2].value, '14 hosts');
  assert.equal(M.tileItems({ domainCompromiseStatus: 'unknown' })[1].value, 'Undetermined');
  assert.equal(M.tileItems({ domainCompromiseStatus: 'not-observed' })[1].tone, 'ok');
});

test('page body order: side cards before tiles; empty state unchanged', () => {
  const h = apRichBody({ collected: true, summary: S, coverage: {} }, null);
  assert.ok(h.indexOf('ap-side') < h.indexOf('Lateral movement'));
  assert.ok(!h.includes('Findings</h2><span class="rk-hd-sub">'));
  assert.match(apRichBody(null, null), /openAPCollect/);
});
