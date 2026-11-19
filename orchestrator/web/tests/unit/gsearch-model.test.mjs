import test from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/gsearch-model.js';
import { filterCards, providerCounts } from '../../src/features/cloud-model.js';

const items = [
  ...M.pageItems([{ tab: 'agents', title: 'Agents', group: 'Operations' }, { tab: 'scenarios', title: 'Scenarios', group: 'Operations' }]),
  ...M.agentItems([{ agentId: 'a-1', hostname: 'DESKTOP-1C8MGV5', osVersion: 'Windows 11', status: 'online', ipAddress: '10.0.0.4' }]),
  ...M.scenarioItems([{ id: 'akira', name: 'Akira Kill Chain', description: 'Ransomware emulation', steps: [{ techniqueId: 'T1486' }] }]),
  ...M.cloudItems([{ id: 'aws-backup', name: 'AWS Backup: destroy recovery points', provider: 'aws', providerLabel: 'AWS', description: 'Can an identity delete backups?' }]),
  ...M.reportItems([{ id: 'r1', reportType: 'posture', agentId: 'a-1', format: 'pdf', generatedBy: 'admin', generatedAt: '2026-11-10T10:00:00Z' }], { 'a-1': 'DESKTOP-1C8MGV5' }),
];

test('a title match outranks a description match', () => {
  const a = M.scoreItem({ title: 'Backup vault', sub: '' }, 'backup');
  const b = M.scoreItem({ title: 'Other', sub: 'about backup' }, 'backup');
  assert.ok(a > b && b > 0);
});
test('every word must match; operators like type:x are not text', () => {
  assert.equal(M.scoreItem({ title: 'Akira Kill Chain' }, 'akira zzz'), 0);
  assert.ok(M.scoreItem({ title: 'Akira Kill Chain' }, 'type:scenario akira') > 0);
});
test('search groups by scope and finds an agent by hostname fragment and a technique by id', () => {
  const r = M.search(items, 'desktop');
  assert.deepEqual(r.sections.map((s) => s.scope), ['agent', 'report']);
  const t = M.search(items, 't1486');
  assert.equal(t.sections[0].items[0].sourceId, 'akira');
});
test('a scope narrows to one section and keeps counts for all', () => {
  const r = M.search(items, 'a', { scope: 'agent' });
  assert.deepEqual(r.sections.map((s) => s.scope), ['agent']);
  assert.ok(r.counts.scenario >= 1);
});
test('cloud scenarios are searchable under Scenarios', () => {
  const r = M.search(items, 'backup', { scope: 'scenario' });
  assert.equal(r.sections[0].items[0].kind, 'cloud');
});
test('phishing scenarios from the library are searchable, under Scenarios, and non-phishing entries are ignored', () => {
  const ph = M.phishingItems([{ type: 'phishing', id: 'PH-ID-001', name: 'Credential harvest lure', status: 'available' }, { type: 'phishing', id: 'PH-X', name: 'Old', status: 'unavailable' }, { type: 'attack', id: 'nope', name: 'Credential other' }]);
  assert.equal(ph.length, 2);
  const r = M.search(ph, 'credential', { scope: 'scenario' });
  assert.deepEqual(r.sections[0].items.map((i) => i.phishId), ['PH-ID-001']);
  assert.equal(M.search(ph, 'phishing').sections[0].items.length, 2, 'the word phishing finds them');
  assert.match(ph[1].sub, /Unavailable/);
});
test('a server result replaces the local copy of the same scenario', () => {
  const server = M.resultItems([{ docType: 'scenario', sourceId: 'akira', title: 'Akira Kill Chain', description: '', favorited: true }]);
  const r = M.search(items.concat(server), 'akira', { scope: 'scenario' });
  assert.equal(r.sections[0].items.length, 1);
  assert.equal(r.sections[0].items[0].kind, 'result');
});
test('highlight escapes first and marks matches', () => {
  assert.equal(M.highlight('<b>Akira</b> chain', 'akira'), '&lt;b&gt;<mark>Akira</mark>&lt;/b&gt; chain');
  assert.equal(M.highlight('a.b', 'a.b'), '<mark>a.b</mark>');
  assert.equal(M.highlight('x', ''), 'x');
});
test('section overflow is reported, and nextScope cycles', () => {
  const many = Array.from({ length: 9 }, (_, i) => ({ id: 'p' + i, kind: 'page', scope: 'pages', tab: 't' + i, title: 'Page ' + i }));
  const r = M.search(many, 'page');
  assert.equal(r.sections[0].items.length, 5);
  assert.equal(r.sections[0].more, 4);
  assert.equal(M.nextScope('all', 1, null), 'pages');
  assert.equal(M.nextScope('all', -1, null), 'other');
  assert.equal(M.nextScope('all', 1, ['agent']), 'agent');
});
test('cloud filter by provider and words; counts', () => {
  const cards = [{ id: '1', name: 'S3 data access', provider: 'aws', providerLabel: 'AWS', description: 'bucket' }, { id: '2', name: 'Storage keys', provider: 'azure', providerLabel: 'Azure', description: 'blobs' }];
  assert.deepEqual(filterCards(cards, 'azure', '').map((c) => c.id), ['2']);
  assert.deepEqual(filterCards(cards, 'all', 'bucket s3').map((c) => c.id), ['1']);
  assert.deepEqual(providerCounts(cards), { all: 2, aws: 1, azure: 1, gcp: 0 });
});
