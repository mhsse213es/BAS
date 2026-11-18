import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const C = await import('../../src/features/exfil-chain.js');

test('isExfilChainRun matches every DLP chain scenario and nothing else', () => {
  assert.equal(C.isExfilChainRun('collection-staging-exfil'), true);
  assert.equal(C.isExfilChainRun('collection-email-mailbox-exfil'), true);
  assert.equal(C.isExfilChainRun('collection-browser-cloud-email-discovery'), true);
  assert.equal(C.isExfilChainRun('collection-large-volume-transfer'), true);
  assert.equal(C.isExfilChainRun('collection-multidir-automated-exfil'), true);
  assert.equal(C.isExfilChainRun('akira-kill-chain'), false);
  assert.equal(C.isExfilChainRun(undefined), false);
});

test('model is ok when linked, complete and no findings', () => {
  const m = C.exfilChainModel({ summary: 's', linked: true, missing: [], findings: [], stages: [] });
  assert.equal(m.tone, 'ok');
});

test('model is warn when linked with missing phases', () => {
  const m = C.exfilChainModel({ summary: 's', linked: true, missing: ['staging'], findings: [], stages: [] });
  assert.equal(m.tone, 'warn');
  assert.deepEqual(m.missing, ['Staging']);
});

test('model is bad when not linked', () => {
  const m = C.exfilChainModel({ summary: 's', linked: false, missing: [], findings: ['no run tag'], stages: [] });
  assert.equal(m.tone, 'bad');
});

test('stage results map to tones and phase labels', () => {
  const m = C.exfilChainModel({ linked: true, missing: [], findings: [], stages: [
    { order: 1, phase: 'collection', techniqueId: 'T1005', stepName: 'a', result: 'fail' },
    { order: 2, phase: 'transfer', techniqueId: 'T1048.003', stepName: 'b', result: 'pass' },
    { order: 3, phase: 'archive', techniqueId: 'T1560.001', stepName: 'c', result: 'skip' },
  ] });
  assert.deepEqual(m.stages.map(s => s.tone), ['bad', 'ok', 'muted']);
  assert.deepEqual(m.stages.map(s => s.phase), ['Collection', 'Transfer', 'Archive']);
});

test('panel states that linked is not SIEM correlation', () => {
  const html = C.exfilChainHTML(C.exfilChainModel({ summary: 's', linked: true, missing: [], findings: [], stages: [] }));
  assert.ok(html.includes('does not show that the SIEM correlated them'));
});

test('step names and findings from the run are escaped', () => {
  const html = C.exfilChainHTML(C.exfilChainModel({ summary: 's', linked: false, missing: [], findings: ['<img src=x onerror=alert(1)>'], stages: [
    { order: 1, phase: 'collection', techniqueId: 'T1', stepName: '<script>bad()</script>', result: 'pass' },
  ] }));
  assert.ok(!html.includes('<script>bad'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('no stages shows a plain message', () => {
  const html = C.exfilChainHTML(C.exfilChainModel({ summary: 's', linked: false, missing: [], findings: [], stages: [] }));
  assert.ok(html.includes('No stage results for this run.'));
});
