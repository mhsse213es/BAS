import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { canApproveForLocal, approveForLocalUse } = await load(['canApproveForLocal', 'approveForLocalUse']);
const tick = () => new Promise((r) => setTimeout(r, 0));

const sc = (registry, source = 'intel') => ({ id: 'intel-a', source, registry });

test('canApproveForLocal: unapproved DRAFT and newer DRAFT over an approved version', () => {
  assert.equal(canApproveForLocal(sc({ executableVersion: 0, latestVersion: 1, latestLifecycle: 'DRAFT' }), 'admin'), true);
  // Re-review M-c: an approved intel id must be able to approve its new v3 DRAFT.
  assert.equal(canApproveForLocal(sc({ executableVersion: 2, latestVersion: 3, latestLifecycle: 'DRAFT' }), 'admin'), true);
  assert.equal(canApproveForLocal(sc({ executableVersion: 2, latestVersion: 3, latestLifecycle: 'VALIDATED' }, 'custom'), 'admin'), true);
});

test('canApproveForLocal: refuses when nothing newer, wrong role, wrong source or lifecycle', () => {
  assert.equal(canApproveForLocal(sc({ executableVersion: 3, latestVersion: 3, latestLifecycle: 'PUBLISHED_LOCAL' }), 'admin'), false);
  assert.equal(canApproveForLocal(sc({ executableVersion: 0, latestVersion: 1, latestLifecycle: 'DRAFT' }), 'operator'), false);
  assert.equal(canApproveForLocal(sc({ executableVersion: 0, latestVersion: 1, latestLifecycle: 'DRAFT' }, 'builtin'), 'admin'), false);
  assert.equal(canApproveForLocal(sc({ executableVersion: 2, latestVersion: 3, latestLifecycle: 'RETIRED' }), 'admin'), false);
  assert.equal(canApproveForLocal(sc(null), 'admin'), false);
});

// Re-review M-d: a slow response for an earlier click must not overwrite
// the confirmation for a later one.
test('approveForLocalUse ignores stale version responses', async () => {
  const pending = {};
  globalThis.fetch = (url) => new Promise((resolve) => { pending[url] = resolve; });
  const detail = (id, cid) => ({ status: 200, json: async () => ({ id, contentId: cid, version: 1, lifecycle: 'DRAFT', trust: 'UNTRUSTED',
    intakeSource: 'intel', stepCount: 0, artTechniques: ['T1082'], safetyVerdicts: [], artifactSha256: 'ab' }) });
  approveForLocalUse('intel-old', 'v-old');
  approveForLocalUse('intel-new', 'v-new');
  pending['/api/content-registry/versions/v-new'](detail('v-new', 'intel-new'));
  await tick(); await tick();
  pending['/api/content-registry/versions/v-old'](detail('v-old', 'intel-old'));
  await tick(); await tick();
  const body = document.getElementById('approve-local-body').textContent;
  assert.ok(body.includes('intel-new'), 'latest request must be shown');
  assert.ok(!body.includes('intel-old'), 'stale response must be ignored');
});
