import { test } from 'node:test';
import assert from 'node:assert/strict';

const M = await import('../../src/features/var-model.js');

test('a finished run with failed cleanup is never shown as fully complete', () => {
  const c = M.cleanupBanner({ status: 'completed', cleanupStatus: 'FAILED', remediationRequired: true, cleanupError: 'task-b: key left behind' });
  assert.equal(c.tone, 'danger');
  assert.match(c.label, /remediation required/i);
  assert.doesNotMatch(c.label, /^completed$/i);
  assert.equal(c.error, 'task-b: key left behind');
});

test('pending cleanup is shown as pending, not as done', () => {
  const c = M.cleanupBanner({ status: 'running', cleanupStatus: 'PENDING', remediationRequired: false });
  assert.equal(c.tone, 'warning');
  assert.match(c.label, /cleanup pending/i);
});

test('successful cleanup is shown as completed', () => {
  const c = M.cleanupBanner({ status: 'completed', cleanupStatus: 'SUCCEEDED', remediationRequired: false });
  assert.equal(c.tone, 'success');
  assert.match(c.label, /cleanup completed/i);
});

test('no cleanup needed says so', () => {
  assert.match(M.cleanupBanner({ status: 'completed', cleanupStatus: 'NOT_REQUIRED' }).label, /no cleanup needed/i);
});

test('runs recorded before cleanup tracking show an honest unknown, not a success', () => {
  const c = M.cleanupBanner({ status: 'completed', cleanupStatus: '' });
  assert.equal(c.tone, 'muted');
  assert.match(c.label, /not recorded/i);
});

test('cleanup state never changes the attack verdict text', () => {
  const failed = M.cleanupBanner({ status: 'completed', cleanupStatus: 'FAILED', remediationRequired: true });
  assert.equal(Object.prototype.hasOwnProperty.call(failed, 'verdict'), false);
});
