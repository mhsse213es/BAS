import test from 'node:test';
import assert from 'node:assert/strict';
import { checkRecoveryForm } from '../../src/features/recovery-model.js';

const ok = { username: 'admin@corp.test', passphrase: 'Ab3dEf6hIj9LmN', next: 'brand-new-pass-1', again: 'brand-new-pass-1' };

test('a complete, matching form passes and is trimmed only where it should be', () => {
  assert.equal(checkRecoveryForm({ ...ok, username: '  admin@corp.test  ' }), null);
});

test('every field is required', () => {
  assert.match(checkRecoveryForm({ ...ok, username: '' }), /username/i);
  assert.match(checkRecoveryForm({ ...ok, passphrase: '' }), /passphrase/i);
  assert.match(checkRecoveryForm({ ...ok, next: '', again: '' }), /password/i);
});

test('the passphrase must be exactly 14 letters and digits before anything is sent', () => {
  for (const bad of ['Ab3dEf6hIj9Lm', 'Ab3dEf6hIj9LmNp', 'Ab3dEf6hIj9Lm-', 'Ab3dEf6hIj 9LmN']) {
    assert.match(checkRecoveryForm({ ...ok, passphrase: bad }), /14 letters and digits/, bad);
  }
});

test('the new password needs 10 characters and must be repeated identically', () => {
  assert.match(checkRecoveryForm({ ...ok, next: 'short', again: 'short' }), /10 characters/);
  assert.match(checkRecoveryForm({ ...ok, again: 'different-pass-9' }), /do not match/i);
});

test('the passphrase is not trimmed: a stray space is an error, not silently dropped', () => {
  assert.match(checkRecoveryForm({ ...ok, passphrase: ' Ab3dEf6hIj9LmN' }), /14 letters and digits/);
});
