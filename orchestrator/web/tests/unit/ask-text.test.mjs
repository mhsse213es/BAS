import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['askText', 'askEnter', 'runConfirmDiffModal', 'closeConfirmDiffModal']);
const input = () => document.getElementById('ask-input');
const open = () => document.getElementById('confirm-diff-overlay').classList.contains('open');

test('askText opens the in-page dialog with the label and the current value', () => {
  fns.askText('Rename group', 'Group name', 'Lab', 'Rename', () => {});
  assert.equal(open(), true);
  assert.equal(input().value, 'Lab');
  assert.equal(document.getElementById('confirm-diff-title').textContent, 'Rename group');
  assert.equal(document.getElementById('confirm-diff-submit-btn').textContent, 'Rename');
});

test('an empty answer keeps the dialog open with a message and never calls back', () => {
  let called = 0;
  fns.askText('New group', 'Group name', '', 'Create', () => { called++; });
  input().value = '   ';
  fns.runConfirmDiffModal();
  assert.equal(called, 0);
  assert.equal(open(), true);
  assert.match(document.getElementById('ask-err').textContent, /Enter a value/);
  assert.equal(document.getElementById('ask-err').hidden, false);
});

test('a value is trimmed and passed to the callback, and the dialog closes', () => {
  let got = null;
  fns.askText('New group', 'Group name', '', 'Create', (v) => { got = v; });
  input().value = '  Web tier ';
  fns.runConfirmDiffModal();
  assert.equal(got, 'Web tier');
  assert.equal(open(), false);
});

test('allowEmpty lets an empty answer through (used to clear the minimum version)', () => {
  let got = 'unset';
  fns.askText('Minimum agent version', 'Version', '1.9.0', 'Save', (v) => { got = v; }, { allowEmpty: true });
  input().value = '';
  fns.runConfirmDiffModal();
  assert.equal(got, '');
});

test('the initial value is escaped, not injected as markup', () => {
  fns.askText('Rename', 'Name', '"><img src=x onerror=alert(1)>', 'Rename', () => {});
  assert.equal(document.querySelector('#confirm-diff-body img'), null);
  assert.equal(input().value, '"><img src=x onerror=alert(1)>');
  fns.closeConfirmDiffModal();
});

test('Enter submits, but not while an IME is composing', () => {
  let called = 0;
  fns.askText('New group', 'Group name', 'x', 'Create', () => { called++; });
  fns.askEnter(input(), { key: 'Enter', isComposing: true, preventDefault() {} });
  assert.equal(called, 0);
  fns.askEnter(input(), { key: 'Enter', isComposing: false, preventDefault() {} });
  assert.equal(called, 1);
});
