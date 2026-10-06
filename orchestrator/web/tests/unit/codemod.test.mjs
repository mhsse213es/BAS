import { test } from 'node:test';
import assert from 'node:assert/strict';
import { convertHandler, convertHtml } from '../../tools/g1d-codemod.mjs';
import { on } from '../../src/core/actions.js';

test('single call with literal args becomes the same text on() produces', () => {
  assert.equal(convertHandler('click', "showTab('agents')"), on('click', 'showTab', 'agents'));
  assert.equal(convertHandler('change', "setThing('a', 3, -1.5, true, null)"), on('change', 'setThing', 'a', 3, -1.5, true, null));
  assert.equal(convertHandler('click', 'closeModal()'), on('click', 'closeModal'));
  assert.equal(convertHandler('click', 'closeModal();'), on('click', 'closeModal'));
});

test('escaped quotes inside a JS string survive', () => {
  assert.equal(convertHandler('click', "say('it\\'s')"), on('click', 'say', "it's"));
});

test('anything that is not a single call with literal args is left alone', () => {
  for (const body of ['setPF(this.value)', 'event.stopPropagation()', "a(); b()", "x = 1", 'f(g())', 'f(someVar)', "f('a' + b)", 'obj.method()']) {
    assert.equal(convertHandler('click', body), null, body);
  }
});

test('unsupported event types are left alone', () => {
  assert.equal(convertHandler('dblclick', 'f()'), null);
});

test('convertHtml decodes attribute entities, rewrites and reports skips with line numbers', () => {
  const src = '<a onclick="showTab(&#39;x&#39;)">a</a>\n<b onclick="setPF(this.value)">b</b>\n<i data-on-click="kept"></i>';
  const out = convertHtml(src);
  assert.equal(out.converted, 1);
  assert.equal(out.html.split('\n')[0], `<a${on('click', 'showTab', 'x')}>a</a>`);
  assert.deepEqual(out.skipped, [{ line: 2, attr: 'onclick="setPF(this.value)"' }]);
  assert.equal(out.html.split('\n').length, 3);
});
