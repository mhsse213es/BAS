import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { escapeHTML, x } = await load(['escapeHTML', 'x']);

test('escapes & < > " and nothing else (G1a contract)', () => {
  assert.equal(escapeHTML(`&<>"'`), "&amp;&lt;&gt;&quot;'");
});
test('apostrophe is deliberately left raw', () => {
  assert.equal(escapeHTML("it's"), "it's");
});
test('x is an alias of escapeHTML', () => {
  for (const s of ['a&b', '<i>', '"q"', "o'k"]) assert.equal(x(s), escapeHTML(s));
});
test('null, undefined and numbers keep their current behavior', () => {
  for (const v of [null, undefined, 0, 42]) assert.equal(typeof escapeHTML(v), 'string');
  assert.equal(escapeHTML(42), '42');
});
