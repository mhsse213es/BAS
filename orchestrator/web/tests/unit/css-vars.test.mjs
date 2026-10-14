import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { TYPES, cssVars, renderValue, applyCssVars } from '../../src/core/css-vars.js';
import { CSS_VAR_RULES } from '../../src/core/css-var-rules.js';

const RULES = {
  'g1-v-00000001': { prop: 'width', value: '{0}%', types: ['number'] },
  'g1-v-00000002': { prop: 'border', value: '1px solid {0}44', types: ['color'] },
  'g1-v-00000003': { prop: 'grid-template-columns', value: 'repeat({0},1fr)', types: ['integer'] },
};
Object.assign(CSS_VAR_RULES, RULES);
// jsdom has no CSS.supports; this stub accepts what a browser would for these rules.
const supports = (prop, v) => (prop === 'width' ? /^\d+(\.\d+)?%$/.test(v)
  : prop === 'border' ? /^1px solid #([0-9a-f]{3}|[0-9a-f]{6})44$/i.test(v)
  : prop === 'grid-template-columns' ? /^repeat\([1-9]\d*,1fr\)$/.test(v) : false);

function el(html) {
  const dom = new JSDOM(`<body>${html}</body>`);
  return dom.window.document.body.firstElementChild;
}

test('type patterns accept their tokens', () => {
  for (const v of ['#abc', '#aabbcc', '#aabbcc22', 'red', 'transparent', 'var(--danger)', 'rgb(1, 2, 3)', 'rgba(1,2,3,0.5)', 'hsl(120 50% 50% / 50%)']) assert.ok(TYPES.color.test(v), v);
  for (const v of ['0', '12', '-3', '33.5', '.5']) assert.ok(TYPES.number.test(v), v);
  for (const v of ['0', '7', '24', '-1']) assert.ok(TYPES.integer.test(v), v);
});

test('type patterns reject anything outside their character set', () => {
  for (const v of ['red;background:url(x)', 'url(x)', 'expression(alert(1))', 'var(--x) !important', 'var(--x);', '#abc"', 'rgb(1,2,3);x', '"red"', 'red blue', '']) assert.equal(TYPES.color.test(v), false, v);
  for (const v of ['1e3', '12px', 'NaN', '', ' 1']) assert.equal(TYPES.number.test(v), false, v);
  for (const v of ['1.5', '', '1 '] ) assert.equal(TYPES.integer.test(v), false, v);
});

test('renderValue substitutes typed values into the declaration template', () => {
  assert.equal(renderValue('g1-v-00000001', [42]), '42%');
  assert.equal(renderValue('g1-v-00000002', ['#ef4444']), '1px solid #ef444444');
  assert.equal(renderValue('g1-v-00000001', ['42;color:red']), null);
  assert.equal(renderValue('g1-v-00000001', [42, 1]), null);
  assert.equal(renderValue('g1-v-00000001', ['x'.repeat(65)]), null);
  assert.equal(renderValue('g1-v-00000001', [{}]), null);
  assert.equal(renderValue('g1-v-ffffffff', [1]), null);
  assert.equal(renderValue('__proto__', [1]), null);
});

test('cssVars output is one inert attribute that round-trips', () => {
  const attr = cssVars(['g1-v-00000002', '"><img src=x onerror=alert(1)>']);
  const e = el(`<div${attr}></div>`);
  assert.equal(e.attributes.length, 1);
  assert.deepEqual(JSON.parse(e.getAttribute('data-css-vars')), [['g1-v-00000002', '"><img src=x onerror=alert(1)>']]);
});

test('applyCssVars sets the property and adds the class for a valid value', () => {
  const e = el(`<div${cssVars(['g1-v-00000001', 37.5], ['g1-v-00000003', 4])}></div>`);
  applyCssVars(e, supports);
  assert.equal(e.style.getPropertyValue('--g1-v-00000001'), '37.5%');
  assert.equal(e.style.getPropertyValue('--g1-v-00000003'), 'repeat(4,1fr)');
  assert.deepEqual([...e.classList].sort(), ['g1-v-00000001', 'g1-v-00000003']);
});

test('an invalid value is dropped like an invalid inline declaration: no property, no class', () => {
  const e = el(`<div${cssVars(['g1-v-00000003', 0], ['g1-v-00000001', 'undefined'], ['g1-v-00000001', 50])}></div>`);
  const warn = console.warn; const seen = []; console.warn = (m) => seen.push(m);
  try { applyCssVars(e, supports); } finally { console.warn = warn; }
  assert.equal(e.style.getPropertyValue('--g1-v-00000003'), '');
  assert.equal(e.classList.contains('g1-v-00000003'), false);
  assert.equal(e.style.getPropertyValue('--g1-v-00000001'), '50%');
  assert.equal(seen.length, 2);
});

test('unregistered rules, malformed JSON and non-array entries are dropped', () => {
  for (const raw of ['not json', '{"a":1}', '[["g1-v-ffffffff",1]]', '[["constructor",1]]', '[[1,2]]', '[null]']) {
    const e = el('<div></div>');
    e.setAttribute('data-css-vars', raw);
    const warn = console.warn; console.warn = () => {};
    try { applyCssVars(e, supports); } finally { console.warn = warn; }
    assert.equal(e.getAttribute('style'), null, raw);
    assert.equal(e.classList.length, 0, raw);
  }
});
