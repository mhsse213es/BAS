import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { GENERATED, displayOf, setDisplay, replaceClasses, setCssText, clearInlineStyle } from '../../src/core/inline-style.js';

const doc = new JSDOM('<body></body>').window.document;
const make = (html) => { const d = doc.createElement('div'); d.innerHTML = html; return d.firstElementChild; };
// Effective display as CSS would compute it from inline + generated classes
// (generated rules outrank everything but inline).
const effective = (el) => el.style.display || (el.classList.contains('is-hidden') ? 'none'
  : ([...el.classList].find((c) => c.startsWith('g1-display-')) || '').slice(11)) || 'default';
const oldEffective = (el) => el.style.display || 'default';

const STARTS = [
  ['<p style="display:none"></p>', '<p class="is-hidden"></p>'],
  ['<p style="display:flex"></p>', '<p class="g1-display-flex"></p>'],
  ['<p style="display:inline-block;color:red"></p>', '<p class="g1-display-inline-block g1-s-0000000a"></p>'],
  ['<p></p>', '<p></p>'],
];
const VALUES = ['', 'none', 'flex', 'block', null];

function* sequences(n) {
  if (n === 0) { yield []; return; }
  for (const s of sequences(n - 1)) for (const v of VALUES) yield [...s, v];
}

test('setDisplay/displayOf reproduce inline display for every write sequence up to length 4', () => {
  for (const [oldHtml, newHtml] of STARTS) {
    for (const seq of sequences(4)) {
      const o = make(oldHtml); const n = make(newHtml);
      assert.equal(displayOf(n), o.style.display, `${newHtml} initial`);
      for (const v of seq) {
        o.style.display = v; setDisplay(n, v);
        assert.equal(displayOf(n), o.style.display, `${newHtml} after ${JSON.stringify(seq)}`);
        assert.equal(effective(n), oldEffective(o), `${newHtml} effective after ${JSON.stringify(seq)}`);
      }
    }
  }
});

test('setDisplay returns its value (usable in expressions)', () => {
  assert.equal(setDisplay(make('<p></p>'), 'none'), 'none');
});

test('replaceClasses keeps generated classes, as inline styles survived className writes', () => {
  const n = make('<p class="a is-hidden g1-s-0000000a g1-v-0000000b g1-display-flex"></p>');
  replaceClasses(n, 'b c');
  assert.deepEqual([...n.classList].sort(), ['b', 'c', 'g1-display-flex', 'g1-s-0000000a', 'g1-v-0000000b', 'is-hidden']);
  assert.equal(replaceClasses(n, 'd'), 'd');
});

test('setCssText and clearInlineStyle drop generated classes, as the inline style was replaced', () => {
  const a = make('<p class="keep is-hidden g1-s-0000000a g1-v-0000000b"></p>');
  setCssText(a, 'color: red');
  assert.deepEqual([...a.classList], ['keep']);
  assert.equal(a.style.color, 'red');
  const b = make('<p class="keep g1-display-flex"></p>');
  b.style.setProperty('--g1-v-0000000b', '5%');
  clearInlineStyle(b);
  assert.deepEqual([...b.classList], ['keep']);
  assert.equal(b.getAttribute('style'), null);
});

test('GENERATED matches only generated class names', () => {
  for (const c of ['is-hidden', 'g1-display-inline-flex', 'g1-s-0123abcd', 'g1-v-0123abcd']) assert.ok(GENERATED.test(c), c);
  for (const c of ['hidden', 'g1-s-0123abc', 'g1-x-0123abcd', 'is-hidden2', 'g1-display-']) assert.equal(GENERATED.test(c), false, c);
});
