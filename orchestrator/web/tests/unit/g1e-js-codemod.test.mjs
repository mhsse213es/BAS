import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rewrite } from '../../tools/g1e-js-codemod.mjs';

const head = "import { x } from '../core/escape.js';\n";

test('display writes and reads become setDisplay/displayOf with the import added', () => {
  const src = head + "function f(el, on) {\n  el.style.display = '';\n  document.getElementById('a').style.display = 'none';\n  el.style.display = on ? 'flex' : 'none';\n  if (el.style.display !== 'none') g();\n}\n";
  const { code, sites } = rewrite(src, 'features/x.js');
  assert.ok(code.includes("import { displayOf, setDisplay } from '../core/inline-style.js';"));
  assert.ok(code.includes("setDisplay(el, '');"));
  assert.ok(code.includes("setDisplay(document.getElementById('a'), 'none');"));
  assert.ok(code.includes("setDisplay(el, on ? 'flex' : 'none');"));
  assert.ok(code.includes("if (displayOf(el) !== 'none') g();"));
  assert.deepEqual(sites.map((s) => s.kind), ['display-reveal', 'display-hide', 'display-expr', 'display-read']);
  assert.equal(sites[0].line, 3);
});

test('className, cssText and removeAttribute(style) are rewritten', () => {
  const src = head + "a.className = 'x';\nb.style.cssText = 'color:red';\nc.removeAttribute('style');\nd.removeAttribute('title');\n";
  const { code, sites } = rewrite(src, 'features/x.js');
  assert.ok(code.includes("replaceClasses(a, 'x');"));
  assert.ok(code.includes("setCssText(b, 'color:red');"));
  assert.ok(code.includes('clearInlineStyle(c);'));
  assert.ok(code.includes("d.removeAttribute('title');"));
  assert.deepEqual(sites.map((s) => s.kind), ['class-write', 'csstext-write', 'style-remove']);
});

test('a module without matches is returned unchanged, without an import', () => {
  const src = head + "el.style.color = '';\n";
  assert.equal(rewrite(src, 'features/x.js').code, src);
});

test('unsupported forms are refused, never guessed', () => {
  for (const bad of ["el.setAttribute('style', 'x');", "el.setAttribute('class', 'x');", "el.style.setProperty('display', 'none');", "el.style['display'] = 'x';", "el.style.display += 'x';", "el.className += ' x';"]) {
    assert.throws(() => rewrite(head + bad + '\n', 'features/x.js'), /refused/, bad);
  }
});

test('a local name that would shadow the helpers is refused', () => {
  assert.throws(() => rewrite(head + "function setDisplay() {}\nel.style.display = '';\n", 'features/x.js'), /shadow/);
});

test('a display read inside another write right-hand side is rewritten with it (nested sites compose)', () => {
  const src = head + "el.style.display = (m.style.display === 'none') ? 'block' : 'none';\n";
  const { code, sites } = rewrite(src, 'features/x.js');
  assert.ok(code.includes("setDisplay(el, (displayOf(m) === 'none') ? 'block' : 'none');"), code);
  assert.deepEqual(sites.map((s) => s.kind).sort(), ['display-expr', 'display-read']);
});
