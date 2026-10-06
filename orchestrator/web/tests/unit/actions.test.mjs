import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { EVENT_TYPES, on, dispatch, installActions, stopEvent } from '../../src/core/actions.js';

// A fresh document per test so listeners never accumulate.
function fresh(html = '') {
  const dom = new JSDOM(`<!DOCTYPE html><body>${html}</body>`, { url: 'http://127.0.0.1/' });
  return dom.window;
}
function withConsoleErrors(fn) {
  const seen = []; const orig = console.error;
  console.error = (...a) => seen.push(a.join(' '));
  try { fn(); } finally { console.error = orig; }
  return seen;
}

test('on() emits a data-on attribute and JSON args', () => {
  assert.equal(on('click', 'openRun', 'abc', 3), ' data-on-click="openRun" data-args="[&quot;abc&quot;,3]"');
  assert.equal(on('change', 'reload'), ' data-on-change="reload"');
});

test('on() rejects event types the dispatcher does not listen for', () => {
  assert.throws(() => on('dblclick', 'f'), /unsupported event "dblclick"/);
});

test('on() round-trips hostile arguments as inert data', () => {
  const payloads = ['"><img src=x onerror="globalThis.__xss=1">', "'); alert(1); ('", '</script><script>globalThis.__xss=1</script>', '&amp; & é 🔥', '', 'x'.repeat(5000)];
  const w = fresh();
  for (const p of payloads) {
    const div = w.document.createElement('div');
    div.innerHTML = `<b${on('click', 'f', p, 1, true, null)}>t</b>`;
    const b = div.querySelector('b');
    assert.equal(div.querySelectorAll('*').length, 1, 'payload created an element');
    assert.deepEqual([...b.attributes].map((a) => a.name).sort(), ['data-args', 'data-on-click']);
    assert.deepEqual(JSON.parse(b.getAttribute('data-args')), [p, 1, true, null]);
  }
  assert.equal(globalThis.__xss, undefined);
});

test('click on a child dispatches the nearest action with args, this, el and event', () => {
  const w = fresh('<div id="row" data-on-click="openRun" data-args="[&quot;r1&quot;,2]"><span id="s">x</span></div>');
  const calls = [];
  installActions({ openRun(a, b, el, ev) { calls.push([a, b, this.id, el.id, ev.type]); } }, w.document);
  w.document.getElementById('s').click();
  assert.deepEqual(calls, [['r1', 2, 'row', 'row', 'click']]);
});

test('without stopPropagation both nested actions run, inner first', () => {
  const w = fresh('<div data-on-click="outer"><button id="b" data-on-click="inner">x</button></div>');
  const calls = [];
  installActions({ outer() { calls.push('outer'); }, inner() { calls.push('inner'); } }, w.document);
  w.document.getElementById('b').click();
  assert.deepEqual(calls, ['inner', 'outer']);
});

test('stopPropagation in an action ends the ancestor walk', () => {
  const w = fresh('<div data-on-click="outer"><button id="b" data-on-click="stopEvent">x</button></div>');
  const calls = [];
  installActions({ outer() { calls.push('outer'); }, stopEvent }, w.document);
  w.document.getElementById('b').click();
  assert.deepEqual(calls, []);
});

test('unknown and prototype names are never dispatched and never fall back to window', () => {
  for (const name of ['nope', 'constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    const w = fresh(`<button id="b" data-on-click="${name}">x</button>`);
    w.nope = () => { throw new Error('window fallback used'); };
    installActions({}, w.document);
    const errs = withConsoleErrors(() => w.document.getElementById('b').click());
    assert.equal(errs.length, 1, `${name}: expected one console.error`);
    assert.match(errs[0], /not registered/);
  }
});

test('malformed data-args is logged and the action is not called', () => {
  for (const raw of ['{"a":1}', 'not json', '"str"']) {
    const w = fresh(`<button id="b" data-on-click="f" data-args='${raw}'>x</button>`);
    let called = false;
    installActions({ f() { called = true; } }, w.document);
    const errs = withConsoleErrors(() => w.document.getElementById('b').click());
    assert.equal(called, false);
    assert.match(errs[0], /data-args is not a JSON array/);
  }
});

test('an action on <a href="#"> prevents the navigation', () => {
  const w = fresh('<a id="a" href="#" data-on-click="f">x</a>');
  installActions({ f() {} }, w.document);
  const ev = new w.MouseEvent('click', { bubbles: true, cancelable: true });
  w.document.getElementById('a').dispatchEvent(ev);
  assert.equal(ev.defaultPrevented, true);
});

test('disabled form controls are not dispatched', () => {
  const w = fresh('<button id="b" disabled data-on-click="f"><span id="s">x</span></button>');
  let called = false;
  installActions({ f() { called = true; } }, w.document);
  w.document.getElementById('s').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.equal(called, false);
});

test('non-bubbling events act on the target only', () => {
  const w = fresh('<div data-on-blur="outer"><input id="i" data-on-blur="inner"></div>');
  const calls = [];
  installActions({ outer() { calls.push('outer'); }, inner() { calls.push('inner'); } }, w.document);
  w.document.getElementById('i').dispatchEvent(new w.FocusEvent('blur', { bubbles: false }));
  assert.deepEqual(calls, ['inner']);
});

test('change and input pass the element so handlers can read value/checked', () => {
  const w = fresh('<input id="i" type="checkbox" data-on-change="toggle" data-args="[7]">');
  const seen = [];
  installActions({ toggle(id) { seen.push([id, this.checked]); } }, w.document);
  const i = w.document.getElementById('i');
  i.checked = true;
  i.dispatchEvent(new w.Event('change', { bubbles: true }));
  assert.deepEqual(seen, [[7, true]]);
});

test('EVENT_TYPES covers every event used by the dashboard today', () => {
  for (const t of ['click', 'change', 'input', 'keydown', 'blur', 'mouseover', 'mouseout', 'mouseenter', 'mouseleave', 'mousedown']) {
    assert.ok(EVENT_TYPES.includes(t), t);
  }
  assert.equal(typeof dispatch, 'function');
});
