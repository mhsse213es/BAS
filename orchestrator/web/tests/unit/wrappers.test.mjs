// Dispatch-target wrappers (G1d Task 7 review). core/actions.js calls
// fn.apply(el, [...args, el, event]) with the DELEGATED event, whose
// currentTarget is the document, not the element carrying the attribute.
// These tests call each event/element-using action exactly that way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['toggleRowMenuById', 'openComplianceDetail']);
const tick = () => new Promise((r) => setTimeout(r, 0));

function delegatedEvent(extra = {}) {
  return {
    currentTarget: document, // what a delegated listener sees
    target: extra.target || document.body,
    key: extra.key,
    cancelBubble: false,
    defaultPrevented: false,
    stopPropagation() { this.cancelBubble = true; },
    preventDefault() { this.defaultPrevented = true; },
  };
}

// dispatch(): fn.apply(el, [...args, el, event])
function dispatchTo(fn, el, args, event) { return fn.apply(el, [...args, el, event]); }

function stubButton(rect) {
  const el = document.createElement('button');
  el.getBoundingClientRect = () => ({ top: rect.top, bottom: rect.bottom, left: 0, right: rect.right, width: 10, height: 10 });
  document.body.appendChild(el);
  return el;
}

const table = [
  {
    name: 'toggleRowMenuById positions the panel from the button element and stops propagation',
    run() {
      const panel = document.createElement('div');
      panel.id = 'row-menu-t1';
      document.body.appendChild(panel);
      const btn = stubButton({ top: 100, bottom: 120, right: 300 });
      const ev = delegatedEvent();
      dispatchTo(fns.toggleRowMenuById, btn, ['row-menu-t1'], ev);
      assert.ok(panel.classList.contains('open'), 'menu opened');
      assert.equal(panel.style.top, '124px');
      assert.equal(ev.cancelBubble, true, 'propagation stopped');
    },
  },
];

for (const row of table) test(row.name, row.run);

test('openComplianceDetail selects the framework only after the options have loaded', async () => {
  const urls = [];
  globalThis.fetch = async (url) => {
    urls.push(String(url));
    const body = String(url).includes('/api/compliance/frameworks') ? [{ id: 'fw-1', name: 'NIST', version: '1' }] : {};
    return { status: 200, json: async () => body };
  };
  fns.openComplianceDetail('fw-1', '');
  for (let i = 0; i < 6; i++) await tick();
  assert.equal(document.getElementById('cmp-fw-sel').value, 'fw-1');
  assert.ok(urls.some((u) => u.includes('/api/compliance/frameworks')), 'frameworks fetched');
});
