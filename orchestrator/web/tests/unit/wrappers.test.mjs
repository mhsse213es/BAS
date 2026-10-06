// Dispatch-target wrappers (G1d Task 7 review). core/actions.js calls
// fn.apply(el, [...args, el, event]) with the DELEGATED event, whose
// currentTarget is the document, not the element carrying the attribute.
// These tests call each event/element-using action exactly that way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['toggleRowMenuById']);

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
