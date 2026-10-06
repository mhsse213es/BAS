// Dispatch-target wrappers (G1d Task 7 review). core/actions.js calls
// fn.apply(el, [...args, el, event]) with the DELEGATED event, whose
// currentTarget is the document, not the element carrying the attribute.
// These tests call each event/element-using action exactly that way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['toggleRowMenuById', 'openComplianceDetail', 'tmplGroupChange', 'runGroupChange', 'vexSweepGroupChange', 'vexRunGroupChange', 'openAgentGroupMenuStop', 'toggleScenarioPinFromEvent', 'scenarioPinKeydown', 'techKeydown', 'abortExecutionStop']);
const { state } = await import('../../src/core/state.js');
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
  {
    name: 'openAgentGroupMenuStop stops propagation before opening the group prompt',
    run() {
      globalThis.prompt = () => null;
      const span = document.createElement('span');
      const ev = delegatedEvent();
      dispatchTo(fns.openAgentGroupMenuStop, span, [3], ev);
      assert.equal(ev.cancelBubble, true);
    },
  },
  {
    name: 'toggleScenarioPinFromEvent pins the tile id and stops propagation',
    run() {
      state.overlayPinned = null;
      const tile = document.createElement('div');
      const ev = delegatedEvent({ target: tile });
      dispatchTo(fns.toggleScenarioPinFromEvent, tile, ['sc-1'], ev);
      assert.equal(ev.cancelBubble, true);
      assert.equal(state.overlayPinned, 'sc-1');
      state.overlayPinned = null;
    },
  },
  {
    name: 'scenarioPinKeydown acts on Enter and Space only',
    run() {
      state.overlayPinned = null;
      const tile = document.createElement('div');
      const other = delegatedEvent({ target: tile, key: 'a' });
      dispatchTo(fns.scenarioPinKeydown, tile, ['sc-2'], other);
      assert.equal(other.defaultPrevented, false);
      assert.equal(state.overlayPinned, null);
      const enter = delegatedEvent({ target: tile, key: 'Enter' });
      dispatchTo(fns.scenarioPinKeydown, tile, ['sc-2'], enter);
      assert.equal(enter.defaultPrevented, true);
      assert.equal(state.overlayPinned, 'sc-2');
      state.overlayPinned = null;
    },
  },
  {
    name: 'techKeydown forwards (event, input): ArrowDown activates a row, Escape closes the panel',
    run() {
      const wrap = document.createElement('div');
      wrap.className = 'st-tech-wrap';
      wrap.innerHTML = '<input><div class="st-tech-panel show"><div class="st-tech-row" data-id="T1"></div><div class="st-tech-row" data-id="T2"></div></div>';
      document.body.appendChild(wrap);
      const input = wrap.querySelector('input');
      const down = delegatedEvent({ key: 'ArrowDown' });
      dispatchTo(fns.techKeydown, input, [], down);
      assert.equal(down.defaultPrevented, true);
      assert.ok(wrap.querySelector('.st-tech-row[data-id="T1"]').classList.contains('active'));
      dispatchTo(fns.techKeydown, input, [], delegatedEvent({ key: 'Escape' }));
      assert.ok(!wrap.querySelector('.st-tech-panel').classList.contains('show'));
    },
  },
  {
    name: 'abortExecutionStop stops propagation so the row click does not also fire',
    run() {
      globalThis.confirm = () => false;
      const btn = document.createElement('button');
      const ev = delegatedEvent();
      dispatchTo(fns.abortExecutionStop, btn, ['ex-1'], ev);
      assert.equal(ev.cancelBubble, true);
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

// Group-selection checkboxes: each caller has its own fixed state key and
// renderers; nothing is looked up by a name taken from data-args.
for (const [action, key] of [['tmplGroupChange', '_tmplGroupSel'], ['runGroupChange', '_groupSel'], ['vexSweepGroupChange', '_vexGroupSel'], ['vexRunGroupChange', '_vexRunGroupSel']]) {
  test(`${action} records the checkbox in state.${key} when dispatched`, () => {
    state[key] = {};
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = true;
    dispatchTo(fns[action], box, [7], delegatedEvent());
    assert.deepEqual(state[key], { 7: true });
    box.checked = false;
    dispatchTo(fns[action], box, [7], delegatedEvent());
    assert.deepEqual(state[key], { 7: false });
  });
}
