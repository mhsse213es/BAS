// Inline handlers write app variables through window (onchange=
// "scenarioView='grid'", "_groupSel[id]=this.checked"); module code reads
// core/state.js. installGlobals() must make both the same storage
// (G1c final review I2).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const { installGlobals, STATE_GLOBALS } = await import('../../src/globals.js');
const { state } = await import('../../src/core/state.js');
installGlobals();

test('a handler assignment through window reaches core state', () => {
  window.scenarioView = 'grid';
  assert.equal(state.scenarioView, 'grid');
  state.scenarioView = 'list';
  assert.equal(window.scenarioView, 'list');
});

test('a handler indexed write through window reaches core state', () => {
  state._groupSel = {};
  window._groupSel[7] = true;
  assert.deepEqual(state._groupSel, { 7: true });
});

test('every STATE_GLOBALS name is a live accessor onto core state', () => {
  for (const name of STATE_GLOBALS) {
    const probe = { probe: name };
    window[name] = probe;
    assert.equal(state[name], probe, name);
  }
});
