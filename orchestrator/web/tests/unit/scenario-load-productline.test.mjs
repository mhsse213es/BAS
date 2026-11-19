import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { loadScenarios, scenarioProductOf } = await load(['loadScenarios', 'scenarioProductOf']);
const { state } = await import('../../src/core/state.js');

// The loader copies each API scenario into its own shape. If it drops
// productLine, every scenario falls back to the Common section.
test('loadScenarios keeps each scenario\'s productLine so it lands in its licence section', async () => {
  globalThis.fetch = () => Promise.resolve({
    ok: true, status: 200,
    json: () => Promise.resolve([
      { id: 'lolbin-execution', name: 'LOLBin', productLine: 'av' },
      { id: 'art-full-windows', name: 'ART', productLine: 'common' },
    ]),
    text: () => Promise.resolve(''),
    headers: new Map(),
  });
  loadScenarios();
  for (let i = 0; i < 50 && !(state.scenarios || []).length; i++) await new Promise((r) => setTimeout(r, 10));
  const byId = Object.fromEntries(state.scenarios.map((s) => [s.id, s]));
  assert.equal(byId['lolbin-execution'].productLine, 'av');
  assert.equal(scenarioProductOf(byId['lolbin-execution']), 'av');
  assert.equal(scenarioProductOf(byId['art-full-windows']), 'common');
});
