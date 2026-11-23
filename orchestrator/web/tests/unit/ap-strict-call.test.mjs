import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';
import * as M from '../../src/features/ap-model.js';

test('a good finding (tone ok) draws a check, not the category warning icon', () => {
  setupDom();
  const bad = document.createElement('div'); bad.innerHTML = M.findingRowsHtml([{ key: 'domain', tone: 'bad', text: 'x' }]);
  const ok = document.createElement('div'); ok.innerHTML = M.findingRowsHtml([{ key: 'domain', tone: 'ok', text: 'y' }]);
  assert.notEqual(bad.querySelector('.ap-ico').innerHTML, ok.querySelector('.ap-ico').innerHTML);
});

test('apicallOk raises a server { error } body and passes lists and normal bodies through', async () => {
  setupDom();
  const { apicallOk } = await load(['apicallOk']);
  const reply = (body) => { globalThis.fetch = async () => ({ status: 200, json: async () => body }); };
  reply({ error: 'agent is revoked' });
  await assert.rejects(apicallOk('/x'), /agent is revoked/);
  reply([]); assert.deepEqual(await apicallOk('/x'), []);
  reply({ job: { id: 'j1' } }); assert.deepEqual(await apicallOk('/x'), { job: { id: 'j1' } });
});
