import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// A rule's title and text are user-supplied: they must reach the page as text, never as markup.
test('the review list shows a hostile rule title as text and builds no elements from it', async () => {
  const dom = new JSDOM(`<!doctype html><body>
    <div id="ci-overlay"></div><select id="ci-kind"><option value="sigma"></option></select>
    <span id="ci-os-wrap"></span><span id="ci-name-wrap"></span><span id="ci-tech-wrap"></span>
    <textarea id="ci-text"></textarea><div id="ci-err"></div><div id="ci-results"></div><div id="ci-drafts"></div>
    <button id="ci-submit-btn"></button></body>`);
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  const store = {};
  globalThis.localStorage = { getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; } };
  const evil = '<img src=x onerror=alert(1)><script>boom()</script>';
  globalThis.fetch = async () => ({ status: 200, json: async () => ({ drafts: [
    { id: 'd1', kind: 'sigma', status: 'draft', title: evil, coverage: JSON.stringify({ notEmulated: [evil] }),
      scenario: { steps: [{ executor: 'cmd', command: evil }] } }] }) });
  const m = await import('../../src/features/content-import.js');
  m.loadImportDrafts();
  await new Promise(r => setTimeout(r, 20));
  const box = dom.window.document.getElementById('ci-drafts');
  assert.equal(box.querySelectorAll('img,script').length, 0, 'no element may be created from rule text');
  assert.ok(box.textContent.includes(evil), 'the text is shown literally');
  const approve = box.querySelector('[data-on-click="approveImportDraft"]');
  assert.equal(approve.getAttribute('data-args'), '["d1"]');
});
