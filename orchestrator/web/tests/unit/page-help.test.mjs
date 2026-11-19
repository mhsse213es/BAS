import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setupDom, load } from './dom.mjs';
import { HELP, helpFor, FALLBACK } from '../../src/features/page-help-content.js';

const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
const TABS = [...html.matchAll(/<div id="tab-([a-z0-9-]+)"/g)].map((m) => m[1]);

test('every page in the console has its own help entry, with a purpose and steps', () => {
  const missing = TABS.filter((t) => helpFor(t) === FALLBACK);
  assert.deepEqual(missing, []);
  for (const t of TABS) {
    const h = helpFor(t);
    assert.ok(h.about && h.about.length > 30, t + ' about');
    assert.ok(h.steps && h.steps.length >= 2, t + ' steps');
  }
});

test('help entries point only at pages that exist and have no stray entries', () => {
  for (const [k, h] of Object.entries(HELP)) {
    assert.ok(TABS.includes(k), 'help for a page that does not exist: ' + k);
    for (const r of h.related || []) assert.ok(TABS.includes(r), k + ' links to missing page ' + r);
  }
});

test('the header has a ? button and it opens a panel for the current page; Escape closes it', async () => {
  setupDom(); localStorage.setItem('bas_role', 'admin');
  const { openPageHelp, closePageHelp } = await load(['openPageHelp', 'closePageHelp']);
  const btn = document.getElementById('page-help-btn');
  assert.ok(btn); assert.equal(btn.getAttribute('data-on-click'), 'openPageHelp'); assert.equal(btn.textContent.trim(), '?');
  document.querySelectorAll('main > [id^="tab-"]').forEach((e) => e.classList.add('is-hidden'));
  document.getElementById('tab-cloud-scenarios').classList.remove('is-hidden');
  openPageHelp();
  const p = document.getElementById('page-help');
  assert.ok(p);
  assert.match(p.textContent, /What this page is for/);
  assert.match(p.textContent, /read-only/i);
  assert.match(p.textContent, /How to use it/);
  assert.ok(p.querySelectorAll('.ph-steps li').length >= 3);
  assert.equal(btn.getAttribute('aria-expanded'), 'true');
  document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  assert.equal(document.getElementById('page-help'), null);
  openPageHelp(); openPageHelp();
  assert.equal(document.querySelectorAll('#page-help').length, 1, 'opening twice keeps one panel');
  closePageHelp();
});

test('an unknown page still gets a panel, and ? is ignored while typing', async () => {
  setupDom(); localStorage.setItem('bas_role', 'admin');
  const { openPageHelp, isTyping } = await load(['openPageHelp', 'isTyping']);
  document.querySelectorAll('main > [id^="tab-"]').forEach((e) => e.classList.add('is-hidden'));
  openPageHelp();
  assert.match(document.getElementById('page-help').textContent, /does not have detailed help yet/);
  assert.equal(isTyping(document.createElement('input')), true);
  assert.equal(isTyping(document.createElement('textarea')), true);
  assert.equal(isTyping(document.createElement('div')), false);
});
