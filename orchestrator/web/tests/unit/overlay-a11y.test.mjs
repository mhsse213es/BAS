import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { installOverlayA11y } from '../../src/core/overlay-a11y.js';

const HTML = `<!DOCTYPE html><body>
<button id="opener">open</button>
<div id="ov" class="overlay"><div class="modal"><h3>Run Scenario</h3>
  <input id="a"><button id="b">Next</button><button id="cancel" data-on-click="closeRun">Cancel</button></div></div>
<div id="dr" class="drawer-overlay" data-on-click="closeDrOnBackdrop"><div class="drawer">
  <div class="drawer-header"><strong>Agent</strong><button class="drawer-close" id="x">&#10005;</button></div><button id="z">z</button></div></div>
</body>`;

function setup() {
  const dom = new JSDOM(HTML, { url: 'http://127.0.0.1/', pretendToBeVisual: true });
  const { window } = dom;
  // jsdom has no layout; treat every element as visible.
  Object.defineProperty(window.HTMLElement.prototype, 'offsetWidth', { get() { return 10; } });
  installOverlayA11y(window.document);
  const doc = window.document;
  const tick = () => new Promise((r) => window.setTimeout(r, 120));
  const key = (k, o = {}) => doc.dispatchEvent(new window.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...o }));
  return { window, doc, tick, key };
}

test('opening an overlay gives its dialog role, aria-modal, a label and moves focus in', async () => {
  const { doc, tick } = setup();
  doc.getElementById('opener').focus();
  doc.getElementById('ov').classList.add('open');
  await tick();
  const dlg = doc.querySelector('#ov .modal');
  assert.equal(dlg.getAttribute('role'), 'dialog');
  assert.equal(dlg.getAttribute('aria-modal'), 'true');
  assert.equal(dlg.getAttribute('aria-label'), 'Run Scenario');
  assert.equal(doc.activeElement, dlg);
});

test('drawer label comes from its header and an existing role is kept', async () => {
  const { doc, tick } = setup();
  doc.querySelector('#dr .drawer').setAttribute('role', 'complementary');
  doc.getElementById('dr').classList.add('open');
  await tick();
  const dlg = doc.querySelector('#dr .drawer');
  assert.equal(dlg.getAttribute('aria-label'), 'Agent');
  assert.equal(dlg.getAttribute('role'), 'complementary');
});

test('Tab wraps inside the dialog in both directions', async () => {
  const { doc, tick, key } = setup();
  doc.getElementById('ov').classList.add('open');
  await tick();
  doc.getElementById('cancel').focus();
  key('Tab');
  assert.equal(doc.activeElement.id, 'a');
  key('Tab', { shiftKey: true });
  assert.equal(doc.activeElement.id, 'cancel');
});

test('Tab from outside the dialog is pulled back in', async () => {
  const { doc, tick, key } = setup();
  doc.getElementById('ov').classList.add('open');
  await tick();
  doc.getElementById('opener').focus();
  key('Tab');
  assert.equal(doc.activeElement.id, 'a');
});

test('Escape clicks the overlay\'s own close control and focus returns to the opener', async () => {
  const { doc, window, tick, key } = setup();
  let clicked = 0;
  doc.getElementById('cancel').addEventListener('click', () => { clicked++; doc.getElementById('ov').classList.remove('open'); });
  doc.getElementById('opener').focus();
  doc.getElementById('ov').classList.add('open');
  await tick();
  key('Escape');
  await tick();
  assert.equal(clicked, 1);
  assert.equal(doc.activeElement.id, 'opener');
  assert.ok(window);
});

test('Escape closes a drawer through .drawer-close', async () => {
  const { doc, tick, key } = setup();
  let clicked = 0;
  doc.getElementById('x').addEventListener('click', () => { clicked++; doc.getElementById('dr').classList.remove('open'); });
  doc.getElementById('dr').classList.add('open');
  await tick();
  key('Escape');
  await tick();
  assert.equal(clicked, 1);
});

test('Escape already handled by the feature (defaultPrevented) is left alone', async () => {
  const { doc, tick, key } = setup();
  let clicked = 0;
  doc.getElementById('cancel').addEventListener('click', () => { clicked++; });
  doc.getElementById('ov').classList.add('open');
  await tick();
  doc.addEventListener('keydown', (e) => e.preventDefault(), { once: true, capture: true });
  key('Escape');
  await tick();
  assert.equal(clicked, 0);
});

test('with two overlays open only the topmost reacts to Escape', async () => {
  const { doc, tick, key } = setup();
  const log = [];
  doc.getElementById('cancel').addEventListener('click', () => { log.push('modal'); doc.getElementById('ov').classList.remove('open'); });
  doc.getElementById('x').addEventListener('click', () => { log.push('drawer'); doc.getElementById('dr').classList.remove('open'); });
  doc.getElementById('dr').classList.add('open');
  await tick();
  doc.getElementById('ov').classList.add('open');
  await tick();
  key('Escape');
  await tick();
  assert.deepEqual(log, ['modal']);
});

test('no overlay open: keys are ignored', async () => {
  const { doc, key } = setup();
  doc.getElementById('opener').focus();
  key('Tab');
  key('Escape');
  assert.equal(doc.activeElement.id, 'opener');
});

test('an overlay added later is picked up', async () => {
  const { doc, window, tick } = setup();
  const o = doc.createElement('div');
  o.className = 'overlay';
  o.innerHTML = '<div class="modal"><h3>Late</h3><button>ok</button></div>';
  doc.body.appendChild(o);
  await tick();
  o.classList.add('open');
  await tick();
  assert.equal(o.querySelector('.modal').getAttribute('aria-label'), 'Late');
  assert.ok(window);
});

test('drawer title in a styled header (no heading element) still labels the dialog', async () => {
  const { doc, tick } = setup();
  const hd = doc.querySelector('#dr .drawer-header');
  hd.innerHTML = '<div class="sc-dh"><span>web-01</span></div><button class="drawer-close" id="x">✕</button>';
  doc.getElementById('dr').classList.add('open');
  await tick();
  assert.equal(doc.querySelector('#dr .drawer').getAttribute('aria-label'), 'web-01');
});
