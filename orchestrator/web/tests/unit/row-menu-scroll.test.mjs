// The row action menu ("⋮" in the Agents table) is a fixed-position panel that is re-placed under its button on every
// scroll. The scroll listener runs in the capture phase, so it also heard the panel's own scrolling and reset the
// panel to the top each time: a long action list could not be scrolled. These tests pin the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['toggleRowMenu', 'repositionOpenRowMenus', 'closeAllRowMenus']);

// Builds a trigger button and an open menu panel. The panel's layout is faked: it overflows the viewport, so
// placeRowMenu takes its clamping path, and re-measuring resets the scroll position the way a browser does.
function openMenu(id, { scrolled = 0 } = {}) {
  const wrap = document.createElement('div');
  wrap.className = 'row-menu-wrap';
  const btn = document.createElement('button');
  btn.className = 'row-menu-btn';
  btn.getBoundingClientRect = () => ({ top: 300, bottom: 320, left: 900, right: 930, width: 30, height: 20 });
  const panel = document.createElement('div');
  panel.className = 'row-menu-panel';
  panel.id = id;
  const item = document.createElement('button');
  item.className = 'row-menu-item';
  panel.appendChild(item);
  wrap.append(btn, panel);
  document.body.appendChild(wrap);

  let scrollTop = scrolled;
  Object.defineProperty(panel, 'scrollTop', { get: () => scrollTop, set: (v) => { scrollTop = v; }, configurable: true });
  panel.getBoundingClientRect = () => {
    scrollTop = 0; // the browser clamps scroll when max-height is reset to none
    return { top: 324, bottom: window.innerHeight + 400, left: 700, right: 930, width: 230, height: window.innerHeight + 76 };
  };
  fns.toggleRowMenu(btn, id);
  scrollTop = scrolled; // opening resets it; put the user's scroll position back
  return { btn, panel, item, wrap };
}

test('scrolling inside the open menu does not re-place it', () => {
  const { panel, item, wrap } = openMenu('rm-own');
  panel.style.maxHeight = '123px';
  panel.style.top = '11px';
  fns.repositionOpenRowMenus({ target: item }); // scroll event from inside the panel
  fns.repositionOpenRowMenus({ target: panel });
  assert.equal(panel.style.maxHeight, '123px', 'the menu must be left alone while the user scrolls it');
  assert.equal(panel.style.top, '11px');
  assert.ok(panel.classList.contains('open'));
  wrap.remove();
});

test('scrolling the page still moves an open menu with its button', () => {
  const { panel, wrap } = openMenu('rm-page');
  panel.style.maxHeight = '123px';
  fns.repositionOpenRowMenus({ target: document.body }); // scroll event from the page
  assert.notEqual(panel.style.maxHeight, '123px', 'a page scroll must re-place the menu under its button');
  assert.ok(panel.classList.contains('open'));
  wrap.remove();
});

test('re-placing a menu keeps the position the user scrolled to', () => {
  const { panel, wrap } = openMenu('rm-keep', { scrolled: 60 });
  assert.equal(panel.scrollTop, 60);
  fns.repositionOpenRowMenus({ target: document.body });
  assert.equal(panel.scrollTop, 60, 're-measuring must not send a scrolled menu back to the top');
  wrap.remove();
});

test('a call with no event still re-places open menus', () => {
  const { panel, wrap } = openMenu('rm-noevent');
  panel.style.maxHeight = '123px';
  fns.repositionOpenRowMenus();
  assert.notEqual(panel.style.maxHeight, '123px');
  wrap.remove();
});

test('the menu panel contains overscroll so the page behind does not scroll', async () => {
  const { readFileSync } = await import('node:fs');
  const css = readFileSync(new URL('../../styles/app.css', import.meta.url), 'utf8');
  const block = css.slice(css.indexOf('.row-menu-panel {'), css.indexOf('.row-menu-panel.open'));
  assert.match(block, /overscroll-behavior:\s*contain/);
});
