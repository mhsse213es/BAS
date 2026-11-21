// The "?" button in the header: a side panel that explains the page you are on and how to use it. The text lives in
// page-help-content.js; this file only finds the current page, draws the panel and handles opening and closing.
// Every value goes through x() before it reaches the markup.

import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showTab } from './shell.js';
import { helpFor } from './page-help-content.js';

var PANEL_ID = 'page-help';

// currentTab: the id of the page showing now, or ''. A page counts as showing when it has no is-hidden class and is
// not displayed as none (pages are also shown and hidden with inline styles, so the class alone is not enough). If
// several pages pass that test, the one the navigation marks active wins.
export function currentTab() {
  var shown = [];
  document.querySelectorAll('main > [id^="tab-"]').forEach(function(el) {
    if (!el.classList.contains("is-hidden") && el.ownerDocument.defaultView.getComputedStyle(el).display !== "none") shown.push(el.id.replace(/^tab-/, ''));
  });
  if (!shown.length) return '';
  var nav = document.querySelector('.nav-item.active[data-tab]');
  var active = nav ? nav.getAttribute('data-tab') : '';
  return shown.indexOf(active) >= 0 ? active : shown[0];
}

function titleOf(tab) {
  var nav = document.querySelector('.nav-item[data-tab="' + tab + '"]');
  var fromNav = nav ? (nav.getAttribute('title') || '').trim() : '';
  var head = document.getElementById('header-page-title');
  return fromNav || (head && head.textContent.trim()) || tab;
}

function li(t) { return '<li>' + x(t) + '</li>'; }

// helpHtml: the panel's inner markup for one page. Exposed for tests.
export function helpHtml(tab, title) {
  var h = helpFor(tab);
  var out = '<header class="ph-head"><div><span class="ph-kicker">Help</span><h2 id="ph-title">' + x(title) + '</h2></div>' +
    '<button type="button" class="ph-close" aria-label="Close help"' + on('click', 'closePageHelp') + '>&times;</button></header><div class="ph-body">';
  out += '<section class="ph-sec ph-about"><h3>What this page is for</h3><p>' + x(h.about) + '</p></section>';
  out += '<section class="ph-sec"><h3>How to use it</h3><ol class="ph-steps">' + h.steps.map(li).join('') + '</ol></section>';
  if (h.reading && h.reading.length) {
    out += '<section class="ph-sec"><h3>Reading the page</h3><dl class="ph-dl">' + h.reading.map(function(r) { return '<dt>' + x(r[0]) + '</dt><dd>' + x(r[1]) + '</dd>'; }).join('') + '</dl></section>';
  }
  if (h.tips && h.tips.length) out += '<section class="ph-sec ph-tips"><h3>Good to know</h3><ul>' + h.tips.map(li).join('') + '</ul></section>';
  if (h.related && h.related.length) {
    out += '<section class="ph-sec"><h3>Where to go next</h3><div class="ph-rel">' + h.related.map(function(id) {
      return '<button type="button" class="ph-chip"' + on('click', 'pageHelpGo', id) + '>' + x(titleOf(id)) + '</button>';
    }).join('') + '</div></section>';
  }
  out += '<p class="ph-foot">Press <kbd>?</kbd> on any page to open this help, <kbd>Ctrl</kbd> <kbd>K</kbd> to search.</p></div>';
  return out;
}

function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); closePageHelp(); } }

export function openPageHelp() {
  closePageHelp();
  var tab = currentTab();
  var wrap = document.createElement('div');
  wrap.id = PANEL_ID;
  wrap.className = 'ph-scrim';
  wrap.innerHTML = '<aside class="ph-panel" role="dialog" aria-modal="true" aria-labelledby="ph-title">' + helpHtml(tab, titleOf(tab)) + '</aside>';
  wrap.addEventListener('mousedown', function(e) { if (e.target === wrap) closePageHelp(); });
  document.body.appendChild(wrap);
  document.addEventListener('keydown', onKey, true);
  var btn = document.getElementById('page-help-btn');
  if (btn) btn.setAttribute('aria-expanded', 'true');
  var c = wrap.querySelector('.ph-close');
  if (c) c.focus();
}

export function closePageHelp() {
  document.removeEventListener('keydown', onKey, true);
  var w = document.getElementById(PANEL_ID);
  if (w) w.remove();
  var btn = document.getElementById('page-help-btn');
  if (btn) btn.setAttribute('aria-expanded', 'false');
}

// pageHelpGo is the "where to go next" chips: close the panel and open that page.
export function pageHelpGo(tab) { closePageHelp(); showTab(tab); }

// isTyping: true when a key press belongs to a text field, so "?" is not taken from someone typing a question mark.
export function isTyping(target) {
  if (!target || !target.tagName) return false;
  var t = target.tagName.toLowerCase();
  return t === 'input' || t === 'textarea' || t === 'select' || !!target.isContentEditable;
}
