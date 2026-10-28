import { state } from '../core/state.js';

// Sidebar extras that need no server support:
//  - count badges on a few nav items, computed from data the pages already loaded (state), so a badge
//    only appears once that data is known and never shows an invented number;
//  - Pinned items (a star on each nav item) and Recent pages (the last few visited), both kept in this
//    browser's localStorage only.

var PINS_KEY = 'bas_nav_pins';
var RECENT_KEY = 'bas_nav_recent';
var MAX_RECENT = 3;

// parseList reads a stored JSON array of tab ids, ignoring anything that is not a list of strings.
export function parseList(raw) {
  try {
    var v = JSON.parse(raw || '[]');
    return Array.isArray(v) ? v.filter(function(t) { return typeof t === 'string' && /^[a-z0-9-]+$/.test(t); }) : [];
  } catch (e) { return []; }
}

// nextRecent puts tab first, drops duplicates and pinned tabs, and keeps at most max entries.
export function nextRecent(list, tab, pins, max) {
  var out = [tab].concat(list).filter(function(t, i, a) { return a.indexOf(t) === i && pins.indexOf(t) < 0; });
  return out.slice(0, max || MAX_RECENT);
}

// navBadgeCounts maps a tab id to { n, tone, label } for tabs whose count is known right now.
// st is the shared state object; only values the pages have really loaded are used.
export function navBadgeCounts(st) {
  var out = {};
  var t = st && st.agentTotals;
  if (t && (typeof t.offline === 'number' || typeof t.degraded === 'number')) {
    var off = Number(t.offline) || 0, deg = Number(t.degraded) || 0;
    if (off + deg > 0) out.agents = { n: off + deg, tone: off > 0 ? 'bad' : 'warn', label: off + ' offline, ' + deg + ' degraded' };
  }
  var f = st && st._findings;
  if (Array.isArray(f) && f.length) {
    var open = f.filter(function(r) { return r && r.status === 'open'; });
    if (open.length) {
      var crit = open.some(function(r) { return r.severity === 'critical'; });
      out.findings = { n: open.length, tone: crit ? 'bad' : 'warn', label: open.length + ' open findings' };
    }
  }
  var c = st && st._campaigns;
  if (Array.isArray(c)) {
    var running = c.filter(function(r) { return r && r.status === 'running'; }).length;
    if (running) out.campaigns = { n: running, tone: 'accent', label: running + ' running' };
  }
  return out;
}

function readList(key) {
  try { return parseList(localStorage.getItem(key)); } catch (e) { return []; }
}
function writeList(key, list) {
  try { localStorage.setItem(key, JSON.stringify(list)); } catch (e) { /* private mode: nothing is remembered */ }
}

function sourceItem(tab) {
  var el = document.querySelector('.sidebar-nav .nav-item[data-tab="' + tab + '"]');
  if (!el || el.closest('[hidden]')) return null;
  return el;
}
function isShown(el) {
  return !!el && el.style.display !== 'none' && !el.classList.contains('is-hidden') && !el.classList.contains('disabled');
}

function cloneItem(tab, src) {
  var c = src.cloneNode(true);
  c.removeAttribute('data-tab');
  c.setAttribute('data-nav-clone', tab);
  var pin = c.querySelector('.nav-pin');
  if (pin) pin.remove();
  var badge = c.querySelector('.nav-badge');
  if (badge) badge.remove();
  return c;
}

function renderGroup(id, label, tabs) {
  var nav = document.querySelector('.sidebar-nav');
  if (!nav) return;
  var old = document.getElementById(id);
  if (old) old.remove();
  var items = tabs.map(function(t) { var s = sourceItem(t); return s && isShown(s) ? cloneItem(t, s) : null; }).filter(Boolean);
  if (!items.length) return;
  var g = document.createElement('div');
  g.className = 'nav-group nav-extra';
  g.id = id;
  var lab = document.createElement('div');
  lab.className = 'nav-group-label';
  lab.textContent = label;
  g.appendChild(lab);
  items.forEach(function(i) { g.appendChild(i); });
  var first = nav.querySelector('.nav-group:not(.nav-extra)');
  nav.insertBefore(g, id === 'nav-pinned' ? nav.firstChild : (document.getElementById('nav-pinned') ? document.getElementById('nav-pinned').nextSibling : nav.firstChild));
  void first;
}

export function renderNavExtras() {
  var pins = readList(PINS_KEY);
  var recent = readList(RECENT_KEY).filter(function(t) { return pins.indexOf(t) < 0; }).slice(0, MAX_RECENT);
  renderGroup('nav-pinned', 'Pinned', pins);
  renderGroup('nav-recent', 'Recent', recent);
  document.querySelectorAll('.sidebar-nav .nav-item[data-tab]').forEach(function(el) {
    var pin = el.querySelector('.nav-pin');
    if (pin) {
      var on = pins.indexOf(el.getAttribute('data-tab')) >= 0;
      pin.classList.toggle('on', on);
      pin.setAttribute('aria-pressed', on ? 'true' : 'false');
      pin.title = on ? 'Unpin' : 'Pin to the top of the sidebar';
    }
  });
  markActive();
}

function markActive() {
  var current = document.querySelector('.sidebar-nav .nav-item[data-tab].active');
  var tab = current ? current.getAttribute('data-tab') : '';
  document.querySelectorAll('.sidebar-nav [data-nav-clone]').forEach(function(el) {
    el.classList.toggle('active', el.getAttribute('data-nav-clone') === tab);
  });
}

// toggleNavPin is the action behind each nav item's star.
export function toggleNavPin(tab) {
  if (!/^[a-z0-9-]+$/.test(String(tab))) return;
  var pins = readList(PINS_KEY);
  var i = pins.indexOf(tab);
  if (i >= 0) pins.splice(i, 1); else pins.push(tab);
  writeList(PINS_KEY, pins);
  renderNavExtras();
}

// navTabActivated is called whenever a tab becomes the current one.
export function navTabActivated(tab) {
  if (tab && sourceItem(tab)) {
    var pins = readList(PINS_KEY);
    writeList(RECENT_KEY, nextRecent(readList(RECENT_KEY), tab, pins, MAX_RECENT));
  }
  renderNavExtras();
  refreshNavBadges();
}

export function refreshNavBadges() {
  var counts = navBadgeCounts(state);
  document.querySelectorAll('.sidebar-nav .nav-item[data-tab]').forEach(function(el) {
    var tab = el.getAttribute('data-tab');
    var b = el.querySelector('.nav-badge');
    var c = counts[tab];
    if (!c) { if (b) b.remove(); return; }
    if (!b) {
      b = document.createElement('span');
      b.className = 'nav-badge';
      el.appendChild(b);
    }
    b.textContent = c.n > 99 ? '99+' : String(c.n);
    b.className = 'nav-badge tone-' + c.tone;
    b.title = c.label;
  });
}

var started = false;
// initNavExtras adds the pin stars once and keeps the badges current.
export function initNavExtras() {
  if (started) return;
  started = true;
  document.querySelectorAll('.sidebar-nav .nav-item[data-tab]').forEach(function(el) {
    if (el.querySelector('.nav-pin')) return;
    var tab = el.getAttribute('data-tab');
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'nav-pin';
    b.setAttribute('data-on-click', 'toggleNavPin');
    b.setAttribute('data-args', JSON.stringify([tab]));
    b.setAttribute('aria-label', 'Pin ' + tab);
    b.innerHTML = '<svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor" aria-hidden="true"><path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/></svg>';
    el.appendChild(b);
  });
  renderNavExtras();
  refreshNavBadges();
}

// refreshBadgeData loads what a badge counts, so the number shows from sign-in on instead of only after the page that
// owns the data has been opened. isActive says whether anyone is signed in; a failed or odd answer keeps the last list.
export function refreshBadgeData(fetchJson, st, isActive) {
  if (!isActive()) return Promise.resolve();
  return fetchJson('/api/findings').then(function(list) {
    if (Array.isArray(list)) st._findings = list;
    refreshNavBadges();
  }).catch(function() { /* keep the last known list */ });
}

var badgeDataTimer = null;
// startBadgeDataRefresh loads the badge data now and then once a minute. Safe to call on every sign-in.
export function startBadgeDataRefresh(fetchJson) {
  var active = function() { var app = document.getElementById('app'); return !!app && app.style.display !== 'none'; };
  refreshBadgeData(fetchJson, state, active);
  if (!badgeDataTimer) badgeDataTimer = setInterval(function() { refreshBadgeData(fetchJson, state, active); }, 60000);
}

// startNavBadgePolling re-reads the badges every few seconds. Called from main.js only, so it never
// runs (and never keeps a process alive) where only a single module is loaded, such as the unit tests.
export function startNavBadgePolling() {
  setInterval(refreshNavBadges, 5000);
}
