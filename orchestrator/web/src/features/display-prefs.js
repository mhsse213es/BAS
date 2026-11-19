// Applies the Theme & Display preferences (compact density, reduced motion, accent colour) to the page
// and keeps the Settings controls in step. Preferences live in this browser only (localStorage).
import { ACCENTS, accentVars, normalizeAccent, readDisplayPrefs } from './display-model.js';

var KEYS = { compact: 'audspect_compact', reduce: 'audspect_reduce_motion' };
var BODY_CLASS = { compact: 'compact', reduce: 'reduce-motion' };

function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function lsSet(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* storage blocked: the choice still applies for this page view */ } }

// Set on <body> so the values win over the theme classes (body.theme-light also defines --accent).
function paintAccent(hex) {
  var st = document.body.style;
  var vars = hex ? accentVars(hex) : null;
  ['--accent', '--accent-dim', '--accent-glow', '--accent-border', '--on-accent'].forEach(function(k) {
    if (vars) st.setProperty(k, vars[k]); else st.removeProperty(k);
  });
}

// syncDisplayPrefControls reflects the saved preferences on the Settings switches and swatches.
export function syncDisplayPrefControls() {
  var p = readDisplayPrefs(lsGet);
  document.querySelectorAll('[data-display-pref]').forEach(function(el) {
    var on = !!p[el.getAttribute('data-display-pref')];
    el.classList.toggle('on', on);
    el.setAttribute('aria-checked', on ? 'true' : 'false');
  });
  var current = p.accent || ACCENTS[0][0];
  document.querySelectorAll('[data-accent]').forEach(function(el) {
    var on = el.getAttribute('data-accent') === current;
    el.classList.toggle('on', on);
    el.setAttribute('aria-checked', on ? 'true' : 'false');
  });
}

// applyDisplayPrefs paints the saved preferences; called at start-up.
export function applyDisplayPrefs() {
  var p = readDisplayPrefs(lsGet);
  document.body.classList.toggle(BODY_CLASS.compact, p.compact);
  document.body.classList.toggle(BODY_CLASS.reduce, p.reduce);
  paintAccent(p.accent);
  syncDisplayPrefControls();
}

// toggleDisplayPref flips 'compact' or 'reduce' (the value of data-display-pref on the switch).
export function toggleDisplayPref(name) {
  if (!KEYS[name]) return;
  lsSet(KEYS[name], lsGet(KEYS[name]) === '1' ? null : '1');
  applyDisplayPrefs();
}

// setAccentColour stores one of the offered accent colours; blue is the default and clears the override.
export function setAccentColour(hex) {
  var h = normalizeAccent(hex);
  if (!h) return;
  lsSet('audspect_accent', h === ACCENTS[0][0] ? null : h);
  applyDisplayPrefs();
}
