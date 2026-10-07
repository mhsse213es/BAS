// Data-driven style values under style-src 'self' (G1e spec 4.4).
// Templates emit cssVars([rule, ...values]); installCssVars() renders each
// registered rule's declaration value from typed values, checks it with
// CSS.supports exactly as the browser checked the former inline declaration,
// then sets the custom property (CSSOM, which CSP does not govern) and adds
// the rule's class. Invalid values are dropped, as the browser dropped invalid
// inline declarations. Nothing here applies an arbitrary property or value.
/* global CSS, MutationObserver */
import { x } from './escape.js';
import { CSS_VAR_RULES } from './css-var-rules.js';

// Character-set limits per placeholder type (security); validity is CSS.supports.
export const TYPES = {
  color: /^(?:#[0-9a-f]{3,8}|[a-z]+|var\(--[a-z0-9-]+\)|(?:rgba?|hsla?)\([0-9.,%\s/+-]*\))$/i,
  number: /^-?(?:\d+|\d*\.\d+)$/,
  integer: /^-?\d+$/,
};
const MAX_LEN = 64;

export function cssVars(...entries) {
  return ` data-css-vars="${x(JSON.stringify(entries))}"`;
}

export function renderValue(rule, values) {
  const def = Object.hasOwn(CSS_VAR_RULES, rule) ? CSS_VAR_RULES[rule] : null;
  if (!def || !Array.isArray(values) || values.length !== def.types.length) return null;
  const parts = [];
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (typeof v !== 'string' && typeof v !== 'number') return null;
    const s = String(v);
    if (s.length > MAX_LEN || !TYPES[def.types[i]].test(s)) return null;
    parts.push(s);
  }
  return def.value.replace(/\{(\d+)\}/g, (_, i) => parts[Number(i)]);
}

export function applyCssVars(el, supports = (p, v) => CSS.supports(p, v)) {
  let entries = null;
  try { entries = JSON.parse(el.getAttribute('data-css-vars')); } catch { /* malformed */ }
  if (!Array.isArray(entries)) { console.warn('css-vars: malformed data-css-vars dropped'); return; }
  for (const entry of entries) {
    const rule = Array.isArray(entry) && typeof entry[0] === 'string' ? entry[0] : null;
    const value = rule === null ? null : renderValue(rule, entry.slice(1));
    if (value === null || !supports(CSS_VAR_RULES[rule].prop, value)) {
      console.warn(`css-vars: dropped ${JSON.stringify(entry).slice(0, 120)}`);
      continue;
    }
    el.style.setProperty(`--${rule}`, value);
    el.classList.add(rule);
  }
}

export function installCssVars(root = document) {
  for (const el of root.querySelectorAll('[data-css-vars]')) applyCssVars(el);
  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === 'attributes') { if (r.target.hasAttribute('data-css-vars')) applyCssVars(r.target); continue; }
      for (const n of r.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.hasAttribute('data-css-vars')) applyCssVars(n);
        for (const el of n.querySelectorAll('[data-css-vars]')) applyCssVars(el);
      }
    }
  }).observe(root.documentElement || root, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-css-vars'] });
}
