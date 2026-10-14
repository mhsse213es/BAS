// Inline-style semantics after G1e (spec 4.3, plan C1/C2). Static inline styles
// became generated classes: is-hidden / g1-display-<v> stand for a former
// inline display value, g1-s-* / g1-v-* for a former style attribute. JS that
// read or cleared inline styles goes through these helpers so it sees exactly
// what it saw before.
export const GENERATED = /^(?:is-hidden|g1-display-[a-z-]+|g1-[sv]-[0-9a-f]{8})$/;
const DISPLAY_CLASS = /^(?:is-hidden|g1-display-[a-z-]+)$/;

export function displayOf(el) {
  if (el.style.display) return el.style.display;
  for (const c of el.classList) {
    if (c === 'is-hidden') return 'none';
    if (c.startsWith('g1-display-')) return c.slice(11);
  }
  return '';
}

export function setDisplay(el, value) {
  el.style.display = value;
  // Clearing the inline value used to fall back to the stylesheet; the class
  // standing for the old inline value must go too. Invalid values are ignored
  // by CSSOM, exactly as before, and leave the classes alone.
  if (value === '' || value === null) {
    for (const c of [...el.classList]) if (DISPLAY_CLASS.test(c)) el.classList.remove(c);
  }
  return value;
}

function dropGenerated(el) {
  for (const c of [...el.classList]) if (GENERATED.test(c)) el.classList.remove(c);
}

export function replaceClasses(el, value) {
  const keep = [...el.classList].filter((c) => GENERATED.test(c));
  el.className = value;
  if (keep.length) el.classList.add(...keep);
  return value;
}

export function setCssText(el, value) {
  dropGenerated(el);
  el.style.cssText = value;
  return value;
}

export function clearInlineStyle(el) {
  dropGenerated(el);
  el.removeAttribute('style');
}
