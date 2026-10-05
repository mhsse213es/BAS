

// escapeHTML is the single canonical HTML-text/double-quoted-attribute
// escaper for this file (G1a canonicalization -- previously 4 divergent
// copies existed: two more "x" definitions with weaker/inconsistent
// coverage, plus a separate "escHtml" name for the same job). It
// deliberately does NOT escape ' -- several call sites receive its output
// and then apply their OWN context-specific quote handling afterward
// (e.g. .replace(/'/g,'&#39;') for an HTML single-quoted attribute, or
// .replace(/'/g,"\\'") for a value embedded inside a single-quoted JS
// string literal within an onclick="..." handler). If this escaped '
// too, those downstream .replace() calls would become no-ops and the
// JS-string-literal cases would break out of their quote -- don't add '
// escaping here; give call sites that need it their own explicit step.
export function escapeHTML(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
// x is the short alias used at hundreds of call sites throughout this
// file; escapeHTML is the one real implementation.
export function x(s) { return escapeHTML(s); }