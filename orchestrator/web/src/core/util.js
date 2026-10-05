import { state } from './state.js';
import { x } from './escape.js';

export function ago(iso) {
  if (!iso) return '—';
  var s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)   return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  return Math.floor(s/3600) + 'h ago';
}
export function daysAgo(iso) {
  if (!iso) return 0;
  var diff = Date.now() - new Date(iso);
  return Math.max(0, Math.floor(diff / (1000 * 60 * 60 * 24)));
}
export function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}
// fmtRunIdCode renders a run/sweep ID as a <code> cell truncated for table
// width, but -- unlike a bare .substring(0,14) -- an ellipsis marks it as
// truncated and the full ID is available via title (hover) and by copying
// the visible text plus the tooltip. Without this, a truncated ID silently
// LOOKS complete (e.g. "18cea85f279812" for the real ID "18cea85f279812f5"),
// which breaks any attempt to look the run up directly by that ID later.
export function fmtRunIdCode(id) {
  if (!id) return '<code>—</code>';
  var shown = id.length > 14 ? x(id.substring(0, 14)) + '&hellip;' : x(id);
  return '<code title="' + x(id) + '">' + shown + '</code>';
}
export function showToast(msg, type) {
  var el = document.getElementById('toast');
  el.textContent = msg; el.className = 'show ' + (type || 'ok');
  clearTimeout(state._toast);
  state._toast = setTimeout(function() { el.className = ''; }, 3800);
}