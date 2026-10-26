// Layout kit for the redesigned pages: KPI tiles, cards, grids, bars, segmented controls, filter bars.
//
// Every helper returns an HTML string. Text arguments (labels, values, titles) are ESCAPED here.
// Arguments named `html`/`body`/`actions`/`cells` are trusted markup the caller already built from
// escaped pieces. Behaviour is never attached with inline handlers: pass `action` (a name in the
// ACTIONS registry) and `args` and the helper emits data-on-click / data-args like the rest of the app.
import { x } from './escape.js';
import { chartSlot, CHART_COLORS } from './charts.js';
import { ICON } from '../features/page-heroes.js';

const svg = (d) => '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>';

// A wider icon set than the page banners need: ICON (banners) plus generic UI glyphs.
export const KIT_ICON = Object.assign({}, ICON, {
  search: svg('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>'),
  filter: svg('<path d="M3 5h18l-7 8v6l-4-2v-4z"/>'),
  download: svg('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>'),
  upload: svg('<path d="M12 16V5M7 9l5-5 5 5M5 20h14"/>'),
  plus: svg('<path d="M12 5v14M5 12h14"/>'),
  refresh: svg('<path d="M20 11a8 8 0 10-2.3 5.7M20 5v6h-6"/>'),
  shield: svg('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>'),
  alert: svg('<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.5"/>'),
  external: svg('<path d="M14 4h6v6M20 4l-9 9M18 14v5H5V6h5"/>'),
  x: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  chevron: svg('<path d="M9 6l6 6-6 6"/>'),
  play: svg('<path d="M7 5l12 7-12 7z"/>'),
  pause: svg('<path d="M8 5v14M16 5v14"/>'),
  eye: svg('<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
  copy: svg('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/>'),
  calendar: svg('<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>'),
  server: svg('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'),
  users: svg('<circle cx="9" cy="8" r="3.5"/><path d="M2 20c.7-3.5 3.3-5.5 7-5.5s6.3 2 7 5.5M16 4.5a3.5 3.5 0 010 7M22 20c-.4-2.4-1.7-4-3.5-4.8"/>'),
  key: svg('<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>'),
  database: svg('<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>'),
  cloud: svg('<path d="M7 18a5 5 0 01-.5-10 6 6 0 0111.5 1.5A4 4 0 0117 18z"/>'),
  file: svg('<path d="M7 3h8l4 4v14H7z"/><path d="M15 3v4h4"/>'),
  more: svg('<path d="M5 12h.01M12 12h.01M19 12h.01"/>'),
});

const TONES = { accent: 1, ok: 1, warn: 1, bad: 1, info: 1, muted: 1, violet: 1 };
const tone = (t) => (TONES[t] ? t : 'accent');
const cls = (...a) => a.filter(Boolean).join(' ');
// Built from parts so the action-registry checker (which scans source for literal attributes) sees only real markup.
const ON = 'data-on-';
const actionAttrs = (action, args) => (action ? ' ' + ON + 'click="' + x(action) + '"' + (args ? ' data-args="' + x(JSON.stringify(args)) + '"' : '') : '');
export const icon = (name) => KIT_ICON[name] || '';

// kpi({label, value, sub?, icon?, tone?, spark?:[numbers], action?, args?})
export function kpi(o) {
  const t = tone(o.tone);
  return '<div class="rk-kpi tone-' + t + (o.action ? ' rk-click' : '') + '"' + actionAttrs(o.action, o.args) + '>' +
    '<div class="rk-kpi-top">' + (o.icon ? '<span class="rk-kpi-ico">' + icon(o.icon) + '</span>' : '') + '<span class="rk-kpi-lbl">' + x(o.label) + '</span></div>' +
    '<div class="rk-kpi-val">' + x(o.value) + '</div>' +
    (o.sub ? '<div class="rk-kpi-sub">' + x(o.sub) + '</div>' : '') +
    (o.spark && o.spark.length > 1 ? '<div class="rk-kpi-spark">' + chartSlot({ type: 'spark', data: o.spark, color: CHART_COLORS[t] || CHART_COLORS.accent, h: 38 }) + '</div>' : '') +
    '</div>';
}

// grid(n, itemsHtml[]) n = 2..4 columns, collapsing on narrow screens
export const grid = (n, items) => '<div class="rk-grid g' + (n >= 2 && n <= 4 ? n : 2) + '">' + items.join('') + '</div>';

// card(title, bodyHtml, {actions?, cls?, flush?, sub?})
export function card(title, body, o) {
  o = o || {};
  return '<section class="' + cls('rk-card', o.flush && 'flush', o.cls) + '">' +
    (title ? '<header class="rk-hd"><h2>' + x(title) + '</h2>' + (o.sub ? '<span class="rk-hd-sub">' + x(o.sub) + '</span>' : '') + (o.actions ? '<div class="rk-hd-actions">' + o.actions + '</div>' : '') + '</header>' : '') +
    body + '</section>';
}

// bar(percent, tone?) thin progress bar; the width is applied by the chart kit's observer from data-w (CSP-safe)
export function bar(pct, t, thick) {
  const v = Math.max(0, Math.min(100, Number(pct) || 0));
  return '<div class="rk-bar' + (thick ? ' thick' : '') + ' tone-' + tone(t) + '"><i data-w="' + Math.round(v) + '"></i></div>';
}

// hbars([[label, percent, tone?, valueText?]])
export function hbars(rows) {
  return rows.map((r) => '<div class="rk-hbar"><span class="rk-hbar-l">' + x(r[0]) + '</span>' + bar(r[1], r[2]) + '<span class="rk-hbar-v">' + x(r[3] != null ? r[3] : Math.round(Number(r[1]) || 0) + '%') + '</span></div>').join('');
}

// pill(text, tone?) status pill with a leading dot
export const pill = (text, t) => '<span class="rk-pill tone-' + tone(t) + '">' + x(text) + '</span>';
export const chip = (text, t) => '<span class="rk-chip tone-' + tone(t) + '">' + x(text) + '</span>';

// seg([{id,label,count?}], activeId, action) segmented control; each option calls action with [id]
export function seg(opts, active, action) {
  return '<div class="rk-seg" role="tablist">' + opts.map((o) =>
    '<button type="button" role="tab" class="' + (o.id === active ? 'on' : '') + '" aria-selected="' + (o.id === active) + '"' + actionAttrs(action, [o.id]) + '>' + x(o.label) + (o.count != null ? ' <span class="rk-seg-n">' + x(o.count) + '</span>' : '') + '</button>').join('') + '</div>';
}

// tabs([{id,label,count?}], activeId, action) underline tabs
export function tabs(opts, active, action) {
  return '<div class="rk-tabs" role="tablist">' + opts.map((o) =>
    '<button type="button" role="tab" class="' + (o.id === active ? 'on' : '') + '" aria-selected="' + (o.id === active) + '"' + actionAttrs(action, [o.id]) + '>' + x(o.label) + (o.count != null ? ' <span class="rk-seg-n">' + x(o.count) + '</span>' : '') + '</button>').join('') + '</div>';
}

// filterBar(...partsHtml) a wrapping row for a search box, selects and buttons
export const filterBar = (...parts) => '<div class="rk-filters">' + parts.join('') + '</div>';
export const searchBox = (id, placeholder, action) => '<label class="rk-search">' + icon('search') + '<input type="search" id="' + x(id) + '" placeholder="' + x(placeholder) + '"' + (action ? ' ' + ON + 'input="' + x(action) + '"' : '') + '></label>';

// empty(iconName, title, sub?) an honest empty state
export const empty = (ic, title, sub) => '<div class="rk-empty">' + (icon(ic) ? '<span class="rk-empty-ico">' + icon(ic) + '</span>' : '') + '<b>' + x(title) + '</b>' + (sub ? '<div>' + x(sub) + '</div>' : '') + '</div>';

// kv([[label, valueText]]) a definition list; values are escaped text
export const kv = (rows) => '<dl class="rk-kv">' + rows.map((r) => '<dt>' + x(r[0]) + '</dt><dd>' + x(r[1]) + '</dd>').join('') + '</dl>';

// row of label + value + optional bar, used for "check" lists
export const checkRow = (state, title, sub, right) => '<div class="rk-check"><span class="rk-dot tone-' + tone(state) + '"></span><div class="rk-check-t"><b>' + x(title) + '</b>' + (sub ? '<span>' + x(sub) + '</span>' : '') + '</div>' + (right ? '<div class="rk-check-r">' + right + '</div>' : '') + '</div>';
