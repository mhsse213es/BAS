// Integrations page view (design demo): banner figures, the ITSM / EPP boxes' empty states, the search +
// category chips and the connector card grid, and the read-only TAXII table. Data loading stays in
// integrations.js (ITSM + EPP lists) and /api/taxii/connectors (loaded here); this module paints what it is
// given. Pure helpers: int-model.js. Every dynamic string is escaped; behaviour goes through data-on-*.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { apicall } from '../core/api.js';
import { icon, empty, pill, filterBar, searchBox } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './int-model.js';

var ITSM = null, EPP = null;
var T = { q: '', kind: '' };
var TAXII = null; // null = not loaded, 'err' = failed, else the server's list

function setHidden(id, h) { var e = document.getElementById(id); if (e) e.hidden = h; }
function rows() { return M.connectorRows(ITSM || [], EPP || []); }

function paintHero(all) {
  var s = M.heroStats(all);
  setHeroStat('int-hs-total', s.total);
  setHeroStat('int-hs-connected', s.connected);
  setHeroStat('int-hs-attention', s.attention);
  setHeroStat('int-hs-fresh', M.since(s.freshest));
}

function cardHtml(r) {
  var ko = r.kind === 'itsm' ? 'openEditConnector' : 'openEditResponseConnector';
  var test = r.kind === 'itsm' ? 'testConnectorById' : 'testResponseConnectorById';
  var del = r.kind === 'itsm' ? 'deleteConnector' : 'deleteResponseConnector';
  return '<div class="rk-card hov int-card"' + on('click', 'intCardOpen', r.kind, r.id) + '>' +
    '<div class="int-top"><span class="int-logo">' + icon(r.kind === 'itsm' ? 'plug' : 'shield') + '</span><span title="' + x(r.status.title) + '">' + pill(r.status.label, r.status.tone) + '</span></div>' +
    '<h2 class="int-name">' + x(r.name) + '</h2>' +
    '<div class="int-meta muted">' + x(M.cardMeta(r)) + '</div>' +
    '<p class="int-detail muted">' + x(r.detail) + '</p>' +
    '<div class="int-acts"><button type="button" class="btn btn-outline btn-sm"' + on('click', test, r.id) + '>Test</button>' +
    '<button type="button" class="btn btn-ghost btn-sm"' + on('click', ko, r.id) + '>Configure</button>' +
    '<span class="grow"></span><button type="button" class="btn btn-ghost btn-sm int-del"' + on('click', del, r.id, r.name) + '>Delete</button></div></div>';
}

function chipsHtml() {
  return '<div class="int-chips">' + M.KIND_FILTERS.map(function(f) {
    return '<button type="button" class="int-chip' + (T.kind === f[0] ? ' on' : '') + '"' + on('click', 'setIntKind', f[0]) + '>' + x(f[1]) + '</button>';
  }).join('') + '</div>';
}

function paintGrid(all) {
  var el = document.getElementById('int-grid');
  if (!el) return;
  var bar = document.getElementById('int-filters');
  if (!all.length) {
    // Nothing configured: the boxes above already say so, so no search bar and no empty grid.
    if (bar) bar.innerHTML = '';
    el.innerHTML = '';
    return;
  }
  if (bar && !bar.querySelector('#int-q')) {
    bar.innerHTML = filterBar(searchBox('int-q', 'Search integrations...', 'intQuery'), '<span id="int-chips"></span>');
    var q = document.getElementById('int-q'); if (q) q.value = T.q;
  }
  var chips = document.getElementById('int-chips');
  if (chips) chips.innerHTML = chipsHtml();
  var list = M.filterRows(all, T.q, T.kind);
  el.innerHTML = list.length
    ? '<div class="rk-grid g3 int-grid">' + list.map(cardHtml).join('') + '</div>'
    : empty('search', 'No integrations match', 'Choose another category.');
}

export function paintIntegrationsView() {
  var all = rows();
  paintHero(all);
  setHidden('int-itsm-empty', !(ITSM && !ITSM.length));
  setHidden('int-epp-empty', !(EPP && !EPP.length));
  paintGrid(all);
}

export function setIntItsm(list) { ITSM = Array.isArray(list) ? list : []; paintIntegrationsView(); }
export function setIntEpp(list) { EPP = Array.isArray(list) ? list : []; paintIntegrationsView(); }

export function intQuery(el) { T.q = String((el && el.value) || ''); paintGrid(rows()); }
export function setIntKind(k) { T.kind = String(k || ''); paintGrid(rows()); }
// The whole card opens Configure; its own buttons keep their own action.
export function intCardOpen(kind, id, el, event) {
  if (event && event.target && event.target.closest && event.target.closest('button')) return;
  var fn = kind === 'itsm' ? 'openEditConnector' : 'openEditResponseConnector';
  var btn = el && el.querySelector ? el.querySelector('[data-on-click=' + JSON.stringify(fn) + ']') : null;
  if (btn) btn.click();
}

// ---- TAXII (read-only; add / edit / delete stay in Settings -> TAXII Connectors) ----
function taxiiBody() {
  if (TAXII === null) return '<tr><td colspan="4" class="empty">Loading…</td></tr>';
  if (TAXII === 'err') return '<tr><td colspan="4" class="empty">Could not load TAXII connectors.</td></tr>';
  var r = M.taxiiRows(TAXII);
  if (!r.length) return '<tr><td colspan="4" class="empty">No TAXII connectors configured yet.</td></tr>';
  return r.map(function(t) {
    return '<tr><td>' + x(t.name) + '</td><td class="mono muted">' + x(t.url) + '</td><td>' + pill(t.status.label, t.status.tone) + '</td><td class="muted">' + x(t.last) + '</td></tr>';
  }).join('');
}
export function paintTaxii() {
  var b = document.getElementById('int-taxii-body');
  if (b) b.innerHTML = taxiiBody();
}
export function loadIntTaxii() {
  paintTaxii();
  apicall('/api/taxii/connectors').then(function(list) { TAXII = Array.isArray(list) ? list : []; paintTaxii(); })
    .catch(function() { TAXII = 'err'; paintTaxii(); });
}
