import { state } from '../core/state.js';
import { on } from '../core/actions.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { techniqueIndex, filterIndex, paragraphs, safeMitreUrl } from './scn-techniques-model.js';

// "ATT&CK Techniques" on the Scenarios banner opens this panel: every technique the scenarios use, grouped by tactic,
// and for each one MITRE's own details. Nothing here is written by hand; it all comes from the server's ATT&CK data.

var _matrix = null;
var _idx = null;
var _detail = {};

function body() { return document.getElementById('scn-tech-body'); }
function setTitle(t) { var h = document.getElementById('scn-tech-title'); if (h) h.textContent = t; }
function open() { var o = document.getElementById('scn-tech-overlay'); if (o) o.classList.add('open'); }

export function openTechniqueCatalog() {
  open();
  setTitle('ATT&CK techniques in your scenarios');
  var b = body();
  if (b) b.innerHTML = '<div class="tiny muted">Loading…</div>';
  var ready = _matrix ? Promise.resolve(_matrix) : apicall('/api/attack/matrix').then(function(m) { _matrix = m; return m; });
  ready.then(function(m) {
    _idx = techniqueIndex({ scenarios: state.scenarios, matrix: m });
    paintList('');
  }).catch(function() {
    if (body()) body().innerHTML = '<div class="tt-note">The ATT&amp;CK dataset could not be loaded, so techniques cannot be listed right now.</div>';
  });
}

export function closeTechniqueCatalog() {
  var o = document.getElementById('scn-tech-overlay');
  if (o) o.classList.remove('open');
}
export function closeTechniqueCatalogOnBackdrop(el, event) { if (event.target === el) closeTechniqueCatalog(); }

export function techniqueSearch(el) { if (_idx) paintList(el ? el.value : ''); }

export function techniqueListHtml(idx, q) {
  var f = filterIndex(idx, q);
  var head = '<div class="tt-summary"><b>' + f.total + '</b> technique' + (f.total === 1 ? '' : 's') + ' across <b>' + f.tacticCount + '</b> tactic' + (f.tacticCount === 1 ? '' : 's') + '</div>' +
    '<input type="search" id="scn-tech-q" class="tt-search" placeholder="Search technique ID or name" value="' + x(q || '') + '" data-on-input="techniqueSearch">';
  var groups = f.tactics.map(function(t) {
    return '<section class="tt-group"><h4>' + x(t.name) + ' <span>' + t.items.length + '</span></h4>' +
      t.items.map(function(i) {
        return '<button type="button" class="tt-row"' + on('click', 'openTechniqueDetail', i.id) + '>' +
          '<span class="tt-id">' + x(i.id) + '</span><span class="tt-name">' + x(i.name) + '</span>' +
          '<span class="tt-count">' + i.count + ' scenario' + (i.count === 1 ? '' : 's') + '</span></button>';
      }).join('') + '</section>';
  }).join('');
  var unknown = f.unknown.length ? '<section class="tt-group"><h4>Not in the ATT&amp;CK dataset <span>' + f.unknown.length + '</span></h4>' +
    '<div class="tt-note">These ids are used by scenarios but are not in the ATT&amp;CK data this build ships (a custom or retired id), so no MITRE details exist for them.</div>' +
    f.unknown.map(function(u) { return '<div class="tt-row tt-row-static"><span class="tt-id">' + x(u.id) + '</span><span class="tt-count">' + u.count + ' scenario' + (u.count === 1 ? '' : 's') + '</span></div>'; }).join('') + '</section>' : '';
  var empty = !groups && !unknown ? '<div class="tt-note">' + (q ? 'No technique matches “' + x(q) + '”.' : 'No scenario declares an ATT&amp;CK technique yet.') + '</div>' : '';
  return head + groups + unknown + empty;
}

function paintList(q) {
  setTitle('ATT&CK techniques in your scenarios');
  var b = body();
  if (!b || !_idx) return;
  b.innerHTML = techniqueListHtml(_idx, q);
  var s = document.getElementById('scn-tech-q');
  if (s && q) { s.focus(); s.setSelectionRange(q.length, q.length); }
}

function chips(list, cls) {
  return (list || []).map(function(v) { return '<span class="tt-chip' + (cls ? ' ' + cls : '') + '">' + x(v) + '</span>'; }).join('');
}
function block(title, inner) { return inner ? '<section class="tt-sec"><h5>' + x(title) + '</h5>' + inner + '</section>' : ''; }

export function techniqueDetailHtml(e, users) {
  var url = safeMitreUrl(e.url);
  var desc = paragraphs(e.description).map(function(p) { return '<p>' + x(p) + '</p>'; }).join('');
  var det = paragraphs(e.detection).map(function(p) { return '<p>' + x(p) + '</p>'; }).join('');
  var mits = (e.mitigations || []).map(function(m) {
    return '<li><b>' + x(m.name || '') + '</b>' + (m.desc ? '<span>' + x(paragraphs(m.desc)[0] || '') + '</span>' : '') + '</li>';
  }).join('');
  var d3 = (e.d3fend || []).map(function(c) { return x(c.name || c.id || ''); }).filter(Boolean);
  var meta = [];
  if (e.version) meta.push('ATT&CK version ' + x(e.version));
  if (e.modified) meta.push('modified ' + x(e.modified));
  var who = (users || []).map(function(u) { return '<li>' + x(u.name) + '</li>'; }).join('');
  return '<button type="button" class="tt-back" data-on-click="techniqueBack">&larr; All techniques</button>' +
    '<div class="tt-hero"><span class="tt-id tt-id-lg">' + x(e.id) + '</span><h3>' + x(e.name || e.id) + '</h3>' +
    '<div class="tt-chips">' + chips(e.tactics, 'tt-tactic') + '</div>' +
    (meta.length ? '<div class="tiny muted">' + meta.join(' · ') + '</div>' : '') + '</div>' +
    block('Description', desc) +
    block('Platforms', chips(e.platforms)) +
    block('Permissions required', chips(e.permissions)) +
    block('Data sources', chips(e.dataSources)) +
    block('How to detect it', det) +
    block('Mitigations', mits ? '<ul class="tt-list">' + mits + '</ul>' : '') +
    block('Known groups', chips(e.groups)) +
    block('Known software', chips(e.software)) +
    block('D3FEND countermeasures', chips(d3)) +
    block('CAPEC', chips(e.capec)) +
    block('Used by these scenarios', who ? '<ul class="tt-list tt-plain">' + who + '</ul>' : '') +
    (url ? '<a class="tt-link" href="' + x(url) + '" target="_blank" rel="noopener noreferrer">View on attack.mitre.org &rarr;</a>' : '');
}

export function openTechniqueDetail(id) {
  var b = body();
  if (!b) return;
  setTitle(id);
  b.innerHTML = '<div class="tiny muted">Loading…</div>';
  var ready = _detail[id] ? Promise.resolve(_detail[id]) : apicall('/api/attack/technique/' + encodeURIComponent(id)).then(function(e) { _detail[id] = e; return e; });
  ready.then(function(e) {
    setTitle(e.id || id);
    b.innerHTML = techniqueDetailHtml(e, _idx && _idx.users[id]);
  }).catch(function() {
    b.innerHTML = '<button type="button" class="tt-back" data-on-click="techniqueBack">&larr; All techniques</button>' +
      '<div class="tt-note">No MITRE details are available for ' + x(id) + '.</div>';
  });
}

// Back returns to the list; when the detail was opened from elsewhere (a scenario's technique chip) there is no list to
// return to, so it closes the panel.
export function techniqueBack() { if (_idx) paintList(''); else closeTechniqueCatalog(); }
