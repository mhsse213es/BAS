import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { kpi, card, chip, hbars, empty, icon } from '../core/kit.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './adc-model.js';
import { chartSlot, CHART_COLORS } from '../core/charts.js';

// ── Active Directory Coverage ────────────────────────────────────────────────
// Dedicated AD capability-coverage view. It is intentionally separate from
// coverage.js (which is run-verdict ATT&CK coverage): the AD model is a
// per-capability record with five INDEPENDENT axes (modeled / content-available
// / scenario-composed / execution-validated / detection-validated) plus
// prerequisites, cleanup, evidence and honest limitations. Everything is read
// from /api/ad/coverage and /api/ad/content-inventory as the source of truth;
// this module classifies nothing and never promotes a validation state.

var _adData = null;        // last /api/ad/coverage report
var _adInv = null;         // last /api/ad/content-inventory response (or null)
var _adInvError = false;   // content-inventory call failed (e.g. no permission)
var _adFilter = { family: 'all', content: 'all', exec: 'all' };

function badge(ax) { return chip(ax.label, ax.tone); }

// adDistribution: how many capabilities fall in each value of one axis (counted from the report
// itself; nothing is classified here). Unknown values keep their own bucket.
export function adDistribution(caps, field, dflt) {
  return M.distribution(caps, field, dflt);
}

export function loadADCoverage() {
  // Two independent reads. Coverage is always available; content-inventory is
  // permission-gated, so a failure there must NOT blank the page -- it only
  // means the live-store completeness note can't be shown.
  apicall('/api/ad/coverage').then(function(d) {
    _adData = d || null;
    return apicall('/api/ad/content-inventory').then(function(inv) {
      _adInv = inv || null; _adInvError = false;
    }).catch(function() {
      _adInv = null; _adInvError = true;
    });
  }).then(function() {
    renderADCoverage(_adData);
  }).catch(function(e) {
    var list = document.getElementById('adc-list');
    if (list) list.innerHTML = '<div class="empty u-danger">Failed to load AD coverage: ' + x(e && e.message ? e.message : 'request failed') + '</div>';
  });
}

export function setADFilter(dim, val) {
  _adFilter[dim] = val;
  renderADCoverage(_adData);
}

// Report exports open the server-generated assessment report, built from the
// SAME /api/ad/coverage data this view renders (no separate client tallies):
// PDF is the primary enterprise deliverable, JSON the machine-readable export.
export function exportADReportPDF() { window.open('/api/ad/assessment.pdf', '_blank'); }
export function exportADReportJSON() { window.open('/api/ad/assessment.json', '_blank'); }

// renderADCoverage is a pure render from a coverage report (as returned by
// /api/ad/coverage). Exported so it is unit-testable with crafted data,
// including hostile strings in names/evidence.
export function renderADCoverage(report) {
  var caps = (report && report.capabilityStates) || [];
  var sum = (report && report.capabilityStateSummary) || {};
  var content = (report && report.contentSummary) || {};

  renderHero(sum);
  renderDisclaimer(sum);
  renderSummary(sum, content);
  renderFilters(caps);
  renderList(caps);
  renderCharts(caps);
  renderInventoryNote();
}

function renderHero(sum) {
  var h = M.heroStats(sum);
  var dash = function(v) { return v == null ? '—' : v; };
  setHeroStat('adc-hs-total', dash(h.capabilities));
  setHeroStat('adc-hs-composed', dash(h.composed));
  setHeroStat('adc-hs-executed', h.executed);
  setHeroStat('adc-hs-detected', h.detected);
}

// A persistent, unmissable statement of the gap between modeled coverage and
// genuinely validated AD security -- the whole point of this view. The report exports sit inside it.
function renderDisclaimer(sum) {
  var el = document.getElementById('adc-disclaimer');
  if (!el) return;
  var executed = sum.executed || 0;
  var detected = sum.detectionValidated || 0;
  el.className = 'adc-warn';
  el.innerHTML =
    '<div class="adc-warn-row">' + icon('alert') + '<div><strong>Modeled / content coverage — not validated against real Active Directory.</strong> ' +
    x(String(executed)) + ' capabilities executed and ' + x(String(detected)) +
    ' detection-validated. Content availability and scenario composition do not imply a technique has run against, or been detected in, a real domain.</div></div>' +
    '<div class="adc-warn-actions">' +
    '<button class="btn btn-outline btn-sm" data-on-click="exportADReportPDF" title="Download the enterprise assessment report (PDF)">Export PDF</button>' +
    '<button class="btn btn-outline btn-sm" data-on-click="exportADReportJSON" title="Download the assessment data (JSON)">JSON</button>' +
    '</div>';
}

function renderSummary(sum, content) {
  var el = document.getElementById('adc-summary');
  if (!el) return;
  el.innerHTML = '<div class="rk-grid adc-tiles">' + M.summaryTiles(sum, content).map(kpi).join('') + '</div>';
}

// Content-availability donut and capabilities-by-family bars, counted from the report itself.
function renderCharts(caps) {
  var el = document.getElementById('adc-charts');
  if (!el) return;
  if (!caps || !caps.length) { el.innerHTML = ''; return; }
  var cd = M.distribution(caps, 'contentAvailability', 'unknown');
  var cMap = { 'scenario-composable': ['Composable', CHART_COLORS.ok], 'reusable-unmapped': ['Reusable (unmapped)', CHART_COLORS.info], 'model-only': ['Model-only', CHART_COLORS.muted], 'missing-executable-content': ['Missing content', CHART_COLORS.bad] };
  var cSegs = Object.keys(cd).map(function(k) { return { label: (cMap[k] || [k])[0], value: cd[k], color: (cMap[k] || [0, CHART_COLORS.warn])[1] }; });
  var fam = M.distribution(caps, 'family', '—');
  var famKeys = Object.keys(fam).sort(function(p, q) { return fam[q] - fam[p]; });
  el.innerHTML = '<div class="rk-grid g2">' +
    card('Content availability', chartSlot({ type: 'donut', segments: cSegs, center: String(caps.length), centerSub: 'capabilities', legend: true, h: 150 })) +
    card('Capabilities by family', hbars(famKeys.slice(0, 8).map(function(k) { return [k, fam[k] / caps.length * 100, 'accent', fam[k]]; }))) +
    '</div>';
}

// Live ART/Caldera inventory completeness. Absent or partial stores must read
// as "incomplete", never as a verified absence of content.
function renderInventoryNote() {
  var el = document.getElementById('adc-inventory-note');
  if (!el) return;
  if (_adInvError) {
    el.className = 'u-muted u-mt-06';
    el.textContent = 'Live content inventory unavailable (requires permission); content-availability below reflects repository classification only.';
    return;
  }
  if (!_adInv) { el.textContent = ''; el.className = ''; return; }
  var both = _adInv.artStoreLoaded && _adInv.calderaStoreLoaded;
  el.className = (both ? 'u-muted' : 'u-warning') + ' u-mt-06';
  if (both) {
    el.textContent = 'Live inventory: ART and Caldera stores attached (' + (_adInv.artTechniques || 0) + ' ART techniques).';
  } else {
    el.textContent = 'Live inventory INCOMPLETE — ' +
      (_adInv.artStoreLoaded ? 'Caldera store not attached' : _adInv.calderaStoreLoaded ? 'ART store not attached' : 'no content stores attached') +
      '. "missing" means not found in the attached store(s), not a verified absence.' +
      (_adInv.note ? ' ' + _adInv.note : '');
  }
}

function pfSet(dim, options, active) {
  return options.map(function(o) {
    var on = o[0] === active ? ' active' : '';
    return '<button class="pfbtn' + on + '" data-on-click="setADFilter" data-args="[&quot;' + x(dim) + '&quot;,&quot;' + x(o[0]) + '&quot;]">' + x(o[1]) + '</button>';
  }).join(' ');
}

function renderFilters(caps) {
  var el = document.getElementById('adc-filters');
  if (!el) return;
  el.innerHTML =
    '<div class="adc-filters">' +
    '<div class="adc-frow"><span class="adc-flbl">Family</span><div class="adc-chips">' + pfSet('family', M.familyOptions(caps), _adFilter.family) + '</div></div>' +
    '<div class="adc-frow"><span class="adc-flbl">Content</span><div class="adc-chips">' + pfSet('content', M.CONTENT_OPTIONS, _adFilter.content) + '</div></div>' +
    '<div class="adc-frow"><span class="adc-flbl">Execution</span><div class="adc-chips">' + pfSet('exec', M.EXEC_OPTIONS, _adFilter.exec) + '</div></div>' +
    '</div>';
}

function applyFilter(caps) { return M.applyFilter(caps, _adFilter); }

function detailList(label, arr) {
  if (!arr || !arr.length) return '';
  return '<div class="u-mt-06"><span class="u-fw600">' + x(label) + '</span><ul>' +
    arr.map(function(s) { return '<li>' + x(String(s)) + '</li>'; }).join('') + '</ul></div>';
}

function prereqText(p) {
  if (!p) return '—';
  var parts = [];
  if (p.domainJoined) parts.push('domain-joined');
  (p.privileges || []).forEach(function(pr) { parts.push(String(pr)); });
  (p.capabilities || []).forEach(function(c) { parts.push((c && c.kind ? String(c.kind) : '') + (c && c.target ? '@' + c.target : '')); });
  if (p.conditions) { Object.keys(p.conditions).forEach(function(k) { if (p.conditions[k]) parts.push(k); }); }
  return parts.length ? parts.map(x).join(', ') : '—';
}

var HEAD = '<div class="adc-head"><span>Capability</span><span>Content</span><span>Composition</span><span>Execution</span><span>Validation</span><span>Safety</span></div>';

function renderList(caps) {
  var el = document.getElementById('adc-list');
  var foot = document.getElementById('adc-foot');
  if (!el) return;
  if (!caps.length) {
    el.innerHTML = empty('shield', 'No AD capabilities reported');
    if (foot) foot.textContent = '';
    return;
  }
  var rows = applyFilter(caps);
  var body = rows.map(function(c) {
    var postconds = (c.expectedPostconditions || []).map(function(pc) { return (pc && pc.kind ? pc.kind : '') + (pc && pc.target ? '@' + pc.target : ''); });
    var provenance = [];
    if (c.contentSource) provenance.push('Source: ' + c.contentSource);
    if (c.contentReason) provenance.push('Reason: ' + c.contentReason);
    return '<details class="adc-cap">' +
      '<summary>' +
        '<span class="adc-cell-cap"><b>' + x(c.name || c.primitiveId || '—') + '</b>' +
          '<span class="adc-id">' + x(c.primitiveId || '') + (c.techniqueId ? ' · ' + x(c.techniqueId) : '') + '</span>' +
          '<span class="adc-fam">' + x(c.family || '—') + '</span></span>' +
        '<span>' + badge(M.contentAxis(c.contentAvailability)) + '</span>' +
        '<span>' + badge(M.compositionAxis(c)) + '</span>' +
        '<span>' + badge(M.execAxis(c.executionValidation)) + '</span>' +
        '<span>' + badge(M.detAxis(c.detectionValidation)) + '</span>' +
        '<span>' + badge(M.riskAxis(c.riskClass)) + '</span>' +
      '</summary>' +
      '<div class="adc-detail">' +
        '<div><span class="u-fw600">Prerequisites:</span> ' + prereqText(c.prerequisites) + '</div>' +
        (postconds.length ? '<div><span class="u-fw600">Expected postconditions:</span> ' + postconds.map(x).join(', ') + '</div>' : '') +
        detailList('Evidence requirements', c.evidenceRequirements) +
        detailList('Telemetry sources', c.telemetrySources) +
        detailList('Cleanup', c.cleanup) +
        detailList('Limitations', c.limitations) +
        detailList('Outstanding work', c.outstanding) +
        (provenance.length ? detailList('Content provenance', provenance) : '') +
      '</div>' +
    '</details>';
  }).join('');
  el.innerHTML = body ? card('Capabilities', '<div class="adc-table">' + HEAD + body + '</div>') : empty('filter', 'No capabilities match the current filters');
  if (foot) foot.textContent = 'Showing ' + rows.length + ' of ' + caps.length + ' capabilities · states read from /api/ad/coverage; nothing is executed by this view.';
}
