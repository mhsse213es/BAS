import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { kpi, grid, card, chip, hbars, empty } from '../core/kit.js';
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

// Badge maps: value -> [sbadge-modifier, label]. Every map falls back to a grey
// "unknown" badge so an unexpected API value is shown honestly, never dropped.
var CONTENT_BADGE = {
  'scenario-composable': ['s-active', 'Scenario-composable'],
  'reusable-unmapped': ['s-restricted', 'Reusable (unmapped)'],
  'model-only': ['s-idle', 'Model-only'],
  'missing-executable-content': ['s-quarantined', 'Missing content'],
};
var EXEC_BADGE = {
  'not_executed': ['s-idle', 'Not executed'],
  'execution_attempted': ['s-restricted', 'Attempted'],
  'execution_completed': ['s-active', 'Completed'],
  'postcondition_verified': ['s-active', 'Postcondition verified'],
};
var DET_BADGE = {
  'not_validated': ['s-idle', 'Not validated'],
  'simulated_evidence_only': ['s-restricted', 'Simulated only'],
  'telemetry_observed': ['s-active', 'Telemetry observed'],
};
var RISK_BADGE = {
  'non_destructive': ['s-idle', 'Non-destructive'],
  'potentially_destructive': ['s-restricted', 'Potentially destructive'],
  'destructive': ['s-quarantined', 'Destructive'],
};

var BADGE_TONE = { 's-active': 'ok', 's-restricted': 'warn', 's-idle': 'muted', 's-quarantined': 'bad', 's-retired': 'muted' };
function badge(map, val) {
  var hit = map[val] || ['s-retired', (val || 'unknown')];
  return chip(hit[1], BADGE_TONE[hit[0]] || 'muted');
}

// adDistribution: how many capabilities fall in each value of one axis (counted from the report
// itself; nothing is classified here). Unknown values keep their own bucket.
export function adDistribution(caps, field, dflt) {
  var out = {};
  (caps || []).forEach(function(c) {
    if (!c) return;
    var v = c[field] || dflt || 'unknown';
    out[v] = (out[v] || 0) + 1;
  });
  return out;
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

  renderDisclaimer(sum);
  renderSummary(sum, content, caps);
  renderInventoryNote();
  renderFilters(caps);
  renderList(caps);
}

// A persistent, unmissable statement of the gap between modeled coverage and
// genuinely validated AD security -- the whole point of this view.
function renderDisclaimer(sum) {
  var el = document.getElementById('adc-disclaimer');
  if (!el) return;
  var executed = sum.executed || 0;
  var detected = sum.detectionValidated || 0;
  el.className = 'rg2-alert';
  el.innerHTML =
    '<strong>Modeled / content coverage — not validated against real Active Directory.</strong> ' +
    x(String(executed)) + ' capabilities executed and ' + x(String(detected)) +
    ' detection-validated. Content availability and scenario composition do not imply a technique has run against, or been detected in, a real domain.';
}

function renderSummary(sum, content, caps) {
  var el = document.getElementById('adc-summary');
  if (!el) return;
  var n = function(v) { return v == null ? '—' : v; };
  var tiles = grid(3, [
    kpi({ label: 'Capabilities', value: n(sum.total), icon: 'shield', tone: 'accent' }),
    kpi({ label: 'Modeled', value: n(sum.modeled), icon: 'layers', tone: 'info' }),
    kpi({ label: 'Scenario-composed', value: n(sum.scenarioComposed), icon: 'path', tone: 'violet' }),
    kpi({ label: 'Executed vs real AD', value: sum.executed || 0, icon: 'play', tone: sum.executed ? 'ok' : 'muted' }),
    kpi({ label: 'Detection-validated', value: sum.detectionValidated || 0, icon: 'eye', tone: sum.detectionValidated ? 'ok' : 'muted' }),
    kpi({ label: 'Reusable content', value: n(content.reusableUnmapped), icon: 'file', tone: 'muted' }),
  ]);
  var charts = '';
  if (caps && caps.length) {
    var cd = adDistribution(caps, 'contentAvailability', 'unknown');
    var cMap = { 'scenario-composable': ['Composable', CHART_COLORS.ok], 'reusable-unmapped': ['Reusable (unmapped)', CHART_COLORS.info], 'model-only': ['Model-only', CHART_COLORS.muted], 'missing-executable-content': ['Missing content', CHART_COLORS.bad] };
    var cSegs = Object.keys(cd).map(function(k) { return { label: (cMap[k] || [k])[0], value: cd[k], color: (cMap[k] || [0, CHART_COLORS.warn])[1] }; });
    var fam = adDistribution(caps, 'family', '—');
    var famKeys = Object.keys(fam).sort(function(p, q) { return fam[q] - fam[p]; });
    charts = grid(2, [
      card('Content availability', chartSlot({ type: 'donut', segments: cSegs, center: String(caps.length), centerSub: 'capabilities', legend: true, h: 150 })),
      card('Capabilities by family', hbars(famKeys.slice(0, 8).map(function(k) { return [k, fam[k] / caps.length * 100, 'accent', fam[k]]; }))),
    ]);
  }
  el.innerHTML = tiles + charts;
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
  var famSet = {};
  caps.forEach(function(c) { if (c && c.family) famSet[c.family] = true; });
  var famOpts = [['all', 'All families']].concat(Object.keys(famSet).sort().map(function(f) { return [f, f]; }));
  var contentOpts = [['all', 'All content'], ['scenario-composable', 'Composable'], ['reusable-unmapped', 'Reusable'], ['model-only', 'Model-only'], ['missing-executable-content', 'Missing']];
  var execOpts = [['all', 'All execution'], ['not_executed', 'Not executed'], ['execution_completed', 'Executed'], ['postcondition_verified', 'Verified']];
  el.innerHTML =
    '<div class="rg2-filter-card">' +
    '<div class="rg2-filter-row"><span class="u-muted">Family</span><div>' + pfSet('family', famOpts, _adFilter.family) + '</div></div>' +
    '<div class="rg2-filter-row"><span class="u-muted">Content</span><div>' + pfSet('content', contentOpts, _adFilter.content) + '</div></div>' +
    '<div class="rg2-filter-row"><span class="u-muted">Execution</span><div>' + pfSet('exec', execOpts, _adFilter.exec) + '</div></div>' +
    '</div>';
}

function applyFilter(caps) {
  return caps.filter(function(c) {
    if (!c) return false;
    if (_adFilter.family !== 'all' && c.family !== _adFilter.family) return false;
    if (_adFilter.content !== 'all' && c.contentAvailability !== _adFilter.content) return false;
    if (_adFilter.exec !== 'all' && (c.executionValidation || 'not_executed') !== _adFilter.exec) return false;
    return true;
  });
}

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
  el.innerHTML = rows.map(function(c) {
    var postconds = (c.expectedPostconditions || []).map(function(pc) { return (pc && pc.kind ? pc.kind : '') + (pc && pc.target ? '@' + pc.target : ''); });
    var provenance = [];
    if (c.contentSource) provenance.push('Source: ' + c.contentSource);
    if (c.contentReason) provenance.push('Reason: ' + c.contentReason);
    return '<details class="adc-cap">' +
      '<summary>' +
        '<span class="u-fw600">' + x(c.name || c.primitiveId || '—') + '</span> ' +
        '<span class="u-muted">' + x(c.primitiveId || '') + (c.techniqueId ? ' · ' + x(c.techniqueId) : '') + '</span> ' +
        chip(c.family || '—', 'accent') + ' ' +
        badge(CONTENT_BADGE, c.contentAvailability) + ' ' +
        chip(c.scenarioComposed ? 'Composed' : 'Not composed', c.scenarioComposed ? 'ok' : 'muted') + ' ' +
        badge(EXEC_BADGE, c.executionValidation || 'not_executed') + ' ' +
        badge(DET_BADGE, c.detectionValidation || 'not_validated') + ' ' +
        badge(RISK_BADGE, c.riskClass) +
      '</summary>' +
      '<div class="u-mt-06">' +
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
  }).join('') || empty('filter', 'No capabilities match the current filters');
  if (foot) foot.textContent = 'Showing ' + rows.length + ' of ' + caps.length + ' capabilities · states read from /api/ad/coverage; nothing is executed by this view.';
}
