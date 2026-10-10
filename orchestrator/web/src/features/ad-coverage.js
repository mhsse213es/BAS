import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';

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

function badge(map, val) {
  var hit = map[val] || ['s-retired', (val || 'unknown')];
  return '<span class="sbadge ' + hit[0] + '">' + x(hit[1]) + '</span>';
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

// renderADCoverage is a pure render from a coverage report (as returned by
// /api/ad/coverage). Exported so it is unit-testable with crafted data,
// including hostile strings in names/evidence.
export function renderADCoverage(report) {
  var caps = (report && report.capabilityStates) || [];
  var sum = (report && report.capabilityStateSummary) || {};
  var content = (report && report.contentSummary) || {};

  renderDisclaimer(sum);
  renderSummary(sum, content);
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
  el.className = 'empty u-warning u-mb-1';
  el.innerHTML =
    '<strong>Modeled / content coverage — not validated against real Active Directory.</strong> ' +
    x(String(executed)) + ' capabilities executed and ' + x(String(detected)) +
    ' detection-validated. Content availability and scenario composition do not imply a technique has run against, or been detected in, a real domain.';
}

function renderSummary(sum, content) {
  var el = document.getElementById('adc-summary');
  if (!el) return;
  function tile(label, val, cls) {
    return '<div class="ca-card"><div class="ca-label">' + x(label) + '</div>' +
      '<div class="ca-val ' + (cls || '') + '">' + x(String(val == null ? '—' : val)) + '</div></div>';
  }
  el.innerHTML =
    tile('Capabilities', sum.total == null ? '—' : sum.total) +
    tile('Modeled', sum.modeled == null ? '—' : sum.modeled) +
    tile('Scenario-composed', sum.scenarioComposed == null ? '—' : sum.scenarioComposed) +
    tile('Executed vs real AD', sum.executed || 0, (sum.executed ? 'u-success' : 'u-muted')) +
    tile('Detection-validated', sum.detectionValidated || 0, (sum.detectionValidated ? 'u-success' : 'u-muted')) +
    tile('Reusable content', content.reusableUnmapped == null ? '—' : content.reusableUnmapped, 'u-muted');
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
    '<div class="u-mb-1"><span class="u-muted">Family:</span> ' + pfSet('family', famOpts, _adFilter.family) + '</div>' +
    '<div class="u-mb-1"><span class="u-muted">Content:</span> ' + pfSet('content', contentOpts, _adFilter.content) + '</div>' +
    '<div class="u-mb-1"><span class="u-muted">Execution:</span> ' + pfSet('exec', execOpts, _adFilter.exec) + '</div>';
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
    el.innerHTML = '<div class="empty">No AD capabilities reported.</div>';
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
        '<span class="tag">' + x(c.family || '—') + '</span> ' +
        badge(CONTENT_BADGE, c.contentAvailability) + ' ' +
        '<span class="sbadge ' + (c.scenarioComposed ? 's-active' : 's-idle') + '">' + (c.scenarioComposed ? 'Composed' : 'Not composed') + '</span> ' +
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
  }).join('') || '<div class="empty">No capabilities match the current filters.</div>';
  if (foot) foot.textContent = 'Showing ' + rows.length + ' of ' + caps.length + ' capabilities · states read from /api/ad/coverage; nothing is executed by this view.';
}
