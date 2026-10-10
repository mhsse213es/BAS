import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load, PAYLOADS } from './dom.mjs';

setupDom();
const { renderADCoverage, loadADCoverage, setADFilter, exportADReportPDF, exportADReportJSON } =
  await load(['renderADCoverage', 'loadADCoverage', 'setADFilter', 'exportADReportPDF', 'exportADReportJSON']);
const tick = () => new Promise((r) => setTimeout(r, 0));

function assertInert(container, label) {
  assert.equal(container.querySelector('img,svg,script,iframe'), null, `${label}: payload created an element`);
  for (const el of container.querySelectorAll('*')) {
    for (const a of el.attributes) assert.ok(!/^on/i.test(a.name) || !/__xss/.test(a.value), `${label}: payload created ${a.name}`);
  }
  assert.equal(globalThis.__xss, undefined, `${label}: payload executed`);
}

function cap(over) {
  return Object.assign({
    primitiveId: 'acl-genericall-takeover', name: 'ACL GenericAll takeover', techniqueId: 'T1069',
    family: 'ACL', modeled: true, contentAvailability: 'model-only', scenarioComposed: false,
    executionValidation: 'not_executed', detectionValidation: 'not_validated', riskClass: 'non_destructive',
    prerequisites: { domainJoined: true, capabilities: [{ kind: 'domain-user' }] },
    evidenceRequirements: ['some evidence'], limitations: ['not executed against a real domain'], outstanding: ['integrate into a scenario'],
  }, over || {});
}
function report(caps, over) {
  return Object.assign({
    capabilityStates: caps,
    capabilityStateSummary: { total: caps.length, modeled: caps.length, scenarioComposed: 0, executed: 0, detectionValidated: 0 },
    contentSummary: { total: caps.length, scenarioComposable: 0, reusableUnmapped: 0, modelOnly: caps.length, missingExecutableContent: 0 },
  }, over || {});
}

test('renders one expandable row per capability with its family and technique', () => {
  renderADCoverage(report([cap(), cap({ primitiveId: 'dcsync', name: 'DCSync', family: 'DCSync', contentAvailability: 'reusable-unmapped' })]));
  const list = document.getElementById('adc-list');
  assert.equal(list.querySelectorAll('details.adc-cap').length, 2);
  assert.ok(list.textContent.includes('ACL GenericAll takeover'));
  assert.ok(list.textContent.includes('T1069'));
  assert.ok(list.textContent.includes('DCSync'));
});

test('default not-executed / not-validated capability is never shown as executed or detection-confirmed', () => {
  renderADCoverage(report([cap()]));
  const t = document.getElementById('adc-list').textContent;
  assert.ok(t.includes('Not executed'), 'shows Not executed');
  assert.ok(t.includes('Not validated'), 'shows Not validated');
  assert.ok(!/\bCompleted\b/.test(t), 'must not label a not_executed capability Completed');
  // The persistent disclaimer states the executed/detection-validated counts.
  const d = document.getElementById('adc-disclaimer').textContent;
  assert.ok(/0 capabilities executed/.test(d) && /0 detection-validated/.test(d), 'disclaimer states the real validated counts');
});

test('an unknown axis value is surfaced (fail-closed), not silently dropped', () => {
  renderADCoverage(report([cap({ contentAvailability: 'some-future-state', executionValidation: 'weird' })]));
  const t = document.getElementById('adc-list').textContent;
  assert.ok(t.includes('some-future-state'), 'unknown content state shown verbatim');
  assert.ok(t.includes('weird'), 'unknown execution state shown verbatim');
});

test('aggregate count in the footer is consistent with rows rendered', () => {
  renderADCoverage(report([cap(), cap({ primitiveId: 'x' }), cap({ primitiveId: 'y' })]));
  assert.ok(document.getElementById('adc-foot').textContent.includes('Showing 3 of 3 capabilities'));
});

test('hostile strings in names, evidence, limitations and provenance stay inert and are shown as text', () => {
  for (const p of PAYLOADS) {
    globalThis.__xss = undefined;
    renderADCoverage(report([cap({ name: p, family: p, techniqueId: p, evidenceRequirements: [p], limitations: [p], outstanding: [p], contentSource: p, contentReason: p })]));
    const list = document.getElementById('adc-list');
    assertInert(list, 'renderADCoverage');
    assert.ok(list.textContent.includes(p), 'payload text is preserved as inert text');
  }
});

test('loadADCoverage reads both endpoints and flags an INCOMPLETE live inventory', async () => {
  globalThis.fetch = async (url) => {
    if (String(url).includes('/api/ad/coverage')) return { status: 200, ok: true, json: async () => report([cap()]) };
    if (String(url).includes('/api/ad/content-inventory')) return { status: 200, ok: true, json: async () => ({ artStoreLoaded: true, calderaStoreLoaded: false, artTechniques: 5, note: 'only one store attached' }) };
    return { status: 404, ok: false, json: async () => ({}) };
  };
  loadADCoverage();
  await tick(); await tick(); await tick();
  const note = document.getElementById('adc-inventory-note').textContent;
  assert.ok(/INCOMPLETE/.test(note), 'partial store set must read as incomplete');
  assert.ok(/verified absence/.test(note), 'must warn that missing != verified absence');
});

test('a failed (e.g. unauthorized) content-inventory call does not blank the page', async () => {
  globalThis.fetch = async (url) => {
    if (String(url).includes('/api/ad/coverage')) return { status: 200, ok: true, json: async () => report([cap()]) };
    throw new Error('forbidden');
  };
  loadADCoverage();
  await tick(); await tick(); await tick();
  assert.ok(document.getElementById('adc-list').querySelectorAll('details.adc-cap').length === 1, 'capabilities still render');
  assert.ok(/unavailable/.test(document.getElementById('adc-inventory-note').textContent), 'inventory note explains the gap');
});

test('report exports open the server-generated PDF and JSON assessment endpoints', () => {
  const opened = [];
  const orig = globalThis.window.open;
  globalThis.window.open = (url) => { opened.push(url); };
  try {
    exportADReportPDF();
    exportADReportJSON();
  } finally {
    globalThis.window.open = orig;
  }
  assert.deepEqual(opened, ['/api/ad/assessment.pdf', '/api/ad/assessment.json']);
});

test('setADFilter by family narrows the rendered rows', async () => {
  globalThis.fetch = async (url) => {
    if (String(url).includes('/api/ad/coverage')) return { status: 200, ok: true, json: async () => report([cap({ family: 'ACL' }), cap({ primitiveId: 'd', family: 'DCSync' })]) };
    return { status: 200, ok: true, json: async () => ({ artStoreLoaded: true, calderaStoreLoaded: true, artTechniques: 1 }) };
  };
  loadADCoverage();
  await tick(); await tick(); await tick();
  assert.equal(document.getElementById('adc-list').querySelectorAll('details.adc-cap').length, 2);
  setADFilter('family', 'DCSync');
  assert.equal(document.getElementById('adc-list').querySelectorAll('details.adc-cap').length, 1);
  setADFilter('family', 'all');
});
