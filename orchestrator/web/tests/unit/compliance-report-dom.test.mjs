import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

// Drives the real report screen with a report as the API now sends it: what is shown must be a resistance rate with
// its coverage, never "compliant", with the technique-level statuses and the mapping warning.

const report = {
  framework: { id: 'RBI_CSF', name: 'RBI Framework', version: '2026', mappingWarning: 'Not verified against the 2026 directions.' },
  agentId: 'agent-1', narrative: 'Resistance rate 100%: 1 of 1 tested controls resisted the techniques executed.',
  summary: { totalControls: 25, testableControls: 19, manualControls: 6, testedControls: 1, passingControls: 1, failingControls: 0,
    untestedControls: 18, coveragePct: 5.26, compliancePct: 100, resistedControls: 0, partialControls: 1, inconclusiveControls: 2,
    techniquesMapped: 57, techniquesTested: 1, sufficientCoverage: false, coverageNote: 'Insufficient coverage for framework-level conclusions' },
  domains: [{ name: 'Protect', total: 4, passing: 1, failing: 0, untested: 3, manual: 0, compliancePct: 100, resisted: 0, partial: 1, inconclusive: 0 }],
  controls: [
    { id: 'C1', name: 'Partial one', domain: 'Protect', testable: true, status: 'partial', tested: 1, passed: 1, failed: 0, techniquesMapped: 3, techniquesTested: 1,
      evidence: [{ techniqueId: 'T1001', result: 'pass', details: '' }, { techniqueId: 'T1002', result: 'error', details: 'could not run' }] },
    { id: 'C2', name: 'Done', domain: 'Protect', testable: true, status: 'resisted', tested: 2, passed: 2, failed: 0, techniquesMapped: 2, techniquesTested: 2, evidence: [] },
    { id: 'C3', name: 'Broke', domain: 'Protect', testable: true, status: 'failed', tested: 1, passed: 0, failed: 1, techniquesMapped: 2, techniquesTested: 1, evidence: [] },
    { id: 'C4', name: 'Errored', domain: 'Protect', testable: true, status: 'inconclusive', tested: 0, passed: 0, failed: 0, techniquesMapped: 1, techniquesTested: 0, evidence: [] },
  ],
};

async function open() {
  setupDom();
  globalThis.fetch = async () => ({ status: 200, ok: true, json: async () => report, text: async () => JSON.stringify(report) });
  const fns = await load(['loadComplianceReport', 'filterControls']);
  document.getElementById('cmp-agent-sel').innerHTML = '<option value="agent-1">a</option>';
  document.getElementById('cmp-fw-sel').innerHTML = '<option value="RBI_CSF">RBI</option>';
  fns.loadComplianceReport();
  await new Promise((r) => setTimeout(r, 20));
  return fns;
}

test('the report shows a resistance rate with coverage, the caveats, and never says compliant', async () => {
  await open();
  const text = document.getElementById('cmp-report').textContent;
  assert.match(text, /resistance rate/i);
  assert.match(text, /Control coverage1 of 19 \(5\.3%\)|Control coverage\s*1 of 19/);
  assert.match(text, /Techniques tested\s*1 of 57/);
  assert.match(text, /Insufficient coverage for framework-level conclusions/);
  assert.match(text, /Mapping note/);
  assert.doesNotMatch(text, /compliant/i);
});

test('each control shows its status in the new vocabulary and how many techniques were tested', async () => {
  await open();
  const rows = [...document.querySelectorAll('#cmp-controls-body tr')].map((r) => r.textContent);
  assert.match(rows[0], /Partial/);
  assert.match(rows[0], /1 of 3 mapped techniques tested/);
  assert.match(rows[1], /Resisted/);
  assert.match(rows[2], /Failed/);
  assert.match(rows[3], /Inconclusive/);
});

test('the filter tabs use the new statuses and filter by them', async () => {
  const fns = await open();
  const filters = [...document.querySelectorAll('.cmp-ftab')].map((b) => b.dataset.filter);
  assert.deepEqual(filters, ['', 'resisted', 'partial', 'failed', 'inconclusive', 'untested', 'manual']);
  fns.filterControls('failed');
  const rows = [...document.querySelectorAll('#cmp-controls-body tr')];
  assert.equal(rows.length, 1);
  assert.match(rows[0].textContent, /Broke/);
});

test('a control shows the paragraph of the regulator text it comes from', async () => {
  const withRef = JSON.parse(JSON.stringify(report));
  withRef.controls[0].reference = '¶110, ¶114';
  setupDom();
  globalThis.fetch = async () => ({ status: 200, ok: true, json: async () => withRef, text: async () => JSON.stringify(withRef) });
  const fns = await load(['loadComplianceReport']);
  document.getElementById('cmp-agent-sel').innerHTML = '<option value="agent-1">a</option>';
  document.getElementById('cmp-fw-sel').innerHTML = '<option value="RBI_CSF">RBI</option>';
  fns.loadComplianceReport();
  await new Promise((r) => setTimeout(r, 20));
  const first = document.querySelector('#cmp-controls-body tr').textContent;
  assert.match(first, /source ¶110, ¶114/);
});
