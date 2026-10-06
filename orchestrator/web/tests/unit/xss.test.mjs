import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load, PAYLOADS } from './dom.mjs';

setupDom();
const { initiativeStateLabel, openAdvDrawer, openFinding, renderRunReportExtra, renderVariantCoverage, complianceTile } =
  await load(['initiativeStateLabel', 'openAdvDrawer', 'openFinding', 'renderRunReportExtra', 'renderVariantCoverage', 'complianceTile']);
const tick = () => new Promise((r) => setTimeout(r, 0));

function assertInert(container, label) {
  assert.equal(container.querySelector('img,svg,script,iframe'), null, `${label}: payload created an element`);
  for (const el of container.querySelectorAll('*')) {
    for (const a of el.attributes) assert.ok(!/^on/i.test(a.name) || !/__xss/.test(a.value), `${label}: payload created ${a.name} on <${el.tagName}>`);
  }
  assert.equal(globalThis.__xss, undefined, `${label}: payload executed`);
}

test('initiativeStateLabel escapes unknown states', () => {
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = initiativeStateLabel(p);
    assertInert(div, 'initiativeStateLabel');
    assert.equal(div.textContent, p);
  }
});

test('openAdvDrawer: unknown adversary id and ability text stay inert', async () => {
  for (const p of PAYLOADS) {
    globalThis.fetch = async () => ({ status: 200, json: async () => ({ abilities: [{ name: p, description: p, tactic: 'discovery', platforms: [p] }] }) });
    openAdvDrawer(p);
    await tick(); await tick();
    assertInert(document.getElementById('adv-drawer'), 'openAdvDrawer');
    assert.ok(document.getElementById('adv-drawer').textContent.includes('__xss'), 'openAdvDrawer: fixture did not render');
  }
});

test('openFinding: finding fields stay inert in the results drawer', async () => {
  for (const p of PAYLOADS) {
    globalThis.fetch = async () => ({ status: 200, json: async () => ({ id: p, techniqueId: p, techniqueName: p, status: 'open', severity: p, enrichment: {} }) });
    openFinding(p);
    await tick(); await tick();
    assertInert(document.getElementById('results-overlay'), 'openFinding');
    assert.ok(document.getElementById('results-overlay').textContent.includes('__xss'), 'openFinding: fixture did not render');
  }
});

test('renderRunReportExtra: attack-surface and restoration fields stay inert', () => {
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = renderRunReportExtra({
      attackSurfaceAge: 5, oldestFindingID: p, oldestFindingName: p, oldestFindingSeverity: p,
      envRestoration: { impactLevel: 'clean', statusLabel: p, impactLabel: p, cleanupRate: 100, stepsLeaked: 0, stepsCleaned: 1, execSummary: p },
    });
    assertInert(div, 'renderRunReportExtra');
    assert.ok(div.textContent.includes(p), 'payload text should be rendered as text');
  }
});

test('variant-report: renderVariantCoverage keeps payloads inside data-args', () => {
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = renderVariantCoverage({
      runId: p, variantDepth: 'quick', summary: {},
      techniques: [{ techniqueId: p, techniqueName: p, hasBypass: true, bypassRate: 50, headline: p, remediationPoints: [p], bestBypass: { encoding: p, verdict: 'bypassed' } }],
    });
    assertInert(div, 'renderVariantCoverage');
    const args = [...div.querySelectorAll('[data-args]')].map((e) => e.getAttribute('data-args')).join(' ');
    assert.ok(args.includes(JSON.stringify(p).slice(1, -1)), 'payload should travel as data-args');
  }
});

test('compliance: complianceTile keeps payloads inside data-args', () => {
  for (const p of PAYLOADS) {
    const div = document.createElement('div');
    div.innerHTML = complianceTile({ frameworkId: p, agentId: p, frameworkName: p, testedControls: 1, passingControls: 1, compliancePct: 100 });
    assertInert(div, 'complianceTile');
    const args = [...div.querySelectorAll('[data-args]')].map((e) => e.getAttribute('data-args')).join(' ');
    assert.ok(args.includes(JSON.stringify(p).slice(1, -1)), 'payload should travel as data-args');
  }
});
