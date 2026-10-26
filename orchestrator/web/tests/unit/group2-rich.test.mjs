import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { covTone, covOutcomeSegments, schedStatus, schedSummary, initiativeCounts, egSummary, egStatusTone, egOutcomeRows, vexCoverageTotals, adDistribution, k8sRunCounts, renderK8sRuns, metricTile } =
  await load(['covTone', 'covOutcomeSegments', 'schedStatus', 'schedSummary', 'initiativeCounts', 'egSummary', 'egStatusTone', 'egOutcomeRows', 'vexCoverageTotals', 'adDistribution', 'k8sRunCounts', 'renderK8sRuns', 'metricTile']);

test('covTone thresholds and odd input', () => {
  assert.equal(covTone(80), 'ok'); assert.equal(covTone(75), 'ok'); assert.equal(covTone(40), 'warn');
  assert.equal(covTone(39), 'bad'); assert.equal(covTone(undefined), 'bad'); assert.equal(covTone('x'), 'bad');
});

test('covOutcomeSegments drops zero buckets and tolerates missing summary', () => {
  assert.deepEqual(covOutcomeSegments(null), []);
  const s = covOutcomeSegments({ prevented: 3, detectedOnly: 0, missed: 2 });
  assert.deepEqual(s.map((g) => [g.label, g.value]), [['Prevented', 3], ['Missed', 2]]);
});

test('schedStatus: a fired one-time schedule is Completed, not Enabled', () => {
  assert.equal(schedStatus({ RecurrenceType: 'once', LastOccurrenceAt: '2026-01-01', Enabled: true }).key, 'completed');
  assert.equal(schedStatus({ RecurrenceType: 'daily', Enabled: true }).key, 'enabled');
  assert.equal(schedStatus({ RecurrenceType: 'daily', Enabled: false }).key, 'cancelled');
});

test('schedSummary counts by status, mode and recurrence', () => {
  const r = schedSummary([{ Enabled: true, Mode: 'telemetry', RecurrenceType: 'daily' }, { Enabled: false, RecurrenceType: '' }, null && {}].filter(Boolean));
  assert.equal(r.total, 2); assert.equal(r.enabled, 1); assert.equal(r.cancelled, 1); assert.equal(r.telemetry, 1); assert.equal(r.posture, 1);
  assert.equal(r.byRecurrence.weekly, 1);
  assert.equal(schedSummary(null).total, 0);
});

test('initiativeCounts keeps unknown states and unknown creators', () => {
  const c = initiativeCounts([{ State: 'active', CreatedBy: 'a' }, { State: 'weird' }, { State: 'closed', CreatedBy: 'a' }]);
  assert.equal(c.total, 3); assert.equal(c.active, 1); assert.equal(c.closed, 1); assert.equal(c.other, 1);
  assert.equal(c.byCreator.a, 2); assert.equal(c.byCreator.unknown, 1);
});

test('email summary and status tone', () => {
  const m = egSummary([{ status: 'completed' }, { status: 'failed' }, { status: 'pending' }, { status: 'running' }], [{ status: 'running' }]);
  assert.equal(m.runs, 4); assert.equal(m.runsActive, 2); assert.equal(m.campaignsRunning, 1);
  assert.equal(egStatusTone('completed'), 'ok'); assert.equal(egStatusTone('cancelled'), 'muted'); assert.equal(egStatusTone(undefined), 'muted');
});

test('egOutcomeRows: no runs gives an honest empty line, escapes nothing it does not own', () => {
  assert.match(egOutcomeRows({ outcomes: {} }), /No runs yet/);
  assert.match(egOutcomeRows({ outcomes: { confirmedSuccess: 3, confirmedFailure: 1 } }), /Success/);
});

test('vexCoverageTotals sums rows', () => {
  const t = vexCoverageTotals([{ totalTested: 10, prevented: 8, allowed: 1, errored: 1, firstBypass: 'x' }, { totalTested: 5, prevented: 5 }]);
  assert.deepEqual(t, { techniques: 2, tested: 15, prevented: 13, allowed: 1, errored: 1, bypassed: 1 });
  assert.equal(vexCoverageTotals(null).techniques, 0);
});

test('adDistribution buckets unknown values and defaults', () => {
  const d = adDistribution([{ family: 'ACL' }, { family: 'ACL' }, {}, null], 'family', '—');
  assert.deepEqual(d, { ACL: 2, '—': 1 });
});

test('k8sRunCounts groups states', () => {
  const c = k8sRunCounts([{ state: 'PLANNED' }, { state: 'APPROVED' }, { state: 'CLEANED' }, { state: 'FAILED' }, { state: 'zzz' }]);
  assert.deepEqual(c, { total: 5, pending: 1, ready: 1, clean: 1, problem: 2 });
});

test('metricTile escapes a hostile label and reason', () => {
  const h = metricTile('<img src=x onerror=1>', { state: 'no_data', reason: '<script>1</script>' }, String);
  assert.ok(!h.includes('<img') && !h.includes('<script'));
});

test('renderK8sRuns still escapes hostile cluster names with the summary in place', () => {
  document.body.innerHTML = '<div id="k8s-summary"></div><div id="k8s-runs"></div>';
  renderK8sRuns([{ id: '1', requester: 'u', cluster: '<b>c</b>', namespace: 'n', action: 'sa-token-probe', state: 'FAILED', detail: '' }]);
  assert.ok(!document.getElementById('k8s-runs').innerHTML.includes('<b>c'));
  assert.ok(document.getElementById('k8s-summary').innerHTML.includes('Runs by state'));
});
