import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';
import { displayOf } from '../../src/core/inline-style.js';
import { velocityModel } from '../../src/features/fh-velocity-model.js';

setupDom();
const { metricTile, renderSparkline, renderFactoryHealthIngestion, activateTab, renderFactoryVelocity } = await load(['metricTile', 'renderSparkline', 'renderFactoryHealthIngestion', 'activateTab', 'renderFactoryVelocity']);

test('activateTab makes the factory-health panel visible when its tab is active, hidden otherwise', () => {
  // Restore the full dashboard markup: earlier tests overwrite document.body.
  setupDom();
  const panel = document.getElementById('tab-factory-health');
  assert.ok(panel, 'index.html must contain the factory-health panel');

  activateTab('factory-health');
  assert.notEqual(displayOf(panel), 'none',
    'factory-health panel must be shown when its own tab is selected (it is omitted from activateTab\'s panel list)');

  activateTab('agents');
  assert.equal(displayOf(panel), 'none',
    'factory-health panel must be hidden when a different tab is selected');
});

test('renderFactoryHealthIngestion shows per-source sync status, never-synced distinctly, and unresolved candidates', () => {
  document.body.innerHTML = '<div id="factory-health-ingestion"></div>';

  renderFactoryHealthIngestion({
    pipeline: {
      ingestion: {
        sources: [
          { sourceInstanceId: 'src-ok', displayName: 'Healthy Source', lastSuccessAt: '2026-10-01T00:00:00Z', failuresInWindow: 0, lastDiagnostic: '' },
          { sourceInstanceId: 'src-never', displayName: 'Never Synced', lastSuccessAt: null, failuresInWindow: 0, lastDiagnostic: '' },
          { sourceInstanceId: 'src-flaky', displayName: 'Flaky Source', lastSuccessAt: '2026-09-01T00:00:00Z', failuresInWindow: 3, lastDiagnostic: 'connection timeout' },
        ],
        unresolvedCandidates: 2,
      },
    },
  });

  const html = document.getElementById('factory-health-ingestion').innerHTML;
  assert.ok(html.includes('Healthy Source'), 'lists a healthy source');
  assert.ok(html.includes('Never Synced'), 'lists a never-synced source');
  assert.ok(html.includes('never synced'), 'labels the never-synced source distinctly, not as a stale timestamp');
  assert.ok(html.includes('Flaky Source') && html.includes('connection timeout'), 'shows the failure diagnostic for a flaky source');
  assert.ok(html.includes('2'), 'shows the unresolved-candidates count');
});

test('metricTile renders a NO_DATA tile distinctly from a measured tile', () => {
  const measuredHtml = metricTile('Threats Processed', { state: 'measured', value: 5 }, (v) => String(v));
  const noDataHtml = metricTile('Duplicate Generation Rate', { state: 'no_data', reason: 'not persisted yet' }, (v) => String(v));
  assert.ok(measuredHtml.includes('5'), 'measured tile shows the real value');
  assert.ok(!measuredHtml.includes('NO DATA'), 'measured tile must not say NO DATA');
  assert.ok(noDataHtml.includes('NO DATA'), 'no_data tile must say so, not show a blank or zero');
  assert.ok(noDataHtml.includes('not persisted yet'), 'no_data tile explains why');
  assert.notEqual(measuredHtml, noDataHtml);
});

test('renderSparkline shows an empty state below 3 points, a polyline at or above', () => {
  document.body.innerHTML = '<div id="spark"></div>';

  renderSparkline('spark', [{ day: '2026-01-01', value: 1 }, { day: '2026-01-02', value: 2 }]);
  assert.ok(!document.getElementById('spark').innerHTML.includes('<svg'), '2 points must not render a polyline');

  renderSparkline('spark', [{ day: '2026-01-01', value: 1 }, { day: '2026-01-02', value: 2 }, { day: '2026-01-03', value: 3 }]);
  assert.ok(document.getElementById('spark').innerHTML.includes('<polyline'), '3 points must render a polyline');

  renderSparkline('spark', null);
  assert.ok(!document.getElementById('spark').innerHTML.includes('<svg'), 'null/empty trend must not render a polyline');
});

test('renderFactoryVelocity shows per-stage durations, cohort counts, and the bottleneck', () => {
  document.body.innerHTML = '<div id="factory-health-velocity"></div>';
  const reports = {
    queue: { stage: 'queue', segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 300, p95_seconds: 900 }], open_count: 2, oldest_open_seconds: 90000, bottleneck: 'validation', incomplete_window: false },
    generation: { stage: 'generation', segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 120, p95_seconds: 240 }], open_count: 2, bottleneck: 'validation', incomplete_window: false },
    validation: { stage: 'validation', segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 600, p95_seconds: 1800 }], open_count: 2, bottleneck: 'validation', incomplete_window: false },
    end_to_end: { stage: 'end_to_end', segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 7200, p95_seconds: 15000 }, { source: 'OTX', content_type: 'emulates', cohort: 'failed', n: 1 }], open_count: 2, oldest_open_seconds: 90000, bottleneck: 'validation', incomplete_window: false },
  };
  renderFactoryVelocity(velocityModel(reports));
  const html = document.getElementById('factory-health-velocity').innerHTML;
  assert.ok(html.includes('OTX'), 'shows the source');
  assert.ok(html.includes('Emulation'), 'prettifies the content type');
  assert.ok(html.includes('2.0h'), 'shows end-to-end p50 (7200s) as a duration');
  assert.ok(html.includes('10m'), 'shows validation p50 (600s) as a duration');
  assert.ok(html.includes('4 validated') && html.includes('1 failed') && html.includes('2 open'), 'shows cohort counts');
  assert.ok(html.includes('Bottleneck'), 'names the bottleneck');
});

test('renderFactoryVelocity shows an unavailable state (not a false empty) when every stage call failed', () => {
  document.body.innerHTML = '<div id="factory-health-velocity"></div>';
  renderFactoryVelocity(velocityModel({ queue: { error: 'x' }, generation: { error: 'x' }, validation: { error: 'x' }, end_to_end: { error: 'x' } }));
  const html = document.getElementById('factory-health-velocity').innerHTML.toLowerCase();
  assert.ok(html.includes('not available'), 'says velocity is not available');
  assert.ok(!html.includes('0 validated'), 'must not show fabricated zero-cohort chips during an outage');
});

test('renderFactoryVelocity shows an honest empty state before any validated coverage', () => {
  document.body.innerHTML = '<div id="factory-health-velocity"></div>';
  renderFactoryVelocity(velocityModel({ end_to_end: { stage: 'end_to_end', segments: [], open_count: 3, bottleneck: '', incomplete_window: false } }));
  const html = document.getElementById('factory-health-velocity').innerHTML.toLowerCase();
  assert.ok(html.includes('no validated coverage yet'), 'states there is no validated coverage yet');
  assert.ok(html.includes('3 open'), 'still shows the open count');
});
