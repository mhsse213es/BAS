import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { metricTile, renderSparkline } = await load(['metricTile', 'renderSparkline']);

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
