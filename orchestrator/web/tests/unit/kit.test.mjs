import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom } from './dom.mjs';

setupDom();
const kit = await import('../../src/core/kit.js');
const charts = await import('../../src/core/charts.js');

test('kit text arguments are escaped', () => {
  const h = kit.kpi({ label: '<b>x</b>', value: '"><img src=x>', sub: '<i>', tone: 'ok' });
  assert.ok(!/<b>x|<img|<i>/.test(h), h);
  assert.match(h, /tone-ok/);
});

test('an unknown tone falls back to accent instead of reaching a class name', () => {
  assert.match(kit.pill('up', 'x" onload="1'), /tone-accent/);
  assert.ok(!/onload/.test(kit.chip('t', 'x" onload="1')));
});

test('seg and tabs wire clicks through the action registry only', () => {
  const h = kit.seg([{ id: 'a"b', label: 'A' }], 'a"b', 'setThing');
  assert.match(h, /data-on-click="setThing"/);
  assert.ok(!/ on[a-z]+=/.test(h));
  assert.match(h, /class="on"/);
});

test('hbars clamp the percentage and escape the label', () => {
  const h = kit.hbars([['<s>', 250, 'bad'], ['n', -4]]);
  assert.ok(!h.includes('<s>'));
  assert.match(h, /data-w="100"/);
  assert.match(h, /data-w="0"/);
});

test('empty, kv and checkRow escape their text', () => {
  assert.ok(!/<u>/.test(kit.empty('search', '<u>t', '<u>s') + kit.kv([['<u>', '<u>']]) + kit.checkRow('ok', '<u>', '<u>', '')));
});

test('charts draw into their slot with escaped tooltips, and empty data is honest', () => {
  charts.installCharts();
  document.body.insertAdjacentHTML('beforeend', '<div id="t">' + charts.chartSlot({ type: 'bar', labels: ['<q>'], series: [{ name: 'n', data: [3], color: 'red' }] }) + charts.chartSlot({ type: 'line', labels: [], series: [{ name: 'n', data: [], color: 'red' }] }) + charts.chartSlot({ type: 'donut', segments: [{ label: '<d>', value: 2, color: 'red' }] }) + '</div>');
  charts.hydrateCharts(document.getElementById('t'));
  const html = document.getElementById('t').innerHTML;
  assert.equal(document.getElementById('t').querySelectorAll('q, d').length, 0);
  assert.match(html, /chart-empty/);
  assert.match(html, /donut-legend/);
});

test('non-numeric series values become zero, never NaN', () => {
  document.body.insertAdjacentHTML('beforeend', '<div id="t2">' + charts.chartSlot({ type: 'line', labels: ['a', 'b'], series: [{ name: 'n', data: [null, 'x'], color: 'red' }] }) + '</div>');
  charts.hydrateCharts(document.getElementById('t2'));
  assert.ok(!/NaN/.test(document.getElementById('t2').innerHTML));
});
