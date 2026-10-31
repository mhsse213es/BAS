/* Detection validation — expected vs fired detections per source. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  var exp = D.detectionSources.reduce(function (a, s) { return a + s.expected; }, 0);
  var fired = D.detectionSources.reduce(function (a, s) { return a + s.fired; }, 0);
  C.append(
    UI.banner(),
    UI.pageHeader({ title: 'Detection validation', sub: 'When a simulation runs, does your SIEM or EDR actually raise the right alert — and how fast? This measures detection, separately from prevention.',
      actions: [UI.btn('Export CSV', { icon: 'download' }), UI.btn('Validate detections', { primary: true, icon: 'play', href: '03-assessments.html#new' })] }),
    h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'Detection rate', value: Math.round(fired * 100 / exp), unit: '%', ctx: fired + ' of ' + exp + ' expected alerts fired', delta: [9, 'up', ' pts', 'vs 30d'] }),
      UI.kpi({ label: 'Mean time to detect', value: '4m 12s', ctx: 'Median 2m 40s across sources', delta: [-95, 'down', '', 'vs 30d', '−1m 05s'] }),
      UI.kpi({ label: 'Silent failures', value: exp - fired, ctx: 'Expected alerts that never fired', delta: [-14, 'down', '', 'vs 30d'] }),
      UI.kpi({ label: 'Connected sources', value: D.detectionSources.length, ctx: '1 needs attention (Sentinel)' })));

  C.appendChild(UI.card({ id: 'dv-src', title: 'Detection health by source', sub: 'Expected vs fired for each connected SIEM / EDR · higher is better', flush: true,
    body: h('div', { class: 'table-wrap' }, UI.table([
      { h: 'Source', cls: 'cell-main', render: function (s) { return h('div', null, h('div', { class: 't-title row gap-1' }, s.name, s.health !== 'good' ? UI.pill('warning', 'Needs attention', 'alert') : null), h('div', { class: 't-sub' }, s.kind)); } },
      { h: 'Detections firing', render: function (s) { var pc = Math.round(s.fired * 100 / s.expected); return h('div', { class: 'metric', style: 'max-width:200px' }, UI.meter(pc, UI.band(pc), 'sm'), h('span', null, pc + '%')); } },
      { h: 'Fired / expected', cls: 'r', render: function (s) { return h('span', { class: 'num' }, s.fired + ' / ' + s.expected); } },
      { h: 'Missing', cls: 'r', render: function (s) { return h('span', { class: 'num', style: s.missing > 40 ? 'color:var(--danger-text)' : '' }, String(s.missing)); } },
      { h: 'MTTD', cls: 'r', render: function (s) { return h('span', { class: 'num soft' }, s.mttd); } }
    ], D.detectionSources)) }));

  C.appendChild(h('div', { class: 'section-title' }, 'Detection results by technique'));
  var ST = { Fired: ['good', 'checkCircle'], 'Fired late': ['warning', 'clock'], Missing: ['critical', 'xoct'] };
  C.appendChild(UI.card({ id: 'dv-rules', flush: true,
    body: h('div', { class: 'table-wrap' }, UI.table([
      { h: 'Technique', cls: 'cell-main', render: function (r) { return h('div', null, h('div', { class: 't-title' }, r.name), h('div', { class: 't-sub mono' }, r.tech)); } },
      { h: 'Detection rule', render: function (r) { return h('div', null, h('div', null, r.rule), h('div', { class: 't-sub' }, r.source)); } },
      { h: 'Result', render: function (r) { return UI.pill(ST[r.status][0], r.status, ST[r.status][1]); } },
      { h: 'Note', render: function (r) { return h('span', { class: 'small soft' }, r.note); } },
      { h: '', cls: 'r', render: function (r) { return r.status === 'Fired' ? h('span', { class: 'muted small' }, '—') : UI.btn('Tune', { sm: true, ghost: true }); } }
    ], D.detectionRules)) }));

  UI.boot('detection');
  UI.notes([
    { n: 1, sel: '#dv-src', title: 'Detection measured per source', body: 'For each connected SIEM/EDR: how many expected alerts fired, how many are silently missing, and the time to detect. A connector being down means “unknown”, not “missed”.', data: '/api/scenarios/runs/{id}/detection-response-effectiveness and the connector integrations.' },
    { n: 2, sel: '#dv-rules', title: 'Rule-level results', body: 'Every expected detection, whether it fired, fired late, or is missing — with a one-click path to tune the rule.' }
  ]);
})();
