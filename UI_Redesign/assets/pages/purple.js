/* Purple-team exercises — plans, live exercise, scoring. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  var live = D.exercises[0];
  C.append(
    UI.banner(),
    UI.pageHeader({ title: 'Purple-team exercises', sub: 'Run red-team actions and measure the blue team’s detection and response together, step by step.',
      actions: [UI.btn('Templates', { ghost: true, icon: 'library' }), UI.btn('New exercise', { primary: true, icon: 'plus' })] }),
    h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'Exercises · 90 days', value: 7, ctx: '3 scheduled this quarter' }),
      UI.kpi({ label: 'Steps detected', value: 71, unit: '%', ctx: 'Blue team saw 71% of red actions', delta: [9, 'up', ' pts', 'vs last'] }),
      UI.kpi({ label: 'Median time to detect', value: '8m', ctx: 'Across all exercises', delta: [-95, 'down', '', 'vs last', '−1m 35s'] }),
      UI.kpi({ label: 'Open gaps found', value: 6, ctx: 'Converted to findings', delta: [-2, 'down', '', 'vs last'] })));

  var split = h('div', { class: 'split' });
  var main = h('div', { class: 'stack gap-4' });
  var side = h('div', { class: 'stack gap-4' });
  split.append(main, side);
  C.appendChild(split);

  // Live exercise
  var stepRows = D.exerciseSteps.map(function (s) {
    return h('div', { class: 'feed-row', style: 'grid-template-columns:52px 96px minmax(0,1fr) auto' },
      h('span', { class: 'mono muted' }, s.t), h('span', { class: 'tag mono' }, s.tech),
      h('span', { class: 'truncate' }, s.name + (s.who !== '—' ? ' · ' + s.who + ' · ' + s.mttd : '')),
      UI.outcome(s.o === 'D' ? 'D' : 'M'));
  });
  main.appendChild(UI.card({ id: 'pt-live', title: h('span', { class: 'row' }, h('span', { class: 'live-dot' }), live.name), sub: live.red + ' vs ' + live.blue + ' · step ' + live.done + ' of ' + live.steps,
    actions: [UI.btn('Pause', { sm: true, icon: 'pause' }), UI.btn('Open', { sm: true })],
    body: [h('div', { class: 'row wrap mb-4' }, UI.pill('accent', 'In progress', 'zap'), h('span', { class: 'small soft' }, live.detected + ' of ' + live.done + ' steps detected so far · median ' + live.mttd)),
      h('div', { class: 'progress mb-4' }, h('i', { style: 'width:' + Math.round(live.done * 100 / live.steps) + '%' })),
      h('div', { class: 'block-title mt-0' }, 'Timeline'), h('div', { class: 'feed' }, stepRows)] }));

  // Past exercises
  main.appendChild(UI.card({ id: 'pt-past', title: 'Past exercises', flush: true,
    body: h('div', { class: 'table-wrap' }, UI.table([
      { h: 'Exercise', cls: 'cell-main', render: function (e) { return h('div', null, h('div', { class: 't-title' }, e.name), h('div', { class: 't-sub' }, e.red + ' vs ' + e.blue)); } },
      { h: 'Detected', render: function (e) { var pc = Math.round(e.detected * 100 / e.steps); return h('div', { class: 'metric', style: 'max-width:160px' }, UI.meter(pc, UI.band(pc), 'sm'), h('span', null, e.detected + '/' + e.steps)); } },
      { h: 'MTTD', cls: 'r', render: function (e) { return h('span', { class: 'num soft' }, e.mttd); } },
      { h: 'When', cls: 'r', render: function (e) { return h('span', { class: 'soft small nowrap' }, e.when); } }
    ], D.exercises.slice(1))) }));

  side.appendChild(UI.card({ id: 'pt-score', title: 'This exercise: detection scorecard',
    body: [h('div', { class: 'row', style: 'align-items:baseline;gap:10px' }, h('span', { class: 'big-stat' }, Math.round(live.detected * 100 / live.done) + '%'), h('span', { class: 'small soft' }, 'of executed steps detected')),
      h('div', { class: 'mt-3' }, UI.segbar([{ n: 'Detected', v: live.detected, color: 'var(--detected)' }, { n: 'Missed', v: live.done - live.detected, color: 'var(--missed)' }])),
      h('div', { class: 'legend-list mt-3' }, [['Detected', live.detected, 'var(--detected)'], ['Missed', live.done - live.detected, 'var(--missed)']].map(function (x) {
        return h('div', { class: 'k' }, h('span', { class: 'sw', style: 'background:' + x[2] }), h('span', null, x[0]), h('b', null, String(x[1]))); }))] }));
  side.appendChild(UI.card({ id: 'pt-conv', title: 'Turn gaps into findings', sub: 'Missed steps become tracked findings',
    body: h('div', { class: 'list' }, [['T1003.001', 'Credential access not detected'], ['T1486', 'Encryption behaviour not detected']].map(function (g) {
      return UI.listRow({ icon: UI.outcome('M'), title: g[1], sub: g[0], right: UI.btn('Create', { sm: true }) }); })) }));

  UI.boot('purple');
  UI.notes([
    { n: 1, sel: '#pt-live', title: 'Live purple-team timeline', body: 'Each red action and whether the blue team detected it, with the time to detect, as it happens.', data: 'OpenAEV exercises + detection verdicts.' },
    { n: 2, sel: '#pt-conv', title: 'Gaps become findings', body: 'A missed step is one click from a tracked finding, so exercises feed the same remediation loop as automated runs.' }
  ]);
})();
