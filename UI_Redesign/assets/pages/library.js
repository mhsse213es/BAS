/* Threat library — scenario catalogue with detail panel. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, S = D.libraryStats;
  var C = $('#content');
  C.append(
    UI.banner('Click a scenario to see its detail.'),
    UI.pageHeader({ title: 'Threat library', sub: 'Reusable test content: threat-group emulations, scenario packs, technique sets and your own custom scenarios. Signed and verified before every run.',
      actions: [UI.btn('Import scenario', { icon: 'upload' }), UI.btn('New scenario', { icon: 'plus', primary: true })] }),
    h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'Scenarios', value: S.scenarios, ctx: 'Across all categories' }),
      UI.kpi({ label: 'Techniques covered', value: S.techniques, unit: ' / 105', ctx: 'In the BFSI · India profile' }),
      UI.kpi({ label: 'Threat groups', value: S.actors, ctx: 'Emulations ready to run' }),
      UI.kpi({ label: 'Custom scenarios', value: S.custom, ctx: 'Built by your team' })));

  var filt = h('div', { class: 'filter-bar' }, UI.searchBox('Search scenarios, techniques, groups'),
    UI.chip('Category', 'Any'), UI.chip('Tactic', 'Any'), UI.chip('Platform', 'Any'), UI.chip('Source', 'Any'),
    h('span', { class: 'spacer' }), UI.chip('Sort', 'Recently updated', { icon: 'sliders' }));
  C.appendChild(filt);

  var split = h('div', { class: 'split' });
  var SEL = D.scenarios[0].id;
  var tableWrap = h('section', { class: 'table-wrap' });
  var panel = h('aside', { class: 'panel', 'aria-label': 'Scenario detail' });
  split.append(tableWrap, panel);
  C.appendChild(split);

  var CATC = { 'Threat group': 'critical', 'Scenario pack': 'info', 'Technique set': 'accent', 'Scenario': 'accent', 'Custom': 'good' };
  tableWrap.appendChild(UI.table([
    { h: 'Scenario', cls: 'cell-main', render: function (s) { return h('div', null, h('div', { class: 't-title' }, s.name), h('div', { class: 't-sub' }, h('span', { class: 'tag mono' }, s.id), ' ' + s.tactics.join(' · '))); } },
    { h: 'Category', render: function (s) { return UI.pill(CATC[s.cat] || '', s.cat); } },
    { h: 'Techniques', cls: 'r', render: function (s) { return h('span', { class: 'num' }, String(s.tech)); } },
    { h: 'Source', render: function (s) { return h('span', { class: 'small soft' }, s.source); } },
    { h: 'Runs', cls: 'r', render: function (s) { return h('span', { class: 'num soft' }, String(s.runs)); } }
  ], D.scenarios, { key: function (s) { return s.id; }, selected: SEL, onRow: function (s) { show(s.id); } }));

  function show(sid) {
    SEL = sid; UI.selectRow(tableWrap, sid);
    var s = D.scenarios.filter(function (x) { return x.id === sid; })[0];
    panel.replaceChildren(
      h('div', { class: 'panel-h' },
        h('div', { class: 'row' }, UI.pill(CATC[s.cat] || '', s.cat), h('span', { class: 'tag mono' }, s.id), h('span', { class: 'spacer' }), s.safe ? UI.pill('good', 'Safe mode', 'shield') : null),
        h('h2', { class: 'panel-title' }, s.name),
        h('div', { class: 'small soft mt-1' }, s.tech + ' techniques · ' + s.os.join(', ') + ' · updated ' + s.updated)),
      h('div', { class: 'panel-b' },
        s.note ? h('div', { class: 'callout good mb-4' }, icon('shield'), h('div', { class: 'small' }, s.note)) : null,
        UI.kv([['Category', s.cat], ['Tactics', s.tactics.join(', ')], ['Techniques', String(s.tech)], ['Platforms', s.os.join(', ')], ['Source', s.source], ['Times run', String(s.runs)]]),
        h('div', { class: 'block-title' }, 'What it covers'),
        h('p', { class: 'small soft' }, 'This ' + s.cat.toLowerCase() + ' exercises ' + s.tech + ' techniques across ' + s.tactics.join(', ').toLowerCase() + '. Payloads are benign and signed; the agent verifies each one and cleans up automatically.'),
        h('div', { class: 'block-title' }, 'Safety'),
        h('ul', { class: 'check-list' }, ['No destructive actions (guardrail on)', 'Signed payloads, verified on the endpoint', 'Automatic clean-up and rollback check'].map(function (t) { return h('li', null, icon('checkCircle', 'sm'), t); }))),
      h('div', { class: 'panel-f' }, UI.btn('Preview steps', { ghost: true }), UI.btn('Add to assessment', { icon: 'plus' }), UI.btn('Run now', { primary: true, icon: 'play', href: '03-assessments.html#new' })));
  }
  show(SEL);

  UI.boot('library');
  UI.notes([
    { n: 1, sel: '.filter-bar', title: 'One catalogue for all test content', body: 'Threat-group emulations, scenario packs, technique sets and custom scenarios in one searchable place.', today: 'Scenarios, the Threat Actor library and ART content live in separate spots.' },
    { n: 2, sel: '.panel', title: 'Scenario detail with safety front and centre', body: 'Coverage, platforms and the safety guarantees, then run or add to an assessment. Air-gap safe: content arrives as signed offline bundles.' }
  ]);
})();
