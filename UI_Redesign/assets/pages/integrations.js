/* Integrations — every connector in one place. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  var good = D.integrations.filter(function (i) { return i.status === 'good'; }).length;
  var conn = D.integrations.filter(function (i) { return i.status !== 'off'; }).length;
  C.append(UI.banner(), UI.pageHeader({ title: 'Integrations', sub: 'Every connector in one place: SIEM, EDR/EPP, ITSM, threat-intel feeds and the simulation engine.',
    actions: [UI.btn('Re-check all', { ghost: true, icon: 'refresh' }), UI.btn('Add connector', { primary: true, icon: 'plus' })] }),
    h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'Connected', value: conn, ctx: 'Of ' + D.integrations.length + ' available' }),
      UI.kpi({ label: 'Healthy', value: good, unit: ' / ' + conn, ctx: '2 need attention' }),
      UI.kpi({ label: 'Detection sources', value: 4, ctx: 'Feeding detection validation' }),
      UI.kpi({ label: 'Last sync issue', value: 'MISP', ctx: '3 days ago — import bundle' })));

  var KIC = { SIEM: 'chart', 'EDR / EPP': 'shield', ITSM: 'ticket', 'Threat intel': 'target', Engine: 'zap' };
  var SST = { good: ['good', 'Healthy', 'checkCircle'], warning: ['warning', 'Needs attention', 'alert'], off: ['', 'Not configured', 'plus'] };
  var cards = h('div', { class: 'cards-3' });
  D.integrations.forEach(function (i) {
    var st = SST[i.status];
    cards.appendChild(UI.card({ cls: 'tile' + (i.status === 'off' ? ' flat' : ''),
      title: h('span', { class: 'row', style: 'width:100%' }, icon(KIC[i.kind] || 'plug', 'tx-accent'), h('span', null, i.name), h('span', { class: 'spacer' }), UI.pill(st[0], st[1], st[2])),
      body: [h('div', { class: 'small soft' }, i.kind), h('p', null, i.detail),
        h('div', { class: 'row end' }, h('span', { class: 'xs muted' }, i.since), h('span', { class: 'spacer' }), i.status === 'off' ? UI.btn('Connect', { sm: true, icon: 'plus' }) : UI.btn('Configure', { sm: true, ghost: true, icon: 'settings' }))] }));
  });
  C.appendChild(cards);

  UI.boot('integrations');
  UI.notes([
    { n: 1, sel: '.cards-3', title: 'One home for every connector', body: 'SIEM, EDR, ITSM, threat-intel and the engine in one grid with a clear health state.', today: 'Integrations are split across the Integrations page and several Settings sections; a TAXII table says “Manage in Settings” next to its own “Add” button.' },
    { n: 2, sel: '.kpi-grid', title: 'Health that matters for results', body: 'Connector health drives whether detection is “measured” or “unknown”, so it belongs next to the posture numbers it affects.' }
  ]);
})();
