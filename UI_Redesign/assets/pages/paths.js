/* Attack paths & exposure — paths to crown jewels, choke points, exposure explorer. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  var PS = D.pathStats, p0 = D.paths[0];
  C.append(UI.banner(), UI.pageHeader({ title: 'Attack paths', sub: 'Chains of techniques that succeeded end-to-end in your environment, and the choke points that break the most of them.',
    actions: [UI.btn('Export graph', { icon: 'download' }), UI.btn('Recollect', { ghost: true, icon: 'refresh' }), UI.btn('Run attack-path assessment', { primary: true, icon: 'play', href: '03-assessments.html#new' })] }));

  var tabs = UI.tabsNav([['paths', 'Attack paths', 3], ['choke', 'Choke points', 2], ['exposure', 'Exposure explorer', null]], 'paths');
  C.appendChild(tabs);
  var body = h('div'); C.appendChild(body);

  var rb = UI.band(PS.resilience);
  function chainEl() {
    var chain = h('div', { class: 'path' });
    p0.chain.forEach(function (c) {
      if (c.n) chain.appendChild(h('div', { class: 'path-node' + (c.jewel ? ' jewel' : '') }, h('span', { class: 'k' }, c.jewel ? icon('crown', 'sm') : null, c.k), h('b', null, c.n)));
      else chain.appendChild(h('div', { class: 'path-edge missed', title: c.t + ' ' + c.l }, h('span', { class: 'tech' }, c.t), h('span', { class: 'tech-n' }, c.l)));
    });
    return chain;
  }
  function paths() {
    return [
      h('section', { class: 'kpi-grid four mb-4' },
        UI.kpi({ label: 'Attack-path resilience', value: PS.resilience, unit: '/100', extra: h('div', { class: 'mt-1' }, UI.statusPill(PS.resilience)), delta: [6, 'up', ' pts', 'vs 30d'] }),
        UI.kpi({ label: 'Successful paths', value: PS.total, ctx: 'Reached a crown jewel end-to-end' }),
        UI.kpi({ label: 'To Domain Admin', value: p0.steps, unit: ' steps', ctx: 'Reachable from 14 workstations' }),
        UI.kpi({ label: 'Crown jewels reachable', value: 3, ctx: 'DC01, core banking, SWIFT' })),
      UI.card({ id: 'ap-main', title: 'Shortest path to Domain Admin', sub: 'All steps succeeded (not prevented)',
        body: [h('div', { class: 'row wrap mb-4' }, UI.pill('critical lg', 'Domain compromise possible', 'xoct'), h('span', { class: 'small soft' }, 'Reachable from ' + p0.hosts + ' finance workstations')), chainEl()] }),
      UI.card({ id: 'ap-other', title: 'Other crown jewels reachable', flush: true,
        body: h('div', { class: 'table-wrap' }, UI.table([
          { h: 'Target', cls: 'cell-main', render: function (p) { return h('div', null, h('div', { class: 't-title row gap-1' }, icon('crown', 'sm tx-muted'), p.target), h('div', { class: 't-sub' }, p.kind)); } },
          { h: 'Steps', cls: 'r', render: function (p) { return h('span', { class: 'num' }, String(p.steps)); } },
          { h: 'Reachable from', cls: 'r', render: function (p) { return h('span', { class: 'num soft' }, p.hosts + ' endpoints'); } },
          { h: 'Risk', render: function (p) { return UI.pill(p.risk, p.risk === 'critical' ? 'Critical' : 'High', 'alert'); } },
          { h: '', cls: 'r', render: function () { return UI.btn('View path', { sm: true }); } }
        ], D.paths)) })];
  }
  function choke() {
    return [h('p', { class: 'page-sub mb-4' }, 'Fixing a choke point breaks every path that runs through it — the highest-leverage remediation.'),
      UI.card({ id: 'ap-choke', flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
        { h: 'Choke point', cls: 'cell-main', render: function (c) { return h('div', null, h('div', { class: 't-title' }, c.name), h('div', { class: 't-sub' }, 'Fix: ' + c.fix)); } },
        { h: 'Paths broken if fixed', render: function (c) { var pc = Math.round(c.breaks * 100 / PS.total); return h('div', { class: 'metric', style: 'max-width:200px' }, UI.meter(pc, 'good', 'sm'), h('span', null, c.breaks + ' / ' + PS.total)); } },
        { h: '', cls: 'r', render: function () { return UI.btn('Create finding', { sm: true }); } }
      ], D.chokePoints)) })];
  }
  function exposure() {
    var rows = D.endpoints.slice(0, 8).map(function (e) { return { host: e.host, crown: e.tags.indexOf('Crown jewel') >= 0, net: e.tags.indexOf('Internet-facing') >= 0, score: e.score, findings: e.score < 60 ? 3 : e.score < 75 ? 1 : 0 }; });
    return [h('p', { class: 'page-sub mb-4' }, 'Assets ranked by exposure: crown-jewel value, internet exposure, open findings and how reachable they are. Higher score is safer.'),
      UI.card({ id: 'ap-exp', flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
        { h: 'Asset', cls: 'cell-main', render: function (r) { return h('div', null, h('div', { class: 't-title mono row gap-1' }, r.host, r.crown ? UI.pill('warning', 'Crown jewel', 'crown') : null, r.net ? UI.pill('info', 'Internet-facing', 'globe') : null)); } },
        { h: 'Exposure (safer →)', render: function (r) { return h('div', { class: 'metric', style: 'max-width:200px' }, UI.meter(r.score, UI.band(r.score), 'sm'), h('span', null, String(r.score))); } },
        { h: 'Open findings', cls: 'r', render: function (r) { return r.findings ? h('span', { class: 'num', style: 'color:var(--danger-text)' }, String(r.findings)) : h('span', { class: 'num soft' }, '0'); } },
        { h: '', cls: 'r', render: function () { return UI.btn('Open', { sm: true, href: '07-endpoints.html' }); } }
      ], rows)) })];
  }
  UI.bindTabs(tabs, function (id) { body.replaceChildren.apply(body, (id === 'choke' ? choke() : id === 'exposure' ? exposure() : paths())); });

  UI.boot('paths');
  UI.notes([
    { n: 1, sel: '.tabs', title: 'Attack paths and exposure, together', body: 'Two related analyses in one place instead of two separate pages, with the standard page anatomy.', today: 'Attack Paths has a bespoke button row and no stat chips; Exposure Explorer is a separate nav item.' },
    { n: 2, sel: '#ap-choke, #ap-exp', title: 'Choke points are the highest-leverage fix', body: 'Ranking fixes by how many paths they break turns graph analysis into a short action list.', data: '/api/attackpath/summary and /api/exposure/assets (both already exist).' }
  ]);
})();
