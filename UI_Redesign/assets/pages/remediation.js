/* Remediation plans — initiatives, SLA report. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  C.append(UI.banner(), UI.pageHeader({ title: 'Remediation plans', sub: 'Group findings into initiatives with an owner and a due date, and track whether fixes land within SLA.',
    actions: [UI.btn('SLA policy', { ghost: true, icon: 'clock' }), UI.btn('New initiative', { primary: true, icon: 'plus' })] }));
  var tabs = UI.tabsNav([['init', 'Initiatives', 4], ['sla', 'SLA report', null]], 'init');
  C.appendChild(tabs);
  var body = h('div'); C.appendChild(body);

  function init() {
    var ST = { 'On track': ['good', 'checkCircle'], 'At risk': ['warning', 'alert'], 'Behind': ['critical', 'xoct'] };
    var cards = h('div', { class: 'cards-3 mb-4' }, D.initiatives.map(function (i) {
      var pc = Math.round(i.done * 100 / i.findings);
      return UI.card({ cls: 'tile', title: h('span', { class: 'row', style: 'width:100%' }, h('span', null, i.name), h('span', { class: 'spacer' }), UI.pill(ST[i.status][0], i.status, ST[i.status][1])),
        body: [h('div', { class: 'small soft' }, i.owner + ' · due ' + i.due),
          h('div', { class: 'metric mt-2' }, UI.meter(pc, UI.band(pc), 'sm'), h('span', null, i.done + '/' + i.findings)),
          h('div', { class: 'row end' }, h('span', { class: 'small' }, 'Projected uplift ', h('b', { class: 'tx-success' }, '+' + i.uplift)), h('span', { class: 'spacer' }), UI.btn('Open', { sm: true }))] });
    }));
    return [cards, UI.card({ id: 'rm-all', title: 'All initiatives', flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
      { h: 'Initiative', cls: 'cell-main', render: function (i) { return h('div', null, h('div', { class: 't-title' }, i.name), h('div', { class: 't-sub' }, h('span', { class: 'tag mono' }, i.id), ' ' + i.owner)); } },
      { h: 'Progress', render: function (i) { var pc = Math.round(i.done * 100 / i.findings); return h('div', { class: 'metric', style: 'max-width:180px' }, UI.meter(pc, UI.band(pc), 'sm'), h('span', null, i.done + '/' + i.findings)); } },
      { h: 'Due', cls: 'r', render: function (i) { return h('span', { class: 'soft small nowrap' }, i.due); } },
      { h: 'Uplift', cls: 'r', render: function (i) { return h('span', { class: 'strong tx-success' }, '+' + i.uplift); } },
      { h: 'Status', render: function (i) { return UI.pill(ST[i.status][0], i.status, ST[i.status][1]); } }
    ], D.initiatives)) })];
  }
  function sla() {
    var T = D.findingTotals;
    var trendHost = h('div');
    var out = [h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'On-time rate', value: 87, unit: '%', ctx: 'All severities, last 90 days', delta: [4, 'up', ' pts', 'vs prior'] }),
      UI.kpi({ label: 'Past SLA now', value: T.breached, ctx: 'All critical' }),
      UI.kpi({ label: 'Mean time to remediate', value: T.mttr, ctx: 'Critical 4.1 days', delta: [-95, 'down', '', '', '−1.2 days'] }),
      UI.kpi({ label: 'Verified fixed · 30d', value: T.verified30d, ctx: 'Closed after a passing re-test', delta: [8, 'up', '', 'vs prior'] })),
      h('div', { class: 'grid' },
        UI.card({ cls: 'c-7 lg-12', id: 'rm-sev', title: 'On-time rate by severity', flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
          { h: 'Severity', render: function (r) { return UI.sev(r.sev.toLowerCase()); } },
          { h: 'Target', render: function (r) { return h('span', { class: 'small soft' }, r.target); } },
          { h: 'On time', render: function (r) { return h('div', { class: 'metric', style: 'max-width:160px' }, UI.meter(r.rate, UI.band(r.rate), 'sm'), h('span', null, r.rate + '%')); } },
          { h: 'Late', cls: 'r', render: function (r) { return h('span', { class: 'num' }, String(r.late)); } }
        ], D.slaBySeverity)) }),
        UI.card({ cls: 'c-5 lg-12', id: 'rm-trend', title: 'On-time rate trend', sub: 'Monthly', body: trendHost }))];
    setTimeout(function () { UI.lineChart(trendHost, { labels: ['Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct'], xName: 'Month', series: [{ name: 'On-time %', short: 'On time', color: 'var(--series-1)', values: D.slaTrend }], fmt: function (v) { return v + '%'; }, yMin: 50, yMax: 100, yTicks: [50, 75, 100], height: 200, area: true, aria: 'SLA on-time rate by month' }); }, 0);
    return out;
  }
  UI.bindTabs(tabs, function (id) { body.replaceChildren.apply(body, (id === 'sla' ? sla() : init())); });

  UI.boot('plans');
  UI.notes([
    { n: 1, sel: '.tabs', title: 'Initiatives and SLA in one place', body: 'Remediation, Initiatives and the hidden SLA report combine into one page.', today: 'SLA report has no nav entry; Initiatives and Remediation are separate.' },
    { n: 2, sel: '#rm-all', title: 'Findings grouped into owned initiatives', body: 'Each initiative rolls up findings, a due date and a projected posture uplift, so remediation is planned, not ad-hoc.', data: 'findings + /api/sla/report (overall, bySeverity, monthlyTrend).' }
  ]);
})();
