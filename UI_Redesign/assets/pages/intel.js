/* Threat intelligence — groups, IOCs, KEV, what to test next. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  C.append(UI.banner(), UI.pageHeader({ title: 'Threat intelligence', sub: 'The groups that target banks like yours, the indicators and known-exploited vulnerabilities in play, and what to test next.',
    actions: [UI.btn('Import bundle', { icon: 'upload' }), UI.btn('Edit threat profile', { ghost: true, icon: 'target' }), UI.btn('Build test pack', { primary: true, icon: 'play' })] }));
  var tabs = UI.tabsNav([['groups', 'Threat groups', 6], ['next', 'Test next', 4], ['kev', 'KEV exposure', 5], ['ioc', 'IOC registry', null]], 'groups');
  C.appendChild(tabs);
  var body = h('div'); C.appendChild(body);

  function groups() {
    var list = h('div', { class: 'list' });
    D.actors.forEach(function (a) {
      var st = a.p >= 80 ? ['good', 'Protected', 'checkCircle'] : a.p >= 60 ? ['warning', 'Partly protected', 'alert'] : ['critical', 'Exposed', 'xoct'];
      list.appendChild(h('div', { class: 'list-row', style: 'align-items:flex-start' }, icon('ghost', 'tx-muted'),
        h('div', { class: 'grow' },
          h('div', { class: 'row' }, h('span', { class: 'list-title nowrap' }, a.name), h('span', { class: 'tag' }, a.aka), h('span', { class: 'spacer' }), UI.pill(st[0], st[1], st[2])),
          h('div', { class: 'list-sub', title: a.why }, a.why),
          h('div', { class: 'grid mt-2', style: 'gap:12px' },
            h('div', { class: 'c-6' }, h('div', { class: 'xs muted mb-2' }, 'Prevented'), UI.metric(a.p)),
            h('div', { class: 'c-6' }, h('div', { class: 'xs muted mb-2' }, 'Detected'), UI.metric(a.d))),
          h('div', { class: 'row mt-2 small muted' }, a.ttps + ' techniques · validated ' + a.last.toLowerCase(), h('span', { class: 'spacer' }), UI.btn('Emulate', { sm: true, icon: 'play', href: '03-assessments.html#new' }))),
        null));
    });
    return [h('p', { class: 'page-sub mb-4' }, 'Default profile: BFSI · India. Share of each group’s known techniques your controls prevent, measured fleet-wide.'), UI.card({ id: 'ti-groups', flush: true, body: h('div', { class: 'card-b' }, list) })];
  }
  function next() {
    var PR = { High: 'critical', Medium: 'warning', Low: '' };
    return [h('p', { class: 'page-sub mb-4' }, 'Ranked by threat relevance and coverage gaps — the techniques most worth testing next.'),
      UI.card({ id: 'ti-next', flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
        { h: 'Technique', cls: 'cell-main', render: function (r) { return h('div', null, h('div', { class: 't-title row gap-1' }, r.name, r.kev ? UI.pill('critical', 'KEV', 'alert') : null), h('div', { class: 't-sub mono' }, r.tech)); } },
        { h: 'Why now', render: function (r) { return h('span', { class: 'small soft' }, r.why); } },
        { h: 'Priority', render: function (r) { return UI.pill(PR[r.priority], r.priority); } },
        { h: '', cls: 'r', render: function () { return UI.btn('Add to run', { sm: true, icon: 'plus' }); } }
      ], D.testNext)) })];
  }
  function kev() {
    var SIM = { Prevented: 'P', 'Detected only': 'D', Missed: 'M' };
    return [h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'KEV in your estate', value: D.kev.length, ctx: '2 ransomware-linked' }),
      UI.kpi({ label: 'Validated by simulation', value: 3, unit: ' / 5', ctx: 'Exploitation prevented or detected' }),
      UI.kpi({ label: 'Still open', value: 2, ctx: 'Follina, mail client' }),
      UI.kpi({ label: 'Catalogue', value: '1,384', ctx: 'CISA KEV · updated 3 days ago' })),
      UI.card({ id: 'ti-kev', title: 'Known-exploited vulnerabilities, validated by attack simulation', sub: 'Does your control actually stop the exploit, not just “is it patched”', flush: true,
        body: h('div', { class: 'table-wrap' }, UI.table([
          { h: 'CVE', cls: 'cell-main', render: function (r) { return h('div', null, h('div', { class: 't-title mono row gap-1' }, r.cve, r.ransomware ? UI.pill('critical', 'Ransomware', 'lock') : null), h('div', { class: 't-sub' }, r.product)); } },
          { h: 'Patch status', render: function (r) { return UI.pill(r.status === 'Open' ? 'critical' : 'good', r.status, r.status === 'Open' ? 'alert' : 'checkCircle'); } },
          { h: 'Exploit simulation', render: function (r) { return UI.outcome(SIM[r.sim]); } },
          { h: 'Assets', cls: 'r', render: function (r) { return h('span', { class: 'num' }, String(r.assets)); } },
          { h: '', cls: 'r', render: function () { return UI.btn('Simulate', { sm: true, icon: 'play' }); } }
        ], D.kev)) })];
  }
  function ioc() {
    return [h('section', { class: 'kpi-grid four mb-4' },
      UI.kpi({ label: 'Indicators', value: D.iocStats.total.toLocaleString('en-IN'), ctx: 'Across 4 feeds' }),
      UI.kpi({ label: 'Matched in simulations', value: D.iocStats.matchedInSim, ctx: 'Seen during test runs' }),
      UI.kpi({ label: 'Feeds', value: D.iocStats.feeds, ctx: 'MISP, OpenCTI, OTX, CERT-In' }),
      UI.kpi({ label: 'Stale feeds', value: D.iocStats.stale, ctx: 'MISP — import next bundle' })),
      h('div', { class: 'filter-bar' }, UI.searchBox('Search indicators'), UI.chip('Type', 'Any'), UI.chip('Actor', 'Any'), UI.chip('Feed', 'Any'), h('span', { class: 'spacer' }), UI.btn('Add indicator', { sm: true, icon: 'plus' })),
      UI.card({ id: 'ti-ioc', flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
        { h: 'Indicator', cls: 'cell-main', render: function (r) { return h('div', null, h('div', { class: 't-title mono' }, r.value), h('div', { class: 't-sub' }, r.type + ' · ' + r.kind)); } },
        { h: 'Group', render: function (r) { return h('span', null, r.actor); } },
        { h: 'Feed', render: function (r) { return h('span', { class: 'small soft' }, r.source); } },
        { h: 'Sim hits', cls: 'r', render: function (r) { return r.hits ? h('span', { class: 'num', style: 'color:var(--warning-text)' }, String(r.hits)) : h('span', { class: 'num soft' }, '0'); } },
        { h: 'Added', cls: 'r', render: function (r) { return h('span', { class: 'soft small nowrap' }, r.added); } }
      ], D.iocs)) })];
  }
  var want = (location.hash || '').replace('#', '');
  UI.bindTabs(tabs, function (id) { body.replaceChildren.apply(body, (id === 'next' ? next() : id === 'kev' ? kev() : id === 'ioc' ? ioc() : groups())); });

  UI.boot('intel');
  UI.notes([
    { n: 1, sel: '.tabs', title: 'All threat intel in one place', body: 'Groups, “test next”, KEV exposure and the IOC registry become tabs of one page.', today: 'Threat Prioritization, Recommendations and IOC Registry are three separate nav items.' },
    { n: 2, sel: '#ti-kev, #ti-groups', title: 'Intelligence tied to evidence', body: 'KEV entries show whether a simulation actually stops the exploit; group readiness is fleet-wide, not first-agent.', data: '/api/threat-priority/actors, /api/ti/*, KEV catalogue in the offline bundle.' }
  ]);
})();
