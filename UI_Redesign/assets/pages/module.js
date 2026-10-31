/* Module detail — one template for every module (?m=endpoint, ?m=email, …). */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var id = (/[?&]m=([a-z0-9]+)/.exec(location.search) || [])[1] || 'endpoint';
  var M = D.modules.filter(function (m) { return m.id === id; })[0] || D.modules[0];
  document.title = M.name + ' · Audspect';
  var C = $('#content');

  /* Module rail: jump between all modules */
  var rail = h('div', { class: 'mod-rail', role: 'navigation', 'aria-label': 'Modules' }, D.modules.map(function (m) {
    var b = m.state ? '' : UI.band(m.score);
    return h('a', { class: 'mod-chip' + (m.id === M.id ? ' on' : ''), href: '09-module.html?m=' + m.id },
      h('span', { class: 'd', style: 'background:' + (m.state ? 'var(--viz-muted)' : 'var(--' + b + ')') }), m.name, h('b', null, m.state ? '—' : String(m.score)));
  }));

  var head = UI.pageHeader({
    title: h('span', { class: 'row gap-3' }, icon(M.icon, 'lg tx-accent'), M.name),
    sub: M.desc,
    actions: [UI.btn('All modules', { href: '02-dashboard.html#modules', icon: 'grid' }), M.state ? null : UI.btn('Report', { href: '08-reports.html', icon: 'file' }),
      UI.btn(M.state === 'addon' ? 'Request add-on' : 'Run this module', { href: M.state === 'addon' ? '#' : '03-assessments.html#new', icon: M.state === 'addon' ? 'mail' : 'play', primary: true })]
  });
  C.append(UI.banner('Every dashboard module tile opens this template.'), head, rail);

  /* ---------------------------------------------------- Not assessed / add-on */
  if (M.state) {
    var none = M.state === 'none';
    C.appendChild(h('div', { class: 'grid mt-4' },
      UI.card({ cls: 'c-7 lg-12', id: 'm-empty', title: none ? 'No evidence yet' : 'Add-on not enabled', sub: none ? 'The score stays “Not assessed” until a run completes; it is never shown as 0 or 100.' : 'Shown so you can see the full product surface; nothing runs without a licence.',
        body: h('div', { class: 'empty' }, icon(none ? 'minus' : 'lock'), h('b', null, none ? '0 of ' + M.mapped + ' cloud techniques validated' : 'Kubernetes lab simulations'),
          h('span', { class: 'small' }, none ? 'Connect a cloud account in Integrations, then run the Cloud baseline template (≈ 25 min, read-only by default).' : 'Cluster hardening, access configuration and isolation checks, run in an isolated lab cluster.'),
          h('div', { class: 'row mt-2' }, UI.btn(none ? 'Connect cloud account' : 'Contact sales', { href: none ? '16-integrations.html' : '#', icon: none ? 'plug' : 'mail' }), none ? UI.btn('Plan assessment', { href: '03-assessments.html#new', primary: true, icon: 'play' }) : null)) }),
      UI.card({ cls: 'c-5 lg-12', title: 'What this module tests', body: h('ul', { class: 'check-list' }, (none
        ? ['Identity and access configuration', 'Storage exposure checks', 'Control-plane logging and alerting', 'Workload hardening baseline']
        : ['Cluster hardening baseline', 'Role-based access configuration', 'Secrets handling', 'Namespace isolation']).map(function (t) { return h('li', null, icon('dot', 'sm'), t); })) })));
    UI.boot('dashboard', { title: M.name });
    return;
  }

  /* -------------------------------------------------------------- Scored */
  var b = UI.band(M.score);
  var pts = (M.score * M.weight / 100).toFixed(1);
  var heroCard = UI.card({ cls: 'c-4 lg-12', id: 'm-hero', title: 'Module score', sub: 'Higher is better · same scale as the posture score',
    body: [h('div', { class: 'hero-row' }, h('div', null, h('span', { class: 'hero-num' }, String(M.score)), h('span', { class: 'hero-den' }, '/100')),
      h('div', { class: 'stack', style: 'gap:8px;align-items:flex-start;padding-bottom:6px' }, UI.statusPill(M.score), UI.delta(M.delta, 'up', ' pts', 'vs 30 days ago'))),
      h('div', { class: 'mt-3' }, UI.meter(M.score, b)),
      h('div', { class: 'small soft mt-3' }, M.weight ? 'Weight in the posture score: ' + M.weight + '% · contributes ' + pts + ' points' : 'Shown for context; not weighted in the posture score')],
    foot: [h('span', null, 'Last run ' + M.last), h('a', { class: 'link-more', href: '02-dashboard.html#modules' }, 'Compare modules', icon('arrowRight', 'sm'))] });
  var kp = h('section', { class: 'c-8 lg-12 kpi-grid four', id: 'm-kpis' },
    UI.kpi({ label: 'Prevented', value: M.p != null ? M.p : '—', unit: M.p != null ? '%' : '', ctx: M.p != null ? 'Share of simulations blocked' : 'Not applicable: detect-only module' }),
    UI.kpi({ label: 'Detected', value: M.d != null ? M.d : '—', unit: M.d != null ? '%' : '', ctx: 'Alerted in SIEM or EDR' }),
    UI.kpi({ label: 'Simulations · 30 days', value: M.sims ? M.sims.toLocaleString('en-IN') : '—', ctx: M.tests ? M.tests.length + ' test types' : 'See the full page' }),
    UI.kpi({ label: 'Change · 30 days', value: UI.signed(M.delta), unit: ' pts', ctx: M.delta >= 0 ? 'Improving' : 'Getting worse: review below', spark: M.spark }));
  C.appendChild(h('div', { class: 'grid mt-4' }, heroCard, kp));

  var trendHost = h('div');
  var techs = (M.tests || []).map(function (t) { return t[0]; });
  var related = D.findings.filter(function (f) { return techs.indexOf(f.tech) >= 0 && f.status !== 'Verified fixed'; });
  var findingsCard = UI.card({ cls: 'c-5 lg-12', id: 'm-findings', title: 'Open findings in this module', sub: related.length ? related.length + ' linked to these tests' : 'None open',
    body: related.length ? h('div', { class: 'list' }, related.map(function (f) { return UI.listRow({ icon: UI.sev(f.sev), title: f.title, sub: f.tech + ' · ' + f.sla, right: h('span', { class: 'tag mono' }, f.id), href: '04-findings.html#' + f.id }); }))
      : h('div', { class: 'empty' }, icon('checkCircle'), h('b', null, 'No open findings'), h('span', { class: 'small' }, M.link ? 'This module is summarised here; the detail lives on its own page.' : 'Every gap found by this module has been fixed and verified.'), M.link ? UI.btn('Open full page', { href: M.link, sm: true, icon: 'external' }) : null),
    actions: related.length ? h('a', { class: 'link-more', href: '04-findings.html' }, 'All findings', icon('arrowRight', 'sm')) : null });
  C.appendChild(h('div', { class: 'grid mt-4' }, UI.card({ cls: 'c-7 lg-12', id: 'm-trend', title: 'Module score over time', sub: 'Weekly · last 12 weeks', body: trendHost }), findingsCard));
  UI.lineChart(trendHost, { labels: D.weeks, xName: 'Week of', series: [{ name: M.name, short: 'Score', color: 'var(--series-1)', values: M.spark }], fmt: String, yMin: 0, yMax: 100, height: 240, area: true, target: { value: 80, label: 'Target 80' }, aria: M.name + ' score by week' });

  if (M.tests) {
    var cnt = { P: 0, D: 0, M: 0 }; M.tests.forEach(function (t) { cnt[t[2]]++; });
    C.appendChild(h('div', { class: 'grid mt-4' }, UI.card({ cls: 'c-12', id: 'm-tests', title: 'Results by test', sub: cnt.P + ' prevented · ' + cnt.D + ' detected only · ' + cnt.M + ' missed (worst outcome across endpoints)',
      actions: [UI.btn('Re-test misses', { sm: true, icon: 'refresh' })], flush: true,
      body: h('div', { class: 'table-wrap' }, UI.table([
        { h: 'Test', render: function (t) { return h('div', null, h('div', { class: 't-title' }, t[1]), h('div', { class: 't-sub mono' }, t[0])); } },
        { h: 'Outcome', render: function (t) { return UI.outcome(t[2]); } },
        { h: 'Endpoints', cls: 'r', render: function (t, i) { return h('span', { class: 'num' }, t[2] === 'M' ? '14 of 206' : t[2] === 'D' ? '0 blocked · alerted' : 'All blocked'); } },
        { h: 'Last run', cls: 'r', render: function () { return h('span', { class: 'soft small' }, M.last); } },
        { h: '', cls: 'r', render: function (t) { var f = D.findings.filter(function (x) { return x.tech === t[0]; })[0]; return f ? h('a', { class: 'tag mono', href: '04-findings.html#' + f.id }, f.id) : h('span', { class: 'muted small' }, t[2] === 'P' ? 'No action' : 'Tuning advised'); } }
      ], M.tests)) })));
  } else {
    C.appendChild(h('div', { class: 'grid mt-4' }, UI.card({ cls: 'c-12', title: 'Detail lives on its own page', body: h('div', { class: 'row wrap' }, h('p', { class: 'soft' }, M.desc + ' This module has a dedicated page with the full breakdown.'), h('span', { class: 'spacer' }), UI.btn('Open ' + M.name, { href: M.link, primary: true, icon: 'arrowRight' })) })));
  }

  UI.boot('dashboard', { title: M.name });
  UI.notes([
    { n: 1, sel: '.mod-rail', title: 'One template, every module',
      body: 'Each dashboard tile opens this page. The rail lets reviewers and users hop between modules without going back.',
      build: 'Route /modules/:id; data from GET /api/posture/summary?module=:id plus the module’s own endpoint.' },
    { n: 2, sel: '#m-hero', title: 'Score, band, change and weight',
      body: 'The module score uses the same 0–100 scale and bands as the posture score, and states how much it contributes, so the headline number is traceable.' },
    { n: 3, sel: '#m-trend', title: 'Trend and linked findings',
      body: 'Has this area improved, and what is still open? Findings link straight to the master–detail Findings page.' }
  ]);
})();
