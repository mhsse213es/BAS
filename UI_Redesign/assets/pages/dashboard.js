/* Security posture dashboard — page logic (external file: CSP script-src 'self' compatible). */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, $$ = UI.$$;
  var P = D.posture;
  var BAND_ICON = { good: 'checkCircle', warning: 'alert', serious: 'alert', critical: 'xoct' };
  function pct(v) { return v + '%'; }
  function keys(host, list, kind) {
    list.forEach(function (k) { host.appendChild(h('span', { class: 'k' }, h('span', { class: (kind || 'sw') + (k.u ? ' u' : ''), style: 'background:' + k.color }), k.name + (k.count != null ? ' · ' + k.count : ''))); });
  }
  function agoShort(s) { return s.replace(' hours ago', 'h ago').replace(' h ago', 'h ago').replace(' days ago', 'd ago').replace('Yesterday', '1d ago').replace('Today', 'today'); }

  /* ---------------------------------------------------------- Freshness */
  $('#freshness').append(h('span', { class: 'live-dot' }), 'Latest evidence ' + P.lastRun + ' · ' + P.simulations.toLocaleString('en-IN') + ' simulations · ' + P.endpoints + ' endpoints');

  /* --------------------------------------------------------- Hero (gauge) */
  var weak = D.modules.filter(function (m) { return !m.state && m.weight; }).slice().sort(function (a, b) { return a.score - b.score; });
  var top3 = D.actions.slice(0, 3).reduce(function (s, a) { return s + a.uplift; }, 0);
  var proj = Math.round(P.score + top3);
  var trendWord = P.score > P.ago ? 'improving' : P.score < P.ago ? 'slipping' : 'steady';
  $('#gauge').appendChild(UI.gauge(P.score, { size: 200, target: P.target }));
  $('#gauge-meta').append(UI.delta(P.score - P.ago, 'up', ' pts', 'vs 30 days ago'), h('span', { class: 'muted' }, '· target ' + P.target));
  $('#hero-lead').append('Security posture is ', h('span', { class: 'em' }, UI.bandLabel(P.score).toLowerCase()), ', and ' + trendWord + '.');
  $('#hero-say').textContent = 'You block ' + D.kpis[0].value + '% of simulated attacks and detect ' + D.kpis[1].value + '%. The weakest areas are ' +
    weak[0].name.toLowerCase() + ' and ' + weak[1].name.toLowerCase() + '. Completing the top three fixes would reach your target of ' + P.target + '.';
  [['Prevention', D.kpis[0].value, '%'], ['Detection', D.kpis[1].value, '%'], ['Mean time to detect', '4m 12s', ''], ['Open criticals', 12, '']].forEach(function (s) {
    $('#hero-stats').appendChild(h('div', { class: 'hero-stat' }, h('div', { class: 'v' }, String(s[1]), s[2] ? h('span', { class: 'u' }, s[2]) : null), h('div', { class: 'k' }, s[0])));
  });

  /* How it's scored (collapsible, lives just under the hero) */
  var total = 0;
  var calcRows = D.modules.filter(function (m) { return m.weight; }).map(function (m) { var part = m.score * m.weight / 100; total += part; return [m.name, String(m.score), m.weight + '%', part.toFixed(1)]; });
  calcRows.push(['Posture score', '', '100%', total.toFixed(1) + ' → ' + Math.round(total)]);
  var calc = h('div', { class: 'card pad mt-4', id: 'hero-calc', hidden: true },
    h('p', { class: 'small soft mb-4' }, 'The posture score is the weighted average of the module scores below. Weights are a proposal and can be tuned per organisation; modules with no evidence or no licence are excluded, not counted as zero.'),
    UI.vizTable(['Module', 'Score', 'Weight', 'Points'], calcRows));
  $('#hero-calc-wrap').appendChild(calc);
  $('#how-btn').addEventListener('click', function () { var c = $('#hero-calc'); c.hidden = !c.hidden; this.setAttribute('aria-expanded', String(!c.hidden)); if (!c.hidden) c.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); });

  /* ------------------------------------------------------------ Modules */
  var mv = $('#mod-viz');
  mv.classList.add('viz');
  function rankRow(m) {
    if (m.state) {
      return h('a', { class: 'rank-row muted', href: '09-module.html?m=' + m.id, title: m.desc },
        h('div', { class: 'rank-name' }, icon(m.icon), h('span', null, m.name)),
        h('div', { class: 'rank-track' }), h('div', { class: 'rank-score' }, m.state === 'none' ? 'n/a' : 'add-on'));
    }
    var b = UI.band(m.score);
    return h('a', { class: 'rank-row', href: '09-module.html?m=' + m.id, title: m.desc + ' · ' + agoShort(m.last) },
      h('div', { class: 'rank-name' }, icon(m.icon), h('span', null, m.name)),
      h('div', { class: 'rank-track', role: 'img', 'aria-label': m.score + ' of 100' }, h('i', { style: 'width:' + m.score + '%;background:var(--' + b + ')' })),
      h('div', { class: 'rank-score' }, String(m.score), h('span', { class: 'bl' }, UI.bandLabel(m.score))));
  }
  var byGroup = h('div', { class: 'rank-wrap' });
  D.moduleGroups.forEach(function (g) {
    byGroup.appendChild(h('div', { class: 'rank-group-label' }, g[1]));
    D.modules.filter(function (m) { return m.group === g[0]; }).forEach(function (m) { byGroup.appendChild(rankRow(m)); });
  });
  var byWeak = h('div', { class: 'rank-wrap', hidden: true });
  D.modules.slice().filter(function (m) { return !m.state; }).sort(function (a, b) { return a.score - b.score; })
    .concat(D.modules.filter(function (m) { return m.state; })).forEach(function (m) { byWeak.appendChild(rankRow(m)); });
  var modTable = h('div', { class: 'viz-table' }, UI.vizTable(['Module', 'Area', 'Score', 'Prevented', 'Detected', 'Weight'],
    D.modules.map(function (m) { var g = D.moduleGroups.filter(function (x) { return x[0] === m.group; })[0]; return [m.name, g[1], m.state ? (m.state === 'none' ? 'Not assessed' : 'Add-on') : String(m.score), m.p != null ? m.p + '%' : '—', m.d != null ? m.d + '%' : '—', m.weight ? m.weight + '%' : '—']; })));
  var plot = h('div', { class: 'viz-plot' }, byGroup, byWeak);
  mv.append(plot, modTable);
  $$('#mod-sort button').forEach(function (btn) {
    btn.addEventListener('click', function () {
      $$('#mod-sort button').forEach(function (b) { b.classList.toggle('on', b === btn); });
      var weak = btn.getAttribute('data-sort') === 'weak';
      byGroup.hidden = weak; byWeak.hidden = !weak;
    });
  });
  UI.vizToggle($('#mod-tbl'), mv);

  /* ------------------------------------------------------------ Actions */
  D.actions.slice(0, 4).forEach(function (a, i) {
    $('#actions-list').appendChild(h('a', { class: 'list-row link-card', href: '04-findings.html#' + a.finding },
      h('span', { class: 'rank' }, String(i + 1)),
      h('div', { class: 'grow' },
        h('div', { class: 'list-title' }, a.title),
        h('div', { class: 'list-sub row wrap gap-1', style: 'margin-top:5px' }, UI.sev(a.sev), a.tech.map(function (t) { return h('span', { class: 'tag mono' }, t); }), h('span', null, a.scope))),
      h('div', { class: 'uplift' }, '+' + a.uplift.toFixed(1), h('small', null, 'pts'))));
  });
  $('#proj').appendChild(h('div', { class: 'proj' },
    h('div', { class: 'row wrap' }, h('span', { class: 'small soft' }, 'Projected after the top three fixes'), h('span', { class: 'spacer' }), h('span', { class: 'strong' }, P.score + ' → ' + proj), UI.pill('good', 'Meets target', 'checkCircle')),
    h('div', { class: 'meter proj-meter mt-2', role: 'img', 'aria-label': 'Score ' + P.score + ', projected ' + proj + ', target ' + P.target },
      h('i', { style: 'width:' + P.score + '%' }), h('i', { class: 'ext', style: 'left:' + P.score + '%;width:' + (proj - P.score) + '%' }), h('span', { class: 'tick', style: 'left:' + P.target + '%' }))));

  /* -------------------------------------------------------------- Trend */
  var TS = [
    { name: 'Posture score', short: 'Posture', color: 'var(--series-1)', values: P.history },
    { name: 'Prevention', short: 'Prevention', color: 'var(--series-3)', values: D.trend.prevention },
    { name: 'Detection', short: 'Detection', color: 'var(--series-2)', values: D.trend.detection }
  ];
  keys($('#trend-legend'), TS, 'ln');
  UI.lineChart($('#trend-viz'), { labels: D.weeks, xName: 'Week of', series: TS, fmt: pct, yFmt: pct, height: 300, target: { value: P.target, label: 'Target ' + P.target }, events: D.trend.events, aria: 'Posture, prevention and detection over the last 12 weeks' });
  UI.vizToggle($('#trend-tbl'), $('#trend-viz'));

  /* ------------------------------------------------------------- Deeper */
  var cnt = { P: 0, D: 0, M: 0, U: 0 };
  D.matrix.forEach(function (t) { t.tech.forEach(function (tc) { cnt[tc[2]]++; }); });
  var tested = cnt.P + cnt.D + cnt.M, allt = tested + cnt.U;
  var exposed = D.actors.filter(function (a) { return a.p < 60; }).length;
  var fwAvg = Math.round(D.frameworks.reduce(function (s, f) { return s + f.pass * 100 / f.total; }, 0) / D.frameworks.length);
  var DEEP = [
    { ic: 'grid', k: 'ATT&CK coverage', v: Math.round(tested * 100 / allt) + '%', d: tested + ' of ' + allt + ' techniques validated', href: '05-coverage.html' },
    { ic: 'route', k: 'Attack paths', v: D.pathStats.total + ' paths', d: 'Domain compromise possible', href: '13-attack-paths.html', warn: true },
    { ic: 'target', k: 'Threat readiness', v: exposed + ' exposed', d: 'of ' + D.actors.length + ' groups in your profile', href: '14-threat-intel.html' },
    { ic: 'scale', k: 'Compliance', v: fwAvg + '%', d: 'across 7 frameworks', href: '06-compliance.html' }
  ];
  DEEP.forEach(function (x) {
    $('#deeper').appendChild(h('a', { class: 'deep', href: x.href },
      h('div', { class: 'dh' }, icon(x.ic), x.k),
      h('div', { class: 'dv' + (x.warn ? ' tx-danger' : '') }, x.v),
      h('div', { class: 'dd' }, x.d),
      h('div', { class: 'darr' }, 'Open', icon('arrowRight', 'sm'))));
  });

  /* ===================================================== Operations view */
  var O = D.ops;
  var good = O.connectors.filter(function (c) { return c.status === 'good'; }).length;
  $('#ops-kpis').classList.add('four');
  [
    { label: 'Running now', value: '1', ctx: O.live.name + ' · ' + O.live.progress + '% complete' },
    { label: 'Endpoints online', value: String(D.fleet.online), unit: ' / ' + D.fleet.total, ctx: D.fleet.offline + ' offline · ' + D.fleet.quarantined + ' quarantined' },
    { label: 'Integrations healthy', value: String(good), unit: ' / ' + O.connectors.length, ctx: (O.connectors.length - good) + ' threat-intel feed is stale' },
    { label: 'Next scheduled', value: 'Sat 08:00', ctx: O.upcoming[0].name }
  ].forEach(function (k) {
    $('#ops-kpis').appendChild(h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, k.label), h('div', { class: 'kpi-value' }, k.value, k.unit ? h('span', { class: 'unit' }, k.unit) : null), h('div', { class: 'kpi-ctx truncate' }, k.ctx)));
  });
  $('#ops-live-sub').textContent = O.live.scope + ' · started ' + O.live.started;
  $('#ops-live-b').append(
    h('div', { class: 'row' }, h('span', { class: 'strong' }, O.live.name), h('span', { class: 'tag mono' }, O.live.id), h('span', { class: 'spacer' }), h('span', { class: 'small soft' }, O.live.done + ' of ' + O.live.total + ' simulations · ETA ' + O.live.eta)),
    h('div', { class: 'progress mt-2' }, h('i', { style: 'width:' + O.live.progress + '%' })),
    h('div', { class: 'block-title' }, 'Live results'),
    h('div', { class: 'feed' }, O.feed.map(function (f) {
      return h('div', { class: 'feed-row' }, h('span', { class: 'mono muted' }, f.t), h('span', { class: 'truncate' }, f.host), h('span', { class: 'truncate' }, h('span', { class: 'tag mono' }, f.tech), ' ', f.name), UI.outcome(f.o));
    })));
  var F = D.fleet;
  var parts = [{ n: 'Online', v: F.online, color: 'var(--good)' }, { n: 'Agent update needed', v: F.attention, color: 'var(--warning)' }, { n: 'Offline', v: F.offline, color: 'var(--viz-muted)' }, { n: 'Quarantined', v: F.quarantined, color: 'var(--critical)' }];
  var vpct = Math.round(F.validated30d * 100 / F.total);
  $('#fleet-b').append(
    h('div', { class: 'row', style: 'align-items:baseline;gap:10px;flex-wrap:wrap' }, h('span', { class: 'big-stat' }, vpct + '%'), h('span', { class: 'small soft' }, F.validated30d + ' of ' + F.total + ' validated in 30 days')),
    h('div', { class: 'mt-3' }, UI.segbar(parts)),
    h('div', { class: 'legend-list mt-3' }, parts.map(function (p) { return h('div', { class: 'k' }, h('span', { class: 'sw', style: 'background:' + p.color }), h('span', null, p.n), h('b', null, String(p.v))); })));
  var EPS = { Offline: ['', 'Offline', 'power', 'Diagnose'], Quarantined: ['critical', 'Quarantined', 'ban', 'Review'], Update: ['warning', 'Update needed', 'refresh', 'Upgrade'] };
  D.endpoints.filter(function (e) { return EPS[e.status]; }).forEach(function (e) {
    var s = EPS[e.status];
    $('#ops-agents-list').appendChild(h('div', { class: 'list-row' }, icon('monitor', 'tx-muted'),
      h('div', { class: 'grow' }, h('div', { class: 'list-title' }, e.host), h('div', { class: 'list-sub' }, e.group + ' · seen ' + e.seen.toLowerCase())),
      UI.pill(s[0], s[1], s[2]), h('button', { class: 'btn btn-sm', type: 'button' }, s[3])));
  });
  $('#ops-agents-list').appendChild(h('div', { class: 'list-row' }, h('span', { class: 'small muted' }, 'Showing 3 of ' + (F.offline + F.quarantined + F.attention) + ' needing attention'), h('span', { class: 'spacer' }), h('a', { class: 'small', href: '07-endpoints.html' }, 'View all')));
  O.connectors.forEach(function (c) {
    $('#ops-conn-list').appendChild(h('div', { class: 'list-row' }, icon('plug', 'tx-muted'),
      h('div', { class: 'grow' }, h('div', { class: 'list-title' }, c.name), h('div', { class: 'list-sub' }, c.kind + ' · ' + c.last)),
      UI.pill(c.status, c.label, c.status === 'good' ? 'checkCircle' : 'alert')));
  });
  O.content.forEach(function (c) {
    $('#ops-content-list').appendChild(h('div', { class: 'list-row' }, icon('book', 'tx-muted'),
      h('div', { class: 'grow' }, h('div', { class: 'list-title row gap-1' }, c.name, h('span', { class: 'tag mono' }, c.v)), h('div', { class: 'list-sub' }, c.when))));
  });
  O.upcoming.forEach(function (u) {
    $('#ops-next-list').appendChild(h('div', { class: 'list-row' }, icon('calendar', 'tx-muted'),
      h('div', { class: 'grow' }, h('div', { class: 'list-title' }, u.name), h('div', { class: 'list-sub' }, u.scope)), h('span', { class: 'small soft nowrap' }, u.when)));
  });

  /* -------------------------------------------------------- View switch */
  function setView(v) {
    $$('#view-seg button').forEach(function (x) { var on = x.getAttribute('data-view') === v; x.classList.toggle('on', on); x.setAttribute('aria-selected', on ? 'true' : 'false'); });
    $('#view-exec').hidden = v !== 'exec';
    $('#view-ops').hidden = v !== 'ops';
  }
  $$('#view-seg button').forEach(function (b) { b.addEventListener('click', function () { setView(b.getAttribute('data-view')); }); });
  if (location.hash === '#ops') setView('ops');

  /* --------------------------------------------------------- Boot+notes */
  UI.boot('dashboard');
  UI.notes([
    { n: 1, sel: '#hero', title: 'The whole answer in one band',
      body: 'A single radial gauge, a plain-language verdict, the four numbers that matter and the next action — no boxes competing for attention. This is the five-second read.',
      why: 'v0.1 opened with a grid of equal-weight cards, so nothing stood out. v0.2 gives the page one clear focal point.',
      data: 'New GET /api/posture/summary (server-side, windowed): the weighted average of the module scores, with the target set per tenant.',
      build: 'Formula and bands live in one Go package reused by the board report and PDF, so dashboard and reports never disagree.' },
    { n: 2, sel: '#modules', title: 'Module scores as one ranked chart, not 16 boxes',
      body: 'Every area scored 0–100 on a single row with a coloured bar — weak areas (amber/clay) jump out instantly. Toggle “weakest first” to triage, or keep “by area”. Each row opens its module page.',
      why: 'You asked to see every module’s individual score; v0.1 did that as 16 bordered tiles, which felt boxy. Same information, one calm visual.',
      data: 'Per module from its own feed (coverage/analytics, emailgw, waf, ad, controlhealth, attackpath, exposure…). Modules with no evidence or no licence read “n/a”.' },
    { n: 3, sel: '#actions', title: 'Fix these first',
      body: 'The four findings that would raise the score most, each opening the finding. The bar shows where the score lands once the top three are done.',
      data: 'findings + recommend/simulations; uplift = posture(verdict=prevented) − posture(now), computed server-side.' },
    { n: 4, sel: '#trend', title: 'One trend, three lines',
      body: 'Posture, prevention and detection on one axis with the target line and change markers — is it getting better, and did that detection pack help?',
      data: 'Weekly buckets from /api/dashboard/trends (add the three series to the daily snapshot).' },
    { n: 5, sel: '#deeper-sec', title: 'A launchpad, not a data dump',
      body: 'The deep analyses — ATT&CK matrix, attack paths, threat readiness, compliance — each get a headline number and a link to their own page, instead of being embedded as heavy widgets on the dashboard.',
      why: 'v0.1 embedded all of these on the dashboard, which is why “nothing could be understood at a glance”. They are now full pages reachable in one click.',
      today: 'Today these live across many places; each is now a single destination.' },
    { n: 6, sel: '#filters', title: 'One filter row; real freshness',
      body: 'Period, site, asset group and threat profile scope everything below. The freshness text is the age of the latest evidence, not the time the page opened.',
      build: 'Serve the page from one cached summary call; refresh in place without layout jumps.' },
    { n: 7, sel: '#view-seg', title: 'Two views, two audiences',
      body: 'Executive answers “are we secure, and improving?”. Operations is for the SOC and BAS operator: live runs, unhealthy endpoints, integration health, content freshness and what runs next.' }
  ]);
})();
