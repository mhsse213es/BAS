/* Endpoints — fleet table, endpoint detail, deployment flow. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, $$ = UI.$$;
  var F = D.fleet;

  /* ---------------------------------------------------------------- KPIs */
  var parts = [
    { n: 'Online', v: F.online, color: 'var(--good)' }, { n: 'Agent update needed', v: F.attention, color: 'var(--warning)' },
    { n: 'Offline', v: F.offline, color: 'var(--viz-muted)' }, { n: 'Quarantined', v: F.quarantined, color: 'var(--critical)' }
  ];
  $('#e-kpis').append(
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Endpoints'), h('div', { class: 'kpi-value' }, String(F.total), h('span', { class: 'unit' }, ' / 250 seats')),
      h('div', { class: 'mt-1' }, UI.meter(Math.round(F.total * 100 / 250), '', 'sm')), h('div', { class: 'kpi-ctx' }, Object.keys(F.os).map(function (k) { return k + ' ' + F.os[k]; }).join(' · '))),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Online now'), h('div', { class: 'kpi-value' }, String(F.online), h('span', { class: 'unit' }, ' · ' + Math.round(F.online * 100 / F.total) + '%')),
      h('div', { class: 'mt-1' }, UI.segbar(parts, 'sm')), h('div', { class: 'kpi-ctx' }, F.offline + ' offline · ' + F.quarantined + ' quarantined · ' + F.attention + ' outdated')),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Need attention'), h('div', { class: 'kpi-value' }, String(F.offline + F.quarantined + F.attention)),
      h('div', { class: 'kpi-ctx' }, 'Oldest: FIN-WS-031, offline 3 days'), h('div', { class: 'kpi-foot' }, UI.delta(-6, 'down', '', 'vs 30d'))),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Validated · 30 days'), h('div', { class: 'kpi-value' }, String(Math.round(F.validated30d * 100 / F.total)), h('span', { class: 'unit' }, '%')),
      h('div', { class: 'kpi-ctx' }, F.validated30d + ' of ' + F.total + ' endpoints have fresh evidence'), h('div', { class: 'kpi-foot' }, UI.delta(2, 'up', ' pts', 'vs 30d'), UI.spark([88, 89, 90, 91, 92, 93, 94, 94, 95, 95, 96, 96], { w: 72, h: 28 }))));

  /* --------------------------------------------------------------- Table */
  var ST = { Online: ['good', 'Online', 'checkCircle'], Running: ['accent', 'Running', 'zap'], Offline: ['', 'Offline', 'power'], Update: ['warning', 'Update needed', 'refresh'], Quarantined: ['critical', 'Quarantined', 'ban'] };
  var SEL = 'FIN-WS-023';
  var tbody = h('tbody');
  D.endpoints.forEach(function (e) {
    var st = ST[e.status];
    var tr = h('tr', { 'data-id': e.host, tabindex: 0 },
      h('td', { class: 'cell-main' }, h('div', { class: 't-title mono' }, e.host), h('div', { class: 't-sub truncate', title: e.group + ' · ' + e.ip }, e.os + ' · ' + e.group)),
      h('td', null, UI.pill(st[0], st[1], st[2])),
      h('td', { style: 'min-width:120px' }, h('div', { class: 'metric' }, UI.meter(e.score, UI.band(e.score), 'sm'), h('span', null, String(e.score)))),
      h('td', { class: 'r small soft nowrap' }, e.tested));
    tr.addEventListener('click', function () { select(e.host); });
    tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') select(e.host); });
    tbody.appendChild(tr);
  });
  $('#e-table').append(h('table', { class: 't' },
    h('thead', null, h('tr', null, h('th', null, 'Endpoint'), h('th', null, 'Status'), h('th', null, 'Posture'), h('th', { class: 'r' }, 'Last tested'))),
    tbody), h('div', { class: 'pager' }, h('span', null, 'Showing 1–12 of 214'), h('span', { class: 'row' }, h('button', { class: 'btn btn-sm', type: 'button', disabled: true }, 'Previous'), h('button', { class: 'btn btn-sm', type: 'button' }, 'Next'))));

  /* ------------------------------------------------------- Detail panel */
  var CONTROLS = [['Microsoft Defender for Endpoint', 'Active · real-time protection on', 'good', 'Healthy'], ['Sysmon v15', 'Installed · events forwarded', 'good', 'Healthy'], ['Splunk Universal Forwarder', 'Forwarding · last event 30 s ago', 'good', 'Healthy'], ['LAPS', 'Not installed · shared local admin password', 'warning', 'Missing']];
  function select(host) {
    SEL = host;
    $$('#e-table tbody tr').forEach(function (tr) { tr.classList.toggle('selected', tr.getAttribute('data-id') === host); });
    var e = D.endpoints.filter(function (x) { return x.host === host; })[0], st = ST[e.status], b = UI.band(e.score);
    var rich = host === 'FIN-WS-023';
    var head = h('div', { class: 'panel-h' },
      h('div', { class: 'row wrap' }, UI.pill(st[0], st[1], st[2]), e.tags.map(function (t) { return h('span', { class: 'tag' }, t); }), h('span', { class: 'spacer' }), h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More actions' }, icon('more'))),
      h('h2', { class: 'panel-title mono' }, e.host),
      h('div', { class: 'small soft mt-1' }, e.os + ' · ' + e.group + ' · ' + e.ip));
    var body = h('div', { class: 'panel-b' },
      h('div', { class: 'row', style: 'align-items:flex-end;gap:14px' },
        h('div', null, h('span', { class: 'big-stat' }, String(e.score)), h('span', { class: 'hero-den' }, '/100')),
        h('div', { class: 'stack', style: 'gap:6px;align-items:flex-start' }, UI.pill(b, UI.bandLabel(e.score), b === 'good' ? 'checkCircle' : 'alert'), rich ? UI.delta(-3, 'up', ' pts', 'vs 30d') : null)),
      h('div', { class: 'small muted mt-1' }, 'Endpoint posture score · same formula as the fleet score'));
    if (rich) {
      body.append(h('div', { class: 'block-title' }, 'Weakest stages on this endpoint'));
      var mini = h('div');
      UI.stackBars(mini, {
        rows: [{ label: 'Credential access', values: [33, 17, 50] }, { label: 'Lateral movement', values: [40, 10, 50] }, { label: 'Defense evasion', values: [62, 13, 25] }],
        keys: [{ name: 'Prevented', color: 'var(--prevented)' }, { name: 'Detected only', color: 'var(--detected)' }, { name: 'Missed', color: 'var(--missed)' }],
        valueCol: function (r) { return h('span', { class: 'strong' }, r.values[0] + '%'); }
      });
      body.append(mini,
        h('div', { class: 'block-title' }, 'Open findings · 6'),
        h('div', { class: 'list' }, D.findings.slice(0, 3).map(function (f) {
          return h('a', { class: 'list-row link-card', href: '04-findings.html#' + f.id }, UI.sev(f.sev), h('div', { class: 'grow' }, h('div', { class: 'list-title' }, f.title), h('div', { class: 'list-sub' }, f.tech)), h('span', { class: 'tag mono' }, f.id));
        })),
        h('div', { class: 'block-title' }, 'Security controls seen on this endpoint'),
        h('div', { class: 'list' }, CONTROLS.map(function (c) {
          return h('div', { class: 'list-row' }, icon('shield', 'tx-muted'), h('div', { class: 'grow' }, h('div', { class: 'list-title' }, c[0]), h('div', { class: 'list-sub' }, c[1])), UI.pill(c[2], c[3], c[2] === 'good' ? 'checkCircle' : 'alert'));
        })));
    }
    body.append(h('div', { class: 'block-title' }, 'Agent'),
      h('dl', { class: 'kv' },
        h('dt', null, 'Version'), h('dd', null, e.ver + (e.status === 'Update' ? ' · 3.0.2 available' : ' · current')),
        h('dt', null, 'Binary'), h('dd', null, UI.pill('good', 'Signature verified', 'badge')),
        h('dt', null, 'Channel'), h('dd', null, 'Mutual TLS · certificate valid to 12 Apr 2027'),
        h('dt', null, 'Last seen'), h('dd', null, e.seen),
        h('dt', null, 'Last tested'), h('dd', null, e.tested)));
    var foot = h('div', { class: 'panel-f' },
      h('button', { class: 'btn btn-danger', type: 'button' }, icon('ban'), e.status === 'Quarantined' ? 'Release' : 'Quarantine'),
      e.status === 'Update' ? h('button', { class: 'btn', type: 'button' }, icon('refresh'), 'Upgrade agent') : null,
      h('a', { class: 'btn btn-primary', href: '03-assessments.html#new' }, icon('play'), 'Run assessment'));
    $('#e-panel').replaceChildren(head, body, foot);
  }
  select(SEL);

  UI.boot('endpoints');
  UI.notes([
    { n: 1, sel: '#e-kpis', title: 'Fleet health and evidence coverage',
      body: 'Licence use, online state, what needs attention and how much of the estate has fresh evidence: the inputs that decide whether the posture score can be trusted.',
      data: '/api/analytics/endpoint-posture (online, offline, quarantined, untrusted binary) + licence seats.',
      today: 'The Agents page hero has 5 status chips, then a 3-way view toggle where “Operational” means installation, not operations.' },
    { n: 2, sel: '#e-table', title: 'Same table and panel as every list page',
      body: 'Host, OS, status, posture and freshness. Selecting a row opens the panel: posture, weakest stages, open findings, the security controls seen on the host and agent trust details.',
      today: 'A 17-action row menu, including report exports, and a 6-tab drawer.',
      build: 'Report exports move to Reports; row actions shrink to the three that matter (run, quarantine, upgrade).' },
    { n: 3, sel: '#deploy-card', title: 'Guided deployment, secret-safe',
      body: 'Platform, signed installer, then a one-time token that is masked by default, single-use and self-expiring. The signing and mTLS guarantees are stated where the operator needs them.',
      today: 'A very long Deploy Agent page plus a separate Connection Config section.' }
  ]);
})();
