/* Compliance — framework cards, control table, trend, signed reports. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, $$ = UI.$$;
  var SEL = 'rbi';
  var MONTHS = ['Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct'];
  var CST = { Pass: ['good', 'checkCircle'], Partial: ['warning', 'alert'], Fail: ['critical', 'xoct'], 'Not tested': ['', 'minus'] };

  function counts(f) {
    var u = f.untested || 0, fail = f.total - f.pass - f.partial - u;
    return { pass: f.pass, partial: f.partial, fail: fail, untested: u, pct: Math.round(f.pass * 100 / f.total) };
  }

  /* ------------------------------------------------------- Framework cards */
  D.frameworks.forEach(function (f) {
    var c = counts(f);
    var card = h('div', { class: 'card fw-card c-3 md-6' + (f.id === SEL ? ' on' : ''), 'data-id': f.id, role: 'button', tabindex: 0, 'aria-label': f.name },
      h('div', { class: 'row' }, h('b', null, f.short), h('span', { class: 'spacer' }), UI.delta(f.delta, 'up', ' pts')),
      h('div', { class: 'small muted truncate', title: f.name }, f.name),
      h('div', { class: 'row', style: 'align-items:flex-end' }, h('span', { class: 'big' }, c.pct + '%'), h('span', { class: 'spacer' }), UI.spark(f.spark, { w: 84, h: 28 })),
      UI.meter(c.pct, UI.band(c.pct), 'sm'),
      h('div', { class: 'small soft' }, c.pass + '/' + f.total + ' passing · ' + c.partial + ' partial · ' + c.fail + ' failing' + (c.untested ? ' · ' + c.untested + ' untested' : '')));
    card.addEventListener('click', function () { select(f.id); });
    card.addEventListener('keydown', function (e) { if (e.key === 'Enter') select(f.id); });
    $('#fw-cards').appendChild(card);
  });
  $('#fw-cards').appendChild(h('div', { class: 'card fw-card c-3 md-6', style: 'border-style:dashed;justify-content:center;align-items:center;text-align:center' },
    icon('plus', 'lg tx-muted'), h('b', null, 'Map a custom framework'), h('span', { class: 'small muted' }, 'Internal policy, SWIFT CSP or a board-specific control set')));

  /* ------------------------------------------------------ Selected framework */
  function select(id) {
    SEL = id;
    $$('#fw-cards .fw-card').forEach(function (c) { c.classList.toggle('on', c.getAttribute('data-id') === id); });
    var f = D.frameworks.filter(function (x) { return x.id === id; })[0], c = counts(f);
    $('#ctl-title').textContent = f.name + ' · controls';
    $('#ctl-sub').textContent = c.pass + ' of ' + f.total + ' controls pass on all in-scope endpoints · evidence from the last 90 days';
    var filters = [['All', f.total, true], ['Failing', c.fail], ['Partial', c.partial], ['Passing', c.pass], ['Not tested', c.untested]];
    $('#ctl-filter').replaceChildren(h('div', { class: 'seg', role: 'tablist', 'aria-label': 'Control status' }, filters.map(function (x) { return h('button', { type: 'button', class: x[2] ? 'on' : null }, x[0] + ' · ' + x[1]); })));
    var rows = id === 'rbi' ? D.rbiControls : D.rbiControls.slice(0, 6).map(function (r, i) {
      return { id: f.short.replace(/\s.*/, '').toUpperCase() + '-' + String(i + 1).padStart(2, '0'), name: r.name, tech: r.tech, status: r.status, tests: r.tests, last: r.last };
    });
    $('#ctl-table').replaceChildren(h('table', { class: 't' },
      h('thead', null, h('tr', null, h('th', null, 'Control'), h('th', null, 'Validated by'), h('th', null, 'Status'), h('th', { class: 'r' }, 'Evidence'), h('th', { class: 'r' }, 'Last validated'))),
      h('tbody', null, rows.map(function (r) {
        var st = CST[r.status];
        return h('tr', null,
          h('td', { class: 'cell-main' }, h('div', { class: 'mono xs muted' }, r.id), h('div', { class: 't-title' }, r.name)),
          h('td', null, h('div', { class: 'row wrap gap-1' }, r.tech.map(function (t) { return h('span', { class: 'tag mono' }, t); }))),
          h('td', null, UI.pill(st[0], r.status, st[1])),
          h('td', { class: 'r num' }, r.tests ? h('a', { href: '#' }, r.tests.toLocaleString('en-IN') + ' tests') : h('span', { class: 'muted' }, '—')),
          h('td', { class: 'r soft nowrap' }, r.last));
      }))));
    if (id !== 'rbi') $('#ctl-table').appendChild(h('div', { class: 'pager' }, h('span', { class: 'muted' }, 'Illustrative rows · the real table lists all ' + f.total + ' controls')));
    $('#trend-sub').textContent = f.short + ' · controls passing, monthly';
    var host = $('#trend-viz'); host.replaceChildren(); host.className = '';
    UI.lineChart(host, { labels: MONTHS, xName: 'Month', series: [{ name: f.short, short: 'Readiness', color: 'var(--series-1)', values: f.spark }], fmt: function (v) { return v + '%'; }, yFmt: function (v) { return v + '%'; }, yMin: 50, yMax: 100, yTicks: [50, 75, 100], height: 190, area: true, aria: f.short + ' readiness by month' });
  }
  select(SEL);

  /* ---------------------------------------------------------- Signed list */
  [['RBI CSF · Q2 FY2026-27', 'PDF · 2 Oct 2026 · CISO', '3f9a…c21e'], ['SEBI CSCRF · half-yearly', 'PDF · 30 Sep 2026 · schedule', '81d0…7a44'], ['CERT-In readiness', 'HTML · 15 Sep 2026 · A. Khan', 'c6b2…09fe']].forEach(function (r) {
    $('#signed-list').appendChild(h('div', { class: 'list-row' }, icon('file', 'tx-muted'),
      h('div', { class: 'grow' }, h('div', { class: 'list-title' }, r[0]), h('div', { class: 'list-sub' }, r[1] + ' · SHA-256 ', h('span', { class: 'mono' }, r[2]))),
      UI.pill('good', 'Valid', 'badge')));
  });

  UI.boot('compliance');
  UI.notes([
    { n: 1, sel: '#cm-filters', title: 'The aggregation rule is a visible choice',
      body: 'Fleet readiness depends on how endpoints are combined. The rule is chosen here and printed on every report.',
      today: '/api/compliance/scores without an agentId silently returns the worst agent per framework.',
      build: 'Add an aggregation parameter (all | worst | per-endpoint) to /api/compliance/scores and /report.' },
    { n: 2, sel: '#fw-cards', title: 'All frameworks at a glance',
      body: 'Readiness, direction of travel and the pass / partial / fail split for each of the seven frameworks, plus room for custom control sets.',
      today: 'Compliance has no sidebar entry; its page hero is titled “Reports”, and it works per agent only.',
      data: '/api/compliance/scores (compliancePct, passing / failing / untested) + a JSON trend over compliance_history.' },
    { n: 3, sel: '#controls', title: 'Control-level evidence',
      body: 'Each control shows the techniques that validate it, its status and the number of tests behind it, linking straight to the evidence.',
      data: '/api/compliance/report?framework=… → domains[], controls[].' },
    { n: 4, sel: '#signed', title: 'Signed, verifiable reports',
      body: 'Reports are signed so auditors can verify them without trusting the console. This is a differentiator for regulated Indian BFSI.',
      data: 'Existing attestation and verify handlers (report_verify_handlers.go).' }
  ]);
})();
