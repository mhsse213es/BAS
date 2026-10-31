/* Assessments — unified run list, run detail, new-assessment flow. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, $$ = UI.$$;

  /* ---------------------------------------------------------------- KPIs */
  $('#a-kpis').append(
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Running now'), h('div', { class: 'kpi-value' }, '1'),
      h('div', { class: 'kpi-ctx' }, 'Ransomware readiness · 64% complete'), h('div', { class: 'kpi-foot' }, h('div', { class: 'progress', style: 'width:100%' }, h('i', { style: 'width:64%' })))),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Scheduled · next 7 days'), h('div', { class: 'kpi-value' }, '4'),
      h('div', { class: 'kpi-ctx' }, 'Next: board scorecard, Sat 08:00')),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Simulations · 30 days'), h('div', { class: 'kpi-value' }, (1284).toLocaleString('en-IN')),
      h('div', { class: 'kpi-ctx' }, 'Across 206 endpoints'), h('div', { class: 'kpi-foot' }, UI.delta(212, 'up', '', 'vs prior 30d'), UI.spark([820, 860, 910, 940, 980, 1010, 1060, 1090, 1150, 1190, 1240, 1284], { w: 72, h: 28 }))),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Prevention · 30 days'), h('div', { class: 'kpi-value' }, '78', h('span', { class: 'unit' }, '%')),
      h('div', { class: 'kpi-ctx' }, 'Share of simulations blocked'), h('div', { class: 'kpi-foot' }, UI.delta(4, 'up', ' pts', 'vs 30d'), UI.spark(D.trend.prevention, { w: 72, h: 28 }))));

  /* --------------------------------------------------------------- Table */
  var ST = { Completed: ['good', 'checkCircle'], Running: ['accent', 'zap'], Partial: ['warning', 'alert'], Scheduled: ['outline', 'clock'], Failed: ['critical', 'xoct'] };
  var SELECTED = 'A-3318';
  function outcomeCell(a) {
    if (a.status === 'Running') return h('div', { class: 'stack', style: 'gap:4px;min-width:130px' }, h('div', { class: 'progress' }, h('i', { style: 'width:' + a.progress + '%' })), h('span', { class: 'xs muted' }, a.progress + '% complete'));
    if (a.p == null) return h('span', { class: 'muted small' }, 'Not run yet');
    var tot = a.p + a.d + a.m;
    var txt = a.type === 'Detection' ? Math.round(a.d * 100 / tot) + '% detected' : Math.round(a.p * 100 / tot) + '% prevented';
    return h('div', { class: 'stack', style: 'gap:4px;min-width:130px' },
      UI.segbar([{ n: 'Prevented', v: a.p, color: 'var(--prevented)' }, { n: 'Detected only', v: a.d, color: 'var(--detected)' }, { n: 'Missed', v: a.m, color: 'var(--missed)' }], 'sm'),
      h('span', { class: 'xs muted' }, txt + ' · ' + tot + ' sims'));
  }
  var tbody = h('tbody');
  D.assessments.forEach(function (a) {
    var st = ST[a.status];
    var tr = h('tr', { 'data-id': a.id, tabindex: 0 },
      h('td', { class: 'cell-main' }, h('div', { class: 't-title truncate' }, a.name), h('div', { class: 't-sub truncate', title: a.scope }, a.type + ' · ' + a.when)),
      h('td', null, UI.pill(st[0], a.status, st[1])),
      h('td', null, outcomeCell(a)),
      h('td', { class: 'r' }, a.delta != null ? UI.delta(a.delta, 'up', ' pts') : h('span', { class: 'muted' }, '—')));
    tr.addEventListener('click', function () { select(a.id); });
    tr.addEventListener('keydown', function (e) { if (e.key === 'Enter') select(a.id); });
    tbody.appendChild(tr);
  });
  $('#a-table').append(h('table', { class: 't' },
    h('thead', null, h('tr', null, h('th', null, 'Assessment'), h('th', null, 'Status'), h('th', null, 'Outcome'), h('th', { class: 'r' }, 'Score'))),
    tbody), h('div', { class: 'pager' }, h('span', null, 'Showing 6 of 6 in the last 30 days'), h('span', { class: 'row' }, h('button', { class: 'btn btn-sm', type: 'button', disabled: true }, 'Previous'), h('button', { class: 'btn btn-sm', type: 'button', disabled: true }, 'Next'))));

  /* ----------------------------------------------------------- Run detail */
  var WORST = [['T1003.001', 'LSASS memory dumping', 14, 'F-1042'], ['T1021.002', 'SMB admin shares', 22, 'F-1038'], ['T1490', 'Inhibit system recovery', 9, 'F-1035']];
  function select(id) {
    SELECTED = id;
    $$('#a-table tbody tr').forEach(function (tr) { tr.classList.toggle('selected', tr.getAttribute('data-id') === id); });
    var a = D.assessments.filter(function (x) { return x.id === id; })[0];
    var st = ST[a.status];
    var head = h('div', { class: 'panel-h' },
      h('div', { class: 'row' }, UI.pill(st[0], a.status, st[1]), h('span', { class: 'tag mono' }, a.id), h('span', { class: 'tag' }, a.type), h('span', { class: 'spacer' }), h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More actions' }, icon('more'))),
      h('h2', { class: 'panel-title' }, a.name),
      h('div', { class: 'small soft mt-1' }, a.scope + ' · ' + a.when + ' · by ' + a.by + (a.dur && a.dur !== '—' ? ' · took ' + a.dur : '')));
    var body = h('div', { class: 'panel-b' });
    if (a.p != null) {
      var tot = a.p + a.d + a.m;
      body.append(
        h('div', { class: 'out-tiles' },
          tile('shield', 'Prevented', a.p, tot), tile('eye', 'Detected only', a.d, tot), tile('xoct', 'Missed', a.m, tot)),
        h('div', { class: 'mt-3' }, UI.segbar([{ n: 'Prevented', v: a.p, color: 'var(--prevented)' }, { n: 'Detected only', v: a.d, color: 'var(--detected)' }, { n: 'Missed', v: a.m, color: 'var(--missed)' }])));
      if (a.delta != null) body.append(h('div', { class: 'callout good mt-3' }, icon('gauge'), h('div', { class: 'small' }, h('b', null, 'Posture ' + UI.signed(a.delta) + ' pts. '), 'Compared with the previous run: 5 techniques newly prevented, 2 new misses.')));
      body.append(h('div', { class: 'block-title' }, 'Weakest stages in this run'));
      var mini = h('div');
      UI.stackBars(mini, {
        rows: D.tactics.slice().sort(function (x, y) { return x.p - y.p; }).slice(0, 4).map(function (t) { return { label: t.name, values: [t.p, t.d, t.m] }; }),
        keys: [{ name: 'Prevented', color: 'var(--prevented)' }, { name: 'Detected only', color: 'var(--detected)' }, { name: 'Missed', color: 'var(--missed)' }],
        valueCol: function (r) { return h('span', { class: 'strong' }, r.values[0] + '%'); }
      });
      body.append(mini, h('div', { class: 'block-title' }, 'Top misses → findings'),
        h('div', { class: 'list' }, WORST.map(function (w) {
          return h('a', { class: 'list-row link-card', href: '04-findings.html#' + w[3] }, UI.outcome('M'),
            h('div', { class: 'grow' }, h('div', { class: 'list-title' }, w[1]), h('div', { class: 'list-sub' }, w[0] + ' · ' + w[2] + ' endpoints')),
            h('span', { class: 'tag mono' }, w[3]));
        })));
    } else if (a.status === 'Running') {
      body.append(h('div', { class: 'progress' }, h('i', { style: 'width:' + a.progress + '%' })), h('p', { class: 'small soft mt-2' }, a.progress + '% complete · results stream live on the Operations view.'),
        h('a', { class: 'btn btn-sm mt-3', href: '02-dashboard.html#ops' }, icon('zap'), 'Watch live'));
    } else {
      body.append(h('div', { class: 'empty' }, icon('calendar'), h('b', null, 'Scheduled for ' + a.when), h('span', { class: 'small' }, 'Results appear here after the run. You can run it now or change the window.')));
    }
    body.append(h('div', { class: 'block-title' }, 'Safety'),
      h('ul', { class: 'check-list' },
        h('li', null, icon('checkCircle', 'sm'), 'Safe mode: destructive actions blocked by the guardrail'),
        h('li', null, icon('checkCircle', 'sm'), 'Every command signed by the orchestrator and verified by the agent'),
        h('li', null, icon('checkCircle', 'sm'), 'Automatic clean-up confirmed on all endpoints')));
    var foot = h('div', { class: 'panel-f' },
      h('a', { class: 'btn', href: '08-reports.html' }, icon('file'), 'Report'),
      a.m ? h('button', { class: 'btn', type: 'button' }, icon('refresh'), 'Re-test misses') : null,
      h('button', { class: 'btn btn-primary', type: 'button' }, icon('play'), a.status === 'Scheduled' ? 'Run now' : 'Run again'));
    $('#a-panel').replaceChildren(head, body, foot);
  }
  function tile(ic, label, v, tot) {
    return h('div', { class: 'out-tile' }, h('div', { class: 'row' }, icon(ic, 'sm'), label), h('b', null, String(v)), h('small', null, Math.round(v * 100 / tot) + '%'));
  }
  select(SELECTED);

  /* --------------------------------------------------------------- Wizard */
  var steps = ['What to test', 'Where', 'Safety & schedule', 'Review'];
  steps.forEach(function (s, i) {
    if (i) $('#stepper').appendChild(h('span', { class: 'step-line' }));
    $('#stepper').appendChild(h('span', { class: 'step' + (i === 0 ? ' on' : '') }, h('b', null, String(i + 1)), s));
  });
  var TPL = [
    { id: 'bfsi', ic: 'target', name: 'BFSI · India threat pack', desc: 'Techniques used against Indian banks and insurers in the last 12 months.', meta: '184 simulations · 62 techniques · ≈ 35 min', rec: true },
    { id: 'rw', ic: 'lock', name: 'Ransomware readiness', desc: 'Pre-encryption behaviour: discovery, credential theft, backup deletion. Nothing is encrypted.', meta: '96 simulations · 38 techniques · ≈ 20 min' },
    { id: 'actor', ic: 'ghost', name: 'Threat-group emulation', desc: 'Pick a group, such as Lazarus, FIN7 or APT41, and run its known techniques in order.', meta: '40–120 simulations · varies by group' },
    { id: 'kc', ic: 'layers', name: 'Full kill chain', desc: 'Every technique in the active threat profile, from initial access to impact.', meta: '420 simulations · 105 techniques · ≈ 1.5 h' },
    { id: 'det', ic: 'radar', name: 'Detection validation', desc: 'Fire known-bad telemetry and check that each SIEM / EDR detection actually alerts.', meta: '64 detections · ≈ 30 min' },
    { id: 'custom', ic: 'sliders', name: 'Custom', desc: 'Choose techniques, scenarios or variants from the Threat library.', meta: 'You decide' }
  ];
  TPL.forEach(function (t) {
    $('#tpls').appendChild(h('div', { class: 'tpl' + (t.rec ? ' on' : ''), role: 'radio', 'aria-checked': t.rec ? 'true' : 'false', tabindex: 0 },
      h('h4', null, icon(t.ic, 'tx-accent'), t.name, t.rec ? h('span', { class: 'pill accent', style: 'margin-left:auto' }, 'Recommended') : null),
      h('p', null, t.desc), h('div', { class: 'meta' }, t.meta)));
  });
  $('#w-summary').append(
    h('div', { class: 'strong' }, 'Summary'),
    h('dl', { class: 'kv mt-2', style: 'grid-template-columns:110px 1fr' },
      h('dt', null, 'Template'), h('dd', null, 'BFSI · India threat pack'),
      h('dt', null, 'Scope'), h('dd', { class: 'muted' }, 'Choose in step 2'),
      h('dt', null, 'Estimate'), h('dd', null, '184 simulations · ≈ 35 min'),
      h('dt', null, 'Window'), h('dd', null, 'Mon–Fri 01:00–05:00 IST')),
    h('div', { class: 'block-title' }, 'Safe by default'),
    h('ul', { class: 'check-list' },
      h('li', null, icon('checkCircle', 'sm'), 'No destructive actions (guardrail on)'),
      h('li', null, icon('checkCircle', 'sm'), 'Signed payloads, verified on the endpoint'),
      h('li', null, icon('checkCircle', 'sm'), 'Automatic clean-up and rollback check'),
      h('li', null, icon('checkCircle', 'sm'), 'Crown-jewel hosts need a second approver')));

  UI.boot('assessments');
  UI.notes([
    { n: 1, sel: '#a-table', title: 'One list for every kind of run',
      body: 'Runs, schedules, campaigns, sweeps, emulations, detection validations and re-tests share one table. Type, status and vector are filters and tabs, not separate pages.',
      today: 'Run lists exist in six places (Live Runs, Email, Kubernetes, Aleef, Variant sweeps, Campaigns) and scheduling in four. “Live Runs” also lists finished runs.',
      data: 'New unified GET /api/assessments (paginated) over runs, campaigns, scheduled-assessments and re-tests.' },
    { n: 2, sel: '#a-panel', title: 'Run detail in a panel, not a 12-tab drawer',
      body: 'Outcome split, score change against the previous run, the weakest stages, the top misses linked to findings, safety confirmation and next actions.',
      today: 'The run-results drawer has 12 tabs; reports.js alone carries 215 inline styles.',
      build: 'At most five sections, no tabs. Deep detail (raw telemetry, per-endpoint matrix) opens as its own page.' },
    { n: 3, sel: '#wizard', title: 'New assessment: four steps, safe by default',
      body: 'Start from an outcome-oriented template; scope, safety and schedule come next. The summary keeps the estimate and safety guarantees visible at all times.',
      today: 'A 4-step Run wizard exists on Scenarios, a separate 4-step wizard on Schedules, and a Launch modal on Campaigns.',
      build: 'One wizard for all three; “Schedule” is a choice in step 3, not a different product area.' }
  ]);
})();
