/* Findings — master–detail page logic. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, $$ = UI.$$;
  var T = D.findingTotals;

  /* ---------------------------------------------------------------- KPIs */
  var open = T.critical + T.high + T.medium + T.low;
  var sevParts = [
    { n: 'Critical', v: T.critical, color: 'var(--critical)' }, { n: 'High', v: T.high, color: 'var(--serious)' },
    { n: 'Medium', v: T.medium, color: 'var(--warning)' }, { n: 'Low', v: T.low, color: 'var(--viz-muted)' }
  ];
  $('#f-kpis').append(
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Open findings'), h('div', { class: 'kpi-value' }, String(open)),
      h('div', { class: 'mt-1' }, UI.segbar(sevParts, 'sm')),
      h('div', { class: 'kpi-ctx' }, T.critical + ' critical · ' + T.high + ' high · ' + T.medium + ' medium · ' + T.low + ' low')),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Past SLA'), h('div', { class: 'kpi-value' }, String(T.breached)),
      h('div', { class: 'kpi-ctx' }, 'All critical · oldest overdue by 1 day'), h('div', { class: 'kpi-foot' }, UI.delta(-2, 'down', '', 'vs 30d'))),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Mean time to remediate'), h('div', { class: 'kpi-value' }, '9.4', h('span', { class: 'unit' }, ' days')),
      h('div', { class: 'kpi-ctx' }, 'Critical 4.1 days · target 7'), h('div', { class: 'kpi-foot' }, UI.delta(-1.2, 'down', '', 'vs 30d', '−1.2 days'), UI.spark([14.2, 13.5, 13.1, 12.4, 12.0, 11.2, 10.9, 10.6, 10.1, 9.9, 9.6, 9.4], { w: 72, h: 28 }))),
    h('div', { class: 'card kpi' }, h('div', { class: 'kpi-label' }, 'Verified fixed · 30 days'), h('div', { class: 'kpi-value' }, String(T.verified30d)),
      h('div', { class: 'kpi-ctx' }, 'Closed only after a passing re-test'), h('div', { class: 'kpi-foot' }, UI.delta(8, 'up', '', 'vs prior 30d'), UI.spark([9, 11, 12, 14, 13, 16, 18, 17, 21, 22, 25, 27], { w: 72, h: 28 }))));

  /* --------------------------------------------------------------- Table */
  var SELECTED = 'F-1042';
  var STATUS = { 'Open': ['outline', 'dot'], 'In progress': ['accent', 'zap'], 'Risk accepted': ['', 'minus'], 'Verified fixed': ['good', 'checkCircle'] };
  function gapChips(f) {
    return h('div', { class: 'gap-chips' },
      h('span', null, f.prevented ? icon('check', 'sm tx-success') : icon('x', 'sm tx-danger'), f.prevented ? 'Blocked' : 'Not blocked'),
      h('span', null, f.detected ? icon('check', 'sm tx-success') : icon('x', 'sm tx-danger'), f.detected ? 'Alerted' : 'No alert'));
  }
  function sla(f) {
    var ic = { ok: 'clock', warn: 'clock', breach: 'alert', done: 'checkCircle' }[f.slaState];
    return h('span', { class: 'sla ' + f.slaState }, icon(ic, 'sm'), f.sla);
  }
  var tbody = h('tbody');
  D.findings.filter(function (f) { return f.status !== 'Verified fixed'; }).forEach(function (f) {
    var checked = f.id === 'F-1042' || f.id === 'F-1038';
    var tr = h('tr', { 'data-id': f.id, class: f.id === SELECTED ? 'selected' : null, tabindex: 0 },
      h('td', { class: 'w-check' }, h('span', { class: 'checkbox' + (checked ? ' on' : ''), role: 'checkbox', 'aria-checked': String(checked), 'aria-label': 'Select ' + f.id }, checked ? icon('check', 'sm') : null)),
      h('td', { class: 'cell-main' },
        h('div', { class: 'row gap-1' }, UI.sev(f.sev)),
        h('div', { class: 't-title mt-1' }, f.title),
        h('div', { class: 't-sub truncate' }, f.tech + ' · ' + f.tactic + ' · ' + (f.assetLabel || f.assets + ' endpoint' + (f.assets > 1 ? 's' : '')) + ' · ' + f.owner)),
      h('td', null, gapChips(f)),
      h('td', null, sla(f), h('div', { class: 'mt-1' }, UI.pill(STATUS[f.status][0], f.status, STATUS[f.status][1] === 'dot' ? null : STATUS[f.status][1]))),
      h('td', { class: 'r' }, f.uplift ? h('span', { class: 'strong tx-success' }, '+' + f.uplift.toFixed(1)) : h('span', { class: 'muted' }, '—')));
    tr.addEventListener('click', function (e) { if (e.target.closest('.checkbox')) return; select(f.id); });
    tr.addEventListener('keydown', function (e) { if (e.key === 'Enter') select(f.id); });
    tbody.appendChild(tr);
  });
  $('#f-table').append(
    h('div', { class: 'bulkbar' }, h('span', { class: 'checkbox on' }, icon('check', 'sm')), h('b', null, '2 selected'),
      h('span', { class: 'spacer' }),
      h('button', { class: 'btn btn-sm', type: 'button' }, icon('ticket'), 'Create tickets'),
      h('button', { class: 'btn btn-sm', type: 'button' }, icon('users'), 'Assign'),
      h('button', { class: 'btn btn-sm', type: 'button' }, icon('refresh'), 'Re-test'),
      h('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, 'Accept risk')),
    h('table', { class: 't' },
      h('thead', null, h('tr', null, h('th', { class: 'w-check' }, h('span', { class: 'checkbox' })), h('th', null, 'Finding'), h('th', null, 'Control gap'), h('th', null, 'SLA · status'), h('th', { class: 'r', title: 'Projected posture-score gain if fixed' }, 'Gain', icon('info')))),
      tbody),
    h('div', { class: 'pager' }, h('span', null, 'Showing 1–10 of 145 · ranked by projected score gain'), h('span', { class: 'row' }, h('button', { class: 'btn btn-sm', type: 'button', disabled: true }, 'Previous'), h('button', { class: 'btn btn-sm', type: 'button' }, 'Next'))));

  /* -------------------------------------------------------- Detail panel */
  var RICH = {
    'F-1042': {
      technique: 'T1003.001 · OS Credential Dumping: LSASS Memory',
      what: 'The agent read LSASS process memory with a signed Windows component (the comsvcs.dll MiniDump method used by most credential-theft tooling). The dump was written to a sandbox path and deleted after the test. Microsoft Defender for Endpoint allowed it and Splunk raised no alert within the 15-minute window.',
      evidence: [['FIN-WS-023', false, false, '—'], ['FIN-WS-031', false, false, '—'], ['HR-WS-009', false, false, '—']],
      more: 11,
      why: 'Credential dumping is the first step of the shortest path to Domain Admin (FIN-WS-023 → DC01). Fixing it breaks 16 of 22 known attack paths.',
      steps: [
        'Enable LSA protection: set RunAsPPL = 1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa through GPO or Intune, then reboot.',
        'Turn on the Defender ASR rule “Block credential stealing from the Windows local security authority subsystem” (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) in block mode.',
        'Detect it too: alert on Sysmon event 10 (process access) that targets lsass.exe with credential-read access rights.'
      ],
      code: 'index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10\n  TargetImage="*\\\\lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x1fffff")\n| stats count by host, SourceImage, GrantedAccess',
      controls: ['RBI CSF · Advanced real-time threat defence', 'ISO 27001 · A.8.7 Protection against malware', 'PCI DSS 4.0 · Req. 5 Anti-malware', 'NIST CSF 2.0 · DE.CM Continuous monitoring'],
      history: [['accent', '27 Oct', 'Re-test A-3290: 1 of 2 endpoints passed (FIN-WS-031 offline)'], ['', '13 Oct', 'Assigned to Endpoint team (R. Iyer)'], ['', '12 Oct', 'Ticket SEC-2291 created in ServiceNow'], ['critical', '12 Oct', 'Found by “Weekly BFSI threat pack” (A-3172) on 14 endpoints']]
    }
  };
  function generic(f) {
    var action = D.actions.filter(function (a) { return a.finding === f.id; })[0];
    return {
      technique: f.tech + ' · ' + f.tactic,
      what: 'The simulation of ' + f.tech + ' ' + (f.prevented ? 'was blocked' : 'was not blocked') + ' and ' + (f.detected ? 'raised an alert' : 'raised no alert') + ' on ' + (f.assetLabel || f.assets + ' endpoint' + (f.assets > 1 ? 's' : '')) + '.',
      why: 'Linked to ' + f.tactic.toLowerCase() + ' gaps on the dashboard kill-chain view.',
      steps: action ? [action.detail] : ['Vendor-specific guidance appears here (Defender, CrowdStrike, SentinelOne, Splunk, Sentinel), drawn from the mitigation library for ' + f.tech + '.'],
      controls: [], history: [['', f.first, 'First found'], ['', 'Today', 'Status: ' + f.status]]
    };
  }
  function kv(pairs) { var dl = h('dl', { class: 'kv' }); pairs.forEach(function (p) { dl.append(h('dt', null, p[0]), h('dd', null, p[1])); }); return dl; }

  function select(id) {
    SELECTED = id;
    $$('#f-table tbody tr').forEach(function (tr) { tr.classList.toggle('selected', tr.getAttribute('data-id') === id); });
    var f = D.findings.filter(function (x) { return x.id === id; })[0];
    var R = RICH[id] || generic(f);
    var panel = $('#f-panel');
    var head = h('div', { class: 'panel-h' },
      h('div', { class: 'row' }, UI.sev(f.sev), h('span', { class: 'tag mono' }, f.id), h('span', { class: 'spacer' }),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Copy link' }, icon('copy')), h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More actions' }, icon('more'))),
      h('h2', { class: 'panel-title' }, f.title),
      h('div', { class: 'small soft mt-1' }, R.technique),
      h('div', { class: 'row wrap mt-3' },
        f.prevented ? UI.pill('good', 'Blocked', 'shield') : UI.pill('critical', 'Not blocked', 'xoct'),
        f.detected ? UI.pill('good', 'Alerted', 'eye') : UI.pill('critical', 'No alert', 'xoct'),
        f.uplift ? UI.pill('accent', '+' + f.uplift.toFixed(1) + ' pts if fixed', 'gauge') : null));
    var body = h('div', { class: 'panel-b' },
      kv([
        ['Affected', f.assetLabel || (f.assets + ' endpoint' + (f.assets > 1 ? 's' : ''))],
        ['First seen', f.first + ' 2026'],
        ['SLA', sla(f)],
        ['Owner', f.owner],
        ['Ticket', f.ticket ? h('a', { href: '#' }, f.ticket + ' · ServiceNow') : h('a', { href: '#' }, 'Create ticket')]
      ]),
      h('div', { class: 'block-title' }, 'What happened'), h('p', { class: 'small' }, R.what),
      R.evidence ? h('div', { class: 'table-wrap mt-2' }, h('table', { class: 't ev-table' },
        h('thead', null, h('tr', null, h('th', null, 'Endpoint'), h('th', null, 'Blocked'), h('th', null, 'Alerted'), h('th', { class: 'r' }, 'MTTD'))),
        h('tbody', null, R.evidence.map(function (e) {
          return h('tr', { style: 'cursor:default' }, h('td', { class: 'mono' }, e[0]), h('td', null, e[1] ? icon('check', 'sm tx-success') : icon('x', 'sm tx-danger')), h('td', null, e[2] ? icon('check', 'sm tx-success') : icon('x', 'sm tx-danger')), h('td', { class: 'r muted' }, e[3]));
        }), h('tr', { style: 'cursor:default' }, h('td', { class: 'muted', colspan: 4 }, '+ ' + R.more + ' more endpoints · ', h('a', { href: '#' }, 'raw telemetry'))))) ) : null,
      h('div', { class: 'block-title' }, 'Why it matters'), h('p', { class: 'small' }, R.why, ' ', h('a', { href: '02-dashboard.html#paths' }, 'View attack path')),
      h('div', { class: 'block-title row' }, 'How to fix', h('span', { class: 'spacer' }),
        h('div', { class: 'seg', role: 'tablist', 'aria-label': 'Vendor' }, ['Defender', 'CrowdStrike', 'SentinelOne'].map(function (v, i) { return h('button', { type: 'button', class: i === 0 ? 'on' : null }, v); }))),
      h('ol', { class: 'steps' }, R.steps.map(function (s) { return h('li', null, s); })),
      R.code ? h('div', { class: 'mt-3' }, h('div', { class: 'row small soft mb-2' }, icon('terminal', 'sm'), 'Splunk detection (SPL)', h('span', { class: 'spacer' }), h('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, icon('copy'), 'Copy')), h('pre', { class: 'code' }, R.code)) : null,
      h('div', { class: 'block-title' }, 'Verify the fix'),
      h('div', { class: 'callout' }, icon('refresh'), h('div', { class: 'small' }, 'A re-test runs the same simulation on the affected endpoints and closes the finding automatically when every endpoint passes. No manual closure.')),
      R.controls.length ? h('div', null, h('div', { class: 'block-title' }, 'Compliance controls affected'), h('div', { class: 'row wrap gap-1' }, R.controls.map(function (c) { return h('span', { class: 'tag' }, c); }))) : null,
      h('div', { class: 'block-title' }, 'History'),
      h('ul', { class: 'timeline' }, R.history.map(function (x) { return h('li', { class: x[0] }, h('span', { class: 'muted small' }, x[1] + ' · '), h('span', { class: 'small' }, x[2])); })));
    var foot = h('div', { class: 'panel-f' },
      h('button', { class: 'btn btn-ghost', type: 'button' }, 'Accept risk'),
      f.ticket ? h('a', { class: 'btn', href: '#' }, icon('external'), 'Open ' + f.ticket) : h('a', { class: 'btn', href: '#' }, icon('ticket'), 'Create ticket'),
      h('button', { class: 'btn btn-primary', type: 'button' }, icon('refresh'), 'Re-test ' + (f.assetLabel ? 'domain' : f.assets + ' endpoint' + (f.assets > 1 ? 's' : ''))));
    panel.replaceChildren(head, body, foot);
  }
  var initial = (location.hash || '').replace('#', '');
  select(D.findings.some(function (f) { return f.id === initial; }) ? initial : SELECTED);

  UI.boot('findings');
  UI.notes([
    { n: 1, sel: '#f-kpis', title: 'Summary that drives behaviour',
      body: 'Open findings by severity, SLA breaches, mean time to remediate and verified fixes. “Verified fixed” rewards proving the fix, not just closing tickets.',
      data: '/api/findings (with pagination and counts), /api/sla/report → overall, bySeverity, monthlyTrend.',
      today: 'Five KPI tiles plus charts above an unpaginated table; SLA lives on a separate hidden page.' },
    { n: 2, sel: '#f-filters', title: 'One filter row, saved views',
      body: 'Search, severity, tactic, control domain, owner and SLA in one row; views such as “My team” or “Past SLA” are saved per user. Default sort is projected score gain.',
      today: 'Search and severity chips only; no saved views; no ranking.' },
    { n: 3, sel: '#f-table', title: 'Ranked table with bulk actions',
      body: 'Severity, title, technique, tactic, scope and owner in one cell, the control gap as two plain facts (blocked? alerted?), SLA and status, then the score gain. Bulk tickets, assignment and re-test.',
      build: 'One shared table component: sticky header, keyboard row selection, pagination, column chooser. The same component is used on Assessments and Endpoints.' },
    { n: 4, sel: '#f-panel', title: 'Detail panel: evidence → why → fix → verify',
      body: 'Evidence per endpoint, business impact (link to the attack path), vendor-specific steps with a ready-to-paste detection, then re-test to verify. Compliance controls affected and full history.',
      today: 'The finding drawer shows tickets and EPP actions; remediation guidance is generic and lives on a separate Remediation page.',
      data: 'Finding + run results (detection verdicts, MTTD), mitigation library per technique and vendor, compliance mapping, ticketing.' }
  ]);
})();
