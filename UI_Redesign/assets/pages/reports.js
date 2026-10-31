/* Reports centre — types, schedules, verification, history. */
(function () {
  'use strict';
  var h = UI.h, icon = UI.icon, $ = UI.$;

  var TYPES = [
    { ic: 'gauge', name: 'Board scorecard', who: 'Board · CEO', desc: 'One page: posture score and trend, top three risks and the decisions needed.', fmt: ['PDF', 'HTML'] },
    { ic: 'chart', name: 'Executive summary', who: 'CISO · CRO', desc: 'Posture, control domains, threat readiness and the remediation plan with owners.', fmt: ['PDF', 'HTML'] },
    { ic: 'scale', name: 'Compliance report', who: 'Auditors · regulators', desc: 'Per-framework readiness with control-level evidence. Signed and verifiable.', fmt: ['PDF', 'HTML', 'JSON', 'CSV'] },
    { ic: 'alert', name: 'Technical findings', who: 'SOC · engineering', desc: 'Every finding with its evidence, the vendor-specific fix and the detection to deploy.', fmt: ['PDF', 'HTML', 'CSV'] },
    { ic: 'grid', name: 'ATT&CK Navigator layer', who: 'SOC · threat intel', desc: 'A coverage layer (v4.5) for the official ATT&CK Navigator, ready to combine with detection layers.', fmt: ['JSON'] },
    { ic: 'lock', name: 'Audit evidence pack', who: 'Internal audit', desc: 'All evidence for a period with a hashed, signed manifest that can be verified offline.', fmt: ['ZIP'] }
  ];
  TYPES.forEach(function (t) {
    $('#types').appendChild(h('div', { class: 'card rt-card c-4 md-6' },
      h('h3', null, icon(t.ic), t.name),
      h('div', null, h('span', { class: 'pill outline' }, t.who)),
      h('p', null, t.desc),
      h('div', { class: 'row wrap gap-1' }, t.fmt.map(function (f) { return h('span', { class: 'tag mono' }, f); })),
      h('div', { class: 'row end' }, h('span', { class: 'spacer' }),
        h('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, icon('calendar'), 'Schedule'),
        h('button', { class: 'btn btn-sm', type: 'button' }, 'Generate'))));
  });

  var SCHED = [
    ['Board scorecard', 'PDF', 'Monthly · 1st, 08:00', 'CISO, CRO', 'Sat 1 Nov', ['good', 'Delivered', 'checkCircle']],
    ['RBI CSF compliance', 'PDF · signed', 'Quarterly', 'Compliance, internal audit', '1 Jan 2027', ['good', 'Delivered', 'checkCircle']],
    ['Weekly findings digest', 'HTML email', 'Weekly · Mon 09:00', 'SOC, endpoint and infra leads', 'Mon 3 Nov', ['good', 'Delivered', 'checkCircle']],
    ['SEBI CSCRF', 'PDF · signed', 'Half-yearly', 'Compliance', '31 Mar 2027', ['critical', 'Failed · retrying', 'alert']]
  ];
  $('#sched-t').appendChild(h('table', { class: 't' },
    h('thead', null, h('tr', null, h('th', null, 'Report'), h('th', null, 'Frequency'), h('th', null, 'Recipients'), h('th', null, 'Next run'), h('th', null, 'Last delivery'))),
    h('tbody', null, SCHED.map(function (s) {
      return h('tr', null, h('td', { class: 'cell-main' }, h('div', { class: 't-title' }, s[0]), h('div', { class: 't-sub' }, s[1])), h('td', { class: 'small soft' }, s[2]), h('td', { class: 'small soft' }, s[3]), h('td', { class: 'small nowrap' }, s[4]), h('td', null, UI.pill(s[5][0], s[5][1], s[5][2])));
    }))));

  var HIST = [
    ['Board scorecard · September 2026', 'All sites · Sep 2026', 'PDF', '1 Oct 2026 · 08:00', 'Schedule'],
    ['RBI CSF · Q2 FY2026-27', 'Regulatory scope · Jul–Sep 2026', 'PDF', '2 Oct 2026 · 11:20', 'CISO'],
    ['Technical findings · A-3318', 'Weekly BFSI threat pack', 'HTML', 'Today · 07:45', 'R. Iyer'],
    ['ATT&CK layer · BFSI · India', 'All endpoints · last 30 days', 'JSON', 'Yesterday · 18:02', 'SOC'],
    ['Audit evidence pack · Q2', 'RBI + SEBI · Jul–Sep 2026', 'ZIP', '3 Oct 2026 · 16:40', 'Internal audit']
  ];
  $('#hist-t').appendChild(h('table', { class: 't' },
    h('thead', null, h('tr', null, h('th', null, 'Report'), h('th', null, 'Format'), h('th', null, 'Generated'), h('th', null, 'By'), h('th', null, 'Signature'), h('th', { class: 'r' }, ''))),
    h('tbody', null, HIST.map(function (r) {
      return h('tr', null,
        h('td', { class: 'cell-main' }, h('div', { class: 't-title' }, r[0]), h('div', { class: 't-sub' }, r[1])),
        h('td', null, h('span', { class: 'tag mono' }, r[2])), h('td', { class: 'small soft nowrap' }, r[3]), h('td', { class: 'small soft' }, r[4]),
        h('td', null, UI.pill('good', 'Valid', 'badge')),
        h('td', { class: 'r nowrap' }, h('button', { class: 'btn btn-sm btn-ghost', type: 'button' }, icon('badge'), 'Verify'), h('button', { class: 'btn btn-sm', type: 'button' }, icon('download'), 'Download')));
    }))));

  UI.boot('reports');
  UI.notes([
    { n: 1, sel: '#types', title: 'Start from the audience, not the format',
      body: 'Six report types, each named for its reader, with formats as options. Exports that are hidden today move here.',
      today: 'The board scorecard, Navigator layer, full report and audit pack exist only in each agent’s row menu, and the generator works per agent only.' },
    { n: 2, sel: '#schedules', title: 'Scheduled delivery is live',
      body: 'Recurring reports with recipients, next run and delivery status; failures retry and raise an alert.',
      today: 'The page says “Scheduled delivery is not available in this release”, although /api/report/schedules CRUD exists.',
      data: '/api/report/schedules (+ SMTP settings).' },
    { n: 3, sel: '#verify', title: 'Verification as a first-class action',
      body: 'Anyone can prove a report is unaltered: a strong trust signal for regulators that cloud-only tools cannot match in an air-gapped bank.',
      data: 'report_verify_handlers.go (attestation manifest + signature).' },
    { n: 4, sel: '#history', title: 'History with signatures',
      body: 'Every generated report keeps its signature, evidence window and author, ready for audit sampling.' }
  ]);
})();
