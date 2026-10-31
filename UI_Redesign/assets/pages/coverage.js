/* ATT&CK coverage — matrix, technique detail, threat groups. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$, $$ = UI.$$;

  /* --------------------------------------------------------------- Matrix */
  var cnt = { P: 0, D: 0, M: 0, U: 0 };
  D.matrix.forEach(function (t) { t.tech.forEach(function (tc) { cnt[tc[2]]++; }); });
  var tested = cnt.P + cnt.D + cnt.M, all = tested + cnt.U;
  $('#mx-sub').textContent = tested + ' of ' + all + ' techniques validated in the last 30 days (' + Math.round(tested * 100 / all) + '%) · ' + D.posture.endpoints + ' endpoints';
  ['P', 'D', 'M', 'U'].forEach(function (c) {
    $('#mx-legend').appendChild(h('span', { class: 'k' }, h('span', { class: 'sw' + (c === 'U' ? ' u' : ''), style: 'background:' + UI.OUT[c].color }), UI.OUT[c].label + ' · ' + cnt[c]));
  });
  var SEL = 'T1003';
  D.matrix.forEach(function (t) {
    var p = t.tech.filter(function (x) { return x[2] === 'P'; }).length;
    var ts = t.tech.filter(function (x) { return x[2] !== 'U'; }).length;
    var col = h('div', { class: 'mx-col' }, h('div', { class: 'mx-head' }, h('b', null, t.name), h('span', null, ts + '/' + t.tech.length + ' tested · ' + p + ' prevented')));
    t.tech.forEach(function (tc) {
      var o = UI.OUT[tc[2]];
      var cell = h('div', { class: 'mx-cell ' + (tc[2] === 'U' ? '' : tc[2].toLowerCase()) + (tc[0] === SEL ? ' sel' : ''), 'data-id': tc[0], tabindex: 0, role: 'button', 'aria-label': tc[0] + ' ' + tc[1] + ': ' + o.label },
        h('span', { class: 'id' }, tc[0]), tc[1]);
      UI.tip.bind(cell, function () { return UI.tip.content(tc[0] + ' · ' + t.name, [{ v: o.label, n: tc[1], color: o.color, kind: 'sw' }], 'Click for detail'); });
      cell.addEventListener('click', function () { show(t, tc); });
      cell.addEventListener('keydown', function (e) { if (e.key === 'Enter') show(t, tc); });
      col.appendChild(cell);
    });
    $('#mx').appendChild(col);
  });

  /* ------------------------------------------------------ Technique detail */
  var RICH = {
    T1003: {
      sub: [['T1003.001', 'LSASS Memory', 'M', '14 endpoints'], ['T1003.002', 'Security Account Manager', 'D', 'alert in 3m 40s'], ['T1003.003', 'NTDS', 'P', 'blocked on DCs'], ['T1003.004', 'LSA Secrets', 'D', 'alert in 6m 05s'], ['T1003.006', 'DCSync', 'M', 'domain']],
      controls: [['Microsoft Defender for Endpoint', 'Blocked .002 and .003; allowed .001 and .006'], ['Splunk Enterprise Security', 'Alerted on .002 and .004; no alert for .001 or .006']],
      groups: 'Used by Lazarus Group, APT41, FIN7 and LockBit 3.0 affiliates in your profile',
      finding: 'F-1042',
      compliance: ['RBI CSF · Advanced real-time threat defence', 'ISO 27001 · A.8.7', 'NIST CSF 2.0 · DE.CM']
    }
  };
  function show(t, tc) {
    SEL = tc[0];
    $$('.mx-cell').forEach(function (c) { c.classList.toggle('sel', c.getAttribute('data-id') === SEL); });
    var o = UI.OUT[tc[2]], R = RICH[tc[0]];
    var card = $('#tech');
    var head = h('div', { class: 'card-h' },
      h('div', { class: 'titles' }, h('h2', { class: 'card-title' }, h('span', { class: 'tag mono' }, tc[0]), tc[1]), h('div', { class: 'card-sub' }, t.name + ' · worst outcome across in-scope endpoints')),
      h('div', { class: 'card-actions' }, UI.outcome(tc[2])));
    var body = h('div', { class: 'card-b' });
    if (R) {
      body.append(
        h('dl', { class: 'kv' },
          h('dt', null, 'Tested'), h('dd', null, '214 endpoints · 6 simulations · last run 2 h ago (A-3318)'),
          h('dt', null, 'Outcome'), h('dd', null, 'Blocked on 188 · detected only on 12 · missed on 14')),
        h('div', { class: 'block-title' }, 'Sub-techniques'),
        h('div', { class: 'table-wrap' }, h('table', { class: 't ev-table' },
          h('thead', null, h('tr', null, h('th', null, 'Sub-technique'), h('th', null, 'Outcome'), h('th', { class: 'r' }, 'Detail'))),
          h('tbody', null, R.sub.map(function (s) {
            return h('tr', { style: 'cursor:default' }, h('td', null, h('span', { class: 'mono small muted' }, s[0] + ' '), s[1]), h('td', null, UI.outcome(s[2])), h('td', { class: 'r small soft' }, s[3]));
          })))),
        h('div', { class: 'block-title' }, 'What each control did'),
        h('div', { class: 'list' }, R.controls.map(function (c) { return h('div', { class: 'list-row' }, icon('plug', 'tx-muted'), h('div', { class: 'grow' }, h('div', { class: 'list-title' }, c[0]), h('div', { class: 'list-sub' }, c[1]))); })),
        h('div', { class: 'block-title' }, 'Context'),
        h('p', { class: 'small soft' }, R.groups + '.'),
        h('div', { class: 'row wrap gap-1 mt-2' }, R.compliance.map(function (c) { return h('span', { class: 'tag' }, c); })));
    } else if (tc[2] === 'U') {
      body.append(h('div', { class: 'empty' }, icon('minus'), h('b', null, 'Not tested in this period'), h('span', { class: 'small' }, 'No simulation for ' + tc[0] + ' ran in the last 30 days, so its outcome is unknown, not safe.'),
        h('a', { class: 'btn btn-sm mt-2', href: '03-assessments.html#new' }, icon('plus'), 'Add to next assessment')));
    } else {
      body.append(h('dl', { class: 'kv' },
        h('dt', null, 'Outcome'), h('dd', null, o.label + ' (worst across in-scope endpoints)'),
        h('dt', null, 'Last tested'), h('dd', null, '2 h ago · Weekly BFSI threat pack (A-3318)'),
        h('dt', null, 'Tactic'), h('dd', null, t.name)),
        h('p', { class: 'small muted mt-3' }, 'Sub-technique outcomes, per-control results and the mapped compliance controls appear here, as shown for T1003.'));
    }
    var foot = h('div', { class: 'card-f' },
      R ? h('a', { class: 'link-more', href: '04-findings.html#' + R.finding }, 'Open finding ' + R.finding, icon('arrowRight', 'sm')) : h('span', { class: 'muted' }, 'Click any technique in the matrix'),
      h('button', { class: 'btn btn-sm', type: 'button' }, icon('refresh'), tc[2] === 'U' ? 'Test now' : 'Re-test technique'));
    card.replaceChildren(head, body, foot);
  }
  var first = null;
  D.matrix.forEach(function (t) { t.tech.forEach(function (tc) { if (tc[0] === SEL) first = [t, tc]; }); });
  var want = (location.hash || '').replace('#', '');
  D.matrix.forEach(function (t) { t.tech.forEach(function (tc) { if (tc[0] === want) first = [t, tc]; }); });
  show(first[0], first[1]);

  /* --------------------------------------------------------------- Groups */
  D.actors.forEach(function (a) {
    var st = a.p >= 80 ? ['good', 'Protected', 'checkCircle'] : a.p >= 60 ? ['warning', 'Partly protected', 'alert'] : ['critical', 'Exposed', 'xoct'];
    $('#groups').appendChild(h('div', { class: 'list-row', style: 'align-items:flex-start' },
      icon('ghost', 'tx-muted'),
      h('div', { class: 'grow' },
        h('div', { class: 'row' }, h('span', { class: 'list-title nowrap' }, a.name), h('span', { class: 'tag truncate' }, a.aka), h('span', { class: 'spacer' }), UI.pill(st[0], st[1], st[2])),
        h('div', { class: 'list-sub truncate', title: a.why }, a.why),
        h('div', { class: 'grid mt-2', style: 'gap:12px' },
          h('div', { class: 'c-6' }, h('div', { class: 'xs muted mb-2' }, 'Prevented'), h('div', { class: 'metric' }, UI.meter(a.p, UI.band(a.p), 'sm'), h('span', null, a.p + '%'))),
          h('div', { class: 'c-6' }, h('div', { class: 'xs muted mb-2' }, 'Detected'), h('div', { class: 'metric' }, UI.meter(a.d, UI.band(a.d), 'sm'), h('span', null, a.d + '%')))),
        h('div', { class: 'row mt-2 small muted' }, a.ttps + ' techniques · validated ' + a.last.toLowerCase(), h('span', { class: 'spacer' }), h('a', { class: 'btn btn-sm', href: '03-assessments.html#new' }, icon('play'), 'Emulate')))));
  });

  UI.boot('coverage');
  UI.notes([
    { n: 1, sel: '#mx-card', title: 'One matrix, one rule',
      body: 'Every technique in the active threat profile, coloured by the worst outcome across in-scope endpoints (the same rule as the Navigator export). Grey means not tested, which is unknown rather than safe. Column headers show tested and prevented counts.',
      today: 'Coverage is spread over five places (Coverage, Technique Coverage, AD Coverage, Email, Variants) and the dashboard adds two more. The page says “Export layer · soon”, although /api/report/navigator exists.',
      data: '/api/coverage/analytics → byTechnique (bestVerdict, runCount) joined with the threat profile (/api/coverage/matrix?actor=…).' },
    { n: 2, sel: '#tech', title: 'Technique detail: sub-techniques and controls',
      body: 'Sub-technique outcomes, what each integrated control did, which groups use the technique, and the mapped compliance controls, with a direct link to the finding and a re-test button.',
      build: 'Uses the same outcome pills as everywhere else; the detection verdicts come from the connector integrations.' },
    { n: 3, sel: '#actors', title: 'Threat-group readiness, fleet-wide',
      body: 'Prevention and detection for each group in the profile, with a plain status and one-click emulation.',
      today: 'Readiness widgets use only the first agent; Threat Prioritization puts its charts below the table.',
      data: '/api/threat-priority/actors and /actors/{name} → techniqueCoverage (preventionVerdict, detectionVerdict).' }
  ]);
})();
