// Scheduled Assessments, Initiatives and Campaigns: one merged page each. Uses the real console's records and columns
// inside the original rich layouts, so there is no second list or duplicate button.
(() => {
const { S, P, A, h, toast } = AUD;
const { tag, bar, table, kpi } = h;
const K = KIT, { tile } = RL;
const st = h.st;
const chips = (key, def, opts) => `<div class="chips">${opts.map(([v, l, n]) => `<button class="chip ${(S[key] || def) === v ? 'on' : ''}" data-act="set" data-a="${key}" data-b="${v}">${l}${n !== undefined ? ` <span class="cnt">${n}</span>` : ''}</button>`).join('')}</div>`;
const swap = (arr, rows) => arr.splice(0, arr.length, ...rows);

// ================= SCHEDULED ASSESSMENTS =================
swap(D.SCHEDULES, [
  { id: 'SA-201', name: 'Full Security Posture Scan', mode: 'Posture', targets: 3, scope: '3 agents', rec: 'Weekly · Wednesday · 22:00 · UTC', cron: '0 22 * * 3', lastRun: '23/10/2026, 17:30', next: 'Wed 29 Oct, 22:00', last: 'PASS 94%', state: 'Active' },
  { id: 'SA-204', name: 'Windows Security Configuration & Identity Baseline', mode: 'Posture', targets: 3, scope: '3 agents', rec: 'Weekly · Monday · 09:00 · UTC', cron: '0 9 * * 1', lastRun: '23/10/2026, 17:30', next: 'Mon 27 Oct, 09:00', last: 'WARN 81%', state: 'Active' },
  { id: 'SA-207', name: 'Linux Discovery - Host, Network, User, Process Enumeration', mode: 'Posture', targets: 3, scope: '3 agents', rec: 'Weekly · Tuesday · 03:00 · UTC', cron: '0 3 * * 2', lastRun: '23/10/2026, 17:30', next: '—', last: 'PASS 100%', state: 'Cancelled' },
  { id: 'SA-210', name: 'Credential Access — LSA Secrets, Credential Manager, Kerberos, NTLM (Phase 4)', mode: 'Posture', targets: 3, scope: '3 agents', rec: 'Weekly · Friday · 14:30 · UTC', cron: '30 14 * * 5', lastRun: '23/10/2026, 19:58', next: 'Fri 31 Oct, 14:30', last: 'FAIL 72%', state: 'Active' }]);
const stag = s => tag(s === 'Active' ? 'Enabled' : s, s === 'Active' ? 'green' : 'red');
P.scheduled = P['scheduled-assessments'] = () => {
  const q = (S.sQ || '').toLowerCase(), f = S.sF || 'All';
  const list = D.SCHEDULES.filter(s => (!q || (s.name + s.id).toLowerCase().includes(q)) && (f === 'All' || (f === 'Enabled' ? s.state === 'Active' : s.state === 'Cancelled')));
  const act = D.SCHEDULES.filter(s => s.state === 'Active').length, can = D.SCHEDULES.length - act;
  return K.hero('clock', 'Scheduled Assessments', 'Recurring validations on defined agent scopes.',
    `<button class="btn primary" data-act="schedWiz">${ic('plus')}New Scheduled Assessment</button>`,
    [['clock', D.SCHEDULES.length, 'Schedules'], ['play', act, 'Enabled'], ['x', can, 'Cancelled'], ['bolt', 'Wed 29 Oct, 22:00', 'Next run']]) +
  `<div class="after-hero"><div class="grid g4">${tile('clock', 'Active schedules', act, `of ${D.SCHEDULES.length} defined`, 'green')}${tile('x', 'Cancelled', can, 'will not run', 'red')}${tile('play', 'Next run', 'Mon 09:00', 'Windows Security Baseline', 'accent')}${tile('check', 'Last 4 weeks', '100%', 'runs completed', 'green')}</div></div>` +
  K.card('Next 7 days', `<div class="week">${D.WEEK.map(([d, ev], i) => `<div class="wk-day ${i === 0 ? 'today' : ''}"><div class="wk-h">${d}</div>${ev.map(([t, n]) => `<div class="wk-ev"><b>${t}</b>${n}</div>`).join('') || '<div class="muted" style="font-size:11px">—</div>'}</div>`).join('')}</div>`, `<span class="muted" style="font-size:12px">${D.WEEK.reduce((a, [, e]) => a + e.length, 0)} runs planned</span>`, 'mt') +
  `<div style="height:14px"></div><div class="row between" style="gap:10px;flex-wrap:wrap;margin-bottom:10px">${chips('sF', 'All', [['All', 'All', D.SCHEDULES.length], ['Enabled', 'Enabled', act], ['Cancelled', 'Cancelled', can]])}${K.search('sQ', 'Search schedules...')}</div>` +
  (list.length ? `<div class="card pad0">${table(['Assessment', 'Mode', 'Targets', 'Recurrence', 'Last run', 'Next run', 'Last result', 'Status', ''], list.map(s => `<tr data-act="openSched" data-a="${s.id}">
    <td><div><b>${s.name}</b></div><div class="mono muted" style="font-size:11px">${s.id}</div></td><td>${tag(s.mode, 'blue')}</td><td>${s.targets} agents</td><td class="muted">${s.rec}</td><td class="mono muted">${s.lastRun}</td><td>${s.next}</td><td>${tag(s.last, s.last.startsWith('PASS') ? 'green' : s.last.startsWith('WARN') ? 'amber' : 'red')}</td><td>${stag(s.state)}</td>
    <td style="white-space:nowrap"><button class="btn sm" data-act="schedEdit" data-a="${s.id}">Edit</button> ${s.state === 'Active' ? `<button class="btn sm danger" data-act="schedToggle" data-a="${s.id}">Cancel</button>` : `<button class="btn sm" data-act="schedToggle" data-a="${s.id}">Resume</button>`}</td></tr>`))}</div>` : K.empty('search', 'No schedules match', 'Clear the filters to see all schedules.'));
};
Object.assign(A, {
  schedEdit: () => A.schedWiz(),
  schedToggle: d => { const s = D.SCHEDULES.find(x => x.id === d.a); s.state = s.state === 'Active' ? 'Cancelled' : 'Active'; if (s.state === 'Cancelled') s.next = '—'; toast(s.state === 'Cancelled' ? 'Schedule cancelled' : 'Schedule resumed', s.name.slice(0, 44), s.state === 'Cancelled' ? 'warn' : 'success'); AUD.h.closeDrawer(); AUD.render(); }
});

// ================= INITIATIVES =================
const INI = [
  ['INI-07', 'Identity Hardening', 'Identity Team', 64, '15 Nov 2026', 'On Track', 9, 'Active', 'Remove excessive ACLs and retire vulnerable ADCS templates across the forest.', [['Scope agreed', 100], ['Baseline validation', 100], ['Fix ACLs', 70], ['Retire ESC1 template', 40], ['Re-validate', 0]]],
  ['INI-08', 'Q4 Ransomware Readiness', 'SOC Lead', 38, '30 Nov 2026', 'At Risk', 14, 'Active', 'Validate ransomware detection and containment on tier-0 and file-tier hosts.', [['Scope agreed', 100], ['Baseline validation', 100], ['Containment playbook tuned', 35], ['Re-validate', 0]]],
  ['INI-09', 'RBI CSCF Annual Drill', 'Compliance', 82, '31 Oct 2026', 'On Track', 6, 'Active', 'Annual RBI Cyber Security Framework drill: baseline controls posture across banking systems.', [['Baseline', 100], ['Control mapping', 100], ['Gap drills', 75], ['Re-validate', 40]]],
  ['INI-06', 'FY25 Phishing Resilience', 'Messaging', 100, '30 Jun 2026', 'Completed', 8, 'Closed', 'Raise email gateway detection of credential phishing and QR lures above 95%.', [['Baseline', 100], ['Rule tuning', 100], ['QR-code lure coverage', 100], ['Re-validate', 100]]],
  ['INI-05', 'Legacy EDR Migration', 'Endpoint Team', 100, '31 Mar 2026', 'Completed', 5, 'Archived', 'Validate parity of the replacement EDR against the legacy product.', [['Inventory', 100], ['Parity tests', 100], ['Cutover', 100]]]];
swap(D.INITIATIVES, INI.map(([id, name, owner, progress, due, status, jobs, state, desc, ms], i) => ({ id, name, owner, progress, due, status, jobs, state, desc, ms, by: 'admin@preview.local', created: `${15 - i}/09/2026, 17:30` })));
P.initiatives = () => {
  const q = (S.iQ || '').toLowerCase(), f = S.iF || 'Active';
  const cnt = k => D.INITIATIVES.filter(x => k === 'All' || x.state === k).length;
  const list = D.INITIATIVES.filter(x => (!q || (x.name + x.owner + x.id).toLowerCase().includes(q)) && (f === 'All' || x.state === f));
  const act = D.INITIATIVES.filter(x => x.state === 'Active'), avg = Math.round(act.reduce((a, x) => a + x.progress, 0) / (act.length || 1));
  return K.hero('flag', 'Initiatives', 'Programmes that group validation jobs into measurable remediation goals.',
    `<button class="btn primary" data-act="newInitiative">${ic('plus')}New Initiative</button>`,
    [['flag', act.length, 'Active'], ['trend', avg + '%', 'Avg progress'], ['alert', D.INITIATIVES.filter(x => x.status === 'At Risk').length, 'At risk'], ['box', D.INITIATIVES.reduce((a, x) => a + x.jobs, 0), 'Jobs attached']]) +
  `<div class="row between" style="gap:10px;flex-wrap:wrap;margin:14px 0">${chips('iF', 'Active', ['Active', 'Closed', 'Archived', 'All'].map(x => [x, x, cnt(x)]))}${K.search('iQ', 'Search initiatives or owners...')}</div>` +
  (list.length ? `<div class="grid g2">${list.map(x => `<div class="card hov" data-act="openInit" data-a="${x.id}">
    <div class="row between"><div><h2>${x.name}</h2><div class="muted" style="font-size:12px;margin-top:4px">${x.id} · ${K.avatar(x.owner)} ${x.owner}</div></div><div class="row" style="gap:6px">${tag(x.state, x.state === 'Active' ? 'green' : 'blue')}${st(x.status)}</div></div>
    <p class="muted" style="font-size:12.5px;margin:10px 0 12px">${x.desc}</p>
    <div class="ms-strip">${x.ms.map(([n, v]) => `<i class="${v >= 100 ? 'done' : v > 0 ? 'run' : ''}" title="${n} — ${v}%"></i>`).join('')}</div>
    <div class="row between" style="font-size:12px;color:var(--muted-hi);margin:10px 0 6px"><span>${x.ms.filter(m => m[1] >= 100).length} of ${x.ms.length} milestones</span><span>${x.progress}%</span></div>${bar(x.progress, x.status === 'At Risk' ? 'amber' : x.status === 'Planned' ? '' : 'green')}
    <div class="row mt" style="margin-top:14px;font-size:12px;color:var(--muted)"><span>${ic('clock', 'sm')} Due ${x.due}</span><span>${ic('box', 'sm')} ${x.jobs} jobs</span></div>
    <div class="init-meta"><span>${K.avatar('admin preview')} Created by ${x.by}</span><span class="muted">${x.created}</span></div></div>`).join('')}</div>` : K.empty('search', 'No initiatives match', 'Clear the filters to see everything.'));
};

// ================= CAMPAIGNS =================
const CAMP = [
  ['camp-2156803233', 'APT29 Emulation', 'Apt29 Kill Chain', 'Completed', [5, 0, 0], '20/10/2026, 17:30'], ['camp-e7edc49543', 'Weekly Posture Check', 'Windows Security Config', 'Partial', [3, 1, 1], '17/10/2026, 17:30'],
  ['camp-bd462a25fc', 'Akira Kill Chain Validation', 'Akira Kill Chain', 'Completed', [5, 0, 0], '14/10/2026, 17:30'], ['camp-3446d90eda', 'Domain Controller Credential Test', 'Credential Access', 'Completed', [4, 1, 0], '11/10/2026, 17:30'],
  ['camp-b5e126f8dd', 'Engineering Linux Baseline', 'Linux Discovery', 'Completed', [5, 0, 0], '08/10/2026, 17:30'], ['camp-285e18e383', 'Finance Endpoint Sweep', 'Lolbin Execution', 'Partial', [3, 1, 1], '05/10/2026, 17:30']];
swap(D.CAMPAIGNS, CAMP.map(([id, name, scenario, status, mix, started], i) => ({ id, name, scenario, scope: scenario, status, mix, start: started, runs: 5, pass: Math.round(mix[0] / 5 * 100), phase: 'Complete', by: 'admin@preview.local', targets: '5/5',
  phases: [['Dispatch', 100], ['Execution', Math.round(mix[0] / 5 * 100)], ['Collection', 100], ['Scoring', Math.round(mix[0] / 5 * 100)]] })));
P.campaigns = () => {
  const q = (S.cQ || '').toLowerCase(), f = S.cF || 'All';
  const cnt = k => D.CAMPAIGNS.filter(c => k === 'All' || c.status === k).length;
  const list = D.CAMPAIGNS.filter(c => (!q || (c.name + c.scenario + c.id).toLowerCase().includes(q)) && (f === 'All' || c.status === f));
  return K.hero('campaign', 'Campaigns', 'One scenario fanned out across many agents. Open a campaign for the per-agent breakdown and result mix.',
    `<button class="btn primary" data-act="newCampaign">${ic('plus')}New campaign</button>`,
    [['campaign', D.CAMPAIGNS.length, 'Campaigns'], ['check', cnt('Completed'), 'Completed'], ['alert', cnt('Partial'), 'Partial'], ['box', D.CAMPAIGNS.reduce((a, c) => a + c.runs, 0), 'Runs executed']]) +
  `<div class="row between" style="gap:10px;flex-wrap:wrap;margin:14px 0">${chips('cF', 'All', [['All', 'All', cnt('All')], ['Completed', 'Completed', cnt('Completed')], ['Partial', 'Partial', cnt('Partial')]])}<div class="row" style="gap:8px">${K.search('cQ', 'Search campaigns...')}<button class="btn" data-act="toast" data-a="Schedule" data-b="Coming soon" data-c="info">${ic('clock')}Schedule · soon</button></div></div>` +
  (list.length ? `<div class="grid g3">${list.map(c => { const t = c.mix[0] + c.mix[1] + c.mix[2]; return `<div class="card hov" data-act="openCampaign" data-a="${c.id}"><div class="row between"><h2>${c.name}</h2>${st(c.status)}</div>
    <p class="muted" style="margin:6px 0 0;font-size:12.5px">${c.scenario} · ${c.targets} agents</p><div class="mono muted" style="font-size:11px;margin-top:2px">${c.id} · ${c.by}</div>
    <div class="mix-bar" style="margin:14px 0 6px"><i style="width:${c.mix[0] / t * 100}%;background:var(--green)"></i><i style="width:${c.mix[1] / t * 100}%;background:var(--amber)"></i><i style="width:${c.mix[2] / t * 100}%;background:var(--red)"></i></div>
    <div class="mix-k" style="justify-content:flex-start;margin-bottom:12px"><span style="color:var(--green)">${c.mix[0]} pass</span><span style="color:var(--amber)">${c.mix[1]} partial</span><span style="color:var(--red)">${c.mix[2]} fail</span></div>
    <div class="grid g3" style="gap:8px;margin-bottom:12px">${[['Runs', c.runs], ['Pass rate', c.pass + '%'], ['Started', c.start.split(',')[0]]].map(([a, b]) => `<div><div class="muted" style="font-size:11px">${a}</div><b style="font-weight:600">${b}</b></div>`).join('')}</div>
    <div class="row"><button class="btn sm" data-act="openCampaign" data-a="${c.id}">View per-agent breakdown</button></div></div>`; }).join('')}</div>` : K.empty('search', 'No campaigns match', 'Clear the filters to see all campaigns.'));
};

// ================= IOC REGISTRY: Add IOC + Import work =================
const ICB = (n, a, b) => `<button class="btn primary" data-act="${a}">${b}</button>`;
let iocAct = 'Alert';
P.iocs = (o => () => o().replace('data-act="toast" data-a="Indicator added"', 'data-act="addIoc"'))(P.iocs);
Object.assign(A, {
  addIoc: () => { iocAct = 'Alert'; AUD.modal(AUD.h.mhd('Add IOC', 'plus') + `<div class="modal-bd"><div class="field"><label>Indicator value</label><input class="input" id="ni-val" placeholder="e.g. 203.0.113.9 or evil-domain[.]com"></div>
    <div class="field mt" style="margin-top:12px"><label>Type</label><select class="select" id="ni-type" style="width:100%">${['IPv4', 'Domain', 'SHA-256', 'URL', 'Filename', 'Registry key', 'Email'].map(t => `<option>${t}</option>`).join('')}</select></div>
    <div class="field mt" style="margin-top:12px"><label>Source</label><input class="input" id="ni-src" value="Manual entry"></div>
    <div class="field mt" style="margin-top:12px"><label>Action</label><div class="chips">${['Block', 'Alert', 'Monitor'].map(a => `<button class="chip ${a === 'Alert' ? 'on' : ''}" data-act="iocAct" data-a="${a}">${a}</button>`).join('')}</div></div><div id="ni-err" class="muted" style="color:var(--red);margin-top:10px;font-size:12.5px"></div></div>
    <div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="saveIoc">Add indicator</button></div>`); },
  iocAct: (d, el) => { iocAct = d.a; el.parentNode.querySelectorAll('.chip').forEach(c => c.classList.toggle('on', c === el)); },
  saveIoc: () => {
    const v = id => (document.getElementById(id) || {}).value || '', val = v('ni-val').trim();
    if (!val) return document.getElementById('ni-err').textContent = 'Enter an indicator value.';
    if (D.IOCS.some(x => x.value === val)) return document.getElementById('ni-err').textContent = 'This indicator already exists.';
    D.IOCS.unshift({ value: val, type: v('ni-type'), source: v('ni-src') || 'Manual entry', conf: 70, action: iocAct, seen: 'just now', first: 'Today', sightings: 0, tags: ['manual'] });
    AUD.closeModal(); toast('Indicator added', `${val} · ${iocAct}`, 'success'); AUD.render();
  },
  importIocGo: () => {
    const n = ['198.51.100.88', 'c2-beacon-sync[.]io', 'f0e1d2…a9b8c7', 'http://dl-update-svc[.]top/p.bin', 'upd_helper.dll'], ty = ['IPv4', 'Domain', 'SHA-256', 'URL', 'Filename'];
    let added = 0; n.forEach((val, i) => { if (!D.IOCS.some(x => x.value === val)) { D.IOCS.unshift({ value: val, type: ty[i], source: 'Imported file', conf: 75, action: iocAct, seen: 'just now', first: 'Today', sightings: 0, tags: ['imported'] }); added++; } });
    AUD.closeModal(); toast('Indicators imported', `${added} added · demo sample rows`, 'success'); AUD.render();
  }
});
const imp = A.importIoc;
A.importIoc = () => { iocAct = 'Alert'; imp(); const b = document.querySelector('.modal [data-a="Indicators imported"]'); if (b) { b.setAttribute('data-act', 'importIocGo'); b.removeAttribute('data-a'); } document.querySelectorAll('.modal .chip').forEach(c => c.setAttribute('data-act', 'iocAct') || c.setAttribute('data-a', c.textContent.trim())); };
})();
