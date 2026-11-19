// Deep page modules, group 1 — Operations: Live Runs, Kubernetes, Scheduled, Initiatives, Campaigns, Factory
(() => {
const { S, P, A, h, toast, modal, closeModal } = AUD;
const { tag, st, bar, table, kpi, pageHead, tabs, curTab, drawer, dhd, mhd, relBlock } = h;
const K = KIT;
const dr = (title, sub, icon, body, foot = '') => drawer(dhd(title, sub, icon) + `<div class="drawer-bd">${body}</div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button>${foot}</div>`);

// ============ LIVE RUNS ============
P.runs = () => {
  const q = (S.rQ || '').toLowerCase();
  const list = D.RUNS.filter(r => (!q || (r.name + r.id + r.target).toLowerCase().includes(q)) && (!S.rSt || r.status === S.rSt) && (!S.rTg || r.target === S.rTg));
  const live = D.RUNS.filter(r => r.status === 'Running' || r.status === 'Queued');
  const done = D.RUNS.filter(r => r.status === 'Passed' || r.status === 'Failed');
  const passed = done.filter(r => r.status === 'Passed').length;
  const rows = list.map(r => `<tr data-act="openRun" data-a="${r.id}">
    <td><div>${r.name}</div><div class="mono muted" style="font-size:11px">${r.id}</div></td>
    <td class="muted">${r.target}</td><td>${st(r.status)}</td>
    <td style="min-width:170px"><div class="row" style="gap:8px"><div class="grow">${bar(Math.round(r.progress), r.status === 'Failed' ? 'red' : r.status === 'Passed' ? 'green' : 'cyan')}</div><span class="mono muted" data-prog="${r.id}" style="width:38px;text-align:right">${Math.round(r.progress)}%</span></div></td>
    <td class="muted" style="max-width:260px" data-step="${r.id}">${r.step}</td><td class="mono muted">${r.started}</td><td class="mono muted">${r.dur}</td>
    <td class="num"><button class="btn sm ghost" data-act="stopRun" data-a="${r.id}" title="Stop">${ic('stop', 'sm')}</button></td></tr>`);
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  return K.hero('play', 'Live Runs', 'Scenario executions in progress, queued and recently completed.',
    `<button class="btn" data-act="toast" data-a="Export started" data-b="CSV will be emailed to you">${ic('download')}Export</button><button class="btn primary" data-act="nav" data-a="scenarios">${ic('plus')}New Run</button>`,
    [['play', D.RUNS.filter(r => r.status === 'Running').length, 'Running now'], ['clock', D.RUNS.filter(r => r.status === 'Queued').length, 'Queued'], ['check', Math.round(passed / done.length * 100) + '%', 'Pass rate (all)'], ['agent', '7 / 412', 'Agents busy']]) +
  (live.length ? `<h4 class="sec-label">${ic('bolt', 'sm')} In flight</h4><div class="live-strip">${live.map(r => `<div class="live-card" data-act="openRun" data-a="${r.id}">
      <div class="row between"><span class="mono muted" style="font-size:11px">${r.id}</span>${st(r.status)}</div>
      <b class="lc-name">${r.name}</b><div class="muted lc-tgt">${ic('server', 'sm')} ${r.target}</div>
      <div class="lp"><div class="row" style="gap:8px"><div class="grow">${bar(Math.round(r.progress), 'cyan')}</div><span class="mono muted" data-prog="${r.id}" style="width:38px;text-align:right">${Math.round(r.progress)}%</span></div></div>
      <div class="muted lc-step" data-step="${r.id}">${r.step}</div></div>`).join('')}</div>` : '') +
  `<div class="grid g2 mb mt">${K.card('Runs this week', chartSlot({ type: 'bar', stacked: true, labels: days, h: 170, series: [{ name: 'Passed', color: '#10b981', data: [14, 18, 16, 21, 19, 6, 9] }, { name: 'Failed', color: '#ef4444', data: [2, 1, 3, 2, 1, 0, 1] }] }), '<div class="legend"><span><i style="background:#10b981"></i>Passed</span><span><i style="background:#ef4444"></i>Failed</span></div>')}
    ${K.card('Outcome mix', K.donut([{ label: 'Passed', value: passed + 82, color: '#10b981' }, { label: 'Failed', value: done.length - passed + 9, color: '#ef4444' }, { label: 'Running', value: 1, color: '#22d3ee' }, { label: 'Queued', value: 1, color: '#a78bfa' }], 'runs, 7 days'))}</div>` +
  K.filters(K.search('rQ', 'Search runs by name, ID or target...'), K.select('rSt', 'All statuses', ['Running', 'Queued', 'Passed', 'Failed']), K.select('rTg', 'All targets', [...new Set(D.RUNS.map(r => r.target))]), (S.rQ || S.rSt || S.rTg) ? K.clearBtn(['rQ', 'rSt', 'rTg']) : '') +
  (list.length ? `<div class="card pad0">${table(['Run', 'Target', 'Status', 'Progress', 'Current step', 'Started', 'Duration', { t: '' }], rows)}</div>` : K.empty('search', 'No runs match these filters', 'Try a different status or target.'));
};

// ============ KUBERNETES ============
P.k8s = () => {
  const q = (S.kQ || '').toLowerCase();
  const list = D.K8S.filter(k => (!q || (k.name + k.id).toLowerCase().includes(q)) && (!S.kCl || k.cluster === S.kCl) && (!S.kSt || k.status === S.kSt));
  return K.hero('server', 'Kubernetes Scenarios', 'Cluster-level attack simulations for AKS, EKS and self-managed clusters.',
    `<button class="btn primary" data-act="newK8sRun">${ic('plus')}New K8s Run</button>`,
    [['server', D.CLUSTERS.length, 'Clusters connected'], ['box', D.CLUSTERS.reduce((a, c) => a + c.pods, 0), 'Pods in scope'], ['target', D.K8S.length, 'K8s scenarios'], ['trend', Math.round(D.CLUSTERS.reduce((a, c) => a + c.posture, 0) / D.CLUSTERS.length) + '%', 'Avg posture']]) +
  `<h4 class="sec-label">${ic('server', 'sm')} Clusters <span class="muted">· click to filter</span></h4><div class="grid g4 mb">${D.CLUSTERS.map(c => `<div class="card cl-card ${S.kCl === c.id ? 'sel' : ''}" data-act="pickCluster" data-a="${c.id}">
    <div class="row between"><b class="mono">${c.id}</b>${st(c.status)}</div><div class="muted" style="font-size:12px;margin:3px 0 12px">${c.provider} · v${c.version}</div>
    <div class="row between" style="font-size:12px"><span class="muted">Posture</span><b>${c.posture}%</b></div><div style="margin:5px 0 10px">${bar(c.posture, K.pct(c.posture))}</div>
    <div class="row" style="gap:14px;font-size:12px;color:var(--muted)"><span>${c.nodes} node${c.nodes > 1 ? "s" : ""}</span><span>${c.pods} pods</span><span>${c.runs} runs</span></div></div>`).join('')}</div>` +
  K.filters(K.search('kQ', 'Search K8s scenarios...'), K.select('kCl', 'All clusters', D.CLUSTERS.map(c => c.id)), K.select('kSt', 'All statuses', ['Active', 'Draft']), (S.kQ || S.kCl || S.kSt) ? K.clearBtn(['kQ', 'kCl', 'kSt']) : '') +
  (list.length ? `<div class="card pad0">${table(['Scenario', 'Cluster', 'Namespace', 'Techniques', 'Duration', 'Status', 'Last result', { t: '' }], list.map(k => `<tr data-act="openK8s" data-a="${k.id}">
    <td><div>${k.name}</div><div class="mono muted" style="font-size:11px">${k.id}</div></td><td class="mono">${k.cluster}</td><td class="mono">${k.ns}</td><td>+${k.techniques}</td><td>${k.mins} min</td><td>${st(k.status)}</td><td>${k.last === 'NEVER' ? '<span class="muted">Never run</span>' : st(k.last)}</td>
    <td class="num"><button class="btn sm ghost" data-act="toast" data-a="K8s run started" data-b="${k.name} on ${k.cluster}" title="Run">${ic('play', 'sm')}</button></td></tr>`))}</div>` : K.empty('search', 'No K8s scenarios match', 'Clear the cluster or status filter.'));
};
A.pickCluster = d => { S.kCl = S.kCl === d.a ? '' : d.a; AUD.render(); };
A.newK8sRun = () => modal(mhd('New K8s Run', 'server') + `<div class="modal-bd"><div class="field"><label>Scenario</label><select class="select">${D.K8S.map(k => `<option>${k.name}</option>`).join('')}</select></div><div class="field"><label>Cluster</label><select class="select">${D.CLUSTERS.map(c => `<option>${c.id} — ${c.provider}</option>`).join('')}</select></div><div class="alert info">${ic('bell')}<div>Runs use a read-only service account unless the scenario declares otherwise. All created objects are removed at the end.</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="K8s run queued" data-b="Starts within 1 minute">Start run</button></div>`, 'lg');
A.openK8s = d => {
  const k = D.K8S.find(x => x.id === d.a), c = D.CLUSTERS.find(x => x.id === k.cluster);
  dr(k.name, `${k.id} · ${k.cluster}`, 'server', `<div class="row between mb">${st(k.status)}<span class="muted">Last result: ${k.last === 'NEVER' ? 'never run' : k.last}</span></div>
    ${K.kv([['Cluster', `<span class="mono">${k.cluster}</span> · ${c.provider}`], ['Namespace', `<span class="mono">${k.ns}</span>`], ['Techniques', '+' + k.techniques], ['Est. duration', k.mins + ' min'], ['Cluster posture', `${c.posture}%`]])}
    <h4 style="margin:18px 0 8px">Steps</h4><div class="timeline">${D.K8S_STEPS.map((s, i) => `<div class="tl-step"><div class="tl-dot">${i + 1}</div><div><div class="t">${s}</div></div></div>`).join('')}</div>
    ${relBlock([['server', 'Cluster ' + c.id, `${c.nodes} nodes · ${c.pods} pods`, 'pickClusterGo', c.id], ['mapped', 'ATT&CK coverage', 'Containers matrix', 'nav', 'coverage']])}`,
    `<button class="btn primary" data-act="toast" data-a="K8s run started" data-b="${k.name}">${ic('play')}Run now</button>`);
};
A.pickClusterGo = d => { AUD.closeDrawer(); S.kCl = d.a; AUD.render(); };

// ============ SCHEDULED ============
P.scheduled = () => {
  const q = (S.sQ || '').toLowerCase();
  const list = D.SCHEDULES.filter(s => (!q || (s.name + s.scope + s.id).toLowerCase().includes(q)) && (!S.sSt || s.state === S.sSt));
  const act = D.SCHEDULES.filter(s => s.state === 'Active').length;
  return K.hero('clock', 'Scheduled Assessments', 'Recurring validations on defined agent scopes.',
    `<button class="btn primary" data-act="schedWiz">${ic('plus')}New Scheduled Assessment</button>`,
    [['clock', D.SCHEDULES.length, 'Schedules'], ['play', act, 'Active'], ['pause', D.SCHEDULES.length - act, 'Paused'], ['bolt', 'Sat 25 Oct, 23:30', 'Next run']]) +
  K.card('Next 7 days', `<div class="week">${D.WEEK.map(([d, ev], i) => `<div class="wk-day ${i === 0 ? 'today' : ''}"><div class="wk-h">${d}</div>${ev.map(([t, n]) => `<div class="wk-ev"><b>${t}</b>${n}</div>`).join('') || '<div class="muted" style="font-size:11px">—</div>'}</div>`).join('')}</div>`, `<span class="muted" style="font-size:12px">${D.WEEK.reduce((a, [, e]) => a + e.length, 0)} runs planned</span>`) +
  `<div style="height:14px"></div>` + K.filters(K.search('sQ', 'Search schedules...'), K.select('sSt', 'All states', ['Active', 'Paused']), (S.sQ || S.sSt) ? K.clearBtn(['sQ', 'sSt']) : '') +
  (list.length ? `<div class="card pad0">${table(['Assessment', 'Scope', 'Schedule (cron)', 'Next run', 'Last result', 'State', ''], list.map(s => `<tr data-act="openSched" data-a="${s.id}">
   <td><div>${s.name}</div><div class="mono muted" style="font-size:11px">${s.id}</div></td><td class="muted">${s.scope}</td><td class="mono">${s.cron}</td><td>${s.next}</td><td>${tag(s.last, s.last.startsWith('PASS') ? 'green' : s.last.startsWith('WARN') ? 'amber' : 'red')}</td><td>${st(s.state)}</td>
   <td class="num"><div class="row" style="justify-content:flex-end"><button class="btn sm" data-act="schedToggle" data-a="${s.id}">${s.state === 'Paused' ? ic('play', 'sm') + 'Resume' : ic('pause', 'sm') + 'Pause'}</button><button class="btn sm ghost" data-act="toast" data-a="Run started" data-b="${s.name} · ad-hoc run" title="Run now">${ic('play', 'sm')}</button></div></td></tr>`))}</div>` : K.empty('search', 'No schedules match', 'Clear the filters to see all schedules.'));
};
A.schedToggle = d => { const s = D.SCHEDULES.find(x => x.id === d.a); s.state = s.state === 'Paused' ? 'Active' : 'Paused'; toast(s.state === 'Paused' ? 'Schedule paused' : 'Schedule resumed', s.name); AUD.render(); };
A.openSched = d => {
  const s = D.SCHEDULES.find(x => x.id === d.a);
  dr(s.name, `${s.id} · ${s.scope}`, 'clock', `<div class="row between mb">${st(s.state)}<span>${tag(s.last, s.last.startsWith('PASS') ? 'green' : s.last.startsWith('WARN') ? 'amber' : 'red')}</span></div>
    ${K.kv([['Scope', s.scope], ['Cron', `<span class="mono">${s.cron}</span>`], ['Next run', s.next], ['Jitter', '± 7 min (anti-thundering-herd)'], ['Notifications', 'SOC channel on FAIL']])}
    <h4 style="margin:18px 0 8px">Last 6 runs</h4>${chartSlot({ type: 'bar', labels: ['#1', '#2', '#3', '#4', '#5', '#6'], h: 130, series: [{ name: 'Pass rate %', color: '#3b82f6', data: [92, 88, 95, 71, 90, parseInt(s.last.replace(/\D/g, '')) || 90] }] })}
    <h4 style="margin:18px 0 8px">Run history</h4>${table(['Run', 'When', 'Result'], [['RUN-5517', 'Last scheduled', s.last], ['RUN-5489', 'Prev. week', 'PASS 92%'], ['RUN-5461', '2 weeks ago', 'PASS 88%']].map(r => `<tr class="noclick"><td class="mono">${r[0]}</td><td class="muted">${r[1]}</td><td>${r[2]}</td></tr>`))}`,
    `<button class="btn" data-act="schedToggle" data-a="${s.id}">${s.state === 'Paused' ? 'Resume' : 'Pause'}</button><button class="btn primary" data-act="toast" data-a="Run started" data-b="${s.name}">${ic('play')}Run now</button>`);
};

// ============ INITIATIVES ============
P.initiatives = () => {
  const q = (S.iQ || '').toLowerCase();
  const list = D.INITIATIVES.filter(x => (!q || (x.name + x.owner + x.id).toLowerCase().includes(q)) && (!S.iSt || x.status === S.iSt));
  const avg = Math.round(D.INITIATIVES.reduce((a, x) => a + x.progress, 0) / D.INITIATIVES.length);
  return K.hero('flag', 'Initiatives', 'Programmes that group validation jobs into measurable remediation goals.',
    `<button class="btn primary" data-act="newInitiative">${ic('plus')}New Initiative</button>`,
    [['flag', D.INITIATIVES.length, 'Initiatives'], ['trend', avg + '%', 'Avg progress'], ['alert', D.INITIATIVES.filter(x => x.status === 'At Risk').length, 'At risk'], ['box', D.INITIATIVES.reduce((a, x) => a + x.jobs, 0), 'Jobs attached']]) +
  K.filters(K.search('iQ', 'Search initiatives or owners...'), K.select('iSt', 'All statuses', ['In progress', 'At Risk', 'Planned', 'Completed']), (S.iQ || S.iSt) ? K.clearBtn(['iQ', 'iSt']) : '') +
  (list.length ? `<div class="grid g2">${list.map(x => `<div class="card hov" data-act="openInit" data-a="${x.id}">
    <div class="row between"><div><h2>${x.name}</h2><div class="muted" style="font-size:12px;margin-top:4px">${x.id} · ${K.avatar(x.owner)} ${x.owner}</div></div>${st(x.status)}</div>
    <p class="muted" style="font-size:12.5px;margin:10px 0 12px">${x.desc}</p>
    <div class="ms-strip">${x.ms.map(([n, v]) => `<i class="${v >= 100 ? 'done' : v > 0 ? 'run' : ''}" title="${n} — ${v}%"></i>`).join('')}</div>
    <div class="row between" style="font-size:12px;color:var(--muted-hi);margin:10px 0 6px"><span>${x.ms.filter(m => m[1] >= 100).length} of ${x.ms.length} milestones</span><span>${x.progress}%</span></div>${bar(x.progress, x.status === 'At Risk' ? 'amber' : x.status === 'Planned' ? '' : 'green')}
    <div class="row mt" style="margin-top:14px;font-size:12px;color:var(--muted)"><span>${ic('clock', 'sm')} Due ${x.due}</span><span>${ic('box', 'sm')} ${x.jobs} jobs</span></div></div>`).join('')}</div>` : K.empty('search', 'No initiatives match', 'Clear the filters to see everything.'));
};
A.openInit = d => {
  const x = D.INITIATIVES.find(i => i.id === d.a); S.initSel = x.id;
  dr(x.name, `${x.id} · ${x.owner}`, 'flag', `<p class="muted" style="margin:0 0 14px">${x.desc}</p><div class="grid g3 mb">${kpi('Progress', x.progress + '%', '', 'trend', '--accent')}${kpi('Jobs', x.jobs, '', 'box', '--cyan')}${kpi('Due', x.due.slice(0, 6), '', 'clock', '--amber')}</div>
    <h4 class="mb">Milestones</h4><div class="timeline">${x.ms.map(([n, v], i) => `<div class="tl-step ${v >= 100 ? 'done' : v > 0 ? 'run' : ''}"><div class="tl-dot">${v >= 100 ? '✓' : i + 1}</div><div class="grow"><div class="t">${n}</div><div class="d">${v >= 100 ? 'Complete' : v > 0 ? v + '% done' : 'Not started'}</div></div></div>`).join('')}</div>
    <h4 style="margin:18px 0 8px">Attached jobs</h4>${table(['Job', 'Status'], [['ACL audit — Domain Controllers', 'Passed'], ['AdminSDHolder remediation', 'In progress'], ['ADCS template review', 'Open']].map(r => `<tr class="noclick"><td>${r[0]}</td><td>${st(r[1])}</td></tr>`))}`,
    `<button class="btn primary" data-act="attachJob">${ic('plus')}Attach Job</button>`);
};

// ============ CAMPAIGNS ============
P.campaigns = () => {
  const q = (S.cQ || '').toLowerCase();
  const list = D.CAMPAIGNS.filter(c => (!q || (c.name + c.scope).toLowerCase().includes(q)) && (!S.cSt || c.status === S.cSt));
  return K.hero('campaign', 'Campaigns', 'Coordinated, multi-phase validation programmes across the estate.',
    `<button class="btn primary" data-act="newCampaign">${ic('plus')}New Campaign</button>`,
    [['campaign', D.CAMPAIGNS.length, 'Campaigns'], ['play', D.CAMPAIGNS.filter(c => c.status === 'Running').length, 'Running'], ['box', D.CAMPAIGNS.reduce((a, c) => a + c.runs, 0), 'Runs executed'], ['check', Math.round(D.CAMPAIGNS.filter(c => c.pass).reduce((a, c) => a + c.pass, 0) / D.CAMPAIGNS.filter(c => c.pass).length) + '%', 'Avg pass rate']]) +
  K.filters(K.search('cQ', 'Search campaigns...'), K.select('cSt', 'All statuses', ['Running', 'Completed', 'Scheduled']), (S.cQ || S.cSt) ? K.clearBtn(['cQ', 'cSt']) : '') +
  (list.length ? `<div class="grid g3">${list.map(c => `<div class="card hov" data-act="openCampaign" data-a="${c.id}"><div class="row between"><h2>${c.name}</h2>${st(c.status)}</div><p class="muted" style="margin:6px 0 0;font-size:12.5px">${c.scope}</p>
  <div class="phase-strip">${c.phases.map(([n, v]) => `<i class="${v === null ? '' : v >= 85 ? 'ok' : 'warn'}" title="${n}${v === null ? ' — pending' : ' — ' + v + '%'}"></i>`).join('')}</div>
  <div class="muted" style="font-size:12px;margin-bottom:14px">${c.phase}</div>
  <div class="grid g3" style="gap:8px;margin-bottom:12px">${[['Runs', c.runs], ['Pass rate', c.pass ? c.pass + '%' : '—'], ['Start', c.start]].map(([a, b]) => `<div><div class="muted" style="font-size:11px">${a}</div><b style="font-weight:600">${b}</b></div>`).join('')}</div>
  <div class="row"><button class="btn sm" data-act="openCampaign" data-a="${c.id}">View</button><button class="btn sm ghost" data-act="toast" data-a="Campaign ${c.status === 'Running' ? 'paused' : 'started'}" data-b="${c.name}">${c.status === 'Running' ? 'Pause' : 'Start'}</button></div></div>`).join('')}</div>` : K.empty('search', 'No campaigns match', 'Clear the filters.'));
};
A.openCampaign = d => {
  const c = D.CAMPAIGNS.find(x => x.id === d.a);
  dr(c.name, `${c.id} · ${c.scope}`, 'campaign', `<div class="row between mb">${st(c.status)}<span class="muted">${c.runs} runs · ${c.pass ? c.pass + '% pass' : 'no results yet'}</span></div>
    <div class="timeline">${c.phases.map(([p, v], i) => `<div class="tl-step ${v === null ? '' : 'done'}"><div class="tl-dot">${v === null ? i + 1 : '✓'}</div><div class="grow"><div class="t">${p}</div><div class="d">${v === null ? 'Pending' : 'Completed · ' + v + '% pass'}</div></div>${v !== null ? tag(v + '%', v >= 85 ? 'green' : 'amber') : ''}</div>`).join('')}</div>
    ${relBlock([['report', 'Campaign report', 'Generate executive summary', 'nav', 'reports'], ['alert', 'Findings from this campaign', '3 open', 'nav', 'findings']])}`,
    `<button class="btn primary" data-act="toast" data-a="Campaign ${c.status === 'Running' ? 'paused' : 'started'}" data-b="${c.name}">${c.status === 'Running' ? 'Pause' : 'Start'}</button>`);
};

// ============ FACTORY HEALTH ============
P.factory = () => {
  const b = S.fbF || '';
  const builds = D.FACTORY.builds.filter(x => !b || x.result === b);
  return K.hero('factory', 'Factory Health', 'Health of the scenario build, signing and content pipelines.',
    `<button class="btn" data-act="toast" data-a="Pipelines re-checked">${ic('refresh')}Re-check</button>`,
    [['factory', '142', 'Built (30d)'], ['lock', '105 / 107', 'Signed & verified'], ['check', D.FACTORY.pipelines.filter(p => p.state === 'Healthy').length + ' / ' + D.FACTORY.pipelines.length, 'Pipelines healthy'], ['clock', '4 min', 'Avg queue wait']]) +
  `<div class="alert warn mb">${ic('alert')}<div class="grow"><b>2 scenarios need re-signing</b><div style="font-size:12.5px;margin-top:2px">Edited scenarios are blocked from running until their signature is regenerated.</div>${D.UNSIGNED.map(u => `<div class="check-row" style="border:0;padding:4px 0"><span class="mono muted">${u[0]}</span><span class="grow">${u[1]} <span class="muted">· ${u[2]}</span></span></div>`).join('')}</div><button class="btn sm primary" data-act="reSign">${ic('lock', 'sm')}Re-sign all</button></div>` +
  `<div class="grid g-side"><div class="card pad0">${table(['Pipeline', 'State', 'Last run', 'Queue', 'Last result'], D.FACTORY.pipelines.map(p => `<tr data-act="openPipe" data-a="${p.name}"><td>${p.name}</td><td>${st(p.state)}</td><td class="muted">${p.last}</td><td>${p.queue}</td><td class="muted">${p.lastResult}</td></tr>`))}</div>
  <div class="card"><div class="card-hd"><h2>Recent builds</h2><div class="actions"><div class="seg"><button class="${!b ? 'on' : ''}" data-act="set" data-a="fbF" data-b="">All</button><button class="${b === 'err' ? 'on' : ''}" data-act="set" data-a="fbF" data-b="err">Failed</button></div></div></div>${builds.map(x => `<div class="check-row"><span class="dot" style="background:var(--${x.result === 'ok' ? 'green' : x.result === 'warn' ? 'amber' : 'red'});box-shadow:none"></span><div class="grow"><div>${x.what}</div><div class="mono muted" style="font-size:11px">${x.id} · ${x.when} · ${x.by}</div></div></div>`).join('') || '<div class="muted">No builds match.</div>'}</div></div>`;
};
A.reSign = () => { D.UNSIGNED.length = 0; toast('Scenarios re-signed', '2 signatures regenerated'); AUD.render(); };
A.openPipe = d => {
  const p = D.FACTORY.pipelines.find(x => x.name === d.a);
  dr(p.name, 'Pipeline', 'factory', `<div class="row between mb">${st(p.state)}<span class="muted">Queue: ${p.queue}</span></div>${K.kv([['Last run', p.last], ['Last result', p.lastResult], ['Trigger', 'Schedule + on commit'], ['Runner', 'factory-runner-02']])}
    <h4 style="margin:18px 0 8px">Duration (last 8 runs, min)</h4>${chartSlot({ type: 'line', labels: ['1', '2', '3', '4', '5', '6', '7', '8'], h: 140, series: [{ name: 'Minutes', color: '#3b82f6', data: [6, 7, 6, 9, 7, 6, 8, 7] }], yMax: 12, suffix: '' })}`,
    `<button class="btn primary" data-act="toast" data-a="Pipeline triggered" data-b="${p.name}">${ic('play')}Trigger now</button>`);
};

P['k8s-scenarios'] = P.k8s; P['scheduled-assessments'] = P.scheduled; P['factory-health'] = P.factory;
})();
