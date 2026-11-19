// Deep page modules, group 2 — Visibility: Coverage, Variants, AD, Email, IOCs, Remediation, Reports,
// Verification, Attack Path, Exposure, Recommendations, Exercises, Technique Coverage, Threat Priority
(() => {
const { S, P, A, h, toast, modal } = AUD;
const { tag, sev, st, bar, table, kpi, tabs, curTab, relBlock, mhd, lineChart } = h;
const K = KIT, dr = K.dr;
const filt = (list, q, fn) => list.filter(x => !q || fn(x).toLowerCase().includes(q.toLowerCase()));
const sevOf = x => x === 'info' ? '—' : sev(x);

// ============ MITRE COVERAGE ============
P.coverage = () => {
  const cls = ['c0', 'c1', 'c2', 'c3'], lbl = ['Detected', 'Partial', 'Alert only', 'Missed'];
  const cells = [
    ['Initial Access', ['T1566', 'T1190', 'T1133', 'T1078']], ['Execution', ['T1059', 'T1204', 'T1203', 'T1569']], ['Persistence', ['T1547', 'T1053', 'T1543', 'T1505']],
    ['Privilege Esc.', ['T1068', 'T1484', 'T1548', 'T1134']], ['Defense Evasion', ['T1562', 'T1070', 'T1218', 'T1036']], ['Credential Access', ['T1003', 'T1558', 'T1110', 'T1555']],
    ['Discovery', ['T1087', 'T1018', 'T1082', 'T1482']], ['Lateral Movement', ['T1021', 'T1570', 'T1550', 'T1080']], ['Collection', ['T1005', 'T1114', 'T1560', 'T1039']],
    ['Command & Control', ['T1071', 'T1105', 'T1573', 'T1095']], ['Exfiltration', ['T1041', 'T1567', 'T1048', 'T1029']], ['Impact', ['T1486', 'T1490', 'T1489', 'T1485']]];
  const score = (i, j) => [3, 1, 2, 0, 2, 1, 3, 0, 2, 1, 0, 1, 3, 2, 0, 1][(i * 4 + j * 3 + i) % 16];
  const only = S.covF; // '' | '0'..'3'
  const grid = `<div class="matrix">${cells.map(([t]) => `<div class="tac">${t}</div>`).join('')}${[0, 1, 2, 3].map(r => cells.map(([t, ids], i) => { const sc = score(i, r); return `<div class="tech ${cls[sc]} ${only !== '' && only !== undefined && only !== String(sc) ? 'dim' : ''}" data-act="techDetail" data-a="${ids[r]}">${ids[r]}<small>${lbl[sc]}</small></div>`; }).join('')).join('')}</div>`;
  const tacs = [...new Set(D.TECH_ROWS.map(t => t.tac))].map(t => { const r = D.TECH_ROWS.filter(x => x.tac === t); return [t, Math.round(r.reduce((a, x) => a + x.cov, 0) / r.length)]; }).sort((a, b) => a[1] - b[1]);
  const worst = [...D.TECH_ROWS].sort((a, b) => a.cov - b.cov).slice(0, 5);
  const legend = [['', 'All'], ['0', 'Detected', 'green'], ['3', 'Missed', 'red'], ['1', 'Partial', 'amber'], ['2', 'Alert only', 'cyan']];
  return K.hero('mapped', 'MITRE ATT&CK Coverage', 'Detection coverage mapped to the ATT&CK matrix from validated scenario results.',
    `<button class="btn" data-act="pickTech">${ic('mapped')}Select techniques</button><button class="btn primary" data-act="toast" data-a="Coverage recalculated" data-b="Based on runs up to 24 Oct 14:20">${ic('refresh')}Recalculate</button>`,
    [['mapped', '212 / 242', 'Techniques covered'], ['check', '74%', 'Validated detected'], ['alert', '19', 'Missed'], ['target', '30', 'Untested']]) +
  K.card('ATT&CK heatmap <span class="muted" style="font-weight:400;font-size:12px">· sample, 4 techniques per tactic</span>', grid,
    `<div class="chips">${legend.map(([v, l, c]) => `<button class="chip ${(only || '') === v ? 'on' : ''}" data-act="set" data-a="covF" data-b="${v}">${c ? `<i class="dotc" style="background:var(--${c})"></i>` : ''}${l}</button>`).join('')}</div>`) +
  `<div class="grid g3 mt">${K.card('Weakest tactics', K.hbars(tacs.slice(0, 5).map(([n, v]) => [n, v, K.pct(v)])))}
    ${K.card('Live Threat Coverage', `<p class="muted mb" style="font-size:12.5px">Coverage of techniques used by threat actors active against your sector.</p>${K.hbars([['APT29', 78, 'green'], ['Akira', 64, 'amber'], ['Scattered Spider', 52, 'amber'], ['APT36', 81, 'green']])}`)}
    ${K.card('Coverage by product line', K.hbars([['Endpoint / EDR', 82, 'green'], ['Identity', 66, ''], ['Network', 58, 'amber'], ['Email', 90, 'green'], ['Cloud', 44, 'red']]))}</div>` +
  K.card('Biggest gaps — fix these first', table(['Technique', 'Tactic', 'Coverage', 'Last'], worst.map(t => `<tr data-act="techDetail" data-a="${t.id}"><td><div>${t.name}</div><div class="mono muted" style="font-size:11px">${t.id}</div></td><td class="muted">${t.tac}</td><td>${K.prog(t.cov, K.pct(t.cov))}</td><td>${st(t.last)}</td></tr>`)), '', 'mt pad0');
};

// ============ VARIANTS ============
P.variants = () => {
  const list = filt(D.VARIANTS, S.vQ, v => v.name + v.family + v.id).filter(v => !S.vSt || v.status === S.vSt);
  const tot = D.VARIANTS.reduce((a, v) => a + v.count, 0), ok = D.VARIANTS.reduce((a, v) => a + v.pass, 0);
  return K.hero('layers', 'Variants', 'Generated technique variants and full-estate variant sweeps.',
    `<button class="btn" data-act="variantDrill">${ic('layers')}Full Variant Sweep</button><button class="btn primary" data-act="sweepStart">${ic('play')}Run Full Sweep</button>`,
    [['layers', D.VARIANTS.length, 'Variant sets'], ['box', tot, 'Variants generated'], ['check', Math.round(ok / tot * 100) + '%', 'Evade nothing (pass)'], ['alert', tot - ok, 'Variants that evaded']]) +
  `<div class="grid g-side mb">${K.card('Pass rate by set', K.hbars(D.VARIANTS.map(v => [v.family + ' · ' + v.name.split(' — ')[0], Math.round(v.pass / v.count * 100), K.pct(Math.round(v.pass / v.count * 100))])))}
   ${K.card('All variants', K.donut([{ label: 'Detected', value: ok, color: '#10b981' }, { label: 'Evaded', value: tot - ok, color: '#ef4444' }], 'variants'))}</div>` +
  K.filters(K.search('vQ', 'Search variant sets or techniques...'), K.select('vSt', 'All statuses', [...new Set(D.VARIANTS.map(v => v.status))]), (S.vQ || S.vSt) ? K.clearBtn(['vQ', 'vSt']) : '') +
  (list.length ? `<div class="card pad0">${table(['Variant set', 'Technique', 'Variants', 'Passing', 'Status', ''], list.map(v => `<tr data-act="variantOpen" data-a="${v.id}">
    <td><div>${v.name}</div><div class="mono muted" style="font-size:11px">${v.id}</div></td><td class="mono">${v.family}</td><td>${v.count}</td><td style="min-width:150px"><div class="row"><div class="grow">${bar(v.count ? Math.round(v.pass / v.count * 100) : 0, v.pass === v.count ? 'green' : v.pass === 0 ? 'red' : 'amber')}</div><span class="mono muted">${v.pass}/${v.count}</span></div></td><td>${st(v.status)}</td>
    <td class="num"><button class="btn sm ghost" data-act="variantRun" data-a="${v.id}" title="Run this variant set on the selected agent">${ic('play', 'sm')}</button></td></tr>`))}</div>` : K.empty('search', 'No variant sets match', 'Clear the filters.'));
};
A.variantOpen = d => {
  const v = D.VARIANTS.find(x => x.id === d.a), vs = D.variantList(v);
  dr(v.name, `${v.id} · ${v.family}`, 'layers', `<div class="row between mb">${st(v.status)}<span class="muted">${v.pass} of ${v.count} detected</span></div>${bar(Math.round(v.pass / v.count * 100), v.pass === v.count ? 'green' : 'amber')}
    <h4 style="margin:18px 0 8px">Variants</h4><div class="var-grid">${vs.map(x => `<div class="var-chip ${x.ok ? 'ok' : 'bad'}" title="${x.desc}"><b>${x.id.split('-').pop()}</b><span>${x.desc}</span><i>${x.ok ? 'Detected' : 'Evaded'}</i></div>`).join('')}</div>
    ${relBlock([['mapped', 'Technique ' + v.family, 'Open coverage detail', 'techDetail', v.family]])}`,
    `<button class="btn primary" data-act="variantRun" data-a="${v.id}">${ic('play')}Re-run set</button>`);
};

// ============ AD COVERAGE ============
P['ad-coverage'] = () => {
  const list = filt(D.AD, S.adQ, a => a.check + a.cat + a.mapped).filter(a => (!S.adC || a.cat === S.adC) && (!S.adS || a.status === S.adS));
  const by = k => D.AD.filter(a => a.sev === k).length;
  return K.hero('key', 'AD Coverage', 'Active Directory attack-surface checks across the forest.',
    `<button class="btn primary" data-act="toast" data-a="AD checks queued" data-b="Forest acme-bank.local · ${D.AD.length} checks">${ic('refresh')}Re-run checks</button>`,
    [['box', 'acme-bank.local', 'Forest · 3 domains'], ['server', '6', 'Tier-0 hosts'], ['alert', by('critical') + by('high'), 'Critical + high'], ['shield', '93%', 'LAPS coverage']]) +
  `<div class="grid g-side mb">${K.card('Checks by severity', K.donut([{ label: 'Critical', value: by('critical'), color: '#7f1d1d' }, { label: 'High', value: by('high'), color: '#ef4444' }, { label: 'Medium', value: by('medium'), color: '#f59e0b' }, { label: 'Info / pass', value: by('info') + by('low'), color: '#10b981' }], 'checks'))}
   ${K.card('Open issues by category', K.hbars([...new Set(D.AD.map(a => a.cat))].map(c => { const n = D.AD.filter(a => a.cat === c && a.status !== 'Pass').length; return [c, n * 20, n > 1 ? 'red' : n ? 'amber' : 'green', ' ' + n]; })))}</div>` +
  K.filters(K.search('adQ', 'Search checks or ATT&CK IDs...'), K.select('adC', 'All categories', [...new Set(D.AD.map(a => a.cat))]), K.select('adS', 'All statuses', ['Open', 'In progress', 'Pass']), (S.adQ || S.adC || S.adS) ? K.clearBtn(['adQ', 'adC', 'adS']) : '') +
  (list.length ? `<div class="card pad0">${table(['Check', 'Category', 'Result', 'Severity', 'MITRE', 'Status'], list.map(a => `<tr data-act="adOpen" data-a="${D.AD.indexOf(a)}"><td>${a.check}</td><td>${tag(a.cat, 'gray')}</td><td>${a.result}</td><td>${sevOf(a.sev)}</td><td class="mono">${a.mapped}</td><td>${st(a.status)}</td></tr>`))}</div>` : K.empty('search', 'No checks match', 'Clear the filters.'));
};
A.adOpen = d => {
  const a = D.AD[+d.a];
  dr(a.check, `Category: ${a.cat} · ${a.mapped}`, 'key', `<div class="row between mb">${st(a.status)}${sevOf(a.sev)}</div>${K.kv([['Result', a.result], ['ATT&CK', `<span class="mono">${a.mapped}</span>`], ['Forest', 'acme-bank.local']])}
    <h4 style="margin:18px 0 6px">Why it matters</h4><p class="muted" style="margin:0">${a.why}</p><h4 style="margin:18px 0 6px">Recommended fix</h4><p class="muted" style="margin:0">${a.fix}</p>
    ${relBlock([['mapped', 'Technique ' + a.mapped, 'Open coverage detail', 'techDetail', a.mapped], ['wrench', 'Remediation board', 'Track the fix', 'nav', 'remediation']])}`,
    a.status === 'Pass' ? '' : `<button class="btn primary" data-act="remNew" data-b="${a.check}">${ic('plus')}Create remediation</button>`);
};

// ============ EMAIL ============
P.email = () => {
  const tab = curTab('email', [['campaigns'], ['templates'], ['results']]);
  const cs = D.EMAIL.campaigns, sent = cs.reduce((a, c) => a + c.sent, 0), clk = cs.reduce((a, c) => a + c.clicked, 0), op = cs.reduce((a, c) => a + c.opened, 0), rep = cs.reduce((a, c) => a + c.reported, 0);
  const pc = (a, b) => b ? Math.round(a / b * 100) : 0;
  let body = '';
  if (tab === 'campaigns') {
    const list = filt(cs, S.eQ, c => c.name + c.tpl + c.group).filter(c => !S.eSt || c.status === S.eSt);
    body = K.filters(K.search('eQ', 'Search campaigns...'), K.select('eSt', 'All statuses', ['Running', 'Completed', 'Scheduled']), (S.eQ || S.eSt) ? K.clearBtn(['eQ', 'eSt']) : '') +
      (list.length ? `<div class="card pad0">${table(['Campaign', 'Audience', 'Sent', 'Open', 'Click', 'Reported', 'Status', ''], list.map(c => `<tr data-act="emailOpen" data-a="${c.id}"><td><div>${c.name}</div><div class="muted" style="font-size:11px">${c.id} · ${c.tpl}</div></td><td class="muted">${c.group}</td><td>${c.sent}</td><td>${pc(c.opened, c.delivered)}%</td><td>${tag(pc(c.clicked, c.delivered) + '%', pc(c.clicked, c.delivered) > 20 ? 'red' : pc(c.clicked, c.delivered) > 10 ? 'amber' : 'green')}</td><td>${pc(c.reported, c.delivered)}%</td><td>${st(c.status)}</td><td class="num muted">${c.date}</td></tr>`))}</div>` : K.empty('search', 'No campaigns match', 'Clear the filters.'));
  }
  if (tab === 'templates') body = `<div class="grid g3">${D.EMAIL.templates.map((t, i) => `<div class="card hov" data-act="tplOpen" data-a="${i}"><div class="row between">${tag(t.vector, t.vector === 'QR code' ? 'purple' : t.vector === 'Attachment' ? 'amber' : 'blue')}${st(t.status)}</div><h2 style="margin:12px 0 4px;font-size:14.5px">${t.name}</h2><div class="muted" style="font-size:12px">"${t.subject}"</div><div class="row mt" style="margin-top:14px;font-size:12px;color:var(--muted)"><span>${ic('mail', 'sm')} Used ${t.used}×</span><span style="margin-left:auto">Click ${t.click}</span></div></div>`).join('')}</div>`;
  if (tab === 'results') body = `<div class="grid g2">${K.card('Funnel (all campaigns)', K.hbars([['Delivered', pc(cs.reduce((a, c) => a + c.delivered, 0), sent), 'cyan'], ['Opened', pc(op, sent), 'blue'], ['Clicked', pc(clk, sent), 'red'], ['Reported', pc(rep, sent), 'green']]))}
    ${K.card('Click rate by campaign', chartSlot({ type: 'bar', labels: cs.filter(c => c.sent).map(c => c.id), h: 180, series: [{ name: 'Click %', color: '#ef4444', data: cs.filter(c => c.sent).map(c => pc(c.clicked, c.delivered)) }] }))}</div>
    ${K.card('Who clicked — by department', K.hbars([['Finance', 13, 'red'], ['Procurement', 11, 'amber'], ['Executives', 28, 'red'], ['Marketing', 9, 'amber'], ['Engineering', 4, 'green']]), '', 'mt')}`;
  return K.hero('mail', 'Email', 'Phishing and email-delivery validation (Email BAS).',
    `<button class="btn" data-act="toast" data-a="Template imported" data-b="2 templates added from library">${ic('upload')}Import template</button><button class="btn primary" data-act="emailCampaign">${ic('plus')}New Email Campaign</button>`,
    [['mail', sent, 'Sent (30d)'], ['eye', pc(op, sent) + '%', 'Open rate'], ['alert', pc(clk, sent) + '%', 'Click rate'], ['check', pc(rep, sent) + '%', 'Report rate']]) +
  tabs('email', [['campaigns', 'Campaigns', cs.length], ['templates', 'Templates', D.EMAIL.templates.length], ['results', 'Results']]) + body;
};
A.emailOpen = d => {
  const c = D.EMAIL.campaigns.find(x => x.id === d.a);
  dr(c.name, `${c.id} · ${c.group}`, 'mail', `<div class="row between mb">${st(c.status)}<span class="muted">${c.date}</span></div>${K.kv([['Template', c.tpl], ['Audience', c.group]])}
    <h4 style="margin:18px 0 10px">Funnel</h4>${K.hbars([['Delivered', c.sent ? Math.round(c.delivered / c.sent * 100) : 0, 'cyan'], ['Opened', c.sent ? Math.round(c.opened / c.sent * 100) : 0, 'blue'], ['Clicked', c.sent ? Math.round(c.clicked / c.sent * 100) : 0, 'red'], ['Reported', c.sent ? Math.round(c.reported / c.sent * 100) : 0, 'green']])}
    <div class="alert info" style="margin-top:14px">${ic('bell')}<div>${c.reported > c.clicked ? 'More users reported than clicked — awareness is working.' : 'Clicks exceeded reports; consider targeted awareness training.'}</div></div>`);
};
A.tplOpen = d => {
  const t = D.EMAIL.templates[+d.a];
  dr(t.name, t.vector + ' lure', 'mail', `<div class="mail-prev"><div class="mp-h"><div><b>From</b> ${t.from}</div><div><b>Subject</b> ${t.subject}</div></div><div class="mp-b"><p>${t.body}</p><span class="mp-btn">${t.vector === 'QR code' ? 'Scan QR code' : t.vector === 'Attachment' ? 'Open attachment' : 'Review now'}</span></div></div>
    ${K.kv([['Vector', t.vector], ['Times used', t.used], ['Click rate', t.click]])}<div class="alert warn" style="margin-top:14px">${ic('alert')}<div>Simulation only. Links resolve to the Audspect awareness landing page.</div></div>`,
    `<button class="btn primary" data-act="emailCampaign">${ic('plus')}Use in campaign</button>`);
};

// ============ IOC REGISTRY ============
P.iocs = () => {
  const list = filt(D.IOCS, S.oQ, i => i.value + i.source + i.type).filter(i => (!S.oT || i.type === S.oT) && (!S.oA || i.action === S.oA));
  const types = [...new Set(D.IOCS.map(i => i.type))];
  const cnt = a => D.IOCS.filter(i => i.action === a).length;
  return K.hero('hash', 'IOC Registry', 'Indicators of compromise from threat intel, scenario artefacts and validation runs.',
    `<button class="btn" data-act="importIoc">${ic('upload')}Import Indicators</button><button class="btn primary" data-act="toast" data-a="Indicator added">${ic('plus')}Add IOC</button>`,
    [['hash', D.IOCS.length, 'Indicators'], ['lock', cnt('Block'), 'Blocking'], ['alert', cnt('Alert'), 'Alerting'], ['eye', cnt('Monitor'), 'Monitoring']]) +
  `<div class="grid g2 mb">${K.card('By type', K.donut(types.map((t, i) => ({ label: t, value: D.IOCS.filter(x => x.type === t).length, color: ['#3b82f6', '#22d3ee', '#a78bfa', '#f59e0b', '#10b981', '#ef4444', '#60a5fa'][i % 7] })), 'indicators'))}
   ${K.card('Top sources', K.hbars([...new Set(D.IOCS.map(i => i.source))].map(s => [s, D.IOCS.filter(i => i.source === s).length * 10, 'blue', ' · ' + D.IOCS.filter(i => i.source === s).length]).sort((a, b) => b[1] - a[1]).slice(0, 6)))}</div>` +
  K.filters(K.search('oQ', 'Search indicators or sources...'), K.select('oT', 'All types', types), K.select('oA', 'All actions', ['Block', 'Alert', 'Monitor']), (S.oQ || S.oT || S.oA) ? K.clearBtn(['oQ', 'oT', 'oA']) : '') +
  (list.length ? `<div class="card pad0">${table(['Indicator', 'Type', 'Source', 'Confidence', 'Action', 'Last seen'], list.map(i => `<tr data-act="iocOpen" data-a="${D.IOCS.indexOf(i)}"><td class="mono" style="max-width:300px;word-break:break-all">${i.value}</td><td>${tag(i.type, 'gray')}</td><td class="muted">${i.source}</td><td style="min-width:140px">${K.prog(i.conf, i.conf > 85 ? 'green' : 'amber')}</td><td>${tag(i.action, i.action === 'Block' ? 'red' : i.action === 'Alert' ? 'amber' : 'gray')}</td><td class="muted">${i.seen} ago</td></tr>`))}</div>` : K.empty('search', 'No indicators match', 'Clear the filters.'));
};
A.iocOpen = d => {
  const i = D.IOCS[+d.a];
  dr(i.value, `${i.type} · ${i.source}`, 'hash', `<div class="row between mb">${tag(i.action, i.action === 'Block' ? 'red' : i.action === 'Alert' ? 'amber' : 'gray')}<span class="muted">Confidence ${i.conf}</span></div>${K.prog(i.conf, i.conf > 85 ? 'green' : 'amber')}
    <div style="height:14px"></div>${K.kv([['First seen', i.first + ' Oct'], ['Last seen', i.seen + ' ago'], ['Sightings', i.sightings], ['Tags', i.tags.map(t => tag(t, 'blue')).join(' ')]])}
    <h4 style="margin:18px 0 8px">Set response action</h4><div class="chips">${['Block', 'Alert', 'Monitor'].map(a => `<button class="chip ${i.action === a ? 'on' : ''}" data-act="iocSet" data-a="${d.a}" data-b="${a}">${a}</button>`).join('')}</div>
    ${relBlock([['target', 'Related scenario', 'Where this indicator was seen', 'nav', 'scenarios'], ['alert', 'Related findings', '2 open', 'nav', 'findings']])}`);
};
A.iocSet = d => { D.IOCS[+d.a].action = d.b; toast('Action updated', `${D.IOCS[+d.a].value} → ${d.b}`); AUD.closeDrawer(); AUD.render(); };

// ============ REMEDIATION ============
P.remediation = () => {
  const cards = D.REMED.cards.filter(x => (!S.rmO || x.owner === S.rmO) && (!S.rmS || x.sev === S.rmS) && (!S.rmQ || (x.title + x.asset + x.id).toLowerCase().includes(S.rmQ.toLowerCase())));
  const open = D.REMED.cards.filter(x => x.col !== 'closed').length, crit = D.REMED.cards.filter(x => x.sev === 'critical' && x.col !== 'closed').length;
  const view = S.rmV || 'board';
  const board = `<div class="kanban">${D.REMED.cols.map(([label, c, key]) => `<div class="kcol"><h4><span class="dot" style="background:var(--${c});box-shadow:none"></span>${label}<span class="cnt" style="margin-left:auto">${cards.filter(x => x.col === key).length}</span></h4>
   ${cards.filter(x => x.col === key).map(x => `<div class="kcard" data-act="openRem" data-a="${x.id}"><div class="row between" style="margin-bottom:6px">${sev(x.sev)}<span class="mono muted" style="font-size:11px">${x.id}</span></div><div style="font-weight:500;line-height:1.3">${x.title}</div><div class="row mt" style="margin-top:10px;font-size:11.5px;color:var(--muted)"><span class="mono">${x.asset}</span><span style="margin-left:auto">Due ${x.due}</span></div><div class="row between" style="margin-top:10px">${K.avatar(x.owner)}<span class="muted" style="font-size:11.5px;margin-left:-4px;flex:1">${x.owner}</span>${key !== 'closed' ? `<button class="btn sm ghost" data-act="remMove" data-a="${x.id}" title="Advance to next stage">${ic('chevr', 'sm')}</button>` : ''}</div></div>`).join('') || '<div class="muted" style="font-size:12px;padding:8px">Nothing here</div>'}</div>`).join('')}</div>`;
  const tbl = `<div class="card pad0">${table(['ID', 'Item', 'Asset', 'Owner', 'Severity', 'Stage', 'Due'], cards.map(x => `<tr data-act="openRem" data-a="${x.id}"><td class="mono muted">${x.id}</td><td>${x.title}</td><td class="mono">${x.asset}</td><td class="muted">${x.owner}</td><td>${sev(x.sev)}</td><td>${st(D.REMED.cols.find(c => c[2] === x.col)[0])}</td><td class="muted">${x.due}</td></tr>`))}</div>`;
  return K.hero('wrench', 'Remediation', 'Track fixes from detection through verification.',
    `<button class="btn primary" data-act="remNew">${ic('plus')}New item</button>`,
    [['wrench', open, 'Open items'], ['alert', crit, 'Critical open'], ['clock', '11 d', 'Median time to fix'], ['check', D.REMED.cards.filter(x => x.col === 'closed').length, 'Closed']]) +
  K.filters(K.search('rmQ', 'Search items, assets, IDs...'), K.select('rmO', 'All owners', [...new Set(D.REMED.cards.map(x => x.owner))]), K.select('rmS', 'All severities', ['critical', 'high', 'medium', 'low']),
    (S.rmQ || S.rmO || S.rmS) ? K.clearBtn(['rmQ', 'rmO', 'rmS']) : '', `<div class="seg" style="margin-left:auto"><button class="${view === 'board' ? 'on' : ''}" data-act="set" data-a="rmV" data-b="board">${ic('grid2', 'sm')}Board</button><button class="${view === 'list' ? 'on' : ''}" data-act="set" data-a="rmV" data-b="list">${ic('list', 'sm')}List</button></div>`) +
  (cards.length ? (view === 'board' ? board : tbl) : K.empty('search', 'No remediation items match', 'Clear the filters.'));
};
A.remMove = d => { const x = D.REMED.cards.find(c => c.id === d.a), o = D.REMED.cols.map(c => c[2]); x.col = o[Math.min(o.length - 1, o.indexOf(x.col) + 1)]; toast('Item moved', `${x.id} → ${D.REMED.cols.find(c => c[2] === x.col)[0]}`); AUD.render(); };

// ============ REPORTS ============
P.reports = () => {
  const list = [['reports', 'Reports'], ['compliance', 'Compliance report'], ['sla', 'SLA compliance']];
  const tab = curTab('reports', list);
  let body = '';
  if (tab === 'reports') {
    const rs = filt(D.REPORTS, S.rpQ, r => r.name + r.type + r.id).filter(r => !S.rpT || r.type === S.rpT);
    body = K.filters(K.search('rpQ', 'Search reports...'), K.select('rpT', 'All types', [...new Set(D.REPORTS.map(r => r.type))]), (S.rpQ || S.rpT) ? K.clearBtn(['rpQ', 'rpT']) : '') +
      `<div class="grid g-side"><div class="card pad0">${rs.length ? table(['Report', 'Type', 'Period', 'Created', 'By', 'Format', ''], rs.map(r => `<tr class="noclick"><td><div>${r.name}</div><div class="mono muted" style="font-size:11px">${r.id}</div></td><td>${tag(r.type, 'blue')}</td><td class="muted">${r.period}</td><td>${r.created}</td><td class="muted">${r.by}</td><td>${tag(r.fmt, 'gray')}</td><td class="num"><div class="row" style="justify-content:flex-end"><button class="btn sm ghost" data-act="previewRpt" data-a="${r.id}">${ic('eye', 'sm')}Preview</button><button class="btn sm" data-act="downloadRpt" data-a="${r.id}">${ic('download', 'sm')}Download</button></div></td></tr>`)) : K.empty('search', 'No reports match', 'Clear the filters.')}</div>
      ${K.card('Scheduled deliveries', [['Executive posture', 'Monthly · 1st', 'ciso@acme-bank.demo'], ['SOC weekly digest', 'Mondays 08:00', '#soc-reports'], ['PCI evidence pack', 'Quarterly', 'compliance@acme-bank.demo']].map(([n, w, t]) => `<div class="check-row"><span class="dot" style="background:var(--accent);box-shadow:none"></span><div class="grow"><div>${n}</div><div class="muted" style="font-size:11.5px">${w} → ${t}</div></div></div>`).join('') + `<button class="btn sm" style="margin-top:12px" data-act="toast" data-a="Delivery added">${ic('plus', 'sm')}Add delivery</button>`)}</div>`;
  }
  if (tab === 'compliance') body = `<div class="grid g2">${[['PCI-DSS v4.0', 86, 'green', '12 of 14 requirements evidenced'], ['ISO 27001:2022', 79, 'amber', '3 controls with gaps'], ['NIST CSF 2.0', 83, 'green', 'Detect function strongest'], ['SOC 2 (CC7)', 71, 'amber', 'Logging evidence incomplete']].map(([n, v, c, d]) => `<div class="card"><div class="row between"><h2>${n}</h2><span class="mono">${v}%</span></div><div style="margin:10px 0">${bar(v, c)}</div><p class="muted" style="font-size:12.5px">${d}</p><div class="row" style="margin-top:12px"><button class="btn sm" data-act="genReport">Generate evidence pack</button></div></div>`).join('')}</div>`;
  if (tab === 'sla') body = `<div class="grid g4 mb">${kpi('SLA compliance', '91%', 'Target 95%', 'clock', '--amber', 'var(--amber)')}${kpi('Median time to remediate', '11 d', '▼ 2 d', 'wrench', '--cyan')}${kpi('Breaches (30d)', '4', '▼ 3', 'alert', '--red', 'var(--green)')}${kpi('Accepted risks', '6', 'Expire in 30 d: 2', 'shield', '--purple', 'var(--amber)')}</div>
    <div class="grid g2">${K.card('By Severity', K.hbars([['Critical (≤7 d)', 100, 'green', '%'], ['High (≤30 d)', 88, '', '%'], ['Medium (≤90 d)', 96, 'green', '%'], ['Low (≤180 d)', 100, 'green', '%']]))}${K.card('Monthly Trend', lineChart([84, 86, 85, 88, 90, 89, 91, 92, 90, 93, 91, 91], ['May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar', 'Apr'], '#22d3ee'))}</div>
    ${K.card('Recently Resolved', table(['Finding', 'Severity', 'Resolved', 'Verified by'], D.FINDINGS.filter(f => f.status === 'Closed' || f.status === 'Verified').map(f => `<tr class="noclick"><td>${f.title}</td><td>${sev(f.sev)}</td><td class="muted">22 Oct 2026</td><td class="muted">Validation run</td></tr>`)), '', 'mt pad0')}`;
  return K.hero('report', 'Reports', 'Generate, review and share validation and compliance reports.', `<button class="btn primary" data-act="genReport">${ic('plus')}Generate report</button>`,
    [['report', D.REPORTS.length, 'Reports'], ['clock', '3', 'Scheduled deliveries'], ['check', '4', 'Frameworks tracked'], ['download', '1.2 GB', 'Stored']]) + tabs('reports', [['reports', 'Reports', D.REPORTS.length], ['compliance', 'Compliance report'], ['sla', 'SLA compliance']]) + body;
};

// ============ DETECTION VERIFICATION ============
P.verification = () => {
  const list = filt(D.VERIFY, S.vfQ, v => v.detection + v.scenario + v.id).filter(v => (!S.vfR || v.result === S.vfR) && (!S.vfS || v.src === S.vfS));
  const n = r => D.VERIFY.filter(v => v.result === r).length;
  return K.hero('check', 'Detection Verification', 'Confirms whether detections fired as expected for each validated step.',
    `<button class="btn primary" data-act="rerunReview">${ic('refresh')}Re-run review</button>`,
    [['check', D.VERIFY.length, 'Checks'], ['shield', Math.round(n('Detected') / D.VERIFY.length * 100) + '%', 'Detected'], ['alert', n('Partial'), 'Partial'], ['x', n('Missed'), 'Missed']]) +
  `<div class="grid g-side mb">${K.card('Result by control', K.hbars([...new Set(D.VERIFY.map(v => v.src))].map(s => { const a = D.VERIFY.filter(v => v.src === s), p = Math.round(a.filter(v => v.result === 'Detected').length / a.length * 100); return [s, p, K.pct(p)]; })))}
   ${K.card('Outcome', K.donut([{ label: 'Detected', value: n('Detected'), color: '#10b981' }, { label: 'Partial', value: n('Partial'), color: '#f59e0b' }, { label: 'Missed', value: n('Missed'), color: '#ef4444' }], 'checks'))}</div>` +
  K.filters(K.search('vfQ', 'Search detections or scenarios...'), K.select('vfR', 'All results', ['Detected', 'Partial', 'Missed']), K.select('vfS', 'All controls', [...new Set(D.VERIFY.map(v => v.src))]), (S.vfQ || S.vfR || S.vfS) ? K.clearBtn(['vfQ', 'vfR', 'vfS']) : '') +
  (list.length ? `<div class="card pad0">${table(['ID', 'Detection', 'Scenario', 'Expected', 'Observed', 'Result', 'Checked', ''], list.map(v => `<tr data-act="vfOpen" data-a="${v.id}"><td class="mono muted">${v.id}</td><td>${v.detection}</td><td class="muted">${v.scenario}</td><td>${v.expected}</td><td>${v.seen}</td><td>${st(v.result)}</td><td class="muted">${v.checked}</td><td class="num"><button class="btn sm ghost" data-act="rerunReview" data-a="${v.id}">${ic('refresh', 'sm')}</button></td></tr>`))}</div>` : K.empty('search', 'No checks match', 'Clear the filters.'));
};
A.vfOpen = d => {
  const v = D.VERIFY.find(x => x.id === d.a);
  dr(v.detection, `${v.id} · ${v.scenario}`, 'check', `<div class="row between mb">${st(v.result)}<span class="muted">${v.checked}</span></div>${K.kv([['Control', v.src], ['Expected', v.expected], ['Observed', v.seen], ['Time to detect', v.ttd], ['Rule', v.rule]])}
    <h4 style="margin:18px 0 8px">Timeline</h4><div class="timeline">${[['Step executed', 'Scenario action ran on agent', 'done'], ['Telemetry shipped', 'Event received by ' + v.src, 'done'], [v.result === 'Missed' ? 'No detection fired' : 'Detection fired', v.result === 'Missed' ? 'Rule did not match this variant' : v.rule, v.result === 'Missed' ? 'fail' : 'done']].map(([t, dd, s], i) => `<div class="tl-step ${s === 'done' ? 'done' : ''}"><div class="tl-dot">${s === 'fail' ? '!' : '✓'}</div><div><div class="t">${t}</div><div class="d">${dd}</div></div></div>`).join('')}</div>
    ${v.result !== 'Detected' ? `<div class="alert warn" style="margin-top:14px">${ic('alert')}<div>Tuning suggestion: broaden the rule to cover this variant, then re-run to confirm.</div></div>` : ''}${relBlock([['target', 'Scenario', v.scenario, 'nav', 'scenarios']])}`,
    `<button class="btn primary" data-act="rerunReview" data-a="${v.id}">${ic('refresh')}Re-check</button>`);
};

// ============ ATTACK PATH ============
P.attackpath = () => {
  const paths = D.ATTACK_PATHS.filter(x => !S.apF || x.risk === S.apF), p = D.ATTACK_PATHS.find(x => x.id === S.apSel) || D.ATTACK_PATHS[0];
  const techs = ['T1566', 'T1059', 'T1003', 'T1078', 'T1021'], tacs = ['Initial access', 'Execution', 'Credential access', 'Privilege escalation', 'Impact / objective'];
  return K.hero('path', 'Attack Path Validation', 'Chained techniques validated end-to-end across identity, endpoint and cloud.',
    `<button class="btn primary" data-act="toast" data-a="Path validation started" data-b="${p.name}">${ic('play')}Validate path</button>`,
    [['path', D.ATTACK_PATHS.length, 'Paths modelled'], ['check', D.ATTACK_PATHS.filter(x => x.validated).length, 'Validated'], ['alert', D.ATTACK_PATHS.filter(x => x.risk === 'Critical').length, 'Critical'], ['layers', Math.max(...D.ATTACK_PATHS.map(x => x.steps)), 'Longest chain (hops)']]) +
  K.filters(K.select('apF', 'All risk levels', ['Critical', 'High', 'Medium']), S.apF ? K.clearBtn(['apF']) : '') +
  `<div class="split split-300"><div class="col">${paths.map(x => `<div class="card hov ${x.id === p.id ? 'sel' : ''}" data-act="set" data-a="apSel" data-b="${x.id}"><div class="row between">${sev(x.risk.toLowerCase())}${x.validated ? tag('Validated', 'green') : tag('Modelled', 'gray')}</div><div style="font-weight:600;margin:8px 0 4px">${x.name}</div><div class="muted" style="font-size:12px">${x.steps} hops · ${x.id}</div></div>`).join('') || K.empty('search', 'No paths', 'Clear the filter.')}</div>
  <div class="col">${K.card(p.name, `<div class="path-chain">${p.hops.map((hp, i) => `<div class="pc-node ${i === p.hops.length - 1 ? 'goal' : ''}"><span class="pc-n">${i + 1}</span><div><div style="font-weight:500">${hp}</div><div class="muted mono" style="font-size:11px">${tacs[Math.min(i, 4)]} · ${techs[Math.min(i, 4)]}</div></div><button class="btn sm ghost" data-act="techDetail" data-a="${techs[Math.min(i, 4)]}" style="margin-left:auto">${ic('mapped', 'sm')}</button></div>${i < p.hops.length - 1 ? '<div class="pc-link"></div>' : ''}`).join('')}</div>`, sev(p.risk.toLowerCase()))}
  <div class="grid g2">${K.card('Validation', K.kv([['Status', p.validated ? st('Passed') : st('Pending')], ['Last run', '22 Oct 2026'], ['Blocking control', p.validated ? 'None — path reached objective' : 'Not yet tested'], ['Detections fired', p.validated ? '1 of 4 hops' : '—']]))}
   ${K.card('Break the chain', `<p class="muted" style="font-size:12.5px;margin:0 0 10px">Fixing hop ${p.hops.length - 1} removes the shortest route: restrict the ${p.id === 'AP-14' ? 'ADCS UserAuth template' : 'service account scope'}, then re-validate.</p><div class="row"><button class="btn sm" data-act="nav" data-a="recommendations">View recommendation</button><button class="btn sm primary" data-act="remNew">Create remediation</button></div>`)}</div></div></div>`;
};

// ============ EXPOSURE ============
P.exposure = () => {
  const f = S.exF || 'All';
  const list = filt(D.EXPOSURE, S.exQ, e => e.asset + e.owner + e.tag).filter(e => f === 'All' || (f === 'Internet-facing' ? e.type.startsWith('Internet') : f === 'Internal' ? e.type.startsWith('Internal') : e.type === 'Cloud'));
  return K.hero('exposure', 'Exposure Explorer', 'Internet-facing and internal assets with exposure and vulnerability context.', `<button class="btn" data-act="toast" data-a="Exposure scan queued">${ic('refresh')}Rescan</button>`,
    [['exposure', D.EXPOSURE.length, 'Assets'], ['globe', D.EXPOSURE.filter(e => e.type.startsWith('Internet')).length, 'Internet-facing'], ['alert', D.EXPOSURE.reduce((a, e) => a + e.crit, 0), 'Critical vulns'], ['bug', D.EXPOSURE.reduce((a, e) => a + e.vulns, 0), 'Total vulns']].map(x => x[0] === 'bug' ? ['alert', x[1], x[2]] : x)) +
  `<div class="grid g2 mb">${K.card('Exposure by type', K.donut([{ label: 'Internet-facing', value: D.EXPOSURE.filter(e => e.type.startsWith('Internet')).length, color: '#ef4444' }, { label: 'Internal', value: D.EXPOSURE.filter(e => e.type.startsWith('Internal')).length, color: '#3b82f6' }, { label: 'Cloud', value: D.EXPOSURE.filter(e => e.type === 'Cloud').length, color: '#22d3ee' }], 'assets'))}
   ${K.card('Vulnerabilities by owner', chartSlot({ type: 'bar', labels: [...new Set(D.EXPOSURE.map(e => e.owner))], h: 170, series: [{ name: 'Vulns', color: '#f59e0b', data: [...new Set(D.EXPOSURE.map(e => e.owner))].map(o => D.EXPOSURE.filter(e => e.owner === o).reduce((a, e) => a + e.vulns, 0)) }] }))}</div>` +
  K.filters(K.search('exQ', 'Search assets, owners, tags...'), `<div class="chips">${['All', 'Internet-facing', 'Internal', 'Cloud'].map(c => `<button class="chip ${f === c ? 'on' : ''}" data-act="set" data-a="exF" data-b="${c}">${c}</button>`).join('')}</div>`) +
  (list.length ? `<div class="card pad0">${table(['Asset', 'Exposure', 'Open ports', 'Vulns', 'Critical', 'Owner', 'Tag'], list.map(e => `<tr data-act="exOpen" data-a="${D.EXPOSURE.indexOf(e)}"><td class="mono">${e.asset}</td><td>${tag(e.type, e.type.startsWith('Internet') ? 'red' : 'gray')}</td><td class="mono muted">${e.ports}</td><td>${e.vulns}</td><td>${e.crit ? `<span class="sev critical">${e.crit}</span>` : '0'}</td><td class="muted">${e.owner}</td><td>${tag(e.tag, 'blue')}</td></tr>`))}</div>` : K.empty('search', 'No assets match', 'Change the exposure filter.'));
};
A.exOpen = d => {
  const e = D.EXPOSURE[+d.a], cves = D.CVES.slice(+d.a % 4, +d.a % 4 + Math.max(1, e.vulns));
  dr(e.asset, `${e.type} · owner ${e.owner}`, 'exposure', `<div class="row between mb">${tag(e.type, e.type.startsWith('Internet') ? 'red' : 'gray')}${tag(e.tag, 'blue')}</div>${K.kv([['Open ports', `<span class="mono">${e.ports}</span>`], ['Vulnerabilities', e.vulns], ['Critical', e.crit], ['Owner', e.owner]])}
    <h4 style="margin:18px 0 8px">Vulnerabilities</h4>${table(['CVE', 'Description', 'CVSS'], cves.map(c => `<tr class="noclick"><td class="mono">${c[0]}</td><td>${c[1]}</td><td>${sev(c[3])} <span class="mono">${c[2]}</span></td></tr>`))}
    ${relBlock([['alert', 'Findings on this asset', 'Open findings', 'nav', 'findings'], ['path', 'Attack paths through this asset', 'Validated chains', 'nav', 'attackpath']])}`,
    `<button class="btn primary" data-act="toast" data-a="Finding created" data-b="${e.asset}">${ic('plus')}Create finding</button>`);
};

// ============ RECOMMENDATIONS ============
P.recommendations = () => {
  const f = S.recFilter || 'all';
  const list = D.RECS.map((r, i) => [r, i]).filter(([r]) => f === 'all' || r.priority === f);
  return K.hero('rec', 'Recommendations', 'Prioritised fixes ranked by validated impact and effort.', '',
    [['rec', D.RECS.length, 'Recommendations'], ['alert', D.RECS.filter(r => r.priority === 'P1').length, 'P1 priority'], ['clock', D.RECS.filter(r => r.effort === 'Low').length, 'Quick wins (low effort)'], ['shield', '+12 pts', 'Est. score gain if all applied']]) +
  K.filters(`<div class="seg">${[['all', 'All'], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3']].map(([v, l]) => `<button class="${f === v ? 'on' : ''}" data-act="set" data-a="recFilter" data-b="${v}">${l}</button>`).join('')}</div>`) +
  (list.length ? `<div class="grid g2">${list.map(([r, i]) => `<div class="card"><div class="row between">${tag(r.priority, r.priority === 'P1' ? 'red' : r.priority === 'P2' ? 'amber' : 'gray')}<span class="muted" style="font-size:12px">From ${r.from}</span></div><h2 style="margin:10px 0 6px;font-size:14.5px">${r.title}</h2><p class="muted" style="font-size:12.5px">${r.impact}</p><div class="row" style="margin-top:12px"><span class="tag">Effort: ${r.effort}</span><button class="btn sm primary" style="margin-left:auto" data-act="applyRec" data-a="${i}">Create remediation</button></div></div>`).join('')}</div>` : K.empty('search', 'No recommendations at this priority', 'Choose another priority.'));
};

// ============ EXERCISES ============
P.exercises = () => {
  const list = filt(D.EXERCISES, S.xQ, e => e.name).filter(e => !S.xS || e.status === S.xS);
  return K.hero('flag', 'Exercises', 'Tabletop, purple-team and live-fire exercises with outcomes.', `<button class="btn primary" data-act="toast" data-a="Exercise draft created">${ic('plus')}New Exercise</button>`,
    [['flag', D.EXERCISES.length, 'Exercises'], ['clock', D.EXERCISES.filter(e => e.status === 'Scheduled').length, 'Upcoming'], ['user', D.EXERCISES.reduce((a, e) => a + e.participants, 0), 'Participants'], ['check', D.EXERCISES.filter(e => e.status === 'Completed').length, 'Completed']]) +
  K.filters(K.search('xQ', 'Search exercises...'), K.select('xS', 'All statuses', [...new Set(D.EXERCISES.map(e => e.status))]), (S.xQ || S.xS) ? K.clearBtn(['xQ', 'xS']) : '') +
  (list.length ? `<div class="card pad0">${table(['Exercise', 'Date', 'Participants', 'Status', 'Score', 'Outcome'], list.map(e => `<tr data-act="exOpen2" data-a="${D.EXERCISES.indexOf(e)}"><td>${e.name}</td><td>${e.date}</td><td>${e.participants}</td><td>${st(e.status)}</td><td>${e.score ? tag(e.score + '/100', K.pct(e.score)) : '<span class="muted">—</span>'}</td><td>${e.outcome}</td></tr>`))}</div>` : K.empty('search', 'No exercises match', 'Clear the filters.'));
};
A.exOpen2 = d => {
  const e = D.EXERCISES[+d.a];
  dr(e.name, `${e.date} · ${e.participants} participants`, 'flag', `<div class="row between mb">${st(e.status)}${e.score ? tag(e.score + '/100', K.pct(e.score)) : ''}</div><p class="muted" style="margin:0 0 12px">Outcome: ${e.outcome}</p>
    <h4 style="margin:6px 0 8px">Agenda</h4><div class="timeline">${e.agenda.map(([t, w], i) => `<div class="tl-step ${e.status === 'Completed' ? 'done' : ''}"><div class="tl-dot">${i + 1}</div><div><div class="t">${w}</div><div class="d mono">${t}</div></div></div>`).join('')}</div>
    <h4 style="margin:18px 0 8px">Roles</h4>${table(['Role', 'Part'], e.people.map(p => `<tr class="noclick"><td>${p[0]}</td><td class="muted">${p[1]}</td></tr>`))}`,
    `<button class="btn primary" data-act="toast" data-a="${e.status === 'Scheduled' ? 'Invites sent' : 'Report opened'}" data-b="${e.name}">${e.status === 'Scheduled' ? 'Send invites' : 'Open report'}</button>`);
};

// ============ TECHNIQUE COVERAGE ============
P['attack-coverage'] = () => {
  const rows = filt(D.TECH_ROWS, S.tcQ, t => t.name + t.id).filter(t => (!S.tac || t.tac === S.tac) && (!S.tcR || t.last === S.tcR));
  const avg = Math.round(D.TECH_ROWS.reduce((a, t) => a + t.cov, 0) / D.TECH_ROWS.length), n = r => D.TECH_ROWS.filter(t => t.last === r).length;
  return K.hero('mapped', 'Technique Coverage', 'Per-technique detection scores with test history.', `<button class="btn primary" data-act="toast" data-a="Tests queued" data-b="${rows.length} techniques">${ic('play')}Run tests</button>`,
    [['mapped', D.TECH_ROWS.length, 'Techniques tracked'], ['trend', avg + '%', 'Avg coverage'], ['check', n('PASS'), 'Passing'], ['alert', n('FAIL'), 'Failing']]) +
  `<div class="grid g2 mb">${K.card('Average coverage by tactic', K.hbars([...new Set(D.TECH_ROWS.map(t => t.tac))].map(t => { const r = D.TECH_ROWS.filter(x => x.tac === t), v = Math.round(r.reduce((a, x) => a + x.cov, 0) / r.length); return [t, v, K.pct(v)]; })))}
   ${K.card('Last result', K.donut([{ label: 'Pass', value: n('PASS'), color: '#10b981' }, { label: 'Warn', value: n('WARN'), color: '#f59e0b' }, { label: 'Fail', value: n('FAIL'), color: '#ef4444' }], 'techniques'))}</div>` +
  K.filters(K.search('tcQ', 'Search techniques or IDs...'), K.select('tac', 'All tactics', [...new Set(D.TECH_ROWS.map(t => t.tac))]), K.select('tcR', 'All results', ['PASS', 'WARN', 'FAIL']), (S.tcQ || S.tac || S.tcR) ? K.clearBtn(['tcQ', 'tac', 'tcR']) : '') +
  (rows.length ? `<div class="card pad0">${table(['Technique', 'Tactic', 'Coverage', 'Tests', 'Last result'], rows.map(t => `<tr data-act="techDetail" data-a="${t.id}"><td><div>${t.name}</div><div class="mono muted" style="font-size:11px">${t.id}</div></td><td class="muted">${t.tac}</td><td style="min-width:180px">${K.prog(t.cov, t.cov > 75 ? 'green' : t.cov > 50 ? 'amber' : 'red')}</td><td>${t.tests}</td><td>${st(t.last)}</td></tr>`))}</div>` : K.empty('search', 'No techniques match', 'Clear the filters.'));
};

// ============ THREAT PRIORITIZATION ============
P['threat-priority'] = () => {
  const sc = t => t.score > 85 ? '#ef4444' : t.score > 70 ? '#f59e0b' : '#3b82f6';
  return K.hero('priority', 'Threat Prioritization', 'Threat actors ranked by relevance to your estate and validated gaps.', `<button class="btn" data-act="toast" data-a="Model refreshed">${ic('refresh')}Refresh model</button>`,
    [['priority', D.THREATS.length, 'Actors tracked'], ['alert', D.THREATS.filter(t => t.score > 85).length, 'High relevance'], ['mapped', D.THREATS.reduce((a, t) => a + t.mapped, 0), 'Techniques mapped'], ['x', D.THREATS.reduce((a, t) => a + t.gaps, 0), 'Validated gaps']]) +
  `<div class="grid g2">${D.THREATS.map((t, i) => `<div class="card hov" data-act="thOpen" data-a="${i}" style="display:flex;gap:16px;align-items:center"><div class="gauge" style="width:92px;height:92px;margin:0;flex:none"><svg viewBox="0 0 150 150" width="92" height="92" class="progress-ring"><circle cx="75" cy="75" r="62" fill="none" class="track" stroke-width="14"/><circle cx="75" cy="75" r="62" fill="none" stroke="${sc(t)}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${t.score / 100 * 389.5} 389.5"/></svg><div class="gv"><b style="font-size:22px">${t.score}</b></div></div><div class="grow"><h2>#${i + 1} ${t.name}</h2><p class="muted" style="margin:6px 0 10px;font-size:12.5px">${t.why}</p><div class="row" style="gap:8px">${tag(t.mapped + ' techniques mapped', 'blue')}${tag(t.gaps + ' validated gaps', 'red')}</div></div></div>`).join('')}</div>`;
};
A.thOpen = d => {
  const t = D.THREATS[+d.a];
  dr(t.name, `Relevance score ${t.score}`, 'priority', `<p class="muted" style="margin:0 0 14px">${t.why}</p><h4 class="mb">Why this score</h4>${K.hbars(t.factors.map(([n, v]) => [n, v, K.pct(v)]))}
    <h4 style="margin:18px 0 8px">Techniques used</h4><div class="chips">${t.techs.map(x => `<button class="chip" data-act="techDetail" data-a="${x}">${x}</button>`).join('')}</div>
    ${relBlock([['target', t.scen[1], 'Scenario ' + t.scen[0], 'scDetail', t.scen[0]], ['mapped', 'Coverage against this actor', t.gaps + ' gaps', 'nav', 'coverage']])}`,
    `<button class="btn primary" data-act="scDetail" data-a="${t.scen[0]}">${ic('play')}Run linked scenario</button>`);
};
})();
