// Deep page modules, group 3 — Infrastructure & Administration: Agents, Integrations, Settings (users/ART/audit), Profile
(() => {
const { S, P, A, h, toast, modal } = AUD;
const { tag, sev, st, bar, table, tabs, curTab, relBlock, mhd, wave } = h;
const K = KIT, dr = K.dr;
const filt = (list, q, fn) => list.filter(x => !q || fn(x).toLowerCase().includes(q.toLowerCase()));

// ============ AGENTS ============
const agentRows = list => table(['Host', 'Group', 'OS', 'Status', 'Version', 'Last seen', 'Risk', ''], list.map(a => `<tr data-act="agentMenu" data-a="${a.id}"><td><div class="mono">${a.host}</div><div class="muted" style="font-size:11px">${a.ip} · ${a.id}</div></td><td>${a.group}</td><td class="muted">${a.os}</td><td>${st(a.status)}</td><td class="mono">${a.version}${a.version !== '1.9.2' ? ' <span class="tag amber" title="Update available">old</span>' : ''}</td><td class="muted">${a.lastSeen}</td><td>${a.risk === 'High' ? sev('high') : a.risk === 'Medium' ? sev('medium') : a.risk === 'Low' ? sev('low') : '—'}</td><td class="num"><button class="btn sm ghost" data-act="agentMenu" data-a="${a.id}">${ic('chev', 'sm')}</button></td></tr>`));
const osFam = o => o.startsWith('Windows Server') ? 'Windows Server' : o.startsWith('Windows') ? 'Windows' : o.startsWith('macOS') ? 'macOS' : 'Linux';
P.agents = () => {
  const inGroup = D.AGENTS.filter(a => S.agSel === 'All agents' || a.group === S.agSel);
  const list = filt(inGroup, S.agQ, a => a.host + a.ip + a.id + a.group).filter(a => (!S.agSt || a.status === S.agSt) && (!S.agOS || osFam(a.os) === S.agOS));
  const tl = [['overview', 'Overview', list.length], ['scenarios', 'Scenarios'], ['logs', 'Logs'], ['health', 'Health'], ['attackpath', 'Attack Path'], ['risk', 'Risk']];
  const t = curTab('agents', tl);
  const n = s => D.AGENTS.filter(a => a.status === s).length;
  let body = '';
  if (t === 'overview') body = (list.length ? `<div class="card pad0">${agentRows(list)}</div>` : K.empty('search', 'No agents match', 'Clear the filters or pick another group.'));
  if (t === 'scenarios') body = `<div class="card pad0">${table(['Scenario', 'Assigned to', 'Schedule', 'Last result'], [['ACL Privilege Exposure Audit', 'Domain Controllers', 'Weekly', 'PASS'], ['Akira Kill Chain', 'File Servers', 'Manual', 'NEVER'], ['Linux Persistence & Cron', 'Linux Web Tier', 'Daily', 'FAIL']].map(r => `<tr class="noclick"><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td>${st(r[3])}</td></tr>`))}</div>`;
  if (t === 'logs') body = `<div class="log">${['<span class="inf">[14:20:11]</span> agent.heartbeat ok AG-1042', '<span class="ok">[14:20:09]</span> task RUN-5521/T1087 started', '<span class="wrn">[14:18:44]</span> slow DNS resolve (1.9s) DC-PRI-01', '<span class="err">[12:10:03]</span> AG-1302 heartbeat missed (3 retries)', '<span class="ok">[11:04:52]</span> scenario SC-0412 completed · 1 finding', '<span class="inf">[10:58:31]</span> config pushed v37 · 2 keys changed'].map(l => `<div>${l}</div>`).join('')}</div>`;
  if (t === 'health') body = `<div class="grid g3">${[['CPU', 18], ['Memory', 47], ['Disk', 62], ['Heartbeat latency', 22], ['Queue', 9], ['Log lag', 4]].map(([nm, v], k) => `<div class="card"><div class="row between"><span class="muted">${nm}</span><span class="mono">${v}${nm === 'Heartbeat latency' ? ' ms' : nm === 'Queue' || nm === 'Log lag' ? '' : '%'}</span></div><div style="margin-top:10px">${chartSlot({ type: 'spark', data: wave(24, v * 0.75, v, v * 0.15, k + 1), color: v > 60 ? '#f59e0b' : '#10b981', h: 40 })}</div><div class="muted" style="font-size:11px;margin-top:4px">last 24 h</div></div>`).join('')}</div>`;
  if (t === 'attackpath') body = `<div class="card">${D.ATTACK_PATHS.map(p => `<div class="check-row">${sev(p.risk.toLowerCase())}<div class="grow">${p.name}</div><span class="muted">${p.steps} hops</span></div>`).join('')}</div>`;
  if (t === 'risk') body = `<div class="card">${K.hbars([['Domain Controllers', 92, 'red', ''], ['Payments DB', 74, 'amber', ''], ['Finance Workstations', 48, 'green', ''], ['Executive Laptops', 31, 'green', '']])}</div>`;
  const filters = t === 'overview' ? K.filters(K.search('agQ', 'Search host, IP or ID...'), K.select('agSt', 'All statuses', ['Online', 'Degraded', 'Offline']), K.select('agOS', 'All OS', ['Windows', 'Windows Server', 'Linux', 'macOS']), (S.agQ || S.agSt || S.agOS) ? K.clearBtn(['agQ', 'agSt', 'agOS']) : '') : '';
  return K.hero('agent', 'Simulation agents', 'Endpoints that execute scenarios under policy.',
    `<button class="btn" data-act="connConfig">${ic('gear')}Connection Config</button><button class="btn primary" data-act="deployAgent">${ic('plus')}Deploy Agent</button>`,
    [['agent', D.AGENTS.length, 'Agents shown (of 412)'], ['check', n('Online'), 'Online'], ['alert', n('Degraded'), 'Degraded'], ['x', n('Offline'), 'Offline']]) +
  `<div class="grid g3 mb">${K.card('Status', K.donut([{ label: 'Online', value: n('Online'), color: '#10b981' }, { label: 'Degraded', value: n('Degraded'), color: '#f59e0b' }, { label: 'Offline', value: n('Offline'), color: '#ef4444' }], 'agents', 150))}
    ${K.card('Operating systems', K.hbars(['Windows', 'Windows Server', 'Linux', 'macOS'].map(o => [o, Math.round(D.AGENTS.filter(a => osFam(a.os) === o).length / D.AGENTS.length * 100), 'blue'])))}
    ${K.card('Agent version', K.hbars([...new Set(D.AGENTS.map(a => a.version))].sort().reverse().map(v => [v, Math.round(D.AGENTS.filter(a => a.version === v).length / D.AGENTS.length * 100), v === '1.9.2' ? 'green' : 'amber'])))}</div>` +
  `<div class="split split-240"><div class="card" style="padding:10px"><h4 style="padding:4px 8px 8px">Groups</h4>${D.AGENT_GROUPS.map(([nm, c]) => `<div class="tree-item ${S.agSel === nm ? 'on' : ''}" data-act="setAgGroup" data-a="${nm}">${ic(nm === 'All agents' ? 'layers' : 'server', 'sm')}<span>${nm}</span><span class="n">${c}</span></div>`).join('')}<div style="margin-top:10px"><button class="btn sm block" data-act="toast" data-a="Group created">${ic('plus', 'sm')}New group</button></div></div>
   <div class="col">${tabs('agents', tl)}${filters}${body}</div></div>`;
};

// ============ INTEGRATIONS ============
const kindIcon = k => k === 'Cloud' ? 'cloud' : k === 'EDR' ? 'shield' : k === 'SIEM' ? 'dash' : k === 'Email' ? 'mail' : k === 'DLP' ? 'lock' : k === 'Threat intel' ? 'hash' : 'plug';
P.integrations = () => {
  const kinds = [...new Set(D.INTEGRATIONS.map(i => i.kind))], k = S.inK || '';
  const list = filt(D.INTEGRATIONS, S.inQ, i => i.name + i.kind + i.detail).filter(i => !k || i.kind === k);
  const n = s => D.INTEGRATIONS.filter(i => i.state === s).length;
  return K.hero('plug', 'Integrations', 'Connect security tooling, threat intel and response platforms.', `<button class="btn primary" data-act="addTaxii">${ic('plus')}Add TAXII connector</button>`,
    [['plug', D.INTEGRATIONS.length, 'Integrations'], ['check', n('Connected'), 'Connected'], ['alert', D.INTEGRATIONS.length - n('Connected'), 'Need attention'], ['clock', '2 min', 'Freshest sync']]) +
  K.filters(K.search('inQ', 'Search integrations...'), `<div class="chips">${[['', 'All'], ...kinds.map(x => [x, x])].map(([v, l]) => `<button class="chip ${k === v ? 'on' : ''}" data-act="set" data-a="inK" data-b="${v}">${l}</button>`).join('')}</div>`) +
  (list.length ? `<div class="grid g3">${list.map(i => `<div class="card hov" data-act="intOpen" data-a="${D.INTEGRATIONS.indexOf(i)}"><div class="row between"><div class="brand-mark" style="width:34px;height:34px;border-radius:9px;background:var(--elevated);color:var(--accent-hi);box-shadow:none">${ic(kindIcon(i.kind))}</div>${st(i.state)}</div><h2 style="margin:12px 0 4px;font-size:14px">${i.name}</h2><div class="muted" style="font-size:12px">${i.kind} · last sync ${i.last}</div><p class="muted" style="margin:8px 0 0;font-size:12px">${i.detail}</p><div class="row" style="margin-top:12px"><button class="btn sm" data-act="toast" data-a="Connection test passed" data-b="${i.name}">Test</button><button class="btn sm ghost" data-act="intOpen" data-a="${D.INTEGRATIONS.indexOf(i)}">Configure</button></div></div>`).join('')}</div>` : K.empty('search', 'No integrations match', 'Choose another category.')) +
  `<div class="grid g2 mt">${K.card('TAXII Connectors', table(['Name', 'Endpoint', 'Status', 'Last poll'], D.TAXII.map(t => `<tr class="noclick"><td>${t.name}</td><td class="mono muted">${t.url}</td><td>${st(t.status)}</td><td class="muted">${t.last}</td></tr>`)), '', 'pad0')}
   ${K.card('EPP Response Connectors', table(['Connector', 'Action', 'Target', 'Status'], D.EPP.map(e => `<tr class="noclick"><td>${e.name}</td><td>${tag(e.action, 'gray')}</td><td class="muted">${e.target}</td><td>${st(e.status)}</td></tr>`)), `<button class="btn sm" data-act="responseAction">${ic('bolt', 'sm')}Response Action</button>`, 'pad0')}</div>`;
};
A.intOpen = d => {
  const i = D.INTEGRATIONS[+d.a], on = i.state === 'Connected';
  dr(i.name, `${i.kind} integration`, kindIcon(i.kind), `<div class="row between mb">${st(i.state)}<span class="muted">Last sync ${i.last}</span></div><p class="muted" style="margin:0 0 14px">${i.detail}</p>
    <h4 class="mb">Connection</h4><div class="field"><label>Endpoint / tenant</label><input class="input" value="https://${i.name.toLowerCase().replace(/[^a-z]+/g, '-')}.acme-bank.demo" readonly></div><div class="field"><label>Credential</label><input class="input" value="••••••••••••••••" readonly></div>
    <div class="check-row"><span class="grow">Pull detections for verification</span><button class="switch on" data-act="toggle"></button></div><div class="check-row"><span class="grow">Push results as events</span><button class="switch ${on ? 'on' : ''}" data-act="toggle"></button></div>
    <h4 style="margin:18px 0 8px">Recent sync</h4><div class="log">${D.INTEGRATION_LOGS.map(([t, m]) => `<div><span class="${m.startsWith('Warn') ? 'wrn' : 'ok'}">[${t}]</span> ${m}</div>`).join('')}</div>`,
    `<button class="btn" data-act="toast" data-a="Connection test passed" data-b="${i.name}">Test connection</button><button class="btn primary" data-act="toast" data-a="Settings saved" data-b="${i.name}">Save</button>`);
};

// ============ SETTINGS (users, ART, audit enriched; other tabs unchanged) ============
const prevSettings = P.settings;
const SET_NAV = [['users', 'Users & roles', 'key'], ['caldera', 'Caldera Engine', 'bolt'], ['intel', 'Threat Intel Connector', 'hash'], ['taxii', 'TAXII Connectors', 'plug'], ['art', 'ART Content Library', 'book'], ['audit', 'Audit Logs', 'file'], ['theme', 'Theme & Display', 'sun'], ['dashprefs', 'Dashboard Preferences', 'dash'], ['license', 'License', 'shield'], ['backup', 'Backup & Recovery', 'archive']];
P.settings = () => {
  const t = S.sttab;
  if (!['users', 'art', 'audit', 'intel', 'taxii', 'dashprefs'].includes(t)) return prevSettings();
  let b = '';
  if (t === 'users') {
    const us = filt(D.USERS, S.suQ, u => u.name + u.email + u.role);
    b = `<div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Users &amp; roles <span class="cnt">${D.USERS.length}</span></h2><div class="actions"><div class="input-icon" style="min-width:200px">${ic('search')}<input class="input" placeholder="Search users..." value="${S.suQ || ''}" data-input="suQ"></div><button class="btn sm primary" data-act="inviteUser">${ic('plus', 'sm')}New user</button></div></div>
      ${table(['Name', 'Email', 'Role', 'MFA', 'Last active', ''], us.map(u => `<tr data-act="userOpen" data-a="${D.USERS.indexOf(u)}"><td><div class="row"><span class="avatar avatar-sm">${u.name[0]}</span>${u.name}</div></td><td class="muted">${u.email}</td><td>${tag(u.role, u.role === 'Admin' ? 'purple' : u.role === 'Analyst' ? 'blue' : 'gray')}</td><td>${u.mfa ? st('Enabled') : st('Off')}</td><td class="muted">${u.last}</td><td class="num"><button class="btn sm ghost" data-act="userOpen" data-a="${D.USERS.indexOf(u)}">${ic('edit', 'sm')}</button></td></tr>`))}</div>
      ${K.card('Role permissions', table(['Permission', ...Object.keys(D.PERMS)], [...new Set(Object.values(D.PERMS).flat())].map(p => `<tr class="noclick"><td>${p}</td>${Object.keys(D.PERMS).map(r => `<td>${D.PERMS[r].includes(p) ? '<span style="color:var(--green)">●</span>' : '<span class="muted">—</span>'}</td>`).join('')}</tr>`)), '', 'mt pad0')}`;
  }
  if (t === 'art') {
    const rows = filt(D.ART, S.artQ, a => a.name + a.tech).filter(a => !S.artP || a.plat === S.artP);
    b = `<div class="card"><div class="card-hd"><h2>ART Content Library <span class="cnt">${D.ART.filter(a => a.on).length}/${D.ART.length} enabled</span></h2><div class="actions"><button class="btn sm" data-act="toast" data-a="Library updated" data-b="14 atomics synced">${ic('refresh', 'sm')}Sync</button></div></div>
      ${K.filters(K.search('artQ', 'Search atomics or techniques...'), K.select('artP', 'All platforms', [...new Set(D.ART.map(a => a.plat))]))}
      ${rows.length ? table(['Atomic test', 'Technique', 'Platform', 'Enabled'], rows.map(a => `<tr class="noclick"><td>${a.name}</td><td class="mono">${a.tech}</td><td>${tag(a.plat, 'gray')}</td><td><button class="switch ${a.on ? 'on' : ''}" data-act="artToggle" data-a="${D.ART.indexOf(a)}" aria-label="Toggle"></button></td></tr>`)) : K.empty('search', 'No atomics match', 'Clear the search.')}</div>`;
  }
  if (t === 'audit') {
    const rows = filt(D.AUDIT, S.auQ, a => a.join(' ')).filter(a => (!S.auA || a[1] === S.auA) && (!S.auR || a[4] === S.auR));
    b = `<div class="card">${K.filters(K.search('auQ', 'Search audit trail...'), K.select('auA', 'All actors', [...new Set(D.AUDIT.map(a => a[1]))]), K.select('auR', 'All results', [['ok', 'Success'], ['warn', 'Warning'], ['err', 'Failed']]), (S.auQ || S.auA || S.auR) ? K.clearBtn(['auQ', 'auA', 'auR']) : '')}
      ${rows.length ? table(['Time', 'Actor', 'Action', 'Detail', 'Result'], rows.map(a => `<tr class="noclick"><td class="mono muted">${a[0]}</td><td>${a[1]}</td><td class="mono">${a[2]}</td><td>${a[3]}</td><td>${st(a[4] === 'ok' ? 'Passed' : a[4] === 'warn' ? 'Warning' : 'Failed')}</td></tr>`)) : K.empty('search', 'No entries match', 'Clear the filters.')}</div>`;
  }
  if (t === 'intel') {
    const ti = S.ti = S.ti || { otx: true, misp: false, cti: false, aev: true, pol: 'none' };
    const stat = (rows) => `<div class="ti-stats">${rows.map(([k, v]) => `<div><div class="lbl-s">${k}</div><b>${v}</b></div>`).join('')}</div>`;
    const conn = (key, title, sub, fields, stats, extra = '') => `<div class="card ti-card"><div class="row between"><div class="row" style="gap:10px"><span class="ti-ico">${ic('hash')}</span><div><b>${title}</b><div class="muted" style="font-size:11.5px">${sub}</div></div></div><div class="row" style="gap:8px"><span class="muted" style="font-size:12px">Enabled</span><button class="switch ${ti[key] ? 'on' : ''}" data-act="tiToggle" data-a="${key}"></button></div></div>
      ${fields.map(([l, ph, type]) => `<div class="field" style="margin-top:12px"><label>${l}</label><input class="input" type="${type || 'text'}" placeholder="${ph}"></div>`).join('')}${extra}
      <div class="row" style="gap:8px;margin-top:14px"><button class="btn" data-act="tiTest" data-a="${title}">Test Connection</button><button class="btn primary" data-act="toast" data-a="${title} saved" data-b="Settings stored" data-c="success">Save</button></div>
      <div class="ti-status"><span class="${ti[key + 'ok'] ? 'ok' : 'no'}">${ti[key + 'ok'] ? '✓ Connected' : (key === 'aev' ? '— Not synced yet' : '✗ Not configured')}</span></div>${stats}</div>`;
    b = `<div class="row between mb"><h2 style="margin:0">Threat Intel Connector</h2><button class="btn" data-act="toast" data-a="Sync started" data-b="All enabled connectors" data-c="success">${ic('refresh')}Sync Now</button></div>
      ${K.card('Execution policy (installation default)', `<select class="select" style="width:100%;max-width:560px" data-change="tiPol">${[['none', 'Not stated (in-process verdict stays UNVERIFIED)'], ['restricted', 'Restricted: custom hosts must run ConstrainedLanguage'], ['unrestricted', 'Unrestricted: FullLanguage is permitted']].map(([v, l]) => `<option value="${v}" ${ti.pol === v ? 'selected' : ''}>${l}</option>`).join('')}</select> <button class="btn primary" data-act="toast" data-a="Execution policy saved" data-b="Applies to runs dispatched after this change" data-c="success">Save</button><div class="muted" style="font-size:12px;margin-top:8px">Applies to runs dispatched after this change. A run keeps the policy it was dispatched with, so changing this never rewrites a finished run. Runs without an explicit policy inherit this value.</div>`)}
      <div class="grid g2 mt">${conn('misp', 'MISP', 'Events and threat actors', [['Server URL', 'https://misp.example.local'], ['API key', 'Paste API key', 'password']], stat([['Status', ti.mispok ? 'Connected' : 'Not configured'], ['Events', ti.mispok ? 1284 : '—'], ['Actors extracted', ti.mispok ? 37 : '—'], ['Last fetch', ti.mispok ? 'just now' : '—']]), `<label class="row" style="gap:8px;margin-top:12px;font-size:13px"><input type="checkbox"> Skip TLS verify</label>`)}
        ${conn('cti', 'OpenCTI', 'Threat actor knowledge graph', [['Server URL', 'https://opencti.example.local'], ['API token', 'Paste token', 'password']], stat([['Status', ti.ctiok ? 'Connected' : 'Not configured'], ['Threat actor nodes', ti.ctiok ? 412 : '—'], ['Actors extracted', ti.ctiok ? 58 : '—'], ['Last fetch', ti.ctiok ? 'just now' : '—']]))}
        ${conn('aev', 'OpenAEV', 'Scenarios and exercises · never synced', [['Server URL', 'https://openaev.example.local'], ['API token', 'Paste token', 'password']], stat([['Status', ti.aevok ? 'Connected' : '— Not synced yet'], ['Scenarios synced', 6], ['Created / updated', '0 / 0'], ['Last fetch', '—']]), `<button class="btn sm" style="margin-top:12px" data-act="toast" data-a="OpenAEV sync" data-b="6 scenarios up to date">Sync Now</button>`)}
        ${conn('otx', 'OTX Sync Overview', 'AlienVault OTX · pulses', [['OTX API key', '••••••••••••••••••••4f1a', 'password']], stat([['OTX (AlienVault)', ti.otxok ? 'Connected' : 'Not configured'], ['Bundle (air-gapped)', 'Not configured'], ['Last sync', '25/10/2026, 12:24'], ['Status', 'ok'], ['Scenarios created', '0 created, 0 updated'], ['Next sync', '26/10/2026, 12:24']]), `<div class="field" style="margin-top:12px"><label>Pulse subscriptions</label><textarea class="input">APT29 tradecraft\nAkira ransomware\nFinance sector watch</textarea></div>`)}</div>`;
  }
  if (t === 'dashprefs') b = window.dashPrefsHtml();
  if (t === 'taxii') {
    b = `<div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>TAXII Connectors <span class="cnt">${D.TAXII.length}</span></h2><div class="actions"><button class="btn sm" data-act="toast" data-a="Refreshed" data-b="Connector list reloaded">${ic('refresh', 'sm')}Refresh</button><button class="btn sm primary" data-act="taxiiAdd">${ic('plus', 'sm')}Add Connector</button></div></div>
      ${D.TAXII.length ? table(['Name', 'Server URL', 'Enabled', 'Last poll', 'Last result'], D.TAXII.map((x, i) => `<tr class="noclick"><td><b>${x.name}</b></td><td class="mono muted">${x.url}</td><td><button class="switch ${x.off ? '' : 'on'}" data-act="taxiiToggle" data-a="${i}"></button></td><td class="muted">${x.last}</td><td>${st(x.status)}</td></tr>`)) : K.empty('plug', 'No TAXII connectors configured yet.', 'Add a TAXII 2.1 server to ingest threat intelligence collections.')}</div>`;
  }
  return h.pageHead('Settings', 'Platform configuration, identity, integrations and maintenance.', '') +
    `<div class="split split-240"><div class="card" style="padding:10px">${SET_NAV.map(([id, l, i]) => `<div class="tree-item ${t === id ? 'on' : ''}" data-act="sttab" data-a="${id}">${ic(i, 'sm')}<span>${l}</span></div>`).join('')}</div><div>${b}</div></div>`;
};
A.artToggle = d => { D.ART[+d.a].on = !D.ART[+d.a].on; AUD.render(); };
A.inviteUser = () => modal(mhd('Create user', 'user') + `<div class="modal-bd">
  <div class="field"><label>Email</label><input class="input" id="nu-email" placeholder="name@acme-bank.demo" autocomplete="off"></div>
  <div class="field"><label>Display name</label><input class="input" id="nu-name" placeholder="Full name"></div>
  <div class="field"><label>Initial password</label><input class="input" id="nu-pw" type="password" placeholder="At least 12 characters" autocomplete="new-password"><div class="muted" style="font-size:11.5px;margin-top:4px">Share it with the user securely. They are asked to change it at first sign-in.</div></div>
  <div class="field"><label>Role</label><div class="rw-opts" id="nu-roles">${[['Admin', 'Full access: manage users, agents, integrations and settings'], ['Analyst', 'Run scenarios, manage agents, approve remediation, view reports'], ['Viewer', 'Read-only: view dashboards and reports']].map(([r, d], i) => `<label class="rw-radio ${i === 1 ? 'on' : ''}"><input type="radio" name="nu-role" value="${r}" ${i === 1 ? 'checked' : ''}><span><b>${r}</b><br><span class="muted" style="font-size:12px">${d}</span></span></label>`).join('')}</div></div>
  <div id="nu-err" class="muted" style="color:var(--red);font-size:12.5px"></div></div>
  <div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="createUser">Create user</button></div>`, 'sm');
A.createUser = () => {
  const v = id => (document.getElementById(id) || {}).value || '', email = v('nu-email').trim(), name = v('nu-name').trim() || email.split('@')[0], pw = v('nu-pw'), role = (document.querySelector('input[name="nu-role"]:checked') || {}).value || 'Analyst';
  const err = !/^\S+@\S+\.\S+$/.test(email) ? 'Enter a valid email address.' : D.USERS.some(u => u.email === email) ? 'A user with this email already exists.' : pw.length < 12 ? 'Password must be at least 12 characters.' : '';
  if (err) { document.getElementById('nu-err').textContent = err; return; }
  D.USERS.push({ name, email, role, last: 'never', mfa: false });
  AUD.closeModal(); toast('User created', `${email} · ${role}`, 'success'); AUD.render();
};
A.userOpen = d => {
  const u = D.USERS[+d.a];
  dr(u.name, u.email, 'user', `<div class="row between mb">${tag(u.role, u.role === 'Admin' ? 'purple' : u.role === 'Analyst' ? 'blue' : 'gray')}${u.mfa ? st('Enabled') : st('Off')}</div>${K.kv([['Last active', u.last], ['MFA', u.mfa ? 'Authenticator app' : 'Not enrolled']])}
    <h4 style="margin:18px 0 8px">Role</h4><div class="chips">${Object.keys(D.PERMS).map(r => `<button class="chip ${u.role === r ? 'on' : ''}" data-act="userRole" data-a="${d.a}" data-b="${r}">${r}</button>`).join('')}</div>
    <h4 style="margin:18px 0 8px">Permissions in this role</h4>${D.PERMS[u.role].map(p => `<div class="check-row"><span style="color:var(--green)">●</span><span class="grow">${p}</span></div>`).join('')}`,
    `<button class="btn danger" data-act="toast" data-a="User disabled" data-b="${u.name}">Disable</button>`);
};
A.userRole = d => { D.USERS[+d.a].role = d.b; toast('Role updated', `${D.USERS[+d.a].name} → ${d.b}`); A.userOpen({ a: d.a }); AUD.render(); };

// ============ PROFILE ============
P.profile = () => {
  const prefs = [['Two-factor authentication', true], ['Notify on critical findings', true], ['Notify on failed runs', false], ['Weekly digest email', true]];
  return K.hero('user', 'My Profile', 'Your account, sign-in and preferences.', '<button class="btn primary" data-act="toast" data-a="Profile saved">Save changes</button>',
    [['clock', 'Today 08:12', 'Last sign-in'], ['key', D.SESSIONS.length, 'Active sessions'], ['lock', D.TOKENS.length, 'API tokens'], ['shield', 'Admin', 'Role']]) +
  `<div class="grid g-side">${K.card('Account', `<div class="row" style="margin-bottom:16px"><span class="avatar" style="width:56px;height:56px;font-size:20px">A</span><div><h2>Admin</h2><div class="muted">admin@acme-bank.demo</div></div></div>
    <div class="field"><label>Display name</label><input class="input" value="Admin"></div><div class="grid g2" style="gap:10px"><div class="field"><label>Time zone</label><select class="select"><option>Europe/London</option><option>Asia/Karachi</option><option>America/New_York</option></select></div><div class="field"><label>Language</label><select class="select"><option>English (UK)</option></select></div></div>`)}
   ${K.card('Security & notifications', prefs.map(([n, v]) => `<div class="check-row"><span class="grow">${n}</span><button class="switch ${v ? 'on' : ''}" data-act="toggle"></button></div>`).join('') + `<div class="row" style="margin-top:14px"><button class="btn" data-act="toast" data-a="Password change email sent">Change password</button></div>`)}</div>
  <div class="grid g2 mt">${K.card('Active sessions', table(['Device', 'IP', 'Last active', ''], D.SESSIONS.map((s, i) => `<tr class="noclick"><td>${s[0]}</td><td class="mono muted">${s[1]}</td><td>${s[3] ? '<span style="color:var(--green)">This session</span>' : s[2]}</td><td class="num">${s[3] ? '' : `<button class="btn sm ghost" data-act="sessRevoke" data-a="${i}">Revoke</button>`}</td></tr>`)), '', 'pad0')}
   ${K.card('API tokens', table(['Name', 'Token', 'Scope', 'Expires', ''], D.TOKENS.map((t, i) => `<tr class="noclick"><td>${t[0]}<div class="muted" style="font-size:11px">Created ${t[3]}</div></td><td class="mono">${t[1]}</td><td>${tag(t[2], 'blue')}</td><td class="muted">${t[4]}</td><td class="num"><button class="btn sm ghost" data-act="tokRevoke" data-a="${i}">Revoke</button></td></tr>`)), `<button class="btn sm primary" data-act="tokNew">${ic('plus', 'sm')}New token</button>`, 'pad0')}</div>`;
};
A.sessRevoke = d => { D.SESSIONS.splice(+d.a, 1); toast('Session revoked'); AUD.render(); };
A.tokRevoke = d => { D.TOKENS.splice(+d.a, 1); toast('Token revoked'); AUD.render(); };
A.tokNew = () => { D.TOKENS.push(['New token', 'bas_••••' + Math.random().toString(16).slice(2, 6), 'Read', '25 Oct', '90 days']); toast('Token created', 'Copy it now — it will not be shown again', 'info'); AUD.render(); };
})();

Object.assign(AUD.A, {
  tiToggle: (d, el) => { AUD.S.ti[d.a] = !AUD.S.ti[d.a]; el.classList.toggle('on'); },
  tiTest: d => { const m = { MISP: 'misp', OpenCTI: 'cti', OpenAEV: 'aev', 'OTX Sync Overview': 'otx' }[d.a]; const ti = AUD.S.ti; ti[m + 'ok'] = true; AUD.toast('Connection OK', d.a + ' reachable', 'success'); AUD.render(); },
  tiPol: (d, el) => { AUD.S.ti.pol = el.value; },
  taxiiToggle: d => { const x = D.TAXII[+d.a]; x.off = !x.off; AUD.toast(x.off ? 'Connector disabled' : 'Connector enabled', x.name); AUD.render(); },
  taxiiAdd: () => AUD.modal(AUD.h.mhd('Add TAXII connector', 'plug') + `<div class="modal-bd"><div class="field"><label>Name</label><input class="input" id="tx-name" placeholder="CISA AIS"></div><div class="field"><label>Server URL</label><input class="input" id="tx-url" placeholder="https://taxii.example.org/taxii2/"></div><div class="field"><label>Collection ID</label><input class="input" placeholder="Optional — defaults to all readable collections"></div><div class="grid g2" style="gap:10px"><div class="field"><label>Username</label><input class="input"></div><div class="field"><label>Password / token</label><input class="input" type="password"></div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="taxiiSave">Add connector</button></div>`, 'sm'),
  taxiiSave: () => { const n = (document.getElementById('tx-name') || {}).value || 'New connector', u = (document.getElementById('tx-url') || {}).value || 'https://taxii.example.org/taxii2/'; D.TAXII.push({ name: n, url: u, status: 'Passed', last: 'never' }); AUD.closeModal(); AUD.toast('Connector added', n, 'success'); AUD.render(); }
});
