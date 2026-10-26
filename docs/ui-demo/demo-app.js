// Audspect console UI demo — routing, pages, modals, drawers. Sample data only.
(() => {
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const S = { route: 'dashboard', cat: 'all', scView: 'grid', scSel: 'SC-0355', scQ: '', fSrc: '', fOS: '', fProd: '', scSort: 'newest',
  dashView: 'operational', runSel: null, initSel: null, findSev: 'all', findQ: '', agSel: 'All agents', agTab: 'overview', tac: '', sttab: 'users',
  remSel: null, apSel: 'AP-14', recFilter: 'all', rep: 'reports', prof: false };
const NAMES = {};
D.NAV.forEach(g => g.items.forEach(([id, label]) => NAMES[id] = label));
const tag = (t, c = '') => `<span class="tag ${c}">${t}</span>`;
const sev = s => `<span class="sev ${s}">${s}</span>`;
const st = (t) => {
  const m = { Active: 's-active', Online: 's-active', Connected: 's-active', Healthy: 's-active', Passed: 's-pass', PASS: 's-pass', Detected: 's-pass', Completed: 's-pass', Verified: 's-pass', Closed: 's-pass', Pass: 's-pass', Ready: 's-active',
    Draft: 's-draft', Pending: 's-draft', Planned: 's-draft', Scheduled: 's-draft', Queued: 's-draft', 'At Risk': 's-warn', Warning: 's-warn', Degraded: 's-warn', WARN: 's-warn', Partial: 's-warn', Missed: 's-fail', Failing: 's-fail', Failed: 's-fail', FAIL: 's-fail', Error: 's-fail', Offline: 's-fail', 'Not connected': 's-off', Paused: 's-off', Disabled: 's-off', Running: 's-run', 'In progress': 's-run', Open: 's-warn', 'Accepted risk': 's-off', NEVER: 's-off', Enabled: 's-active', On: 's-active' };
  return `<span class="pill-status ${m[t] || ''}">${t}</span>`;
};
const bar = (v, c = '') => `<div class="bar ${c}"><i style="width:${v}%"></i></div>`;
const pageHead = (title, sub, actions = '', count = '') => `<div class="page-head"><div class="grow"><div class="page-title-row"><h1>${title}</h1>${count !== '' ? `<span class="cnt">${count}</span>` : ''}</div><div class="sub">${sub}</div></div><div class="actions">${actions}</div></div>`;
const table = (cols, rows, cls = '') => `<div class="tbl-wrap"><table class="tbl ${cls}"><thead><tr>${cols.map(c => `<th class="${c.num ? 'num' : ''}">${c.t ?? c}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
const tabs = (route, list) => `<div class="tabs">${list.map(([id, label, n]) => `<button class="${S.tab?.[route] === id || (!S.tab?.[route] && id === list[0][0]) ? 'on' : ''}" data-act="tab" data-a="${route}" data-b="${id}">${label}${n !== undefined ? ` <span class="cnt">${n}</span>` : ''}</button>`).join('')}</div>`;
const curTab = (route, list) => S.tab?.[route] || list[0][0];
const kpi = (label, val, delta, icon, color = '--accent', dcol = 'var(--green)', spark = null) => `<div class="kpi" style="--kc:var(${color})"><div class="kpi-top"><div class="lbl"><span class="ico" style="background:transparent;color:var(${color})">${ic(icon)}</span>${label}</div></div><div class="val">${val}</div><div class="delta" style="color:${dcol}">${delta}</div>${spark ? `<div class="kpi-spark">${chartSlot({ type: 'spark', data: spark, color: getComputedStyle(document.documentElement).getPropertyValue(color).trim() || '#3b82f6', h: 38 })}</div>` : ''}</div>`;
const seg = (route, key, opts) => `<div class="seg">${opts.map(([v, l, i]) => `<button class="${S[key] === v ? 'on' : ''}" data-act="set" data-a="${key}" data-b="${v}">${i ? ic(i, 'sm') : ''}${l}</button>`).join('')}</div>`;
const sel = (key, label, opts, cur) => `<select class="select" data-change="setSel" data-a="${key}"><option value="">${label}</option>${opts.map(o => `<option ${o === cur ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
// Thin wrappers over demo-charts.js (responsive, with tooltips and axes)
const lineChart = (vals, labels, color = '#3b82f6', extra = {}) => chartSlot({ type: 'line', labels, series: [{ name: 'Value', data: vals, color }], h: 190, yMax: 100, suffix: '%', ...extra });
const barChart = (vals, labels, color = '#3b82f6') => chartSlot({ type: 'bar', labels, series: [{ name: 'Count', data: vals, color }], h: 180 });
const gauge = (score, color = '#f59e0b') => `<div class="gauge"><svg viewBox="0 0 150 150" width="150" height="150" class="progress-ring"><circle cx="75" cy="75" r="62" fill="none" class="track" stroke-width="12"/><circle cx="75" cy="75" r="62" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${(score / 100) * 389.5} 389.5"/></svg><div class="gv"><div><b>${score}</b><span class="muted" style="font-size:11px">out of 100</span></div></div></div>`;
// Cross-links between records (finding ↔ scenario ↔ run ↔ agent ↔ remediation)
const F2S = { 'F-2231': 'SC-0355', 'F-2230': 'SC-0412', 'F-2228': 'SC-0398', 'F-2226': 'SC-0318', 'F-2221': 'SC-0340', 'F-2219': 'SC-0260', 'F-2217': 'SC-0391', 'F-2212': 'SC-0305' };
const RUN_SC = { 'RUN-5521': 'SC-0355', 'RUN-5520': 'SC-0412', 'RUN-5519': 'SC-0377', 'RUN-5518': 'SC-0291', 'RUN-5517': 'SC-0318', 'RUN-5516': 'SC-0391' };
const relBlock = items => items.length ? `<h4 class="mt" style="margin-top:18px;margin-bottom:8px">Related</h4><div class="rel-list">${items.map(([i, l, sub, act, arg]) => `<a class="rel" data-act="${act}" data-a="${arg}">${ic(i)}<span class="grow"><b>${l}</b><em>${sub}</em></span>${ic('chevr', 'sm')}</a>`).join('')}</div>` : '';
const relForFinding = f => {
  const out = [], sc = D.SCENARIOS.find(s => s.id === F2S[f.id]);
  if (sc) out.push(['target', sc.name, 'Scenario ' + sc.id, 'scDetail', sc.id]);
  const ag = D.AGENTS.find(a => a.host === f.asset);
  if (ag) out.push(['agent', ag.host, `Agent ${ag.id} · ${ag.group}`, 'agentMenu', ag.id]);
  const rm = D.REMED.cards.find(c => c.asset === f.asset);
  if (rm) out.push(['wrench', rm.title, `Remediation ${rm.id}`, 'openRem', rm.id]);
  out.push(['mapped', 'Technique ' + f.tech, 'Open coverage detail', 'techDetail', f.tech]);
  return out;
};

// Deterministic sample series for the time-range picker (no randomness, so screenshots are stable)
const wave = (n, a, b, amp, seed = 1) => Array.from({ length: n }, (_, i) => Math.round((a + (b - a) * (n < 2 ? 0 : i / (n - 1)) + Math.sin(i * 1.7 + seed) * amp) * 10) / 10);
const rangeLabels = (range, n) => {
  const end = new Date(2026, 9, 24, 14, 0);
  return Array.from({ length: n }, (_, i) => {
    const back = n - 1 - i, d = new Date(end);
    if (range === '24h') { d.setHours(end.getHours() - back); return String(d.getHours()).padStart(2, '0') + ':00'; }
    d.setDate(end.getDate() - back * (range === '90d' ? 2 : 1));
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
  });
};
const scColor = s => ({ 'Built-in': '#3b82f6', Custom: '#a78bfa', 'Threat intel': '#ef4444', Common: '#3b82f6', 'APT & Threat Actors': '#ef4444', Compliance: '#f59e0b', 'Cloud & Infrastructure': '#22d3ee', 'Data Security': '#10b981', 'Identity & Access': '#a78bfa', 'Network & Perimeter': '#60a5fa' })[s] || '#3b82f6';

// ---------- Overlays ----------
const modal = (html, cls = '') => {
  const m = $('#modal'); m.className = 'modal ' + cls; m.innerHTML = html; $('#overlay').classList.remove('hidden');
  m.querySelectorAll('.icon-btn:not([aria-label])').forEach(b => b.setAttribute('aria-label', 'Close'));
  hydrateCharts(m);
  const f = m.querySelector('input:not([type=checkbox]):not([type=radio]), textarea');   // focus the first text field, never a destructive button
  if (f) setTimeout(() => f.focus(), 40);
};
const closeModal = () => $('#overlay').classList.add('hidden');
const mhd = (title, icon = 'box') => `<div class="modal-hd">${ic(icon)}<h3>${title}</h3><button class="icon-btn x" data-act="closeModal">${ic('x')}</button></div>`;
const drawer = (html, cls = '') => { $('#drawer').className = 'drawer ' + cls; $('#drawer').innerHTML = html; $('#drawer-overlay').classList.remove('hidden'); hydrateCharts($('#drawer')); };
const closeDrawer = () => { $('#drawer-overlay').classList.add('hidden'); S.liveRun = null; };
const dhd = (title, sub = '', icon = 'box') => `<div class="drawer-hd">${ic(icon)}<div class="grow"><h3>${title}</h3>${sub ? `<div class="muted" style="font-size:12px">${sub}</div>` : ''}</div><button class="icon-btn" data-act="closeDrawer">${ic('x')}</button></div>`;
const toast = (title, msg = '', kind = '') => {
  const t = document.createElement('div'); t.className = 'toast ' + kind;
  t.innerHTML = `${ic(kind === 'err' ? 'alert' : kind === 'warn' ? 'alert' : kind === 'info' ? 'bell' : 'check')}<div><b>${title}</b><span>${msg}</span></div>`;
  $('#toasts').appendChild(t); setTimeout(() => t.remove(), 3600);
};
const go = r => { location.hash = '#/' + r; };

// ---------- Nav ----------
function renderNav() {
  $('#nav').innerHTML = shellNavExtra(S.route) + D.NAV.map(g => `<div class="nav-group"><div class="nav-group-label">${g.group}</div>${g.items.map(([id, label, icon, badge]) => `
    <div class="nav-item ${S.route === id ? 'active' : ''}" data-act="nav" data-a="${id}" title="${label}">${ic(icon)}<span>${label}</span>${badge ? `<span class="${id === 'findings' ? 'nav-badge' : 'nav-count'}">${badge}</span>` : ''}</div>`).join('')}</div>`).join('');
}

// ---------- Pages ----------
const P = {};

P.dashboard = () => {
  const ops = S.dashView === 'operational';
  const head = pageHead(ops ? 'Security Posture' : 'Executive Dashboard', ops ? 'Live view of validation activity, detection performance and agent health.' : 'Board-level view of security posture, risk and SLA compliance.',
    `<div class="seg"><button class="${ops ? 'on' : ''}" data-act="set" data-a="dashView" data-b="operational">Operational</button><button class="${!ops ? 'on' : ''}" data-act="set" data-a="dashView" data-b="executive">Executive</button></div><button class="btn" data-act="toast" data-a="Dashboard refreshed" data-b="Data as of 24 Oct 14:20">${ic('refresh')}Refresh</button>`);
  if (!ops) return head + `
    <div class="grid g4">
      ${kpi('Overall risk score', '68 / 100', '▲ 4 vs last month', 'shield', '--amber', 'var(--red)')}
      ${kpi('Validated controls', '76%', '▲ 3 pts', 'check', '--green')}
      ${kpi('Critical exposures', '4', '▼ 2 closed this week', 'alert', '--red', 'var(--green)')}
      ${kpi('SLA compliance', '91%', 'Target 95%', 'clock', '--cyan', 'var(--amber)')}
    </div>
    <div class="grid g-side mt">
      <div class="card"><div class="card-hd"><h2>Risk trend — last 12 weeks</h2><div class="actions"><span class="tag">Overall</span></div></div>${lineChart([62, 60, 64, 63, 66, 61, 65, 67, 64, 69, 66, 68], ['W1','W2','W3','W4','W5','W6','W7','W8','W9','W10','W11','W12'], '#f59e0b')}</div>
      <div class="card"><h2>Overall posture</h2><div class="muted" style="font-size:12px;margin:4px 0 6px">Weighted across validated domains</div>${gauge(68)}<div class="legend mt" style="justify-content:center"><span><i style="background:#f59e0b"></i>Moderate</span></div></div>
    </div>
    <div class="card mt"><div class="card-hd"><h2>What changed this period</h2><div class="actions"><span class="muted" style="font-size:12px">vs previous ${SHELL.range}</span></div></div>${[
      ['trend', 'Detection rate up 9 points since 1 Oct', 'After EDR rule tuning and ASR enforcement, Office-child-process attacks are now blocked end to end.', 'verification'],
      ['alert', 'Identity is still the weakest domain (61%)', 'ADCS ESC1 and AdminSDHolder ACL drift are open, and both sit on validated attack path AP-14.', 'attackpath'],
      ['clock', 'SLA compliance is 91% against a 95% target', 'Four breaches in the last 30 days, all medium severity and owned by Linux Ops.', 'reports'],
      ['check', 'Public storage exposure closed', 'The customer-exports bucket was made private and re-validated by CMP-33 dry run.', 'exposure']].map(([i, t, d, r]) => `<a class="insight feed-link" data-act="nav" data-a="${r}"><span class="ii">${ic(i, 'sm')}</span><div class="grow"><b style="font-weight:500">${t}</b><div class="muted" style="font-size:12.5px;margin-top:2px">${d}</div></div>${ic('chevr', 'sm')}</a>`).join('')}</div>
    <div class="grid g2 mt">
      <div class="card"><h2 class="mb">Posture by domain</h2>${[['Endpoint', 84, 'green'], ['Email', 90, 'green'], ['Network', 77, ''], ['Data security', 72, 'cyan'], ['Identity', 61, 'amber'], ['Cloud', 58, 'red']].map(([n, v, c]) => `<div class="hbar-row"><span>${n}</span>${bar(v, c)}<span class="v">${v}%</span></div>`).join('')}</div>
      <div class="card"><h2 class="mb">Top business risks</h2>${[['Domain Admin reachable from helpdesk', 'critical', 'Identity'], ['Ransomware path to file tier unvalidated', 'high', 'Endpoint'], ['Cardholder logs not forwarded (1 DB)', 'high', 'Logging'], ['Public S3 bucket with customer exports', 'critical', 'Cloud']].map(([t, s, d]) => `<div class="check-row">${sev(s)}<div class="grow"><b style="font-weight:500">${t}</b><div class="muted" style="font-size:12px">${d} domain</div></div></div>`).join('')}</div>
    </div>`;
  const runs = D.RUNS.slice(0, 5);
  const R = SHELL.range, n = ({ '24h': 24, '7d': 7, '30d': 30, '90d': 45 })[R];
  const labels = rangeLabels(R, n);
  const detRate = wave(n, R === '24h' ? 77 : 70, 83, 2.2, 3).map(v => Math.min(98, Math.round(v)));
  const vol = ({ '24h': 4, '7d': 58, '30d': 42, '90d': 88 })[R];
  const dDet = wave(n, vol * 0.6, vol * 0.66, vol * 0.08, 1).map(v => Math.max(1, Math.round(v)));
  const dPar = wave(n, vol * 0.2, vol * 0.2, vol * 0.04, 2).map(v => Math.max(1, Math.round(v)));
  const dMis = wave(n, vol * 0.14, vol * 0.12, vol * 0.03, 3).map(v => Math.max(0, Math.round(v)));
  const kv = ({ '24h': ['58', '79%'], '7d': ['412', '80%'], '30d': ['1,284', '81%'], '90d': ['3,702', '77%'] })[R];
  return head + `
    <div class="grid g5">
      ${kpi(`Validations (${R})`, kv[0], `▲ 12% vs prior ${R}`, 'play', '--accent', 'var(--green)', [31, 36, 33, 40, 38, 44, 41, 47, 45, 49, 52, 48, 55, 51, 58, 54])}
      ${kpi('Detection rate', kv[1], '▲ 4 pts', 'shield', '--green', 'var(--green)', [72, 74, 73, 76, 78, 77, 79, 80, 79, 81, 83, 81])}
      ${kpi('Open findings', '47', '9 critical / high', 'alert', '--red', 'var(--red)', [58, 55, 57, 52, 53, 50, 51, 49, 52, 48, 47, 47])}
      ${kpi('Agents online', '412 / 428', '16 need attention', 'agent', '--cyan', 'var(--amber)', [405, 409, 411, 407, 410, 412, 408, 411, 413, 410, 412, 412])}
      ${kpi('Mean time to detect', '6m 12s', '▼ 48s', 'clock', '--purple', 'var(--green)', [9.1, 8.4, 8.8, 7.9, 7.6, 7.2, 7.4, 6.9, 6.7, 6.5, 6.3, 6.2])}
    </div>
    <div class="grid g-side mt">
      <div class="card"><div class="card-hd"><h2>Detection rate — ${R === '24h' ? 'last 24 hours' : R === '7d' ? 'last 7 days' : R === '30d' ? 'last 30 days' : 'last 90 days'}</h2><div class="actions"><div class="legend"><span><i style="background:#3b82f6"></i>Detected</span><span><i style="background:#f59e0b"></i>Target 90%</span></div></div></div>${lineChart(detRate, labels, '#3b82f6', { series: [{ name: 'Detected', data: detRate, color: '#3b82f6' }, { name: 'Target', data: Array(n).fill(90), color: '#f59e0b', dash: true }], area: true })}</div>
      <div class="card"><div class="card-hd"><h2>${R === '24h' ? 'Hourly validations' : R === '90d' ? 'Validations (per 2 days)' : 'Daily validations'}</h2><div class="actions"><div class="legend"><span><i style="background:#10b981"></i>Detected</span><span><i style="background:#f59e0b"></i>Partial</span><span><i style="background:#ef4444"></i>Missed</span></div></div></div>${chartSlot({ type: 'bar', stacked: true, labels, h: 190, series: [
        { name: 'Detected', color: '#10b981', data: dDet },
        { name: 'Partial', color: '#f59e0b', data: dPar },
        { name: 'Missed', color: '#ef4444', data: dMis }] })}</div>
    </div>
    <div class="grid g2 mt">
      <div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Recent validation runs</h2><div class="actions"><button class="btn sm ghost" data-act="nav" data-a="runs">View all ${ic('chevr','sm')}</button></div></div>
        ${table(['Run', 'Target', { t: 'Status' }], runs.map(r => `<tr data-act="openRun" data-a="${r.id}"><td><div>${r.name}</div><div class="mono muted" style="font-size:11px">${r.id}</div></td><td class="muted">${r.target}</td><td>${st(r.status)}</td></tr>`))}</div>
      <div class="card"><div class="card-hd"><h2>Top coverage gaps</h2></div>${[['T1547.001 Registry Run Keys', 41, 'red'], ['T1486 Data Encrypted for Impact', 35, 'red'], ['T1021.002 SMB Admin Shares', 49, 'amber'], ['T1068 Priv-Esc Exploitation', 56, 'amber'], ['T1041 Exfil over C2', 52, 'amber']].map(([n, v, c]) => `<div class="hbar-row"><span class="mono" style="font-size:11.5px">${n}</span>${bar(v, c)}<span class="v">${v}%</span></div>`).join('')}</div>
    </div>
    <div class="grid g2 mt">
      <div class="card"><div class="card-hd"><h2>Agent health by group</h2></div>${D.AGENT_GROUPS.slice(1).map(([n, c], i) => `<div class="hbar-row"><span>${n}</span>${bar([96, 100, 88, 75, 100, 90][i], [ '', '', 'amber', 'red', '', ''][i])}<span class="v">${c}</span></div>`).join('')}</div>
      <div class="card"><div class="card-hd"><h2>Recent alerts</h2></div>${D.NOTIFS.map(([i, c, t, d]) => `<div class="notif"><span class="ni" style="background:var(--${c === 'red' ? 'red' : c === 'green' ? 'green' : c === 'amber' ? 'amber' : 'accent'}-dim);color:var(--${c === 'red' ? 'red' : c === 'green' ? 'green' : c === 'amber' ? 'amber' : 'accent'})">${ic(i)}</span><div><b>${t}</b><span>${d}</span></div></div>`).join('')}</div>
    </div>
    <div class="grid g-side mt">
      <div class="card"><div class="card-hd"><h2>Activity</h2><div class="actions"><span class="muted" style="font-size:12px">Today</span></div></div><div class="feed">${[
        ['play', 'accent', 'RUN-5521 started — APT29 Kill Chain', 'Finance Workstations · started by admin', '14:02', 'openRun', 'RUN-5521'],
        ['alert', 'red', 'New finding F-2231 — Run-key persistence not detected', 'High severity · WS-FIN-0142', '13:47', 'openFinding', 'F-2231'],
        ['check', 'green', 'Remediation R-299 verified', 'ASR rule enabled — Office child processes now blocked', '12:31', 'openRem', 'R-299'],
        ['agent', 'amber', 'Agent lnx-web-08 went offline', 'Heartbeat missed 3 times · Linux Web Tier', '12:10', 'agentMenu', 'AG-1302'],
        ['report', 'accent', 'Report ready — Executive Security Posture', 'October 2026 · PDF · 14 pages', '11:15', 'previewRpt', 'RPT-0198'],
        ['shield', 'amber', 'Signature gate: 2 scenarios need re-sign', 'SC-0377 and SC-0274 are unsigned', '09:40', 'nav', 'factory-health']].map(([i, c, t, d, tm, act, arg]) => `<a class="feed-item feed-link" data-act="${act}" data-a="${arg}"><span class="fi" style="background:var(--${c}-dim);color:var(--${c})">${ic(i, 'sm')}</span><div><b>${t}</b><span class="d">${d}</span></div><time>${tm}</time></a>`).join('')}</div></div>
      <div class="card"><div class="card-hd"><h2>Up next</h2><div class="actions"><button class="btn sm ghost" data-act="nav" data-a="scheduled-assessments">All ${ic('chevr', 'sm')}</button></div></div><div class="feed">${[
        ['Nightly Ransomware Canary', 'File Servers (18)', 'in 9 h 10 m'], ['Weekly Endpoint Regression', 'Windows Workstations (412)', 'in 2 d 11 h'], ['Monthly Identity Posture', 'Domain Controllers (6)', 'in 7 d'], ['Campaign CMP-33 — Cloud Storage Sweep', 'AWS prod accounts (3)', 'in 3 d 19 h']].map(([t, d, cd]) => `<div class="feed-item" style="grid-template-columns:28px 1fr auto"><span class="fi" style="background:var(--accent-dim);color:var(--accent-hi)">${ic('clock', 'sm')}</span><div><b>${t}</b><span class="d">${d}</span></div><span class="countdown">${cd}</span></div>`).join('')}</div></div>
    </div>`;
};

const AVAIL = { ok: ['Available on this installation', '', '<span class="avail ok">● Available</span>'], cat: ['Catalogued only', '', '<span class="avail cat">○ Catalogued only</span>'], identity: ['Unavailable: identity connector not configured', '', '<span class="avail no">⚠ Identity connector needed</span>'], exp: ['Experimental', '', '<span class="avail exp">⚗ Experimental</span>'] };
P.scenarios = () => {
  const cats = D.CATEGORIES;
  const list = D.SCENARIOS.filter(s => (!S.scQ || (s.name + s.desc + s.tech.join(' ') + s.id).toLowerCase().includes(S.scQ.toLowerCase())) && (!S.fSrc || s.source === S.fSrc) && (!S.fOS || s.os.startsWith(S.fOS)) && (!S.fProd || s.product === S.fProd) && (!S.fTier || s.tier.includes(S.fTier)) && (S.cat === 'all' || s.cat === S.cat || (S.cat === 'common' && s.source === 'Common')));
  if (S.scSort === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
  if (S.scSort === 'tech') list.sort((a, b) => b.techniques - a.techniques);
  return `
    <div class="scn-banner"><div class="row" style="align-items:flex-start;gap:16px">
      <div class="brand-mark" style="width:56px;height:56px;border-radius:14px">${ic('target')}</div>
      <div class="grow"><h1 style="font-size:26px">Scenarios</h1><div class="muted mt" style="margin-top:6px">Explore and launch security scenarios to validate your security controls.</div></div>
      <div class="row"><button class="btn" data-act="uploadYaml">${ic('upload')}Upload YAML</button><button class="btn primary" data-act="newScenario">${ic('plus')}New Scenario</button></div></div>
      <div class="stats">
        <div class="stat"><span class="ico">${ic('target')}</span><div><b>119</b><span>Total Scenarios</span></div></div>
        <div class="stat"><span class="ico">${ic('mapped')}</span><div><b>1251</b><span>Techniques &amp; Tests</span></div></div>
        <div class="stat"><span class="ico">${ic('layers')}</span><div><b>12</b><span>Product Families</span></div></div>
        <div class="stat"><span class="ico">${ic('check')}</span><div><b>Oct 22, 2026</b><span>Updated</span></div></div>
      </div></div>
    <div class="filter-bar">
      <div class="input-icon">${ic('search')}<input class="input" placeholder="Search by name, tag, technique, or ID..." value="${S.scQ}" data-input="scQ"></div>
      <select class="select" data-change="setSel" data-a="fSrc"><option value="">All Sources</option>${['Built-in', 'Custom', 'Threat intel'].map(o => `<option ${S.fSrc === o ? 'selected' : ''}>${o}</option>`).join('')}</select>
      <select class="select" data-change="setSel" data-a="fOS"><option value="">All OS</option>${['Windows', 'Linux', 'macOS'].map(o => `<option ${S.fOS === o ? 'selected' : ''}>${o}</option>`).join('')}</select>
      <select class="select" data-change="setSel" data-a="fProd"><option value="">All Product Lines</option>${['Endpoint / EDR', 'Identity & Access', 'Network', 'Cloud', 'Email', 'Logging & SIEM', 'Application Security'].map(o => `<option ${S.fProd === o ? 'selected' : ''}>${o}</option>`).join('')}</select>
      <select class="select" data-change="setSel" data-a="fTier"><option value="">All Tiers</option>${['Core', 'Advanced', 'Enterprise'].map(o => `<option ${S.fTier === o ? 'selected' : ''}>${o}</option>`).join('')}</select>
      <button class="btn" data-act="refreshScen">${ic('refresh')}Refresh</button>
    </div>
    <div class="scn-layout ${S.catOff ? 'cat-off' : ''}">
      ${S.catOff ? '' : `<div class="card" style="padding:12px">
        <div class="row between" style="padding:2px 4px 8px 8px"><h4>Scenario Categories</h4><button class="icon-btn" data-act="set" data-a="catOff" data-b="1" title="Collapse categories" aria-label="Collapse categories">${ic('chev','sm')}</button></div>
        <div class="cat-list">${cats.map(([id, label, icn, n]) => `<div class="cat-item ${S.cat === id ? 'on' : ''}" data-act="setCat" data-a="${id}">${ic(icn)}<span>${label}</span><span class="n">${n}</span></div>${id === 'phishing' ? '<div class="cat-sub">16 runnable here · 5 need a connector · 23 catalogued only</div>' : ''}`).join('')}</div>
      </div>`}
      <div class="scn-main">
        <div class="row mb" style="justify-content:flex-end;gap:10px;flex-wrap:wrap">${S.catOff ? `<button class="btn sm" data-act="set" data-a="catOff" data-b="" style="margin-right:auto">${ic('layers','sm')}Show categories</button>` : ''}
          <div class="seg"><button class="${S.scView === 'grid' ? 'on' : ''}" data-act="set" data-a="scView" data-b="grid" title="Grid">${ic('grid2','sm')}</button><button class="${S.scView === 'list' ? 'on' : ''}" data-act="set" data-a="scView" data-b="list" title="List">${ic('list','sm')}</button></div>
          <span class="muted">Sort by:</span><select class="select" data-change="setSel" data-a="scSort"><option value="newest" ${S.scSort === 'newest' ? 'selected' : ''}>Newest</option><option value="name" ${S.scSort === 'name' ? 'selected' : ''}>Name</option><option value="tech" ${S.scSort === 'tech' ? 'selected' : ''}>Most techniques</option></select>
        </div>
        <div class="scn-results">
          <div class="${S.scView === 'list' ? 'sc-list' : ''}">
            <div class="sc-grid" style="${S.scView === 'list' ? 'grid-template-columns:1fr' : ''}">${list.map(s => `
              <div class="sc-card ${(s.avail || 'ok') === 'ok' ? '' : 'unavail'}" style="--sc:${scColor(s.source)}" data-act="scDetail" data-a="${s.id}">
                <div class="tags"><span class="tag blue">${s.source}</span><span class="tag">${ic('grid', 'sm')}${s.os}</span><span class="tag purple">${ic('shield', 'sm')}${s.tacticTag}</span></div>
                <h3>${s.name}</h3><p>${s.desc}</p>
                <div class="foot"><span>${ic('mapped', 'sm')} +${s.techniques} techniques</span><span>${ic('clock', 'sm')} ${s.mins} min</span></div>
                <div class="card-actions">${AVAIL[s.avail || 'ok'][2]}${s.status === 'Active' ? '' : st(s.status)}<button class="btn sm primary" ${(s.avail || 'ok') === 'ok' ? `data-act="runScModal" data-a="${s.id}"` : 'disabled'} title="${AVAIL[s.avail || 'ok'][0]}">${ic('play', 'sm')}Run</button></div>
              </div>`).join('')}
            </div>
            ${list.length === 0 ? `<div class="card empty">${ic('search')}<b>No scenarios match these filters</b><div>Try a different keyword or clear the filters.</div><div style="margin-top:12px"><button class="btn sm" data-act="clearFilters">Clear all filters</button></div></div>` : `<div class="muted mt" style="font-size:12px">Showing ${list.length} of 107 scenarios</div>`}
          </div>
        </div>
      </div>
    </div>`;
};

P.runs = () => {
  const rows = D.RUNS.map(r => `<tr data-act="openRun" data-a="${r.id}">
    <td><div>${r.name}</div><div class="mono muted" style="font-size:11px">${r.id}</div></td>
    <td class="muted">${r.target}</td><td>${st(r.status)}</td>
    <td style="min-width:170px"><div class="row" style="gap:8px"><div class="grow">${bar(r.progress, r.status === 'Failed' ? 'red' : r.status === 'Passed' ? 'green' : 'cyan')}</div><span class="mono muted" data-prog="${r.id}" style="width:38px;text-align:right">${r.progress}%</span></div></td>
    <td class="muted" style="max-width:260px" data-step="${r.id}">${r.step}</td><td class="mono muted">${r.started}</td><td class="mono muted">${r.dur}</td>
    <td class="num"><button class="btn sm ghost" data-act="stopRun" data-a="${r.id}" title="Stop">${ic('stop', 'sm')}</button></td></tr>`);
  return pageHead('Live Runs', 'Scenario executions in progress, queued and recently completed.', `<button class="btn" data-act="toast" data-a="Export started" data-b="CSV will be emailed to you">${ic('download')}Export</button><button class="btn primary" data-act="nav" data-a="scenarios">${ic('plus')}New Run</button>`, D.RUNS.length) +
    `<div class="grid g4 mb">${kpi('Running', D.RUNS.filter(r => r.status === 'Running').length, 'Live', 'play', '--cyan')}${kpi('Queued', 1, 'Waiting for slot', 'clock', '--amber')}${kpi('Passed (24h)', 18, '2 failed', 'check', '--green')}${kpi('Agents busy', '7 / 412', '', 'agent', '--accent')}</div>` +
    `<div class="card pad0">${table(['Run', 'Target', 'Status', 'Progress', 'Current step', 'Started', 'Duration', { t: '' }], rows)}</div>`;
};

P.k8s = () => pageHead('Kubernetes Scenarios', 'Cluster-level attack simulations for AKS, EKS and self-managed clusters.', `<button class="btn primary" data-act="toast" data-a="Cluster connector" data-b="Pick a cluster in Integrations to run K8s scenarios">${ic('plus')}New K8s Run</button>`, D.K8S.length) +
  `<div class="grid g3 mb">${['prod-aks-east', 'staging-eks', 'prod-eks-west'].map((c, i) => `<div class="kpi" style="--kc:var(${['--green', '--amber', '--green'][i]})"><div class="lbl">${ic('server')} ${c}</div><div class="val" style="font-size:20px">${['Healthy · 3 nodes', 'Degraded · 1 node cordoned', 'Healthy · 5 nodes'][i]}</div><div class="delta muted">Kubernetes ${['1.29.4', '1.28.9', '1.30.1'][i]}</div></div>`).join('')}</div>` +
  `<div class="card pad0">${table(['Scenario', 'Cluster', 'Namespace', 'Techniques', 'Duration', 'Status', 'Last result'], D.K8S.map(k => `<tr data-act="toast" data-a="${k.name}" data-b="Opening scenario definition">
    <td><div>${k.name}</div><div class="mono muted" style="font-size:11px">${k.id}</div></td><td class="mono">${k.cluster}</td><td class="mono">${k.ns}</td><td>+${k.techniques}</td><td>${k.mins} min</td><td>${st(k.status)}</td><td>${st(k.last)}</td></tr>`))}</div>`;

P.scheduled = () => pageHead('Scheduled Assessments', 'Recurring validations on defined agent scopes.', `<button class="btn primary" data-act="schedWiz">${ic('plus')}New Scheduled Assessment</button>`, D.SCHEDULES.length) +
  `<div class="card pad0">${table(['Assessment', 'Scope', 'Schedule (cron)', 'Next run', 'Last result', 'State', ''], D.SCHEDULES.map(s => `<tr class="noclick">
   <td><div>${s.name}</div><div class="mono muted" style="font-size:11px">${s.id}</div></td><td class="muted">${s.scope}</td><td class="mono">${s.cron}</td><td>${s.next}</td><td>${tag(s.last, s.last.startsWith('PASS') ? 'green' : s.last.startsWith('WARN') ? 'amber' : 'red')}</td><td>${st(s.state)}</td>
   <td class="num"><div class="row" style="justify-content:flex-end"><button class="btn sm" data-act="toast" data-a="${s.state === 'Paused' ? 'Schedule resumed' : 'Schedule paused'}" data-b="${s.name}">${s.state === 'Paused' ? ic('play', 'sm') + 'Resume' : ic('pause', 'sm') + 'Pause'}</button><button class="btn sm ghost" data-act="toast" data-a="Run started" data-b="${s.name} · ad-hoc run">${ic('play', 'sm')}</button></div></td></tr>`))}</div>`;

P.initiatives = () => {
  return pageHead('Initiatives', 'Programmes that group validation jobs into measurable remediation goals.', `<button class="btn primary" data-act="newInitiative">${ic('plus')}New Initiative</button>`, D.INITIATIVES.length) +
    `<div class="grid g2">${D.INITIATIVES.map(x => `<div class="card" style="cursor:pointer" data-act="openInit" data-a="${x.id}">
      <div class="row between"><div><h2>${x.name}</h2><div class="muted" style="font-size:12px;margin-top:4px">${x.id} · Owner: ${x.owner}</div></div>${st(x.status)}</div>
      <div class="row mt" style="justify-content:space-between;font-size:12px;color:var(--muted-hi)"><span>Progress</span><span>${x.progress}%</span></div>
      <div class="mt-1" style="margin-top:6px">${bar(x.progress, x.status === 'At Risk' ? 'amber' : x.status === 'Planned' ? '' : 'green')}</div>
      <div class="row mt" style="margin-top:14px;font-size:12px;color:var(--muted)"><span>${ic('clock', 'sm')} Due ${x.due}</span><span>${ic('box', 'sm')} ${x.jobs} jobs</span></div></div>`).join('')}</div>`;
};

P.campaigns = () => pageHead('Campaigns', 'Coordinated, multi-phase validation programmes across the estate.', `<button class="btn primary" data-act="newCampaign">${ic('plus')}New Campaign</button>`, D.CAMPAIGNS.length) +
  `<div class="grid g3">${D.CAMPAIGNS.map(c => `<div class="card"><div class="row between"><h2>${c.name}</h2>${st(c.status)}</div><p class="muted mt" style="margin-top:6px;font-size:12.5px">${c.scope}</p>
  <div class="mt" style="margin-top:14px;font-size:12px;color:var(--muted)">${c.phase}</div><div style="margin:6px 0 14px">${bar(c.status === 'Scheduled' ? 0 : c.status === 'Completed' ? 100 : 56, c.status === 'Completed' ? 'green' : 'cyan')}</div>
  <div class="grid g3" style="gap:8px;margin-bottom:12px">${[['Runs', c.runs], ['Pass rate', c.pass ? c.pass + '%' : '—'], ['Start', c.start]].map(([a, b]) => `<div><div class="muted" style="font-size:11px">${a}</div><b style="font-weight:600">${b}</b></div>`).join('')}</div>
  <div class="row"><button class="btn sm" data-act="openCampaign" data-a="${c.id}">View</button><button class="btn sm ghost" data-act="toast" data-a="Campaign ${c.status === 'Running' ? 'paused' : 'started'}" data-b="${c.name}">${c.status === 'Running' ? 'Pause' : 'Start'}</button></div></div>`).join('')}</div>`;

P.factory = () => pageHead('Factory Health', 'Health of the scenario build, signing and content pipelines.', `<button class="btn" data-act="toast" data-a="Pipelines re-checked">${ic('refresh')}Re-check</button>`) +
  `<div class="grid g4 mb">${kpi('Scenarios built (30d)', '142', '▲ 9', 'factory', '--accent')}${kpi('Signed & verified', '105 / 107', '2 need re-sign', 'lock', '--green', 'var(--amber)')}${kpi('Pipelines healthy', '3 / 5', 'See below', 'check', '--amber', 'var(--amber)')}${kpi('Queue depth', '8', 'Avg wait 4 min', 'clock', '--cyan')}</div>` +
  `<div class="grid g-side"><div class="card pad0">${table(['Pipeline', 'State', 'Last run', 'Queue', 'Last result'], D.FACTORY.pipelines.map(p => `<tr class="noclick"><td>${p.name}</td><td>${st(p.state)}</td><td class="muted">${p.last}</td><td>${p.queue}</td><td class="muted">${p.lastResult}</td></tr>`))}</div>
  <div class="card"><h2 class="mb">Recent builds</h2>${D.FACTORY.builds.map(b => `<div class="check-row"><span class="dot" style="background:var(--${b.result === 'ok' ? 'green' : b.result === 'warn' ? 'amber' : 'red'});box-shadow:none"></span><div class="grow"><div>${b.what}</div><div class="mono muted" style="font-size:11px">${b.id} · ${b.when} · ${b.by}</div></div></div>`).join('')}</div></div>`;

P.coverage = () => {
  const cls = ['c0', 'c1', 'c2', 'c3'];
  const cells = [
    ['Initial Access', ['T1566', 'T1190', 'T1133', 'T1078']], ['Execution', ['T1059', 'T1204', 'T1203', 'T1569']], ['Persistence', ['T1547', 'T1053', 'T1543', 'T1505']],
    ['Privilege Esc.', ['T1068', 'T1484', 'T1548', 'T1134']], ['Defense Evasion', ['T1562', 'T1070', 'T1218', 'T1036']], ['Credential Access', ['T1003', 'T1558', 'T1110', 'T1555']],
    ['Discovery', ['T1087', 'T1018', 'T1082', 'T1482']], ['Lateral Movement', ['T1021', 'T1570', 'T1550', 'T1080']], ['Collection', ['T1005', 'T1114', 'T1560', 'T1039']],
    ['Command & Control', ['T1071', 'T1105', 'T1573', 'T1095']], ['Exfiltration', ['T1041', 'T1567', 'T1048', 'T1029']], ['Impact', ['T1486', 'T1490', 'T1489', 'T1485']]];
  const score = (i, j) => [3, 1, 2, 0, 2, 1, 3, 0, 2, 1, 0, 1, 3, 2, 0, 1][(i * 4 + j * 3 + i) % 16];
  const grid = `<div class="matrix">${cells.map(([t]) => `<div class="tac">${t}</div>`).join('')}${[0, 1, 2, 3].map(r => cells.map(([t, ids], i) => `<div class="tech ${cls[score(i, r)]}" data-act="techDetail" data-a="${ids[r]}">${ids[r]}<small>${['Detected', 'Partial', 'Alert only', 'Missed'][score(i, r)]}</small></div>`).join('')).join('')}</div>`;
  return pageHead('MITRE ATT&CK Coverage', 'Detection coverage mapped to the ATT&CK matrix from validated scenario results.', `<button class="btn" data-act="pickTech">${ic('mapped')}Select techniques</button><button class="btn primary" data-act="toast" data-a="Coverage recalculated" data-b="Based on runs up to 24 Oct 14:20">${ic('refresh')}Recalculate</button>`) +
    `<div class="grid g4 mb">${kpi('Techniques covered', '212 / 242', '87% of matrix', 'mapped', '--accent')}${kpi('Validated detected', '74%', '▲ 2 pts', 'check', '--green')}${kpi('Missed', '19', '▼ 3', 'alert', '--red', 'var(--green)')}${kpi('Untested', '30', 'Add scenarios', 'target', '--amber', 'var(--amber)')}</div>` +
    `<div class="card"><div class="card-hd"><h2>ATT&amp;CK heatmap (sample — 4 techniques per tactic)</h2><div class="actions legend"><span><i style="background:var(--green)"></i>Detected</span><span><i style="background:var(--cyan)"></i>Alert only</span><span><i style="background:var(--amber)"></i>Partial</span><span><i style="background:var(--red)"></i>Missed</span></div></div>${grid}</div>` +
    `<div class="grid g2 mt"><div class="card"><h2 class="mb">Live Threat Coverage</h2><p class="muted mb" style="font-size:12.5px">Coverage of techniques used by threat actors active against your sector.</p>${[['APT29', 78, 'green'], ['Akira', 64, 'amber'], ['Scattered Spider', 52, 'amber'], ['APT36', 81, 'green']].map(([n, v, c]) => `<div class="hbar-row"><span>${n}</span>${bar(v, c)}<span class="v">${v}%</span></div>`).join('')}</div>
    <div class="card"><h2 class="mb">Coverage by product line</h2>${[['Endpoint / EDR', 82, 'green'], ['Identity', 66, ''], ['Network', 58, 'amber'], ['Email', 90, 'green'], ['Cloud', 44, 'red']].map(([n, v, c]) => `<div class="hbar-row"><span>${n}</span>${bar(v, c)}<span class="v">${v}%</span></div>`).join('')}</div></div>`;
};

P.variants = () => pageHead('Variants', 'Generated technique variants and full-estate variant sweeps.', `<button class="btn" data-act="variantDrill">${ic('layers')}Full Variant Sweep</button><button class="btn primary" data-act="sweepStart">${ic('play')}Run Full Sweep</button>`, D.VARIANTS.length) +
  `<div class="card pad0">${table(['Variant set', 'Technique', 'Variants', 'Passing', 'Status'], D.VARIANTS.map(v => `<tr data-act="variantDrill">
    <td><div>${v.name}</div><div class="mono muted" style="font-size:11px">${v.id}</div></td><td class="mono">${v.family}</td><td>${v.count}</td><td style="min-width:150px"><div class="row"><div class="grow">${bar(v.count ? Math.round(v.pass / v.count * 100) : 0, v.pass === v.count ? 'green' : v.pass === 0 ? 'red' : 'amber')}</div><span class="mono muted">${v.pass}/${v.count}</span></div></td><td>${st(v.status)}</td></tr>`))}</div>`;

P['ad-coverage'] = () => pageHead('AD Coverage', 'Active Directory attack-surface checks across the forest.', `<button class="btn primary" data-act="toast" data-a="AD checks queued" data-b="Forest acme-bank.local · 7 checks">${ic('refresh')}Re-run checks</button>`) +
  `<div class="grid g4 mb">${kpi('Forest', 'acme-bank.local', '3 domains · 2 DCs each', 'box', '--accent')}${kpi('Tier-0 hosts', '6', 'Last scanned 2 h ago', 'server', '--cyan')}${kpi('Critical findings', '3', 'Unconstrained, ADCS, ACL', 'alert', '--red', 'var(--red)')}${kpi('LAPS coverage', '93%', '▲ 4 pts', 'shield', '--green')}</div>` +
  `<div class="card pad0">${table(['Check', 'Result', 'Severity', 'MITRE', 'Status'], D.AD.map(a => `<tr data-act="toast" data-a="${a.check}" data-b="Opening check detail"><td>${a.check}</td><td>${a.result}</td><td>${a.sev === 'info' ? '—' : sev(a.sev)}</td><td class="mono">${a.mapped}</td><td>${st(a.status)}</td></tr>`))}</div>`;

P.email = () => pageHead('Email', 'Phishing and email-delivery validation (Email BAS).', `<button class="btn" data-act="toast" data-a="Template imported" data-b="2 templates added from library">${ic('upload')}Import template</button><button class="btn primary" data-act="emailCampaign">${ic('plus')}New Email Campaign</button>`) +
  `<div class="grid g4 mb">${kpi('Sent (30d)', '600', '▲ 120', 'mail', '--accent')}${kpi('Open rate', '48%', 'Industry avg 42%', 'eye', '--cyan')}${kpi('Click rate', '12%', '▼ 3 pts', 'alert', '--amber', 'var(--green)')}${kpi('Reported', '137', '23% report rate', 'check', '--green')}</div>` +
  `<div class="grid g2"><div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Templates</h2></div>${table(['Template', 'Vector', 'Used', 'Click', 'Status'], D.EMAIL.templates.map(t => `<tr data-act="toast" data-a="${t.name}" data-b="Template preview"><td>${t.name}</td><td>${t.vector}</td><td>${t.used}</td><td>${t.click}</td><td>${st(t.status)}</td></tr>`))}</div>
  <div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Recent campaigns</h2></div>${table(['Campaign', 'Sent', 'Opened', 'Clicked', 'Reported'], D.EMAIL.recent.map(r => `<tr class="noclick"><td>${r.campaign}</td><td>${r.sent}</td><td>${r.opened}</td><td>${r.clicked}</td><td>${r.reported}</td></tr>`))}</div></div>`;

P.findings = () => {
  const rows = D.FINDINGS.filter(f => (S.findSev === 'all' || f.sev === S.findSev) && (!S.findQ || (f.title + f.asset + f.id).toLowerCase().includes(S.findQ.toLowerCase())));
  return pageHead('Findings', 'Gaps surfaced by validation runs, with owners and remediation status.', `<button class="btn" data-act="toast" data-a="Export started" data-b="findings.csv">${ic('download')}Export</button>`, D.FINDINGS.length) +
    `<div class="grid g2 mb"><div class="card"><div class="card-hd"><h2>Open findings by severity</h2><span class="muted" style="margin-left:auto;font-size:12px">Updated 14:20</span></div>${chartSlot({ type: 'donut', h: 180, legendRight: true, centerSub: 'open + in progress', segments: [
      { label: 'Critical', value: 2, color: '#7f1d1d' }, { label: 'High', value: 3, color: '#ef4444' }, { label: 'Medium', value: 1, color: '#f59e0b' }, { label: 'Low', value: 0, color: '#10b981' }] })}</div>
      <div class="card"><div class="card-hd"><h2>Status</h2></div>${chartSlot({ type: 'donut', h: 180, legendRight: true, thick: 16, centerSub: 'total findings', segments: [
      { label: 'Open', value: 3, color: '#f59e0b' }, { label: 'In progress', value: 1, color: '#3b82f6' }, { label: 'Verified', value: 1, color: '#22d3ee' }, { label: 'Accepted risk', value: 1, color: '#a78bfa' }, { label: 'Closed', value: 1, color: '#10b981' }] })}</div></div>` +
    `<div class="filter-bar"><div class="input-icon">${ic('search')}<input class="input" placeholder="Search findings, assets, IDs..." value="${S.findQ}" data-input="findQ"></div>
    <div class="chips">${['all', 'critical', 'high', 'medium', 'low'].map(s => `<button class="chip ${S.findSev === s ? 'on' : ''}" data-act="set" data-a="findSev" data-b="${s}">${s === 'all' ? 'All severities' : s}</button>`).join('')}</div><button class="btn sm" data-act="saveView" title="Save this filter to the sidebar">${ic('filter', 'sm')}Save view</button></div>
    <div class="card pad0">${table(['ID', 'Finding', 'Severity', 'Asset', 'Technique', 'Owner', 'Status', 'Age'], rows.map(f => `<tr data-act="openFinding" data-a="${f.id}"><td class="mono muted">${f.id}</td><td><div>${f.title}</div><div class="muted" style="font-size:11.5px">${f.scenario}</div></td><td>${sev(f.sev)}</td><td class="mono">${f.asset}</td><td class="mono">${f.tech}</td><td class="muted">${f.owner}</td><td>${st(f.status)}</td><td class="muted">${f.age}</td></tr>`))}</div>`;
};

P.iocs = () => pageHead('IOC Registry', 'Indicators of compromise from threat intel, scenario artefacts and validation runs.', `<button class="btn" data-act="importIoc">${ic('upload')}Import Indicators</button><button class="btn primary" data-act="toast" data-a="Indicator added">${ic('plus')}Add IOC</button>`, D.IOCS.length) +
  `<div class="card pad0">${table(['Indicator', 'Type', 'Source', 'Confidence', 'Action', 'Last seen'], D.IOCS.map(i => `<tr class="noclick"><td class="mono">${i.value}</td><td>${tag(i.type, 'gray')}</td><td class="muted">${i.source}</td><td style="min-width:140px"><div class="row"><div class="grow">${bar(i.conf, i.conf > 85 ? 'green' : 'amber')}</div><span class="mono muted">${i.conf}</span></div></td><td>${tag(i.action, i.action === 'Block' ? 'red' : i.action === 'Alert' ? 'amber' : 'gray')}</td><td class="muted">${i.seen} ago</td></tr>`))}</div>`;

P.remediation = () => pageHead('Remediation', 'Track fixes from detection through verification.', `<button class="btn primary" data-act="remNew">${ic('plus')}New item</button>`, D.REMED.cards.length) +
  `<div class="kanban">${D.REMED.cols.map(([label, c, key]) => `<div class="kcol"><h4><span class="dot" style="background:var(--${c});box-shadow:none"></span>${label}<span class="cnt" style="margin-left:auto">${D.REMED.cards.filter(x => x.col === key).length}</span></h4>
   ${D.REMED.cards.filter(x => x.col === key).map(x => `<div class="kcard" data-act="openRem" data-a="${x.id}"><div class="row between" style="margin-bottom:6px">${sev(x.sev)}<span class="mono muted" style="font-size:11px">${x.id}</span></div><div style="font-weight:500;line-height:1.3">${x.title}</div><div class="row mt" style="margin-top:10px;font-size:11.5px;color:var(--muted)"><span class="mono">${x.asset}</span><span style="margin-left:auto">Due ${x.due}</span></div></div>`).join('')}</div>`).join('')}</div>`;

P.reports = () => {
  const tab = curTab('reports', [['reports', 'Reports'], ['compliance', 'Compliance report'], ['sla', 'SLA compliance']]);
  const head = pageHead('Reports', 'Generate, review and share validation and compliance reports.', `<button class="btn primary" data-act="genReport">${ic('plus')}Generate report</button>`);
  let body = '';
  if (tab === 'reports') body = `<div class="card pad0">${table(['Report', 'Type', 'Period', 'Created', 'By', 'Format', ''], D.REPORTS.map(r => `<tr class="noclick"><td><div>${r.name}</div><div class="mono muted" style="font-size:11px">${r.id}</div></td><td>${tag(r.type, 'blue')}</td><td class="muted">${r.period}</td><td>${r.created}</td><td class="muted">${r.by}</td><td>${tag(r.fmt, 'gray')}</td><td class="num"><div class="row" style="justify-content:flex-end"><button class="btn sm ghost" data-act="previewRpt" data-a="${r.id}">${ic('eye', 'sm')}Preview</button><button class="btn sm" data-act="downloadRpt" data-a="${r.id}">${ic('download', 'sm')}Download</button></div></td></tr>`))}</div>`;
  if (tab === 'compliance') body = `<div class="grid g3">${[['PCI-DSS v4.0', 86, 'green', '12 of 14 requirements evidenced'], ['ISO 27001:2022', 79, 'amber', '3 controls with gaps'], ['NIST CSF 2.0', 83, 'green', 'Detect function strongest'], ['SOC 2 (CC7)', 71, 'amber', 'Logging evidence incomplete']].map(([n, v, c, d]) => `<div class="card"><div class="row between"><h2>${n}</h2><span class="mono">${v}%</span></div><div class="mt" style="margin:10px 0">${bar(v, c)}</div><p class="muted" style="font-size:12.5px">${d}</p><div class="row mt" style="margin-top:12px"><button class="btn sm" data-act="genReport">Generate evidence pack</button></div></div>`).join('')}</div>`;
  if (tab === 'sla') body = `<div class="grid g4 mb">${kpi('SLA compliance', '91%', 'Target 95%', 'clock', '--amber', 'var(--amber)')}${kpi('Median time to remediate', '11 d', '▼ 2 d', 'wrench', '--cyan')}${kpi('Breaches (30d)', '4', '▼ 3', 'alert', '--red', 'var(--green)')}${kpi('Accepted risks', '6', 'Expire in 30 d: 2', 'shield', '--purple', 'var(--amber)')}</div>
    <div class="grid g2"><div class="card"><h2 class="mb">By Severity</h2>${[['Critical (≤7 d)', 100, 'green', '2/2'], ['High (≤30 d)', 88, '', '14/16'], ['Medium (≤90 d)', 96, 'green', '23/24'], ['Low (≤180 d)', 100, 'green', '8/8']].map(([n, v, c, r]) => `<div class="hbar-row"><span>${n}</span>${bar(v, c)}<span class="v">${r}</span></div>`).join('')}</div>
    <div class="card"><h2 class="mb">Monthly Trend</h2>${lineChart([84, 86, 85, 88, 90, 89, 91, 92, 90, 93, 91, 91], ['May','Jun','Jul','Aug','Sep','Oct','Nov','Dec','Jan','Feb','Mar','Apr'], '#22d3ee')}</div></div>
    <div class="card pad0 mt"><div class="card-hd" style="padding:14px 16px 0"><h2>Recently Resolved</h2></div>${table(['Finding', 'Severity', 'Resolved', 'Verified by'], D.FINDINGS.filter(f => f.status === 'Closed' || f.status === 'Verified').map(f => `<tr class="noclick"><td>${f.title}</td><td>${sev(f.sev)}</td><td class="muted">22 Oct 2026</td><td class="muted">Validation run</td></tr>`))}</div>`;
  return head + tabs('reports', [['reports', 'Reports', D.REPORTS.length], ['compliance', 'Compliance report'], ['sla', 'SLA compliance']]) + body;
};

P.verification = () => pageHead('Detection Verification', 'Confirms whether detections fired as expected for each validated step.', `<button class="btn primary" data-act="rerunReview">${ic('refresh')}Re-run review</button>`, D.VERIFY.length) +
  `<div class="grid g4 mb">${kpi('Checks (7d)', '7', 'Last batch 24 Oct', 'check', '--accent')}${kpi('Detected', '4', '57%', 'shield', '--green')}${kpi('Partial', '1', '', 'alert', '--amber')}${kpi('Missed', '2', 'Needs tuning', 'alert', '--red', 'var(--red)')}</div>` +
  `<div class="card pad0">${table(['ID', 'Detection', 'Scenario', 'Expected', 'Observed', 'Result', 'Checked', ''], D.VERIFY.map(v => `<tr class="noclick"><td class="mono muted">${v.id}</td><td>${v.detection}</td><td class="muted">${v.scenario}</td><td>${v.expected}</td><td>${v.seen}</td><td>${st(v.result)}</td><td class="muted">${v.checked}</td><td class="num"><button class="btn sm ghost" data-act="rerunReview" data-a="${v.id}">${ic('refresh', 'sm')}</button></td></tr>`))}</div>`;

P.attackpath = () => {
  const p = D.ATTACK_PATHS.find(x => x.id === S.apSel) || D.ATTACK_PATHS[0];
  return pageHead('Attack Path Validation', 'Chained techniques validated end-to-end across identity, endpoint and cloud.', `<button class="btn primary" data-act="toast" data-a="Path validation started" data-b="${p.name}">${ic('play')}Validate path</button>`, D.ATTACK_PATHS.length) +
    `<div class="split split-300">
    <div class="col">${D.ATTACK_PATHS.map(x => `<div class="card" style="cursor:pointer;${x.id === p.id ? 'border-color:var(--accent)' : ''}" data-act="set" data-a="apSel" data-b="${x.id}"><div class="row between">${sev(x.risk.toLowerCase())}${x.validated ? tag('Validated', 'green') : tag('Modelled', 'gray')}</div><div style="font-weight:600;margin:8px 0 4px">${x.name}</div><div class="muted" style="font-size:12px">${x.steps} hops · ${x.id}</div></div>`).join('')}</div>
    <div class="col"><div class="card"><div class="card-hd"><h2>${p.name}</h2><div class="actions">${sev(p.risk.toLowerCase())}</div></div>
      <div class="graph" style="height:auto;padding:24px 18px;background:none;border:0;display:flex;flex-direction:column;gap:10px;align-items:stretch">
      ${p.hops.map((h, i) => `<div class="row" style="gap:12px"><div class="gnode" style="position:static;transform:none;min-width:0;width:44px;height:44px;display:grid;place-items:center;border-radius:50%;padding:0;flex:none;border-color:${i === p.hops.length - 1 ? 'var(--red)' : 'var(--accent)'}">${i + 1}</div><div class="card" style="flex:1;padding:12px 14px"><div style="font-weight:500">${h}</div><div class="muted mono" style="font-size:11px">${['Initial access', 'Execution', 'Credential access', 'Impact / objective'][Math.min(i, 3)]} · ${i === 0 ? 'T1566' : i === 1 ? 'T1059' : i === 2 ? 'T1003' : 'T1078'}</div></div>${i < p.hops.length - 1 ? '' : ''}</div>${i < p.hops.length - 1 ? `<div style="margin-left:21px;width:2px;height:12px;background:var(--border-hi);margin-top:-10px;margin-bottom:-10px"></div>` : ''}`).join('')}
      </div></div>
      <div class="grid g2"><div class="card"><h2 class="mb">Validation</h2><dl class="kv" style="grid-template-columns:120px 1fr"><dt>Status</dt><dd>${p.validated ? st('Passed') : st('Pending')}</dd><dt>Last run</dt><dd>22 Oct 2026</dd><dt>Blocking control</dt><dd>${p.validated ? 'None — path reached objective' : 'Not yet tested'}</dd></dl></div>
      <div class="card"><h2 class="mb">Recommended fix</h2><p class="muted" style="font-size:12.5px">Remediate hop ${p.hops.length - 1} first: restrict the ${p.id === 'AP-14' ? 'ADCS UserAuth template' : 'service account scope'}, then re-validate.</p><div class="row mt" style="margin-top:12px"><button class="btn sm" data-act="nav" data-a="recommendations">View recommendation</button></div></div></div>
    </div></div>`;
};

P.exposure = () => pageHead('Exposure Explorer', 'Internet-facing and internal assets with exposure and vulnerability context.', `<button class="btn" data-act="toast" data-a="Exposure scan queued">${ic('refresh')}Rescan</button>`, D.EXPOSURE.length) +
  `<div class="filter-bar">${['All', 'Internet-facing', 'Internal', 'Cloud'].map((c, i) => `<button class="chip ${i === 0 ? 'on' : ''}" data-act="toast" data-a="Filter applied" data-b="${c}">${c}</button>`).join('')}</div>` +
  `<div class="card pad0">${table(['Asset', 'Exposure', 'Open ports', 'Vulns', 'Critical', 'Owner', 'Tag'], D.EXPOSURE.map(e => `<tr data-act="toast" data-a="${e.asset}" data-b="Asset detail"><td class="mono">${e.asset}</td><td>${tag(e.type, e.type.startsWith('Internet') ? 'red' : 'gray')}</td><td class="mono muted">${e.ports}</td><td>${e.vulns}</td><td>${e.crit ? `<span class="sev critical">${e.crit}</span>` : '0'}</td><td class="muted">${e.owner}</td><td>${tag(e.tag, 'blue')}</td></tr>`))}</div>`;

P.recommendations = () => pageHead('Recommendations', 'Prioritised fixes ranked by validated impact and effort.', '', D.RECS.length) +
  `<div class="grid g2">${D.RECS.map((r, i) => `<div class="card"><div class="row between">${tag(r.priority, r.priority === 'P1' ? 'red' : r.priority === 'P2' ? 'amber' : 'gray')}<span class="muted" style="font-size:12px">From ${r.from}</span></div><h2 style="margin:10px 0 6px;font-size:14.5px">${r.title}</h2><p class="muted" style="font-size:12.5px">${r.impact}</p><div class="row mt" style="margin-top:12px"><span class="tag">Effort: ${r.effort}</span><button class="btn sm primary" style="margin-left:auto" data-act="applyRec" data-a="${i}">Create remediation</button></div></div>`).join('')}</div>`;

P.exercises = () => pageHead('Exercises', 'Tabletop, purple-team and live-fire exercises with outcomes.', `<button class="btn primary" data-act="toast" data-a="Exercise draft created">${ic('plus')}New Exercise</button>`, D.EXERCISES.length) +
  `<div class="card pad0">${table(['Exercise', 'Date', 'Participants', 'Status', 'Outcome'], D.EXERCISES.map(e => `<tr data-act="toast" data-a="${e.name}" data-b="Exercise report"><td>${e.name}</td><td>${e.date}</td><td>${e.participants}</td><td>${st(e.status)}</td><td>${e.outcome}</td></tr>`))}</div>`;

P['attack-coverage'] = () => {
  const rows = D.TECH_ROWS.filter(t => !S.tac || t.tac === S.tac);
  return pageHead('Technique Coverage', 'Per-technique detection scores with test history.', `<button class="btn primary" data-act="toast" data-a="Tests queued" data-b="${rows.length} techniques">${ic('play')}Run tests</button>`, D.TECH_ROWS.length) +
    `<div class="filter-bar"><select class="select" data-change="setSel" data-a="tac"><option value="">All tactics</option>${[...new Set(D.TECH_ROWS.map(t => t.tac))].map(t => `<option ${S.tac === t ? 'selected' : ''}>${t}</option>`).join('')}</select></div>` +
    `<div class="card pad0">${table(['Technique', 'Tactic', 'Coverage', 'Tests', 'Last result'], rows.map(t => `<tr data-act="techDetail" data-a="${t.id}"><td><div>${t.name}</div><div class="mono muted" style="font-size:11px">${t.id}</div></td><td class="muted">${t.tac}</td><td style="min-width:180px"><div class="row"><div class="grow">${bar(t.cov, t.cov > 75 ? 'green' : t.cov > 50 ? 'amber' : 'red')}</div><span class="mono muted">${t.cov}%</span></div></td><td>${t.tests}</td><td>${st(t.last)}</td></tr>`))}</div>`;
};

P['threat-priority'] = () => pageHead('Threat Prioritization', 'Threat actors ranked by relevance to your estate and validated gaps.', `<button class="btn" data-act="toast" data-a="Model refreshed">${ic('refresh')}Refresh model</button>`, D.THREATS.length) +
  `<div class="grid g2">${D.THREATS.map((t, i) => `<div class="card" style="display:flex;gap:16px;align-items:center"><div class="gauge" style="width:92px;height:92px;margin:0;flex:none"><svg viewBox="0 0 150 150" width="92" height="92" class="progress-ring"><circle cx="75" cy="75" r="62" fill="none" class="track" stroke-width="14"/><circle cx="75" cy="75" r="62" fill="none" stroke="${t.score > 85 ? '#ef4444' : t.score > 70 ? '#f59e0b' : '#3b82f6'}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${t.score / 100 * 389.5} 389.5"/></svg><div class="gv"><b style="font-size:22px">${t.score}</b></div></div><div class="grow"><div class="row between"><h2>#${i + 1} ${t.name}</h2></div><p class="muted mt" style="margin:6px 0 10px;font-size:12.5px">${t.why}</p><div class="row" style="gap:8px">${tag(t.mapped + ' techniques mapped', 'blue')}${tag(t.gaps + ' validated gaps', 'red')}</div></div></div>`).join('')}</div>`;

// ----- Infrastructure -----
const agentRows = (list) => table(['Host', 'Group', 'OS', 'Status', 'Version', 'Last seen', 'Risk', ''], list.map(a => `<tr data-act="agentMenu" data-a="${a.id}"><td><div class="mono">${a.host}</div><div class="muted" style="font-size:11px">${a.ip} · ${a.id}</div></td><td>${a.group}</td><td class="muted">${a.os}</td><td>${st(a.status)}</td><td class="mono">${a.version}</td><td class="muted">${a.lastSeen}</td><td>${a.risk === 'High' ? sev('high') : a.risk === 'Medium' ? sev('medium') : a.risk === 'Low' ? sev('low') : '—'}</td><td class="num"><button class="btn sm ghost" data-act="agentMenu" data-a="${a.id}">${ic('chev', 'sm')}</button></td></tr>`));
P.agents = () => {
  const list = D.AGENTS.filter(a => S.agSel === 'All agents' || a.group === S.agSel);
  const t = curTab('agents', [['overview', 'Overview', list.length], ['scenarios', 'Scenarios'], ['logs', 'Logs'], ['health', 'Health'], ['attackpath', 'Attack Path'], ['risk', 'Risk']]);
  let body = '';
  if (t === 'overview') body = `<div class="card pad0">${agentRows(list)}</div>`;
  if (t === 'scenarios') body = `<div class="card pad0">${table(['Scenario', 'Assigned to', 'Schedule', 'Last result'], [['ACL Privilege Exposure Audit', 'Domain Controllers', 'Weekly', 'PASS'], ['Akira Kill Chain', 'File Servers', 'Manual', 'NEVER'], ['Linux Persistence & Cron', 'Linux Web Tier', 'Daily', 'FAIL']].map(r => `<tr class="noclick"><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td>${st(r[3])}</td></tr>`))}</div>`;
  if (t === 'logs') body = `<div class="log">${['<span class="inf">[14:20:11]</span> agent.heartbeat ok AG-1042', '<span class="ok">[14:20:09]</span> task RUN-5521/T1087 started', '<span class="wrn">[14:18:44]</span> slow DNS resolve (1.9s) DC-PRI-01', '<span class="err">[12:10:03]</span> AG-1302 heartbeat missed (3 retries)', '<span class="ok">[11:04:52]</span> scenario SC-0412 completed · 1 finding', '<span class="inf">[10:58:31]</span> config pushed v37 · 2 keys changed'].map(l => `<div>${l}</div>`).join('')}</div>`;
  if (t === 'health') body = `<div class="grid g3">${[['CPU', 18], ['Memory', 47], ['Disk', 62], ['Heartbeat latency', 22], ['Queue', 9], ['Log lag', 4]].map(([n, v], k) => `<div class="card"><div class="row between"><span class="muted">${n}</span><span class="mono">${v}${n === 'Heartbeat latency' ? ' ms' : n === 'Queue' || n === 'Log lag' ? '' : '%'}</span></div><div style="margin-top:10px">${chartSlot({ type: 'spark', data: wave(24, v * 0.75, v, v * 0.15, k + 1), color: v > 60 ? '#f59e0b' : '#10b981', h: 40 })}</div><div class="muted" style="font-size:11px;margin-top:4px">last 24 h</div></div>`).join('')}</div>`;
  if (t === 'attackpath') body = `<div class="card">${D.ATTACK_PATHS.map(p => `<div class="check-row">${sev(p.risk.toLowerCase())}<div class="grow">${p.name}</div><span class="muted">${p.steps} hops</span></div>`).join('')}</div>`;
  if (t === 'risk') body = `<div class="card">${[['Domain Controllers', 92, 'red'], ['Payments DB', 74, 'amber'], ['Finance Workstations', 48, 'green'], ['Executive Laptops', 31, 'green']].map(([n, v, c]) => `<div class="hbar-row"><span>${n}</span>${bar(v, c)}<span class="v">${v}</span></div>`).join('')}</div>`;
  return pageHead('Simulation agents', 'Endpoints that execute scenarios under policy.', `<button class="btn" data-act="connConfig">${ic('gear')}Connection Config</button><button class="btn primary" data-act="deployAgent">${ic('plus')}Deploy Agent</button>`, D.AGENTS.length) +
    `<div class="split split-240">
      <div class="card" style="padding:10px"><h4 style="padding:4px 8px 8px">Groups</h4>${D.AGENT_GROUPS.map(([n, c]) => `<div class="tree-item ${S.agSel === n ? 'on' : ''}" data-act="setAgGroup" data-a="${n}">${ic(n === 'All agents' ? 'layers' : 'server', 'sm')}<span>${n}</span><span class="n">${c}</span></div>`).join('')}<div class="mt" style="margin-top:10px"><button class="btn sm block" data-act="toast" data-a="Group created">${ic('plus', 'sm')}New group</button></div></div>
      <div class="col">${tabs('agents', [['overview', 'Overview', list.length], ['scenarios', 'Scenarios'], ['logs', 'Logs'], ['health', 'Health'], ['attackpath', 'Attack Path'], ['risk', 'Risk']])}${body}</div></div>`;
};

P.integrations = () => pageHead('Integrations', 'Connect security tooling, threat intel and response platforms.', `<button class="btn primary" data-act="addTaxii">${ic('plus')}Add TAXII connector</button>`, D.INTEGRATIONS.length) +
  `<div class="grid g3">${D.INTEGRATIONS.map(i => `<div class="card"><div class="row between"><div class="brand-mark" style="width:34px;height:34px;border-radius:9px;background:var(--elevated);color:var(--accent-hi);box-shadow:none">${ic(i.kind === 'Cloud' ? 'cloud' : i.kind === 'EDR' ? 'shield' : i.kind === 'SIEM' ? 'dash' : i.kind === 'Email' ? 'mail' : i.kind === 'DLP' ? 'lock' : i.kind === 'Threat intel' ? 'hash' : 'plug')}</div>${st(i.state)}</div><h2 style="margin:12px 0 4px;font-size:14px">${i.name}</h2><div class="muted" style="font-size:12px">${i.kind} · last sync ${i.last}</div><p class="muted mt" style="margin-top:8px;font-size:12px">${i.detail}</p><div class="row mt" style="margin-top:12px"><button class="btn sm" data-act="toast" data-a="Connection test passed" data-b="${i.name}">Test</button><button class="btn sm ghost" data-act="toast" data-a="Settings opened" data-b="${i.name}">Configure</button></div></div>`).join('')}</div>
  <div class="card pad0 mt"><div class="card-hd" style="padding:14px 16px 0"><h2>TAXII Connectors</h2></div>${table(['Name', 'Endpoint', 'Status', 'Last poll'], D.TAXII.map(t => `<tr class="noclick"><td>${t.name}</td><td class="mono muted">${t.url}</td><td>${st(t.status)}</td><td class="muted">${t.last}</td></tr>`))}</div>
  <div class="card pad0 mt"><div class="card-hd" style="padding:14px 16px 0"><h2>EPP Response Connectors</h2><div class="actions"><button class="btn sm" data-act="responseAction">${ic('bolt', 'sm')}Response Action</button></div></div>${table(['Connector', 'Action', 'Target', 'Status'], D.EPP.map(e => `<tr class="noclick"><td>${e.name}</td><td>${tag(e.action, 'gray')}</td><td class="muted">${e.target}</td><td>${st(e.status)}</td></tr>`))}</div>`;

// ----- Settings -----
const SETTINGS = [['users', 'Users & roles', 'key'], ['caldera', 'Caldera Engine', 'bolt'], ['intel', 'Threat Intel Connector', 'hash'], ['taxii', 'TAXII Connectors', 'plug'], ['art', 'ART Content Library', 'book'], ['audit', 'Audit Logs', 'file'], ['theme', 'Theme & Display', 'sun'], ['dashprefs', 'Dashboard Preferences', 'dash'], ['license', 'License', 'shield'], ['backup', 'Backup & Recovery', 'archive']];
P.settings = () => {
  const t = S.sttab;
  let b = '';
  if (t === 'users') b = `<div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Users &amp; roles <span class="cnt">${D.USERS.length}</span></h2><div class="actions"><button class="btn sm primary" data-act="toast" data-a="Invitation sent" data-b="Role: Operator">${ic('plus', 'sm')}Invite user</button></div></div>${table(['Name', 'Email', 'Role', 'MFA', 'Last active', ''], D.USERS.map(u => `<tr class="noclick"><td><div class="row"><span class="avatar avatar-sm">${u.name[0]}</span>${u.name}</div></td><td class="muted">${u.email}</td><td>${tag(u.role, u.role === 'Owner' ? 'purple' : 'blue')}</td><td>${u.mfa ? st('Enabled') : st('Off')}</td><td class="muted">${u.last}</td><td class="num"><button class="btn sm ghost" data-act="toast" data-a="Role editor" data-b="${u.name}">${ic('edit', 'sm')}</button></td></tr>`))}</div>`;
  if (t === 'caldera') b = `<div class="grid g2"><div class="card"><div class="row between"><h2>Caldera Engine</h2>${st('Connected')}</div><dl class="kv mt" style="margin-top:14px"><dt>Version</dt><dd>5.2.0 (bundled)</dd><dt>Endpoint</dt><dd class="mono">https://127.0.0.1:8888</dd><dt>Abilities loaded</dt><dd>1,204</dd><dt>Adversary profiles</dt><dd>38</dd></dl><div class="row mt" style="margin-top:14px"><button class="btn sm" data-act="toast" data-a="Engine restarted">${ic('refresh', 'sm')}Restart engine</button></div></div>
    <div class="card"><h2 class="mb">Engine options</h2>${[['Allow plugin: emu', true], ['Auto-clean up after runs', true], ['Record full command output', false]].map(([n, v]) => `<div class="check-row"><span class="grow">${n}</span><button class="switch ${v ? 'on' : ''}" data-act="toggle"></button></div>`).join('')}</div></div>`;
  if (t === 'intel') b = `<div class="card" style="max-width:720px"><h2 class="mb">Threat Intel Connector</h2><div class="field"><label>OTX API key</label><input class="input" value="••••••••••••••••••••4f1a" readonly></div><div class="field"><label>Pulse subscriptions</label><textarea class="input">APT29 tradecraft\nAkira ransomware\nFinance sector watch</textarea></div><div class="row"><button class="btn primary" data-act="toast" data-a="Connection OK" data-b="18 feeds reachable">Test connection</button><button class="btn" data-act="toast" data-a="Settings saved">Save</button></div></div>`;
  if (t === 'taxii') b = `<div class="card pad0">${table(['Name', 'Endpoint', 'Status', 'Last poll'], D.TAXII.map(x => `<tr class="noclick"><td>${x.name}</td><td class="mono muted">${x.url}</td><td>${st(x.status)}</td><td class="muted">${x.last}</td></tr>`))}</div>`;
  if (t === 'art') b = `<div class="card"><div class="card-hd"><h2>ART Content Library</h2><div class="actions"><input class="input" placeholder="Search atomics…" style="width:240px"></div></div>${table(['Atomic test', 'Technique', 'Platforms', 'Status'], [['Scheduled task via schtasks', 'T1053.005', 'Windows', 'Enabled'], ['Registry Run key persistence', 'T1547.001', 'Windows', 'Enabled'], ['LaunchAgent persistence', 'T1543.001', 'macOS', 'Enabled'], ['Cron job persistence', 'T1053.003', 'Linux', 'Disabled']].map(r => `<tr class="noclick"><td>${r[0]}</td><td class="mono">${r[1]}</td><td>${r[2]}</td><td>${st(r[3] === 'Enabled' ? 'Active' : 'Off')}</td></tr>`))}</div>`;
  if (t === 'audit') b = `<div class="card pad0">${table(['Time', 'Actor', 'Action', 'Detail', 'Result'], D.AUDIT.map(a => `<tr class="noclick"><td class="mono muted">${a[0]}</td><td>${a[1]}</td><td class="mono">${a[2]}</td><td>${a[3]}</td><td>${st(a[4] === 'ok' ? 'Passed' : a[4] === 'warn' ? 'Warning' : 'Failed')}</td></tr>`))}</div>`;
  if (t === 'theme') b = `<div class="card" style="max-width:720px"><h2 class="mb">Theme &amp; Display Preferences</h2><div class="grid g2 mb">${[['dark', 'Dark', 'Navy console, built for SOC rooms'], ['light', 'Light', 'High-contrast for daylight offices']].map(([v, n, d]) => `<div class="radio-card ${SHELL.theme === v ? 'on' : ''}" data-sh="theme" data-v="${v}" role="radio" aria-checked="${SHELL.theme === v}" tabindex="0"><div><b>${n}</b><span>${d}</span></div></div>`).join('')}</div>
    <div class="check-row"><div class="grow"><b>Compact density</b><div class="muted" style="font-size:12px">Tighter tables, cards and navigation — more rows on screen</div></div><button class="switch ${SHELL.compact ? 'on' : ''}" data-sh="compact"></button></div>
    <div class="check-row"><div class="grow"><b>Reduce motion</b><div class="muted" style="font-size:12px">Turns off page transitions and animated charts</div></div><button class="switch ${SHELL.reduce ? 'on' : ''}" data-sh="reduce"></button></div>
    <div class="check-row"><div class="grow"><b>Accent colour</b><div class="muted" style="font-size:12px">Used for primary actions, links and highlights</div></div><div class="row">${[['#3b82f6', 'Blue'], ['#22d3ee', 'Cyan'], ['#10b981', 'Green'], ['#a78bfa', 'Violet'], ['#ff007f', 'Magenta']].map(([c, n]) => `<button class="swatch ${SHELL.accent === c || (!SHELL.accent && c === '#3b82f6') ? 'on' : ''}" data-act="accent" data-a="${c}" style="background:${c}" title="${n}" aria-label="${n} accent"></button>`).join('')}</div></div></div>`;
  if (t === 'dashprefs') b = `<div class="card" style="max-width:720px"><h2 class="mb">Dashboard Preferences</h2><div class="field"><label>Default view</label>${seg('', 'dashView', [['operational', 'Operational'], ['executive', 'Executive']])}</div>${['Detection rate trend', 'Recent validation runs', 'Top coverage gaps', 'Agent health by group', 'Recent alerts'].map(w => `<div class="check-row"><span class="grow">${w}</span><button class="switch on" data-act="toggle"></button></div>`).join('')}</div>`;
  if (t === 'license') b = `<div class="card" style="max-width:720px"><div class="row between"><h2>License</h2>${st('Active')}</div><dl class="kv mt" style="margin-top:14px"><dt>Customer</dt><dd>Acme Bank (demo)</dd><dt>Edition</dt><dd>Enterprise · On-Premise</dd><dt>Add-ons</dt><dd>${tag('Cloud BAS', 'blue')} ${tag('WAF', 'blue')} ${tag('DLP', 'blue')}</dd><dt>Expires</dt><dd>30 Jun 2027</dd></dl></div>`;
  if (t === 'backup') b = `<div class="card" style="max-width:720px"><div class="row between"><h2>Backup &amp; Recovery</h2>${st('Healthy')}</div><dl class="kv mt" style="margin-top:14px"><dt>Last backup</dt><dd>24 Oct 2026 02:00 · 2.4 GB</dd><dt>Schedule</dt><dd>Nightly · retained 14 days</dd><dt>CA key material</dt><dd>${tag('Included', 'green')}</dd></dl><div class="row mt" style="margin-top:16px"><button class="btn primary" data-act="backupNow">${ic('archive')}Back up now</button><button class="btn" data-act="toast" data-a="Restore wizard" data-b="Select a backup set first">${ic('refresh')}Restore…</button></div></div>`;
  return pageHead('Settings', 'Platform configuration, identity, integrations and maintenance.', '') +
    `<div class="split split-240"><div class="card" style="padding:10px">${SETTINGS.map(([id, l, i]) => `<div class="tree-item ${t === id ? 'on' : ''}" data-act="sttab" data-a="${id}">${ic(i, 'sm')}<span>${l}</span></div>`).join('')}</div><div>${b}</div></div>`;
};

P.profile = () => pageHead('My Profile', 'Your account, sign-in and preferences.', '<button class="btn primary" data-act="toast" data-a="Profile saved">Save changes</button>') +
  `<div class="grid g-side"><div class="card"><div class="row"><span class="avatar" style="width:56px;height:56px;font-size:20px">A</span><div><h2>Admin</h2><div class="muted">admin@acme-bank.demo · Owner</div></div></div><dl class="kv mt" style="margin-top:16px"><dt>Last sign-in</dt><dd>Today 08:12 from 10.20.1.10</dd><dt>Time zone</dt><dd>Europe/London</dd></dl></div>
  <div class="card"><h2 class="mb">Security</h2>${[['Two-factor authentication', true], ['Notify on critical findings', true], ['Notify on failed runs', false]].map(([n, v]) => `<div class="check-row"><span class="grow">${n}</span><button class="switch ${v ? 'on' : ''}" data-act="toggle"></button></div>`).join('')}<div class="row mt" style="margin-top:14px"><button class="btn" data-act="toast" data-a="Password change email sent">Change password</button></div></div></div>`;

// Route ids in the nav differ from the render function names for these three pages.
P['k8s-scenarios'] = P.k8s;
P['scheduled-assessments'] = P.scheduled;
P['factory-health'] = P.factory;

// ---------- Modals & drawers ----------
const A = {};
A.toast = d => toast(d.a, d.b, d.c || '');
A.nav = d => go(d.a);
A.set = d => { S[d.a] = d.b; S.keepScroll = true; render(); };
A.setSel = (d, el) => { S[d.a] = el.value; S.keepScroll = true; render(); };
A.setCat = d => { S.cat = d.a; S.keepScroll = true; render(); };
A.selSc = d => { S.scSel = d.a; render(); };
A.refreshScen = () => { toast('Catalogue refreshed', 'Signatures verified for 107 scenarios'); };
A.toggle = (d, el) => { el.classList.toggle('on'); el.setAttribute('aria-checked', el.classList.contains('on')); };
A.accent = d => { shellSetAccent(d.a); render(); toast('Accent updated', 'Applied across the console'); };
A.clearFilters = () => { S.scQ = ''; S.fSrc = ''; S.fOS = ''; S.fProd = ''; S.fTier = ''; S.cat = 'all'; render(); };
A.closeModal = () => closeModal();
A.closeDrawer = () => closeDrawer();
A.tab = d => { S.tab = S.tab || {}; S.tab[d.a] = d.b; S.keepScroll = true; render(); };
A.sttab = d => { S.sttab = d.a; render(); };
A.setAgGroup = d => { S.agSel = d.a; render(); };
A.scQ = () => {};
A.techDetail = d => {
  const t = D.TECH_ROWS.find(x => x.id === d.a) || { id: d.a, name: 'Technique ' + d.a, tac: '—', cov: 62, tests: 3, last: 'WARN' };
  drawer(dhd(t.name, t.id, 'mapped') + `<div class="drawer-bd"><div class="grid g3 mb">${kpi('Coverage', t.cov + '%', '', 'shield', '--green')}${kpi('Tests', t.tests, '', 'play', '--accent')}${kpi('Last result', t.last, '', 'check', '--amber')}</div><dl class="kv"><dt>Tactic</dt><dd>${t.tac}</dd><dt>Linked scenarios</dt><dd>APT29 Phase 7, Atomic macOS Sweep</dd><dt>Detections</dt><dd>EDR · SIEM (2 rules)</dd></dl><h4 class="mt" style="margin-top:18px">Recent test history</h4><div class="col mt">${['24 Oct · PASS · EDR alert in 4 s', '20 Oct · WARN · alert after 3 min', '14 Oct · PASS · blocked'].map(x => `<div class="check-row"><span class="grow">${x}</span></div>`).join('')}</div></div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button><button class="btn primary" data-act="runScModal" data-a="SC-0355">${ic('play')}Run a test</button></div>`);
};
A.pickTech = () => modal(mhd('Select techniques', 'mapped') + `<div class="modal-bd"><div class="input-icon mb">${ic('search')}<input class="input" style="width:100%" placeholder="Filter techniques…"></div>${D.TECH_ROWS.map((t, i) => `<label class="check-row" style="cursor:pointer"><input type="checkbox" class="check" ${i < 4 ? 'checked' : ''}><span class="mono" style="width:100px">${t.id}</span><span class="grow">${t.name}</span><span class="muted">${t.tac}</span></label>`).join('')}</div><div class="modal-ft"><span class="left">4 selected</span><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Coverage view filtered" data-b="4 techniques">Apply</button></div>`, 'lg');
A.openRun = d => {
  const r = D.RUNS.find(x => x.id === d.a); if (!r) return;
  S.liveRun = r.id;
  const steps = r.id === 'RUN-5521' ? D.STEPS_APT29 : [['Preflight checks', 'done', 'Agent reachable, elevation OK'], ['Execute scenario steps', r.status === 'Queued' ? 'wait' : r.status === 'Failed' ? 'fail' : r.status === 'Passed' ? 'done' : 'run', r.step], ['Cleanup & evidence', r.status === 'Passed' ? 'done' : 'wait', 'Artefacts collected']];
  drawer(dhd(r.name, `${r.id} · ${r.target}`, 'play') + `<div class="drawer-bd">
    <div class="row between mb"><div>${st(r.status)}</div><div class="row"><button class="btn sm" data-act="toast" data-a="Run paused">${ic('pause', 'sm')}Pause</button><button class="btn sm danger" data-act="stopRun" data-a="${r.id}">${ic('stop', 'sm')}Stop</button></div></div>
    <div class="bar thick mb"><i id="ld-bar" style="width:${r.progress}%"></i></div>
    <div class="grid g2 mb" style="gap:10px"><div class="card" style="padding:12px"><div class="muted" style="font-size:11px">Started</div><b>${r.started}</b></div><div class="card" style="padding:12px"><div class="muted" style="font-size:11px">Duration</div><b id="ld-dur">${r.dur}</b></div></div>
    <h4 class="mb">Execution timeline</h4><div class="timeline" id="ld-steps">${steps.map(([t, s, d]) => `<div class="tl-step ${s}"><div class="tl-dot">${s === 'done' ? '✓' : s === 'fail' ? '!' : s === 'run' ? '•' : ''}</div><div><div class="t">${t}</div><div class="d">${d}</div></div></div>`).join('')}</div>
    <h4 class="mt" style="margin-top:16px;margin-bottom:8px">Live log</h4><div class="log"><div class="inf">[${r.started}] run ${r.id} scheduled on ${r.target}</div><div class="ok">[${r.started}] agent accepted task</div><div>[${r.started}] executing step 1/${steps.length}</div></div>${relBlock(RUN_SC[r.id] ? [['target', (D.SCENARIOS.find(s => s.id === RUN_SC[r.id]) || {}).name, 'Scenario ' + RUN_SC[r.id], 'scDetail', RUN_SC[r.id]]] : [])}</div>
    <div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button><button class="btn" data-act="toast" data-a="Report requested">${ic('report')}Report</button></div>`, 'wide');
};
A.stopRun = d => { const r = D.RUNS.find(x => x.id === d.a); if (r && r.status === 'Running') { r.status = 'Failed'; r.step = 'Stopped by operator'; } toast('Run stopped', d.a, 'warn'); render(); };
A.runScModal = d => {
  const s = D.SCENARIOS.find(x => x.id === d.a) || D.SCENARIOS[0];
  modal(mhd('Run Scenario', 'play') + `<div class="modal-bd">
    <div class="row mb" style="margin-bottom:14px"><div class="grow"><b style="font-size:15px">${s.name}</b><div class="muted" style="font-size:12px">${s.id} · ${s.os} · ${s.mins} min · +${s.techniques} techniques</div></div>${st(s.status)}</div>
    ${s.status === 'Draft' ? `<div class="alert warn mb">${ic('alert')}<div>This scenario is still a draft. Runs are limited to the lab group until it is published.</div></div>` : ''}
    <div class="field"><label>Target agent group</label><select class="select" style="width:100%"><option>Finance Workstations (2 online)</option><option>Domain Controllers (2 online)</option><option>File Servers (1 degraded)</option><option>Linux Web Tier (1 online, 1 offline)</option></select></div>
    <div class="field"><label>Run mode</label><div class="grid g2" style="gap:10px"><label class="radio-card on"><input type="radio" name="rm" checked style="accent-color:#3b82f6"><div><b>Execute</b><span>Runs telemetry-safe steps</span></div></label><label class="radio-card"><input type="radio" name="rm" style="accent-color:#3b82f6"><div><b>Dry run</b><span>Plans steps, executes nothing</span></div></label></div></div>
    <div class="field"><label>Start</label><div class="row wrap"><button class="chip on">Now</button><button class="chip">Tonight 23:00</button><button class="chip">Custom…</button></div></div>
    <div class="check-row"><span class="grow">Pause on first detection</span><button class="switch on" data-act="toggle"></button></div>
    <div class="check-row"><span class="grow">Generate HTML report on completion</span><button class="switch on" data-act="toggle"></button></div></div>
    <div class="modal-ft"><span class="left">Est. ${s.mins} min · 1 group</span><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="startRun" data-a="${s.id}">${ic('play')}Start run</button></div>`, 'lg');
};
A.startRun = d => {
  const s = D.SCENARIOS.find(x => x.id === d.a) || D.SCENARIOS[0];
  const id = 'RUN-' + (5522 + D.RUNS.filter(r => r.id.startsWith('RUN-55')).length - 3);
  RUN_SC[id] = s.id;
  D.RUNS.unshift({ id, name: s.name, target: 'Finance Workstations (2)', status: 'Running', progress: 2, step: 'Preflight checks', started: 'just now', dur: '0m 04s' });
  closeModal(); toast('Run started', `${id} · ${s.name}`); go('runs');
};
A.scDetail = d => {
  const s = D.SCENARIOS.find(x => x.id === d.a) || D.SCENARIOS[0];
  const det = D.SCN_DETAIL[s.id] || { overview: s.desc, prereq: ['Windows agent with elevation', 'Telemetry for process and registry events'], steps: s.mins / 6 | 0 || 4 };
  drawer(dhd(s.name, `${s.id} · ${s.source} · ${s.os}`, 'target') + `<div class="drawer-bd">
    <div class="tabs">${['Overview', 'Steps', 'Techniques', 'Requirements', 'History'].map((t, i) => `<button class="${i === 0 ? 'on' : ''}" data-act="scDrawerTab" data-a="${t}">${t}</button>`).join('')}</div>
    <p style="font-size:13.5px;line-height:1.6">${det.overview}</p>
    <dl class="kv mt" style="margin-top:16px"><dt>Author</dt><dd>Audspect Threat Content</dd><dt>Signature</dt><dd>${tag(s.sig, 'green')}</dd><dt>Tiers</dt><dd>${s.tier.join(', ')}</dd><dt>Steps</dt><dd>${det.steps}</dd><dt>Techniques</dt><dd class="mono">${s.tech.join(', ')}</dd></dl>
    <h4 class="mt" style="margin-top:20px">Requirements</h4><ul class="muted" style="margin:8px 0 0 18px;line-height:1.8">${det.prereq.map(p => `<li>${p}</li>`).join('')}</ul>${relBlock([...D.FINDINGS.filter(f => F2S[f.id] === s.id).map(f => ['alert', f.title, `Finding ${f.id} · ${f.sev}`, 'openFinding', f.id]), ...D.RUNS.filter(r => RUN_SC[r.id] === s.id).map(r => ['play', r.id + ' — ' + r.target, r.status, 'openRun', r.id])])}</div>
    <div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button><button class="btn primary" data-act="runScModal" data-a="${s.id}">${ic('play')}Run Scenario</button></div>`, 'wide');
};
A.scDrawerTab = d => toast('Tab: ' + d.a, 'Section content shown in the full build');
A.uploadYaml = () => modal(mhd('Upload YAML', 'upload') + `<div class="modal-bd"><div class="radio-card on" style="flex-direction:column;align-items:center;padding:34px;border-style:dashed;text-align:center">${ic('upload')}<b>Drop a scenario YAML here</b><span>or click to browse · max 2 MB</span></div><div class="alert ok mt" style="margin-top:14px">${ic('check')}<div><b>scenario_akira_v2.yaml</b> parsed: 7 steps, 5 techniques, schema v3 ✓</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Scenario imported as draft">Import as draft</button></div>`, 'lg');
A.newScenario = () => modal(mhd('New Scenario', 'plus') + `<div class="modal-bd"><div class="field"><label>Scenario YAML</label><textarea class="input" style="min-height:260px">${`id: SC-NEW-001
name: Credential Dump via LSASS (lab)
tier: [Core]
platform: windows
techniques: [T1003.001]
steps:
  - name: enumerate_lsass_handle
    technique: T1003.001
    action: telemetry_probe
    cleanup: true`}</textarea></div><div id="val-out"></div></div><div class="modal-ft"><span class="left">Schema v3</span><button class="btn" data-act="closeModal">Cancel</button><button class="btn" data-act="validateYaml">Validate</button><button class="btn primary" data-act="toast" data-a="Draft saved" data-b="SC-NEW-001">Save draft</button></div>`, 'xl');
A.validateYaml = () => { $('#val-out').innerHTML = `<div class="alert ok">${ic('check')}<div>Valid. 1 step, 1 technique, signature will be required before publish.</div></div>`; };
A.schedWiz = () => {
  S.wiz = 1; const draw = () => {
    const n = S.wiz;
    modal(mhd('New Scheduled Assessment', 'clock') + `<div class="modal-bd"><div class="steps">${['Scope', 'Schedule', 'Review'].map((l, i) => `<div class="st ${n === i + 1 ? 'on' : n > i + 1 ? 'done' : ''}"><b>${n > i + 1 ? '✓' : i + 1}</b>${l}</div>${i < 2 ? '<div class="sep"></div>' : ''}`).join('')}</div>
      ${n === 1 ? `<div class="field"><label>Name</label><input class="input" value="Weekly Finance Regression"></div><div class="field"><label>Scenarios</label><div class="chips">${['ACL Privilege Exposure Audit', 'Application Control Efficacy', 'Lateral SMB Movement Baseline'].map((x, i) => `<span class="chip ${i < 2 ? 'on' : ''}">${x}</span>`).join('')}</div></div><div class="field"><label>Agent group</label><select class="select"><option>Finance Workstations</option><option>Domain Controllers</option></select></div>` : ''}
      ${n === 2 ? `<div class="grid g2 mb" style="gap:10px"><label class="radio-card on"><div><b>Weekly</b><span>Mon 02:00</span></div></label><label class="radio-card"><div><b>Monthly</b><span>1st, 01:00</span></div></label></div><div class="field"><label>Cron expression</label><input class="input mono" value="0 2 * * 1"></div><div class="check-row"><span class="grow">Add ±30 min jitter</span><button class="switch on" data-act="toggle"></button></div>` : ''}
      ${n === 3 ? `<dl class="kv"><dt>Name</dt><dd>Weekly Finance Regression</dd><dt>Scenarios</dt><dd>2 selected</dd><dt>Scope</dt><dd>Finance Workstations (2 agents)</dd><dt>Schedule</dt><dd class="mono">0 2 * * 1 (next: Mon 27 Oct 02:00)</dd></dl>` : ''}</div>
    <div class="modal-ft"><span class="left">Step ${n} of 3</span>${n > 1 ? '<button class="btn" data-act="wizBack">Back</button>' : '<button class="btn" data-act="closeModal">Cancel</button>'}${n < 3 ? '<button class="btn primary" data-act="wizNext">Next</button>' : '<button class="btn primary" data-act="wizDone">Create schedule</button>'}</div>`, 'lg');
  }; S.draw = draw; draw();
};
A.wizNext = () => { S.wiz++; S.draw(); };
A.wizBack = () => { S.wiz--; S.draw(); };
A.wizDone = () => { closeModal(); toast('Scheduled assessment created', 'Next run Mon 27 Oct 02:00'); render(); };
A.openInit = d => { S.initSel = d.a; const x = D.INITIATIVES.find(i => i.id === d.a); drawer(dhd(x.name, x.id + ' · ' + x.owner, 'flag') + `<div class="drawer-bd"><div class="grid g3 mb">${kpi('Progress', x.progress + '%', '', 'trend', '--accent')}${kpi('Jobs', x.jobs, '', 'box', '--cyan')}${kpi('Due', x.due.slice(0, 6), '', 'clock', '--amber')}</div><h4 class="mb">Attached jobs</h4>${table(['Job', 'Status'], [['ACL audit — Domain Controllers', 'Passed'], ['AdminSDHolder remediation', 'In progress'], ['ADCS template review', 'Open']].map(r => `<tr class="noclick"><td>${r[0]}</td><td>${st(r[1])}</td></tr>`))}</div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button><button class="btn primary" data-act="attachJob">${ic('plus')}Attach Job</button></div>`); };
A.attachJob = () => modal(mhd('Attach Job', 'plus') + `<div class="modal-bd"><div class="field"><label>Job</label><select class="select"><option>Kerberoasting — service accounts</option><option>LAPS coverage sweep</option></select></div><div class="field"><label>Target date</label><input class="input" value="15 Nov 2026"></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="attachDone">Attach</button></div>`, 'sm');
A.attachDone = () => { closeModal(); toast('Job attached to initiative'); };
A.newInitiative = () => modal(mhd('New Initiative', 'flag') + `<div class="modal-bd"><div class="field"><label>Name</label><input class="input" placeholder="e.g. Close Kerberoasting exposure"></div><div class="grid g2" style="gap:10px"><div class="field"><label>Owner</label><select class="select"><option>Identity Team</option><option>SOC Lead</option></select></div><div class="field"><label>Due date</label><input class="input" value="31 Dec 2026"></div></div><div class="field"><label>Objective</label><textarea class="input" style="font-family:inherit">Reduce validated Kerberoastable accounts from 14 to under 3.</textarea></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="initDone">Create initiative</button></div>`, 'lg');
A.initDone = () => { closeModal(); toast('Initiative created'); };
A.newCampaign = () => modal(mhd('New Campaign', 'campaign') + `<div class="modal-bd"><div class="field"><label>Campaign name</label><input class="input" value="Q1 2027 Purple Team"></div><div class="field"><label>Phases</label><div class="col">${['Reconnaissance validation', 'Identity attack chain', 'Endpoint & persistence', 'Exfiltration & DLP'].map((p, i) => `<label class="check-row" style="cursor:pointer"><input type="checkbox" class="check" ${i < 3 ? 'checked' : ''}><span class="grow">${i + 1}. ${p}</span></label>`).join('')}</div></div><div class="field"><label>Start</label><input class="input" value="05 Jan 2027"></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Campaign created" data-b="Scheduled 05 Jan 2027">Create campaign</button></div>`, 'lg');
A.openCampaign = d => { const c = D.CAMPAIGNS.find(x => x.id === d.a); drawer(dhd(c.name, c.id + ' · ' + c.scope, 'campaign') + `<div class="drawer-bd"><div class="timeline">${['Reconnaissance', 'Identity attack chain', 'Endpoint & persistence', 'Lateral movement', 'Exfiltration'].map((p, i) => `<div class="tl-step ${i < 2 ? 'done' : i === 2 ? 'run' : ''}"><div class="tl-dot">${i < 2 ? '✓' : i + 1}</div><div><div class="t">${p}</div><div class="d">${i < 2 ? 'Completed · 91% pass' : i === 2 ? 'In progress' : 'Pending'}</div></div></div>`).join('')}</div></div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button></div>`); };
A.importIoc = () => modal(mhd('Import Indicators', 'upload') + `<div class="modal-bd"><div class="radio-card on" style="flex-direction:column;align-items:center;padding:26px;border-style:dashed;text-align:center">${ic('upload')}<b>Drop CSV / STIX / plain-text file</b></div><div class="field mt" style="margin-top:14px"><label>Default action</label><div class="chips"><button class="chip on">Alert</button><button class="chip">Block</button><button class="chip">Monitor</button></div></div><div class="alert info">${ic('bell')}<div>1,248 indicators parsed · 22 duplicates skipped</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Indicators imported" data-b="1,226 added">Import</button></div>`, 'lg');
A.applyView = d => {
  const v = SHELL.views[+d.a]; if (!v) return;
  S.findSev = v.sev; S.findQ = v.q;
  if (S.route === 'findings') render(); else go('findings');
  toast('Saved view applied', v.name, 'info');
};
A.saveView = () => modal(mhd('Save view', 'filter') + `<div class="modal-bd"><div class="field"><label>Name</label><input class="input" id="sv-name" value="${S.findSev === 'all' ? 'All' : S.findSev[0].toUpperCase() + S.findSev.slice(1)} findings${S.findQ ? ' matching ' + S.findQ : ''}"></div><p class="muted" style="font-size:12.5px">Saves the current severity filter${S.findQ ? ' and search text' : ''} to <b>Saved views</b> in the sidebar.</p></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="saveViewDone">Save view</button></div>`, 'sm');
A.saveViewDone = () => { const name = ($('#sv-name').value || 'Untitled view').trim(); shellSaveView(name, S.findSev, S.findQ); closeModal(); render(); toast('View saved', name); };
A.openFinding = d => { const f = D.FINDINGS.find(x => x.id === d.a); drawer(dhd(f.title, f.id + ' · ' + f.asset, 'alert') + `<div class="drawer-bd"><div class="row mb wrap" style="margin-bottom:14px">${sev(f.sev)}${st(f.status)}${tag(f.tech, 'mono')}</div>
  <dl class="kv"><dt>Scenario</dt><dd>${f.scenario}</dd><dt>Asset</dt><dd class="mono">${f.asset}</dd><dt>Owner</dt><dd>${f.owner}</dd><dt>Age</dt><dd>${f.age}</dd></dl>
  <h4 class="mt" style="margin-top:18px">Evidence</h4><div class="code mt" style="margin-top:8px"><span class="c"># validation step output</span>\n<span class="k">event</span>: <span class="s">"Run key write not alerted"</span>\n<span class="k">registry</span>: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svcupd\n<span class="k">process</span>: <span class="s">powershell.exe -enc …</span>\n<span class="k">detected</span>: <span class="n">false</span></div>
  <h4 class="mt" style="margin-top:18px">Recommended action</h4><p class="muted mt" style="margin-top:6px;font-size:13px">Add a rule for Run-key writes under HKCU and re-run the APT29 Phase 7 persistence step.</p>${relBlock(relForFinding(f))}</div>
  <div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button><button class="btn" data-act="acceptRisk" data-a="${f.id}">Accept risk</button><button class="btn primary" data-act="toast" data-a="Remediation created" data-b="Linked to ${f.id}">${ic('wrench')}Create remediation</button></div>`, 'wide'); };
A.acceptRisk = d => modal(mhd('Accept risk', 'shield') + `<div class="modal-bd"><div class="alert warn mb">${ic('alert')}<div>Accepted risks are re-reviewed automatically at expiry.</div></div><div class="field"><label>Justification</label><textarea class="input" style="font-family:inherit">Compensating control: manual alerting on Run-key writes in SIEM.</textarea></div><div class="field"><label>Expires</label><select class="select"><option>30 days</option><option>90 days</option></select></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="acceptDone" data-a="${d.a}">Accept risk</button></div>`, 'lg');
A.acceptDone = d => { const f = D.FINDINGS.find(x => x.id === d.a); if (f) f.status = 'Accepted risk'; closeModal(); closeDrawer(); toast('Risk accepted', d.a, 'warn'); render(); };
A.openRem = d => { const x = D.REMED.cards.find(c => c.id === d.a); drawer(dhd(x.title, x.id + ' · ' + x.asset, 'wrench') + `<div class="drawer-bd"><dl class="kv"><dt>Severity</dt><dd>${sev(x.sev)}</dd><dt>Owner</dt><dd>${x.owner}</dd><dt>Due</dt><dd>${x.due}</dd><dt>Status</dt><dd>${D.REMED.cols.find(c => c[2] === x.col)[0]}</dd></dl><h4 class="mt" style="margin-top:18px">Move to</h4><div class="chips mt" style="margin-top:8px">${D.REMED.cols.map(([l, , k]) => `<button class="chip ${x.col === k ? 'on' : ''}" data-act="moveRem" data-a="${x.id}" data-b="${k}">${l}</button>`).join('')}</div>${relBlock([...D.FINDINGS.filter(f => f.asset === x.asset).map(f => ['alert', f.title, `Finding ${f.id}`, 'openFinding', f.id]), ...(D.AGENTS.find(a => a.host === x.asset) ? [['agent', x.asset, 'Open agent', 'agentMenu', D.AGENTS.find(a => a.host === x.asset).id]] : [])])}</div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button></div>`); };
A.moveRem = d => { const x = D.REMED.cards.find(c => c.id === d.a); x.col = d.b; closeDrawer(); render(); toast('Moved', x.id); };
A.genReport = () => modal(mhd('Generate report', 'report') + `<div class="modal-bd"><div class="field"><label>Report type</label><select class="select" style="width:100%"><option>Executive Security Posture</option><option>Detection Validation Matrix</option><option>Compliance evidence — PCI-DSS</option><option>Campaign summary</option></select></div><div class="field"><label>Period</label><div class="chips"><button class="chip">Last 7 days</button><button class="chip on">October 2026</button><button class="chip">Q3 2026</button></div></div><div class="field"><label>Format</label><div class="grid g3" style="gap:10px">${['PDF', 'HTML', 'DOCX'].map((f, i) => `<label class="radio-card ${i === 0 ? 'on' : ''}"><div><b>${f}</b></div></label>`).join('')}</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="genReportDone">Generate</button></div>`, 'lg');
A.genReportDone = () => { toast('Report generated', 'Opening preview'); A.previewRpt({ a: 'RPT-0198' }); };
A.previewRpt = d => {
  const r = D.REPORTS.find(x => x.id === d.a) || D.REPORTS[0];
  const lbl = rangeLabels('30d', 30), vals = wave(30, 70, 83, 2.2, 3).map(v => Math.min(98, Math.round(v)));
  modal(mhd('Report preview', 'report') + `<div class="modal-bd" style="background:var(--bg)"><div class="paper">
    <div class="row between"><img src="images/logo_name.png" alt="Audspect" style="height:34px"><span class="muted">Confidential · ${r.period}</span></div>
    <h2 style="margin-top:20px">${r.name}</h2><div class="muted" style="margin-top:2px">Acme Bank (demo) · Generated 24 Oct 2026, 14:20 · ${SHELL.env} environment</div>
    <h3>Executive summary</h3><p style="line-height:1.6">Detection coverage across validated controls improved to <b>81%</b> (+4 points). Identity remains the weakest domain at 61%, driven by an open ADCS template exposure and AdminSDHolder ACL drift. Four findings are rated high or critical and are owned by the Identity and SOC teams.</p>
    <div class="p-kpis">${[['81%', 'Detection rate'], ['1,284', 'Validations'], ['47', 'Open findings'], ['91%', 'SLA compliance']].map(([v, l]) => `<div class="p-kpi"><b>${v}</b><span class="muted">${l}</span></div>`).join('')}</div>
    <h3>Detection rate — last 30 days</h3>${lineChart(vals, lbl, '#2563eb', { h: 170, series: [{ name: 'Detected', data: vals, color: '#2563eb' }, { name: 'Target', data: Array(30).fill(90), color: '#d97706', dash: true }] })}
    <h3>Top open findings</h3><table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Asset</th></tr></thead><tbody>${D.FINDINGS.slice(0, 4).map(f => `<tr><td>${f.id}</td><td>${f.title}</td><td style="text-transform:capitalize">${f.sev}</td><td>${f.asset}</td></tr>`).join('')}</tbody></table>
    <div class="p-foot"><span>Audspect v1.9.2 · ${r.id}</span><span>Page 1 of 14</span></div></div></div>
    <div class="modal-ft"><span class="left">${r.fmt} · 14 pages · 1.2 MB</span><button class="btn" data-act="closeModal">Close</button><button class="btn primary" data-act="downloadRpt" data-a="${r.id}">${ic('download')}Download</button></div>`, 'xl');
};
A.downloadRpt = d => modal(mhd('Download Options', 'download') + `<div class="modal-bd"><div class="check-row"><span class="grow">Include executive summary</span><button class="switch on" data-act="toggle"></button></div><div class="check-row"><span class="grow">Include raw evidence (redacted)</span><button class="switch" data-act="toggle"></button></div><div class="check-row"><span class="grow">Password-protect archive</span><button class="switch" data-act="toggle"></button></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Download started" data-b="${d.a}">${ic('download')}Download</button></div>`, 'sm');
A.rerunReview = d => modal(mhd('Re-run Review', 'refresh') + `<div class="modal-bd"><p class="muted">Re-runs the detection check against the most recent telemetry for ${d.a ? `<b>${d.a}</b>` : 'all 7 checks'}.</p><div class="check-row mt" style="margin-top:12px"><span class="grow">Use last 24 h telemetry window</span><button class="switch on" data-act="toggle"></button></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Review queued" data-b="Results in ~2 min">Re-run</button></div>`, 'sm');
A.applyRec = d => { toast('Remediation created', D.RECS[d.a].title, ''); };
A.emailCampaign = () => modal(mhd('New Email Campaign', 'mail') + `<div class="modal-bd"><div class="field"><label>Template</label><select class="select" style="width:100%">${D.EMAIL.templates.map(t => `<option>${t.name}</option>`).join('')}</select></div><div class="field"><label>Target group</label><select class="select" style="width:100%"><option>Finance (420 mailboxes)</option><option>Executives (18)</option></select></div><div class="check-row"><span class="grow">Send in waves over 2 hours</span><button class="switch on" data-act="toggle"></button></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Campaign scheduled">Schedule</button></div>`, 'lg');
A.connConfig = () => modal(mhd('Connection Config', 'gear') + `<div class="modal-bd"><div class="field"><label>Orchestrator URL</label><input class="input mono" value="https://audspect.acme-bank.internal:9443"></div><div class="field"><label>Heartbeat interval</label><select class="select"><option>30 s</option><option>60 s</option></select></div><div class="check-row"><span class="grow">Require mTLS for agents</span><button class="switch on" data-act="toggle"></button></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="confirmDiff">Save</button></div>`, 'lg');
A.confirmDiff = () => modal(mhd('Confirm Config Change', 'gear') + `<div class="modal-bd"><p class="muted mb">Review the change before it is pushed to 428 agents.</p><div class="code"><span class="c"># diff</span>\n<span class="n">- heartbeat_interval: 60s</span>\n<span class="s">+ heartbeat_interval: 30s</span></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Back</button><button class="btn primary" data-act="toast" data-a="Config pushed" data-b="v38 → 428 agents">Confirm &amp; push</button></div>`, 'lg');
A.deployAgent = () => modal(mhd('Deploy Agent', 'agent') + `<div class="modal-bd"><div class="field"><label>Platform</label><div class="chips"><button class="chip on">Windows</button><button class="chip">Linux</button><button class="chip">macOS</button></div></div><div class="field"><label>Install command (run elevated)</label><div class="code">msiexec /i AudspectAgent-1.9.2.msi /qn ORCH=https://audspect.acme-bank.internal:9443 TOKEN=••••••••</div></div><div class="alert info">${ic('bell')}<div>Token expires in 24 h. Agents join group <b>Unassigned</b> until moved.</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Close</button><button class="btn" data-act="toast" data-a="Install command copied">${ic('file')}Copy</button></div>`, 'lg');
const agentMetrics = a => {
  const seed = (parseInt(a.id.replace(/\D/g, ''), 10) % 7) + 1, off = a.status === 'Offline';
  const rows = [['CPU', 14 + seed * 3, '%', '#3b82f6'], ['Memory', 38 + seed * 4, '%', '#a78bfa'], ['Heartbeat', 18 + seed * 2, ' ms', '#22d3ee']];
  return `<h4 style="margin:18px 0 8px">Health · last 24 h</h4><div class="grid g3" style="gap:8px">${rows.map(([n, v, u, c], i) => `<div class="mini-metric"><div class="t"><span>${n}</span><b>${off ? '—' : v + u}</b></div>${off ? '<div class="muted" style="font-size:11px;margin-top:12px">No data — agent offline</div>' : chartSlot({ type: 'spark', data: wave(24, v * 0.8, v, v * 0.12, seed + i), color: c, h: 34 })}</div>`).join('')}</div>`;
};
A.agentMenu = d => {
  const a = D.AGENTS.find(x => x.id === d.a);
  if (!a) return;
  modal(mhd(a.host, 'agent') + `<div class="modal-bd"><dl class="kv"><dt>Agent ID</dt><dd class="mono">${a.id}</dd><dt>OS</dt><dd>${a.os}</dd><dt>Group</dt><dd>${a.group}</dd><dt>Status</dt><dd>${st(a.status)}</dd><dt>Version</dt><dd class="mono">${a.version}</dd></dl>${agentMetrics(a)}${relBlock([...D.FINDINGS.filter(f => f.asset === a.host).map(f => ['alert', f.title, `Finding ${f.id} · ${f.sev}`, 'openFinding', f.id]), ...D.REMED.cards.filter(c => c.asset === a.host).map(c => ['wrench', c.title, `Remediation ${c.id}`, 'openRem', c.id])])}
    <h4 class="mt" style="margin-top:18px;margin-bottom:8px">Actions</h4><div class="grid g2" style="gap:8px">
      <button class="btn" data-act="moveGroup" data-a="${a.id}">${ic('layers')}Move to Group</button>
      <button class="btn" data-act="approveLocal" data-a="${a.id}">${ic('check')}Approve for local execution</button>
      <button class="btn" data-act="stopAgent" data-a="${a.id}">${ic('pause')}Stop Agent</button>
      <button class="btn" data-act="toast" data-a="Agent restarted" data-b="${a.host}">${ic('refresh')}Restart</button>
      <button class="btn danger" data-act="uninstallAgent" data-a="${a.id}">${ic('trash')}Uninstall Agent</button>
      <button class="btn danger" data-act="forceRemove" data-a="${a.id}">${ic('alert')}Force Remove Agent</button></div></div>`, 'lg');
};
A.moveGroup = d => modal(mhd('Move to Group', 'layers') + `<div class="modal-bd"><div class="field"><label>Target group</label><select class="select" style="width:100%">${D.AGENT_GROUPS.slice(1).map(g => `<option>${g[0]}</option>`).join('')}</select></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Agent moved">Move</button></div>`, 'sm');
A.approveLocal = d => modal(mhd('Approve for local execution', 'check') + `<div class="modal-bd"><div class="alert warn mb">${ic('alert')}<div>Allows scenarios to run without a central approval for 4 h. Logged to the audit trail.</div></div><div class="field"><label>Duration</label><select class="select"><option>1 hour</option><option selected>4 hours</option></select></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Local execution approved" data-b="4 h">Approve</button></div>`, 'sm');
A.stopAgent = d => modal(mhd('Stop Agent', 'pause') + `<div class="modal-bd"><p>Stops the agent service on <b>${(D.AGENTS.find(a => a.id === d.a) || {}).host}</b>. Running scenarios will be aborted.</p></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn danger" data-act="toast" data-a="Agent stopped" data-b="Service halted" data-c="warn">Stop agent</button></div>`, 'sm');
A.uninstallAgent = d => modal(mhd('Uninstall Agent', 'trash') + `<div class="modal-bd"><p>Removes the agent and its local queue. Historical results are kept.</p></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn danger" data-act="toast" data-a="Uninstall queued" data-b="Agent will uninstall at next check-in" data-c="warn">Uninstall</button></div>`, 'sm');
A.forceRemove = d => modal(mhd('Force Remove Agent', 'alert') + `<div class="modal-bd"><div class="alert err mb">${ic('alert')}<div>Use only if the host is decommissioned. Removes the record without contacting the agent.</div></div><div class="field"><label>Type the agent ID to confirm</label><input class="input mono" placeholder="${d.a}"></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn danger" data-act="toast" data-a="Agent record removed" data-b="${d.a}" data-c="err">Force remove</button></div>`, 'sm');
A.responseAction = () => modal(mhd('Response Action', 'bolt') + `<div class="modal-bd"><div class="field"><label>Connector</label><select class="select" style="width:100%"><option>Defender — Isolate host</option><option>CrowdStrike — Contain device</option></select></div><div class="field"><label>Targets</label><div class="chips"><span class="chip on">WS-FIN-0142</span><span class="chip">WS-FIN-0177</span></div></div><div class="alert warn">${ic('alert')}<div>Requires second-operator approval before execution.</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="toast" data-a="Approval requested" data-b="Sent to 1 approver">Request approval</button></div>`, 'lg');
A.addTaxii = () => modal(mhd('Add TAXII Connector', 'plug') + `<div class="modal-bd"><div class="field"><label>Name</label><input class="input" value="ISAC feed"></div><div class="field"><label>Discovery URL</label><input class="input mono" value="https://taxii.isac.example/taxii2/"></div><div class="grid g2" style="gap:10px"><div class="field"><label>Username</label><input class="input"></div><div class="field"><label>API key</label><input class="input" type="password" value="secret"></div></div><div class="field"><label>Poll interval</label><select class="select"><option>1 h</option><option>6 h</option></select></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn" data-act="toast" data-a="Connection OK">Test</button><button class="btn primary" data-act="toast" data-a="TAXII connector added">Save</button></div>`, 'lg');
A.backupNow = () => { toast('Backup started', 'Estimated 6 min'); setTimeout(() => toast('Backup complete', '2.4 GB · verified'), 2400); };
A.variantDrill = () => drawer(dhd('Full Variant Sweep', 'Endpoint Mastery · 51 variant sets', 'layers') + `<div class="drawer-bd">${table(['Variant set', 'Variants', 'Passing'], D.VARIANTS.map(v => `<tr class="noclick"><td>${v.name}</td><td>${v.count}</td><td>${v.pass}/${v.count}</td></tr>`))}</div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Close</button><button class="btn primary" data-act="sweepStart">${ic('play')}Run Full Sweep</button></div>`, 'wide');
A.sweepStart = () => { closeDrawer(); modal(mhd('Run Full Sweep — Endpoint Mastery', 'play') + `<div class="modal-bd"><div class="field"><label>Scope</label><select class="select" style="width:100%"><option>Finance Workstations (2)</option><option>Endpoints — all Windows (412)</option></select></div><div class="field"><label>Variant sets</label><div class="chips"><span class="chip on">All 51 sets</span><span class="chip">Persistence only</span></div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="sweepPreview">Next: Preview</button></div>`, 'lg'); };
A.sweepPreview = () => modal(mhd('Preview &amp; Confirm', 'check') + `<div class="modal-bd"><dl class="kv"><dt>Variants</dt><dd>412 executions</dd><dt>Est. duration</dt><dd>~3 h 20 min</dd><dt>Impact</dt><dd>Telemetry-safe; cleanup enabled</dd></dl><div class="alert warn mt" style="margin-top:14px">${ic('alert')}<div>Sweeps run across 412 agents. Confirm the change window.</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Back</button><button class="btn primary" data-act="sweepLive">Confirm &amp; start</button></div>`, 'lg');
A.sweepLive = () => {
  modal(mhd('EM Full Sweep — Live', 'play') + `<div class="modal-bd"><div class="row between mb" style="margin-bottom:10px"><b id="sw-pct">0%</b><span class="muted" id="sw-txt">Starting…</span></div><div class="bar thick"><i id="sw-bar" style="width:0%"></i></div><div class="log mt" style="margin-top:14px" id="sw-log"></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Hide</button></div>`, 'lg');
  let p = 0; const iv = setInterval(() => {
    p = Math.min(100, p + 4 + Math.random() * 6);
    const b = $('#sw-bar'); if (!b) { clearInterval(iv); return; }
    b.style.width = p + '%'; $('#sw-pct').textContent = Math.round(p) + '%'; $('#sw-txt').textContent = Math.round(p * 4.12) + ' / 412 agents';
    $('#sw-log').insertAdjacentHTML('beforeend', `<div class="ok">[${new Date().toTimeString().slice(0, 8)}] batch ${Math.round(p / 4)} complete · ${Math.round(p * 0.9)}% detected</div>`);
    if (p >= 100) { clearInterval(iv); toast('Full sweep complete', '412 agents · 88% detected'); }
  }, 900);
};
A.rerun = () => {};
A.newStep = () => {};

// Click + input delegation
document.addEventListener('click', e => {
  const t = e.target.closest('[data-act]');
  if (e.target.closest('#menu-btn')) return document.body.classList.toggle('nav-open');
  if (document.body.classList.contains('nav-open') && !e.target.closest('#sidebar')) document.body.classList.remove('nav-open');
  if (e.target.id === 'overlay') return closeModal();
  if (e.target.id === 'drawer-overlay') return closeDrawer();
  if (e.target.closest('#user-btn')) return userMenu();
  if (e.target.closest('#bell-btn')) return notifMenu();
  if (e.target.closest('#open-search')) return searchPalette();
  if (e.target.closest('#help-btn')) return helpModal();
  if (!t) { if (!e.target.closest('.popover, .search-pop')) closePop(); return; }
  if (t.dataset.act === 'toggle') return A.toggle(t.dataset, t);
  if (t.dataset.act === 'accent') return A.accent(t.dataset);
  if (t.dataset.act === 'validateYaml' || t.dataset.act === 'wizNext' || t.dataset.act === 'wizBack' || t.dataset.act === 'wizDone') {/* handled */}
  closePop();
  if (t.classList.contains('rel')) closeModal();
  const fn = A[t.dataset.act] || (ACT_EXTRA[t.dataset.act]);
  if (fn) fn(t.dataset, t, e);
});
document.addEventListener('input', e => { if (e.target.dataset.input) { S[e.target.dataset.input] = e.target.value; render(); const el = document.querySelector(`[data-input="${e.target.dataset.input}"]`); if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); } } });
document.addEventListener('change', e => { if (e.target.dataset.change) A[e.target.dataset.change](e.target.dataset, e.target); });
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); searchPalette(); }
  if (e.key === 'Escape') { closeModal(); closeDrawer(); closePop(); }
});
const ACT_EXTRA = {
  doLogout: () => { try { sessionStorage.removeItem('aud-demo-session'); } catch (e) { } $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); closePop(); },
  profileNav: () => { location.hash = '#/profile'; closePop(); },
  sttabGo: () => {}, emailGo: () => {},
  searchGo: d => { closeModal(); location.hash = '#/' + d.a; },
  scTab: () => {},
  wipeRuns: () => {},
};
A.doLogout = ACT_EXTRA.doLogout;
A.profileNav = ACT_EXTRA.profileNav;
A.searchGo = ACT_EXTRA.searchGo;
A.scTab = () => {};

// Popovers
function closePop() { document.querySelectorAll('.popover, .search-pop').forEach(p => p.remove()); }
function userMenu() {
  closePop();
  const p = document.createElement('div'); p.className = 'popover';
  p.innerHTML = `<div class="p-head">admin@acme-bank.demo</div>
    <div class="p-item" data-act="profileNav">${ic('user')}<span>My Profile</span></div>
    <div class="p-item" data-act="nav" data-a="settings">${ic('gear')}<span>Settings</span></div>
    <div class="p-item" data-act="toast" data-a="Shortcuts" data-b="Ctrl+K search · Esc closes dialogs">${ic('help')}<span>Keyboard shortcuts</span></div>
    <div class="p-sep"></div><div class="p-item" data-act="doLogout">${ic('logout')}<span>Sign out</span></div>`;
  document.getElementById('topbar').appendChild(p);
}
function notifMenu() {
  closePop();
  const p = document.createElement('div'); p.className = 'popover'; p.style.width = '360px';
  p.innerHTML = `<div class="p-head">Notifications</div>` + D.NOTIFS.map(([i, c, t, d]) => `<div class="notif"><span class="ni" style="background:var(--${c === 'red' ? 'red' : c === 'green' ? 'green' : c === 'amber' ? 'amber' : 'accent'}-dim);color:var(--${c === 'red' ? 'red' : c === 'green' ? 'green' : c === 'amber' ? 'amber' : 'accent'})">${ic(i)}</span><div><b>${t}</b><span>${d}</span></div></div>`).join('');
  document.getElementById('topbar').appendChild(p);
}
function searchPalette() {
  closePop();
  const p = document.createElement('div'); p.className = 'search-pop';
  p.innerHTML = `<div class="input-icon" style="margin-bottom:6px">${ic('search')}<input class="input" id="sp-in" placeholder="Search pages and scenarios…" style="width:100%;height:40px"></div><div id="sp-list"></div>`;
  document.getElementById('topbar').appendChild(p);
  const list = () => {
    const q = $('#sp-in').value.toLowerCase();
    const pages = D.NAV.flatMap(g => g.items).filter(([id, l]) => l.toLowerCase().includes(q)).slice(0, 6).map(([id, l, i]) => `<div class="res" data-act="searchGo" data-a="${id}">${ic(i)}<span>${l}</span><span class="muted" style="margin-left:auto;font-size:11px">Page</span></div>`);
    const sc = D.SCENARIOS.filter(s => s.name.toLowerCase().includes(q) || s.tech.some(t => t.toLowerCase().includes(q))).slice(0, 5).map(s => `<div class="res" data-act="searchGo" data-a="scenarios">${ic('target')}<span>${s.name}</span><span class="muted mono" style="margin-left:auto;font-size:11px">${s.id}</span></div>`);
    const lk = navLookup();
    const recent = !q && SHELL.recent.length ? `<div class="p-head" style="font-size:10.5px;color:var(--muted);padding:6px 10px">Recent</div>${SHELL.recent.slice(0, 4).map(id => lk[id] ? `<div class="res" data-act="searchGo" data-a="${id}">${ic('clock')}<span>${lk[id].label}</span><span class="muted" style="margin-left:auto;font-size:11px">Recent</span></div>` : '').join('')}` : '';
    $('#sp-list').innerHTML = recent + (pages.length ? `<div class="p-head" style="font-size:10.5px;color:var(--muted);padding:6px 10px">Pages</div>${pages.join('')}` : '') + (sc.length ? `<div class="p-head" style="font-size:10.5px;color:var(--muted);padding:6px 10px">Scenarios</div>${sc.join('')}` : '') || '<div class="empty">No results</div>';
  };
  $('#sp-in').addEventListener('input', list); list(); $('#sp-in').focus();
}
function helpModal() {
  modal(mhd('Keyboard shortcuts', 'help') + `<div class="modal-bd"><div class="check-row"><span class="grow">Search everywhere</span><span class="kbd">Ctrl + K</span></div><div class="check-row"><span class="grow">Close dialog / drawer</span><span class="kbd">Esc</span></div><div class="check-row"><span class="grow">Run selected scenario</span><span class="kbd">Enter</span></div></div>`, 'sm');
}

// Live progress simulation for running runs
setInterval(() => {
  if ($('#app').classList.contains('hidden')) return;   // nothing runs behind the login screen
  let changed = false;
  D.RUNS.forEach(r => {
    if (r.status !== 'Running') return;
    r.progress = Math.min(100, r.progress + 1 + Math.random() * 2.5);
    if (r.progress >= 100) { r.status = 'Passed'; r.step = 'Completed'; changed = true; toast('Run passed', r.id + ' · ' + r.name); }
    document.querySelectorAll(`[data-prog="${r.id}"]`).forEach(pe => { pe.textContent = Math.round(r.progress) + '%'; pe.parentElement.parentElement.querySelector('i').style.width = r.progress + '%'; });
    const lb = document.getElementById('ld-bar'); if (lb && S.liveRun === r.id) lb.style.width = r.progress + '%';
  });
  if (changed) render();
}, 1800);

// ---------- Render & routing ----------
function render() {
  const route = S.route;
  renderNav();
  const fn = P[route] || P.dashboard;
  const keepScroll = S.keepScroll ? $('#content').scrollTop : 0;
  CH.reg = {};
  $('#content').innerHTML = fn();
  hydrateCharts($('#content'));
  enhanceTables($('#content'), route);
  shellDecorate(route, S);
  const c = $('#content');
  c.scrollTop = keepScroll;
  S.keepScroll = false;
  c.classList.remove('enter');
  if (S.animate) { void c.offsetWidth; c.classList.add('enter'); S.animate = false; }
  a11yPass();
  document.title = `${route === 'profile' ? 'My Profile' : NAMES[route] || 'Dashboard'} · Audspect`;
}

// Keyboard + screen-reader details: everything clickable is focusable and labelled
function a11yPass() {
  $$('.icon-btn:not([aria-label])').forEach(b => b.setAttribute('aria-label', b.title || 'Button'));
  $$('#content [data-act], #content [data-sh], #nav [data-act]').forEach(el => {
    if (/^(BUTTON|INPUT|SELECT|TEXTAREA|A)$/.test(el.tagName) || el.hasAttribute('tabindex')) return;
    el.tabIndex = 0;
    if (el.tagName !== 'TR') el.setAttribute('role', 'button');
  });
  $$('.switch').forEach(s => { s.setAttribute('role', 'switch'); s.setAttribute('aria-checked', s.classList.contains('on')); });
  $('#modal').setAttribute('role', 'dialog'); $('#modal').setAttribute('aria-modal', 'true');
  $('#drawer').setAttribute('role', 'dialog'); $('#drawer').setAttribute('aria-modal', 'true');
}
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const el = e.target;
  if (!el.matches || !el.matches('[data-act], [data-sh]') || /^(BUTTON|INPUT|SELECT|TEXTAREA|A)$/.test(el.tagName)) return;
  e.preventDefault();
  el.click();
});

// Loading skeleton (shown on first sign-in and on manual refresh)
function skeleton() {
  $('#content').innerHTML = `<div class="sk" style="height:14px;width:220px;margin-bottom:18px"></div><div class="sk" style="height:30px;width:300px;margin-bottom:8px"></div><div class="sk sk-line" style="width:420px;max-width:100%;margin-bottom:22px"></div>
    <div class="grid g5 mb">${Array(5).fill('<div class="sk" style="height:128px"></div>').join('')}</div>
    <div class="grid g-side"><div class="sk" style="height:250px"></div><div class="sk" style="height:250px"></div></div>
    <div class="sk mt" style="height:200px"></div>`;
}
function route() {
  const r = (location.hash.replace('#/', '') || 'dashboard');
  S.route = P[r] ? r : 'dashboard';
  shellVisit(S.route);
  S.animate = true;
  render();
}
// Public surface for the page modules (demo-pages*.js), which are loaded after this file
window.AUD = { S, toast, render, go, modal, closeModal, skeleton, P, A, h: { $, $$, tag, sev, st, bar, table, kpi, pageHead, seg, tabs, curTab, drawer, dhd, mhd, closeDrawer, relBlock, wave, rangeLabels, gauge, lineChart, barChart, scColor, F2S, RUN_SC } };
window.addEventListener('hashchange', route);
$('#login-btn').addEventListener('click', () => {
  try { sessionStorage.setItem('aud-demo-session', '1'); } catch (e) { }
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  skeleton();                       // brief loading state, like a real first fetch
  setTimeout(route, 380);
});
// Login keyboard
document.addEventListener('keydown', e => { if (e.key === 'Enter' && !$('#login').classList.contains('hidden')) $('#login-btn').click(); });
// Start on the login screen; the app shell is revealed on sign-in.
if (!location.hash) location.hash = '#/dashboard';
route();
// A reload keeps you signed in for this browser tab; Sign out (or closing the tab) ends the session.
// Runs on window load so every page module has already replaced its page.
window.addEventListener('load', () => { try { if (sessionStorage.getItem('aud-demo-session')) { $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); route(); } } catch (e) { } });

// Render a small set of extra interactions for the login state
})();
