// Dashboard — adds the panels/tiles/buttons the real console has (compliance strip, control effectiveness,
// live campaigns, failing techniques, attack flow, tactic coverage, ransomware readiness, exec forecast).
(() => {
const { S, P, A, h, toast, modal } = AUD;
const { tag, sev, st, bar, table, kpi, pageHead, gauge, lineChart, wave, rangeLabels, mhd } = h;
const K = KIT, dr = K.dr;
const prevDash = P.dashboard;

const FW = [
  ['CERT-IN', 'CERT-In / MeitY', 78, 31, 90, 24, 4, 3], ['IRDAI', 'IRDAI', 72, 25, 88, 18, 4, 3], ['ISO 27001', 'ISO/IEC', 81, 93, 95, 74, 14, 5], ['NIST CSF', 'NIST', 76, 108, 86, 82, 11, 15],
  ['PCI DSS V4', 'PCI SSC', 84, 61, 93, 51, 6, 4], ['RBI CSF', 'RBI', 69, 48, 81, 33, 6, 9], ['SEBI CSCRF', 'SEBI', 74, 39, 85, 29, 4, 6]];
const fwCol = v => v >= 80 ? '--green' : v >= 72 ? '--cyan' : v >= 65 ? '--amber' : '--red';
const CE = [['Endpoint / EDR', 61, 27, 12], ['Email gateway', 70, 22, 8], ['Network / NGFW', 48, 31, 21], ['Identity', 34, 29, 37], ['WAF', 66, 24, 10], ['DLP', 41, 28, 31], ['SIEM / logging', 22, 52, 26]];
const FAILING = [['T1547.001', 'Registry Run Keys', 9, 41], ['T1486', 'Data Encrypted for Impact', 7, 35], ['T1021.002', 'SMB Admin Shares', 6, 49], ['T1068', 'Priv-Esc Exploitation', 5, 56], ['T1041', 'Exfil over C2 Channel', 4, 52]];
const TACS = [['Initial Access', 82], ['Execution', 88], ['Persistence', 61], ['Priv. Escalation', 57], ['Defense Evasion', 52], ['Credential Access', 74], ['Discovery', 79], ['Lateral Movement', 58], ['Collection', 66], ['C2', 71], ['Exfiltration', 43], ['Impact', 49]];
const FLOW = [['Initial Access', 62, 28, 10], ['Execution', 58, 30, 12], ['Persistence', 31, 30, 39], ['Priv. Esc.', 28, 29, 43], ['Cred. Access', 44, 30, 26], ['Lateral Mvmt', 30, 28, 42], ['Exfil', 26, 17, 57], ['Impact', 24, 25, 51]];
const RANSOM = [['Backups immutable & offline', 'pass'], ['Shadow-copy deletion blocked', 'pass'], ['Mass-encryption detected < 60 s', 'warn'], ['Lateral SMB spread contained', 'fail'], ['EDR tamper protection enforced', 'pass'], ['Canary files monitored', 'pass']];

const ACTORS = [
  ['LockBit', 'High', 43, 'Ransomware-as-a-service', 38, 11, [22, 25, 24, 30, 33, 31, 38, 41, 40, 46, 49, 52]],
  ['Akira', 'Medium', 37, 'Double-extortion ransomware', 31, 9, [14, 16, 15, 19, 22, 24, 23, 27, 30, 29, 33, 35]],
  ['APT29', 'Medium', 35, 'Nation-state · espionage', 54, 7, [30, 29, 31, 30, 32, 31, 33, 32, 34, 33, 35, 34]],
  ['APT41', 'Medium', 32, 'Dual-use · espionage + crime', 47, 6, [18, 20, 19, 22, 21, 24, 23, 25, 24, 27, 26, 28]],
  ['APT28', 'Medium', 30, 'Nation-state · credential theft', 44, 5, [25, 24, 26, 25, 24, 26, 25, 27, 26, 25, 27, 26]]];
const RT = [
  ['FIN7', 71, 0, 'flat', 1, [71, 71]], ['APT41', 81, 6, 'up', 3, [70, 75, 81]], ['APT28', 87, 0, 'flat', 1, [87, 87]],
  ['LockBit', 58, 9, 'down', 4, [72, 69, 64, 58]], ['Scattered Spider', 65, 4, 'up', 2, [61, 65]], ['Lazarus Group', 67, 0, 'flat', 1, [67, 67]]];
const ep_ring = (v, color) => `<svg viewBox="0 0 60 60" width="72" height="72" class="progress-ring"><circle cx="30" cy="30" r="24" fill="none" class="track" stroke-width="6"/><circle cx="30" cy="30" r="24" fill="none" stroke="${color}" stroke-width="6" stroke-linecap="round" stroke-dasharray="${v / 100 * 150.8} 150.8" transform="rotate(-90 30 30)"/></svg>`;
// Fixed-size trend line: every row spans the same x-range (6 points, older runs padded flat) so lines align.
const miniLine = (hist, color) => { const pts = Array(Math.max(0, 6 - hist.length)).fill(hist[0]).concat(hist), lo = Math.min(...pts), hi = Math.max(...pts), r = hi - lo || 1; const xy = pts.map((v, i) => [4 + i * 22, 24 - (v - lo) / r * 18]); const d = xy.map((p, i) => (i ? 'L' : 'M') + p[0] + ' ' + p[1].toFixed(1)).join(' '); return `<svg width="118" height="30" viewBox="0 0 118 30" class="spark"><path d="${d}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><circle cx="${xy[5][0]}" cy="${xy[5][1].toFixed(1)}" r="3" fill="${color}"/></svg>`; };
const initials = n => n.split(/[ -]/).map(x => x[0]).join('').slice(0, 2).toUpperCase();
const sec = (title, link) => `<div class="row between sec-row"><h4 class="sec-label" style="margin:0">${title}</h4>${link || ''}</div>`;
const viewAll = (act, arg, label = 'View all →') => `<a class="link" data-act="${act}" data-a="${arg}" style="cursor:pointer;font-size:12.5px;color:var(--accent-hi)">${label}</a>`;

P.dashboard = () => {
  const ops = S.dashView === 'operational';
  const R = S.exRange || '30 days';
  const seg = `<div class="seg"><button class="${ops ? 'on' : ''}" data-act="set" data-a="dashView" data-b="operational">Operational</button><button class="${!ops ? 'on' : ''}" data-act="set" data-a="dashView" data-b="executive">Executive</button></div>`;

  if (!ops) {
    const n = { '30 days': 30, '90 days': 45, '1 year': 52 }[R], lab = { '30 days': () => rangeLabels('30d', n), '90 days': () => rangeLabels('90d', n), '1 year': () => Array.from({ length: n }, (_, i) => 'W' + (i + 1)) }[R]();
    const hist = wave(n, 71, 68, 2.4, 5).map(v => Math.round(v)), fc = 71;
    const head = `<div class="row between mb" style="flex-wrap:wrap;gap:10px">${seg}<div class="row"><div class="seg">${['30 days', '90 days', '1 year'].map(r => `<button class="${R === r ? 'on' : ''}" data-act="set" data-a="exRange" data-b="${r}">${r}</button>`).join('')}</div><button class="btn" data-act="toast" data-a="Dashboard refreshed" data-b="Snapshot 25 Oct 00:00">${ic('refresh')}Refresh</button></div></div>`;
    return K.hero('dash', 'Executive Dashboard', 'Fleet-wide risk, exposure, and detection-coverage trends over time — daily snapshots, not a single point-in-time report.',
      `<button class="btn" data-act="genReport">${ic('report')}Generate report</button>`, [['shield', '68', 'Risk score'], ['exposure', '74', 'Exposure score'], ['mapped', '76%', 'Detection coverage'], ['agent', '428', 'Fleet assets']]).replace('<div class="scn-banner">', head + '<div class="scn-banner" style="margin-top:0">') +
    `<div class="grid g4 mt">
      ${kpi('Risk score', '68', '▲ 4 vs last month', 'shield', '--amber', 'var(--red)', [62, 60, 64, 63, 66, 61, 65, 67, 64, 69, 66, 68])}
      ${kpi('Exposure score', '74', '▼ 3 · 4 critical open', 'exposure', '--red', 'var(--green)', [80, 79, 78, 77, 78, 76, 75, 76, 75, 74, 74, 74])}
      ${kpi('Detection coverage', '76%', '▲ 3 pts', 'mapped', '--green', 'var(--green)', [66, 68, 69, 70, 71, 72, 73, 74, 74, 75, 76, 76])}
      ${kpi('Fleet assets', '428', '16 need attention', 'agent', '--cyan', 'var(--amber)', [402, 408, 411, 415, 418, 420, 421, 424, 425, 426, 427, 428])}
    </div>
    <div class="grid g-side mt">
      ${K.card('Risk-score forecast <span class="tag amber" style="margin-left:8px">Rising</span>', lineChart(hist, lab, '#f59e0b', { series: [{ name: 'Risk score', data: hist, color: '#f59e0b' }, { name: 'Target', data: Array(n).fill(55), color: '#10b981', dash: true }], area: true }) + `<div class="muted" style="font-size:12px;margin-top:8px">Projected to reach <b>${fc + 5}</b> in 30 days if open critical exposures are not remediated. Confidence: medium (based on ${n} snapshots).</div>`, '<div class="legend"><span><i style="background:#f59e0b"></i>Risk</span><span><i style="background:#10b981"></i>Target 55</span></div>')}
      ${K.card('Overall posture', gauge(68) + '<div class="legend" style="justify-content:center;margin-top:8px"><span><i style="background:#f59e0b"></i>Moderate</span></div>')}
    </div>
    <div class="card mt pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Open exposure windows</h2><div class="actions"><span class="muted" style="font-size:12px">time each weakness has stayed open</span></div></div>
      ${table(['Finding', 'Severity', 'Window open', 'SLA', 'Owner'], [['Domain Admin reachable via ADCS ESC1', 'critical', 19, 7, 'Identity Team'], ['Run-key persistence not detected', 'high', 4, 30, 'SOC Tier 2'], ['Public S3 bucket with customer exports', 'critical', 11, 7, 'Cloud Platform'], ['Cardholder logs not forwarded', 'high', 27, 30, 'Logging'], ['Weak SMB signing on file tier', 'medium', 41, 90, 'Infra']].map(([t, s, d, sla, o]) => `<tr data-act="nav" data-a="findings"><td>${t}</td><td>${sev(s)}</td><td>${tag(d + ' d', d > sla ? 'red' : 'gray')}</td><td class="muted">${sla} d${d > sla ? ' · <span style="color:var(--red)">breached</span>' : ''}</td><td class="muted">${o}</td></tr>`))}</div>
    <div class="card mt"><div class="card-hd"><h2>What changed this period</h2><div class="actions"><span class="muted" style="font-size:12px">vs previous ${R}</span></div></div>${[
      ['trend', 'Detection rate up 9 points since 1 Oct', 'After EDR rule tuning and ASR enforcement, Office-child-process attacks are now blocked end to end.', 'verification'],
      ['alert', 'Identity is still the weakest domain (61%)', 'ADCS ESC1 and AdminSDHolder ACL drift are open, and both sit on validated attack path AP-14.', 'attackpath'],
      ['clock', 'SLA compliance is 91% against a 95% target', 'Four breaches in the last 30 days, all medium severity and owned by Linux Ops.', 'reports'],
      ['check', 'Public storage exposure closed', 'The customer-exports bucket was made private and re-validated by CMP-33 dry run.', 'exposure']].map(([i, t, d, r]) => `<a class="insight feed-link" data-act="nav" data-a="${r}"><span class="ii">${ic(i, 'sm')}</span><div class="grow"><b style="font-weight:500">${t}</b><div class="muted" style="font-size:12.5px;margin-top:2px">${d}</div></div>${ic('chevr', 'sm')}</a>`).join('')}</div>
    <div class="grid g2 mt">${K.card('Posture by domain', K.hbars([['Endpoint', 84, 'green'], ['Email', 90, 'green'], ['Network', 77, ''], ['Data security', 72, 'cyan'], ['Identity', 61, 'amber'], ['Cloud', 58, 'red']]))}
      ${K.card('Top business risks', [['Domain Admin reachable from helpdesk', 'critical', 'Identity'], ['Ransomware path to file tier unvalidated', 'high', 'Endpoint'], ['Cardholder logs not forwarded (1 DB)', 'high', 'Logging'], ['Public S3 bucket with customer exports', 'critical', 'Cloud']].map(([t, s, d]) => `<div class="check-row">${sev(s)}<div class="grow"><b style="font-weight:500">${t}</b><div class="muted" style="font-size:12px">${d} domain</div></div></div>`).join(''))}</div>`;
  }

  // ---------- Operational ----------
  const old = prevDash();                         // keep my existing operational blocks (charts, activity, up-next, ...)
  const i0 = old.indexOf('<div class="grid g-side mt">');   // everything from the detection-rate chart onward
  const tail = old.slice(i0);
  const kvs = ({ '24h': ['58', '79%'], '7d': ['412', '80%'], '30d': ['1,284', '81%'], '90d': ['3,702', '77%'] })[SHELL.range];
  const lc = D.CAMPAIGNS.filter(c => c.status === 'Running');
  const runs = D.RUNS.slice(0, 5);
  return `<div class="row between mb" style="flex-wrap:wrap;gap:10px">${seg}<div class="muted" style="font-size:12px">Continuous validation across 428 agents and 212 ATT&amp;CK techniques.</div></div>` +
  K.hero('dash', 'Security Posture', 'Continuous validation across 428 agents and 212 ATT&CK techniques. Last run 14 minutes ago.',
    `<button class="btn" data-act="genReport">${ic('report')}Generate report</button><button class="btn primary" data-act="newSim">${ic('play')}New simulation</button>`,
    [['play', kvs[0], `Validations (${SHELL.range})`], ['shield', kvs[1], 'Detection rate'], ['agent', '412 / 428', 'Agents online'], ['clock', '6m 12s', 'Mean time to detect']]).replace('<div class="scn-banner">', '<div class="scn-banner" style="margin-top:0">') +
  `<div class="grid g5 mt">
    <div class="kpi hov" data-act="nav" data-a="findings" style="--kc:var(--red);cursor:pointer"><div class="kpi-top"><div class="lbl"><span class="ico" style="background:transparent;color:var(--red)">${ic('flag')}</span>Open findings</div></div><div class="val">47</div><div class="delta" style="color:var(--red)">9 critical / high</div></div>
    ${kpi('Attack surface age', '18d', 'oldest open weakness', 'clock', '--amber', 'var(--amber)', [12, 13, 14, 14, 15, 16, 16, 17, 17, 18, 18, 18])}
    ${kpi('Prevention score', '71%', '▲ 3 pts · prevented outright', 'shield', '--green', 'var(--green)', [62, 64, 65, 66, 67, 67, 68, 69, 69, 70, 71, 71])}
    ${kpi('ATT&CK coverage', '87%', '212 techniques tested', 'mapped', '--accent', 'var(--green)', [78, 79, 80, 81, 82, 83, 84, 85, 85, 86, 87, 87])}
    <div class="kpi hov" data-act="nav" data-a="campaigns" style="--kc:var(--cyan);cursor:pointer"><div class="kpi-top"><div class="lbl"><span class="ico" style="background:transparent;color:var(--cyan)">${ic('campaign')}</span>Active campaigns</div></div><div class="val">${lc.length}</div><div class="delta" style="color:var(--cyan)"><span class="live-dot"></span> ${lc.length ? lc[0].id + ' running' : 'none running'}</div></div>
  </div>` +
  sec('Regulatory compliance', viewAll('openCompliance', '', 'View details →')) +
  `<div class="grid g7 reg-grid">${FW.map(([n, b, v, c, cov, p, f, u], i) => `<div class="kpi reg hov" style="--kc:var(${fwCol(v)});cursor:pointer" data-act="fwOpen" data-a="${i}"><div style="font-size:11px"><b style="letter-spacing:.04em;white-space:nowrap">${n}</b><div class="muted" style="font-size:10.5px;margin-top:1px">${b}</div></div><div class="val">${v}%</div>${bar(cov, 'green')}<div class="muted" style="font-size:11.5px;margin:6px 0 2px">${cov}% coverage · ${c} controls</div><div class="muted" style="font-size:11.5px">${p} pass · ${f} fail · ${u} untested</div><div class="muted" style="font-size:10.5px;font-style:italic;margin-top:6px;line-height:1.3">Any 1 failed test fails the control — see breakdown</div></div>`).join('')}</div>` +
  sec('Threat intelligence', `<a class="link" data-act="kevPack" style="cursor:pointer;font-size:12.5px;color:var(--accent-hi)">${ic('bolt', 'sm')} Create KEV Pack →</a>`) +
  `<div class="grid g-side">
    ${K.card('Top threat actors', ACTORS.map(([n, lvl, sc, sector, tq, gp, act], i) => `<div class="ta-row" data-act="actorOpen" data-a="${n}">
      <span class="ta-rank">${i + 1}</span>
      <span class="ta-av ${lvl === 'High' ? 'hi' : ''}">${initials(n)}</span>
      <div class="ta-main"><div class="row" style="gap:8px"><b>${n}</b>${tag(lvl, lvl === 'High' ? 'amber' : 'blue')}</div><div class="muted" style="font-size:12px">${sector}</div><div class="ta-meta"><span>${ic('mapped', 'sm')} ${tq} techniques</span><span style="color:var(--red)">${ic('alert', 'sm')} ${gp} validated gaps</span></div></div>
      <div class="ta-spark" title="Observed activity, last 12 weeks">${chartSlot({ type: 'spark', data: act, color: lvl === 'High' ? '#f59e0b' : '#3b82f6', h: 40 })}<span class="muted">12-wk activity</span></div>
      <div class="ta-score"><div class="ta-bar"><i style="width:${Math.min(100, sc * 2)}%;background:var(--${lvl === 'High' ? 'amber' : 'accent'})"></i></div><b>${sc}</b><span class="muted">relevance</span></div>
      ${ic('chevr', 'sm')}</div>`).join(''), viewAll('nav', 'threat-priority', 'Prioritization →'))}
    <div class="col">
      ${K.card('KEV exposure', `<div class="row" style="gap:6px;align-items:center;flex-wrap:wrap">${K.donut([{ label: 'Exploitable here', value: 14, color: '#ef4444' }, { label: 'Product present, patched', value: 27, color: '#f59e0b' }, { label: 'Not in estate', value: 301, color: '#3b82f6' }], 'KEV entries', 150, '342')}</div>
        <div class="grid g2" style="gap:10px;margin-top:10px"><div class="mini-metric"><div class="t"><span>Matched products</span><b>6</b></div></div><div class="mini-metric"><div class="t"><span>New this week</span><b style="color:var(--amber)">+5</b></div></div></div>
        <button class="btn primary block" style="margin-top:12px" data-act="kevPack">${ic('bolt')}Create KEV Pack</button>`)}
      ${K.card('Actor activity vs. your prevention', chartSlot({ type: 'line', labels: ['W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'W7', 'W8'], h: 130, yMax: 100, suffix: '%', series: [{ name: 'Threat activity', data: [32, 36, 41, 39, 47, 52, 55, 58], color: '#ef4444' }, { name: 'Your prevention', data: [61, 60, 63, 59, 62, 58, 60, 58], color: '#10b981' }] }), '<div class="legend"><span><i style="background:#ef4444"></i>Activity</span><span><i style="background:#10b981"></i>Prevention</span></div>')}
    </div></div>` +
  sec('Endpoint posture', viewAll('nav', 'agents', 'Open agents →')) +
  `<div class="grid g3">
    <div class="card ep-card"><div class="row between"><div class="lbl-s">ONLINE / OFFLINE</div><span class="live-dot" style="margin:0"></span></div>
      <div class="row" style="gap:18px;align-items:center;margin-top:8px"><span class="ring-n">${ep_ring(96, '#10b981')}<b>96%</b></span><div><div class="ep-big"><span style="color:var(--green)">412</span> / <span style="color:var(--red)">16</span></div><div class="muted" style="font-size:12px">428 total agents</div></div></div>
      <div style="margin-top:10px">${chartSlot({ type: 'spark', data: [405, 409, 411, 407, 410, 412, 408, 411, 413, 410, 412, 412], color: '#10b981', h: 36 })}</div><div class="muted" style="font-size:11px">agents online, last 24 h</div></div>
    <div class="card ep-card"><div class="lbl-s">LIFECYCLE</div>${K.donut([{ label: 'Active', value: 412, color: '#10b981' }, { label: 'Restricted', value: 8, color: '#f59e0b' }, { label: 'Quarantined', value: 3, color: '#ef4444' }, { label: 'Retired', value: 5, color: '#64748b' }], 'agents', 150, '412')}</div>
    <div class="card ep-card"><div class="lbl-s">HEALTH BY GROUP</div><div style="margin-top:10px">${K.hbars(D.AGENT_GROUPS.slice(1).map(([n, c], i) => [n, [96, 100, 88, 75, 100, 90][i], ['green', 'green', 'amber', 'red', 'green', 'green'][i]]))}</div></div>
  </div>` +
  `<div class="row between sec-row"><h4 class="sec-label" style="margin:0">Readiness trends</h4><span class="rt-pills"><span class="up">▲ ${RT.filter(r => r[3] === 'up').length} improved</span><span class="down">▼ ${RT.filter(r => r[3] === 'down').length} regressed</span><span class="flat">${RT.length} actors tracked</span></span></div>` +
  `<div class="grid g-side"><div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Threat actor prevention trend</h2></div>${table(['Threat actor', 'Prevention', 'Trend', 'History', 'Runs'], RT.map(([n, v, d, t, r, hist]) => `<tr data-act="actorOpen" data-a="${n}"><td><div class="row" style="gap:10px"><span class="ta-av sm">${initials(n)}</span><b>${n}</b></div></td><td style="min-width:150px">${K.prog(v, K.pct(v))}</td><td>${t === 'up' ? `<span class="chip-up">▲ +${d}</span>` : t === 'down' ? `<span class="chip-down">▼ −${d}</span>` : '<span class="chip-flat">no change</span>'}</td><td style="min-width:90px">${miniLine(hist, t === 'down' ? '#ef4444' : t === 'up' ? '#10b981' : '#64748b')}</td><td class="muted num">${r} run${r > 1 ? 's' : ''}</td></tr>`))}</div>
    ${K.card('Prevention by actor', K.hbars(RT.map(r => [r[0], r[1], K.pct(r[1])])) + `<div class="muted" style="font-size:11.5px;margin-top:10px">Target 90% · latest validated run per actor</div>`)}</div>` +
  `<div class="grid g-side mt">
    ${K.card('Posture score', `<div class="row" style="gap:28px;flex-wrap:wrap;align-items:center">${gauge(71, '#3b82f6')}<div class="grow" style="min-width:230px"><div class="grid g2" style="gap:14px"><div><div class="muted" style="font-size:11px;letter-spacing:.06em">TREND</div><b style="font-size:20px;color:var(--amber)">Degrading</b></div><div style="text-align:right"><div class="muted" style="font-size:11px;letter-spacing:.06em">VS TARGET</div><b style="font-size:20px;color:var(--amber)">−19 pts</b> <span class="muted" style="font-size:11px">target 90</span></div></div><div class="pbars">${[['10/21', 68], ['10/22', 61], ['10/23', 66], ['10/23', 49], ['10/23', 47], ['10/24', 71]].map(([d, v]) => `<div><i style="height:${v * 0.8}px;background:var(--${v >= 60 ? 'amber' : 'red'})" title="${v}%"></i><span>${d}</span></div>`).join('')}</div><p class="muted" style="font-size:12px;margin:8px 0 0">Prevention across the last 6 validated runs.</p></div></div>`)}
    ${K.card('Control effectiveness', `<div class="row" style="gap:18px;align-items:center;flex-wrap:wrap">${K.donut([{ label: 'Prevented', value: 219, color: '#10b981' }, { label: 'Detected only', value: 61, color: '#3b82f6' }, { label: 'Missed', value: 160, color: '#ef4444' }], 'PREVENTED', 150, '58%')}</div><div class="muted" style="font-size:11.5px;margin:6px 0 12px">Detected-only appears once a SIEM/EDR integration is reporting alerts.</div><div class="legend" style="margin-bottom:10px"><span><i style="background:#10b981"></i>Prevented</span><span><i style="background:#3b82f6"></i>Detected</span><span><i style="background:#ef4444"></i>Missed</span></div>` + CE.map(([n, a, b, c]) => `<div class="ce-row"><span>${n}</span><div class="ce-bar"><i style="width:${a}%;background:#10b981" title="Prevented ${a}%"></i><i style="width:${b}%;background:#3b82f6" title="Detected ${b}%"></i><i style="width:${c}%;background:#ef4444" title="Missed ${c}%"></i></div><b class="mono">${100 - c}%</b></div>`).join(''))}
  </div>
  <div class="grid g2 mt">
    ${K.card('<span class="live-dot"></span> Live campaigns', (lc.length ? lc.map(c => `<div class="check-row hov-row" data-act="openCampaign" data-a="${c.id}"><div class="grow"><b style="font-weight:500">${c.name}</b><div class="muted" style="font-size:12px">${c.scope} · ${c.phase}</div><div style="margin-top:8px">${bar(56, 'cyan')}</div></div>${st(c.status)}</div>`).join('') : '<div class="muted">No campaigns running.</div>'), viewAll('nav', 'campaigns'))}
    ${K.card('Top exposure gaps', D.FINDINGS.filter(f => f.status !== 'Closed').slice(0, 5).map(f => `<div class="check-row hov-row" data-act="openFinding" data-a="${f.id}">${sev(f.sev)}<div class="grow"><b style="font-weight:500">${f.title}</b><div class="muted" style="font-size:12px">${f.asset} · open ${f.age}</div></div></div>`).join(''), viewAll('nav', 'findings'))}
  </div>
  <div class="grid g2 mt">
    <div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Recent runs</h2><div class="actions">${viewAll('nav', 'runs')}</div></div>${table(['Run', 'Target', { t: 'Status' }], runs.map(r => `<tr data-act="openRun" data-a="${r.id}"><td><div>${r.name}</div><div class="mono muted" style="font-size:11px">${r.id}</div></td><td class="muted">${r.target}</td><td>${st(r.status)}</td></tr>`))}</div>
    <div class="card pad0"><div class="card-hd" style="padding:14px 16px 0"><h2>Top failing techniques</h2><div class="actions">${viewAll('nav', 'attack-coverage')}</div></div>${table(['Technique', 'Failures', 'Coverage'], FAILING.map(([id, n, f, c]) => `<tr data-act="techDetail" data-a="${id}"><td><div>${n}</div><div class="mono muted" style="font-size:11px">${id}</div></td><td>${tag(f + '×', 'red')}</td><td style="min-width:130px">${K.prog(c, K.pct(c))}</td></tr>`))}</div>
  </div>
  <div class="grid g-side mt">
    ${K.card('Attack flow', chartSlot({ type: 'bar', stacked: true, labels: FLOW.map(f => f[0]), h: 210, series: [{ name: 'Prevented', color: '#10b981', data: FLOW.map(f => f[1]) }, { name: 'Detected', color: '#3b82f6', data: FLOW.map(f => f[2]) }, { name: 'Missed', color: '#ef4444', data: FLOW.map(f => f[3]) }] }), '<div class="legend"><span><i style="background:#10b981"></i>Prevented</span><span><i style="background:#3b82f6"></i>Detected</span><span><i style="background:#ef4444"></i>Missed</span></div>')}
    ${K.card('Ransomware readiness', `<div class="row" style="gap:16px;align-items:center;margin-bottom:12px"><div class="rr-score">72<small>/100</small></div><div class="grow muted" style="font-size:12px">Readiness from the last 3 ransomware drills. Weakest point: lateral spread containment.</div></div>` + RANSOM.map(([t, s]) => `<div class="check-row"><span class="dot" style="background:var(--${s === 'pass' ? 'green' : s === 'warn' ? 'amber' : 'red'});box-shadow:none"></span><span class="grow">${t}</span>${st(s === 'pass' ? 'Passed' : s === 'warn' ? 'Warning' : 'Failed')}</div>`).join('') + `<button class="btn primary block" style="margin-top:12px" data-act="runDrill">${ic('play')}Run Drill</button>`)}
  </div>
  ${K.card('ATT&CK tactic coverage', `<div class="grid g2" style="column-gap:32px">${TACS.map(([n, v]) => `<div class="hbar-row"><span>${n}</span>${bar(v, K.pct(v))}<span class="v">${v}%</span></div>`).join('')}</div>`, viewAll('nav', 'coverage', 'Open matrix →'), 'mt')}
  <div class="mt">${tail}</div>`;
};

A.newSim = () => AUD.go('scenarios');
A.kevPack = () => modal(mhd('Create KEV Pack', 'bolt') + `<div class="modal-bd"><p class="muted" style="margin-top:0">Builds a scenario pack from the CISA Known Exploited Vulnerabilities catalogue, limited to products present in your estate.</p><div class="field"><label>Source</label><select class="select"><option>CISA KEV — last 30 days (14 CVEs)</option><option>CISA KEV — last 90 days (41 CVEs)</option><option>CISA KEV — ransomware-linked only (9 CVEs)</option></select></div><div class="field"><label>Scope</label><div class="chips"><button class="chip on">Products in my estate</button><button class="chip">All KEV entries</button></div></div><div class="alert info">${ic('bell')}<div>14 CVEs map to 6 deployed products. The pack is created as a draft and must be signed before it can run.</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="kevGo">${ic('plus')}Create pack</button></div>`, 'lg');
A.kevGo = () => { AUD.closeModal(); toast('KEV pack created', '6 draft scenarios · awaiting signature', 'info'); };
A.actorOpen = d => {
  const a = ACTORS.find(x => x[0] === d.a) || [d.a, 'Medium', 33], r = RT.find(x => x[0] === d.a);
  dr(a[0], 'Threat actor · relevance ' + a[2], 'priority', `<div class="row between mb">${tag(a[1], a[1] === 'High' ? 'amber' : 'blue')}${r ? `<span class="muted">Last prevention ${r[1]}%</span>` : ''}</div>
    ${K.hbars([['Sector targeting', Math.min(98, a[2] * 2 + 8), 'amber'], ['Exposure match', Math.min(95, a[2] * 2 - 4), 'amber'], ['Validated gaps', Math.min(90, a[2] + 30), 'red'], ['Recent activity', Math.min(97, a[2] * 2 + 12), 'amber']])}
    <h4 style="margin:18px 0 8px">Linked scenarios</h4><div class="chips"><button class="chip" data-act="nav" data-a="scenarios">Kill chain emulation</button><button class="chip" data-act="nav" data-a="scenarios">Initial access variants</button></div>`,
    `<button class="btn" data-act="nav" data-a="threat-priority">Open prioritization</button><button class="btn primary" data-act="nav" data-a="scenarios">${ic('play')}Run emulation</button>`);
};
A.openCompliance = () => { S.tab = S.tab || {}; S.tab.reports = 'compliance'; AUD.go('reports'); };
A.fwOpen = d => {
  const [n, b, v, t, cov, p, f, u] = FW[+d.a];
  const doms = ['Access control', 'Logging & monitoring', 'Incident response', 'Network security', 'Data protection', 'Vulnerability mgmt'];
  dr(n, b, 'shield', `<div class="row between mb"><span style="font-size:28px;font-weight:700">${v}%</span>${tag(p + ' pass · ' + f + ' fail · ' + u + ' untested', v >= 80 ? 'green' : 'amber')}</div>${bar(v, v >= 80 ? 'green' : v >= 72 ? 'cyan' : 'amber')}
    <h4 style="margin:18px 0 10px">By control family</h4>${K.hbars(doms.map((d2, i) => [d2, Math.max(40, Math.min(96, v + [9, -12, 4, -6, 7, -15][i])), '']).map(([a, c]) => [a, c, K.pct(c)]))}
    <div class="alert info" style="margin-top:14px">${ic('bell')}<div>Scores come from validated scenario results mapped to ${n} controls. Evidence packs are generated from the Reports page.</div></div>`,
    `<button class="btn primary" data-act="openCompliance">${ic('report')}Open compliance report</button>`);
};
A.runDrill = () => modal(mhd('Run ransomware drill', 'play') + `<div class="modal-bd"><div class="field"><label>Scenario</label><select class="select"><option>Akira Kill Chain — Ransomware Emulation</option><option>Ransomware Canary (safe)</option><option>Mass-encryption detection drill</option></select></div><div class="field"><label>Target group</label><select class="select"><option>File Servers (18)</option><option>Finance Workstations (2)</option></select></div><div class="alert warn">${ic('alert')}<div>Drills use a safe encryptor on canary files only. No production data is modified.</div></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="drillGo">${ic('play')}Start drill</button></div>`, 'lg');
A.drillGo = () => { AUD.closeModal(); toast('Drill started', 'RUN-5522 · results in about 12 minutes'); AUD.go('runs'); };
})();
