// Real-console parity, part 2 — Visibility: Coverage, Variants, AD Coverage, Email.
(() => {
const { S, P, A, h, toast, modal } = AUD;
const { tag, bar, table } = h;
const K = KIT, { ring, tile, wrap, sec } = RL;
const chips = (key, def, opts) => `<div class="chips">${opts.map(([v, l, n]) => `<button class="chip ${(S[key] || def) === v ? 'on' : ''}" data-act="set" data-a="${key}" data-b="${v}">${l}${n !== undefined ? ` <span class="cnt">${n}</span>` : ''}</button>`).join('')}</div>`;

// ---------- Coverage ----------
wrap('coverage', () => {
  const tac = [['collection', 2], ['command-and-control', 2], ['credential-access', 4], ['defense-evasion', 4], ['discovery', 4], ['execution', 3], ['exfiltration', 2], ['impact', 2], ['initial-access', 2], ['lateral-movement', 2], ['persistence', 3], ['privilege-escalation', 2]];
  const lib = [['T1003', 'OS Credential Dumping', 'credential-access', 3, 0, 0, 0], ['T1003.001', 'LSASS Memory', 'credential-access', 14, 0, 0, 0], ['T1021.001', 'Remote Desktop Protocol', 'lateral-movement', 7, 0, 0, 0], ['T1059.001', 'PowerShell', 'execution', 17, 0, 0, 0], ['T1070.001', 'Clear Windows Event Logs', 'defense-evasion', 12, 0, 0, 0], ['T1486', 'Data Encrypted for Impact', 'impact', 17, 0, 0, 0], ['T1490', 'Inhibit System Recovery', 'impact', 23, 0, 0, 0], ['T1547.001', 'Registry Run Keys', 'persistence', 10, 0, 0, 0], ['T1562.001', 'Disable or Modify Tools', 'defense-evasion', 29, 0, 0, 0], ['T1567.002', 'Exfiltration to Cloud Storage', 'exfiltration', 16, 0, 0, 0]];
  const threats = [['FIN7 new PowerShell loader', '23/10/2026', 3], ['APT41 supply-chain intrusion', '22/10/2026', 3], ['APT36 credential harvesting', '17/10/2026', 4], ['Qakbot resurgence via malspam', '16/10/2026', 4], ['Scattered Spider help-desk social engineering', '15/10/2026', 3], ['LockBit affiliate campaign', '10/10/2026', 4], ['Sandworm wiper activity', '09/10/2026', 2], ['APT29 spearphishing wave against government', '05/10/2026', 5], ['Lazarus crypto-theft toolkit', '02/10/2026', 4], ['Akira ransomware targets VPN appliances', '02/10/2026', 3]];
  const src = S.libSrc || 'All', rows = lib.filter(r => src === 'All' || (src === 'BAS' && r[3]) || (src !== 'Multi-source' && src !== 'BAS' && r[4 + ['ART', 'Emu', 'Atomic'].indexOf(src)]));
  return `<div class="row" style="gap:10px;flex-wrap:wrap;margin-bottom:12px">${K.select('covSc', 'All scenarios', ['Akira Kill Chain', 'APT29 Kill Chain', 'Full Security Posture Scan', 'LOLBin Execution Coverage'])}${K.select('covAg', 'All agents', ['FIN-WS-01', 'ENG-WS-02', 'DC-01', 'DMZ-WEB-01', 'ENG-LNX-01'])}<button class="btn" data-act="toast" data-a="Refreshed" data-b="Coverage analytics recomputed">${ic('refresh')}Refresh</button><button class="btn" data-act="toast" data-a="Export layer" data-b="Coming soon" data-c="info">${ic('download')}Export layer · soon</button><button class="btn primary" data-act="toast" data-a="Test coverage gaps" data-b="Queued 14 untested techniques">▶ Test coverage gaps</button></div>
  <div class="grid g4">${tile('target', 'Techniques attempted', 32, '44 runs analysed', 'accent')}${tile('shield', 'Prevented', 32, '100% prevention rate', 'green')}${tile('eye', 'Detected only', 0, 'EDR / SIEM alerted, not blocked', 'amber')}${tile('alert', 'Missed', 0, 'No prevention, no detection', 'red')}</div>
  <div class="grid g-side mt">${K.card('By tactic', chartSlot({ type: 'bar', stacked: true, labels: tac.map(t => t[0].replace('command-and-control', 'c2').replace('privilege-escalation', 'priv-esc').replace('lateral-movement', 'lateral').replace('credential-access', 'cred')), h: 230, series: [{ name: 'Prevented', color: '#10b981', data: tac.map(t => t[1]) }, { name: 'Detected', color: '#f59e0b', data: tac.map(() => 0) }, { name: 'Missed', color: '#ef4444', data: tac.map(() => 0) }] }), '<div class="legend"><span><i style="background:#10b981"></i>Prevented</span><span><i style="background:#f59e0b"></i>Detected only</span><span><i style="background:#ef4444"></i>Missed</span></div>')}
    <div class="col">${K.card('Prevention vs detection', `<div class="row" style="gap:20px;justify-content:space-around">${[['Prevention rate', 100], ['Detection coverage', 100]].map(([l, v]) => `<div style="text-align:center">${ring(v, '#10b981', 92)}<div class="muted" style="font-size:12px;margin-top:6px">${l}</div></div>`).join('')}</div>`)}
    ${K.card('Missed techniques — prioritize these', `<div class="ok-state">${ic('check')}<b>No gaps detected</b><div class="muted">Every attempted technique was prevented or detected.</div></div>`)}</div></div>
  <div class="grid g2 mt">${K.card('Privilege tier coverage', `<div class="row" style="gap:18px;align-items:center">${ring(57, '#f59e0b', 84)}<div><div class="lbl-s">INHERITED</div><div class="rt-val">201 / 348</div><div class="muted" style="font-size:12px">prevented · last 50 runs</div></div></div>${table(['Tier', 'Attempted', 'Prevented', 'Missed', 'Rate'], [['Inherited', 348, 201, 147, 57]].map(r => `<tr><td>${r[0]}</td><td class="num">${r[1]}</td><td class="num">${r[2]}</td><td class="num">${r[3]}</td><td>${K.prog(r[4], 'amber')}</td></tr>`))}`)}
    ${K.card('Privilege coverage gaps — tested elevated only', `<div class="ok-state">${ic('check')}<b>All annotated techniques tested at user tier</b><div class="muted">Gaps are techniques never run as a standard user. Run these at user tier so controls don't rely only on privilege barriers.</div></div>`)}</div>
  ${K.card('Tracked threats', `<div class="grid g2">${threats.map(([n, d, t]) => `<div class="thr-row"><div class="ta-av sm">${n[0]}</div><div class="grow"><b>${n}</b><div class="muted" style="font-size:12px">Last seen ${d} · ${t} techniques tracked, 0 with executable content</div></div>${tag('No content yet', 'amber')}</div>`).join('')}</div>`, '<span class="muted" style="font-size:12px">10 active threats shown</span>', 'mt')}
  ${K.card('Unified technique library', `<p class="muted" style="margin-top:0;font-size:12.5px">152 unique techniques — BAS 152 · ART 0 · Emu 0 · Atomic 0. Each row is one ATT&CK technique; counts show execution variants per source, not whether any were run.</p><div class="row between" style="margin-bottom:10px;gap:10px;flex-wrap:wrap">${chips('libSrc', 'All', [['All', 'All'], ['BAS', 'BAS'], ['ART', 'ART'], ['Emu', 'Emu'], ['Atomic', 'Atomic'], ['Multi-source', 'Multi-source']])}<div class="legend"><span><b>BAS</b> native step</span><span><b>ART</b> Atomic Red Team</span><span><b>Emu</b> CTID ability</span><span><b>Atomic</b> Caldera plugin</span></div></div>${table(['Technique', 'Name', 'Tactic', 'BAS', 'ART', 'EMU', 'ATOMIC', 'Total', 'Sources'], rows.map(r => `<tr><td class="mono">${r[0]}</td><td>${r[1]}</td><td>${tag(r[2], 'blue')}</td><td class="num"><b>${r[3]}</b></td><td class="num muted">${r[4] || '—'}</td><td class="num muted">${r[5] || '—'}</td><td class="num muted">${r[6] || '—'}</td><td class="num">${r[3]}</td><td class="muted">1 src</td></tr>`))}<div class="muted" style="font-size:12px;margin-top:8px">Showing ${rows.length} of 152 techniques</div>`, '', 'mt')}`;
});

// ---------- Variants ----------
// ---- Variant sources: Atomic Red Team and Caldera, each with its own technique list ----
const V_ART = [['T1003.001', 'LSASS memory dump', 'credential-access', 14], ['T1053.005', 'Scheduled task via schtasks', 'execution', 9], ['T1547.001', 'Registry Run key persistence', 'persistence', 10], ['T1059.001', 'PowerShell encoded command', 'execution', 17], ['T1070.001', 'Clear Windows event logs', 'defense-evasion', 12], ['T1218.011', 'Rundll32 proxy execution', 'defense-evasion', 6], ['T1548.002', 'UAC bypass (eventvwr)', 'privilege-escalation', 9], ['T1105', 'Ingress tool transfer (certutil)', 'command-and-control', 8], ['T1490', 'Inhibit system recovery (vssadmin)', 'impact', 23], ['T1005', 'Data from local system', 'collection', 10], ['T1562.001', 'Disable or modify security tools', 'defense-evasion', 29], ['T1021.002', 'SMB admin share access', 'lateral-movement', 8]];
const V_CAL = [['T1087.002', 'Enumerate domain accounts (Caldera)', 'discovery', 6], ['T1018', 'Remote system discovery', 'discovery', 5], ['T1021.001', 'RDP lateral movement ability', 'lateral-movement', 7], ['T1059.003', 'Windows command shell ability', 'execution', 6], ['T1558.003', 'Kerberoast ability', 'credential-access', 4], ['T1569.002', 'Service execution ability', 'execution', 5], ['T1074.001', 'Local data staging', 'collection', 4], ['T1041', 'Exfiltration over C2 channel', 'exfiltration', 6]];
const vSrc = () => S.vSrc || 'Atomic Red Team';
const vList = () => (vSrc() === 'Caldera' ? V_CAL : V_ART).filter(t => !S.vTc || t[2] === S.vTc);
const vSel = () => (S.vSel = S.vSel || {})[vSrc()] || (S.vSel[vSrc()] = []);
const varPanels = () => {
  const mode = S.vMode || 'Individual', src = vSrc(), all = src === 'Caldera' ? V_CAL : V_ART, list = vList(), sel = vSel(), n = all.reduce((x, t) => x + t[3], 0);
  const srcSeg = key => `<div class="seg">${['Atomic Red Team', 'Caldera'].map(m => `<button class="${src === m ? 'on' : ''}" data-act="set" data-a="vSrc" data-b="${m}">${m}</button>`).join('')}</div>`;
  return sweepCard() + `<div class="grid g2 mt">${K.card('Full variant sweep', `<div class="lbl-s">BASE SOURCE</div><div style="margin:6px 0 10px">${srcSeg()}</div>
      <p class="muted" style="margin-top:0;font-size:12.5px">Run all ${all.length} Windows-runnable ${src === 'Caldera' ? 'Caldera abilities' : 'ART techniques'} sequentially · ${n.toLocaleString()} variants total · runs technique by technique with live progress.</p>
      <div class="seg" style="margin-bottom:10px">${['Individual', 'Group(s)'].map(m => `<button class="${mode === m ? 'on' : ''}" data-act="set" data-a="vMode" data-b="${m}">${m}</button>`).join('')}</div>
      <div class="row" style="gap:10px;flex-wrap:wrap">${K.select('vAg', mode === 'Individual' ? 'Select agent…' : 'Select group…', mode === 'Individual' ? ['FIN-WS-01', 'ENG-WS-02', 'DC-01'] : ['Finance', 'Engineering', 'Production'])}${K.select('vSw', 'All variants', ['All variants', 'Adaptive (stop on bypass)', 'Advanced Pack'])}<button class="btn primary" data-act="vsStart" data-a="sweep" ${S.sweep && S.sweep.running ? 'disabled' : ''}>▶ Start sweep</button></div>`)}
    ${K.card('Run variants', `<div class="row" style="gap:10px;flex-wrap:wrap;margin-bottom:10px">${K.select('vTg', 'All agents', ['FIN-WS-01', 'ENG-WS-02', 'DC-01'])}${K.select('vTc', `All tactics (${all.length} techniques)`, [...new Set(all.map(t => t[2]))])}</div>
      <div class="lbl-s">BASE SOURCE</div><div style="margin:6px 0 10px">${srcSeg()}</div>
      <div class="row between"><div class="lbl-s">TECHNIQUES (${list.length})</div><span style="font-size:12.5px"><a class="lg-link" data-act="vtAll">All</a> · <a class="lg-link" data-act="vtNone">None</a></span></div>
      <div class="rw-list" style="max-height:200px">${list.length ? list.map(t => `<label class="rw-item"><input type="checkbox" ${sel.includes(t[0]) ? 'checked' : ''} data-act="vtTog" data-a="${t[0]}"><span class="mono" style="color:var(--accent-hi)">${t[0]}</span><span class="grow">${t[1]}</span><span class="muted" style="font-size:11.5px">${t[3]} variants</span></label>`).join('') : '<div class="muted" style="padding:14px">No techniques match</div>'}</div>
      <div class="lbl-s" style="margin-top:12px">MODE</div><div class="col" style="gap:6px;margin:6px 0 12px;font-size:13px"><label><input type="radio" name="vm" ${S.vAdapt ? '' : 'checked'} data-act="vsMode" data-a="seq"> Sequential (all variants)</label><label><input type="radio" name="vm" ${S.vAdapt ? 'checked' : ''} data-act="vsMode" data-a="adapt"> Adaptive (stop on first bypass)</label><label><input type="checkbox" ${S.vAdv ? 'checked' : ''} data-act="vsAdv"> Include Advanced Pack (AMSI bypass)</label></div>
      <button class="btn primary" data-act="vsStart" data-a="run" ${S.sweep && S.sweep.running ? 'disabled' : ''}>▶ Run${sel.length ? ` ${sel.length} technique${sel.length > 1 ? 's' : ''}` : ''}</button>`)}</div>`;
};
Object.assign(A, {
  vtTog: d => { const l = vSel(), i = l.indexOf(d.a); i < 0 ? l.push(d.a) : l.splice(i, 1); const y = document.querySelector('#content').scrollTop; S.keepScroll = true; AUD.render(); },
  vtAll: () => { S.vSel[vSrc()] = vList().map(t => t[0]); S.keepScroll = true; AUD.render(); },
  vtNone: () => { S.vSel[vSrc()] = []; S.keepScroll = true; AUD.render(); },
  vtRun: () => { const n = vSel().length; n ? toast('Variants running', `${n} ${vSrc()} technique${n > 1 ? 's' : ''} queued`, 'success') : toast('Nothing selected', 'Select an agent and at least one technique', 'info'); }
});

wrap('variants', () => {
  const cov = [['T1547.001', 'persistence', 10, 5, 5, 0, 'Web Protocols was not prevented'], ['T1218.011', 'defense-evasion', 6, 2, 4, 0, 'Data Encrypted for Impact was not prevented'], ['T1548.002', 'privilege-escalation', 9, 4, 5, 0, '[withheld: credential-access output is not exported]'], ['T1053.005', 'execution', 10, 5, 5, 0, 'Data Encrypted for Impact was not prevented'], ['T1059.001', 'execution', 9, 4, 5, 0, 'Remote System Discovery was not prevented'], ['T1105', 'command-and-control', 8, 4, 4, 0, 'Data from Local System was not prevented'], ['T1490', 'impact', 9, 4, 5, 0, 'Registry Run Keys was not prevented'], ['T1005', 'collection', 10, 6, 4, 0, 'Exploit Public-Facing Application was not prevented']];
  cov.unshift(...(S.sweepRows || []));
  const mode = S.vMode || 'Individual';
  return `<div class="grid g4">${tile('layers', 'Executed variants', 51, 'across all agents', 'accent')}${tile('grid', 'Total variants', '1,848', '56 ART tests × 32 techniques × encoding / privilege / context', 'cyan')}${tile('box', 'Custom payload families', 19, '19 families × 56 variants = 1,064', 'purple')}${tile('star', 'Custom-enhanced techniques', 6, 'of 32 ART techniques', 'green')}</div>
  ${varPanels()}
  ${K.card('Bypass coverage', table(['Technique', 'Tactic', 'Total', 'Prevented', 'Allowed', 'Errors', 'First bypass'], cov.map(r => `<tr><td class="mono">${r[0]}</td><td>${tag(r[1], 'blue')}</td><td class="num">${r[2]}</td><td class="num" style="color:var(--green)">${r[3]}</td><td class="num" style="color:var(--red)">${r[4]}</td><td class="num muted">${r[5]}</td><td class="muted" style="font-size:12px">${r[6]}</td></tr>`)) + `<div class="mt">${K.hbars(cov.map(r => [r[0], Math.round(r[3] / r[2] * 100), K.pct(r[3] / r[2] * 100)]))}</div>`, '<span class="muted" style="font-size:12px">Aggregate bypass results across all variant runs</span>', 'mt')}`;
});


// ---- Sweep engine: runs technique by technique with live progress and feeds the bypass table ----
const vHash = str => { let x = 2166136261; for (const c of str) x = Math.imul(x ^ c.charCodeAt(0), 16777619) >>> 0; return x; };
const sweepCard = () => {
  const w = S.sweep; if (!w) return '';
  const done = w.res.length, pct = Math.round(done / w.list.length * 100), prev = w.res.reduce((a, r) => a + r[3], 0), alw = w.res.reduce((a, r) => a + r[4], 0), tot = prev + alw;
  const cur = w.list[Math.min(done, w.list.length - 1)];
  return `<div class="card mt sweep-card ${w.running ? 'run' : ''}"><div class="row between" style="gap:12px;flex-wrap:wrap"><div class="row" style="gap:10px">${w.running ? '<span class="live-dot" style="margin:0"></span>' : ic(w.stopped ? 'alert' : 'check')}<b>${w.running ? 'Sweep in progress' : w.stopped ? 'Sweep stopped at first bypass' : 'Sweep complete'}</b><span class="muted" style="font-size:12.5px">${w.src} · ${w.agent} · ${w.adapt ? 'adaptive' : 'sequential'}${w.adv ? ' · advanced pack' : ''}</span></div>${w.running ? '<button class="btn sm danger" data-act="vsStop">Stop</button>' : '<button class="btn sm" data-act="vsClear">Dismiss</button>'}</div>
    <div style="margin:12px 0 6px">${h.bar(pct, w.running ? '' : (alw ? 'amber' : 'green'))}</div>
    <div class="row between" style="font-size:12.5px;flex-wrap:wrap;gap:8px"><span>${w.running ? `Running <span class="mono" style="color:var(--accent-hi)">${cur[0]}</span> — ${cur[1]}` : `${done} of ${w.list.length} techniques finished`}</span><span class="muted">${done} / ${w.list.length} techniques · ${pct}%</span></div>
    <div class="grid g4 mt" style="gap:10px">${[['Variants run', tot, ''], ['Prevented', prev, 'green'], ['Allowed (bypass)', alw, 'red'], ['Prevention rate', tot ? Math.round(prev / tot * 100) + '%' : '—', tot && prev / tot >= .7 ? 'green' : 'amber']].map(([l, v, c]) => `<div class="mini-metric"><div class="t"><span>${l}</span><b ${c ? `style="color:var(--${c})"` : ''}>${v}</b></div></div>`).join('')}</div></div>`;
};

// ---- "Preview & Confirm — Variant Full Sweep" (real console shows this before dispatching anything) ----
const RISK = ['LOW', 'MODERATE', 'ADVANCED'], ENC = ['plain', 'base64', 'utf-16le', 'xor-0x5a'], CTX = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'in-memory'], PRIVS = ['user', 'admin'];
const vpFilter = list => list.filter(t => (!S.vpTac || t[2] === S.vpTac) && (!S.vpQ || (t[0] + ' ' + t[1]).toLowerCase().includes(S.vpQ.toLowerCase())));
const vpRows = (key, src, list, col) => {
  const hd = `<div class="vp-sec" data-act="vpCol" data-a="${key}"><span>${col ? '▸' : '▾'}</span><b>${src}</b><span class="muted">${list.length}</span></div>`;
  if (col) return hd;
  if (!list.length) return hd + `<div class="muted" style="padding:12px">No ${src} techniques match</div>`;
  return hd + list.map(t => { const k = key + ':' + t[0], open = S.vpOpen === k;
    return `<div class="vp-row" data-act="vpRow" data-a="${k}"><span>${open ? '▾' : '▸'}</span><span class="mono" style="color:var(--accent-hi)">${t[0]}</span><span class="grow">${t[1]}</span><span class="muted" style="font-size:11.5px">${t[2]} · ${t[3]} variants</span></div>` +
      (open ? `<div class="vp-var">${Array.from({ length: 4 }, (_, i) => { const h2 = vHash(t[0] + i), risk = RISK[h2 % 3]; return `<div class="vp-v"><span>Encoding: <b>${ENC[h2 % 4]}</b></span><span>Context: <b>${CTX[(h2 >>> 3) % 4]}</b></span><span>Privilege: <b>${PRIVS[(h2 >>> 5) % 2]}</b></span><span style="color:var(--${risk === 'ADVANCED' ? 'red' : risk === 'MODERATE' ? 'amber' : 'green'})">${risk}</span></div>`; }).join('')}</div>` : ''); }).join('');
};
const vpDraw = () => {
  const src = vSrc(), art = vpFilter(V_ART), cal = vpFilter(V_CAL), nAg = (S.vMode === 'Group(s)') ? (S.vAg === 'Production' ? 4 : S.vAg === 'Engineering' ? 3 : 2) : 1;
  const tacs = [...new Set(V_ART.concat(V_CAL).map(t => t[2]))].sort();
  const body = `<div class="muted" style="font-size:12.5px;margin-bottom:12px">Targeting ${nAg} agent(s). ~${V_ART.length} ART technique(s) + ~${V_CAL.length} Caldera ability/technique(s) dispatched sequentially, ${V_ART.reduce((a, t) => a + t[3], 0) + V_CAL.reduce((a, t) => a + t[3], 0)} variants in total.</div>
    <div class="row" style="gap:10px;margin-bottom:8px"><select class="select" data-change="vpTac"><option value="">All tactics</option>${tacs.map(t => `<option ${S.vpTac === t ? 'selected' : ''}>${t}</option>`).join('')}</select><input class="input grow" placeholder="Search T-ID or name…" value="${S.vpQ || ''}" data-act="vpQ"></div>
    <div class="muted" style="font-size:12px;margin-bottom:6px">${art.length} ART, ${cal.length} Caldera</div>
    <div class="vp-list">${vpRows('art', 'ART', art, S.vpArtCol)}${vpRows('cal', 'Caldera', cal, S.vpCalCol !== false)}</div>`;
  AUD.h.drawer(AUD.h.dhd('Preview & Confirm — Variant Full Sweep', `${src} · ${S.vAg || ''}`, 'layers') + `<div class="drawer-bd">${body}</div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Cancel</button><button class="btn primary" data-act="vpStart">▶ Start Full Sweep</button></div>`, 'wide');
};
Object.assign(A, {
  vpOpen: () => { S.vpTac = ''; S.vpQ = ''; S.vpOpen = null; S.vpArtCol = false; S.vpCalCol = true; vpDraw(); },
  vpCol: d => { if (d.a === 'art') S.vpArtCol = !S.vpArtCol; else S.vpCalCol = S.vpCalCol === false; vpDraw(); },
  vpRow: d => { S.vpOpen = S.vpOpen === d.a ? null : d.a; vpDraw(); },
  vpTac: (d, el) => { S.vpTac = el.value; vpDraw(); },
  vpStart: () => { AUD.h.closeDrawer(); A.vsStart({ a: 'sweep-go' }); }
});
document.addEventListener('input', e => { const t = e.target.closest('[data-act="vpQ"]'); if (!t) return; S.vpQ = t.value; vpDraw(); const i = document.querySelector('[data-act="vpQ"]'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } });
document.head.insertAdjacentHTML('beforeend', '<style>.vp-list{border:1px solid var(--border);border-radius:12px;overflow:hidden}.vp-sec{display:flex;gap:10px;align-items:center;padding:10px 12px;background:var(--elevated);border-bottom:1px solid var(--border);cursor:pointer}.vp-row{display:flex;gap:10px;align-items:center;padding:9px 12px 9px 26px;border-bottom:1px solid var(--border);cursor:pointer;font-size:13px}.vp-row:hover{background:var(--accent-dim)}.vp-var{padding:6px 12px 10px 40px;display:grid;gap:6px;border-bottom:1px solid var(--border)}.vp-v{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;padding:6px 10px;border:1px solid var(--border);border-radius:8px;background:var(--elevated)}</style>');
const sweepStep = () => {
  const w = S.sweep; if (!w || !w.running) { clearInterval(window.__vsTimer); return; }
  const t = w.list[w.res.length], r = vHash(t[0] + w.src), total = t[3], allowed = Math.min(total, (r % 5) + (w.adv ? 1 : 0)), prev = total - allowed;
  const row = [t[0], t[2], total, prev, allowed, 0, allowed ? `Sample result: ${t[1]} was not prevented.` : '—'];
  w.res.push(row); S.sweepRows = [row, ...(S.sweepRows || []).filter(x => x[0] !== t[0])];
  if (w.adapt && allowed) { w.running = false; w.stopped = true; toast('First bypass found', `${t[0]} — ${t[1]}`, 'warn'); }
  else if (w.res.length >= w.list.length) { w.running = false; toast('Sweep complete', `${w.list.length} techniques · ${w.res.reduce((a, x) => a + x[3], 0)} prevented`, 'success'); }
  if (!w.running) { clearInterval(window.__vsTimer); if (w.onDone) w.onDone(w); }
  if (S.route === 'variants') { S.keepScroll = true; AUD.render(); }
};
Object.assign(A, {
  vsMode: d => { S.vAdapt = d.a === 'adapt'; },
  vsAdv: () => { S.vAdv = !S.vAdv; },
  vsStart: d => {
    const src = vSrc(), isSweep = d.a === 'sweep' || d.a === 'sweep-go', confirmed = d.a === 'sweep-go';
    const agent = isSweep ? S.vAg : (S.vTg || 'All agents');
    if (isSweep && !S.vAg) return toast(S.vMode === 'Group(s)' ? 'Select at least one group with a Windows agent — every variant technique requires Windows' : 'Select an agent in the Full Sweep panel first', '', 'warn');
    if (isSweep && S.vMode === 'Group(s)' && S.vAg === 'Engineering') toast('1 non-Windows agent(s) in the selected group(s) were skipped.', '', 'success');
    if (isSweep && !confirmed) return A.vpOpen();
    const list = isSweep ? (src === 'Caldera' ? V_CAL : V_ART) : V_LIST_SEL();
    if (!list.length) return toast('Nothing selected', 'Tick at least one technique to run', 'warn');
    const adapt = isSweep ? /Adaptive/.test(S.vSw || '') : !!S.vAdapt, adv = isSweep ? /Advanced/.test(S.vSw || '') : !!S.vAdv;
    S.sweep = { src, agent, list, res: [], running: true, stopped: false, adapt, adv };
    toast(isSweep ? 'Sweep started' : 'Variants running', `${list.length} ${src} technique${list.length > 1 ? 's' : ''} on ${agent}`, 'success');
    clearInterval(window.__vsTimer); window.__vsTimer = setInterval(sweepStep, 900); S.keepScroll = false; AUD.render();
  },
  variantRun: d => {
    const v = D.VARIANTS.find(x => x.id === d.a); if (!v) return;
    if (S.sweep && S.sweep.running) return toast('A sweep is already running', 'Wait for it to finish or stop it first', 'warn');
    const agent = S.vAg || 'FIN-WS-01';
    const tac = (V_ART.find(t => t[0] === v.family) || [])[2] || 'execution';
    S.sweep = { src: 'Atomic Red Team', agent, list: [[v.family, v.name.split(' — ')[0], tac, v.count]], res: [], running: true, stopped: false, adapt: false, adv: false,
      onDone: w => { const r = w.res[0]; if (!r) return; v.pass = r[3]; v.status = r[4] === 0 ? 'Ready' : r[3] === 0 ? 'Failing' : 'Partial'; } };
    AUD.h.closeDrawer(); toast('Variant set running', `${v.name.split(' — ')[0]} on ${agent}`, 'success');
    clearInterval(window.__vsTimer); window.__vsTimer = setInterval(sweepStep, 900); S.keepScroll = false; AUD.go('variants'); AUD.render(); document.querySelector('#content').scrollTop = 0;
  },
  vsStop: () => AUD.modal(AUD.h.mhd('Stop this sweep?', 'alert') + `<div class="modal-bd">The current technique finishes or is cancelled; no further techniques will be dispatched.</div><div class="modal-ft"><button class="btn" data-act="closeModal">Keep running</button><button class="btn danger" data-act="vsStopYes">Stop sweep</button></div>`, 'sm'),
  vsStopYes: () => { AUD.closeModal(); if (S.sweep) { S.sweep.running = false; S.sweep.stopped = true; } clearInterval(window.__vsTimer); toast('Sweep stopped', `${S.sweep.res.length} techniques completed`, 'info'); AUD.render(); },
  vsClear: () => { S.sweep = null; AUD.render(); }
});
const V_LIST_SEL = () => { const sel = vSel(); return (vSrc() === 'Caldera' ? V_CAL : V_ART).filter(t => sel.includes(t[0])); };

// ---------- AD Coverage ----------
wrap('ad-coverage', () => {
  const caps = [['SPN Enumeration', 'spn-enumerate · T1558.003', 'Kerberoasting', 'Scenario-Composable', 'Composed', 0], ['Kerberoasting TGS-REP Request', 'kerberoast-tgs-request · T1558.003', 'Kerberoasting', 'Scenario-Composable', 'Composed', 1], ['ForceChangePassword ACL Abuse', 'acl-forcechangepassword-abuse', 'ACL', 'Model-Only', 'Not Composed', 1], ['GenericAll ACL Takeover', 'acl-genericall-takeover', 'ACL', 'Model-Only', 'Not Composed', 1], ['ACL Privilege Exposure Audit', 'acl-privilege-exposure-check · T1069', 'ACL', 'Scenario-Composable', 'Composed', 0], ['Configure Resource-Based Constrained Delegation', 'rbcd-configure', 'RBCD', 'Model-Only', 'Not Composed', 1], ['DCSync Directory Replication', 'dcsync · T1003.006', 'DCSync', 'Reusable (Unmapped)', 'Not Composed', 1], ['DCSync Replication-Right Exposure Check', 'dcsync-replication-right-exposure-check', 'DCSync', 'Scenario-Composable', 'Composed', 0], ['ADCS ESC1: Enrollee-Supplied Subject', 'adcs-esc1 · T1649', 'ADCS', 'Model-Only', 'Not Composed', 1], ['ADCS ESC Template Exposure Audit', 'adcs-esc-exposure-check · T1649', 'ADCS', 'Scenario-Composable', 'Composed', 0], ['Unconstrained Delegation TGT Capture', 'kerberos-unconstrained-delegation · T1558', 'Delegation', 'Model-Only', 'Not Composed', 1], ['Trust / SID-History Exposure Audit', 'trust-sid-history-exposure-check · T1134.005', 'Trust', 'Scenario-Composable', 'Composed', 0], ['GPO Abuse: Policy Push to Linked Scope', 'gpo-abuse-linked-scope · T1484.001', 'GPO', 'Model-Only', 'Not Composed', 1], ['GPO Writable-Linked Exposure Audit', 'gpo-abuse-exposure-check · T1484.001', 'GPO', 'Scenario-Composable', 'Composed', 0]];
  const fam = S.adFam || 'All families', con = S.adCon || 'All content';
  const rows = caps.filter(c => (fam === 'All families' || c[2] === fam) && (con === 'All content' || (con === 'Composable' && c[3] === 'Scenario-Composable') || (con === 'Model-only' && c[3] === 'Model-Only') || (con === 'Reusable' && c[3].startsWith('Reusable'))));
  const cc = c => c.startsWith('Scenario') ? 'green' : c.startsWith('Reusable') ? 'cyan' : 'amber';
  return `<div class="card k8s-warn">${ic('alert')} <b>Modeled / content coverage — not validated against real Active Directory.</b> 0 capabilities executed and 0 detection-validated. Content availability and scenario composition do not imply a technique has run against, or been detected in, a real domain.<div class="row" style="gap:8px;margin-top:10px"><button class="btn sm" data-act="toast" data-a="Export PDF" data-b="Preparing AD coverage report">Export PDF</button><button class="btn sm" data-act="toast" data-a="Export JSON" data-b="ad-coverage.json">JSON</button></div></div>
  <div class="grid g3" style="grid-template-columns:repeat(6,minmax(0,1fr))">${[['Capabilities', 28, 'accent'], ['Modeled', 28, 'cyan'], ['Scenario-composed', 10, 'green'], ['Executed vs real AD', 0, 'red'], ['Detection-validated', 0, 'red'], ['Reusable content', 1, 'amber']].map(([l, v, c]) => `<div class="card real-tile" style="--tc:var(--${c});flex-direction:column;align-items:flex-start;gap:6px"><div class="lbl-s">${l.toUpperCase()}</div><div class="rt-val">${v}</div></div>`).join('')}</div>
  <div class="row between mt" style="flex-wrap:wrap;gap:12px"><span class="lbl-s">FAMILY</span>${chips('adFam', 'All families', ['All families', 'ACL', 'ADCS', 'DCSync', 'Delegation', 'GPO', 'Kerberoasting', 'RBCD', 'Trust'].map(x => [x, x]))}${chips('adCon', 'All content', ['All content', 'Composable', 'Reusable', 'Model-only'].map(x => [x, x]))}</div>
  ${K.card('Capabilities', table(['Capability', 'Content', 'Composition', 'Execution', 'Validation', 'Safety'], rows.map(c => `<tr><td><b>${c[0]}</b><div class="mono muted" style="font-size:11px">${c[1]}</div><div class="muted" style="font-size:11px">${c[2]}</div></td><td>${tag(c[3], cc(c[3]))}</td><td>${tag(c[4], c[4] === 'Composed' ? 'green' : '')}</td><td>${tag('Not Executed')}</td><td>${tag('Not Validated')}</td><td>${tag(c[5] ? 'Potentially Destructive' : 'Non-Destructive', c[5] ? 'red' : 'green')}</td></tr>`)) + `<div class="muted" style="font-size:12px;margin-top:8px">Showing ${rows.length} of 28 capabilities · nothing is executed by this view.</div>`, '', 'mt')}`;
});

// ---------- Email ----------
wrap('email', () => {
  const areas = ['A — Sender Identity / Spoofing / Trust', 'B — Phishing / Social Engineering', 'C — Attachments / Content Inspection', 'D — URL / Browser / Post-Delivery Protection', 'E — Outbound Security / DLP', 'F — Mailbox / Identity / Tenant Security', 'G — Detection / IR / Resilience'];
  const sc = [['EG-001', 'Domain spoofing (SPF / DKIM / DMARC)', 6], ['EG-002', 'Executive impersonation', 2], ['EG-003', 'Credential phishing (URL harvesting + rewrite)', 4], ['EG-004', 'Malicious attachment (EICAR, real MIME multipart)', 2], ['EG-005', 'Supplier payment diversion', 2], ['EG-006', 'Sensitive-data leakage (outbound DLP)', 2], ['EG-007', 'External auto-forwarding', 2], ['EG-008', 'Post-delivery threat response', 2], ['EG-009', 'Authentication exception scope', 2], ['EG-010', 'Detection-to-response chain', 2], ['EG-011', 'QR-code lure', 2], ['EG-012', 'PDF with embedded link', 2], ['EG-013', 'Office document with external link', 2], ['EG-014', 'Internal-sender spoof', 2], ['EG-015', 'Reply-chain hijack', 2], ['EG-016', 'Relay-path bypass', 4], ['EG-017', 'Malware-category script attachment', 2], ['EG-018', 'Ransomware stand-in (double extension)', 2], ['EG-019', 'File-type spoofing', 2], ['EG-020', 'Blocked-extension policy', 2]];
  return `<div class="grid g-side">${K.card('Coverage', `<div class="row" style="gap:18px;align-items:center">${ring(100, '#10b981', 92)}<div><div class="rt-val">7/7 areas</div><div class="muted" style="font-size:12px">100% covered</div></div></div><div class="area-list">${areas.map(a => `<div class="area"><span class="dot-ok">${ic('check', 'sm')}</span>${a}</div>`).join('')}</div>`)}
    ${K.card('Time-based metrics', `<div class="grid g2" style="gap:10px">${[['Mean time to detect', '4.2 min', 'green'], ['Mean time to respond', '11 min', 'green'], ['Post-delivery removal', '3.4 min', 'cyan'], ['Longest exposure', '27 min', 'amber']].map(([l, v, c]) => `<div class="mini-metric"><div class="t"><span>${l}</span><b style="color:var(--${c})">${v}</b></div></div>`).join('')}</div>${chartSlot({ type: 'line', labels: ['W1', 'W2', 'W3', 'W4', 'W5', 'W6'], h: 120, suffix: 'm', series: [{ name: 'MTTD', color: '#3b82f6', data: [7.1, 6.4, 5.8, 5.1, 4.6, 4.2] }] })}`)}</div>
  ${K.card('Scenario catalogue', `<div class="eg-grid">${sc.map(([id, n, v]) => `<div class="eg-card hov" data-act="toast" data-a="${id}" data-b="${n}"><div class="row between"><span class="mono" style="color:var(--accent-hi);font-weight:700">${id}</span>${tag(v + ' variants', 'blue')}</div><div style="margin-top:6px;font-size:13px">${n}</div><div class="eg-vars">${['known-good', 'known-bad'].map(x => `<span>${x}</span>`).join('')}</div></div>`).join('')}</div>`, '<span class="muted" style="font-size:12px">20 scenarios · known-good / known-bad pairs</span>', 'mt')}
  ${K.card('Runs', table(['Scenario', 'Status', 'Environment', 'Started', 'Error'], [['EG-001 Domain spoofing', 'Completed', 'staging-mx', '25 Oct 12:30'], ['EG-004 Malicious attachment', 'Completed', 'staging-mx', '24 Oct 09:12'], ['EG-011 QR-code lure', 'Completed', 'prod-mx', '22 Oct 16:45']].map(r => `<tr><td><b>${r[0]}</b></td><td>${tag(r[1], 'green')}</td><td class="mono">${r[2]}</td><td class="muted">${r[3]}</td><td class="muted">—</td></tr>`)), '', 'mt')}`;
});
})();
