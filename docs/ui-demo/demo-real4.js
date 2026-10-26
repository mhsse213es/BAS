// Real-console parity, part 4 — Recommendations, Exercises, Technique Coverage, Threat Prioritization, Agents, Integrations, Settings.
(() => {
const { S, P, A, h, toast, modal } = AUD;
const { tag, bar, table } = h;
const K = KIT, { ring, tile, wrap, sec } = RL;
const chips = (key, def, opts) => `<div class="chips">${opts.map(([v, l, n]) => `<button class="chip ${(S[key] || def) === v ? 'on' : ''}" data-act="set" data-a="${key}" data-b="${v}">${l}${n !== undefined ? ` <span class="cnt">${n}</span>` : ''}</button>`).join('')}</div>`;

// ---------- Recommendations ----------
wrap('recommendations', () => {
  const r = [['T1021.002', 'SMB/Windows Admin Shares', 'lateral-movement', 36, 'Medium', 15, 100, 'Traverses an edge on a domain-compromise or crown-jewel path · Previously failed — remediate before re-testing'], ['T1021.001', 'Remote Desktop Protocol', 'lateral-movement', 31, 'Medium', 15, 100, 'Traverses an edge on a domain-compromise or crown-jewel path in your environment'], ['T1041', 'Exfiltration Over C2 Channel', 'exfiltration', 21, 'Medium', 15, 0, 'Previously failed — remediate before re-testing'], ['T1053.005', 'Scheduled Task', 'persistence', 21, 'Medium', 15, 0, 'Attributed to 15 ATT&CK groups · overdue for testing']];
  const n = S.recN || 'Top 10';
  return `<div class="row between" style="gap:10px;flex-wrap:wrap;margin-bottom:12px"><div class="seg">${['Top 10', 'Top 20', 'Top 50'].map(x => `<button class="${n === x ? 'on' : ''}" data-act="set" data-a="recN" data-b="${x}">${x}</button>`).join('')}</div><div class="row" style="gap:8px"><button class="btn" data-act="toast" data-a="Copied" data-b="${n} scenario techniques copied" data-c="success">${ic('link')}Copy scenario techniques</button><button class="btn" data-act="toast" data-a="Refreshed" data-b="Rankings recomputed">${ic('refresh')}Refresh</button></div></div>
  ${K.card('What to simulate next', table(['Technique', 'Tactic', 'Score', 'Coverage', 'Threat', 'Environment', 'Why'], r.map(x => `<tr><td><b>${x[1]}</b><div class="mono muted" style="font-size:11px">${x[0]}</div></td><td>${tag(x[2], 'blue')}</td><td style="min-width:110px">${K.prog(Math.min(100, x[3] * 2), x[3] > 30 ? 'red' : 'amber')}</td><td>${tag(x[4], 'amber')}</td><td><span class="muted">Recent</span> · ${x[5]} groups</td><td class="num">${x[6] || '—'}</td><td class="muted" style="font-size:12px;max-width:320px">${x[7]}</td></tr>`)), '<span class="muted" style="font-size:12px">Ranked by threat priority, how overdue the technique is, and whether it traverses a real path in your environment</span>')}`;
});

// ---------- Exercises ----------
wrap('exercises', () => {
  const sc = [['Cloud Credential Theft', 'Credential Access', 'high', 4, 9], ['Insider Data Staging', 'Collection', 'medium', 4, 7], ['Lateral Movement via SMB', 'Lateral Movement', 'medium', 4, 6], ['Phishing to Domain Admin', 'Initial Access', 'high', 4, 10], ['Ransomware Precursors', 'Impact', 'critical', 4, 5], ['Web Shell Persistence', 'Persistence', 'high', 4, 11]];
  const plans = [['Ransomware Tabletop + Technical', 2], ['Phishing Response Drill', 2], ['Data Exfiltration Exercise', 2]];
  return `${K.card('OpenAEV scenarios', table(['Name', 'Category', 'Severity', 'Techniques', 'Injects', 'Synced'], sc.map(x => `<tr><td><b>${x[0]}</b></td><td>${x[1]}</td><td>${tag(x[2], x[2] === 'critical' ? 'red' : x[2] === 'high' ? 'amber' : 'blue')}</td><td class="num">${x[3]}</td><td class="num">${x[4]}</td><td class="mono muted">2026-10-15 17:30</td></tr>`)))}
  <div class="grid g2 mt">${K.card('OpenAEV exercises', K.empty('flag', 'No exercises synced yet', 'Exercises appear here after the next OpenAEV sync.'))}${K.card('Exercise plans', plans.map(([n, s]) => `<div class="thr-row" style="margin-bottom:8px"><div class="grow"><b>${n}</b><div class="muted" style="font-size:12px">${s} steps · created 2026-09-25</div></div><button class="btn sm primary" data-act="toast" data-a="Exercise launched" data-b="${n}" data-c="success">Launch</button></div>`).join(''))}</div>
  ${K.card('Executions', table(['Name', 'Status', 'Progress', 'Started'], [['Data Exfiltration Exercise #2', 'completed', 2, '2026-10-21'], ['Phishing Response Drill #3', 'completed', 2, '2026-10-12'], ['Ransomware Tabletop + Technical #1', 'running', 1, '2026-10-25']].map(x => `<tr><td><b>${x[0]}</b></td><td>${tag(x[1], x[1] === 'completed' ? 'green' : 'blue')}</td><td style="min-width:140px">${K.prog(x[2] / 2 * 100, 'green')}<div class="muted" style="font-size:11px">${x[2]} / 2 steps</div></td><td class="mono muted">${x[3]}</td></tr>`)), '', 'mt')}`;
});

// ---------- Technique coverage ----------
wrap('attack-coverage', () => {
  const actors = ['All techniques', 'APT28', 'APT29', 'APT38', 'APT41', 'Akira', 'FIN7', 'Kimsuky', 'LockBit', 'Lazarus Group', 'Scattered Spider', 'Sandworm'];
  const a = S.tcActor || 'All techniques';
  return `<div class="card"><div class="lbl-s">ACTOR</div><div class="row" style="gap:12px;flex-wrap:wrap;margin-top:6px">${K.select('tcActor', 'All techniques', actors.slice(1))}<span class="muted" style="font-size:12.5px">${a === 'All techniques' ? '656 techniques across 14 tactics' : `Showing only techniques attributed to ${a}`} · 20 prevented · 12 missed · 624 untested</span></div><div class="chips" style="margin-top:12px">${actors.map(x => `<button class="chip ${a === x ? 'on' : ''}" data-act="set" data-a="tcActor" data-b="${x}">${x}</button>`).join('')}</div></div>`;
});

// ---------- Threat prioritization ----------
wrap('threat-priority', () => {
  const t = [['LockBit', 'High', 43, -23, '1 of 12'], ['Akira', 'Medium', 37, -1, '5 of 11'], ['APT29', 'Medium', 35, -31, '65 of 121'], ['APT41', 'Medium', 32, -28, '38 of 85'], ['APT28', 'Medium', 30, -36, '53 of 92'], ['Sandworm', 'Medium', 29, -47, '3 of 12'], ['Lazarus Group', 'Medium', 23, -31, '55 of 78'], ['FIN7', 'Medium', 21, -22, '21 of 37'], ['Scattered Spider', 'Low', 16, -57, '24 of 30'], ['APT36', 'Low', 11, -75, '4 of 4']];
  const tc = x => x === 'High' ? 'red' : x === 'Medium' ? 'amber' : '';
  return `<div class="grid g3">${tile('flag', 'High tier', 1, 'LockBit', 'red')}${tile('alert', 'Medium tier', 7, 'monitor closely', 'amber')}${tile('eye', 'Low tier', 2, 'Scattered Spider · APT36', 'accent')}</div>
  ${K.card('Actor priority', table(['Actor', 'Tier', 'Score', 'Trend', 'Coverage gap'], t.map(([n, tr, s, d, g]) => `<tr data-act="actorOpen" data-a="${n}"><td><div class="row" style="gap:10px"><span class="ta-av sm ${tr === 'High' ? 'hi' : ''}">${n.split(' ').map(x => x[0]).join('').slice(0, 2)}</span><b>${n}</b></div></td><td>${tag(tr, tc(tr))}</td><td style="min-width:130px">${K.prog(Math.min(100, s * 2), tr === 'High' ? 'red' : 'amber')}<span class="muted" style="font-size:11px">${s}</span></td><td><span class="chip-down">▼ ${d}</span></td><td><span style="color:var(--red)">${g.split(' of ')[0]}</span><span class="muted"> of ${g.split(' of ')[1]} techniques</span></td></tr>`)), '', 'mt')}`;
});

// ---------- Agents ----------
wrap('agents', () => {
  const v = S.agView || 'System Tree';
  const grp = [['All', 14], ['DMZ', 2], ['Lab', 2], ['Production', 10], ['Engineering', 4], ['Finance', 3]];
  return `<div class="card legacy-card"><div class="row between" style="gap:14px;flex-wrap:wrap"><div class="row" style="gap:14px">${ring(100, '#10b981', 60)}<div><b>Legacy transport migration</b><div class="muted" style="font-size:12.5px">Days clean: 30 / 30</div></div></div>${tag('ELIGIBLE FOR REVIEW', 'green')}</div></div>
  <div class="row between mt" style="gap:12px;flex-wrap:wrap"><div class="seg">${['System Tree', 'Operational', 'Risk & Remediation'].map(x => `<button class="${v === x ? 'on' : ''}" data-act="set" data-a="agView" data-b="${x}">${x}</button>`).join('')}</div></div>
  ${v === 'System Tree' ? '': v === 'Operational' ? `<div class="grid g4 mt">${tile('agent', 'Total agents', 14, 'enrolled', 'accent')}${tile('check', 'Online', 12, '86%', 'green')}${tile('alert', 'Degraded', 0, '', 'amber')}${tile('x', 'Offline', 2, 'check connectivity', 'red')}</div><div class="grid g2 mt">${K.card('Agents by OS', K.donut([{ label: 'Windows', value: 8, color: '#3b82f6' }, { label: 'Linux', value: 4, color: '#10b981' }, { label: 'macOS', value: 2, color: '#a855f7' }], 'agents', 130, '14'))}${K.card('Simulations per agent', K.hbars([['ENG-WS-02', 6, 'blue', ''], ['HR-MAC-01', 6, 'blue', ''], ['DMZ-MAIL-01', 5, 'blue', ''], ['FIN-WS-01', 4, 'blue', '']]))}</div>` : `<div class="grid g3 mt">${tile('shield', 'Hardened', 9, 'meet baseline', 'green')}${tile('alert', 'Needs remediation', 4, 'open findings', 'amber')}${tile('x', 'At risk', 1, 'critical findings', 'red')}</div><div class="mt">${K.card('Remediation backlog by agent', K.hbars([['ENG-WS-02', 14, 'red', ''], ['ENG-LNX-02', 13, 'red', ''], ['FIN-WS-02', 12, 'amber', ''], ['DMZ-MAIL-01', 11, 'amber', ''], ['HR-MAC-01', 10, 'amber', '']]))}</div>`}`;
});

// ---------- Integrations ----------
wrap('integrations', () => {
  const kinds = [['ServiceNow', 'ITSM'], ['Jira', 'ITSM'], ['Webhook', 'ITSM'], ['CrowdStrike', 'EPP'], ['Defender', 'EPP']];
  const box = (title, sub, items, empty) => K.card(title, `<p class="muted" style="margin-top:0;font-size:12.5px">${sub}</p>${K.empty('plug', empty[0], empty[1])}<div class="row" style="gap:8px;margin-top:12px;flex-wrap:wrap">${items.map(i => `<button class="btn" data-act="toast" data-a="Add ${i[0]} connector" data-b="Connector wizard">+ ${i[0]}</button>`).join('')}</div>`, `<div class="row" style="gap:8px"><button class="btn sm" data-act="toast" data-a="Synced" data-b="Connector state refreshed">Sync Now</button><button class="btn sm primary" data-act="toast" data-a="Add connector" data-b="Connector wizard">+ Add Connector</button></div>`);
  return `<div class="grid g2">${box('ITSM connectors', 'Configure ITSM connectors. Analysts create tickets from Findings; BAS can auto-create tickets for critical exposures based on policy.', kinds.filter(k => k[1] === 'ITSM'), ['No connectors configured', 'Add a ServiceNow, Jira, or webhook connector to push findings to your ITSM.'])}
  ${box('EPP response connectors', 'CrowdStrike / Defender credentials for isolate, kill process and quarantine actions from the Findings tab.', kinds.filter(k => k[1] === 'EPP'), ['No response connectors configured', 'Add a CrowdStrike or Defender connector to enable Respond actions from Findings.'])}</div>`;
});

// ---------- Settings ----------
wrap('settings', () => {
  const tabs = ['Users & roles', 'Caldera engine', 'Threat intel', 'ART content', 'Audit logs', 'Theme & display', 'Dashboard', 'License', 'Backup & Recovery'];
  return `<div class="grid g3">${tile('layers', 'Base simulations', 283, '0 ART atomics · 0 Caldera abilities · 119 scenarios · 152 ATT&CK techniques', 'accent')}${tile('grid', 'Available variants', '1,848+', 'encoding × privilege × context', 'purple')}<div class="card real-tile" data-act="toast" data-a="Breakdown" data-b="Scenarios 119 · ART 0 · Caldera 0">${ic('chev')}<div><b>Click for breakdown</b><div class="muted" style="font-size:12px">Content sources and counts</div></div></div></div>`;
});
})();
