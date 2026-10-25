// Real-console parity, part 1 — Operations: Kubernetes, Scheduled, Initiatives, Campaigns, Factory Health.
// Wraps the existing pages and adds the real console's panels, in the demo's visual style.
(() => {
const { S, P, A, h, toast, modal } = AUD;
const { tag, bar, table, kpi } = h;
const K = KIT;
const ring = (v, color, sz = 64) => `<span class="ring-n" style="--sz:${sz}px"><svg viewBox="0 0 60 60" width="${sz}" height="${sz}" class="progress-ring"><circle cx="30" cy="30" r="24" fill="none" class="track" stroke-width="6"/><circle cx="30" cy="30" r="24" fill="none" stroke="${color}" stroke-width="6" stroke-linecap="round" stroke-dasharray="${v / 100 * 150.8} 150.8" transform="rotate(-90 30 30)"/></svg><b>${v}%</b></span>`;
const sec = (t, r = '') => `<div class="row between sec-row"><h4 class="sec-label" style="margin:0">${t}</h4>${r}</div>`;
const tile = (icon, label, val, sub, col = 'accent') => `<div class="card real-tile" style="--tc:var(--${col})"><div class="rt-ico">${ic(icon)}</div><div><div class="lbl-s">${label}</div><div class="rt-val">${val}</div><div class="muted" style="font-size:11.5px">${sub}</div></div></div>`;
// Inserts the extra panels right after the hero banner (end of its closing </div>), falling back to the top.
const afterHero = (html, extra) => { let i = html.indexOf('class="scn-banner"'); if (i < 0) i = html.indexOf('class="page-head"'); if (i < 0) return extra + html; let d = 0, j = html.lastIndexOf('<div', i); const re = /<div|<\/div>/g; re.lastIndex = j; let m; while ((m = re.exec(html))) { d += m[0] === '</div>' ? -1 : 1; if (d === 0) { const e = m.index + 6; return html.slice(0, e) + '<div class="after-hero">' + extra + '</div>' + html.slice(e); } } return extra + html; };
const wrap = (route, fn) => { const o = P[route]; P[route] = (...a) => afterHero(o(...a), fn('', ...a)); };
window.RL = { ring, sec, tile, wrap, afterHero };

// ---------- Kubernetes ----------
wrap('k8s-scenarios', html => {
  const acts = ['Create unprivileged pod', 'Patch labelled ConfigMap', 'Mint and discard a probe token', 'Read synthetic secret as probe'];
  const an = S.k8sAn;
  const flow = [['Plan', 'Nothing is written', 'check'], ['Approve', 'A different operator', 'user'], ['Execute', 'Only the requester', 'play'], ['Verify', 'Evidence and cleanup', 'shield']];
  return `<div class="card k8s-warn"><div class="row" style="gap:12px">${ic('alert')}<div><b>Lab only.</b> Planning writes nothing. A run changes the cluster only after a different operator approves it, and only the requester can execute it.</div></div>
    <div class="flow-steps">${flow.map(([t, s, i], n) => `<div class="fs"><span class="fs-n">${n + 1}</span><span class="fs-i">${ic(i, 'sm')}</span><div><b>${t}</b><div class="muted">${s}</div></div></div>`).join('<span class="fs-arrow">→</span>')}</div></div>
  ${K.card('New run', `<div class="grid g4" style="gap:12px">
      <div><div class="lbl-s">ACTION</div><select class="select" style="width:100%">${acts.map(a => `<option>${a}</option>`).join('')}</select></div>
      <div><div class="lbl-s">CLUSTER</div><input class="input" value="kind-bas-lab"></div>
      <div><div class="lbl-s">NAMESPACE</div><input class="input" value="bas-sandbox"></div>
      <div><div class="lbl-s">OBJECT NAME</div><input class="input" placeholder="bas-sbx-example"></div></div>
    <div class="row" style="margin-top:14px;gap:10px"><button class="btn primary grow" data-act="k8sPlan">${ic('check')}Plan run</button></div>
    <div class="muted" style="font-size:12px;margin-top:10px">${ic('alert', 'sm')} Kubernetes scenarios are unavailable on this installation until a cluster is configured.</div>`)}
  
  ${K.card('Read-only analysis', `<p class="muted" style="font-size:12.5px;margin-top:0">Reads the cluster and reports configured permissions and settings. It writes nothing and proves no attack works.</p>
    <div class="row" style="gap:14px;margin:12px 0"><label class="row" style="gap:8px;font-size:13px"><input type="checkbox" ${S.k8sSys ? 'checked' : ''} data-act="toggleKey" data-a="k8sSys"> Show built-in system: roles</label><button class="btn primary" data-act="k8sAnalyze">${ic('play')}Run analysis</button></div>
    ${an ? `<div class="grid g4">${tile('shield', 'Roles reviewed', S.k8sSys ? 64 : 41, 'cluster roles + roles')}${tile('alert', 'Cluster-admin bindings', 3, 'review recommended', 'amber')}${tile('lock', 'Wildcard verbs', 2, 'on secrets / pods', 'red')}${tile('check', 'Pod-security enforced', '8/10', 'namespaces', 'green')}</div>
      <div class="grid g2 mt">${K.card('Risky permissions', K.hbars([['secrets: get/list', 7, 'red', ' roles'], ['pods/exec', 4, 'amber', ' roles'], ['* on *', 2, 'red', ' roles'], ['nodes/proxy', 1, 'amber', ' roles']]))}${K.card('Namespace posture', K.donut([{ label: 'Restricted', value: 6, color: '#10b981' }, { label: 'Baseline', value: 2, color: '#f59e0b' }, { label: 'Privileged', value: 2, color: '#ef4444' }], 'namespaces', 140, '10'))}</div>` : `<div class="muted" style="font-size:13px">Not run yet.</div>`}`)}`;
});
Object.assign(A, {
  schedEdit: () => A.schedWiz(),
  schedCancel: d => { const r = S.schedRows[+d.a]; r[4] = 'Cancelled'; toast('Schedule cancelled', r[0].slice(0, 40), 'warn'); AUD.render(); },
  toggleKey: d => { S[d.a] = !S[d.a]; AUD.render(); },
  k8sAnalyze: () => { S.k8sAn = true; AUD.render(); toast('Analysis complete', 'Read-only · nothing was written', 'success'); },
  k8sPlan: () => modal('<div class="modal-hd"><h3>Plan preview</h3></div><div class="modal-bd"><ol style="line-height:1.9;margin:0 0 0 18px"><li>Create pod <span class="mono">bas-sbx-example</span> in <span class="mono">bas-sandbox</span></li><li>Pod runs unprivileged, no host mounts</li><li>Cleanup deletes the pod after verification</li></ol><div class="muted" style="margin-top:12px">Planning writes nothing. A different operator must approve.</div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="closeModal">Submit for approval</button></div>')
});

// ---------- Scheduled ----------
wrap('scheduled-assessments', html => {
  const rows = S.schedRows = S.schedRows || [['Full Security Posture Scan', 3, 'Weekly · Wednesday · 22:00 · UTC', '23/10/2026, 17:30', 'Enabled'], ['Windows Security Configuration & Identity Baseline', 3, 'Weekly · Monday · 09:00 · UTC', '23/10/2026, 17:30', 'Enabled'], ['Linux Discovery - Host, Network, User, Process Enumeration', 3, 'Weekly · Tuesday · 03:00 · UTC', '23/10/2026, 17:30', 'Cancelled'], ['Credential Access — LSA Secrets, Credential Manager, Kerberos, NTLM (Phase 4)', 3, 'Weekly · Friday · 14:30 · UTC', '23/10/2026, 19:58', 'Enabled']];
  return `<div class="grid g4">${tile('clock', 'Active schedules', 3, 'of 4 defined', 'green')}${tile('x', 'Cancelled', 1, 'will not run', 'red')}${tile('play', 'Next run', 'Fri 14:30', 'Credential Access', 'accent')}${tile('check', 'Last 4 weeks', '100%', 'runs completed', 'green')}</div>
  <div class="mt">${K.card('Assessment schedule', table(['Assessment', 'Mode', 'Targets', 'Recurrence', 'Last run', 'Status', ''], rows.map(([n, t, rec, last, s], ix) => `<tr><td><b>${n}</b></td><td>${tag('Posture', 'blue')}</td><td>${t} agents</td><td class="muted">${rec}</td><td class="mono muted">${last}</td><td>${tag(s, s === 'Enabled' ? 'green' : 'red')}</td><td style="white-space:nowrap"><button class="btn sm" data-act="schedEdit" data-a="${ix}">Edit</button> ${s === 'Enabled' ? `<button class="btn sm danger" data-act="schedCancel" data-a="${ix}">Cancel</button>` : ''}</td></tr>`)))}</div>
  `;
});

// ---------- Initiatives ----------
wrap('initiatives', html => {
  const f = S.initF || 'Active';
  const rows = [['Q4 Ransomware Readiness', 'Active', 68], ['RBI CSCF Annual Drill', 'Active', 41], ['Identity Hardening', 'Active', 87], ['FY25 Phishing Resilience', 'Closed', 100], ['Legacy EDR Migration', 'Archived', 100]].filter(r => f === 'All' || r[1] === f);
  const counts = { Active: 3, Closed: 1, Archived: 1, All: 5 };
  return `<div class="row between" style="margin-bottom:12px"><div class="chips">${['Active', 'Closed', 'Archived', 'All'].map(x => `<button class="chip ${f === x ? 'on' : ''}" data-act="set" data-a="initF" data-b="${x}">${x} <span class="cnt">${counts[x]}</span></button>`).join('')}</div><button class="btn primary" data-act="toast" data-a="New initiative" data-b="Opens the initiative wizard">+ New Initiative</button></div>
  <div class="grid g3">${rows.map(([n, s, p], i) => `<div class="card hov init-card" data-act="toast" data-a="${n}" data-b="Initiative workspace"><div class="row" style="gap:14px">${ring(p, s === 'Active' ? '#3b82f6' : '#10b981', 68)}<div class="grow"><b>${n}</b><div class="row" style="gap:8px;margin-top:6px">${tag(s, s === 'Active' ? 'green' : 'blue')}</div></div></div>
    <div class="init-meta"><span>${K.avatar('admin preview')} Created by admin@preview.local</span><span class="muted">${15 - i}/09/2026, 17:30</span></div></div>`).join('')}</div>
  `;
});

// ---------- Campaigns ----------
wrap('campaigns', html => {
  const c = [['APT29 Emulation', 'Completed', 5, 0, 0], ['Weekly Posture Check', 'Partial', 3, 1, 1], ['Akira Kill Chain Validation', 'Completed', 5, 0, 0], ['Domain Controller Credential Test', 'Completed', 4, 1, 0], ['Engineering Linux Baseline', 'Completed', 5, 0, 0], ['Finance Endpoint Sweep', 'Partial', 3, 1, 1]];
  const f = S.campF || 'All';
  const list = c.filter(x => f === 'All' || x[1] === f);
  return `<div class="row between" style="margin-bottom:12px"><div class="chips">${[['All', 6], ['Completed', 4], ['Partial', 2]].map(([x, n]) => `<button class="chip ${f === x ? 'on' : ''}" data-act="set" data-a="campF" data-b="${x}">${x} <span class="cnt">${n}</span></button>`).join('')}</div><div class="row" style="gap:8px"><button class="btn" data-act="toast" data-a="Schedule" data-b="Coming soon" data-c="info">${ic('clock')}Schedule · soon</button><button class="btn primary" data-act="toast" data-a="New campaign" data-b="Opens the campaign wizard">▶ New campaign</button></div></div>
  ${K.card('Result mix per campaign', `<div class="mix-list">${list.map(([n, s, p, pa, fl]) => { const t = p + pa + fl; return `<div class="mix-row"><div class="mix-n"><b>${n}</b><div class="muted">${tag(s, s === 'Completed' ? 'green' : 'amber')} 5/5 agents</div></div><div class="mix-bar"><i style="width:${p / t * 100}%;background:var(--green)"></i><i style="width:${pa / t * 100}%;background:var(--amber)"></i><i style="width:${fl / t * 100}%;background:var(--red)"></i></div><div class="mix-k"><span style="color:var(--green)">${p} pass</span><span style="color:var(--amber)">${pa} partial</span><span style="color:var(--red)">${fl} fail</span></div></div>`; }).join('')}</div>`, '<div class="legend"><span><i style="background:var(--green)"></i>Pass</span><span><i style="background:var(--amber)"></i>Partial</span><span><i style="background:var(--red)"></i>Fail</span></div>')}
  `;
});

// ---------- Factory Health ----------
wrap('factory-health', html => {
  const stages = [['Candidate', 0, '#64748b'], ['Validated', 0, '#3b82f6'], ['Published', 141, '#10b981'], ['Rejected', 0, '#ef4444']];
  return `<div class="grid g3">${tile('layers', 'Threats processed', 10, 'selected window', 'accent')}${tile('check', 'Published content', 141, 'scenarios and variants', 'green')}${tile('clock', 'Median threat → content', '1.6d', 'TCV', 'cyan')}</div>
  <div class="grid g3 mt">${tile('shield', 'Static validation pass rate', '100%', 'every build passed', 'green')}${tile('refresh', 'Duplicate generation rate', 'NO DATA', 'no generative attempts recorded in the window', 'muted')}<div class="card real-tile">${ring(100, '#10b981', 64)}<div><div class="lbl-s">SOURCE → TECHNIQUE COVERAGE</div><div class="muted" style="font-size:11.5px;margin-top:4px">0 unresolved actor candidate(s)</div></div></div></div>
  ${K.card('Content pipeline', `<div class="pipe-funnel">${stages.map(([n, v, c], i) => `<div class="pf" style="--pc:${c}"><div class="pf-v">${v}</div><div class="pf-n">${n}</div></div>${i < 3 ? '<span class="fs-arrow">→</span>' : ''}`).join('')}</div><div class="row" style="gap:18px;margin-top:14px;font-size:12.5px"><span style="color:var(--green)">${ic('check', 'sm')} No stale sources</span><span style="color:var(--green)">${ic('check', 'sm')} 0 stuck in validation</span></div>`)}
  `;
});
})();
