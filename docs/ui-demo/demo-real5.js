// Run-scenario wizard matching the real console: Target -> Options (mode, max privilege, step picker) -> Review.
(() => {
const { S, A, toast, modal } = AUD;
const mhd = AUD.h.mhd, st = AUD.h.st, tag = AUD.h.tag;
const osOf = a => /mac/i.test(a.os) ? 'macOS' : /win/i.test(a.os) ? 'Win' : 'Linux';
const agents = () => D.AGENTS.slice(0, 14);
const ACTS = ['indirect execution via cmd.exe parent', 'alternate binary: renamed copy', 'script host proxy', 'alternate host where installed', 'registry write then readback', 'scheduled task create and delete', 'credential store read (synthetic)', 'outbound beacon to sink'];
const stepsOf = s => s.tech.concat(s.tech).slice(0, Math.max(6, s.tech.length)).map((t, i) => ({ n: i + 1, t, name: `${s.name.split(/ [—-] /)[0]} ${ACTS[i % ACTS.length]} (${t})`, prevented: i % 3 === 0 }));
const MODES = [['posture', 'Posture — read-only, safe on any host'], ['telemetry', 'Telemetry — real identity-safe techniques (production-safe under approval)'], ['lab', 'Lab — full-fidelity emulation (isolated range only)']];
const PRIV = [['none', 'No limit — run every step regardless of required privilege'], ['user', 'User — skip steps requiring admin or system'], ['admin', 'Admin — skip steps requiring system']];
const W = () => S.rw;
const radios = (name, list, cur) => list.map(([v, l]) => `<label class="rw-radio ${cur === v ? 'on' : ''}"><input type="radio" name="${name}" ${cur === v ? 'checked' : ''} data-act="rwSet" data-a="${name}" data-b="${v}"><span>${l}</span></label>`).join('');

function draw() {
  const w = W(), s = w.s, ag = agents(), n = w.step;
  const prim = ag.find(a => a.id === w.primary) || ag[0];
  const groups = [...new Set(ag.map(a => a.group))];
  const body = n === 1 ? `
    <div class="lbl-s">TARGET</div>
    <div class="row rw-mode" style="gap:18px;margin:8px 0 14px">${[['one', 'Individual Agent(s)'], ['grp', 'Agent Group(s)'], ['all', 'All Agents']].map(([v, l]) => `<label class="row" style="gap:6px"><input type="radio" name="tg" ${w.target === v ? 'checked' : ''} data-act="rwSet" data-a="target" data-b="${v}">${l}</label>`).join('')}</div>
    ${w.target === 'one' ? `<div class="lbl-s">PRIMARY AGENT</div><select class="select" style="width:100%;margin:6px 0" data-change="rwSel" data-a="primary">${ag.map(a => `<option value="${a.id}" ${a.id === prim.id ? 'selected' : ''}>${a.id} — ${a.host} [${osOf(a)}]</option>`).join('')}</select><div class="muted" style="font-size:12px;margin-bottom:14px">The endpoint that will execute this run.</div>
      <div class="row between"><div class="lbl-s">RUN ON ADDITIONAL AGENTS (${w.extra.length} SELECTED)</div><button class="btn sm" data-act="rwAll">${w.extra.length === ag.length - 1 ? 'Clear' : 'Select all'}</button></div>
      <div class="rw-list">${ag.filter(a => a.id !== prim.id).map(a => `<label class="rw-item"><input type="checkbox" ${w.extra.includes(a.id) ? 'checked' : ''} data-act="rwExtra" data-a="${a.id}"><span class="mono">${a.id}</span><b>${a.host}</b><span class="muted">· ${osOf(a).toLowerCase()}</span>${a.status !== 'Online' ? tag(a.status, 'amber') : ''}</label>`).join('')}</div>`
    : w.target === 'grp' ? `<div class="rw-list" style="max-height:260px">${groups.map(g => `<label class="rw-item"><input type="checkbox" ${w.groups.includes(g) ? 'checked' : ''} data-act="rwGroup" data-a="${g}"><b>${g}</b><span class="muted">· ${ag.filter(a => a.group === g).length} agents</span></label>`).join('')}</div>`
    : `<div class="card" style="padding:14px">${AUD.h.bar(100, '')}<div style="margin-top:8px"><b>${ag.length} agents</b> <span class="muted">· every enrolled endpoint will run this scenario</span></div></div>`}`
  : n === 2 ? `
    <a class="rw-custom" data-act="rwSteps">⚙ Customize — select steps to run${w.sel ? ` <span class="cnt">${w.sel.length}</span>` : ''}</a>
    <div class="lbl-s" style="margin-top:14px">EXECUTION MODE</div><div class="rw-opts">${radios('mode', MODES, w.mode)}</div>
    <div class="lbl-s" style="margin-top:14px">MAX PRIVILEGE</div><div class="rw-opts">${radios('priv', PRIV, w.priv)}</div>
    <div class="muted" style="font-size:12px;margin-top:8px">Steps above this ceiling are skipped, not dispatched to the agent — simulates what an attacker could achieve capped at this privilege level.</div>
    <div class="check-row" style="margin-top:14px"><span class="grow">Pause on first detection</span><button class="switch ${w.pause ? 'on' : ''}" data-act="rwToggle" data-a="pause"></button></div>
    <div class="check-row"><span class="grow">Generate HTML report on completion</span><button class="switch ${w.report ? 'on' : ''}" data-act="rwToggle" data-a="report"></button></div>`
  : (() => { const off = w.target === 'one' && prim.status !== 'Online'; const cnt = w.target === 'one' ? 1 + w.extra.length : w.target === 'all' ? ag.length : ag.filter(a => w.groups.includes(a.group)).length;
    return `<dl class="kv"><dt>Scenario</dt><dd>${s.name}</dd><dt>Target ${w.target === 'one' ? 'agent' : w.target === 'grp' ? 'groups' : ''}</dt><dd>${w.target === 'one' ? `${prim.id} — ${prim.host} [${osOf(prim)}]${w.extra.length ? ` +${w.extra.length} more` : ''}` : w.target === 'all' ? `All agents (${ag.length})` : (w.groups.join(', ') || 'None selected')}</dd></dl>
    ${off ? `<div class="alert warn" style="margin:10px 0">${ic('alert')}<div>Currently ${prim.status.toLowerCase()}: ${prim.host}. The run will likely fail to reach this agent.</div></div>` : ''}
    <dl class="kv"><dt>Mode</dt><dd>${MODES.find(m => m[0] === w.mode)[1].split(' — ')[0]} — ${w.mode === 'posture' ? 'read-only' : w.mode === 'lab' ? 'full fidelity' : 'identity-safe'}</dd><dt>Max privilege</dt><dd>${PRIV.find(m => m[0] === w.priv)[1].split(' — ')[0]}</dd><dt>Scope</dt><dd>${w.sel ? `${w.sel.length} of ${stepsOf(s).length} steps` : 'All steps'}</dd><dt>Targets</dt><dd>${cnt} agent${cnt === 1 ? '' : 's'} · est. ${s.mins} min</dd></dl>`; })();
  modal(mhd('Run: ' + s.name, 'play') + `<div class="modal-bd"><div class="steps">${['Target', 'Options', 'Review'].map((l, i) => `<div class="st ${n === i + 1 ? 'on' : n > i + 1 ? 'done' : ''}"><b>${n > i + 1 ? '✓' : i + 1}</b>${l}</div>${i < 2 ? '<div class="sep"></div>' : ''}`).join('')}</div>${body}</div>
    <div class="modal-ft"><span class="left">Step ${n} of 3</span><button class="btn" data-act="${n > 1 ? 'rwBack' : 'closeModal'}">${n > 1 ? '← Back' : 'Cancel'}</button>${n < 3 ? '<button class="btn primary" data-act="rwNext">Next →</button>' : `<button class="btn primary" data-act="startRun" data-a="${s.id}">▶ Run</button>`}</div>`, 'lg');
}
function steps() {
  const w = W(), all = stepsOf(w.s), q = (w.q || '').toLowerCase(), cur = w.sel || [];
  const list = all.filter(x => !q || (x.name + x.t).toLowerCase().includes(q));
  modal(`<div class="modal-bd"><h3 style="margin:0 0 4px">Select steps — ${w.s.name}</h3><div class="muted" style="font-size:12.5px;margin-bottom:12px">Tick the steps to run. Steps run in the order shown. Search by name or technique.</div>
    <input class="input" placeholder="Filter by ID, name, or tactic…" value="${w.q || ''}" data-act="rwQ" style="width:100%">
    <div class="row between" style="margin:10px 0;font-size:13px"><span><a class="lg-link" data-act="rwStepAll">Select all</a> · <a class="lg-link" data-act="rwStepNone">None</a></span><span class="muted">${cur.length} of ${all.length} selected</span></div>
    <div class="rw-list" style="max-height:300px">${list.map(x => `<label class="rw-item" style="align-items:flex-start"><input type="checkbox" ${cur.includes(x.n) ? 'checked' : ''} data-act="rwStep" data-a="${x.n}"><div><span style="color:var(--accent-hi);font-weight:600">Step ${x.n}</span> ${x.name} ${x.prevented ? tag('Prevented', 'green') : ''}<div class="mono muted" style="font-size:11px">${x.t}</div></div></label>`).join('')}</div></div>
    <div class="modal-ft"><button class="btn" data-act="rwStepsBack">Cancel</button><button class="btn primary" data-act="rwStepsUse">▶ Use selection (${cur.length})</button></div>`, 'lg');
}
Object.assign(A, {
  runScModal: d => { const s = D.SCENARIOS.find(x => x.id === d.a) || D.SCENARIOS[0]; S.rw = { s, step: 1, target: 'one', primary: agents()[0].id, extra: [], groups: [], mode: 'posture', priv: 'none', sel: null, pause: true, report: true }; draw(); },
  rwNext: () => { W().step++; draw(); }, rwBack: () => { W().step--; draw(); },
  rwSet: d => { W()[d.a] = d.b; draw(); },
  rwSel: (d, el) => { W()[d.a] = el.value; W().extra = W().extra.filter(x => x !== el.value); draw(); },
  rwToggle: d => { W()[d.a] = !W()[d.a]; draw(); },
  rwExtra: d => { const w = W(); w.extra = w.extra.includes(d.a) ? w.extra.filter(x => x !== d.a) : [...w.extra, d.a]; draw(); },
  rwGroup: d => { const w = W(); w.groups = w.groups.includes(d.a) ? w.groups.filter(x => x !== d.a) : [...w.groups, d.a]; draw(); },
  rwAll: () => { const w = W(), ids = agents().map(a => a.id).filter(i => i !== w.primary); w.extra = w.extra.length === ids.length ? [] : ids; draw(); },
  rwSteps: () => { W().q = ''; if (!W().sel) W().sel = []; steps(); },
  rwStep: d => { const w = W(), n = +d.a; w.sel = w.sel.includes(n) ? w.sel.filter(x => x !== n) : [...w.sel, n]; steps(); },
  rwStepAll: () => { W().sel = stepsOf(W().s).map(x => x.n); steps(); }, rwStepNone: () => { W().sel = []; steps(); },
  rwStepsBack: () => { if (W().sel && !W().sel.length) W().sel = null; draw(); },
  rwStepsUse: () => { if (W().sel && !W().sel.length) W().sel = null; draw(); }
});
document.addEventListener('input', e => { const t = e.target.closest('[data-act="rwQ"]'); if (!t) return; W().q = t.value; steps(); const i = document.querySelector('[data-act="rwQ"]'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } });
})();

// ---- Scenario detail drawer: working tabs (Overview / Steps / Techniques / Requirements / History) ----
(() => {
const { S, A, toast } = AUD;
const { tag, bar, table, st } = AUD.h;
const TN = { T1222: 'File and Directory Permissions Modification', T1069: 'Permission Groups Discovery', T1649: 'Steal or Forge Authentication Certificates', T1087: 'Account Discovery', T1486: 'Data Encrypted for Impact', T1490: 'Inhibit System Recovery', T1059: 'Command and Scripting Interpreter', T1204: 'User Execution', T1218: 'System Binary Proxy Execution', T1482: 'Domain Trust Discovery', T1547: 'Boot or Logon Autostart Execution', T1053: 'Scheduled Task/Job', T1071: 'Application Layer Protocol', T1550: 'Use Alternate Authentication Material', T1003: 'OS Credential Dumping' };
const nm = t => TN[t] || TN[t.split('.')[0]] || 'ATT&CK technique ' + t;
const cur = () => D.SCENARIOS.find(x => x.id === S.scSel) || D.SCENARIOS[0];
const VERD = ['Prevented', 'Detected', 'Missed', 'Untested'], VC = ['green', 'blue', 'red', ''];
const body = (id, s) => {
  const det = D.SCN_DETAIL[s.id] || { steps: Math.max(4, s.tech.length * 2) };
  const nSteps = Math.max(4, s.tech.length * 2);
  if (id === 'Steps') return `<div class="muted" style="font-size:12.5px;margin-bottom:10px">${nSteps} steps · run in order · cleanup runs automatically at the end.</div><div class="sd-steps">${Array.from({ length: nSteps }, (_, i) => { const t = s.tech[i % s.tech.length]; return `<div class="sd-step"><span class="sd-n">${i + 1}</span><div class="grow"><b>${nm(t)}</b><div class="muted" style="font-size:12px">Safe probe for <span class="mono">${t}</span> · cleanup: yes</div></div>${tag(i % 4 === 3 ? 'Admin' : 'User', i % 4 === 3 ? 'amber' : '')}<span class="muted mono" style="font-size:12px">${(1 + i % 3) * 20}s</span></div>`; }).join('')}</div>`;
  if (id === 'Techniques') return table(['Technique', 'Name', 'Tactic', 'Last result'], s.tech.map((t, i) => `<tr class="noclick"><td class="mono">${t}</td><td>${nm(t)}</td><td>${tag(s.tacticTag, 'blue')}</td><td>${tag(VERD[(i + 1) % 4], VC[(i + 1) % 4])}</td></tr>`)) + `<div class="muted" style="font-size:12px;margin-top:8px">${s.tech.length} ATT&CK techniques mapped · ${s.techniques} validated variants</div>`;
  if (id === 'Requirements') return `<h4 style="margin:0 0 8px">Prerequisites</h4><ul class="sd-req">${(D.SCN_DETAIL[s.id]?.prereq || [`${s.os} agent online`, 'Elevated privileges for admin-tier steps', 'Telemetry for process, registry and network events']).map(p => `<li>${ic('check', 'sm')}${p}</li>`).join('')}</ul>
    <dl class="kv mt" style="margin-top:16px"><dt>Platform</dt><dd>${s.os}</dd><dt>Min agent version</dt><dd class="mono">1.9.0</dd><dt>Execution modes</dt><dd>Posture · Telemetry${s.tier.includes('Enterprise') ? ' · Lab' : ''}</dd><dt>Safety</dt><dd>${tag('Telemetry-safe', 'green')} ${tag('Auto cleanup', 'green')}</dd><dt>Signature</dt><dd>${tag(s.sig, 'green')}</dd></dl>`;
  if (id === 'History') { const h = [['RUN-5516', 'Passed', 'FIN-WS-01', '24 Oct 14:20', 83], ['RUN-5499', 'Failed', 'ENG-WS-02', '21 Oct 09:05', 50], ['RUN-5471', 'Passed', 'DC-01', '18 Oct 22:00', 100], ['RUN-5433', 'Passed', 'FIN-WS-02', '14 Oct 02:00', 67]]; return `<div class="card" style="padding:12px;margin-bottom:12px"><div class="lbl-s">PASS RATE · LAST 4 RUNS</div>${chartSlot({ type: 'spark', data: [67, 100, 50, 83], color: '#10b981', h: 46 })}</div>` + table(['Run', 'Result', 'Agent', 'Started', 'Score'], h.map(r => `<tr data-act="openRun" data-a="${r[0]}"><td class="mono">${r[0]}</td><td>${st(r[1])}</td><td>${r[2]}</td><td class="muted">${r[3]}</td><td style="min-width:110px">${KIT.prog(r[4], KIT.pct(r[4]))}</td></tr>`)); }
  return null;
};
const origDetail = A.scDetail;
A.scDetail = d => { S.scSel = d.a; origDetail(d); const bd = document.querySelector('.drawer-bd'); if (!bd) return; const tabs = bd.querySelector('.tabs'); const wrap = document.createElement('div'); wrap.id = 'sc-tab-body'; while (tabs.nextSibling) wrap.appendChild(tabs.nextSibling); bd.appendChild(wrap); S.scOver = wrap.innerHTML; };
A.scDrawerTab = d => {
  const bd = document.getElementById('sc-tab-body'); if (!bd) return;
  document.querySelectorAll('.drawer-bd .tabs button').forEach(b => b.classList.toggle('on', b.dataset.a === d.a));
  bd.innerHTML = d.a === 'Overview' ? S.scOver : body(d.a, cur());
  if (window.hydrateCharts) hydrateCharts(bd);
};
})();
