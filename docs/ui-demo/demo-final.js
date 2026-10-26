// Last sweep over toast-only buttons: real modals/drawers where there is something to enter or see,
// and a visible "working" state for refresh/export/scan style buttons.
(() => {
const { S, P, A, h, toast } = AUD;
const field = (id, label, ph, val = '') => `<div class="field" style="margin-top:12px"><label>${label}</label><input class="input" id="${id}" placeholder="${ph}" value="${val}"></div>`;
const v = id => ((document.getElementById(id) || {}).value || '').trim();
const err = m => { const e = document.getElementById('fx-err'); if (e) e.textContent = m; return false; };
const ERR = '<div id="fx-err" style="color:var(--red);font-size:12.5px;margin-top:10px"></div>';
const foot = (a, label) => `<div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="${a}">${label}</button></div>`;

// ---- generic working state for refresh / export / scan buttons ----
const BUSY = /^(Runs refreshed|Refreshed|Coverage recalculated|Pipelines re-checked|Exposure scan queued|Model refreshed|AD checks queued|Synced|Connection test passed|Tests queued|Test coverage gaps|K8s run (started|queued)|Export started|Export PDF|Export JSON|PDF report|CSV|Posture report|Audit pack|Compliance evidence|SLA compliance|Push to ITSM|Copied)$/;
const DONE = { 'Runs refreshed': 'Runs up to date', 'Refreshed': 'Data up to date', 'Coverage recalculated': 'Coverage recalculated', 'Exposure scan queued': 'Exposure scan complete', 'AD checks queued': 'AD checks complete', 'Tests queued': 'Tests finished', 'Test coverage gaps': 'Coverage gap tests finished', 'Export started': 'Export ready', 'Export PDF': 'PDF ready', 'Export JSON': 'JSON ready', 'PDF report': 'PDF report ready', 'CSV': 'CSV ready', 'Posture report': 'Posture report ready', 'Audit pack': 'Audit pack ready', 'Compliance evidence': 'Evidence bundle ready', 'SLA compliance': 'SLA report ready', 'Push to ITSM': 'Pushed to ITSM', 'Synced': 'Sync complete', 'Connection test passed': 'Connection test passed', 'Pipelines re-checked': 'Pipelines healthy', 'Model refreshed': 'Model refreshed', 'Copied': 'Copied' };
document.addEventListener('click', e => {
  const b = e.target.closest('#content button[data-act="toast"]'); if (!b || b.disabled) return;
  const t = b.dataset.a; if (!BUSY.test(t || '')) return;
  e.stopImmediatePropagation(); e.preventDefault();
  const old = b.innerHTML; b.disabled = true; b.innerHTML = '<span class="spin"></span> Working…';
  setTimeout(() => { if (document.body.contains(b)) { b.disabled = false; b.innerHTML = old; } toast(DONE[t] || t, b.dataset.b || '', 'success'); }, 1300);
}, true);

// ---- Agents: New group ----
Object.assign(A, {
  agGroupNew: () => AUD.modal(h.mhd('New agent group', 'plus') + `<div class="modal-bd">${field('ng-n', 'Group name', 'e.g. Treasury')}${ERR}</div>` + foot('agGroupSave', 'Create group')),
  agGroupSave: () => { const n = v('ng-n'); if (!n) return err('Enter a group name.'); if (D.AGENT_GROUPS.some(g => g[0].toLowerCase() === n.toLowerCase())) return err('A group with this name already exists.'); D.AGENT_GROUPS.push([n, 0]); AUD.closeModal(); toast('Group created', n, 'success'); AUD.render(); }
});
['agents'].forEach(r => { P[r] = (o => () => o().replace('data-act="toast" data-a="Group created"', 'data-act="agGroupNew"'))(P[r]); });

// ---- Exercises: New Exercise ----
Object.assign(A, {
  exNew: () => AUD.modal(h.mhd('New exercise', 'flag') + `<div class="modal-bd">${field('ne-n', 'Name', 'e.g. Tabletop — Insider data theft')}${field('ne-d', 'Date', '15 Dec 2026', '15 Dec 2026')}${field('ne-p', 'Participants', '10', '10')}<div class="field" style="margin-top:12px"><label>Type</label><select class="select" id="ne-t" style="width:100%"><option>Tabletop</option><option>Purple team</option><option>Live fire</option></select></div>${ERR}</div>` + foot('exSave', 'Create exercise')),
  exSave: () => { const n = v('ne-n'); if (!n) return err('Enter a name.'); D.EXERCISES.unshift({ name: `${v('ne-t')} — ${n}`, date: v('ne-d'), participants: +v('ne-p') || 0, status: 'Scheduled', outcome: '—' }); AUD.closeModal(); toast('Exercise created', n, 'success'); AUD.render(); }
});
['exercises'].forEach(r => { P[r] = (o => () => o().replace('data-act="toast" data-a="Exercise draft created"', 'data-act="exNew"'))(P[r]); });

// ---- Integrations: Add connector ----
S.conns = S.conns || [];
Object.assign(A, {
  connAdd: d => AUD.modal(h.mhd('Add ' + d.a + ' connector', 'plug') + `<div class="modal-bd">${field('cn-n', 'Name', d.a + ' production', d.a + ' production')}${field('cn-u', 'Instance URL', 'https://' + d.a.toLowerCase() + '.example.com')}${field('cn-k', 'API token', 'paste token (stored encrypted)')}<div id="cn-r" class="muted" style="font-size:12.5px;margin-top:10px"></div>${ERR}</div><div class="modal-ft"><button class="btn" data-act="connTest" data-a="${d.a}">Test connection</button><span class="grow"></span><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="connSave" data-a="${d.a}">Save connector</button></div>`),
  connTest: () => { if (!v('cn-u') || !v('cn-k')) return err('Enter the URL and API token first.'); err(''); document.getElementById('cn-r').textContent = 'Testing…'; setTimeout(() => { const r = document.getElementById('cn-r'); if (r) r.innerHTML = '<span style="color:var(--green)">✓ Connection test passed</span>'; }, 900); },
  connSave: d => { if (!v('cn-n') || !v('cn-u') || !v('cn-k')) return err('Name, URL and API token are required.'); S.conns.push({ name: v('cn-n'), kind: d.a, url: v('cn-u') }); AUD.closeModal(); toast('Connector saved', v('cn-n') || d.a, 'success'); AUD.render(); },
  connDel: d => { S.conns.splice(+d.a, 1); toast('Connector removed', '', 'info'); AUD.render(); }
});
P.integrations = (o => () => {
  let html = o().replace(/data-act="toast" data-a="Add ([A-Za-z]+) connector" data-b="Connector wizard"/g, 'data-act="connAdd" data-a="$1"').replace('data-act="toast" data-a="Add connector" data-b="Connector wizard"', 'data-act="connAdd" data-a="ServiceNow"');
  if (!S.conns.length) return html;
  const card = `<div class="card mt" style="margin-bottom:14px"><h2>Your connectors</h2>${S.conns.map((c, i) => `<div class="row between" style="padding:10px 0;border-top:1px solid var(--border)"><div><b>${c.name}</b> ${h.tag(c.kind, 'blue')}<div class="mono muted" style="font-size:11.5px">${c.url}</div></div><div class="row" style="gap:8px">${h.tag('Connected', 'green')}<button class="btn sm danger" data-act="connDel" data-a="${i}">Remove</button></div></div>`).join('')}</div>`;
  const i = html.indexOf('<div class="grid g2">'); return i < 0 ? card + html : html.slice(0, i) + card + html.slice(i);
})(P.integrations);

// ---- Email: template tile opens detail; Import template ----
const EGV = ['Spoofed From header', 'Lookalike display name', 'Reply-To mismatch', 'Missing SPF/DKIM'];
Object.assign(A, {
  egOpen: d => h.drawer(h.dhd(d.a + ' · ' + d.b, 'Email gateway scenario', 'mail') + `<div class="drawer-bd"><p class="muted" style="margin-top:0">Sends sample messages through the gateway under test and records whether each is blocked, quarantined or delivered.</p><h4>Variants</h4>${EGV.map((x, i) => `<div class="row between" style="padding:8px 0;border-top:1px solid var(--border)"><span>${d.a}-v${i + 1} · ${x}</span>${h.tag(['Blocked', 'Quarantined', 'Delivered', 'Blocked'][(d.a.charCodeAt(5) + i) % 4], ['green', 'amber', 'red', 'green'][(d.a.charCodeAt(5) + i) % 4])}</div>`).join('')}</div><div class="drawer-ft"><button class="btn primary" data-act="toast" data-a="Exercise launched" data-b="${d.a} queued on staging-mx" data-c="success">▶ Run scenario</button></div>`),
  tplImport: () => AUD.modal(h.mhd('Import template', 'upload') + `<div class="modal-bd">${['Executive impersonation', 'Invoice fraud', 'MFA reset lure', 'Shared-document phish'].map((t, i) => `<label class="rw-item"><input type="checkbox" class="tp-c" ${i < 2 ? 'checked' : ''}><span class="grow">${t}</span><span class="muted">library</span></label>`).join('')}</div>` + foot('tplSave', 'Import selected')),
  tplSave: () => { const n = document.querySelectorAll('.tp-c:checked').length; AUD.closeModal(); toast('Templates imported', `${n} template${n === 1 ? '' : 's'} added from library`, 'success'); }
});
['email', 'email-gateway'].forEach(r => { if (P[r]) P[r] = (o => () => o().replace(/<div class="eg-card hov" data-act="toast" data-a="([^"]*)" data-b="([^"]*)">/g, '<div class="eg-card hov" data-act="egOpen" data-a="$1" data-b="$2">').replace('data-act="toast" data-a="Template imported" data-b="2 templates added from library"', 'data-act="tplImport"'))(P[r]); });

// ---- Reports: schedule delivery, Settings Profile ----
Object.assign(A, {
  delAdd: () => AUD.modal(h.mhd('Add delivery', 'mail') + `<div class="modal-bd">${field('dl-e', 'Recipient email', 'ciso@acme-bank.com')}<div class="field" style="margin-top:12px"><label>Frequency</label><select class="select" id="dl-f" style="width:100%"><option>Weekly</option><option>Monthly</option><option>Quarterly</option></select></div>${ERR}</div>` + foot('delSave', 'Add delivery')),
  delSave: () => { if (!/^\S+@\S+\.\S+$/.test(v('dl-e'))) return err('Enter a valid email address.'); AUD.closeModal(); toast('Delivery added', `${v('dl-e')} · ${v('dl-f')}`, 'success'); }
});
['reports'].forEach(r => { P[r] = (o => () => o().replace('data-act="toast" data-a="Delivery added"', 'data-act="delAdd"'))(P[r]); });
document.head.insertAdjacentHTML('beforeend', '<style>.spin{display:inline-block;width:11px;height:11px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:fxs .7s linear infinite;vertical-align:-1px}@keyframes fxs{to{transform:rotate(360deg)}}</style>');
})();
