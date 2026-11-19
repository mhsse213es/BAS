// Dashboard Preferences: default view (Operational / Executive / Last used) and a show/hide switch for every
// widget on both dashboard views. Hidden widgets are removed from the Dashboard when it renders.
(() => {
const { S, P, A, toast } = AUD;
const K = KIT;
const LS = { get: (k, d) => { try { return JSON.parse(localStorage.getItem('aud-demo-' + k)) ?? d; } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem('aud-demo-' + k, JSON.stringify(v)); } catch (e) { } } };
// [id, label, kind, match text, group]  kinds: kpi (tile label) · card (card title prefix) · sec (section header + N blocks)
const OPS = [
  ['k-open', 'Open findings tile', 'kpi', 'Open findings', 'Summary tiles'], ['k-age', 'Attack surface age tile', 'kpi', 'Attack surface age', 'Summary tiles'], ['k-prev', 'Prevention score tile', 'kpi', 'Prevention score', 'Summary tiles'],
  ['k-att', 'ATT&CK coverage tile', 'kpi', 'ATT&CK coverage', 'Summary tiles'], ['k-camp', 'Active campaigns tile', 'kpi', 'Active campaigns', 'Summary tiles'],
  ['s-reg', 'Regulatory compliance', 'sec', 'Regulatory compliance', 'Sections'], ['s-ti', 'Threat intelligence', 'sec', 'Threat intelligence', 'Sections'], ['s-ep', 'Endpoint posture', 'sec', 'Endpoint posture', 'Sections'], ['s-rt', 'Readiness trends', 'sec', 'Readiness trends', 'Sections'],
  ['c-post', 'Posture score', 'card', 'Posture score', 'Panels'], ['c-ce', 'Control effectiveness', 'card', 'Control effectiveness', 'Panels'], ['c-live', 'Live campaigns', 'card', 'Live campaigns', 'Panels'], ['c-gaps', 'Top exposure gaps', 'card', 'Top exposure gaps', 'Panels'],
  ['c-runs', 'Recent runs', 'card', 'Recent runs', 'Panels'], ['c-fail', 'Top failing techniques', 'card', 'Top failing techniques', 'Panels'], ['c-flow', 'Attack flow', 'card', 'Attack flow', 'Panels'], ['c-rans', 'Ransomware readiness', 'card', 'Ransomware readiness', 'Panels'], ['c-tac', 'ATT&CK tactic coverage', 'card', 'ATT&CK tactic coverage', 'Panels'],
  ['c-det', 'Detection rate trend', 'card', 'Detection rate', 'Charts & lists'], ['c-daily', 'Daily validations', 'card', 'Daily validations', 'Charts & lists'], ['c-valr', 'Recent validation runs', 'card', 'Recent validation runs', 'Charts & lists'], ['c-cov', 'Top coverage gaps', 'card', 'Top coverage gaps', 'Charts & lists'],
  ['c-ah', 'Agent health by group', 'card', 'Agent health by group', 'Charts & lists'], ['c-al', 'Recent alerts', 'card', 'Recent alerts', 'Charts & lists'], ['c-act', 'Activity', 'card', 'Activity', 'Charts & lists'], ['c-next', 'Up next', 'card', 'Up next', 'Charts & lists']];
const EXE = [
  ['e-risk', 'Risk score tile', 'kpi', 'Risk score', 'Summary tiles'], ['e-exp', 'Exposure score tile', 'kpi', 'Exposure score', 'Summary tiles'], ['e-det', 'Detection coverage tile', 'kpi', 'Detection coverage', 'Summary tiles'], ['e-fleet', 'Fleet assets tile', 'kpi', 'Fleet assets', 'Summary tiles'],
  ['x-fc', 'Risk-score forecast', 'card', 'Risk-score forecast', 'Panels'], ['x-post', 'Overall posture', 'card', 'Overall posture', 'Panels'], ['x-win', 'Open exposure windows', 'card', 'Open exposure windows', 'Panels'], ['x-chg', 'What changed this period', 'card', 'What changed', 'Panels'],
  ['x-dom', 'Posture by domain', 'card', 'Posture by domain', 'Panels'], ['x-biz', 'Top business risks', 'card', 'Top business risks', 'Panels']];
const hidden = () => (S.dashHide = S.dashHide || LS.get('dashhide', {}));
const strip = (root, list) => {
  const off = hidden(), txt = e => e.textContent.replace(/\s+/g, ' ').trim();
  list.filter(w => off[w[0]]).forEach(([, , kind, m]) => {
    if (kind === 'kpi') root.querySelectorAll('.kpi, .real-tile').forEach(k => { const l = k.querySelector('.lbl, .lbl-s'); if (l && txt(l).toLowerCase().startsWith(m.toLowerCase())) k.remove(); });
    else if (kind === 'card') root.querySelectorAll('.card').forEach(c => { const hd = c.querySelector(':scope > .card-hd h2'); if (hd && txt(hd).startsWith(m)) c.remove(); });
    else root.querySelectorAll('.sec-label').forEach(l => { if (txt(l) === m) { const row = l.closest('.sec-row') || l; const nx = row.nextElementSibling; if (nx) nx.remove(); row.remove(); } });
  });
  root.querySelectorAll('.grid').forEach(g => { if (!g.children.length) g.remove(); });
};
const orig = P.dashboard;
P.dashboard = (...a) => { const box = document.createElement('div'); box.innerHTML = orig(...a); strip(box, S.dashView === 'operational' ? OPS : EXE); return box.innerHTML; };

const view = () => LS.get('dashdefault', 'operational');
const group = (list, name) => `<div class="dp-group"><div class="lbl-s">${name.toUpperCase()}</div>${list.filter(w => w[4] === name).map(w => `<div class="check-row"><span class="grow">${w[1]}</span><button class="switch ${hidden()[w[0]] ? '' : 'on'}" data-act="dpToggle" data-a="${w[0]}" aria-label="${w[1]}"></button></div>`).join('')}</div>`;
window.dashPrefsHtml = () => {
  const cur = view(), off = Object.values(hidden()).filter(Boolean).length;
  const opt = (v, t, d) => `<div class="radio-card ${cur === v ? 'on' : ''}" data-act="dpDefault" data-a="${v}" tabindex="0"><div><b>${t}</b><span>${d}</span></div></div>`;
  return `<div class="card"><h2 class="mb">Dashboard Preferences</h2><p class="muted" style="margin-top:0;font-size:12.5px">Choose which view the Dashboard tab opens to. Saved locally in your browser.</p>
    <div class="grid g3 mb">${opt('operational', 'Operational', 'Always land on the Operational view')}${opt('executive', 'Executive', 'Always land on the Executive view')}${opt('last', 'Last used', 'Remember whichever view I had open last')}</div></div>
  <div class="grid g2 mt"><div class="card"><div class="row between"><h2>Operational view widgets</h2><span class="muted" style="font-size:12px">${OPS.length} widgets</span></div>${['Summary tiles', 'Sections', 'Panels', 'Charts & lists'].map(g => group(OPS, g)).join('')}</div>
    <div class="card"><div class="row between"><h2>Executive view widgets</h2><span class="muted" style="font-size:12px">${EXE.length} widgets</span></div>${['Summary tiles', 'Panels'].map(g => group(EXE, g)).join('')}</div></div>
  <div class="row mt" style="gap:10px"><button class="btn" data-act="dpReset">${ic('refresh')}Show all widgets</button><span class="muted" style="font-size:12.5px;align-self:center">${off ? off + ' widget' + (off > 1 ? 's' : '') + ' hidden' : 'All widgets visible'}</span></div>`;
};
Object.assign(A, {
  dpDefault: d => { LS.set('dashdefault', d.a); if (d.a !== 'last') { S.dashView = d.a; } toast('Default view saved', { operational: 'Operational', executive: 'Executive', last: 'Last used' }[d.a], 'success'); AUD.render(); },
  dpToggle: (d, el) => { const o = hidden(); o[d.a] = !o[d.a]; LS.set('dashhide', o); el.classList.toggle('on', !o[d.a]); const n = Object.values(o).filter(Boolean).length; const s = document.querySelector('[data-act="dpReset"] + span'); if (s) s.textContent = n ? n + ' widget' + (n > 1 ? 's' : '') + ' hidden' : 'All widgets visible'; },
  dpReset: () => { S.dashHide = {}; LS.set('dashhide', {}); toast('All widgets visible', '', 'success'); AUD.render(); }
});
// apply the saved default view at start; remember the last used view
const d0 = view(); S.dashView = d0 === 'last' ? LS.get('dashlast', 'operational') : d0;
const setOrig = A.set; A.set = (d, el) => { setOrig(d, el); if (d.a === 'dashView') LS.set('dashlast', d.b); };
})();
