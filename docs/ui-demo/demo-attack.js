// Attack Path Validation: every button does something (validate, collect, tag, schedule, about, history, score breakdown).
(() => {
const { S, P, A, h, toast } = AUD;
S.apHist = S.apHist || [['22/10/2026, 17:30', 'Completed', '412 relationships · 3 paths'], ['15/10/2026, 17:30', 'Completed', '398 relationships · 3 paths'], ['08/10/2026, 17:30', 'Completed', '377 relationships · 2 paths']];
const apRep = html => html
  .replace(/<button class="btn primary" data-act="toast" data-a="Path validation started" data-b="[^"]*">/, `<button class="btn primary" data-act="apValidate" ${S.apBusy ? 'disabled' : ''}>`)
  .replace('data-act="toast" data-a="Collection started" data-b="Recon only — no exploitation" data-c="success">▶ Run Collection', `data-act="apCollect" ${S.apCol ? 'disabled' : ''}>${S.apCol ? '⟳ Collecting…' : '▶ Run Collection'}`)
  .replace('data-act="toast" data-a="Tag assets" data-b="Mark crown jewels">', 'data-act="apTag">')
  .replace('data-act="toast" data-a="Schedule" data-b="Collection schedule">', 'data-act="apSched">')
  .replace(/data-act="toast" data-a="About" data-b="[^"]*" data-c="info">/, 'data-act="apAbout">')
  .replace('data-act="toast" data-a="History" data-b="Previous collections">', 'data-act="apHist">')
  .replace('data-act="toast" data-a="Score breakdown" data-b="Lateral 40% · Domain 40% · Scope 20%">Score breakdown ▼', `data-act="apScore">Score breakdown ${S.apScore ? '▲' : '▼'}`)
  .replace(/(Score breakdown [▼▲]<\/button>)/, `$1${S.apScore ? '<div class="muted" style="font-size:12.5px;margin-top:10px;line-height:1.7">Lateral movement <b>40%</b> · Domain compromise <b>40%</b> · Scope <b>20%</b></div>' : ''}`);
['attackpath', 'attack-paths'].forEach(r => { if (P[r]) P[r] = (o => () => apRep(o()))(P[r]); });
const redraw = () => { if (S.route === 'attackpath') { S.keepScroll = true; AUD.render(); } };
Object.assign(A, {
  apValidate: () => { const p = D.ATTACK_PATHS.find(x => x.id === S.apSel) || D.ATTACK_PATHS[0]; S.apBusy = 1; toast('Path validation started', p.name, 'success'); S.keepScroll = true; AUD.render();
    setTimeout(() => { S.apBusy = 0; p.validated = true; toast('Path validated', `${p.name} · objective reached`, 'warn'); redraw(); }, 3000); },
  apCollect: () => { S.apCol = 1; toast('Collection started', 'Recon only — no exploitation', 'success'); S.keepScroll = true; AUD.render();
    setTimeout(() => { S.apCol = 0; S.apHist.unshift([new Date().toLocaleString('en-GB'), 'Completed', '421 relationships · 3 paths']); toast('Collection complete', '421 relationships mapped', 'success'); redraw(); }, 3500); },
  apTag: () => AUD.modal(h.mhd('Tag crown-jewel assets', 'flag') + `<div class="modal-bd"><div class="muted" style="font-size:12.5px;margin-bottom:10px">Marked assets become attack-path objectives.</div>${['DC-PRI-01', 'SQL-PROD-02', 'FIN-DB-01', 'CA-ROOT-01', 'FS-HR-01'].map(a => `<label class="rw-item"><input type="checkbox" class="ap-t" value="${a}" ${(S.apTags || []).includes(a) ? 'checked' : ''}><span class="mono">${a}</span></label>`).join('')}</div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="apTagSave">Save tags</button></div>`),
  apTagSave: () => { S.apTags = [...document.querySelectorAll('.ap-t:checked')].map(x => x.value); AUD.closeModal(); toast('Crown jewels updated', `${S.apTags.length} asset(s) tagged`, 'success'); },
  apSched: () => AUD.modal(h.mhd('Schedule collection', 'clock') + `<div class="modal-bd"><div class="field"><label>Frequency</label><select class="select" id="aps-f" style="width:100%">${['Daily', 'Weekly', 'Monthly'].map(x => `<option ${S.apSched === x ? 'selected' : ''}>${x}</option>`).join('')}</select></div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="apSchedSave">Save schedule</button></div>`),
  apSchedSave: () => { S.apSched = document.getElementById('aps-f').value; AUD.closeModal(); toast('Collection scheduled', S.apSched, 'success'); },
  apAbout: () => AUD.modal(h.mhd('About attack path collection', 'help') + `<div class="modal-bd">Collection is recon only: it maps relationships (sessions, group membership, ACLs, trusts) to build attack paths. It performs no exploitation or propagation.</div><div class="modal-ft"><button class="btn primary" data-act="closeModal">Close</button></div>`),
  apHist: () => h.drawer(h.dhd('Collection history', `${S.apHist.length} collections`, 'clock') + `<div class="drawer-bd">${h.table(['Started', 'Status', 'Result'], S.apHist.map(r => `<tr class="noclick"><td class="mono">${r[0]}</td><td>${h.tag(r[1], 'green')}</td><td>${r[2]}</td></tr>`))}</div>`),
  apScore: () => { S.apScore = !S.apScore; S.keepScroll = true; AUD.render(); }
});
})();
