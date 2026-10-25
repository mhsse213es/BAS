// Results drawer header actions (JSON / HTML / PDF / CSV / Compare / Re-run), mirroring the real console:
// JSON downloads directly; HTML, PDF and CSV first ask which results to include; Re-run shows a read-only review.
(() => {
const { S, A, toast, modal, closeModal } = AUD;
const { drawer, dhd } = AUD.h;
const run = id => D.RUNS.find(r => r.id === id) || D.RUNS[0];
const scOf = r => D.SCENARIOS.find(s => s.id === (AUD.h.RUN_SC || {})[r.id]) || D.SCENARIOS[0];
const ts = () => new Date().toISOString().slice(0, 19).replace('T', '_').replace(/:/g, '-');
const VERD = ['Prevented', 'Detected', 'Missed', 'Not detected'];
const rows = (r, f) => {
  const s = scOf(r), all = s.tech.concat(s.tech).slice(0, Math.max(6, s.tech.length)).map((t, i) => [i + 1, t, VERD[i % 4]]);
  const keep = { all: () => true, prevented: x => x[2] === 'Prevented', not_prevented: x => x[2] !== 'Prevented', detected: x => x[2] === 'Detected', not_detected: x => x[2] === 'Not detected' }[f] || (() => true);
  return all.filter(keep);
};
const save = (name, text, type) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); };
const FILTERS = [['all', 'All simulation results (Default)'], ['prevented', 'Prevented only'], ['not_prevented', 'Not prevented only'], ['detected', 'Detected only'], ['not_detected', 'Not detected only']];
const dlg = (title, id, kind) => modal(`<div class="modal-bd"><h3 style="margin:0 0 12px">${title}</h3><div class="lbl-s" style="margin-bottom:8px">SELECT RESULTS TO INCLUDE IN THE REPORT:</div><div class="rw-opts">${FILTERS.map(([v, l], i) => `<label class="rw-radio ${i ? '' : 'on'}"><input type="radio" name="dlf" value="${v}" ${i ? '' : 'checked'}><span>${l}</span></label>`).join('')}</div></div><div class="modal-ft"><button class="btn" data-act="closeModal">Cancel</button><button class="btn primary" data-act="resDlGo" data-a="${id}" data-b="${kind}">Confirm &amp; Download</button></div>`, 'sm');
Object.assign(A, {
  resJson: d => { const r = run(d.a); save(`Run_Export_${d.a}_${ts()}.json`, JSON.stringify({ run: r, steps: rows(r, 'all').map(([n, t, v]) => ({ step: n, technique: t, verdict: v })) }, null, 2), 'application/json'); toast('JSON downloaded', `Run_Export_${d.a}.json`, 'success'); },
  resDl: d => dlg({ html: 'Simulation HTML Report', pdf: 'Simulation Report', csv: 'Simulation Forensic CSV' }[d.b], d.a, d.b),
  resDlGo: d => {
    const f = (document.querySelector('input[name="dlf"]:checked') || {}).value || 'all', r = run(d.a), rs = rows(r, f);
    closeModal();
    if (d.b === 'csv') { save(`BAS_Forensic_${d.a}${f === 'all' ? '' : '-' + f}_${ts()}.csv`, 'step,technique,verdict\n' + rs.map(x => x.join(',')).join('\n'), 'text/csv'); toast('CSV downloaded', `${rs.length} rows · filter: ${f}`, 'success'); }
    else if (d.b === 'html') {
      const w = window.open('', '_blank');
      if (w) { w.document.write(`<title>${r.name} — report</title><body style="font:14px system-ui;background:#0b1220;color:#e5e7eb;padding:32px"><h1>${r.name}</h1><p>${d.a} · filter: ${f}</p><table border=1 cellpadding=8 style="border-collapse:collapse"><tr><th>#</th><th>Technique</th><th>Verdict</th></tr>${rs.map(x => `<tr><td>${x[0]}</td><td>${x[1]}</td><td>${x[2]}</td></tr>`).join('')}</table>`); w.document.close(); }
      else toast('Pop-up blocked', 'Allow pop-ups to open the HTML report', 'warn');
    } else toast('PDF report generated', `BAS_Report_${d.a}_${ts()}.pdf · filter: ${f} (demo: no file produced)`, 'success');
  },
  resRerun: d => {
    const r = run(d.a), s = scOf(r), row = (k, v) => `<div class="rr-row"><span class="muted">${k}</span><b>${v}</b></div>`;
    drawer(dhd('Re-run Review', d.a, 'refresh') + `<div class="drawer-bd"><p class="muted" style="font-size:12.5px;margin-top:0">Exact clone of the original run's configuration — nothing below is editable.</p><div class="card" style="padding:4px 14px">${row('Scenario', r.name)}${row('Agent', r.target)}${row('Mode', 'Posture — read-only')}${row('Privilege ceiling', 'No limit')}${row('Techniques', s.tech.length + ' — ' + s.tech.join(', '))}</div></div><div class="drawer-ft"><button class="btn" data-act="closeDrawer">Cancel</button><button class="btn primary" data-act="resRerunGo" data-a="${d.a}">▶ Start Re-run</button></div>`);
  },
  resRerunGo: d => {
    const r = run(d.a), id = 'RUN-' + (5600 + D.RUNS.length);
    D.RUNS.unshift({ id, name: r.name, target: r.target, status: 'Running', progress: 2, step: 'Preflight checks', started: 'just now', dur: '0m 04s' });
    AUD.h.closeDrawer(); toast('Re-run started', `${id} · ${r.name}`, 'success'); AUD.go('runs');
  }
});
document.head.insertAdjacentHTML('beforeend', '<style>.rr-row{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--border);font-size:13px}.rr-row:last-child{border:0}.rr-row b{text-align:right;font-weight:600}</style>');
})();
