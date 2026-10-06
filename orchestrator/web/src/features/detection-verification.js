import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { fmtDate, showToast } from '../core/util.js';


// ── Detection Verification (SP2) ───────────────────────────────────────────
// Manual-attestation queue: turn off-host Pending expectations into analyst-
// verified Detected/NotDetected results backed by hashed evidence. Reads/writes
// the independent Verification Store; every action is audited server-side.
var VF = { runId:'', items:[], domain:'', perms:null, selected:'' };
var VF_DOMAINS = ['siem','identity','cloud','dlp','network','email'];

function vfCan(p) { return VF.perms && VF.perms.indexOf(p) !== -1; }

export function vfStatusColor(s) {
  switch (s) {
    case 'Detected': return 'var(--success)';
    case 'NotDetected': return 'var(--danger)';
    case 'NotApplicable': return 'var(--muted)';
    case 'Approved': return 'var(--success)';
    case 'Rejected': return 'var(--danger)';
    case 'NeedsReview': return 'var(--warning)';
    default: return 'var(--warning)'; // Pending
  }
}
function vfStatusLabel(s) {
  switch (s) {
    case 'Detected': return 'DETECTED';
    case 'NotDetected': return 'SILENT';
    case 'NotApplicable': return 'N/A';
    case 'NeedsReview': return 'NEEDS REVIEW';
    default: return x((s || 'Pending').toUpperCase());
  }
}

export function loadVerificationTab() {
  // Load caller permissions once so controls can be enabled/disabled.
  if (!VF.perms) {
    apicall('/api/me/permissions').then(function(d) {
      VF.perms = (d && d.permissions) || [];
    }).catch(function(){ VF.perms = []; });
  }
  vfRenderDomainChips();
  // Populate the run selector (reuse the runs list).
  apicall('/api/scenarios/runs').then(function(runs) {
    var sel = document.getElementById('vf-run');
    if (!sel) return;
    var cur = VF.runId;
    var opts = '<option value="">Select a run…</option>' + (runs || []).map(function(r) {
      var label = (r.name || r.id) + ' · ' + (r.agentId || '') + ' · ' + fmtDate(r.startedAt);
      return '<option value="' + x(r.id) + '"' + (r.id === cur ? ' selected' : '') + '>' + x(label) + '</option>';
    }).join('');
    sel.innerHTML = opts;
    if (cur) vfLoadQueue();
  }).catch(function(e){ showToast(e.message, 'err'); });
}

function vfRenderDomainChips() {
  var wrap = document.getElementById('vf-domain-chips');
  if (!wrap) return;
  var all = [{k:'',label:'All domains'}].concat(VF_DOMAINS.map(function(d){ return {k:d,label:d}; }));
  wrap.innerHTML = all.map(function(d) {
    var active = VF.domain === d.k;
    return '<span onclick="vfSetDomain(\'' + d.k + '\')" style="cursor:pointer;text-transform:capitalize;padding:0.3rem 0.7rem;border-radius:999px;font-size:0.74rem;border:1px solid ' +
      (active ? 'var(--accent)' : 'var(--border)') + ';color:' + (active ? 'var(--accent)' : 'var(--muted)') +
      ';background:' + (active ? 'rgba(79,142,247,0.12)' : 'transparent') + '">' + x(d.label) + '</span>';
  }).join('');
}

export function vfSetDomain(d) { VF.domain = d; vfRenderDomainChips(); if (VF.runId) vfLoadQueue(); }

export function vfLoadQueue() {
  var sel = document.getElementById('vf-run');
  VF.runId = sel ? sel.value : '';
  VF.selected = '';
  var box = document.getElementById('vf-queue');
  if (!VF.runId) { box.innerHTML = '<div class="empty" style="padding:2.5rem;text-align:center;color:var(--muted)">Select a run to load its pending verifications.</div>'; document.getElementById('vf-summary').textContent = ''; return; }
  box.innerHTML = '<div class="empty" style="padding:2.5rem;text-align:center;color:var(--muted)">Loading…</div>';
  var q = '/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications' + (VF.domain ? ('?domain=' + encodeURIComponent(VF.domain)) : '');
  apicall(q).then(function(d) {
    if (d && d.error) { box.innerHTML = '<div class="empty" style="padding:2rem;color:var(--danger)">' + x(d.error) + '</div>'; return; }
    VF.items = (d && d.items) || [];
    vfRenderQueue();
  }).catch(function(e){ box.innerHTML = '<div class="empty" style="padding:2rem;color:var(--danger)">' + x(e.message) + '</div>'; });
}

function vfRenderQueue() {
  var box = document.getElementById('vf-queue');
  var items = VF.items;
  var pending = items.filter(function(i){ return i.status === 'Pending' || i.status === 'NeedsReview'; }).length;
  document.getElementById('vf-summary').textContent = items.length + ' expectation' + (items.length===1?'':'s') + ' · ' + pending + ' outstanding';
  if (!items.length) {
    box.innerHTML = '<div class="empty" style="padding:2.5rem;text-align:center;color:var(--muted)">No off-host expectations for this run' + (VF.domain ? ' in the ' + x(VF.domain) + ' domain' : '') + '. Endpoint controls are verified automatically.</div>';
    return;
  }
  var rows = items.map(function(i, idx) {
    var badge = '<span style="font-size:0.7rem;font-weight:700;color:' + vfStatusColor(i.status) + '">' + vfStatusLabel(i.status) + '</span>';
    var wf = (i.workflowState && i.workflowState !== 'Approved' && i.workflowState !== 'Pending') ? '<div style="font-size:0.62rem;color:var(--warning)">' + x(i.workflowState) + '</div>' : '';
    var analyst = i.verifiedBy ? x(i.verifiedBy) : '<span class="u-muted">—</span>';
    var ev = i.evidenceCount ? ('<span style="color:var(--accent)">' + i.evidenceCount + ' file' + (i.evidenceCount===1?'':'s') + '</span>') : '<span class="u-muted">—</span>';
    return '<tr style="border-top:1px solid var(--border)">' +
      '<td style="padding:0.6rem 0.8rem">' + badge + wf + '</td>' +
      '<td style="padding:0.6rem 0.8rem"><code style="font-size:0.72rem">' + x(i.techniqueId) + '</code></td>' +
      '<td style="padding:0.6rem 0.8rem;font-size:0.82rem"><strong>' + x(i.providerDisplay || i.provider) + '</strong></td>' +
      '<td style="padding:0.6rem 0.8rem;font-size:0.78rem;text-transform:capitalize;color:var(--muted)">' + x(i.domain) + '</td>' +
      '<td style="padding:0.6rem 0.8rem;font-size:0.78rem;text-transform:capitalize">' + x(i.confidence) + '</td>' +
      '<td style="padding:0.6rem 0.8rem;font-size:0.78rem">' + analyst + '</td>' +
      '<td style="padding:0.6rem 0.8rem;font-size:0.78rem">' + ev + '</td>' +
      '<td style="padding:0.6rem 0.8rem;text-align:right"><button class="btn btn-outline btn-sm" onclick="vfSelect(\'' + x(i.expectationId) + '\')">' + (i.verificationId ? 'Review' : 'Verify') + '</button></td>' +
      '</tr>';
  }).join('');
  box.innerHTML =
    '<table style="width:100%;border-collapse:collapse">' +
    '<thead><tr style="text-align:left;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.04em;color:var(--muted)">' +
    '<th style="padding:0.6rem 0.8rem">Status</th><th style="padding:0.6rem 0.8rem">Technique</th><th style="padding:0.6rem 0.8rem">Expected Control</th><th style="padding:0.6rem 0.8rem">Domain</th><th style="padding:0.6rem 0.8rem">Confidence</th><th style="padding:0.6rem 0.8rem">Analyst</th><th style="padding:0.6rem 0.8rem">Evidence</th><th></th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table>' +
    '<div id="vf-detail"></div>';
  if (VF.selected) vfSelect(VF.selected);
}

function vfItem(expId) { for (var i=0;i<VF.items.length;i++){ if (VF.items[i].expectationId===expId) return VF.items[i]; } return null; }

export function vfSelect(expId) {
  VF.selected = expId;
  var i = vfItem(expId);
  var host = document.getElementById('vf-detail');
  if (!i || !host) return;
  var canVerify = vfCan('verification:verify');
  var canReview = vfCan('verification:review');
  var resultBtn = function(val, label, col) {
    return '<button type="button" id="vf-res-' + val + '" onclick="vfPickResult(\'' + val + '\')" class="btn btn-outline btn-sm" style="border-color:' + col + ';color:' + col + '">' + label + '</button>';
  };
  var evSection = i.verificationId
    ? '<div style="margin-top:0.9rem"><div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.04em;color:var(--muted);margin-bottom:0.4rem">Evidence <span style="text-transform:none;color:var(--muted)">— SHA-256 recorded at upload</span></div>' +
        '<div id="vf-evlist" style="margin-bottom:0.5rem"></div>' +
        (vfCan('verification:evidence:upload')
          ? '<input type="file" id="vf-evfile" style="font-size:0.78rem"> <button class="btn btn-outline btn-sm" onclick="vfUploadEvidence(\'' + x(i.verificationId) + '\')">Attach</button>'
          : '<div style="font-size:0.74rem;color:var(--muted)">You do not have permission to upload evidence.</div>') +
        '</div>'
    : '<div style="margin-top:0.9rem;font-size:0.74rem;color:var(--muted)">Save a verification first, then attach evidence (screenshots, exported alerts, KQL, CSV).</div>';
  host.innerHTML =
    '<div style="border-top:2px solid var(--accent);background:var(--bg);padding:1rem 1.1rem">' +
    '<div style="display:flex;justify-content:space-between;align-items:baseline;gap:1rem;margin-bottom:0.7rem">' +
      '<div><strong style="font-size:0.9rem">' + x(i.providerDisplay || i.provider) + '</strong> · <code style="font-size:0.72rem">' + x(i.techniqueId) + '</code> · <span style="text-transform:capitalize;color:var(--muted);font-size:0.78rem">' + x(i.domain) + '</span></div>' +
      '<button class="btn btn-outline btn-sm" onclick="vfCloseDetail()">Close</button>' +
    '</div>' +
    (i.profileName ? '<div style="font-size:0.7rem;color:var(--muted);margin-bottom:0.6rem">Validated against <strong>' + x(i.profileName) + '</strong> v' + (i.profileVersion||1) + ' · expectation <code>' + x(i.expectationId) + '</code></div>' : '') +
    (canVerify
      ? '<div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.7rem">' + resultBtn('Detected','Detected','var(--success)') + resultBtn('NotDetected','Not Detected','var(--danger)') + resultBtn('NotApplicable','N/A','var(--muted)') + '</div>' +
        '<input id="vf-alert" placeholder="Linked alert / ticket ID (optional)" value="' + x(i.alertId||'') + '" style="width:100%;padding:0.45rem 0.6rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;font-size:0.8rem;margin-bottom:0.5rem">' +
        '<textarea id="vf-note" placeholder="Analyst note — what did you check, what did you see?" style="width:100%;min-height:56px;padding:0.45rem 0.6rem;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;font-size:0.8rem;margin-bottom:0.5rem">' + x(i.note||'') + '</textarea>' +
        '<input type="hidden" id="vf-result" value="' + x(i.result||'') + '">' +
        '<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">' +
          (canReview
            ? '<button class="btn btn-primary btn-sm" onclick="vfSubmit(\'' + x(i.expectationId) + '\',\'Approved\')">Approve &amp; Save</button>' +
              '<button class="btn btn-outline btn-sm" onclick="vfSubmit(\'' + x(i.expectationId) + '\',\'NeedsReview\')">Submit for Review</button>' +
              '<button class="btn btn-outline-red btn-sm" onclick="vfSubmit(\'' + x(i.expectationId) + '\',\'Rejected\')">Reject</button>'
            : '<button class="btn btn-primary btn-sm" onclick="vfSubmit(\'' + x(i.expectationId) + '\',\'NeedsReview\')">Submit for Review</button>') +
          '<span class="u-flex1"></span>' +
          '<button class="btn btn-outline btn-sm" onclick="vfToggleHistory(\'' + x(i.expectationId) + '\')">History</button>' +
        '</div>'
      : '<div style="font-size:0.78rem;color:var(--muted)">You do not have permission to verify. <button class="btn btn-outline btn-sm" onclick="vfToggleHistory(\'' + x(i.expectationId) + '\')">View History</button></div>') +
    evSection +
    '<div id="vf-history" style="margin-top:0.8rem"></div>' +
    '</div>';
  if (i.result) vfPickResult(i.result);
  if (i.verificationId) vfLoadEvidence(i.verificationId);
  try { host.scrollIntoView({behavior:'smooth', block:'nearest'}); } catch(e){}
}

export function vfCloseDetail() { VF.selected=''; var h=document.getElementById('vf-detail'); if (h) h.innerHTML=''; }

export function vfPickResult(val) {
  var hid = document.getElementById('vf-result');
  if (hid) hid.value = val;
  ['Detected','NotDetected','NotApplicable'].forEach(function(v) {
    var b = document.getElementById('vf-res-' + v);
    if (b) b.style.background = v === val ? 'rgba(79,142,247,0.14)' : 'transparent';
    if (b) b.style.fontWeight = v === val ? '700' : '';
  });
}

export function vfSubmit(expId, workflowState) {
  var result = (document.getElementById('vf-result') || {}).value || '';
  if (!result) { showToast('Pick a result (Detected / Not Detected / N/A) first.', 'err'); return; }
  var note = (document.getElementById('vf-note') || {}).value || '';
  var alertId = (document.getElementById('vf-alert') || {}).value || '';
  apicall('/api/verifications', { method:'POST', body: JSON.stringify({
    runId: VF.runId, expectationId: expId, result: result,
    workflowState: workflowState, note: note, alertId: alertId
  })}).then(function(d) {
    if (d && d.error) { showToast(d.error, 'err'); return; }
    showToast('Verification saved.', 'ok');
    vfLoadQueue();
  }).catch(function(e){ showToast(e.message, 'err'); });
}

export function vfUploadEvidence(verificationId) {
  var inp = document.getElementById('vf-evfile');
  if (!inp || !inp.files || !inp.files.length) { showToast('Choose a file first.', 'err'); return; }
  var fd = new FormData();
  fd.append('file', inp.files[0]);
  fetch('/api/verifications/' + encodeURIComponent(verificationId) + '/evidence', {
    method:'POST', credentials:'same-origin', body: fd
  }).then(function(r){ return r.json().then(function(j){ return {ok:r.ok, j:j}; }); })
    .then(function(res) {
      if (!res.ok) { showToast((res.j && res.j.error) || 'Upload failed', 'err'); return; }
      showToast('Evidence attached — SHA-256 ' + (res.j.contentHash||'').substring(0,12) + '…', 'ok');
      inp.value = '';
      vfLoadEvidence(verificationId);
      // refresh counts in the queue silently
      vfLoadQueueQuiet();
    }).catch(function(e){ showToast(e.message, 'err'); });
}

function vfLoadQueueQuiet() {
  if (!VF.runId) return;
  var q = '/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications' + (VF.domain ? ('?domain=' + encodeURIComponent(VF.domain)) : '');
  apicall(q).then(function(d){ if (d && d.items) { VF.items = d.items; } }).catch(function(){});
}

function vfLoadEvidence(verificationId) {
  var host = document.getElementById('vf-evlist');
  if (!host) return;
  apicall('/api/verifications/' + encodeURIComponent(verificationId) + '/evidence').then(function(d) {
    var list = (d && d.evidence) || [];
    if (!list.length) { host.innerHTML = '<div style="font-size:0.74rem;color:var(--muted)">No evidence attached yet.</div>'; return; }
    var canDel = vfCan('verification:evidence:delete');
    host.innerHTML = list.map(function(e) {
      return '<div style="display:flex;align-items:center;gap:0.6rem;padding:0.4rem 0.55rem;border:1px solid var(--border);border-radius:6px;margin-bottom:0.35rem;font-size:0.76rem">' +
        '<span class="u-success">&#10003;</span>' +
        '<a href="/api/evidence/' + encodeURIComponent(e.id) + '/download" style="color:var(--accent);text-decoration:none">' + x(e.displayFilename || e.originalFilename) + '</a>' +
        '<span class="u-muted">' + vfBytes(e.size) + '</span>' +
        '<span style="color:var(--muted);font-family:monospace;font-size:0.66rem" title="' + x(e.hashAlgorithm) + ': ' + x(e.contentHash) + '">' + x((e.contentHash||'').substring(0,12)) + '…</span>' +
        '<span class="u-flex1"></span>' +
        '<span style="color:var(--muted);font-size:0.68rem">' + x(e.uploadedBy||'') + '</span>' +
        (canDel ? '<button class="btn btn-outline-red btn-sm" onclick="vfDeleteEvidence(\'' + x(e.id) + '\',\'' + x(verificationId) + '\')">Delete</button>' : '') +
        '</div>';
    }).join('');
  }).catch(function(){ host.innerHTML = '<div style="font-size:0.74rem;color:var(--danger)">Failed to load evidence.</div>'; });
}

function vfBytes(n) {
  n = n || 0;
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/1024/1024).toFixed(1) + ' MB';
}

export function vfDeleteEvidence(id, verificationId) {
  if (!confirm('Soft-delete this evidence file? It is retained for audit but hidden from the report.')) return;
  apicall('/api/evidence/' + encodeURIComponent(id), { method:'DELETE' }).then(function(d) {
    if (d && d.error) { showToast(d.error, 'err'); return; }
    showToast('Evidence deleted.', 'ok');
    vfLoadEvidence(verificationId);
    vfLoadQueueQuiet();
  }).catch(function(e){ showToast(e.message, 'err'); });
}

export function vfToggleHistory(expId) {
  var host = document.getElementById('vf-history');
  if (!host) return;
  if (host.getAttribute('data-open') === expId) { host.innerHTML=''; host.removeAttribute('data-open'); return; }
  host.setAttribute('data-open', expId);
  host.innerHTML = '<div style="font-size:0.74rem;color:var(--muted)">Loading history…</div>';
  apicall('/api/scenarios/runs/' + encodeURIComponent(VF.runId) + '/verifications/' + encodeURIComponent(expId) + '/history').then(function(d) {
    var h = (d && d.history) || [];
    if (!h.length) { host.innerHTML = '<div style="font-size:0.74rem;color:var(--muted)">No attestations recorded yet.</div>'; return; }
    host.innerHTML = '<div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.04em;color:var(--muted);margin-bottom:0.4rem">Attestation history (immutable)</div>' +
      h.map(function(r) {
        return '<div style="display:flex;gap:0.6rem;font-size:0.74rem;padding:0.35rem 0;border-bottom:1px solid var(--border)">' +
          '<span style="font-weight:700;color:' + vfStatusColor(r.active ? (r.workflowState==='Approved'?r.result:r.workflowState) : r.result) + '">' + x(r.result) + '</span>' +
          '<span class="u-muted">' + x(r.workflowState) + '</span>' +
          '<span class="u-muted">' + x(r.source) + '</span>' +
          '<span class="u-flex1"></span>' +
          '<span class="u-muted">' + x(r.verifiedBy||'') + '</span>' +
          '<span class="u-muted">' + fmtDate(r.verifiedAt) + '</span>' +
          (r.active ? '<span class="u-success">current</span>' : '<span class="u-muted">superseded</span>') +
          '</div>';
      }).join('');
  }).catch(function(){ host.innerHTML = '<div style="font-size:0.74rem;color:var(--danger)">Failed to load history.</div>'; });
}