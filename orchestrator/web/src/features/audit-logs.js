import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { buildReportFilename } from './evidence.js';
import { cssVars } from '../core/css-vars.js';


// ── Audit Logs ────────────────────────────────────────────────────────────────
var AUDIT_OFFSET = 0;
var AUDIT_LIMIT  = 50;
var AUDIT_TOTAL  = 0;

var AUDIT_ACTION_LABELS = {
  'user.login':                'Login',
  'user.create':               'User created',
  'user.update':               'User updated',
  'user.delete':               'User deleted',
  'user.change_password':      'Password changed',
  'user.reset_password':       'Password reset',
  'scenario.run':              'Scenario run',
  'scenario.cancel':           'Scenario cancelled',
  'campaign.create':           'Campaign created',
  'campaign.stop':             'Campaign stopped',
  'scenario.create':           'Scenario created',
  'scenario.update':           'Scenario updated',
  'scenario.delete':           'Scenario deleted',
  'finding.status_change':     'Finding status changed',
  'agent.enroll':              'Agent enrolled',
  'attackpath.collect':        'AP collected',
  'attackpath.schedule_update':'AP schedule updated',
  'attackpath.asset_tag':      'Asset tagged',
  'report.export':             'Report exported',
  'tamper.acknowledge':        'Tamper ack',
  'tamper.acknowledge_all':    'Tamper ack all',
  'connector.sync':            'Connector sync',
  'art.reseed':                'ART reseed',
};

export function loadAuditLogs() {
  AUDIT_OFFSET = 0;
  fetchAuditPage();
}

export function loadLicenseInfo() {
  var wrap = document.getElementById('license-card-wrap');
  if (!wrap) return;
  wrap.innerHTML = '<div class="empty g1-s-be6df18e">Loading…</div>';
  apicall('/api/license').then(function(lic) {
    if (lic.error) { wrap.innerHTML = '<div class="empty g1-s-8e56e4c3">' + x(lic.error) + '</div>'; return; }
    var statusColor = lic.status === 'valid' ? 'var(--success)' : lic.status === 'grace' ? 'var(--warning)' : lic.status === 'locked' ? 'var(--danger)' : 'var(--muted)';
    var statusLabel = lic.status === 'valid' ? 'Active' : lic.status === 'grace' ? 'Grace Period' : lic.status === 'locked' ? 'Locked' : 'Unknown';
    var features = (lic.features || []).map(function(f) {
      return '<span class="sbadge g1-display-inline-block g1-s-221fcf42">' + x(f) + '</span>';
    }).join('');
    wrap.innerHTML =
      '<div class="conn-cfg-card g1-s-ed5b0ac3">' +
        '<div class="g1-display-flex g1-s-7cd1f313">' +
          '<div class="g1-s-0c5a3e12">Entitlement</div>' +
          '<span class="sbadge g1-s-1b1dd8f9"' + cssVars(['g1-v-9a515764', statusColor], ['g1-v-7d75dfc9', statusColor], ['g1-v-d59a9269', statusColor]) + '>' + statusLabel + '</span>' +
        '</div>' +
        _licRow('Customer',    x(lic.customer   || '-')) +
        _licRow('Customer ID', x(lic.customerId || '-')) +
        _licRow('Issued',      x(lic.issuedAt   || '-')) +
        _licRow('Expires',     '<span class="g1-s-6e8bcfac"' + cssVars(['g1-v-7d75dfc9', statusColor]) + '>' + x(lic.expiresAt || '-') + '</span>') +
        (lic.status === 'grace' ? _licRow('Grace Period', '<span class="g1-s-adc02b25">' + lic.daysRemaining + ' day(s) remaining — access disabled on ' + x(lic.lockoutAt) + '</span>') : '') +
        (features ? '<div class="g1-display-flex g1-s-17f7ed50"><span class="g1-s-39e35912">Features</span><div>' + features + '</div></div>' : '') +
      '</div>';
  }).catch(function(e) { wrap.innerHTML = '<div class="empty g1-s-8e56e4c3">' + x(e.message) + '</div>'; });
}

function _licRow(label, val) {
  return '<div class="g1-display-flex g1-s-96ef72d9">' +
    '<span class="g1-s-39e35912">' + label + '</span>' +
    '<span class="g1-s-7f5e108a">' + val + '</span>' +
    '</div>';
}

var BACKUP_STATUS_LABEL = {
  requested: 'Requested', running: 'Running…', protected: 'Protected',
  local_success: 'Local only', remote_failed: 'Remote failed', failed: 'Failed'
};
var BACKUP_STATUS_COLOR = {
  requested: 'var(--muted)', running: 'var(--accent)', protected: 'var(--success)',
  local_success: 'var(--warning)', remote_failed: 'var(--danger)', failed: 'var(--danger)'
};
var BACKUP_POLL_TIMER = null;

export function loadBackups() {
  var wrap = document.getElementById('backup-status-card-wrap');
  apicall('/api/backups').then(function(jobs) {
    if (jobs.error) {
      if (wrap) wrap.innerHTML = '<div class="empty g1-s-8e56e4c3">' + x(jobs.error) + '</div>';
      return;
    }
    renderBackupStatusCard(jobs[0] || null);
    renderBackupJobsTable(jobs);
  }).catch(function(e) {
    if (wrap) wrap.innerHTML = '<div class="empty g1-s-8e56e4c3">' + x(e.message) + '</div>';
  });
}

function renderBackupStatusCard(job) {
  var wrap = document.getElementById('backup-status-card-wrap');
  if (!wrap) return;
  if (!job) {
    wrap.innerHTML = '<div class="conn-cfg-card"><div class="empty g1-s-c19e0f28">No backups yet. Click "Backup Now" to create one.</div></div>';
    return;
  }
  var color = BACKUP_STATUS_COLOR[job.status] || 'var(--muted)';
  var label = BACKUP_STATUS_LABEL[job.status] || job.status;
  var size = job.archiveSizeBytes ? (job.archiveSizeBytes / 1048576).toFixed(1) + ' MB' : '—';
  wrap.innerHTML =
    '<div class="conn-cfg-card">' +
      '<div class="g1-display-flex g1-s-c91d8485">' +
        '<div class="g1-s-0c5a3e12">Most recent backup</div>' +
        '<span class="sbadge g1-s-1b1dd8f9"' + cssVars(['g1-v-9a515764', color], ['g1-v-7d75dfc9', color], ['g1-v-d59a9269', color]) + '>' + x(label) + '</span>' +
      '</div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Requested</span><span class="conn-cfg-val">' + x(new Date(job.requestedAt).toLocaleString()) + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Trigger</span><span class="conn-cfg-val">' + x(job.trigger) + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Size</span><span class="conn-cfg-val">' + size + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Local</span><span class="conn-cfg-val">' + (job.localPath ? '✓' : '—') + '</span></div>' +
      '<div class="conn-cfg-row"><span class="conn-cfg-label">Remote</span><span class="conn-cfg-val">' + (job.remotePath ? '✓' : (job.status === 'local_success' ? '✗' : '—')) + '</span></div>' +
      (job.errorMessage ? '<div class="conn-cfg-row"><span class="conn-cfg-label">Error</span><span class="conn-cfg-val u-danger">' + x(job.errorMessage) + '</span></div>' : '') +
    '</div>';
}

function renderBackupJobsTable(jobs) {
  var tbody = document.getElementById('backup-jobs-body');
  if (!tbody) return;
  if (!jobs.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="g1-s-6928ed1e">No backups yet.</td></tr>';
    return;
  }
  tbody.innerHTML = jobs.map(function(j) {
    var color = BACKUP_STATUS_COLOR[j.status] || 'var(--muted)';
    var label = BACKUP_STATUS_LABEL[j.status] || j.status;
    var canRestore = (j.status === 'protected' || j.status === 'local_success');
    return '<tr class="g1-s-76497c6f">' +
      '<td class="g1-s-b86389a4">' + x(new Date(j.requestedAt).toLocaleString()) + '</td>' +
      '<td class="g1-s-b86389a4">' + x(j.trigger) + '</td>' +
      '<td class="g1-s-b86389a4">' + (j.localPath ? '✓' : '—') + '</td>' +
      '<td class="g1-s-b86389a4">' + (j.remotePath ? '✓' : '—') + '</td>' +
      '<td class="g1-s-b86389a4"><span class="sbadge g1-s-62899a0f"' + cssVars(['g1-v-9a515764', color], ['g1-v-7d75dfc9', color], ['g1-v-d59a9269', color]) + '>' + x(label) + '</span></td>' +
      '<td class="g1-s-b86389a4">' +
        (canRestore ? '<button class="btn btn-outline btn-sm"' + on('click', 'prepareRestore', j.id) + '>Prepare Restore</button>' : '—') +
      '</td>' +
    '</tr>';
  }).join('');
}

export function backupNow() {
  var btn = document.getElementById('backup-now-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Requesting…'; }
  apicall('/api/backups', { method: 'POST' }).then(function(job) {
    if (job.error) { alert('Backup request failed: ' + job.error); if (btn) { btn.disabled = false; btn.textContent = 'Backup Now'; } return; }
    loadBackups();
    pollBackupJob(job.id, btn);
  }).catch(function(e) {
    alert('Backup request failed: ' + e.message);
    if (btn) { btn.disabled = false; btn.textContent = 'Backup Now'; }
  });
}

function pollBackupJob(id, btn) {
  if (BACKUP_POLL_TIMER) clearInterval(BACKUP_POLL_TIMER);
  BACKUP_POLL_TIMER = setInterval(function() {
    apicall('/api/backups/' + id).then(function(job) {
      if (job.error) { clearInterval(BACKUP_POLL_TIMER); return; }
      renderBackupStatusCard(job);
      if (job.status !== 'requested' && job.status !== 'running') {
        clearInterval(BACKUP_POLL_TIMER);
        loadBackups();
        if (btn) { btn.disabled = false; btn.textContent = 'Backup Now'; }
      }
    }).catch(function() { clearInterval(BACKUP_POLL_TIMER); });
  }, 4000);
}

export function prepareRestore(id) {
  apicall('/api/backups/' + id + '/restore-marker', { method: 'POST' }).then(function(res) {
    var wrap = document.getElementById('restore-command-wrap');
    if (!wrap) return;
    if (res.error) { wrap.innerHTML = '<div class="empty g1-s-9b78712f">' + x(res.error) + '</div>'; return; }
    wrap.innerHTML =
      '<div class="conn-cfg-card g1-s-7b0aa428">' +
        '<div class="g1-s-21b099fc">Restore must be run on the host</div>' +
        '<div class="g1-s-1236f559">This console cannot and will not run this for you. An administrator with root access to the server must run the command below and type <b>RESTORE</b> to confirm.</div>' +
        '<code class="g1-display-block g1-s-dca1d235">' + x(res.restoreCommand) + '</code>' +
      '</div>';
  }).catch(function(e) { alert('Failed to prepare restore: ' + e.message); });
}

export function auditPage(dir) {
  AUDIT_OFFSET = Math.max(0, AUDIT_OFFSET + dir * AUDIT_LIMIT);
  fetchAuditPage();
}

function fetchAuditPage() {
  var action = document.getElementById('audit-filter-action').value || '';
  var actor  = (document.getElementById('audit-search-actor').value || '').trim();
  var qs = '?limit=' + AUDIT_LIMIT + '&offset=' + AUDIT_OFFSET;
  if (action) qs += '&action=' + encodeURIComponent(action);
  if (actor)  qs += '&actor='  + encodeURIComponent(actor);
  apicall('/api/audit-logs' + qs).then(function(d) {
    var entries = d.entries || [];
    AUDIT_TOTAL = entries.length; // approximate
    var tbody = document.getElementById('audit-body');
    if (!tbody) return;
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="g1-s-5b31a60f">No audit records found.</td></tr>';
    } else {
      tbody.innerHTML = entries.map(function(e) {
        var ts = new Date(e.ts);
        var tsStr = ts.toLocaleDateString() + ' ' + ts.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
        var actionLabel = AUDIT_ACTION_LABELS[e.action] || e.action;
        var outcomeClass = e.outcome === 'ok' ? 'g1-display-inline-block g1-s-8e6255cd' : 'g1-display-inline-block g1-s-55cda534';
        var detail = '';
        try {
          var d2 = typeof e.detail === 'string' ? JSON.parse(e.detail) : e.detail;
          var parts = [];
          if (d2.username) parts.push('user: ' + d2.username);
          if (d2.role) parts.push('role: ' + d2.role);
          if (d2.scenarioId) parts.push('scenario: ' + d2.scenarioId);
          if (d2.name) parts.push('name: ' + d2.name);
          if (d2.mode) parts.push('mode: ' + d2.mode);
          if (d2.agentId) parts.push('agent: ' + d2.agentId);
          if (d2.hostname) parts.push('host: ' + d2.hostname);
          if (d2.ip) parts.push('ip: ' + d2.ip);
          if (d2.trusted != null) parts.push('trusted: ' + d2.trusted);
          if (d2.state) parts.push('state: ' + d2.state);
          if (d2.reason) parts.push('reason: ' + d2.reason);
          if (d2.status) parts.push('status: ' + d2.status);
          if (d2.format) parts.push('format: ' + d2.format);
          if (d2.type) parts.push('type: ' + d2.type);
          if (d2.crownJewel) parts.push('crown-jewel: ' + d2.crownJewel);
          if (d2.highValue) parts.push('high-value');
          if (d2.criticalityTier) parts.push('criticality: ' + d2.criticalityTier);
          if (d2.version) parts.push('v: ' + d2.version);
          if (d2.techniqueCount != null) parts.push('techniques: ' + d2.techniqueCount);
          if (d2.enabled != null) parts.push('enabled: ' + d2.enabled);
          if (d2.intervalMinutes) parts.push('interval: ' + d2.intervalMinutes + 'min');
          if (d2.agents != null) parts.push('agents: ' + d2.agents);
          if (d2.dispatched != null) parts.push('dispatched: ' + d2.dispatched);
          detail = parts.join(' · ');
          if (!detail && e.resource) detail = e.resource;
        } catch(ex) { detail = e.resource || ''; }
        return '<tr>' +
          '<td class="g1-s-a6cceef3">' + tsStr + '</td>' +
          '<td class="g1-s-42bb765b">' + x(e.actorName) + '</td>' +
          '<td class="g1-s-51a7b72a">' + x(actionLabel) + '</td>' +
          '<td class="g1-s-dc3f58e3">' + x(detail) + '</td>' +
          '<td class="g1-s-e787dcbc">' + x(e.ip || '') + '</td>' +
          '<td><span class="' + outcomeClass + '">' + x(e.outcome) + '</span></td>' +
        '</tr>';
      }).join('');
    }
    var rangeEl = document.getElementById('audit-range-label');
    if (rangeEl) {
      var from = AUDIT_OFFSET + 1;
      var to = AUDIT_OFFSET + entries.length;
      rangeEl.textContent = entries.length ? from + '–' + to + ' shown' : '';
    }
    var prevBtn = document.getElementById('audit-prev-btn');
    var nextBtn = document.getElementById('audit-next-btn');
    if (prevBtn) prevBtn.disabled = AUDIT_OFFSET === 0;
    if (nextBtn) nextBtn.disabled = entries.length < AUDIT_LIMIT;
  }).catch(function() {
    var tbody = document.getElementById('audit-body');
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="g1-s-6c42391e">Failed to load audit logs.</td></tr>';
  });
}

export function exportAuditLogs() {
  var action = document.getElementById('audit-filter-action').value || '';
  var actor  = (document.getElementById('audit-search-actor').value || '').trim();
  apicall('/api/audit-logs?limit=500&offset=0' +
    (action ? '&action=' + encodeURIComponent(action) : '') +
    (actor  ? '&actor='  + encodeURIComponent(actor)  : '')
  ).then(function(d) {
    var rows = (d.entries || []);
    var csv = 'Time,User,Action,Resource,Detail,IP,Outcome\n' + rows.map(function(e) {
      var det = '';
      try { det = JSON.stringify(e.detail); } catch(_err) {}
      return [e.ts, e.actorName, e.action, e.resource, det, e.ip, e.outcome]
        .map(function(v) { return '"' + String(v||'').replace(/"/g,'""') + '"'; }).join(',');
    }).join('\n');
    var a = document.createElement('a');
    a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
    a.download = buildReportFilename('Audit_Logs', actor || 'all', 'csv');
    a.click();
  }).catch(function(e) { showToast('Export failed: ' + e.message, 'err'); });
}