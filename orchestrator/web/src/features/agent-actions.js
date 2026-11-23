import { apicallOk } from '../core/api.js';
import { x } from '../core/escape.js';
import { openConfirmDiffModal } from './compliance.js';
import { showToast } from '../core/util.js';
import { loadAgents } from './attack-path.js';
import { _openAgentActionModal } from './integrations.js';


// ── Stop Agent ───────────────────────────────────────────────────────────────
var _stopAgentTargetId = null;

export function openStopAgentModal(agentId, hostname) {
  _stopAgentTargetId = agentId;
  _openAgentActionModal(hostname, 'stop-agent');
}

export function closeStopAgentModal() {
  document.getElementById('stop-agent-overlay').classList.remove('open');
}

export function submitStopAgent() {
  if (!_stopAgentTargetId) return;
  var reason = document.getElementById('stop-agent-reason').value.trim();
  if (!reason) { showToast('Reason is required', 'err'); return; }
  askSure('Stop agent permanently?', 'This cannot be undone remotely.', reason, 'Stop agent', function() {
  var btn = document.getElementById('stop-agent-submit-btn');
  btn.disabled = true;
  apicallOk('/api/agents/' + encodeURIComponent(_stopAgentTargetId) + '/stop', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function() {
    btn.disabled = false;
    showToast('Stop dispatched', 'ok');
    closeStopAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast('Stop failed: ' + e.message, 'err'); });
  });
}

// ── Uninstall Agent ──────────────────────────────────────────────────────
// Verified uninstall: requires a live connection, waits for the endpoint to
// confirm before the record changes -- unlike Force Remove below, this
// never silently claims an unreachable endpoint is gone.
var _uninstallAgentTargetId = null;

export function openUninstallAgentModal(agentId, hostname) {
  _uninstallAgentTargetId = agentId;
  _openAgentActionModal(hostname, 'uninstall-agent');
}

export function closeUninstallAgentModal() {
  document.getElementById('uninstall-agent-overlay').classList.remove('open');
}

export function submitUninstallAgent() {
  if (!_uninstallAgentTargetId) return;
  var reason = document.getElementById('uninstall-agent-reason').value.trim();
  if (!reason) { showToast('Reason is required', 'err'); return; }
  askSure('Uninstall this agent from the endpoint?', 'The agent must be online to confirm.', reason, 'Uninstall', function() {
  var btn = document.getElementById('uninstall-agent-submit-btn');
  btn.disabled = true;
  apicallOk('/api/agents/' + encodeURIComponent(_uninstallAgentTargetId) + '/uninstall', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function(res) {
    btn.disabled = false;
    showToast('Uninstall dispatched', 'ok');
    closeUninstallAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast('Uninstall failed: ' + e.message, 'err'); });
  });
}

// ── Revoke / Reinstate Agent ───────────────────────────────────────────────
// Revoke blocks ONE agent (certificates revoked, connection dropped, re-enrolment refused) without touching
// the deployment CA or any other agent. Reinstate only lifts the block; the agent must enrol afresh.
function agentStateAction(idPrefix, verb, getTarget, successMsg, confirmText, closeFn) {
  return function() {
    var target = getTarget();
    if (!target) return;
    var reason = document.getElementById(idPrefix + '-reason').value.trim();
    if (!reason) { showToast('Reason is required', 'err'); return; }
    askSure(confirmText, '', reason, 'Confirm', function() {
    var btn = document.getElementById(idPrefix + '-submit-btn');
    btn.disabled = true;
    apicallOk('/api/agents/' + encodeURIComponent(target) + '/' + verb, {
      method: 'POST',
      body: JSON.stringify({ reason: reason })
    }).then(function(res) {
      btn.disabled = false;
      showToast(successMsg, 'ok');
      closeFn();
      loadAgents();
    }).catch(function(e) { btn.disabled = false; showToast('Failed: ' + e.message, 'err'); });
    });
  };
}

var _revokeAgentTargetId = null;
export function openRevokeAgentModal(agentId, hostname) {
  _revokeAgentTargetId = agentId;
  _openAgentActionModal(hostname, 'revoke-agent');
}
export function closeRevokeAgentModal() {
  document.getElementById('revoke-agent-overlay').classList.remove('open');
}
export var submitRevokeAgent = agentStateAction('revoke-agent', 'revoke', function() { return _revokeAgentTargetId; },
  'Agent revoked', 'Revoke this agent? It will be disconnected and refused until reinstated.', closeRevokeAgentModal);

// Allow reinstall: an administrator approves ONE fresh install over a host the server still shows as live (its agent
// broke or lost its keys). The next install on that host with the shared secret then succeeds once; see the server's
// AllowAgentReinstall.
var _allowReinstallTargetId = null;
export function openAllowReinstallModal(agentId, hostname) {
  _allowReinstallTargetId = agentId;
  _openAgentActionModal(hostname, 'allow-reinstall-agent');
}
export function closeAllowReinstallModal() {
  document.getElementById('allow-reinstall-agent-overlay').classList.remove('open');
}
export var submitAllowReinstall = agentStateAction('allow-reinstall-agent', 'allow-reinstall', function() { return _allowReinstallTargetId; },
  'Reinstall approved for 24 hours', 'Approve ONE fresh install on this host? The next install with the shared secret will replace the identity of this agent. It works once and expires after 24 hours.', closeAllowReinstallModal);

var _reinstateAgentTargetId = null;
export function openReinstateAgentModal(agentId, hostname) {
  _reinstateAgentTargetId = agentId;
  _openAgentActionModal(hostname, 'reinstate-agent');
}
export function closeReinstateAgentModal() {
  document.getElementById('reinstate-agent-overlay').classList.remove('open');
}
export var submitReinstateAgent = agentStateAction('reinstate-agent', 'reinstate', function() { return _reinstateAgentTargetId; },
  'Agent reinstated', 'Reinstate this agent so it can enrol again?', closeReinstateAgentModal);

// ── Remove Agent (Force Remove) ─────────────────────────────────────────────
// Removes the dashboard record only (sets state=retired) -- unlike Stop
// Agent, this never talks to the endpoint and works regardless of whether
// the agent is currently connected.
var _removeAgentTargetId = null;

export function openRemoveAgentModal(agentId, hostname) {
  _removeAgentTargetId = agentId;
  _openAgentActionModal(hostname, 'remove-agent');
}

export function closeRemoveAgentModal() {
  document.getElementById('remove-agent-overlay').classList.remove('open');
}

export function submitRemoveAgent() {
  if (!_removeAgentTargetId) return;
  var reason = document.getElementById('remove-agent-reason').value.trim();
  if (!reason) { showToast('Reason is required', 'err'); return; }
  askSure('Remove this agent from the dashboard?', 'The agent software on the endpoint keeps running. This only removes the record here.', reason, 'Remove', function() {
  var btn = document.getElementById('remove-agent-submit-btn');
  btn.disabled = true;
  apicallOk('/api/agents/' + encodeURIComponent(_removeAgentTargetId) + '/remove', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function() {
    btn.disabled = false;
    showToast('Agent removed', 'ok');
    closeRemoveAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast('Remove failed: ' + e.message, 'err'); });
  });
}

export function triggerTicketingSync() {
  apicallOk('/api/ticketing/sync', { method: 'POST' })
    .then(function() { showToast('Sync started', 'ok'); })
    .catch(function(e) { showToast('Sync failed: ' + e.message, 'err'); });
}
// askSure: the in-page confirmation every destructive agent action goes through (it replaces window.confirm).
function askSure(title, warning, reason, label, go) {
  openConfirmDiffModal(title,
    (warning ? '<p class="ag-sure-warn">' + x(warning) + '</p>' : '') + '<div class="ag-sure-reason"><span class="muted">Reason</span><b>' + x(reason) + '</b></div>',
    go, { sub: 'Review before you continue.', confirmLabel: label, danger: true });
}
