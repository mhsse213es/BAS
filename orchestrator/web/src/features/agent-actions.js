import { apicall } from '../core/api.js';
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
  if (!confirm('Stop agent permanently?\n\nReason: ' + reason + '\n\nThis cannot be undone remotely. Proceed?')) return;

  var btn = document.getElementById('stop-agent-submit-btn');
  btn.disabled = true;
  apicall('/api/agents/' + encodeURIComponent(_stopAgentTargetId) + '/stop', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function() {
    btn.disabled = false;
    showToast('Stop dispatched', 'ok');
    closeStopAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
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
  if (!confirm('Uninstall this agent from the endpoint?\n\nReason: ' + reason + '\n\nThe agent must be online to confirm. Proceed?')) return;

  var btn = document.getElementById('uninstall-agent-submit-btn');
  btn.disabled = true;
  apicall('/api/agents/' + encodeURIComponent(_uninstallAgentTargetId) + '/uninstall', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function(res) {
    btn.disabled = false;
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Uninstall dispatched', 'ok');
    closeUninstallAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
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
    if (!confirm(confirmText + '\n\nReason: ' + reason + '\n\nProceed?')) return;
    var btn = document.getElementById(idPrefix + '-submit-btn');
    btn.disabled = true;
    apicall('/api/agents/' + encodeURIComponent(target) + '/' + verb, {
      method: 'POST',
      body: JSON.stringify({ reason: reason })
    }).then(function(res) {
      btn.disabled = false;
      if (res && res.error) { showToast(res.error, 'err'); return; }
      showToast(successMsg, 'ok');
      closeFn();
      loadAgents();
    }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
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
  if (!confirm('Remove this agent from the dashboard?\n\nReason: ' + reason + '\n\nThe agent software on the endpoint keeps running -- this only removes the record here. Proceed?')) return;

  var btn = document.getElementById('remove-agent-submit-btn');
  btn.disabled = true;
  apicall('/api/agents/' + encodeURIComponent(_removeAgentTargetId) + '/remove', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function() {
    btn.disabled = false;
    showToast('Agent removed', 'ok');
    closeRemoveAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

export function triggerTicketingSync() {
  apicall('/api/ticketing/sync', { method: 'POST' })
    .then(function() { showToast('Sync started', 'ok'); })
    .catch(function(e) { showToast(e.message, 'err'); });
}