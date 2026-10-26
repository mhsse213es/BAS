import { state } from '../core/state.js';
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { initComplianceTab, loadComplianceReport } from './agent-drawer.js';
import { showTab } from './shell.js';
import { setDisplay } from '../core/inline-style.js';
import { renderCalderaInsights } from './settings-insights.js';
import { complianceCard, setDashCompliance, setDashCampaigns } from './dash-rich.js';


// ── Compliance score tiles ─────────────────────────────────────────────────
// Renders one tile per compliance framework. Scores come from the
// /api/compliance/scores endpoint which reads compliance_snapshots (O(1)).
// Called fleet-wide (no agentId) so the dashboard shows the worst-case posture
// across all enrolled agents — the view a CISO cares about.
export function loadComplianceScores(agentId) {
  var url = '/api/compliance/scores' + (agentId ? '?agentId=' + encodeURIComponent(agentId) : '');
  apicall(url).then(function(scores) {
    setDashCompliance(Array.isArray(scores) ? scores : []);
  }).catch(function() { setDashCompliance([]); });
}

export function openComplianceDetail(frameworkId, agentId) {
  showTab('compliance');
  // The framework options load asynchronously; wait for them before selecting.
  initComplianceTab().then(function() {
    var fwSel = document.getElementById('cmp-fw-sel');
    var agSel = document.getElementById('cmp-agent-sel');
    if (fwSel) fwSel.value = frameworkId;
    if (agSel && agentId) agSel.value = agentId;
    loadComplianceReport();
  });
}

// One framework card of the dashboard's Regulatory compliance grid (rendered by dash-rich.js).
export function complianceTile(fw) { return complianceCard(fw); }

// refreshDashboardCampaigns — standalone fn so it can be called from the WS
// handler and the periodic poll without running the full dashboard reload.

export function refreshDashboardCampaigns() {
  apicall('/api/campaigns').then(function(cs) {
    setDashCampaigns(Array.isArray(cs) ? cs : []);
  }).catch(function() {});
}

export function openChangePassword() {
  state._pwForced = false;
  document.getElementById('changepw-title').textContent = 'Change Password';
  document.getElementById('changepw-sub').textContent = 'Update your account password.';
  setDisplay(document.getElementById('cpw-cancel-btn'), '');
  document.getElementById('cpw-current').value = '';
  document.getElementById('cpw-new').value = '';
  document.getElementById('cpw-confirm').value = '';
  document.getElementById('cpw-err').textContent = '';
  document.getElementById('changepw-overlay').classList.add('open');
}
export function closeChangePassword() {
  if (state._pwForced) return;
  document.getElementById('changepw-overlay').classList.remove('open');
}
export function closeChangePasswordOnBackdrop(el, event) { if (event.target === el && !state._pwForced) closeChangePassword(); }
export function submitChangePassword() {
  var current = document.getElementById('cpw-current').value;
  var newpw   = document.getElementById('cpw-new').value;
  var confirm = document.getElementById('cpw-confirm').value;
  document.getElementById('cpw-err').textContent = '';
  if (!current || !newpw) { document.getElementById('cpw-err').textContent = 'All fields are required.'; return; }
  if (newpw !== confirm)  { document.getElementById('cpw-err').textContent = 'New passwords do not match.'; return; }
  if (newpw.length < 8)   { document.getElementById('cpw-err').textContent = 'Password must be at least 8 characters.'; return; }
  apicall('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ currentPassword: current, newPassword: newpw }) })
  .then(function(res) {
    if (res.error) throw new Error(res.error);
    state._pwForced = false;
    document.getElementById('changepw-overlay').classList.remove('open');
    showToast('Password updated successfully', 'ok');
  })
  .catch(function(e) { document.getElementById('cpw-err').textContent = e.message; });
}

/* ═══════════════════════════════════════════════════════════════════════════
   THREAT-INTEL CONNECTOR
   ═══════════════════════════════════════════════════════════════════════════ */

export function loadCalderaStatus() {
  var wrap = document.getElementById('caldera-status-wrap');
  if (wrap) setDisplay(wrap, '');
  var btn = document.getElementById('caldera-check-btn');
  if (btn) btn.disabled = true;

  apicall('/api/caldera/status').then(function(d) {
    var dot;
    if (d.reachable) {
      dot = '<span class="g1-display-inline-block g1-s-a3bc72af"></span><span class="u-success">Connected</span>';
    } else if (d.httpStatus === 401) {
      dot = '<span class="g1-display-inline-block g1-s-d9fd6a0b"></span><span class="u-warning">Auth Error — wrong API key</span>';
    } else {
      dot = '<span class="g1-display-inline-block g1-s-d966ce5b"></span><span class="u-danger">Unreachable</span>';
    }
    document.getElementById('cs-caldera-status').innerHTML = dot;
    renderCalderaInsights(d);
    document.getElementById('cs-caldera-url').textContent = d.url || '(not configured)';
    document.getElementById('cs-caldera-version').textContent = d.version || (d.reachable ? 'unknown' : '—');
    if (d.reachable) {
      var abLabel = d.abilityCount.toLocaleString() + ' abilities';
      if (d.byPlugin) {
        var parts = Object.keys(d.byPlugin).sort().map(function(k) { return k + ': ' + d.byPlugin[k].toLocaleString(); });
        abLabel += ' (' + parts.join(', ') + ')';
      }
      if (d.uniqueTechniques) abLabel += ' · ' + d.uniqueTechniques + ' unique techniques';
      abLabel += ' · ' + (d.adversaryCount || 0) + ' adversary profiles';
      document.getElementById('cs-caldera-abilities').textContent = abLabel;
    } else {
      document.getElementById('cs-caldera-abilities').textContent = '—';
    }
    document.getElementById('cs-caldera-latency').textContent = d.reachable ? (d.latencyMs + ' ms') : '—';
    var errEl = document.getElementById('cs-caldera-error');
    if (d.error) {
      errEl.textContent = d.error;
      setDisplay(errEl, '');
    } else {
      setDisplay(errEl, 'none');
    }
  }).catch(function(e) {
    var errEl = document.getElementById('cs-caldera-error');
    if (errEl) { errEl.textContent = e.message; setDisplay(errEl, ''); }
    document.getElementById('cs-caldera-status').innerHTML =
      '<span class="u-danger">Error checking status</span>';
  }).finally(function() {
    if (btn) btn.disabled = false;
  });
}

// _renderConnectorCard fills one per-connector card (MISP/OpenCTI) from its
// ConnectorStatus.BySource entry. rawCountElId differs per connector because
// the two label their raw fetch count differently ("Events" for MISP vs
// "Threat Actor Nodes" for OpenCTI) — they're genuinely different kinds of
// raw data, not the same concept under two names. See
// docs/superpowers/specs/2026-07-22-connector-rich-status-cards-design.md.
export function _renderConnectorCard(prefix, enabled, stat, rawCountElId) {
  var statusEl = document.getElementById('cs-' + prefix + '-status');
  if (!enabled) {
    statusEl.textContent = '✗ Not configured';
    statusEl.style.color = 'var(--muted)';
  } else if (stat && stat.error) {
    statusEl.textContent = '⚠ Error';
    statusEl.style.color = '#f85149';
  } else {
    statusEl.textContent = '✓ Connected';
    statusEl.style.color = '#5cead8';
  }
  document.getElementById(rawCountElId).textContent = stat ? stat.rawCount.toLocaleString() : '—';
  document.getElementById('cs-' + prefix + '-actors').textContent = stat ? stat.actorCount.toLocaleString() : '—';
  document.getElementById('cs-' + prefix + '-lastfetch').textContent = (stat && stat.fetchedAt) ? new Date(stat.fetchedAt).toLocaleString() : '—';
  var errEl = document.getElementById('cs-' + prefix + '-error');
  if (stat && stat.error) { errEl.textContent = stat.error; setDisplay(errEl, ''); }
  else { setDisplay(errEl, 'none'); }
}

// ── Generic config-save confirmation ────────────────────────────────────────
// Shared by every "Save" that can silently overwrite a previously-saved
// connector/config value (threat intel, OpenAEV, ITSM ticketing connectors).
// Each caller builds its own diff HTML (via _diffRow/_diffSecretRow below)
// and passes a zero-arg onConfirm that performs the actual save.
var CONFIRM_DIFF_PENDING = null; // onConfirm callback awaiting the modal's Save click

export function openConfirmDiffModal(title, diffHtml, onConfirm) {
  document.getElementById('confirm-diff-title').textContent = title;
  document.getElementById('confirm-diff-body').innerHTML = diffHtml;
  CONFIRM_DIFF_PENDING = onConfirm;
  document.getElementById('confirm-diff-overlay').classList.add('open');
}

export function closeConfirmDiffModal() {
  document.getElementById('confirm-diff-overlay').classList.remove('open');
  CONFIRM_DIFF_PENDING = null;
}

export function runConfirmDiffModal() {
  var onConfirm = CONFIRM_DIFF_PENDING;
  document.getElementById('confirm-diff-overlay').classList.remove('open');
  CONFIRM_DIFF_PENDING = null;
  if (onConfirm) onConfirm();
}

// Old-value-struck-through / new-value-highlighted row for a plain field.
export function _diffRow(label, oldVal, newVal) {
  return '<div class="tiny g1-s-0990a875"><span class="muted">' + x(label) + ':</span><br>' +
    '<span class="g1-s-91e61789">' + x(oldVal || '(empty)') + '</span><br>' +
    '<span class="u-success">' + x(newVal || '(empty)') + '</span></div>';
}

// A secret/password field never round-trips its real value to the browser, so it
// can only ever say whether it will change, never show old/new text.
export function _diffSecretRow(label, changed) {
  return '<div class="tiny g1-s-0990a875"><span class="muted">' + x(label) + ':</span> ' +
    (changed ? '<span class="u-warning">will be replaced</span>' : '<span class="muted">unchanged (kept)</span>') + '</div>';
}