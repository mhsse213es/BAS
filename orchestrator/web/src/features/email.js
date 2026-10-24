import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, fmtDate, showToast } from '../core/util.js';
import { covSegHtml } from './attack-path.js';
import { ROLE } from './shell.js';


// ── Email ───────────────────────────────────────────────────────────────────
// Console page for Email (internal codename "EmailGW") scenario validation --
// SPF/DKIM/DMARC, phishing, attachments, outbound DLP, mailbox/identity
// security. Talks only to the dedicated /api/emailgw* endpoints -- a
// separate engine from the generic /api/campaigns dispatch used by the
// other masteries, and from internal/webgwefficacy (Secure Web Gateway),
// which this page must never reference.

// EG_CATALOG mirrors internal/emailgwefficacy/maturity.go's own scenario
// groups and internal/api/emailgwrun_executor.go's dispatch table exactly --
// there is no server-side "list scenarios" endpoint, so this is hand-kept in
// sync the same way EM_CATALOG (endpoint-mastery.js) is for its own mastery.
var EG_CATALOG = [
  { id: 'EG-001', name: 'Domain spoofing (SPF/DKIM/DMARC)', expectations: [
    { id: 'EG-001.spf.known-good', label: 'SPF — known-good' },
    { id: 'EG-001.spf.known-bad', label: 'SPF — known-bad' },
    { id: 'EG-001.dkim.known-good', label: 'DKIM — known-good' },
    { id: 'EG-001.dkim.known-bad', label: 'DKIM — known-bad' },
    { id: 'EG-001.dmarc.known-good', label: 'DMARC — known-good' },
    { id: 'EG-001.dmarc.known-bad', label: 'DMARC — known-bad' }
  ] },
  { id: 'EG-002', name: 'Executive impersonation', expectations: [
    { id: 'EG-002.known-good', label: 'Known-good' },
    { id: 'EG-002.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-003', name: 'Credential phishing (URL harvesting + URL rewrite)', expectations: [
    { id: 'EG-003.credential-url.known-good', label: 'Credential URL — known-good' },
    { id: 'EG-003.credential-url.known-bad', label: 'Credential URL — known-bad' },
    { id: 'EG-003.url-rewrite.known-good', label: 'URL rewrite — known-good' },
    { id: 'EG-003.url-rewrite.known-bad', label: 'URL rewrite — known-bad' }
  ] },
  { id: 'EG-004', name: 'Malicious attachment (EICAR, real MIME multipart)', expectations: [
    { id: 'EG-004.known-good', label: 'Known-good' },
    { id: 'EG-004.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-005', name: 'Supplier payment diversion', expectations: [
    { id: 'EG-005.known-good', label: 'Known-good' },
    { id: 'EG-005.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-006', name: 'Sensitive-data leakage (outbound DLP)', expectations: [
    { id: 'EG-006.known-good', label: 'Known-good' },
    { id: 'EG-006.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-007', name: 'External auto-forwarding', expectations: [
    { id: 'EG-007.known-good', label: 'Known-good' },
    { id: 'EG-007.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-008', name: 'Post-delivery threat response', expectations: [
    { id: 'EG-008.known-good', label: 'Known-good' },
    { id: 'EG-008.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-009', name: 'Authentication exception scope', expectations: [
    { id: 'EG-009.known-good', label: 'Known-good' },
    { id: 'EG-009.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-010', name: 'Detection-to-response chain', expectations: [
    { id: 'EG-010.detection', label: 'Detection' },
    { id: 'EG-010.response', label: 'Response' }
  ] },
  { id: 'EG-011', name: 'QR-code lure', expectations: [
    { id: 'EG-011.qr-code-lure.known-good', label: 'Known-good' },
    { id: 'EG-011.qr-code-lure.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-012', name: 'PDF with embedded link', expectations: [
    { id: 'EG-012.pdf-embedded-link.known-good', label: 'Known-good' },
    { id: 'EG-012.pdf-embedded-link.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-013', name: 'Office document with external link', expectations: [
    { id: 'EG-013.office-external-link.known-good', label: 'Known-good' },
    { id: 'EG-013.office-external-link.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-014', name: 'Internal-sender spoof', expectations: [
    { id: 'EG-014.internal-sender-spoof.known-good', label: 'Known-good' },
    { id: 'EG-014.internal-sender-spoof.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-015', name: 'Reply-chain hijack', expectations: [
    { id: 'EG-015.reply-chain-hijack.known-good', label: 'Known-good' },
    { id: 'EG-015.reply-chain-hijack.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-016', name: 'Relay-path bypass', expectations: [
    { id: 'EG-016.relay-path.direct.known-good', label: 'Direct — known-good' },
    { id: 'EG-016.relay-path.direct.known-bad', label: 'Direct — known-bad' },
    { id: 'EG-016.relay-path.relay.known-good', label: 'Relay — known-good' },
    { id: 'EG-016.relay-path.relay.known-bad', label: 'Relay — known-bad' }
  ] },
  { id: 'EG-017', name: 'Malware-category script attachment', expectations: [
    { id: 'EG-017.malware-category-script.known-good', label: 'Known-good' },
    { id: 'EG-017.malware-category-script.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-018', name: 'Ransomware stand-in (double extension)', expectations: [
    { id: 'EG-018.ransomware-stand-in.known-good', label: 'Known-good' },
    { id: 'EG-018.ransomware-stand-in.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-019', name: 'File-type spoofing', expectations: [
    { id: 'EG-019.file-type-spoofing.known-good', label: 'Known-good' },
    { id: 'EG-019.file-type-spoofing.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-020', name: 'Blocked-extension policy', expectations: [
    { id: 'EG-020.blocked-extension-policy.known-good', label: 'Known-good' },
    { id: 'EG-020.blocked-extension-policy.known-bad', label: 'Known-bad' }
  ] }
];

// CAMPAIGN_CATALOG mirrors internal/emailgwcampaign/templates.go's
// registered template IDs -- same "no server-side list" reasoning as
// EG_CATALOG above (ListEmailGWCampaigns lists live campaign *runs*, not
// the static templates they're launched from).
var CAMPAIGN_CATALOG = [
  { id: 'bec-supplier-fraud', name: 'Business Email Compromise — Supplier Payment Fraud' },
  { id: 'credential-phishing-url-chain', name: 'Credential Phishing — Static Lure Then Click-Time Bypass Probe' }
];

var EG_CAN_RUN = (ROLE === 'admin' || ROLE === 'analyst');
var EMAIL_CAMPAIGNS_TAB = 'all';
var EMAIL_RUNS_TAB = 'all';
var EMAIL_CAMPAIGN_DETAIL = {};   // campaignId -> EmailGWCampaignView, fetched lazily on expand
var EMAIL_CAMPAIGN_OPEN = {};     // campaignId -> bool, which rows are expanded
var EMAIL_RUN_OPEN = {};          // runId -> bool

// egVerdictClass/egAreaClass/egStatusBadge all resolve to a static CSS
// class (app.css) rather than a computed inline style -- these pages run
// under style-src 'self' (G1e), so a per-row color can never be written
// as a raw style attribute.
function egVerdictClass(v) {
  if (v === 'confirmed-success') return 'v-success';
  if (v === 'confirmed-failure') return 'v-failure';
  if (v === 'inconclusive') return 'v-warning';
  return 'v-muted'; // not-tested / not-applicable
}
function egVerdictBadge(detail) {
  var v = (detail || {}).verdict || 'not-tested';
  return '<span class="sbadge ' + egVerdictClass(v) + '">' + x(v) + '</span>';
}
function egAreaClass(status) {
  if (status === 'covered') return 'v-success';
  if (status === 'excluded') return 'v-muted';
  return 'v-failure'; // not-covered
}
function egStatusBadge(status) {
  var known = ['running', 'completed', 'failed', 'partial', 'paused'];
  if (known.indexOf(status) >= 0) return '<span class="sbadge s-' + status + '">' + x(status) + '</span>';
  // pending / dispatched / cancelling / cancelled / blocked_by_prerequisite --
  // no dedicated CSS class; fall back to a neutral badge rather than
  // mis-coloring an unrecognized status as success or failure.
  return '<span class="sbadge v-muted">' + x(status || '—') + '</span>';
}
function egReportError(res, fallback) {
  showToast((res && res.error) ? res.error : fallback, 'err');
}

export function loadEmailTab() {
  renderEmailCatalog();
  renderEmailCampaignLaunchButtons();
  loadEmailCoverage();
  loadEmailMetrics();
  loadEmailCampaigns();
  loadEmailRuns();
}

// ── Coverage ─────────────────────────────────────────────────────────────────
function loadEmailCoverage() {
  var el = document.getElementById('email-coverage');
  if (!el) return;
  apicall('/api/emailgw/coverage').then(function(d) {
    if (!d || !Array.isArray(d.areas)) { el.innerHTML = '<div class="empty">Coverage report unavailable.</div>'; return; }
    el.innerHTML =
      '<div class="tiny muted u-mb-1">' + x(d.summary || '') + '</div>' +
      '<div class="email-area-badges">' +
      d.areas.map(function(a) {
        return '<span class="sbadge ' + egAreaClass(a.status) + '" title="' + x(a.exclusionReason || '') + '">' +
          x(a.areaId) + ' — ' + x(a.areaName) + '</span>';
      }).join('') +
      '</div>';
  }).catch(function(e) { el.innerHTML = '<div class="empty">Coverage report unavailable.</div>'; });
}

// ── Metrics (MTTD/MTTR) ──────────────────────────────────────────────────────
function egLatencyLine(label, lat) {
  if (!lat || lat.unavailable) return '<div class="tiny muted">' + label + ': no eligible samples</div>';
  if (!lat.sufficient) return '<div class="tiny muted">' + label + ': ' + lat.sampleCount + '/' + lat.minimumSampleSize + ' samples — insufficient</div>';
  var mean = lat.meanSeconds != null ? Math.round(lat.meanSeconds) + 's' : '—';
  var median = lat.medianSeconds != null ? Math.round(lat.medianSeconds) + 's' : '—';
  return '<div class="tiny">' + label + ': <strong>' + mean + '</strong> mean · ' + median + ' median <span class="muted">(n=' + lat.sampleCount + ')</span></div>';
}
function egOutcomeSummary(dim) {
  var o = (dim || {}).outcomes || {};
  var total = (o.confirmedSuccess || 0) + (o.confirmedFailure || 0) + (o.inconclusive || 0) + (o.notTested || 0) + (o.notApplicable || 0);
  return '<div class="tiny muted">' + (o.confirmedSuccess || 0) + ' success · ' + (o.confirmedFailure || 0) + ' failure · ' +
    (o.inconclusive || 0) + ' inconclusive' + (total ? '' : ' <span>(no runs yet)</span>') + '</div>';
}
function egMetricsColumn(label, m) {
  if (!m) return '';
  return '<div class="email-metrics-col">' +
    '<div class="u-fw600">' + x(label) + ' <span class="tiny muted">(' + (m.runsConsidered || 0) + ' runs)</span></div>' +
    '<div class="email-metrics-block"><div class="tiny muted">Prevention</div>' + egOutcomeSummary(m.prevention) + '</div>' +
    '<div class="email-metrics-block"><div class="tiny muted">Detection (MTTD)</div>' + egOutcomeSummary(m.detection) + egLatencyLine('MTTD', (m.detection || {}).latency) + '</div>' +
    '<div><div class="tiny muted">Response (MTTR)</div>' + egOutcomeSummary(m.response) + egLatencyLine('MTTR', (m.response || {}).latency) + '</div>' +
  '</div>';
}
function loadEmailMetrics() {
  var el = document.getElementById('email-metrics');
  if (!el) return;
  apicall('/api/emailgw/metrics').then(function(d) {
    if (!d) { el.innerHTML = '<div class="empty">Metrics unavailable.</div>'; return; }
    el.innerHTML = '<div class="email-metrics-row">' + egMetricsColumn('Lab', d.lab) + egMetricsColumn('Customer', d.customer) + '</div>';
  }).catch(function(e) { el.innerHTML = '<div class="empty">Metrics unavailable.</div>'; });
}

// ── Scenario catalog ──────────────────────────────────────────────────────────
function renderEmailCatalog() {
  var el = document.getElementById('email-catalog-grid');
  if (!el) return;
  el.innerHTML = EG_CATALOG.map(function(sc) {
    return '<div class="dash-panel">' +
      '<div class="email-card-hdr"><span class="u-fw600">' + x(sc.id) + '</span> — ' + x(sc.name) +
      '</div>' +
      '<div class="email-card-body">' +
        sc.expectations.map(function(e) {
          return '<div class="email-exp-row">' +
            '<span class="tiny muted">' + x(e.label) + '</span>' +
            (EG_CAN_RUN
              ? '<button class="btn btn-outline btn-sm"' + on('click', 'egRunExpectation', e.id) + '>&#9654; Run</button>'
              : '') +
          '</div>';
        }).join('') +
      '</div>' +
    '</div>';
  }).join('');
}

export function egRunExpectation(expectationId) {
  apicall('/api/emailgw-runs', { method: 'POST', body: JSON.stringify({ scenarioId: expectationId }) }).then(function(res) {
    if (res && res.error) { egReportError(res, 'Run failed'); return; }
    showToast('Started ' + expectationId, 'ok');
    loadEmailRuns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// ── Campaigns ─────────────────────────────────────────────────────────────────
function renderEmailCampaignToolbar(list) {
  var el = document.getElementById('email-campaigns-toolbar');
  if (!el) return;
  var count = function(k) { return k === 'all' ? list.length : list.filter(function(c) { return c.status === k; }).length; };
  var items = [['all', 'All'], ['running', 'Running'], ['completed', 'Completed'], ['partial', 'Partial'], ['failed', 'Failed'], ['cancelled', 'Cancelled']]
    .filter(function(o) { return o[0] === 'all' || count(o[0]) > 0; });
  el.innerHTML = covSegHtml(items, EMAIL_CAMPAIGNS_TAB, 'setEmailCampaignsTab', count);
}
export function setEmailCampaignsTab(v) { EMAIL_CAMPAIGNS_TAB = v; loadEmailCampaigns(); }

function loadEmailCampaigns() {
  apicall('/api/emailgw-campaigns?limit=50').then(function(list) {
    list = list || [];
    renderEmailCampaignToolbar(list);
    var rows = EMAIL_CAMPAIGNS_TAB === 'all' ? list : list.filter(function(c) { return c.status === EMAIL_CAMPAIGNS_TAB; });
    var tb = document.getElementById('email-campaigns-body');
    if (!tb) return;
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="empty">No campaigns' + (EMAIL_CAMPAIGNS_TAB === 'all' ? ' yet.' : ' in this state.') + '</td></tr>'; return; }
    tb.innerHTML = rows.map(function(c) {
      var tmpl = CAMPAIGN_CATALOG.filter(function(t) { return t.id === c.templateId; })[0];
      var expanded = !!EMAIL_CAMPAIGN_OPEN[c.id];
      var detailRow = expanded ? egCampaignDetailRowHtml(c.id) : '';
      return '<tr class="u-pointer"' + on('click', 'egToggleCampaign', c.id) + '>' +
          '<td>' + (tmpl ? x(tmpl.name) : x(c.templateId)) + '</td>' +
          '<td>' + egStatusBadge(c.status) + '</td>' +
          '<td>' + fmtDate(c.createdAt) + '</td>' +
          '<td>' + (c.completedAt ? ago(c.completedAt) : '<span class="muted">—</span>') + '</td>' +
          '<td>' + (EG_CAN_RUN && (c.status === 'running')
            ? '<button class="btn btn-outline btn-sm"' + on('click', 'egCancelCampaignClick', c.id) + '>Cancel</button>'
            : '') +
          '</td>' +
        '</tr>' + detailRow;
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function egCampaignDetailRowHtml(campaignId) {
  var view = EMAIL_CAMPAIGN_DETAIL[campaignId];
  if (!view) return '<tr><td colspan="5"><div class="tiny muted email-detail-pad">Loading stages…</div></td></tr>';
  var stages = view.stages || [];
  return '<tr><td colspan="5" class="email-detail-shaded">' +
    '<div class="email-detail-pad">' +
      '<div class="tiny muted u-mb-1">' + view.rollup.completed + '/' + view.rollup.totalStages + ' stages completed' +
        (view.rollup.blockedByPrerequisite ? ' · ' + view.rollup.blockedByPrerequisite + ' blocked' : '') +
        (view.rollup.failed ? ' · ' + view.rollup.failed + ' failed' : '') + '</div>' +
      stages.map(function(s) {
        var run = s.run;
        return '<div class="email-detail-row">' +
          '<span class="ord">' + (s.ordinal + 1) + '</span>' +
          '<span class="key">' + x(s.stageKey) + '</span>' +
          egStatusBadge(s.status) +
          (s.blockedReason ? '<span class="tiny muted">' + x(s.blockedReason) + '</span>' : '') +
          (run ? ('<span class="tiny muted">prevention: ' + x((run.prevention || {}).verdict || 'n/a') + '</span>') : '') +
        '</div>';
      }).join('') +
    '</div>' +
  '</td></tr>';
}

export function egToggleCampaign(campaignId) {
  EMAIL_CAMPAIGN_OPEN[campaignId] = !EMAIL_CAMPAIGN_OPEN[campaignId];
  if (EMAIL_CAMPAIGN_OPEN[campaignId] && !EMAIL_CAMPAIGN_DETAIL[campaignId]) {
    apicall('/api/emailgw-campaigns/' + campaignId).then(function(view) {
      EMAIL_CAMPAIGN_DETAIL[campaignId] = view;
      loadEmailCampaigns();
    }).catch(function(e) { showToast(e.message, 'err'); });
  }
  loadEmailCampaigns();
}

export function egLaunchCampaign(templateId) {
  apicall('/api/emailgw-campaigns', { method: 'POST', body: JSON.stringify({ templateId: templateId }) }).then(function(res) {
    if (res && res.error) { egReportError(res, 'Launch failed'); return; }
    showToast('Campaign launched', 'ok');
    loadEmailCampaigns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function egCancelCampaignClick(campaignId) {
  apicall('/api/emailgw-campaigns/' + campaignId + '/cancel', { method: 'POST' }).then(function(res) {
    if (res && res.error) { egReportError(res, 'Cancel failed'); return; }
    showToast('Cancellation requested', 'ok');
    delete EMAIL_CAMPAIGN_DETAIL[campaignId];
    loadEmailCampaigns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// ── Runs ──────────────────────────────────────────────────────────────────────
function renderEmailRunsToolbar(list) {
  var el = document.getElementById('email-runs-toolbar');
  if (!el) return;
  var count = function(k) { return k === 'all' ? list.length : list.filter(function(r) { return r.status === k; }).length; };
  var items = [['all', 'All'], ['pending', 'Pending'], ['running', 'Running'], ['completed', 'Completed'], ['partial', 'Partial'], ['failed', 'Failed']]
    .filter(function(o) { return o[0] === 'all' || count(o[0]) > 0; });
  el.innerHTML = covSegHtml(items, EMAIL_RUNS_TAB, 'setEmailRunsTab', count);
}
export function setEmailRunsTab(v) { EMAIL_RUNS_TAB = v; loadEmailRuns(); }

function loadEmailRuns() {
  apicall('/api/emailgw-runs?limit=50').then(function(list) {
    list = list || [];
    renderEmailRunsToolbar(list);
    var rows = EMAIL_RUNS_TAB === 'all' ? list : list.filter(function(r) { return r.status === EMAIL_RUNS_TAB; });
    var tb = document.getElementById('email-runs-body');
    if (!tb) return;
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="empty">No runs' + (EMAIL_RUNS_TAB === 'all' ? ' yet.' : ' in this state.') + '</td></tr>'; return; }
    tb.innerHTML = rows.map(function(r) {
      var expanded = !!EMAIL_RUN_OPEN[r.id];
      return '<tr class="u-pointer"' + on('click', 'egToggleRunDetail', r.id) + '>' +
          '<td>' + x(r.scenarioId) + '</td>' +
          '<td>' + egStatusBadge(r.status) + '</td>' +
          '<td>' + x(r.environment || '—') + '</td>' +
          '<td>' + ago(r.startedAt) + '</td>' +
          '<td>' + (r.error ? '<span class="tiny u-danger">' + x(r.error) + '</span>' : '<span class="muted">—</span>') + '</td>' +
        '</tr>' + (expanded ? egRunDetailRowHtml(r) : '');
    }).join('');
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function egRunDetailRowHtml(r) {
  var result = r.result || null;
  return '<tr><td colspan="5" class="email-detail-shaded">' +
    '<div class="email-detail-pad">' +
      (result
        ? ('<div class="email-detail-summary">' +
            '<span>Prevention: ' + egVerdictBadge(result.prevention) + '</span>' +
            '<span>Detection: ' + egVerdictBadge(result.detectionVerdict) + '</span>' +
            '<span>Response: ' + egVerdictBadge(result.responseVerdict) + '</span>' +
          '</div>' +
          '<pre class="email-raw-json">' + x(JSON.stringify(result, null, 2)) + '</pre>')
        : '<div class="tiny muted">No result recorded yet.</div>') +
    '</div>' +
  '</td></tr>';
}

export function egToggleRunDetail(runId) {
  EMAIL_RUN_OPEN[runId] = !EMAIL_RUN_OPEN[runId];
  loadEmailRuns();
}

function renderEmailCampaignLaunchButtons() {
  var el = document.getElementById('email-campaign-launch-buttons');
  if (!el) return;
  if (!EG_CAN_RUN) { el.innerHTML = ''; return; }
  el.innerHTML = CAMPAIGN_CATALOG.map(function(t) {
    return '<button class="btn btn-outline btn-sm"' + on('click', 'egLaunchCampaign', t.id) + '>&#9654; ' + x(t.name) + '</button>';
  }).join('');
}
