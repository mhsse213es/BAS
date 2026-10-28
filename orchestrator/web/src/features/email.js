import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { ago, fmtDate, showToast } from '../core/util.js';
import { covSegHtml } from './attack-path.js';
import { ROLE } from './shell.js';
import { card, hbars, pill, chip, empty, tabs, kv, icon } from '../core/kit.js';
import { ring } from './runs-drawer.js';
import { setHeroStat } from './shell-ui.js';
import * as M from './eml-model.js';


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
  ] },
  { id: 'EG-021', name: 'Attachment in a ZIP archive', expectations: [
    { id: 'EG-021.archive-zip.known-good', label: 'Known-good' },
    { id: 'EG-021.archive-zip.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-022', name: 'Attachment nested three archives deep', expectations: [
    { id: 'EG-022.nested-archive.known-good', label: 'Known-good' },
    { id: 'EG-022.nested-archive.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-023', name: 'Attachment in a tar.gz archive', expectations: [
    { id: 'EG-023.archive-targz.known-good', label: 'Known-good' },
    { id: 'EG-023.archive-targz.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-024', name: 'Attachment inside an attached email', expectations: [
    { id: 'EG-024.attached-message.known-good', label: 'Known-good' },
    { id: 'EG-024.attached-message.known-bad', label: 'Known-bad' }
  ] },
  { id: 'EG-025', name: 'Blocked script and executable extensions', expectations: [
    { id: 'EG-025.script-extension-bat.known-good', label: '.bat — known-good' },
    { id: 'EG-025.script-extension-bat.known-bad', label: '.bat — known-bad' },
    { id: 'EG-025.script-extension-scr.known-good', label: '.scr — known-good' },
    { id: 'EG-025.script-extension-scr.known-bad', label: '.scr — known-bad' },
    { id: 'EG-025.script-extension-pif.known-good', label: '.pif — known-good' },
    { id: 'EG-025.script-extension-pif.known-bad', label: '.pif — known-bad' },
    { id: 'EG-025.script-extension-wsf.known-good', label: '.wsf — known-good' },
    { id: 'EG-025.script-extension-wsf.known-bad', label: '.wsf — known-bad' },
    { id: 'EG-025.script-extension-jse.known-good', label: '.jse — known-good' },
    { id: 'EG-025.script-extension-jse.known-bad', label: '.jse — known-bad' },
    { id: 'EG-025.script-extension-vbe.known-good', label: '.vbe — known-good' },
    { id: 'EG-025.script-extension-vbe.known-bad', label: '.vbe — known-bad' },
    { id: 'EG-025.script-extension-com.known-good', label: '.com — known-good' },
    { id: 'EG-025.script-extension-com.known-bad', label: '.com — known-bad' },
    { id: 'EG-025.script-extension-cmd.known-good', label: '.cmd — known-good' },
    { id: 'EG-025.script-extension-cmd.known-bad', label: '.cmd — known-bad' }
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
var EMAIL_TAB = 'campaigns';      // campaigns | templates
var EMAIL_CAMPAIGNS_TAB = 'all';  // status chip
var EMAIL_CAMPAIGN_Q = '';
var EMAIL_RUNS_TAB = 'all';
var EMAIL_RUN_OPEN = {};          // runId -> bool, which rows are expanded
var EMAIL_DRAWER = null;          // { kind: 'scenario', id } | { kind: 'campaign', id } | { kind: 'new' } | null
var EG_LISTS = { runs: null, campaigns: null };


// egVerdictTone/egAreaTone/egStatusBadge all resolve to a static CSS class
// rather than a computed inline style -- these pages run under style-src
// 'self' (G1e), so a per-row color can never be written as a raw style attribute.
function egVerdictTone(v) {
  if (v === 'confirmed-success') return 'ok';
  if (v === 'confirmed-failure') return 'bad';
  if (v === 'inconclusive') return 'warn';
  return 'muted'; // not-tested / not-applicable
}
function egVerdictBadge(detail) {
  var v = (detail || {}).verdict || 'not-tested';
  return chip(v, egVerdictTone(v));
}
// egStatusTone: run/campaign status -> tone. Unrecognised statuses stay neutral rather than
// being mis-coloured as success or failure.
export function egStatusTone(status) {
  return { completed: 'ok', running: 'info', failed: 'bad', partial: 'warn', paused: 'warn' }[status] || 'muted';
}
function egStatusBadge(status) {
  return pill(status || '—', egStatusTone(status));
}
function egReportError(res, fallback) {
  showToast((res && res.error) ? res.error : fallback, 'err');
}

export function loadEmailTab() {
  renderEmailCatalog();
  renderEmailTabs();
  loadEmailCoverage();
  loadEmailMetrics();
  loadEmailCampaigns();
  loadEmailRuns();
}

// ── Coverage ─────────────────────────────────────────────────────────────────
function loadEmailCoverage() {
  var el = document.getElementById('email-coverage');
  if (!el) return;
  var fail = function() { el.innerHTML = card('Coverage', empty('mail', 'Coverage report unavailable')); };
  apicall('/api/emailgw/coverage').then(function(d) {
    if (!d || !Array.isArray(d.areas)) { fail(); return; }

    var s = M.coverageSummary(d.areas);
    el.innerHTML = card('Coverage',
      '<div class="eml-cov-top">' + ring(s.pct, s.pct >= 75 ? 'ok' : s.pct >= 40 ? 'warn' : 'bad') +
        '<div><div class="eml-big">' + x(s.covered) + '/' + x(s.total - s.excluded) + ' areas</div><div class="muted eml-small">' + x(s.pct) + '% covered' + (s.excluded ? ' · ' + x(s.excluded) + ' excluded' : '') + '</div></div></div>' +
      (d.summary ? '<p class="rg2-note rg2-note-top">' + x(d.summary) + '</p>' : '') +
      '<div class="eml-areas">' + s.rows.map(function(a) {
        return '<div class="eml-area tone-' + (a.status === 'covered' ? 'ok' : a.status === 'excluded' ? 'muted' : 'bad') + '" title="' + x(a.reason) + '">' +
          '<span class="eml-area-ic">' + icon(a.status === 'covered' ? 'ok' : 'alert') + '</span>' + x(a.label) + '</div>';
      }).join('') + '</div>');
  }).catch(fail);
}

// ── Metrics (MTTD/MTTR) ──────────────────────────────────────────────────────
function loadEmailMetrics() {
  var el = document.getElementById('email-metrics');
  if (!el) return;
  var fail = function() { el.innerHTML = card('Time-based metrics', empty('clock', 'Metrics unavailable')); };
  apicall('/api/emailgw/metrics').then(function(d) {
    if (!d) { fail(); return; }
    var tiles = M.metricTiles(d);
    var envs = [['Lab', d.lab], ['Customer', d.customer]].filter(function(e) { return e[1]; });
    if (!tiles.length) { fail(); return; }
    var outcomes = envs.map(function(e) {
      var rows = [['Prevention', e[1].prevention], ['Detection', e[1].detection], ['Response', e[1].response]].map(function(r) {
        var s = M.outcomeShare(r[1]);
        return s ? [r[0], s.pct, 'ok', s.succ + '/' + s.total] : null;
      }).filter(Boolean);
      return '<div class="eml-env"><div class="eml-env-t">' + x(e[0]) + ' <span class="muted">· ' + x(e[1].runsConsidered || 0) + ' runs</span></div>' +
        (rows.length ? hbars(rows) : '<div class="tiny muted">No runs yet</div>') + '</div>';
    }).join('');
    el.innerHTML = card('Time-based metrics',
      '<div class="eml-tiles">' + tiles.map(function(t) {
        return '<div class="eml-mini"><div class="eml-mini-t"><span>' + x(t.label) + '</span><b class="tone-' + t.tone + '">' + x(t.value) + '</b></div><div class="tiny muted">' + x(t.note) + '</div></div>';
      }).join('') + '</div>' +
      '<div class="eml-sub-t">Success share by outcome</div><div class="eml-envs">' + outcomes + '</div>');
  }).catch(fail);
}

// ── Scenario catalogue ────────────────────────────────────────────────────────
function renderEmailCatalog() {
  var el = document.getElementById('email-catalog-grid');
  if (!el) return;
  var cards = M.catalogCards(EG_CATALOG);
  var checks = cards.reduce(function(a, c) { return a + c.count; }, 0);
  el.innerHTML = card('Scenario catalogue',
    '<div class="eml-grid">' + cards.map(function(c) {
      return '<div class="eml-card" role="button" tabindex="0"' + on('click', 'openEmailScenario', c.id) + on('keydown', 'emailScenarioKeydown', c.id) + '>' +
        '<div class="eml-card-hd"><span class="mono eml-card-id">' + x(c.id) + '</span>' + chip(c.count + (c.count === 1 ? ' check' : ' checks'), 'info') + '</div>' +
        '<div class="eml-card-n">' + x(c.name) + '</div>' +
        '<div class="eml-vars">' + c.kinds.map(function(k) { return '<span>' + x(k) + '</span>'; }).join('') + '</div></div>';
    }).join('') + '</div>',
    { sub: cards.length + ' scenarios · ' + checks + ' checks' });
}

export function emailScenarioKeydown(id, el, e) {
  if (e && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openEmailScenario(id); }
}

export function egRunExpectation(expectationId) {
  apicall('/api/emailgw-runs', { method: 'POST', body: JSON.stringify({ scenarioId: expectationId }) }).then(function(res) {
    if (res && res.error) { egReportError(res, 'Run failed'); return; }
    showToast('Started ' + expectationId, 'ok');
    loadEmailRuns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// ── Drawer (scenario, campaign, new campaign) ─────────────────────────────────
function setDrawer(title, sub, body, foot) {
  var set = function(id, h) { var e = document.getElementById(id); if (e) e.innerHTML = h; };
  var t = document.getElementById('eml-drawer-title'); if (t) t.textContent = title;
  var s = document.getElementById('eml-drawer-sub'); if (s) s.textContent = sub;
  set('eml-drawer-body', body);
  set('eml-drawer-foot', foot || '');
  var o = document.getElementById('eml-drawer-overlay');
  if (o) o.classList.add('open');
}
export function closeEmailDrawer() {
  EMAIL_DRAWER = null;
  var o = document.getElementById('eml-drawer-overlay');
  if (o) o.classList.remove('open');
}
export function closeEmailDrawerOnBackdrop(el, event) { if (event.target === el) closeEmailDrawer(); }

var CLOSE_BTN = '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'closeEmailDrawer') + '>Close</button>';

function renderScenarioDrawer(id) {
  var sc = EG_CATALOG.filter(function(s) { return s.id === id; })[0];
  if (!sc) return;
  var latest = M.latestByScenario(EG_LISTS.runs);
  setDrawer(sc.id + ' — ' + sc.name, sc.expectations.length + (sc.expectations.length === 1 ? ' check' : ' checks'),
    '<p class="muted eml-drawer-p">Run an individual expectation against the email gateway.</p><h4 class="eml-h4">Checks</h4>' +
    sc.expectations.map(function(e) {
      var r = latest[e.id];
      return '<div class="eml-exp"><div class="eml-exp-l"><span>' + x(e.label) + '</span><span class="tiny muted mono">' + x(e.id) + '</span></div>' +
        (r ? egStatusBadge(r.status) : '<span class="tiny muted">not run yet</span>') +
        (EG_CAN_RUN ? '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'egRunExpectation', e.id) + '>&#9654; Run</button>' : '') + '</div>';
    }).join(''),
    CLOSE_BTN);
}
export function openEmailScenario(id) {
  EMAIL_DRAWER = { kind: 'scenario', id: id };
  renderScenarioDrawer(id);
}

function templateCard(t) {
  return '<div class="eml-card eml-tpl"><div class="eml-card-hd">' + chip('Campaign template', 'info') + '</div>' +
    '<div class="eml-card-n">' + x(t.name) + '</div><div class="tiny muted mono">' + x(t.id) + '</div>' +
    '<div class="eml-tpl-ft"><span class="muted eml-small">' + icon('mail') + ' Used ' + M.templateUse(EG_LISTS.campaigns, t.id) + '×</span>' +
    (EG_CAN_RUN ? '<button type="button" class="btn btn-primary btn-sm"' + on('click', 'egLaunchCampaign', t.id) + '>' + icon('plus') + 'Launch</button>' : '') + '</div></div>';
}
export function openEmailCampaignDrawer() {
  EMAIL_DRAWER = { kind: 'new' };
  setDrawer('New Email Campaign', 'Choose a template to launch',
    (EG_CAN_RUN ? '' : '<p class="muted eml-drawer-p">Your role cannot launch campaigns.</p>') +
    '<div class="eml-tpl-list">' + CAMPAIGN_CATALOG.map(templateCard).join('') + '</div>', CLOSE_BTN);
}

function renderCampaignDrawer(id, view) {
  var c = (EG_LISTS.campaigns || []).filter(function(k) { return k.id === id; })[0] || (view && view.campaign) || { id: id };
  var body;
  if (!view) {
    body = '<div class="tiny muted">Loading stages…</div>';
  } else {
    var ro = view.rollup || {};
    body = '<div class="eml-dr-top">' + egStatusBadge(c.status) + '<span class="muted eml-small">' + x(c.createdAt ? fmtDate(c.createdAt) : '') + '</span></div>' +
      kv([['Template', M.campaignName(c, CAMPAIGN_CATALOG)], ['Created', c.createdAt ? fmtDate(c.createdAt) : '—'], ['Completed', c.completedAt ? fmtDate(c.completedAt) : '—']]) +
      '<h4 class="eml-h4">Stages</h4><div class="tiny muted eml-mb">' + x(ro.completed || 0) + '/' + x(ro.totalStages || 0) + ' stages completed' +
        (ro.blockedByPrerequisite ? ' · ' + x(ro.blockedByPrerequisite) + ' blocked' : '') + (ro.failed ? ' · ' + x(ro.failed) + ' failed' : '') + '</div>' +
      (view.stages || []).map(function(s) {
        var run = s.run;
        return '<div class="email-detail-row"><span class="ord">' + (s.ordinal + 1) + '</span><span class="key">' + x(s.stageKey) + '</span>' + egStatusBadge(s.status) +
          (s.blockedReason ? '<span class="tiny muted">' + x(s.blockedReason) + '</span>' : '') +
          (run ? '<span class="tiny muted">prevention: ' + x((run.prevention || {}).verdict || 'n/a') + '</span>' : '') + '</div>';
      }).join('');
  }
  setDrawer(M.campaignName(c, CAMPAIGN_CATALOG), c.id || id, body,
    CLOSE_BTN + (EG_CAN_RUN && c.status === 'running' ? '<span class="grow"></span><button type="button" class="btn btn-outline btn-sm"' + on('click', 'egCancelCampaignClick', c.id) + '>Cancel campaign</button>' : ''));
}

// Row click: opens the campaign drawer and fetches its stages.
export function egToggleCampaign(campaignId) {
  EMAIL_DRAWER = { kind: 'campaign', id: campaignId };
  renderCampaignDrawer(campaignId, null);
  apicall('/api/emailgw-campaigns/' + campaignId).then(function(view) {
    if (EMAIL_DRAWER && EMAIL_DRAWER.kind === 'campaign' && EMAIL_DRAWER.id === campaignId) renderCampaignDrawer(campaignId, view);
  }).catch(function(e) { showToast(e.message, 'err'); });
}

// ── Tabs, filters, campaigns ──────────────────────────────────────────────────
function renderEmailTabs() {
  var el = document.getElementById('email-tabs');
  if (!el) return;
  el.innerHTML = tabs([
    { id: 'campaigns', label: 'Campaigns', count: (EG_LISTS.campaigns || []).length },
    { id: 'templates', label: 'Templates', count: CAMPAIGN_CATALOG.length },
  ], EMAIL_TAB, 'setEmailTab');
  var c = document.getElementById('email-panel-campaigns'), t = document.getElementById('email-panel-templates');
  if (c) c.classList.toggle('is-hidden', EMAIL_TAB !== 'campaigns');
  if (t) {
    t.classList.toggle('is-hidden', EMAIL_TAB !== 'templates');
    t.innerHTML = '<div class="rk-grid g3">' + CAMPAIGN_CATALOG.map(templateCard).join('') + '</div>';
  }
}
export function setEmailTab(id) { EMAIL_TAB = id; renderEmailTabs(); }

function renderEmailCampaignToolbar(list) {
  var el = document.getElementById('email-campaigns-toolbar');
  if (!el) return;
  var count = function(k) { return k === 'all' ? list.length : list.filter(function(c) { return c.status === k; }).length; };
  var items = [['all', 'All'], ['running', 'Running'], ['completed', 'Completed'], ['partial', 'Partial'], ['failed', 'Failed'], ['cancelled', 'Cancelled']]
    .filter(function(o) { return o[0] === 'all' || count(o[0]) > 0; });
  el.innerHTML = covSegHtml(items, EMAIL_CAMPAIGNS_TAB, 'setEmailCampaignsTab', count);
  var clr = document.getElementById('email-campaign-clear');
  if (clr) clr.hidden = !(EMAIL_CAMPAIGN_Q || EMAIL_CAMPAIGNS_TAB !== 'all');
}
export function setEmailCampaignsTab(v) { EMAIL_CAMPAIGNS_TAB = v; loadEmailCampaigns(); }
export function emailCampaignSearch(el) { EMAIL_CAMPAIGN_Q = (el && el.value) || ''; renderEmailCampaignRows(); }
export function emailClearFilters() {
  EMAIL_CAMPAIGN_Q = ''; EMAIL_CAMPAIGNS_TAB = 'all';
  var s = document.getElementById('email-campaign-search'); if (s) s.value = '';
  loadEmailCampaigns();
}

// egSummary: counts for the strip at the top of the page, from the run and campaign lists the page already loads.
export function egSummary(runs, campaigns) {
  var by = function(list, st) { return (list || []).filter(function(r) { return r.status === st; }).length; };
  return {
    runs: (runs || []).length, runsCompleted: by(runs, 'completed'), runsFailed: by(runs, 'failed'),
    runsActive: by(runs, 'running') + by(runs, 'pending'),
    campaigns: (campaigns || []).length, campaignsRunning: by(campaigns, 'running'),
  };
}
function renderEmailSummary() {
  if (!EG_LISTS.runs || !EG_LISTS.campaigns) return;
  var h = M.heroStats(EG_LISTS.runs, EG_LISTS.campaigns);
  setHeroStat('eml-hs-runs', h.runs);
  setHeroStat('eml-hs-done', h.completed);
  setHeroStat('eml-hs-failed', h.failed);
  setHeroStat('eml-hs-camps', h.campaigns);
}

function renderEmailCampaignRows() {
  var tb = document.getElementById('email-campaigns-body');
  if (!tb) return;
  var list = EG_LISTS.campaigns || [];
  var rows = M.filterCampaigns(list, CAMPAIGN_CATALOG, EMAIL_CAMPAIGNS_TAB, EMAIL_CAMPAIGN_Q);
  var clr = document.getElementById('email-campaign-clear');
  if (clr) clr.hidden = !(EMAIL_CAMPAIGN_Q || EMAIL_CAMPAIGNS_TAB !== 'all');
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="5">' + (list.length ? empty('search', 'No campaigns match', 'Clear the filters.') : empty('campaign', 'No campaigns yet', 'Launch one from the Templates tab.')) + '</td></tr>';
    return;
  }
  tb.innerHTML = rows.map(function(c) {
    return '<tr class="u-pointer"' + on('click', 'egToggleCampaign', c.id) + '>' +
        '<td><div>' + x(M.campaignName(c, CAMPAIGN_CATALOG)) + '</div><div class="tiny muted mono">' + x(c.id) + '</div></td>' +
        '<td>' + egStatusBadge(c.status) + '</td>' +
        '<td>' + fmtDate(c.createdAt) + '</td>' +
        '<td>' + (c.completedAt ? ago(c.completedAt) : '<span class="muted">—</span>') + '</td>' +
        '<td>' + (EG_CAN_RUN && (c.status === 'running')
          ? '<button class="btn btn-outline btn-sm"' + on('click', 'egCancelCampaignClick', c.id) + '>Cancel</button>'
          : '') +
        '</td></tr>';
  }).join('');
}

function loadEmailCampaigns() {
  apicall('/api/emailgw-campaigns?limit=50').then(function(list) {
    list = Array.isArray(list) ? list : [];
    EG_LISTS.campaigns = list; renderEmailSummary();
    renderEmailCampaignToolbar(list);
    renderEmailTabs();
    renderEmailCampaignRows();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function egLaunchCampaign(templateId) {
  apicall('/api/emailgw-campaigns', { method: 'POST', body: JSON.stringify({ templateId: templateId }) }).then(function(res) {
    if (res && res.error) { egReportError(res, 'Launch failed'); return; }
    showToast('Campaign launched', 'ok');
    if (EMAIL_DRAWER && EMAIL_DRAWER.kind === 'new') closeEmailDrawer();
    EMAIL_TAB = 'campaigns';
    loadEmailCampaigns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}

export function egCancelCampaignClick(campaignId) {
  apicall('/api/emailgw-campaigns/' + campaignId + '/cancel', { method: 'POST' }).then(function(res) {
    if (res && res.error) { egReportError(res, 'Cancel failed'); return; }
    showToast('Cancellation requested', 'ok');
    if (EMAIL_DRAWER && EMAIL_DRAWER.kind === 'campaign') closeEmailDrawer();
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
    list = Array.isArray(list) ? list : [];
    EG_LISTS.runs = list; renderEmailSummary();
    renderEmailRunsToolbar(list);
    if (EMAIL_DRAWER && EMAIL_DRAWER.kind === 'scenario') renderScenarioDrawer(EMAIL_DRAWER.id);
    var rows = EMAIL_RUNS_TAB === 'all' ? list : list.filter(function(r) { return r.status === EMAIL_RUNS_TAB; });
    var tb = document.getElementById('email-runs-body');
    if (!tb) return;
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="5">' + empty('runs', list.length ? 'No runs in this state' : 'No runs yet', list.length ? '' : 'Run a check from the scenario catalogue.') + '</td></tr>'; return; }
    tb.innerHTML = rows.map(function(r) {
      var expanded = !!EMAIL_RUN_OPEN[r.id];
      return '<tr class="u-pointer"' + on('click', 'egToggleRunDetail', r.id) + '>' +
          '<td><b>' + x(r.scenarioId) + '</b></td>' +
          '<td>' + egStatusBadge(r.status) + '</td>' +
          '<td class="mono">' + x(r.environment || '—') + '</td>' +
          '<td class="muted">' + ago(r.startedAt) + '</td>' +
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

// egOutcomeRows: outcome counts for one dimension as horizontal bars (share of all runs considered).
export function egOutcomeRows(dim) {
  var o = (dim || {}).outcomes || {};
  var succ = o.confirmedSuccess || 0, fail = o.confirmedFailure || 0, inc = o.inconclusive || 0;
  var total = succ + fail + inc + (o.notTested || 0) + (o.notApplicable || 0);
  if (!total) return '<div class="tiny muted">No runs yet</div>';
  var pct = function(v) { return v / total * 100; };
  return hbars([['Success', pct(succ), 'ok', succ], ['Failure', pct(fail), 'bad', fail], ['Inconclusive', pct(inc), 'warn', inc]]);
}
