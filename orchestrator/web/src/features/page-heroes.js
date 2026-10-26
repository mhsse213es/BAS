import { mountHero } from './shell-ui.js';

// One place for the banner at the top of every page: icon, title, subtitle, actions and the stat
// chips. A page's own loader fills the chips (setHeroStat) from data it already fetched, so a banner
// never shows a number the server did not return -- until the data arrives a chip shows an em dash.
// Icons are internal inline SVG; action buttons use the normal data-on-click registry.

function svg(paths) {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths + '</svg>';
}
export var ICON = {
  agents: svg('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
  ok: svg('<path d="M5 12l4 4 10-10"/>'),
  warn: svg('<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.01"/>'),
  bad: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  retired: svg('<circle cx="12" cy="12" r="8"/><path d="M8 12h8"/>'),
  total: svg('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/>'),
  posture: svg('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>'),
  runs: svg('<path d="M7 5l12 7-12 7z"/>'),
  technique: svg('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/>'),
  clock: svg('<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>'),
  trend: svg('<path d="M4 18l5-6 4 3 7-9"/>'),
  gear: svg('<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>'),
  user: svg('<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>'),
  globe: svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>'),
  flag: svg('<path d="M5 21V4h11l-2 4 2 4H5"/>'),
  campaign: svg('<path d="M4 14v-4l11-5v14L4 14z"/><path d="M15 9c2 1 2 5 0 6M7 14l1 5"/>'),
  path: svg('<circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 6h6a4 4 0 010 8H10a4 4 0 000 8"/>'),
  lock: svg('<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0"/>'),
  bulb: svg('<path d="M9 18h6M10 21h4M12 3a6 6 0 00-4 10c1 1 1 2 1 3h6c0-1 0-2 1-3a6 6 0 00-4-10z"/>'),
  hash: svg('<path d="M5 9h14M5 15h14M10 4L8 20M16 4l-2 16"/>'),
  wrench: svg('<path d="M14 6a4 4 0 005 5l-9 9a2 2 0 01-3-3l9-9a4 4 0 00-2-2z"/>'),
  check: svg('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>'),
  report: svg('<path d="M7 3h8l4 4v14H7z"/><path d="M15 3v4h4M10 12h6M10 16h6"/>'),
  plug: svg('<path d="M9 3v5M15 3v5M7 8h10v3a5 5 0 01-10 0zM12 16v5"/>'),
  layers: svg('<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>'),
  mail: svg('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>'),
  factory: svg('<path d="M3 21V10l6 4V10l6 4V6h6v15z"/>'),
  bolt: svg('<path d="M13 3L5 14h6l-1 7 8-11h-6z"/>'),
  mapped: svg('<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>'),
  star: svg('<path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/>'),
};

var HEROES = {
  'hero-dashboard': {
    icon: ICON.posture,
    title: 'Security Posture',
    sub: 'Continuous validation of your security controls against real adversary techniques.',
    actions:
      '<button class="btn btn-outline btn-sm" data-on-click="showTab" data-args="[&quot;reports&quot;]">Generate report</button>' +
      '<button class="btn btn-primary btn-sm" data-on-click="openModal">&#9654; New simulation</button>',
    stats: [
      { id: 'hs-dash-validations', icon: ICON.runs, value: '—', label: 'Validations (30d)' },
      { id: 'hs-dash-detect', icon: ICON.check, value: '—', label: 'Detection rate' },
      { id: 'hs-dash-online', icon: ICON.agents, value: '—', label: 'Agents online' },
      { id: 'hs-dash-last', icon: ICON.clock, value: '—', label: 'Last assessment' },
    ],
  },
  'hero-executive': {
    icon: ICON.trend,
    title: 'Executive Dashboard',
    sub: 'Fleet-wide risk, exposure, and detection-coverage trends over time — daily snapshots, not a single point-in-time report.',
    actions:
      '<button class="btn btn-outline btn-sm" data-on-click="showTab" data-args="[&quot;reports&quot;]">Generate report</button>',
    stats: [
      { id: 'hs-exec-risk', icon: ICON.check, value: '—', label: 'Risk score' },
      { id: 'hs-exec-exposure', icon: ICON.warn, value: '—', label: 'Exposure score' },
      { id: 'hs-exec-detect', icon: ICON.mapped, value: '—', label: 'Detection coverage' },
      { id: 'hs-exec-fleet', icon: ICON.agents, value: '—', label: 'Fleet assets' },
    ],
  },
  'hero-scenarios': {
    icon: ICON.technique,
    title: 'Scenarios',
    sub: 'Explore and launch security scenarios to validate your security controls.',
    actions:
      '<button type="button" id="sc-upload-btn" class="btn btn-outline" data-on-click="pickScenarioUploadFile">' + svg('<path d="M12 16V5M7 9l5-5 5 5M5 20h14"/>') + 'Upload YAML</button>' +
      '<button type="button" id="sc-new-btn" class="btn btn-primary" data-on-click="openBuilder" data-args="[null]">' + svg('<path d="M12 5v14M5 12h14"/>') + 'New Scenario</button>',
    stats: [
      { id: 'sc-hs-total', icon: ICON.technique, value: '—', label: 'Total Scenarios' },
      { id: 'sc-hs-tech', icon: ICON.mapped, value: '—', label: 'ATT&CK Techniques' },
      { id: 'sc-hs-fam', icon: ICON.layers, value: '—', label: 'Product Families' },
      { id: 'sc-hs-upd', icon: ICON.ok, value: '—', label: 'Updated' },
    ],
  },
  'hero-agents': {
    icon: ICON.agents,
    title: 'Agents',
    sub: 'Lightweight collectors across your environment — they execute safe emulations locally and stream telemetry back.',
    actions:
      '<button class="btn btn-outline btn-sm" data-on-click="loadAgents">Refresh</button>' +
      '<button class="btn btn-primary btn-sm" data-on-click="showAgentDownload">&#8595; Deploy agent</button>',
    stats: [
      { id: 'hs-agents-total', icon: ICON.total, value: '—', label: 'Agents' },
      { id: 'hs-agents-online', icon: ICON.ok, tone: 'ok', value: '—', label: 'Online' },
      { id: 'hs-agents-degraded', icon: ICON.warn, tone: 'warn', value: '—', label: 'Degraded' },
      { id: 'hs-agents-offline', icon: ICON.bad, tone: 'bad', value: '—', label: 'Offline' },
      { id: 'hs-agents-retired', icon: ICON.retired, tone: 'muted', value: '—', label: 'Retired' },
    ],
  },
  'hero-settings': {
    icon: ICON.gear,
    title: 'Settings',
    sub: 'Manage team access, the simulation engine, threat-intel sync, and content.',
  },
  'hero-profile': {
    icon: ICON.user,
    title: 'My Profile',
    sub: 'Your account details and access.',
  },
  'hero-runs': {
    icon: ICON.runs,
    title: 'Live Runs',
    sub: 'Scenario executions in progress, queued and recently completed.',
    actions:
      '<button type="button" class="btn btn-outline" data-on-click="exportRunsCsv">' + svg('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>') + 'Export</button>' +
      '<button type="button" class="btn btn-outline" data-on-click="loadRuns">' + svg('<path d="M20 11a8 8 0 00-14-4M4 13a8 8 0 0014 4M5 3v4h4M19 21v-4h-4"/>') + 'Refresh</button>' +
      '<button type="button" class="btn btn-primary" data-on-click="showTab" data-args="[&quot;scenarios&quot;]">' + svg('<path d="M12 5v14M5 12h14"/>') + 'New Run</button>',
    stats: [
      { id: 'runs-cnt', icon: ICON.runs, value: '—', label: 'Running now' },
      { id: 'runs-hs-queued', icon: ICON.clock, value: '—', label: 'Queued' },
      { id: 'runs-hs-pass', icon: ICON.ok, value: '—', label: 'Pass rate (all)' },
      { id: 'runs-hs-agents', icon: ICON.agents, value: '—', label: 'Agents busy' },
    ],
  },
  'hero-k8s': {
    icon: ICON.globe,
    title: 'Kubernetes Scenarios',
    sub: 'Plan and run Kubernetes security scenarios in a lab cluster. A different operator approves anything that changes the cluster.',
    actions: '<button class="btn btn-outline btn-sm" data-k8s-refresh="1">Refresh</button>',
    stats: [
      { id: 'k8s-cnt', icon: ICON.runs, value: '—', label: 'Runs' },
    ],
  },
  'hero-scheduled': {
    icon: ICON.clock,
    title: 'Scheduled Assessments',
    sub: 'Recurring assessments that run on a schedule against your agents and groups.',
    actions: '<div class="g1-display-flex g1-s-99b36ba4"><button class="btn btn-outline btn-sm" data-on-click="loadScheduledAssessments">Refresh</button><button class="btn btn-primary btn-sm" data-on-click="openSchedWizard">+ New Schedule</button></div>',
    stats: [
      { id: 'sched-cnt', icon: ICON.clock, value: '—', label: 'Schedules' },
    ],
  },
  'hero-initiatives': {
    icon: ICON.flag,
    title: 'Initiatives',
    sub: 'Group related assessments and jobs under one goal and follow their progress together.',
    actions: '<div class="g1-display-flex g1-s-9b5be34d"><div id="init-filter" class="g1-display-flex g1-s-48b783bb"><button class="btn btn-outline btn-sm active" data-init-filter="active" data-on-click="initiativeSetFilter" data-args="[&quot;active&quot;]">Active</button><button class="btn btn-outline btn-sm" data-init-filter="closed" data-on-click="initiativeSetFilter" data-args="[&quot;closed&quot;]">Closed</button><button class="btn btn-outline btn-sm" data-init-filter="archived" data-on-click="initiativeSetFilter" data-args="[&quot;archived&quot;]">Archived</button><button class="btn btn-outline btn-sm" data-init-filter="all" data-on-click="initiativeSetFilter" data-args="[&quot;all&quot;]">All</button></div><button class="btn btn-outline btn-sm" data-on-click="loadInitiatives">Refresh</button><button class="btn btn-primary btn-sm" data-on-click="openInitiativeCreateDrawer">+ New Initiative</button></div>',
    stats: [
      { id: 'init-cnt', icon: ICON.flag, value: '—', label: 'Initiatives' },
    ],
  },
  'hero-campaigns': {
    icon: ICON.campaign,
    title: 'Campaigns',
    sub: 'One scenario fanned out across many agents. Open a campaign for the per-agent breakdown and result mix.',
    actions: '<div class="g1-display-flex g1-s-993532d2"><button class="btn btn-outline btn-sm g1-s-ddf6ed84" disabled title="Scheduled campaigns — coming soon">Schedule · soon</button><button class="btn btn-outline btn-sm" data-on-click="loadCampaigns">Refresh</button><button class="btn btn-primary btn-sm" id="campaign-new-btn" data-on-click="openCampaignLaunch">&#9654; New campaign</button></div>',
    stats: [
      { id: 'campaign-cnt', icon: ICON.campaign, value: '—', label: 'Campaigns' },
    ],
  },
  'hero-attackpath': {
    icon: ICON.path,
    title: 'Attack Paths',
    sub: 'Fleet lateral-movement graph — reachability, blast radius, choke points, and paths to Domain Admin. Recon only: relationship mapping, no exploitation or propagation.',
    actions: '<div class="g1-display-flex g1-s-993532d2"><button class="btn btn-outline btn-sm" data-on-click="loadAttackPath">Refresh</button><button class="btn btn-outline btn-sm" data-on-click="openAPAssets">&#9873; Tag Assets</button><button class="btn btn-outline btn-sm" data-on-click="openAPSchedule">&#8635; Schedule</button><button class="btn btn-outline btn-sm" data-on-click="openAPAbout" title="How Attack Path Validation works">&#9432; About</button><button class="btn btn-primary btn-sm" id="ap-collect-btn" data-on-click="openAPCollect">&#9654; Run Collection</button></div>',
  },
  'hero-exposure': {
    icon: ICON.lock,
    title: 'Exposure Explorer',
    sub: 'Per-asset attack-path exposure, detection coverage, CVE/KEV/EPSS risk, threat-group attribution, and findings — one composite Exposure Score per host.',
    actions: '<button class="btn btn-outline btn-sm" data-on-click="loadExposureAssets">Refresh</button>',
  },
  'hero-recommendations': {
    icon: ICON.bulb,
    title: 'Recommendations',
    sub: 'What to simulate next, ranked by threat priority, how overdue the technique is for testing, and whether it traverses a real path in your environment.',
    actions: '<div class="g1-display-flex g1-s-9b5be34d"><select id="rec-limit" data-on-change="loadRecommendations" class="g1-s-d41e6472"><option value="10">Top 10</option><option value="20" selected>Top 20</option><option value="50">Top 50</option></select><button class="btn btn-outline btn-sm" data-on-click="copyRecommendedScenario">Copy scenario techniques</button><button class="btn btn-outline btn-sm" data-on-click="loadRecommendations">Refresh</button></div>',
  },
  'hero-findings': {
    icon: ICON.flag,
    title: 'Findings',
    sub: 'Security gaps surfaced by simulations — each is a technique that executed without being prevented. Triage and re-validate.',
    actions: '<div class="g1-display-flex g1-s-993532d2"><button class="btn btn-outline btn-sm is-hidden" id="findings-bulk-btn" data-on-click="bulkPushSelectedFindings">Push to ITSM</button><button class="btn btn-outline btn-sm" data-on-click="loadFindings">Refresh</button></div>',
  },
  'hero-iocs': {
    icon: ICON.hash,
    title: 'IOC Registry',
    sub: 'Indicators observed across every run, deduplicated and cross-referenced against scenarios, agents, and ATT&CK techniques.',
    actions: '<div class="g1-display-flex g1-s-993532d2"><button class="btn btn-outline btn-sm is-hidden" id="ioc-import-btn" data-on-click="openIOCImportModal">Import</button><button class="btn btn-outline btn-sm" data-on-click="loadIOCRegistry">Refresh</button></div>',
  },
  'hero-remediation': {
    icon: ICON.wrench,
    title: 'Remediation',
    sub: 'Prioritized fixes from your open findings, with authoritative MITRE ATT&CK mitigations. Re-validate after applying a fix.',
    actions: '<div id="rem-ticket-actions" class="is-hidden g1-s-993532d2"><button class="btn btn-outline btn-sm" data-on-click="remBulkTicket" data-args="[&quot;critical&quot;]">Create Tickets for All Critical</button><button class="btn btn-outline btn-sm" data-on-click="remBulkTicket" data-args="[&quot;all&quot;]">Create Tickets for All</button></div>',
  },
  'hero-verification': {
    icon: ICON.check,
    title: 'Verification',
    sub: 'Attest whether off-host controls (SIEM, identity, cloud, DLP, network) actually detected each simulated technique. Attestations are immutable, evidence is SHA-256 hashed at upload, and every action is written to the audit log.',
  },
  'hero-reports': {
    icon: ICON.report,
    title: 'Reports',
    sub: 'Generate evidence reports from your validated results. History re-generates on download — no stale copies.',
  },
  'hero-integrations': {
    icon: ICON.plug,
    title: 'Integrations',
    sub: 'Configure ITSM connectors. Analysts create tickets from the Findings tab; BAS can auto-create tickets for critical exposures based on policy.',
    actions: '<div class="g1-display-flex g1-s-993532d2" id="integrations-admin-actions"><button class="btn btn-outline btn-sm" data-on-click="triggerTicketingSync">Sync Now</button><button class="btn btn-primary btn-sm" data-on-click="openAddConnector">+ Add Connector</button></div>',
  },
  'hero-compliance': {
    icon: ICON.check,
    title: 'Compliance Report',
    sub: 'Generate a compliance report for one agent against a regulatory framework, then export it.',
    actions: '<div class="g1-display-flex g1-s-377dd6f6"><select id="cmp-agent-sel" class="btn btn-outline g1-s-4f2248ba"></select><select id="cmp-fw-sel" class="btn btn-outline g1-s-0eddd0ab"></select><button class="btn btn-primary btn-sm" data-on-click="loadComplianceReport">Generate</button><button class="btn btn-outline btn-sm is-hidden" data-on-click="openComplianceDoc" data-args="[&quot;html&quot;]" id="cmp-export-html">↗ HTML</button><button class="btn btn-outline btn-sm is-hidden" data-on-click="openComplianceDoc" data-args="[&quot;pdf&quot;]" id="cmp-export-pdf">↓ PDF</button><button class="btn btn-outline btn-sm is-hidden" data-on-click="exportCompliance" data-args="[&quot;json&quot;]" id="cmp-export-json">↓ JSON</button><button class="btn btn-outline btn-sm is-hidden" data-on-click="exportCompliance" data-args="[&quot;csv&quot;]" id="cmp-export-csv">↓ CSV</button></div>',
  },
  'hero-sla': {
    icon: ICON.clock,
    title: 'SLA Compliance',
    sub: 'Fleet SLA report: on-time resolution rate by severity, monthly trend and recent history.',
    actions: '<button class="btn btn-outline btn-sm" data-on-click="loadSLAReport">&#x21bb; Refresh</button>',
  },
  'hero-variants': {
    icon: ICON.layers,
    title: 'Variants',
    sub: 'Run technique variants on an agent and see which ones bypass your controls.',
    actions: '<div class="g1-display-flex g1-s-9b5be34d"><button class="btn btn-outline btn-sm" data-on-click="loadVariantTab">&#x21bb; Refresh</button></div>',
  },
  'hero-email': {
    icon: ICON.mail,
    title: 'Email',
    sub: 'Email security-effectiveness validation — SPF/DKIM/DMARC, phishing, attachments, outbound DLP, mailbox/identity security',
    actions: '<div class="email-launch-buttons"><button class="btn btn-outline btn-sm" data-on-click="loadEmailTab">&#x21bb; Refresh</button></div>',
  },
  'hero-factory': {
    icon: ICON.factory,
    title: 'Factory Health',
    sub: 'Threat-content pipeline health: ingestion, validation, publication and data quality.',
  },
  'hero-exercises': {
    icon: ICON.bolt,
    title: 'Exercises',
    sub: 'Purple-team exercises and OpenAEV content: scenarios, exercise plans and executions.',
  },
  'hero-attack-coverage': {
    icon: ICON.mapped,
    title: 'Technique Coverage',
    sub: 'Per technique: what is simulated, detected, exercised, mapped to compliance and covered by a response playbook.',
  },
  'hero-threat-priority': {
    icon: ICON.star,
    title: 'Threat Prioritization',
    sub: 'Threat actors ranked by relevance to you, with the techniques you have not yet validated.',
  },
};

export function mountPageHeroes() {
  Object.keys(HEROES).forEach(function(id) { mountHero(id, HEROES[id]); });
}
