// Extra G1e checkpoints beyond every tab and every smoke drawer.
// CHECKPOINTS: reveal and data states reachable under the smoke fixtures:
//   { name, tab, steps: [{ click: sel } | { fill: [sel, text] } | { select: [sel, value] }] }
export const CHECKPOINTS = [
  // -- adversaries.js: openAdvDrawer/openAdvRunModal checkpoints removed --
  // /api/caldera/adversaries has no fixture, so loadAdversaries()'s .then()
  // throws on data.filter (data falls to {}), caught by its own .catch(),
  // leaving the adversary grid permanently empty under these fixtures. See
  // UNREACHABLE_SITES below.

  // -- attack-path.js: attackpath tab's own controls (loadAttackPath's own
  // reveal, attack-path.js:39,41, is exercised by the plain tab visit).
  { name: "attack-path.js:1632 agent-download panel", tab: 'agents', steps: [
    { click: '[data-on-click="showAgentDownload"] >> nth=0' },
  ] },
  { name: "attack-path.js:1094,1095 about modal", tab: 'attackpath', steps: [
    { click: '[data-on-click="openAPAbout"]' },
  ] },
  { name: "attack-path.js:1105 schedule panel", tab: 'attackpath', steps: [
    { click: '[data-on-click="openAPSchedule"]' },
  ] },
  { name: "attack-path.js:1034 assets panel", tab: 'attackpath', steps: [
    { click: '[data-on-click="openAPAssets"]' },
  ] },
  { name: "attack-path.js:679,691,703,712 collect form", tab: 'attackpath', steps: [
    { click: '[data-on-click="openAPCollect"]' },
  ] },
  { name: "attack-path.js:781,944 collect dispatch + job-update panel", tab: 'attackpath', steps: [
    { click: '[data-on-click="openAPCollect"]' },
    { click: '[data-on-click="dispatchAPCollect"]' },
  ] },

  // -- threat-priority (attack-path.js): list auto-renders on tab visit
  // (343,368), but no fixture exists for /api/threat-priority/actors --
  // tests/smoke/baseline.json's "threat-priority" key is an empty array,
  // so loadThreatPriorityActors() always takes the empty branch and no
  // <tr data-on-click="showThreatPriorityDetail"> row ever renders. The
  // detail view (389,481) is unreachable for the same reason as
  // adversaries.js below -- see UNREACHABLE_SITES.

  // -- campaigns.js
  { name: "campaigns.js:165 campaign detail view", tab: 'campaigns', steps: [
    { click: '[data-on-click="openCampaignDetail"] >> nth=0' },
  ] },

  // -- campaigns.js: the KEV TI-pack picker lives inside the New Campaign
  // modal (#campaign-overlay, tab 'campaigns'). But openCampaignLaunch
  // itself bails out before ever opening the modal when state.scenarios is
  // empty ("if (!state.scenarios.length) { showToast(...); return; }") --
  // and /api/scenarios IS fixtured, but as an empty array. So the modal
  // (and everything inside it, including selectTIPack) is unreachable
  // regardless of tab/click fixes -- confirmed via two real visual.sh runs
  // that each hung 30min retrying an invisible element before this was
  // traced to openCampaignLaunch's own guard clause. See UNREACHABLE_SITES.
  { name: "endpoint-mastery.js:162 sweep individual-target wrap", tab: 'em', steps: [
    { click: '[data-on-click="openEMSweepModal"] >> nth=0' },
  ] },

  // -- compliance.js: openChangePassword's button lives under the 'profile'
  // tab (#tab-profile), a separate top-level tab from 'settings' despite the
  // nav label (activateTab's tab-name list in shell.js) -- but 'profile' has
  // NO data-on-click="showTab" nav entry at all (confirmed: it's reached
  // only via goToProfile(), called from the user-menu's "Go to Profile"
  // item), so the harness's tab:'profile' field can't open it -- openTab
  // looks only for a showTab nav element and gets null. Use the real
  // trigger chain instead: open the user menu, then its profile link.
  { name: "compliance.js:170 change-password cancel button", tab: 'dashboard', steps: [
    { click: '[data-on-click="toggleUserMenuFromEvent"]' },
    { click: '[data-on-click="goToProfileFromMenu"]' },
    { click: '[data-on-click="openChangePassword"]' },
  ] },

  // -- evidence.js
  { name: "evidence.js:895 command palette hint", tab: 'dashboard', steps: [
    { click: '[data-on-click="openCmdk"]' },
  ] },

  // -- findings.js: the Respond button only exists in the DOM once
  // openFinding's callback has rendered the finding-detail view (it's
  // string-concatenated in there, not a static row button) and
  // openRespondModal itself bails early without state._currentFinding --
  // so a finding row must be opened first.
  { name: "findings.js: respond modal + default action fields", tab: 'findings', steps: [
    { click: '[data-on-click="openFinding"] >> nth=0' },
    { click: '[data-on-click="openRespondModal"] >> nth=0' },
  ] },
  { name: "integrations.js:535,539 respond fields (kill_process branch)", tab: 'findings', steps: [
    { click: '[data-on-click="openFinding"] >> nth=0' },
    { click: '[data-on-click="openRespondModal"] >> nth=0' },
    { select: ['#respond-action', 'endpoint.kill_process'] },
  ] },

  // -- initiatives.js
  { name: "initiatives.js:136 initiative drawer progress bar", tab: 'initiatives', steps: [
    { click: '[data-on-click="openInitiativeDrawer"] >> nth=0' },
  ] },

  // -- integrations.js
  { name: "integrations.js:107 add-connector form", tab: 'integrations', steps: [
    { click: '[data-on-click="openAddConnector"]' },
  ] },
  // integrations.js:125,339 edit-connector form + test result -- openEditConnector
  // is only wired onto rendered connector cards; no /api/ticketing/configs
  // fixture means loadTicketingConfigs() falls to {} (not an array), so
  // renderConnectorList never gets a list to render. See UNREACHABLE_SITES.
  { name: "integrations.js:417 add-response-connector form", tab: 'integrations', steps: [
    { click: '[data-on-click="openAddResponseConnector"]' },
  ] },
  // integrations.js:435 edit-response-connector form -- same gap as :125,
  // against /api/actions/configs instead. See UNREACHABLE_SITES.

  // -- iocs.js: the import error branches need the form submitted without a
  // file/paste (what the picker allows without extra setup). The submit
  // button lives inside #ioc-import-overlay, which starts closed -- open it
  // via openIOCImportModal first (its own trigger button is admin-gated by
  // loadIOCRegistry, but the smoke role fixture is 'admin').
  { name: "iocs.js:292,299,314 IOC import validation errors", tab: 'iocs', steps: [
    { click: '[data-on-click="openIOCImportModal"]' },
    { click: '[data-on-click="submitIOCImport"]' },
  ] },

  // -- openaev.js: loadOpenAEVConfig only runs for the Settings > Threat
  // Intel sub-section (not the settings tab's default section).
  { name: "openaev.js:69 OpenAEV config error placeholder", tab: 'settings', steps: [
    { click: '[data-set="intel"]' },
  ] },

  // -- reports.js
  { name: "reports.js:118,131 report-gen filter wraps", tab: 'reports', steps: [
    { click: '[data-on-click="openReportGen"]' },
  ] },
  // reports.js:840,842 run-wizard close resets the pips -- openModalForScenario
  // is only wired onto rendered scenario tiles (scenarioDetailHTML); no
  // /api/scenarios fixture data (the endpoint IS fixtured, but as an empty
  // array) means state.scenarios stays empty and renderScenarios() returns
  // at its "No scenarios loaded" guard before ever rendering a tile. See
  // UNREACHABLE_SITES.
  // reports.js:1537 caldera-picker filters -- openBuilderCalderaPicker's
  // "Browse catalog" link lives inside #bld-caldera, which only becomes
  // visible once #bld-mode is switched to 'caldera' (renderBuilderMode),
  // and the scenario builder itself (#builder-overlay, opened via
  // openBuilder) lives under the 'scenarios' tab, not 'reports' -- tab/modal
  // navigation is fine, but the line itself is still unreachable (no
  // /api/caldera/abilities fixture anywhere in this harness means
  // doOpen(catalog) never runs with catalog.length truthy, so execution
  // always dead-ends at the empty-catalog toast instead). See
  // UNREACHABLE_SITES.
  // reports.js:1085,1087 step-picker select-all/apply controls -- openPicker
  // is wired onto the same scenario tiles as openModalForScenario above --
  // same gap. See UNREACHABLE_SITES.
  // reports.js:2672,2673,2674 run-results overlay -- viewRunResults is only
  // wired onto a run row when verdictCounts(r).total is truthy
  // (runRowHtml:266); the smoke fixture's run has no `results` array and a
  // bare numeric `score` (not `score.totalTechniques`), so verdictCounts
  // always returns total:0 and the row falls to the openRunPanelAction
  // branch instead. See UNREACHABLE_SITES.

  // -- scheduled.js: the main table's modeColor/statusColor either-or
  // classes render from the plain tab visit (3-row fixture covers all 5
  // branches). The wizard's agent-list compatible/not-allowed pair
  // (scheduled.js:357) only needs opening -- compatible is always true
  // under these fixtures (empty /api/scenarios means
  // schedSelectedScenarioSupportedOS() has nothing to constrain against,
  // so schedAgentCompatible's early `!supportedOS.length` return always
  // wins); the not-allowed/opacity:0.55 branch (g1-s-3b456e9f) can't be
  // reached without a scenario fixture carrying a supportedOs constraint,
  // which risks the exact loadScenarios() regression noted above --
  // declined rather than risk it for one cosmetic disabled-state pair.
  { name: "scheduled.js:357 new-schedule wizard agent list", tab: 'scheduled-assessments', steps: [
    { click: '[data-on-click="openSchedWizard"]' },
  ] },

  // -- shell.js: the license-grace banner (shell.js:193-198) is rendered
  // once at boot from the pre-login /api/license/status check, before any
  // tab exists to checkpoint from, and gating it on state:'grace' would
  // change that fixture for every single checkpoint in this file (a new
  // banner on every page) rather than just this one widget -- declined.
  // Its g1-s-94d252ab class isn't a g1-v rule, so it isn't coverage-
  // enforced either.
  { name: "shell.js:501 agent risk & remediation table", tab: 'agents', steps: [
    { click: '[data-agents-view="risk"]' },
  ] },

  // -- threat-intel.js: loadConnectorStatus/loadARTContentStatus's own
  // reveals (278,292,318,355) fire at boot already (admin-only init in
  // bootApp); nothing extra needed for them here. Same for
  // compliance.js:274 (its _renderConnectorCard is imported and called
  // from threat-intel.js's loadConnectorStatus).
];

// Reveal sites (docs/superpowers/specs/g1e-reveal-inventory.md) not reachable
// under fixtures: { 'features/x.js:123': 'reason' }.
export const UNREACHABLE_SITES = {
  'features/openaev.js:592': "toggleAPHistory's open branch is triggered by two buttons (#ap-history-toggle and the panel's own Close button), both nested inside containers that start display:none and only un-hide once loadAttackPath's /api/attackpath/summary call returns real graph data; no fixture exists for that endpoint (falls to {}), so neither trigger is ever visible",
  'features/agent-drawer.js:622': "no /api/compliance/frameworks fixture -- the dropdown falls to its error placeholder (empty value), so Generate's 'select a framework' guard always returns early before this line",
  'features/agent-drawer.js:634': "same guard as :622 -- never reached without a real framework option",
  'features/agent-drawer.js:636': "same guard as :622 -- never reached without a real framework option",
  'features/attack-path.js:944': "needs a live WebSocket 'ap_job_update' event; the smoke harness accepts and silently drops all WS traffic (see boot() in tests/smoke/harness.mjs)",
  'features/attack-path.js:389': "showThreatPriorityDetail is only wired onto rendered threat-priority rows; tests/smoke/baseline.json's \"threat-priority\" fixture is an empty array, so loadThreatPriorityActors() always takes the empty branch and no row ever exists to click",
  'features/attack-path.js:481': "evidenceCard's reveal is inside showThreatPriorityDetail -- unreachable for the same reason as :389",
  'features/integrations.js:125': "openEditConnector is only wired onto rendered connector cards; no /api/ticketing/configs fixture means loadTicketingConfigs()'s list falls to {} (not an array, via the `list || []` guard only catching null/undefined), so renderConnectorList never gets a card to render",
  'features/integrations.js:339': "testConnectorForm's result needs the edit-connector form open first (see :125) -- unreachable for the same reason",
  'features/integrations.js:435': "openEditResponseConnector is only wired onto rendered response-connector cards; no /api/actions/configs fixture means the same {}-not-an-array gap as :125, against a different endpoint",
  'features/reports.js:840': "openModalForScenario's run-wizard is only wired onto rendered scenario tiles (scenarioDetailHTML); /api/scenarios IS fixtured but as an empty array, so renderScenarios() returns at its \"No scenarios loaded\" guard before any tile (and its Run button) ever renders",
  'features/reports.js:842': "same run-wizard close path as :840 -- unreachable for the same reason",
  'features/reports.js:1085': "openPicker's step-picker is wired onto the same scenario tiles as :840 -- same gap",
  'features/reports.js:1087': "applyBtn's reveal is inside the same step-picker as :1085 -- same gap",
  'features/campaigns.js:409': "selectTIPack lives inside the New Campaign modal (#campaign-overlay), but openCampaignLaunch returns early ('if (!state.scenarios.length) { showToast(...); return; }') before ever opening it -- /api/scenarios IS fixtured, but as an empty array, so the modal never opens and nothing inside it (including this no-data branch) is reachable",
  'features/campaigns.js:420': "needs the TI-pack preview modal open first (see :409) -- unreachable for the same reason, independent of its own /api/ti/suggest-pack hasData:true requirement",
  'features/campaigns.js:426': "needs the TI-pack preview modal open first (see :409) -- unreachable for the same reason, independent of its own suggest-pack-rejects requirement",
  'features/campaigns.js:460': "needs the TI-pack preview modal open first (see :409) -- unreachable for the same reason",
  'features/reports.js:1766': "techRenderSelected's resolved-technique card only renders for a step whose techniqueId resolves; needs a fixture 'custom'-mode scenario with steps[].techniqueId, which the smoke fixtures don't provide",
  'features/reports.js:1804': "techChangeSelection needs the same resolved-technique card as :1766 to exist first -- same gap",
  'features/adversaries.js:527': "openAdvDrawer is only wired onto rendered adversary cards; no /api/caldera/adversaries fixture means loadAdversaries()'s .then() throws on data.filter (data falls to {}), caught by its own .catch(), so the grid stays empty and no card ever exists to click",
  'features/adversaries.js:528': "same gap as :527 -- openAdvDrawer's drawer body never opens without a rendered card",
  'features/adversaries.js:596': "needs openAdvDrawer open first (see :527) -- unreachable for the same reason",
  'features/adversaries.js:602': "needs openAdvDrawer open first (see :527) -- unreachable for the same reason",
  'features/reports.js:2672': "viewRunResults is only wired onto a run row when verdictCounts(r).total is truthy (runRowHtml:266); the smoke fixture's run has no `results` array and a bare numeric `score` (not `score.totalTechniques`), so verdictCounts always returns total:0 and the row renders the openRunPanelAction button instead",
  'features/reports.js:2673': "same gap as :2672 -- the overlay these lines open never gets a trigger",
  'features/reports.js:2674': "same gap as :2672 -- the overlay these lines open never gets a trigger",
  'features/reports.js:1537': "openBuilderCalderaPicker's filters reveal only runs inside doOpen(catalog) when catalog.length is truthy; no /api/caldera/abilities fixture exists anywhere in this harness, so state.calderaCatalog is always empty and execution always dead-ends at the 'Caldera catalog is empty or Caldera is offline' toast instead",
};
// g1-v rules (src/core/css-var-rules.js) not rendered by any checkpoint:
// { 'g1-v-0a1b2c3d': 'reason' }.
export const UNREACHABLE_RULES = {};
