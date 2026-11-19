// What each page is for and how to use it. Shown by the "?" button in the header (page-help.js).
//
// Every entry: { about, steps, reading?, tips?, related? }
//   about    one or two sentences: what the page is for.
//   steps    what to do, in order. Each step is plain text.
//   reading  optional [term, meaning] pairs that explain what is on the page.
//   tips     optional cautions and good practice.
//   related  optional tab ids worth visiting next.
// Page titles come from the console's own tab titles, so a rename never leaves the help with an old name. The text is
// written from the page's own banner, headings and buttons; if a page changes, change its entry here.

export var HELP = {
  dashboard: {
    about: 'The starting page: how well your security controls are holding up against the attacks Audspect has tested, and what needs attention.',
    steps: [
      'Choose Operational for day-to-day detail (runs, agents, alerts) or Executive for the summary a manager reads.',
      'Read the headline scores and trends first, then open any tile\'s "View details" link to go to the page behind the number.',
      'Use Refresh to reload the figures after a run finishes.',
      'If a tile says there is no data, run a scenario first (Scenarios) and come back.'
    ],
    reading: [['Scores', 'Calculated only from completed runs; a run that errored or was skipped is not counted as a pass.'], ['Trends', 'Change over time, so you can tell whether fixes are working.']],
    tips: ['Numbers here are a summary. For the evidence behind any figure, open Live Runs or Reports & Analytics.'],
    related: ['scenarios', 'runs', 'reports', 'findings']
  },
  agents: {
    about: 'Agents are the programs installed on endpoints that carry out scenarios under policy. This page shows every agent, lets you group them and deploy new ones.',
    steps: [
      'Pick a view: System Tree (by group), Operational (status and activity) or Risk & Remediation (what is exposed and what to fix).',
      'To add an endpoint, open Deploy Agent, check the Connection Config, generate a token and run the installer on the machine.',
      'Create a group with New group to organise agents (for example by site or role). Scenarios and schedules can then target a whole group.',
      'Click an agent to open its details: host information, recent runs, health and the actions available to your role.',
      'Download CSV exports the list for audits.'
    ],
    reading: [['Online / Offline', 'Whether the agent has contacted the server recently. Offline agents cannot take new work.'], ['Group', 'A named set of agents you can target together.']],
    tips: ['Deployment tokens are secrets. Copy them straight into the install and do not share them.', 'Stopping, uninstalling or removing an agent is an administrator action and takes effect on the endpoint.'],
    related: ['scenarios', 'runs', 'scheduled-assessments']
  },
  settings: {
    about: 'Platform configuration: users and roles, content engines, threat-intelligence feeds, audit logs, appearance, licence and backups. Administrators only for most sections.',
    steps: [
      'Choose a section from the list: Users & roles, Caldera Engine, Threat Intel Connector, TAXII Connectors, ART Content Library, Audit Logs, Theme & Display, Dashboard Preferences, License, Backup & Recovery.',
      'Users & roles: add a user with + New user and give the lowest role that does the job.',
      'Threat intel and TAXII: add a connector, then use Sync Now to pull content. Check Now tests connectivity.',
      'Audit Logs: filter and export (Export CSV) to see who did what.',
      'Backup & Recovery: run Backup Now before any upgrade, and keep the backup somewhere other than the server.'
    ],
    tips: ['Changes here affect everyone using the console.', 'Take a backup before upgrading. It includes the certificate authority that your agents trust; without it every agent would need to be enrolled again.'],
    related: ['integrations', 'profile']
  },
  profile: {
    about: 'Your own account: who you are signed in as, the access your role gives you, and your password.',
    steps: ['Check the Account and Your access panels to see your username and what you are allowed to do.', 'Use Change password to set a new password. Choose a long, unique one.'],
    tips: ['If a button you expect is missing elsewhere in the console, your role probably does not allow it. Ask an administrator.']
  },
  scenarios: {
    about: 'The library of security scenarios. Each scenario safely imitates an attack technique or a whole attack chain, so you can check whether your controls stop or detect it.',
    steps: [
      'Browse by category (for example APT, Ransomware, Insider, Network, Email, DLP, Phishing) or search by name, tag, technique or ID. The ATT&CK Techniques figure at the top opens the full technique list.',
      'Open a scenario to read its Overview: what it does, how safe it is, the steps, the techniques it covers and what you need before it runs.',
      'Press Run (or Launch). Choose the agents or groups to run on, review the options and start.',
      'Watch progress under Live Runs; open the report when it finishes.',
      'To make your own, use New scenario or import Sigma/YARA content if your role allows it.'
    ],
    reading: [['Run mode', 'Posture checks read configuration only. Telemetry mode performs real but harmless actions so your tools can see them. Lab mode is full fidelity and only for isolated test environments.'], ['Expected verdicts', 'PASS means the control stopped or detected the technique; FAIL means it got through; SKIP and ERROR mean it could not be judged and are not counted as passes.']],
    tips: ['Start with posture or telemetry scenarios. Run lab-only scenarios only on isolated machines.', 'Unsigned or edited scenarios are flagged; use signed content for production runs.'],
    related: ['runs', 'agents', 'coverage', 'scheduled-assessments']
  },
  runs: {
    about: 'Everything that has run, is running or is queued. Use it to follow a run live and to open results and reports afterwards.',
    steps: [
      'Find a run using the filters or search above the table; Columns chooses what to show.',
      'Click a run to open its detail: each step, its verdict, the evidence and the time taken.',
      'Open the run report for a printable HTML or PDF summary.',
      'Select several runs and use Export selected, or Export CSV for the whole list.'
    ],
    reading: [['PASS / FAIL', 'Whether your controls handled the step.'], ['SKIPPED / ERROR', 'The step could not be judged (for example a tool was missing). These are shown honestly and are never counted as a pass.']],
    tips: ['A run still shown as running is waiting on its agent. Check the agent is online on the Agents page.'],
    related: ['scenarios', 'agents', 'reports', 'findings']
  },
  'cloud-scenarios': {
    about: 'Read-only checks of your cloud accounts (AWS, Azure, GCP): can an identity destroy recovery points or expose data? Nothing in the cloud is changed.',
    steps: [
      'Use the provider chips or the filter box to find a scenario, then press Use in run form.',
      'In Run a scenario fill in the Account ID (it must be on the server\'s allow-list), the Principal and the Resource, and the optional Region.',
      'Press Run scenario. The result shows the status and a run ID.',
      'For a broader look, use Discovery run: it reads the account\'s permissions and asks whether a target can be reached from the identities you list.',
      'Past runs are listed under Recent runs.'
    ],
    tips: ['The server refuses accounts that are not on its allow-list. That is deliberate; ask an administrator to add the account.', 'Discovery of a large account can take a while.'],
    related: ['scenarios', 'findings']
  },
  'k8s-scenarios': {
    about: 'Plan and run Kubernetes security scenarios against a lab cluster. Anything that changes the cluster needs a second person to approve it.',
    steps: [
      'Open New run, choose the action, the registered cluster and the namespace, then Plan run. Planning writes nothing.',
      'A different operator reviews and approves the plan.',
      'Only the person who requested the run can execute it once approved.',
      'Check the evidence and cleanup in the run drawer.',
      'Run analysis is a read-only analysis of a cluster and needs no approval.'
    ],
    tips: ['Lab clusters only. Do not point this at production.', 'Approving your own plan is not allowed; ask a colleague.'],
    related: ['cloud-scenarios', 'runs']
  },
  aleef: {
    about: 'API discovery engagements for Aleef: create an engagement, add the accounts to assess, classify operations and review findings.',
    steps: [
      'Create an engagement with New engagement.',
      'Add the accounts to assess with Add account.',
      'Review the operation classification so that only safe operations are exercised.',
      'Start a run with Start a run, then Load to see its results.',
      'Review Findings and take them to Remediation.'
    ],
    tips: ['Only run against accounts you are authorised to test.'],
    related: ['findings', 'remediation', 'api-inventory']
  },
  'scheduled-assessments': {
    about: 'Recurring validations that run automatically on a chosen set of agents, and the change-freeze windows during which automatic work must not start.',
    steps: [
      'Create a schedule: pick the scenario or assessment, the agent scope and how often it repeats.',
      'Use Change-freeze windows (Add window) for times nothing automatic should start, such as an end-of-day batch or month-end close.',
      'A window is either once (specific start and end) or daily (a time range, optionally limited to weekdays or days of the month).',
      'Check the table for the next run time and the latest result.'
    ],
    reading: [['Freeze window', 'Scheduled assessments that fall inside a window are skipped, not delayed. Other automatic starters are held until it ends.'], ['Runs started by hand', 'Not blocked by a freeze window.']],
    tips: ['Set your timezone on a daily window; the presets are only starting points.'],
    related: ['scenarios', 'agents', 'runs']
  },
  initiatives: {
    about: 'Initiatives group the validation jobs behind one goal and show how far along it is, from creation through to closing or archiving.',
    steps: [
      'Use the filters to narrow the list (Clear filters resets them); the tiles show how many are Active, Closed or Archived.',
      'Open an initiative to see its Attached jobs, the Job states and its Progress.',
      'Attach or detach jobs as the work changes.',
      'When the goal is met, use Close Initiative. Use Archive Initiative to put one away without closing it.'
    ],
    related: ['scenarios', 'runs', 'campaigns']
  },
  segmentation: {
    about: 'Network segmentation checks run from a lab: packs of checks that test whether traffic that should be blocked between zones really is.',
    steps: [
      'Pick a pack in the list at the top and press Run pack.',
      'The run appears in the runs list with who requested it and when it started; select it to open the Run detail.',
      'Read the Verdict for each check and the Repeatability figure, which shows whether repeated runs agree.',
      'Compare the result with the policy you intend, and fix any path that was allowed.'
    ],
    tips: ['If the page says the lab is not configured, an administrator must set up the segmentation lab first.', 'Probing real customer networks needs a signed scope. Test only networks you are authorised to test.'],
    related: ['attackpath', 'findings']
  },
  'api-inventory': {
    about: 'API inventories imported per target: what each API exposes, how it differs from what was actually seen, and what stored test data can be run against it.',
    steps: [
      'Select a target on the left (or All targets for jobs across every target).',
      'Read the inventory and its versions, and what changed against the previous one.',
      'Check Drift: operations in the specification that were never seen, and operations seen but not in the specification.',
      'Use the examples to add stored test data (read, write, function and property examples), then Run stored test data.',
      'Create a schedule to repeat the run, and review the jobs list for results.'
    ],
    tips: ['Check the binding preview before running; writes change data on the target. Remove stored data when you no longer need it.'],
    related: ['aleef', 'findings']
  },
  'factory-health': {
    about: 'Health of the pipelines that bring in, build, sign and validate Audspect scenario content.',
    steps: [
      'Look at each source: healthy, failing or never synced, with its last success and last diagnostic.',
      'Follow content through its stages: Candidate, Validated, Published or Rejected.',
      'Check that there are no stale sources, and investigate any that are failing.'
    ],
    tips: ['Mainly for administrators and content owners.'],
    related: ['scenarios', 'settings']
  },
  campaigns: {
    about: 'A campaign is one scenario run across many agents. Open one to see the result for each agent and the overall mix of Prevented, Detected only and Missed.',
    steps: ['Read the tiles for how many campaigns exist, how many agents were targeted and the result mix across campaigns.', 'Filter the list, then open a campaign for its per-agent breakdown.', 'Follow a weak agent into its run for the evidence.'],
    related: ['runs', 'agents', 'scenarios']
  },
  'ad-coverage': {
    about: 'Active Directory attack-surface coverage: what Audspect models, what has been turned into scenarios, what has been run and whether detections fired.',
    steps: ['Review the capability list and the status of each.', 'Open one to see its scenarios and results.', 'Run the related scenarios from Scenarios to fill gaps.'],
    tips: ['Results need real Active Directory data. A lab domain is best for first use.'],
    related: ['scenarios', 'attackpath']
  },
  coverage: {
    about: 'Detection coverage drawn on the MITRE ATT&CK matrix from your validated results: which techniques your tools prevented, only detected or missed.',
    steps: ['Read the heatmap: colour shows how well each technique is covered.', 'Click a technique for its description, mitigations and your results.', 'Use the source chips (All, BAS, ART, Emu, Atomic, Multi-source) to see where content comes from.', 'Use Test coverage gaps to start runs for techniques not yet covered.'],
    reading: [['Untested', 'No completed run covers that technique yet. It is not a pass.']],
    related: ['attack-coverage', 'scenarios', 'recommendations']
  },
  attackpath: {
    about: 'Maps how an attacker could move between your machines and accounts: reachability, blast radius, choke points and paths to Domain Admin. Recon only; nothing is exploited.',
    steps: ['Run Collection to gather relationships from your agents (or Discover Subnet to find assets).', 'Tag Assets to mark crown jewels such as domain controllers.', 'Read the graph and the path list to find choke points worth fixing first.', 'Schedule recurring collections, and use History to compare over time.'],
    tips: ['Collection reads relationships only. Automatic collection pauses during change-freeze windows.'],
    related: ['ad-coverage', 'exposure', 'findings']
  },
  exposure: {
    about: 'Internet-facing and internal assets with exposure and vulnerability context.',
    steps: ['Browse or search the asset list.', 'Open an asset to see what is exposed and which known vulnerabilities apply.', 'Start with the most exposed assets.'],
    related: ['attackpath', 'findings', 'remediation']
  },
  recommendations: {
    about: 'What to simulate next, ranked by how relevant the threat is, how long since the technique was last tested, and whether it works against a real path in your environment.',
    steps: ['Read the list from the top; the first items matter most.', 'Use Details to see why an item ranked where it did.', 'Use Re-validate or run the suggested scenario to act on it.'],
    related: ['scenarios', 'threat-priority', 'coverage']
  },
  findings: {
    about: 'Security gaps found by simulations. Each is a technique that ran without being stopped. Triage them and re-test after fixing.',
    steps: ['Sort or filter to the most severe findings.', 'Open a finding for the evidence, affected agents and the technique.', 'Create a ticket or move it to Remediation.', 'After the fix, re-validate to prove it worked.'],
    tips: ['A finding closes only when a re-test shows the technique is now stopped.'],
    related: ['remediation', 'verification', 'runs']
  },
  iocs: {
    about: 'Indicators (hashes, domains, IPs and so on) seen across every run, with duplicates merged and links to the scenarios, agents and techniques involved.',
    steps: ['Search or filter to find an indicator.', 'Open one to see where it appeared.', 'Add indicator to record one by hand, or Import to bring a list in.', 'Detection content waiting for review appears under Awaiting review; approve what is right for you.'],
    related: ['findings', 'integrations']
  },
  remediation: {
    about: 'Track fixes from detection through to verification.',
    steps: ['Review open items, most critical first.', 'Create tickets for individual items, or for all critical items at once, if an ITSM connector is configured.', 'After the fix is applied, verify it with a re-run.'],
    tips: ['Creating tickets sends data to your ticketing system. Check the connector under Integrations first.'],
    related: ['findings', 'verification', 'integrations']
  },
  verification: {
    about: 'Confirms whether your detection tools raised an alert for each validated step, by querying the detection connectors you add.',
    steps: ['Add a detection connector (for example your SIEM or EDR) and test it.', 'Run a scenario.', 'Use Verify now, or wait for the automatic check, to see per step whether an alert fired.', 'Mark steps that do not apply as not applicable.'],
    reading: [['Detected / Not detected', 'Only approved verification records count towards the detection rate. If nothing has been judged, no rate is shown.']],
    related: ['integrations', 'runs', 'coverage']
  },
  reports: {
    about: 'Reports & Analytics: generate and download security assessment reports, compliance evidence and audit packs, and find every report you made before.',
    steps: ['Under Available reports pick an agent to see its runs and open or download a report for any finished run.', 'Under Create a report choose the type, agent and format, then generate it.', 'In the history list, search or filter by type, agent and date, then download, copy the ID or copy the link.', 'Use the Compliance Reports and SLA Compliance tabs for framework and remediation-time views.'],
    tips: ['A report for a run that is not finished or that produced no results is not offered.'],
    related: ['compliance', 'sla-report', 'runs']
  },
  integrations: {
    about: 'Connect Audspect to your other tools: ticketing (ServiceNow, Jira, webhooks), endpoint response platforms (CrowdStrike, Defender, SentinelOne) and threat-intelligence feeds.',
    steps: ['Choose the connector type, for example + Jira.', 'Enter its address and credentials, then Test Connection.', 'Save it. Use Sync Now to pull content from feeds.', 'Remove or edit connectors you no longer use.'],
    tips: ['Credentials are stored securely, but use a dedicated service account with only the permissions needed.', 'Response connectors can act on endpoints. Review what is enabled.'],
    related: ['verification', 'remediation', 'settings']
  },
  exercises: {
    about: 'Purple-team exercises and OpenAEV content: synced scenarios and exercises, exercise plans and their executions.',
    steps: [
      'Check the synced OpenAEV scenarios and exercises; if none are listed, sync from the connector first.',
      'Create an exercise plan, then run it and follow it under Executions.',
      'Filter or select rows and use Export selected to take results out.',
      'Open an exercise for its debrief of what was detected and missed.'
    ],
    related: ['verification', 'coverage', 'runs']
  },
  'attack-coverage': {
    about: 'Technique by technique: what is simulated, detected, exercised, mapped to compliance and covered by a response playbook.',
    steps: ['Search or filter to a technique.', 'Open it for the description, your results and mapped controls.', 'Use it to decide which techniques to test next.'],
    related: ['coverage', 'recommendations', 'compliance']
  },
  'threat-priority': {
    about: 'Threat actors ranked by how relevant they are to your estate and your validated gaps.',
    steps: ['Read the ranking from the top.', 'Open an actor to see its techniques and the ones you have not stopped.', 'Run its scenarios to test your defences against it.'],
    related: ['recommendations', 'scenarios', 'coverage']
  },
  compliance: {
    about: 'How your validated results map to compliance frameworks, with downloadable evidence.',
    steps: ['Choose a framework.', 'Filter by status: Resisted, Partial, Failed, Inconclusive, Untested or Manual.', 'Open a control to see the evidence behind it.', 'Generate a report and download it as HTML, PDF, JSON or CSV.'],
    reading: [['Untested / Manual', 'No automatic evidence for this control yet. It is not claimed as met.']],
    tips: ['Only controls the platform can really test are scored. Treat the rest as needing your own evidence.'],
    related: ['reports', 'sla-report', 'scenarios']
  },
  'sla-report': {
    about: 'How quickly findings are fixed compared with your targets, by severity and by month.',
    steps: ['Read By Severity for the current picture and Monthly Trend for direction.', 'Check Recently Resolved for what was closed and how long it took.', 'Refresh to reload.'],
    related: ['remediation', 'reports', 'compliance']
  },
  variants: {
    about: 'Generated variants of techniques, and a Full sweep that runs variants of many techniques on one agent to test how robust your prevention is.',
    steps: [
      'Choose the agent first (the sweep will not start without one).',
      'Tick the techniques to include (at least one).',
      'Press Start Sweep. Queue Progress shows what is running; you can stop a sweep.',
      'Read each result: Prevented, Allowed, and the First bypass, plus the Encoding, Evasion and Context used.',
      '"why this number?" explains how the headline figure was worked out.'
    ],
    tips: ['A full sweep runs many tests. Start with a small selection, on a lab or non-critical machine.'],
    related: ['scenarios', 'coverage']
  },
  email: {
    about: 'Email security validation: SPF, DKIM and DMARC, phishing, attachments, outbound data loss and mailbox and identity security.',
    steps: ['Pick the scenario you want to run.', 'Configure the target mailbox or gateway if asked.', 'Run it and watch the result.', 'Read the verdicts to see which messages were blocked, quarantined or delivered.'],
    tips: ['Test only mailboxes and domains you control.'],
    related: ['scenarios', 'findings']
  },
  dbsim: {
    about: 'Database security simulation: checks how your databases control access, record activity and detect misuse, on PostgreSQL and MySQL.',
    steps: ['Register a database target with its agent, the credential name and the expected identity.', 'Run an identity check so the console knows the target is the one you expect.', 'Keep client read-only mode off unless a customer has approved it in writing.', 'Review run results once a run is available.'],
    tips: ['Credentials are never typed here. Only the credential name is stored; the secret stays on the agent host.', 'Lab targets must be confirmed before they can be used.'],
    related: ['agents', 'findings']
  }
};

// A page the help does not cover yet still gets a useful panel.
export var FALLBACK = {
  about: 'This page does not have detailed help yet.',
  steps: ['Use the page banner at the top to see what the page is for.', 'Press Ctrl+K to search the console for anything you are looking for.'],
  related: ['dashboard']
};

// Pages reached under another tab's content share its help.
export var ALIAS = { users: 'settings' };

export function helpFor(tab) {
  var key = ALIAS[tab] || tab;
  return Object.prototype.hasOwnProperty.call(HELP, key) ? HELP[key] : FALLBACK;
}
