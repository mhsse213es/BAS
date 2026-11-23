// Dummy-data overrides, group c: { 'GET /api/path': value | (url) => value }
// Settings, Integrations, Scenarios and Variants pages. All names and values are fictional.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const DAY = 1440;

const step = (n, name) => ({ id: n, index: n, name, description: name });
const reg = (v = 3) => ({ latestVersion: v, latestLifecycle: 'PUBLISHED_VENDOR', latestVersionId: `ver-${v}`, executableVersion: v, executableTrust: 'VENDOR_SIGNED' });
const scn = (id, name, productLine, description, tags, phases, os, steps, extra = {}) => ({
  id, name, productLine, description, tags, mitrePhases: phases, supportedOs: os, author: 'Audspect Content Team',
  source: 'builtin', executable: true, steps: steps.map((s, i) => step(i + 1, s)), registry: reg(), ...extra,
});

const SCENARIOS = [
  scn('rw-001', 'Ransomware: Shadow Copy and Backup Deletion', 'ransomware', 'Simulates the pre-encryption stage of a ransomware intrusion: deleting volume shadow copies, disabling recovery options and stopping backup services. No files are encrypted.', ['ransomware', 'impact'], ['Impact', 'Defense Evasion'], ['windows'], ['Enumerate shadow copies', 'Delete shadow copies via vssadmin', 'Disable recovery with bcdedit', 'Stop backup agent service']),
  scn('rw-002', 'Ransomware: Mass File Rename Canary Test', 'ransomware', 'Renames a set of canary documents at ransomware-like speed to check whether behavioural controls interrupt the process.', ['ransomware', 'canary'], ['Impact'], ['windows', 'linux'], ['Create canary folder', 'Rename files with locked extension', 'Drop ransom note text file']),
  scn('kc-001', 'Credential Dumping: LSASS Memory Access', 'killchain', 'Attempts to read LSASS process memory using common dumping techniques and reports whether EDR blocked, alerted or stayed silent.', ['credential-access', 'lsass'], ['Credential Access'], ['windows'], ['Open handle to LSASS', 'Create minidump with comsvcs', 'Parse dump for logon material']),
  scn('kc-002', 'Credential Theft: Browser Stored Passwords', 'killchain', 'Reads browser credential stores from a standard user context to validate endpoint data-protection controls.', ['credential-access'], ['Credential Access'], ['windows', 'darwin'], ['Locate browser profile', 'Read login data store']),
  scn('kc-003', 'Lateral Movement: Remote Service Creation', 'killchain', 'Creates and starts a benign service on a peer host through SMB and the service control manager.', ['lateral-movement', 'smb'], ['Lateral Movement'], ['windows'], ['Authenticate to peer share', 'Create remote service', 'Start remote service', 'Remove remote service']),
  scn('kc-004', 'Lateral Movement: WMI Remote Execution', 'killchain', 'Runs a harmless command on a peer host over WMI to check east-west detection.', ['lateral-movement', 'wmi'], ['Lateral Movement', 'Execution'], ['windows'], ['Connect to remote WMI', 'Spawn process via Win32_Process']),
  scn('kc-005', 'Persistence: Run Key and Scheduled Task', 'killchain', 'Establishes registry Run key and scheduled task persistence, then verifies cleanup.', ['persistence'], ['Persistence'], ['windows'], ['Write Run key value', 'Create scheduled task', 'Remove artefacts']),
  scn('kc-006', 'Persistence: Cron and Systemd Unit', 'killchain', 'Installs a user cron entry and a systemd user unit on Linux hosts.', ['persistence', 'linux'], ['Persistence'], ['linux'], ['Add cron entry', 'Create systemd user unit', 'Remove artefacts']),
  scn('dlp-001', 'Exfiltration: DNS Tunnelling Burst', 'dlp', 'Sends encoded sample records in DNS queries to a lab sink to test egress monitoring and DNS filtering.', ['exfiltration', 'dns'], ['Exfiltration', 'Command and Control'], ['windows', 'linux'], ['Encode sample records', 'Send DNS query burst', 'Confirm sink receipt']),
  scn('dlp-002', 'Exfiltration: Cloud Storage Upload of Sample PAN Data', 'dlp', 'Uploads a synthetic card-number test file to a lab object store over HTTPS to test DLP content inspection.', ['exfiltration', 'dlp', 'pci'], ['Exfiltration'], ['windows', 'darwin'], ['Generate synthetic card data file', 'Upload over HTTPS']),
  scn('ad-001', 'Active Directory: DCSync Replication Request', 'ad', 'Requests directory replication from a domain controller using a test account to validate identity-threat detections.', ['active-directory', 'credential-access'], ['Credential Access'], ['windows'], ['Enumerate domain controllers', 'Issue replication request']),
  scn('ad-002', 'Active Directory: Kerberoasting', 'ad', 'Requests service tickets for accounts with SPNs and checks for ticket anomaly alerts.', ['active-directory', 'kerberos'], ['Credential Access'], ['windows'], ['List SPN accounts', 'Request service tickets']),
  scn('em-001', 'Endpoint Mastery: Office Macro Child Process', 'common', 'Opens a sample document that launches a child shell, the classic initial execution pattern behind phishing payloads.', ['endpoint-mastery', 'phishing', 'execution'], ['Initial Access', 'Execution'], ['windows'], ['Open sample document', 'Spawn child process', 'Capture control verdict']),
  scn('em-002', 'Endpoint Mastery: Defender Tamper Attempt', 'common', 'Tries to disable real-time protection and add exclusions from an elevated context.', ['endpoint-mastery', 'defense-evasion'], ['Defense Evasion'], ['windows'], ['Query protection state', 'Attempt to disable real-time protection', 'Attempt to add exclusion path']),
  scn('cu-001', 'Branch Teller Workstation Hardening Check', 'common', 'Operator-authored posture check for the retail branch workstation baseline.', ['custom', 'branch'], ['Discovery'], ['windows'], ['Check USB storage policy', 'Check local admin membership', 'Check screen lock timeout'], { source: 'custom', author: 'r.mehta', registry: { latestVersion: 1, latestLifecycle: 'PUBLISHED_LOCAL', latestVersionId: 'ver-cu-1', executableVersion: 1, executableTrust: 'LOCAL_TRUSTED' } }),
  scn('intel-ta505', 'Threat Actor Emulation: TA505-style Intrusion Chain', 'common', 'Auto-generated from threat-intel reporting on a financially motivated actor targeting banks.', ['intel', 'auto-generated'], ['Initial Access', 'Execution', 'Impact'], ['windows'], [], { source: 'intel', intelSource: 'misp', intelActor: 'TA505', intelConfidence: 'high', artTechniques: ['T1566.001', 'T1059.001', 'T1486'], registry: { latestVersion: 2, latestLifecycle: 'VALIDATED', latestVersionId: 'ver-intel-2', executableVersion: 1, executableTrust: 'LOCAL_TRUSTED' } }),
  scn('intel-fin7', 'Threat Actor Emulation: FIN7-style Credential Harvest', 'common', 'Auto-generated from threat-intel reporting on payment-sector intrusions.', ['intel', 'auto-generated'], ['Credential Access', 'Collection'], ['windows'], [], { source: 'intel', intelSource: 'opencti', intelActor: 'FIN7', intelConfidence: 'medium', artTechniques: ['T1003.001', 'T1056.001', 'T1560'], registry: { latestVersion: 1, latestLifecycle: 'DRAFT', latestVersionId: 'ver-intel-3', executableVersion: 0, executableTrust: '' } }),
];

// Technique catalogue shared by the ART and Caldera pickers.
const TECHS = [
  ['T1003.001', 'LSASS Memory', 'credential-access', 'high'], ['T1003.003', 'NTDS', 'credential-access', 'critical'],
  ['T1547.001', 'Registry Run Keys', 'persistence', 'medium'], ['T1053.005', 'Scheduled Task', 'persistence', 'medium'],
  ['T1021.002', 'SMB/Windows Admin Shares', 'lateral-movement', 'high'], ['T1047', 'Windows Management Instrumentation', 'execution', 'medium'],
  ['T1059.001', 'PowerShell', 'execution', 'medium'], ['T1059.003', 'Windows Command Shell', 'execution', 'low'],
  ['T1490', 'Inhibit System Recovery', 'impact', 'critical'], ['T1486', 'Data Encrypted for Impact', 'impact', 'critical'],
  ['T1562.001', 'Disable or Modify Tools', 'defense-evasion', 'high'], ['T1070.001', 'Clear Windows Event Logs', 'defense-evasion', 'medium'],
  ['T1048.003', 'Exfiltration Over Unencrypted Protocol', 'exfiltration', 'high'], ['T1041', 'Exfiltration Over C2 Channel', 'exfiltration', 'high'],
  ['T1087.002', 'Domain Account Discovery', 'discovery', 'low'], ['T1082', 'System Information Discovery', 'discovery', 'low'],
  ['T1566.001', 'Spearphishing Attachment', 'initial-access', 'high'], ['T1558.003', 'Kerberoasting', 'credential-access', 'high'],
  ['T1218.011', 'Rundll32', 'defense-evasion', 'medium'], ['T1105', 'Ingress Tool Transfer', 'command-and-control', 'medium'],
];
const artTechniques = () => TECHS.map(([id, name, tactic, severity], i) => ({
  id, name, tactic, severity, phase: tactic, tests: 1 + (i % 4), platforms: ['windows'], requiresAdmin: i % 3 === 0, requiresPayload: i % 7 === 0,
}));
const calderaAbilities = () => TECHS.flatMap(([id, name, tactic], i) => [0, 1].map((k) => ({
  id: `ab-${String(i * 2 + k + 1).padStart(4, '0')}`, name: k ? `${name} (stockpile)` : `${name} (emulation)`, technique: id, techniqueId: id, tactic,
  plugin: k ? 'stockpile' : (i % 3 === 0 ? 'atomic' : 'emu'), platforms: i % 5 === 4 ? ['windows', 'linux'] : ['windows'], executor: 'psh',
  requiresAdmin: i % 4 === 0, requiresPayload: false,
})));

const ADVERSARIES = [
  ['adv-01', 'FIN7 Payment Intrusion', 'Financially motivated actor focused on point-of-sale and payment environments.', ['initial-access', 'execution', 'credential-access', 'exfiltration'], 14],
  ['adv-02', 'TA505 Bank Targeting Chain', 'Phishing-led intrusion ending in ransomware staging against financial institutions.', ['initial-access', 'execution', 'defense-evasion', 'impact'], 17],
  ['adv-03', 'Wizard Spider Pre-Ransomware', 'Enterprise intrusion tooling used ahead of ransomware deployment.', ['credential-access', 'lateral-movement', 'discovery', 'impact'], 22],
  ['adv-04', 'APT29 Identity Abuse', 'Stealthy identity and cloud credential abuse with long dwell time.', ['persistence', 'credential-access', 'defense-evasion'], 12],
  ['adv-05', 'Scattered Insider Data Theft', 'Insider-style collection and staged exfiltration over web services.', ['collection', 'exfiltration', 'discovery'], 9],
].map(([id, name, description, tactics, abilityCount]) => ({ id, name, description, tactics, abilityCount }));

const ticketingConfigs = () => [
  { id: 'tk-1', name: 'SOC ServiceNow (Production)', provider: 'servicenow', enabled: true, autoCreate: 'critical_high', autoUpdate: true, autoClose: true, lastTestOk: true, lastTestAt: iso(190), settings: { instance_url: 'https://acmebank.service-now.com', username: 'svc_audspect', password: '***', category: 'security', assignment_group: 'SOC Tier 2' } },
  { id: 'tk-2', name: 'Vulnerability Management Jira', provider: 'jira', enabled: true, autoCreate: 'off', autoUpdate: true, autoClose: false, lastTestOk: true, lastTestAt: iso(2 * DAY), settings: { base_url: 'https://jira.acmebank.example', username: 'svc.audspect@acmebank.example', api_token: '***', project_key: 'VULN' } },
  { id: 'tk-3', name: 'Splunk On-Call Webhook', provider: 'webhook', enabled: false, autoCreate: 'off', autoUpdate: false, autoClose: false, lastTestOk: null, settings: { url: 'https://hooks.acmebank.example/audspect', secret: '***' } },
];

const actionConfigs = () => [
  { id: 'rc-1', name: 'CrowdStrike Falcon (Prod CID)', provider: 'crowdstrike', enabled: true, baseUrl: 'https://api.us-2.crowdstrike.com', clientId: 'fake-client-id-0000', killProcessScriptName: 'bas_kill_process' },
  { id: 'rc-2', name: 'Defender for Endpoint (Corp Tenant)', provider: 'microsoft_defender', enabled: true, baseUrl: 'https://api.securitycenter.microsoft.com', tenantId: '00000000-0000-0000-0000-000000000000', clientId: 'fake-client-id-0000' },
  { id: 'rc-3', name: 'SentinelOne (Branch Sites)', provider: 'sentinelone', enabled: false, baseUrl: 'https://acme.sentinelone.example' },
];

const abilities = calderaAbilities();
const art = artTechniques();

export const DEMO = {
  'GET /api/users': [
    { id: 1, username: 'asha.nair', role: 'admin', isActive: true, mustChangePw: false, createdAt: iso(400 * DAY), lastLogin: iso(25) },
    { id: 2, username: 'r.mehta', role: 'analyst', isActive: true, mustChangePw: false, createdAt: iso(310 * DAY), lastLogin: iso(180) },
    { id: 3, username: 'j.okafor', role: 'analyst', isActive: true, mustChangePw: false, createdAt: iso(260 * DAY), lastLogin: iso(1 * DAY + 90) },
    { id: 4, username: 'l.fernandes', role: 'analyst', isActive: true, mustChangePw: true, createdAt: iso(12 * DAY), lastLogin: iso(5 * DAY) },
    { id: 5, username: 'ciso.office', role: 'viewer', isActive: true, mustChangePw: false, createdAt: iso(200 * DAY), lastLogin: iso(3 * DAY) },
    { id: 6, username: 'audit.readonly', role: 'viewer', isActive: true, mustChangePw: false, createdAt: iso(150 * DAY), lastLogin: iso(21 * DAY) },
    { id: 7, username: 'p.dsouza', role: 'analyst', isActive: false, mustChangePw: false, createdAt: iso(330 * DAY), lastLogin: iso(94 * DAY) },
  ],
  'GET /api/art/content/status': {
    seeded: true, version: 'atomic-red-team 2026.09.2', techniqueCount: 312, techniquesLoaded: 312, windowsRunnable: 241, testCount: 1286,
    psTestCount: 702, cmdTestCount: 431, variantCount: 61240, payloadCount: 38, missingPayloadCount: 0, missingPayloads: [], kevCount: 1184,
    source: 'Bundled content pack (offline)', importedAt: iso(9 * DAY),
  },
  'GET /api/caldera/abilities': abilities,
  'GET /api/caldera/adversaries': ADVERSARIES,
  'GET /api/caldera/status': {
    reachable: true, url: 'https://caldera.lab.acmebank.example:8443', version: '5.0.0', abilityCount: abilities.length,
    byPlugin: abilities.reduce((m, a) => ({ ...m, [a.plugin]: (m[a.plugin] || 0) + 1 }), {}), uniqueTechniques: TECHS.length,
    adversaryCount: ADVERSARIES.length, latencyMs: 38, httpStatus: 200, error: '',
  },
  'GET /api/caldera/techniques': TECHS.map(([id, name, tactic]) => ({ id, name, tactic })),
  'GET /api/art/techniques': art,
  'GET /api/adversary-templates': [
    { id: 'tmpl-fin7', name: 'FIN7 Payment Environment Intrusion', shortName: 'FIN7', category: 'apt', risk: 'critical', description: 'Point-of-sale and payment network intrusion chain.', tactics: ['initial-access', 'execution', 'credential-access', 'exfiltration'], keyTechniques: ['T1566.001', 'T1059.001', 'T1003.001', 'T1041'], basScenarioId: 'intel-fin7', artTechniques: ['T1566.001', 'T1059.001', 'T1003.001', 'T1041'], calderaAdversaryName: 'FIN7 Payment Intrusion', estDuration: '35 min' },
    { id: 'tmpl-wizard', name: 'Wizard Spider Pre-Ransomware', shortName: 'Wizard Spider', category: 'ransomware', risk: 'critical', description: 'Discovery, lateral movement and recovery inhibition ahead of encryption.', tactics: ['discovery', 'lateral-movement', 'impact'], keyTechniques: ['T1087.002', 'T1021.002', 'T1490'], basScenarioId: 'rw-001', artTechniques: ['T1087.002', 'T1021.002', 'T1490'], calderaAdversaryName: 'Wizard Spider Pre-Ransomware', estDuration: '50 min' },
    { id: 'tmpl-apt29', name: 'APT29 Identity Abuse', shortName: 'APT29', category: 'apt', risk: 'high', description: 'Credential and token abuse with defence evasion.', tactics: ['persistence', 'credential-access', 'defense-evasion'], keyTechniques: ['T1547.001', 'T1558.003', 'T1562.001'], artTechniques: ['T1547.001', 'T1558.003', 'T1562.001'], calderaAdversaryName: 'APT29 Identity Abuse', estDuration: '40 min' },
    { id: 'tmpl-lsass', name: 'LSASS Credential Dumping Techniques', shortName: 'LSASS', category: 'technique', risk: 'high', description: 'Common LSASS access methods in isolation.', tactics: ['credential-access'], keyTechniques: ['T1003.001'], basScenarioId: 'kc-001', artTechniques: ['T1003.001'], estDuration: '12 min' },
    { id: 'tmpl-insider', name: 'Insider Staged Data Theft', shortName: 'Insider', category: 'insider', risk: 'medium', description: 'Collection and staged exfiltration by a privileged user.', tactics: ['collection', 'exfiltration'], keyTechniques: ['T1048.003', 'T1041'], basScenarioId: 'dlp-002', artTechniques: ['T1048.003'], estDuration: '25 min' },
  ],
  'GET /api/config/connection': {
    serverURL: 'https://audspect.acmebank.example:9443', agentSecret: 'DEMO-ONLY-NOT-A-REAL-SECRET',
    windows: 'audspect-agent.exe --server https://audspect.acmebank.example:9443',
    linux: 'curl -fsSL https://audspect.acmebank.example:9443/install-agent.sh | sudo bash',
    mac: 'sudo installer -pkg audspect-agent.pkg -target /',
    deploymentSigningFingerprint: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
  },
  'GET /api/execution-policy/default': { inProcessPolicy: 'restricted' },
  'GET /api/connector/status': {
    mispEnabled: true, openctiEnabled: true, otxEnabled: false, bundleEnabled: true, bundleVersion: '2026.10.1',
    bySource: { misp: { rawCount: 1480, actorCount: 38, fetchedAt: iso(140), error: '' }, opencti: { rawCount: 912, actorCount: 27, fetchedAt: iso(140), error: '' } },
    lastSyncAt: iso(140), nextSyncAt: new Date(NOW + 80 * 60_000).toISOString(), lastSyncStatus: 'ok', lastError: '',
    scenariosCreated: 14, scenariosUpdated: 9,
  },
  'GET /api/threat-intel/misp/config': { configured: true, enabled: true, baseUrl: 'https://misp.intel.acmebank.example', insecureTls: false },
  'GET /api/threat-intel/opencti/config': { configured: true, enabled: true, baseUrl: 'https://opencti.intel.acmebank.example', insecureTls: false },
  'GET /api/threat-intel/otx/config': { configured: false, enabled: false, baseUrl: '' },
  'GET /api/taxii/connectors': [
    { id: 'tx-1', name: 'FS-ISAC Feed', serverUrl: 'https://taxii.fsisac.example/taxii2/', enabled: true, lastPollAt: iso(95), lastPollStatus: 'ok', lastPollSummary: { processed: 212, skipped: 18, malformed: 0 } },
    { id: 'tx-2', name: 'National CERT Advisory Feed', serverUrl: 'https://taxii.cert.example/api/v21/', enabled: true, lastPollAt: iso(300), lastPollStatus: 'ok', lastPollSummary: { processed: 47, skipped: 3, malformed: 1 } },
    { id: 'tx-3', name: 'Peer Bank Sharing Group', serverUrl: 'https://share.peerbanks.example/taxii2/', enabled: false, lastPollAt: iso(6 * DAY), lastPollStatus: 'error', lastError: 'TLS handshake timeout', lastPollSummary: {} },
  ],
  'GET /api/scenarios': SCENARIOS,
  'GET /api/scenarios/library': [
    { id: 'PH-ID-001', type: 'phishing', name: 'Credential Phish: Fake Payroll Portal', status: 'available', experimental: false, parameters: [{ name: 'recipient', label: 'Test recipient', kind: 'email', required: true }] },
    { id: 'PH-ID-002', type: 'phishing', name: 'Malicious Attachment: Invoice Macro', status: 'available', experimental: false, parameters: [] },
    { id: 'PH-DET-002', type: 'phishing', name: 'Reported Phish Triage Check', status: 'available', experimental: false, parameters: [] },
    { id: 'PH-IR-003', type: 'phishing', name: 'Business Email Compromise Wire Request', status: 'experimental', experimental: true, parameters: [] },
  ],
  'GET /api/scenarios/api-bas': [],
  'GET /api/content-registry/migration-report': { blockedSchedules: [] },
  'GET /api/variants/stats': {
    executedVariants: 4812, availableVariants: 61240, calderaAvailableVariants: 4480, artTechniqueCount: 312, artAtomicCount: 1286,
    variantsPerFamily: 56, payloadFamilyCount: 6, payloadFamilyVariants: 336, techniquesWithFamilies: 14,
  },
  'GET /api/variants/coverage': TECHS.slice(0, 12).map(([id, , tactic], i) => {
    const total = 48 + i * 6, allowed = [0, 3, 0, 5, 2, 0, 7, 1, 0, 4, 2, 0][i], errored = i % 4;
    return { techniqueId: id, tactic, totalTested: total, prevented: total - allowed - errored, allowed, errored, firstBypass: allowed ? `${['base64', 'charcode', 'wmi-context', 'plain'][i % 4]} / ${['user', 'admin'][i % 2]}` : '' };
  }),
  'GET /api/ticketing/configs': ticketingConfigs(),
  'GET /api/ticketing/revalidation': { pendingRevalidation: 3 },
  'GET /api/actions/configs': actionConfigs(),
  'GET /api/ticketing/candidates': [{ id: 'f-3' }, { id: 'f-5' }, { id: 'f-8' }, { id: 'f-11' }],
  'GET /api/license': {
    status: 'valid', customer: 'Acme Bank plc (demo)', customerId: 'cust-demo-0001', issuedAt: '2026-01-15', expiresAt: '2027-01-14', tier: 'Enterprise',
    productLines: ['killchain', 'ransomware', 'dlp', 'ad', 'email', 'phishing', 'network'], features: ['ransomware', 'purple-team', 'scheduled-assessments'],
  },
  'GET /api/backups': [
    { id: 'bk-1', status: 'protected', archiveSizeBytes: 318767104, requestedAt: iso(14 * 60), trigger: 'scheduled', localPath: '/var/lib/audspect/backups/bk-1.tar.gz', remotePath: 's3://acme-bas-backups/bk-1.tar.gz' },
    { id: 'bk-2', status: 'protected', archiveSizeBytes: 316669952, requestedAt: iso(38 * 60), trigger: 'scheduled', localPath: '/var/lib/audspect/backups/bk-2.tar.gz', remotePath: 's3://acme-bas-backups/bk-2.tar.gz' },
    { id: 'bk-3', status: 'local_success', archiveSizeBytes: 312475648, requestedAt: iso(62 * 60), trigger: 'manual', localPath: '/var/lib/audspect/backups/bk-3.tar.gz', remotePath: '' },
  ],
  'GET /api/audit-logs': {
    entries: [
      ['user.login', 'asha.nair', 'ok', '10.20.8.14', { username: 'asha.nair' }, 25],
      ['scenario.run', 'r.mehta', 'ok', '10.20.8.31', { scenarioId: 'kc-001', mode: 'standard', agents: 3 }, 62],
      ['campaign.create', 'asha.nair', 'ok', '10.20.8.14', { name: 'Q4 Ransomware Readiness' }, 140],
      ['user.login', 'j.okafor', 'failed', '10.20.9.77', { username: 'j.okafor' }, 205],
      ['user.update', 'asha.nair', 'ok', '10.20.8.14', { username: 'l.fernandes', role: 'analyst' }, 380],
      ['scenario.create', 'r.mehta', 'ok', '10.20.8.31', { scenarioId: 'cu-001', name: 'Branch Teller Workstation Hardening Check' }, 700],
      ['user.reset_password', 'asha.nair', 'ok', '10.20.8.14', { username: 'l.fernandes' }, 1500],
      ['scenario.cancel', 'j.okafor', 'ok', '10.20.9.77', { scenarioId: 'rw-001' }, 2300],
    ].map(([action, actorName, outcome, ip, detail, m]) => ({ ts: iso(m), actorName, action, outcome, ip, detail: JSON.stringify(detail) })),
  },
  'GET /api/openaev/config': { configured: false, enabled: false, baseUrl: '' },
  'GET /api/openaev/status': { lastSyncStatus: '', scenarioCount: 0 },
  'GET /api/vex/sweeps': [],
};
