// Sample data for the Audspect console UI demo. Entirely fictional (client: "Acme Bank (demo)").
const D = {};

D.NAV = [
  { group: 'Operations', items: [
    ['dashboard', 'Dashboard', 'grid'], ['scenarios', 'Scenarios', 'target'], ['runs', 'Live Runs', 'play', 3],
    ['k8s-scenarios', 'Kubernetes Scenarios', 'globe'], ['scheduled-assessments', 'Scheduled Assessments', 'clock'],
    ['initiatives', 'Initiatives', 'flag'], ['campaigns', 'Campaigns', 'campaign'], ['factory-health', 'Factory Health', 'factory'],
    ['coverage', 'Coverage', 'shield'], ['variants', 'Variants', 'layers'], ['ad-coverage', 'AD Coverage', 'box'], ['email', 'Email', 'mail'],
  ]},
  { group: 'Visibility', items: [
    ['findings', 'Findings', 'alert', 7], ['iocs', 'IOC Registry', 'hash'], ['remediation', 'Remediation', 'wrench'],
    ['reports', 'Reports', 'report'], ['verification', 'Verification', 'check'], ['attackpath', 'Attack Paths', 'path'],
    ['exposure', 'Exposure Explorer', 'exposure'], ['recommendations', 'Recommendations', 'rec'], ['exercises', 'Exercises', 'bolt'],
    ['attack-coverage', 'Technique Coverage', 'mapped'], ['threat-priority', 'Threat Prioritization', 'priority'],
  ]},
  { group: 'Infrastructure', items: [
    ['agents', 'Agents', 'agent'], ['integrations', 'Integrations', 'plug'],
  ]},
  { group: 'Administration', items: [
    ['settings', 'Settings', 'gear'],
  ]},
];

D.TACTICS = ['Initial Access','Execution','Persistence','Privilege Esc.','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command & Control','Exfiltration','Impact'];

// Scenario catalogue (subset shown on cards; counts drive the category sidebar)
D.SCENARIOS = [
  { id: 'SC-0412', name: 'ACL Privilege Exposure Audit', desc: 'Detects excessive or misconfigured ACLs that may lead to privilege escalation.', source: 'Common', os: 'Windows', product: 'Identity & Access', tactic: 'Privilege Escalation', tier: ['Core'], status: 'Active', techniques: 1, mins: 15, sig: 'Signed v2', cat: 'identity', tech: ['T1222', 'T1069'], tacticTag: 'Privilege Escalation' },
  { id: 'SC-0398', name: 'ADCS ESC Template Exposure Audit', desc: 'Identifies misconfigured ADCS templates allowing certificate abuse.', source: 'Common', os: 'Windows', product: 'Identity & Access', tactic: 'Discovery', tier: ['Core','Advanced'], status: 'Active', techniques: 2, mins: 20, sig: 'Signed v1', cat: 'identity', tech: ['T1649', 'T1087'], tacticTag: 'Discovery' },
  { id: 'SC-0377', name: 'Akira Kill Chain — Ransomware Emulation', desc: 'Simulates the Akira kill chain to validate ransomware detection and response.', source: 'APT & Threat Actors', os: 'Cross-Platform', product: 'Endpoint / EDR', tactic: 'Execution', tier: ['Advanced','Enterprise'], status: 'Draft', techniques: 5, mins: 45, sig: 'Unsigned', cat: 'apt', tech: ['T1486', 'T1490', 'T1059'], tacticTag: 'Execution' },
  { id: 'SC-0391', name: 'Application Control Efficacy — Behavioral Validation', desc: 'Tests application control policies against known malicious behavior.', source: 'Common', os: 'Windows', product: 'Application Security', tactic: 'Execution', tier: ['Core'], status: 'Active', techniques: 3, mins: 30, sig: 'Signed v3', cat: 'appsec', tech: ['T1204', 'T1218'], tacticTag: 'Execution' },
  { id: 'SC-0355', name: 'APT29 Kill Chain — Cozy Bear Tradecraft (Phase 7)', desc: 'Five-stage telemetry-safe emulation of APT29 (Cozy Bear / NOBELIUM) post-compromise tradecraft on Windows.', source: 'APT & Threat Actors', os: 'Windows', product: 'Endpoint / EDR', tactic: 'Lateral Movement', tier: ['Advanced','Enterprise'], status: 'Draft', techniques: 8, mins: 60, sig: 'Signed v1', cat: 'apt', tech: ['T1482', 'T1087', 'T1059', 'T1547', 'T1053', 'T1071', 'T1550'], tacticTag: 'Lateral Movement', actor: 'APT29', ttps: 'T1482, T1087, T1059' },
  { id: 'SC-0362', name: 'APT36 Kill Chain (Three-Tier)', desc: 'Emulates APT36 activity across three tiers to validate detection and response.', source: 'APT & Threat Actors', os: 'Windows', product: 'Endpoint / EDR', tactic: 'Privilege Escalation', tier: ['Core','Advanced'], status: 'Active', techniques: 4, mins: 35, sig: 'Signed v2', cat: 'apt', tech: ['T1068', 'T1555', 'T1041', 'T1105'], tacticTag: 'Privilege Escalation' },
  { id: 'SC-0340', name: 'Atomic Red Team — Full macOS Sweep', desc: 'Runs a comprehensive set of Atomic Red Team tests for macOS environments.', source: 'Common', os: 'macOS', product: 'Endpoint / EDR', tactic: 'Initial Access', tier: ['Core'], status: 'Active', techniques: 10, mins: 50, sig: 'Signed v4', cat: 'common', tech: ['T1566', 'T1059', 'T1543', 'T1562'], tacticTag: 'Initial Access' },
  { id: 'SC-0318', name: 'Linux Persistence & Cron Abuse', desc: 'Validates detection of cron, systemd, and init-script persistence on Linux hosts.', source: 'Common', os: 'Linux', product: 'Endpoint / EDR', tactic: 'Persistence', tier: ['Core'], status: 'Active', techniques: 6, mins: 25, sig: 'Signed v2', cat: 'common', tech: ['T1053', 'T1543', 'T1505'], tacticTag: 'Persistence' },
  { id: 'SC-0305', name: 'PCI-DSS Req. 10 Logging Validation', desc: 'Confirms privileged activity is logged and forwarded to the SIEM with required retention.', source: 'Compliance', os: 'Cross-Platform', product: 'Logging & SIEM', tactic: 'Defense Evasion', tier: ['Core'], status: 'Active', techniques: 3, mins: 20, sig: 'Signed v1', cat: 'compliance', tech: ['T1070'], tacticTag: 'Defense Evasion' },
  { id: 'SC-0291', name: 'S3 Public Exposure & IAM Escalation', desc: 'Tests cloud storage exposure and IAM role-chaining paths in AWS.', source: 'Cloud & Infrastructure', os: 'Cloud (AWS)', product: 'Cloud', tactic: 'Privilege Escalation', tier: ['Advanced'], status: 'Active', techniques: 4, mins: 30, sig: 'Signed v2', cat: 'cloud', tech: ['T1078', 'T1530'], tacticTag: 'Privilege Escalation' },
  { id: 'SC-0274', name: 'Email Gateway Credential Phish Simulation', desc: 'Safe credential-harvest simulation delivered through the email gateway path.', source: 'Data Security', os: 'Cross-Platform', product: 'Email', tactic: 'Initial Access', tier: ['Core','Advanced'], status: 'Draft', techniques: 2, mins: 40, sig: 'Unsigned', cat: 'data', tech: ['T1566.001', 'T1598'], tacticTag: 'Initial Access' },
  { id: 'SC-0260', name: 'Lateral SMB Movement Baseline', desc: 'Measures detection of SMB-based lateral movement between two segments.', source: 'Network & Perimeter', os: 'Windows', product: 'Network', tactic: 'Lateral Movement', tier: ['Core'], status: 'Active', techniques: 3, mins: 18, sig: 'Signed v3', cat: 'network', tech: ['T1021.002', 'T1570'], tacticTag: 'Lateral Movement' },
];

D.CATEGORIES = [
  ['all', 'All Scenarios', 'layers', 107], ['common', 'Common', 'target', 107], ['apt', 'APT & Threat Actors', 'user', 28],
  ['techniques', 'Attack Techniques', 'mapped', 242], ['compliance', 'Compliance', 'report', 16], ['industry', 'Industry Specific', 'box', 19],
  ['cloud', 'Cloud & Infrastructure', 'cloud', 14], ['data', 'Data Security', 'lock', 32], ['identity', 'Identity & Access', 'key', 18],
  ['network', 'Network & Perimeter', 'shield', 21], ['appsec', 'Application Security', 'grid', 27], ['others', 'Others', 'clock', 15],
];

D.K8S = [
  { id: 'K8S-011', name: 'Pod Escape via Privileged Container', cluster: 'prod-aks-east', ns: 'payments', status: 'Active', techniques: 4, mins: 25, last: 'PASS' },
  { id: 'K8S-014', name: 'Service Account Token Theft', cluster: 'prod-aks-east', ns: 'default', status: 'Active', techniques: 3, mins: 15, last: 'FAIL' },
  { id: 'K8S-019', name: 'RBAC Wildcard Escalation', cluster: 'staging-eks', ns: 'kube-system', status: 'Draft', techniques: 2, mins: 12, last: 'NEVER' },
  { id: 'K8S-022', name: 'Malicious Image Pull & Crypto-mining', cluster: 'prod-eks-west', ns: 'batch', status: 'Active', techniques: 5, mins: 40, last: 'WARN' },
];

D.SCHEDULES = [
  { id: 'SA-201', name: 'Weekly Endpoint Regression', scope: 'Windows Workstations (412 agents)', cron: '0 2 * * 1', next: 'Mon 27 Oct, 02:00', last: 'PASS 94%', state: 'Active' },
  { id: 'SA-204', name: 'Monthly Identity Posture', scope: 'Domain Controllers (6)', cron: '0 1 1 * *', next: '1 Nov, 01:00', last: 'WARN 81%', state: 'Active' },
  { id: 'SA-207', name: 'Nightly Ransomware Canary', scope: 'File Servers (18)', cron: '30 23 * * *', next: 'Tonight 23:30', last: 'PASS 100%', state: 'Active' },
  { id: 'SA-210', name: 'Quarterly PCI Logging Check', scope: 'Cardholder Data Env.', cron: '0 9 1 */3 *', next: '1 Jan, 09:00', last: 'FAIL 72%', state: 'Paused' },
];

D.INITIATIVES = [
  { id: 'INI-07', name: 'Close AD privilege-escalation gaps', owner: 'Identity Team', progress: 64, due: '15 Nov 2026', status: 'On Track', jobs: 9 },
  { id: 'INI-08', name: 'Ransomware readiness — tier 0 hosts', owner: 'SOC Lead', progress: 38, due: '30 Nov 2026', status: 'At Risk', jobs: 14 },
  { id: 'INI-09', name: 'Email gateway hardening Q4', owner: 'Messaging', progress: 82, due: '31 Oct 2026', status: 'On Track', jobs: 6 },
  { id: 'INI-10', name: 'Cloud IAM least-privilege review', owner: 'Cloud Platform', progress: 15, due: '18 Dec 2026', status: 'Planned', jobs: 4 },
];

D.CAMPAIGNS = [
  { id: 'CMP-31', name: 'Q4 Full-Estate Purple Team', scope: 'All Windows & Linux agents', runs: 6, pass: 71, status: 'Running', start: '20 Oct', phase: 'Phase 3 of 5' },
  { id: 'CMP-29', name: 'Identity Hardening Validation', scope: 'Domain Controllers, ADCS', runs: 4, pass: 88, status: 'Completed', start: '02 Oct', phase: 'Complete' },
  { id: 'CMP-33', name: 'Cloud Storage Exposure Sweep', scope: 'AWS prod accounts (3)', runs: 0, pass: 0, status: 'Scheduled', start: '28 Oct', phase: 'Not started' },
];

D.FACTORY = {
  pipelines: [
    { name: 'Scenario build — Windows', state: 'Healthy', last: '12 min ago', queue: 0, lastResult: 'Passed (107/107)' },
    { name: 'Scenario build — Linux/macOS', state: 'Healthy', last: '38 min ago', queue: 2, lastResult: 'Passed (61/61)' },
    { name: 'Signature gate (cosign)', state: 'Warning', last: '4 min ago', queue: 1, lastResult: '2 scenarios awaiting re-sign' },
    { name: 'Threat intel ingest (ATT&CK, CISA)', state: 'Healthy', last: '1 h ago', queue: 0, lastResult: '+14 techniques' },
    { name: 'Variant generator', state: 'Failing', last: '2 h ago', queue: 5, lastResult: 'Template error: missing tactic map' },
  ],
  builds: [
    { id: 'b-4211', what: 'APT29 Phase 7 — v1.3', when: 'Today 09:12', by: 'factory-bot', result: 'ok' },
    { id: 'b-4210', what: 'ACL Privilege Exposure v2', when: 'Today 08:40', by: 'factory-bot', result: 'ok' },
    { id: 'b-4206', what: 'Akira Kill Chain — draft', when: 'Yesterday 17:03', by: 'analyst.r', result: 'warn' },
    { id: 'b-4201', what: 'Variant sweep — Endpoint', when: 'Yesterday 14:22', by: 'factory-bot', result: 'err' },
  ],
};

D.AGENTS = [
  { id: 'AG-1042', host: 'WS-FIN-0142', os: 'Windows 11 23H2', group: 'Finance Workstations', status: 'Online', version: '1.9.2', lastSeen: 'now', risk: 'Medium', ip: '10.20.4.142' },
  { id: 'AG-1043', host: 'WS-FIN-0177', os: 'Windows 11 23H2', group: 'Finance Workstations', status: 'Online', version: '1.9.2', lastSeen: '2 min', risk: 'Low', ip: '10.20.4.177' },
  { id: 'AG-0871', host: 'DC-PRI-01', os: 'Windows Server 2022', group: 'Domain Controllers', status: 'Online', version: '1.9.2', lastSeen: 'now', risk: 'High', ip: '10.10.1.11' },
  { id: 'AG-0872', host: 'DC-SEC-02', os: 'Windows Server 2019', group: 'Domain Controllers', status: 'Online', version: '1.9.1', lastSeen: '5 min', risk: 'High', ip: '10.10.1.12' },
  { id: 'AG-1210', host: 'FS-SHARE-03', os: 'Windows Server 2019', group: 'File Servers', status: 'Degraded', version: '1.9.2', lastSeen: '1 min', risk: 'Medium', ip: '10.10.6.23' },
  { id: 'AG-1301', host: 'lnx-web-07', os: 'Ubuntu 22.04', group: 'Linux Web Tier', status: 'Online', version: '1.9.2', lastSeen: 'now', risk: 'Low', ip: '10.30.2.7' },
  { id: 'AG-1302', host: 'lnx-web-08', os: 'Ubuntu 22.04', group: 'Linux Web Tier', status: 'Offline', version: '1.9.0', lastSeen: '3 h', risk: 'Medium', ip: '10.30.2.8' },
  { id: 'AG-1410', host: 'MAC-DES-221', os: 'macOS 14.6', group: 'Executive Laptops', status: 'Online', version: '1.9.2', lastSeen: '12 min', risk: 'Low', ip: '10.20.9.221' },
  { id: 'AG-1411', host: 'MAC-DES-238', os: 'macOS 14.6', group: 'Executive Laptops', status: 'Pending', version: '—', lastSeen: 'never', risk: '—', ip: '10.20.9.238' },
  { id: 'AG-1520', host: 'SQL-PAY-02', os: 'Windows Server 2022', group: 'Payments DB', status: 'Online', version: '1.9.2', lastSeen: 'now', risk: 'High', ip: '10.40.1.52' },
];
D.AGENT_GROUPS = [['All agents', 10], ['Finance Workstations', 2], ['Domain Controllers', 2], ['File Servers', 1], ['Linux Web Tier', 2], ['Executive Laptops', 2], ['Payments DB', 1]];

D.RUNS = [
  { id: 'RUN-5521', name: 'APT29 Kill Chain — Cozy Bear (Phase 7)', target: 'Finance Workstations (2)', status: 'Running', progress: 62, step: 'T1087 — Account Discovery', started: '14:02', dur: '18m 40s' },
  { id: 'RUN-5520', name: 'ACL Privilege Exposure Audit', target: 'DC-PRI-01', status: 'Running', progress: 35, step: 'Enumerating ACEs on AdminSDHolder', started: '14:20', dur: '4m 12s' },
  { id: 'RUN-5519', name: 'Akira Kill Chain — Ransomware Emulation', target: 'FS-SHARE-03', status: 'Queued', progress: 0, step: 'Waiting for agent slot', started: '—', dur: '—' },
  { id: 'RUN-5518', name: 'S3 Public Exposure & IAM Escalation', target: 'AWS prod (3 accounts)', status: 'Passed', progress: 100, step: 'Completed', started: '11:04', dur: '26m 02s' },
  { id: 'RUN-5517', name: 'Linux Persistence & Cron Abuse', target: 'Linux Web Tier (2)', status: 'Failed', progress: 100, step: 'Agent lnx-web-08 went offline', started: '10:30', dur: '7m 51s' },
  { id: 'RUN-5516', name: 'Application Control Efficacy', target: 'WS-FIN-0142', status: 'Passed', progress: 100, step: 'Completed', started: '09:55', dur: '29m 18s' },
];

D.STEPS_APT29 = [
  ['T1566 — Spearphish attachment (simulated)', 'done', 'Macro-less document opened · detected by EDR at 00:42'],
  ['T1059.001 — PowerShell execution', 'done', 'Encoded command blocked → alert raised'],
  ['T1547.001 — Registry Run key persistence', 'done', 'Persistence key written · not detected'],
  ['T1087 — Account discovery', 'run', 'Enumerating domain users via LDAP'],
  ['T1482 — Domain trust discovery', 'wait', 'Pending'],
  ['T1071.001 — Web protocol C2 (telemetry-safe)', 'wait', 'Pending'],
  ['T1053.005 — Scheduled task persistence', 'wait', 'Pending'],
  ['Cleanup & evidence collection', 'wait', 'Pending'],
];

D.FINDINGS = [
  { id: 'F-2231', title: 'Persistence via Run key not detected', sev: 'high', asset: 'WS-FIN-0142', tech: 'T1547.001', scenario: 'APT29 Kill Chain (Phase 7)', status: 'Open', age: '2 h', owner: 'SOC Tier 2' },
  { id: 'F-2230', title: 'Excessive GenericAll on AdminSDHolder', sev: 'critical', asset: 'DC-PRI-01', tech: 'T1222', scenario: 'ACL Privilege Exposure Audit', status: 'In progress', age: '1 d', owner: 'Identity Team' },
  { id: 'F-2228', title: 'ADCS template ESC1 — enrollee supplies SAN', sev: 'critical', asset: 'CA-ISS-01', tech: 'T1649', scenario: 'ADCS ESC Template Exposure Audit', status: 'Open', age: '3 d', owner: 'Identity Team' },
  { id: 'F-2226', title: 'Cron job executes from /tmp', sev: 'medium', asset: 'lnx-web-07', tech: 'T1053.003', scenario: 'Linux Persistence & Cron Abuse', status: 'Open', age: '5 d', owner: 'Linux Ops' },
  { id: 'F-2221', title: 'Office child process not blocked by ASR rule', sev: 'high', asset: 'MAC-DES-221', tech: 'T1059', scenario: 'Atomic Red Team — macOS', status: 'Verified', age: '8 d', owner: 'Endpoint' },
  { id: 'F-2219', title: 'SMB lateral movement alerted with 14 min delay', sev: 'medium', asset: 'FS-SHARE-03', tech: 'T1021.002', scenario: 'Lateral SMB Movement Baseline', status: 'Open', age: '9 d', owner: 'SOC Tier 1' },
  { id: 'F-2217', title: 'Application control allows unsigned DLL load', sev: 'high', asset: 'WS-FIN-0177', tech: 'T1218', scenario: 'Application Control Efficacy', status: 'Accepted risk', age: '12 d', owner: 'Endpoint' },
  { id: 'F-2212', title: 'Log forwarding gap on payment DB', sev: 'low', asset: 'SQL-PAY-02', tech: 'T1070', scenario: 'PCI-DSS Req. 10 Logging', status: 'Closed', age: '21 d', owner: 'Logging' },
];

D.IOCS = [
  { value: '185.220.101.44', type: 'IPv4', source: 'OTX · APT29 feed', conf: 91, action: 'Block', seen: '3 h' },
  { value: 'update-cdn-sync[.]net', type: 'Domain', source: 'CISA AA21-148A', conf: 88, action: 'Block', seen: '1 d' },
  { value: 'a3f9c1…e07b2d', type: 'SHA-256', source: 'Internal run RUN-5516', conf: 76, action: 'Alert', seen: '2 d' },
  { value: 'HKCU\\Software\\Microsoft\\Windows\\Run\\svcupd', type: 'Registry', source: 'Scenario SC-0355', conf: 99, action: 'Alert', seen: '5 h' },
  { value: 'nobelium-tools.onion.example', type: 'Domain', source: 'MISP community', conf: 64, action: 'Monitor', seen: '9 d' },
  { value: '45.155.205.233', type: 'IPv4', source: 'AlienVault OTX', conf: 82, action: 'Block', seen: '6 d' },
  { value: 'invoice_q4.iso', type: 'Filename', source: 'Phish sim SC-0274', conf: 95, action: 'Block', seen: '1 h' },
];

D.REMED = {
  cols: [['Open', 'red', 'open'], ['In progress', 'amber', 'prog'], ['Awaiting verification', 'cyan', 'verify'], ['Closed', 'green', 'closed']],
  cards: [
    { id: 'R-310', title: 'Remove GenericAll from Helpdesk on AdminSDHolder', asset: 'DC-PRI-01', owner: 'Identity Team', col: 'prog', sev: 'critical', due: '26 Oct' },
    { id: 'R-307', title: 'Disable ESC1 on UserAuth template', asset: 'CA-ISS-01', owner: 'Identity Team', col: 'open', sev: 'critical', due: '28 Oct' },
    { id: 'R-304', title: 'Add Run-key monitoring rule for HKCU Run', asset: 'WS-FIN-0142', owner: 'SOC Tier 2', col: 'open', sev: 'high', due: '30 Oct' },
    { id: 'R-299', title: 'Enable ASR: block Office child processes', asset: 'Fleet (Mac)', owner: 'Endpoint', col: 'verify', sev: 'high', due: '22 Oct' },
    { id: 'R-291', title: 'Fix log forwarding for payments DB', asset: 'SQL-PAY-02', owner: 'Logging', col: 'closed', sev: 'low', due: '15 Oct' },
    { id: 'R-288', title: 'Tighten SMB signing on file tier', asset: 'FS-SHARE-03', owner: 'Infra', col: 'prog', sev: 'medium', due: '03 Nov' },
    { id: 'R-285', title: 'Restrict cron writes to root in /etc/cron.d', asset: 'lnx-web-07', owner: 'Linux Ops', col: 'open', sev: 'medium', due: '05 Nov' },
    { id: 'R-280', title: 'Rotate service accounts with stale SPNs', asset: 'AD (forest-wide)', owner: 'Identity Team', col: 'verify', sev: 'medium', due: '24 Oct' },
  ],
};

D.REPORTS = [
  { id: 'RPT-0198', name: 'Executive Security Posture — October', type: 'Executive', period: 'Oct 2026', created: '22 Oct 2026', by: 'admin', fmt: 'PDF' },
  { id: 'RPT-0196', name: 'AV / NGAV Assessment — Finance Estate', type: 'Assessment', period: '16–20 Oct 2026', created: '20 Oct 2026', by: 'analyst.r', fmt: 'PDF' },
  { id: 'RPT-0191', name: 'Detection Validation Matrix', type: 'Technical', period: 'Sep 2026', created: '30 Sep 2026', by: 'admin', fmt: 'HTML' },
  { id: 'RPT-0187', name: 'PCI-DSS Compliance Evidence', type: 'Compliance', period: 'Q3 2026', created: '02 Oct 2026', by: 'compliance', fmt: 'PDF' },
  { id: 'RPT-0184', name: 'Campaign CMP-29 Summary', type: 'Campaign', period: 'Oct 2026', created: '14 Oct 2026', by: 'admin', fmt: 'DOCX' },
];

D.VERIFY = [
  { id: 'V-901', detection: 'EDR · Run-key persistence rule', scenario: 'APT29 Phase 7', result: 'Missed', expected: 'Alert', seen: 'No alert', checked: '24 Oct 09:14' },
  { id: 'V-898', detection: 'EDR · PowerShell encoded command', scenario: 'APT29 Phase 7', result: 'Detected', expected: 'Alert', seen: 'Alert in 4 s', checked: '24 Oct 09:14' },
  { id: 'V-895', detection: 'SIEM · Kerberoasting (4769)', scenario: 'ACL Privilege Exposure', result: 'Detected', expected: 'Alert', seen: 'Alert in 31 s', checked: '23 Oct 16:40' },
  { id: 'V-893', detection: 'SIEM · ADCS certificate request anomaly', scenario: 'ADCS ESC Audit', result: 'Partial', expected: 'Alert', seen: 'Logged, no alert', checked: '23 Oct 16:40' },
  { id: 'V-890', detection: 'EDR · Office macro child process', scenario: 'Atomic macOS Sweep', result: 'Detected', expected: 'Block', seen: 'Blocked', checked: '22 Oct 11:02' },
  { id: 'V-887', detection: 'Email · Credential harvest link', scenario: 'Email Credential Phish', result: 'Detected', expected: 'Alert', seen: 'Quarantined', checked: '21 Oct 08:30' },
  { id: 'V-884', detection: 'DLP · Archive exfil to USB', scenario: 'Data exfil baseline', result: 'Missed', expected: 'Block', seen: 'Allowed', checked: '20 Oct 15:12' },
];

D.ATTACK_PATHS = [
  { id: 'AP-14', name: 'Helpdesk → Domain Admin', steps: 4, risk: 'Critical', validated: true, hops: ['Phish user (HD-07)', 'Local admin WS-HD-07', 'Token on FS-SHARE-03', 'Domain Admin (DC-PRI-01)'] },
  { id: 'AP-11', name: 'Web tier → Payments DB', steps: 3, risk: 'High', validated: true, hops: ['SSRF on web app', 'Service account on lnx-web-07', 'SQL-PAY-02 xp_cmdshell'] },
  { id: 'AP-09', name: 'Cloud role chain → S3 PII bucket', steps: 3, risk: 'High', validated: false, hops: ['Stolen dev key', 'AssumeRole ci-deployer', 'S3 customer-exports'] },
];

D.EXPOSURE = [
  { asset: 'vpn-gw-01.acme-bank.demo', type: 'Internet-facing', ports: '443, 10443', vulns: 3, crit: 0, owner: 'Network', tag: 'VPN' },
  { asset: 'webportal-prod-eu', type: 'Internet-facing', ports: '80, 443', vulns: 5, crit: 1, owner: 'Digital', tag: 'Web' },
  { asset: 'mail-gw-02', type: 'Internet-facing', ports: '25, 587', vulns: 2, crit: 0, owner: 'Messaging', tag: 'Email' },
  { asset: 'CA-ISS-01', type: 'Internal (tier 0)', ports: '135, 443', vulns: 4, crit: 2, owner: 'Identity', tag: 'PKI' },
  { asset: 'SQL-PAY-02', type: 'Internal (cardholder)', ports: '1433', vulns: 1, crit: 0, owner: 'Payments', tag: 'DB' },
  { asset: 'aws-s3-customer-exports', type: 'Cloud storage', ports: '—', vulns: 1, crit: 1, owner: 'Cloud', tag: 'S3' },
];

D.RECS = [
  { title: 'Enable Credential Guard on all Tier 0 hosts', impact: 'Blocks LSASS credential theft used in 4 scenarios', effort: 'Medium', priority: 'P1', from: 'AD Coverage' },
  { title: 'Retire ADCS template UserAuth (ESC1)', impact: 'Closes a validated attack path (AP-14)', effort: 'Low', priority: 'P1', from: 'Attack Paths' },
  { title: 'Add HKCU Run-key monitoring to EDR policy', impact: 'Missed in APT29 Phase 7 validation', effort: 'Low', priority: 'P1', from: 'Verification' },
  { title: 'Enforce SMB signing on file tier', impact: 'Reduces SMB relay exposure on FS-SHARE-03', effort: 'Medium', priority: 'P2', from: 'Findings' },
  { title: 'Rotate service accounts with stale SPNs', impact: 'Lowers Kerberoasting surface (14 accounts)', effort: 'Medium', priority: 'P2', from: 'AD Coverage' },
  { title: 'Restrict DLP archive exfil to removable media', impact: 'Verification V-884 missed', effort: 'High', priority: 'P3', from: 'Verification' },
];

D.EXERCISES = [
  { name: 'Tabletop — Ransomware on file tier', date: '04 Nov 2026', participants: 12, status: 'Scheduled', outcome: '—' },
  { name: 'Live fire — Identity attack chain', date: '18 Sep 2026', participants: 8, status: 'Completed', outcome: 'Detected 5/8' },
  { name: 'Purple team — Email & web', date: '02 Oct 2026', participants: 6, status: 'Completed', outcome: 'Detected 9/12' },
  { name: 'Blue team drill — Cloud IAM', date: '—', participants: 4, status: 'Draft', outcome: '—' },
];

D.THREATS = [
  { name: 'APT29 (Cozy Bear)', score: 94, why: 'Active in finance sector; 8 techniques overlap your gaps', mapped: 22, gaps: 5 },
  { name: 'Akira ransomware', score: 89, why: 'Targets file servers & VPN; exposure present', mapped: 11, gaps: 4 },
  { name: 'APT36 (Transparent Tribe)', score: 61, why: 'Targets Indian-linked orgs; limited relevance', mapped: 9, gaps: 2 },
  { name: 'Scattered Spider', score: 83, why: 'Help-desk social engineering; matches AP-14', mapped: 14, gaps: 6 },
];

D.TECH_ROWS = [
  { id: 'T1566.001', name: 'Spearphishing Attachment', tac: 'Initial Access', cov: 92, tests: 6, last: 'PASS' },
  { id: 'T1059.001', name: 'PowerShell', tac: 'Execution', cov: 78, tests: 9, last: 'PASS' },
  { id: 'T1547.001', name: 'Registry Run Keys', tac: 'Persistence', cov: 41, tests: 3, last: 'FAIL' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tac: 'Privilege Esc.', cov: 56, tests: 4, last: 'WARN' },
  { id: 'T1562.001', name: 'Disable or Modify Tools', tac: 'Defense Evasion', cov: 63, tests: 5, last: 'PASS' },
  { id: 'T1558.003', name: 'Kerberoasting', tac: 'Credential Access', cov: 88, tests: 4, last: 'PASS' },
  { id: 'T1087', name: 'Account Discovery', tac: 'Discovery', cov: 74, tests: 5, last: 'PASS' },
  { id: 'T1021.002', name: 'SMB / Windows Admin Shares', tac: 'Lateral Movement', cov: 49, tests: 3, last: 'WARN' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tac: 'Impact', cov: 35, tests: 2, last: 'FAIL' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tac: 'Exfiltration', cov: 52, tests: 3, last: 'WARN' },
];

D.VARIANTS = [
  { id: 'VAR-01', name: 'Scheduled task persistence — 14 variants', family: 'T1053.005', count: 14, pass: 11, status: 'Ready' },
  { id: 'VAR-02', name: 'PowerShell download cradles — 22 variants', family: 'T1059.001', count: 22, pass: 22, status: 'Ready' },
  { id: 'VAR-03', name: 'LSASS access — 9 variants', family: 'T1003.001', count: 9, pass: 6, status: 'Partial' },
  { id: 'VAR-04', name: 'WMI event subscription — 6 variants', family: 'T1546.003', count: 6, pass: 0, status: 'Failing' },
];

D.AD = [
  { check: 'Kerberoastable service accounts', result: 'Found 14', sev: 'high', mapped: 'T1558.003', status: 'Open' },
  { check: 'AS-REP roastable users', result: 'Found 0', sev: 'info', mapped: 'T1558.004', status: 'Pass' },
  { check: 'Unconstrained delegation hosts', result: 'Found 2', sev: 'critical', mapped: 'T1558', status: 'Open' },
  { check: 'AdminSDHolder ACL drift', result: 'Found 1', sev: 'critical', mapped: 'T1222', status: 'In progress' },
  { check: 'LAPS deployment coverage', result: '93% of hosts', sev: 'low', mapped: 'T1078.002', status: 'Pass' },
  { check: 'ADCS vulnerable templates', result: 'Found 2 (ESC1, ESC6)', sev: 'critical', mapped: 'T1649', status: 'Open' },
  { check: 'Tier-0 logon restriction', result: 'Partial', sev: 'medium', mapped: 'T1078', status: 'Open' },
];

D.EMAIL = {
  templates: [
    { name: 'Invoice overdue — credential harvest', vector: 'Link', used: 14, click: '18%', status: 'Active' },
    { name: 'Payroll update — attachment', vector: 'Attachment', used: 9, click: '11%', status: 'Active' },
    { name: 'MFA re-enrol request (QR)', vector: 'Link', used: 4, click: '27%', status: 'Draft' },
  ],
  recent: [
    { campaign: 'Q4 finance awareness', sent: 420, opened: 201, clicked: 53, reported: 96 },
    { campaign: 'Vendor invoice drill', sent: 180, opened: 88, clicked: 19, reported: 41 },
  ],
};

D.INTEGRATIONS = [
  { name: 'Microsoft Defender for Endpoint', kind: 'EDR', state: 'Connected', last: '2 min ago', detail: 'Tenant acme-bank · 412 devices' },
  { name: 'CrowdStrike Falcon', kind: 'EDR', state: 'Connected', last: '6 min ago', detail: 'CID ···4f1a · 88 devices' },
  { name: 'Splunk Enterprise', kind: 'SIEM', state: 'Connected', last: '1 min ago', detail: 'HEC https://splunk.internal:8088' },
  { name: 'Microsoft Purview DLP', kind: 'DLP', state: 'Warning', last: '3 h ago', detail: 'Token expires in 4 days' },
  { name: 'Proofpoint Email Gateway', kind: 'Email', state: 'Connected', last: '10 min ago', detail: 'Gateway cluster eu-1' },
  { name: 'AWS Security Hub', kind: 'Cloud', state: 'Connected', last: '1 h ago', detail: '3 accounts · us-east-1' },
  { name: 'AlienVault OTX', kind: 'Threat intel', state: 'Connected', last: '40 min ago', detail: 'Pulse subscription · 18 feeds' },
  { name: 'Palo Alto Cortex XSOAR', kind: 'SOAR', state: 'Not connected', last: '—', detail: 'Available — not configured' },
];
D.TAXII = [
  { name: 'MITRE ATT&CK TAXII', url: 'https://cti-taxii.mitre.org/taxii/', status: 'Active', last: '1 h ago' },
  { name: 'CISA AIS', url: 'https://taxii.cisa.gov/taxii2/', status: 'Active', last: '2 h ago' },
  { name: 'Internal MISP', url: 'https://misp.internal/taxii2/', status: 'Error', last: '3 d ago' },
];
D.EPP = [
  { name: 'Defender — Isolate host', action: 'Isolate', target: 'Agents: 2 selected', status: 'Enabled' },
  { name: 'CrowdStrike — Contain device', action: 'Contain', target: 'Agents: 0 selected', status: 'Enabled' },
  { name: 'Kill process (remote)', action: 'Kill', target: 'Approval required', status: 'Disabled' },
];

D.USERS = [
  { name: 'Admin', email: 'admin@acme-bank.demo', role: 'Admin', last: 'now', mfa: true },
  { name: 'Analyst R.', email: 'analyst.r@acme-bank.demo', role: 'Analyst', last: '12 min', mfa: true },
  { name: 'SOC Lead', email: 'soc.lead@acme-bank.demo', role: 'Analyst', last: '1 h', mfa: true },
  { name: 'Auditor', email: 'auditor@acme-bank.demo', role: 'Viewer', last: '2 d', mfa: false },
  { name: 'Compliance', email: 'compliance@acme-bank.demo', role: 'Viewer', last: '5 d', mfa: true },
];
D.AUDIT = [
  ['24 Oct 14:02:11', 'admin', 'run.start', 'RUN-5521 APT29 Phase 7 on Finance Workstations', 'ok'],
  ['24 Oct 13:48:50', 'analyst.r', 'scenario.sign', 'SC-0377 re-signed (v1.1)', 'ok'],
  ['24 Oct 12:10:03', 'system', 'agent.offline', 'AG-1302 lnx-web-08 heartbeat missed', 'warn'],
  ['24 Oct 11:31:27', 'admin', 'settings.update', 'Dashboard default view → Operational', 'ok'],
  ['24 Oct 09:14:45', 'system', 'verify.run', 'Verification batch 24-10 (7 checks, 2 missed)', 'warn'],
  ['23 Oct 17:55:08', 'soc.lead', 'finding.accept', 'F-2217 accepted risk until 30 Nov', 'ok'],
  ['23 Oct 16:02:19', 'admin', 'login.failed', 'auditor@acme-bank.demo — bad password (1/5)', 'err'],
  ['23 Oct 10:20:36', 'system', 'backup.run', 'Nightly backup completed (2.4 GB)', 'ok'],
];

D.NOTIFS = [
  ['alert', 'red', 'Run RUN-5517 failed', 'Agent lnx-web-08 went offline mid-run · 10:30'],
  ['check', 'green', 'Campaign CMP-29 completed', 'Identity Hardening Validation · 88% pass'],
  ['shield', 'amber', 'Signature gate: 2 scenarios unsigned', 'Re-sign required before next run'],
  ['report', 'blue', 'Report ready: Executive Posture', 'October 2026 · PDF'],
];

D.SCN_DETAIL = {
  'SC-0355': {
    overview: 'Five-stage, telemetry-safe emulation of APT29 (Cozy Bear / NOBELIUM) post-compromise tradecraft on Windows. Designed to validate EDR detection depth across initial foothold, discovery, persistence and C2 without causing business impact.',
    prereq: ['Windows 10/11 or Server 2019+ agent (elevated)', 'Network path to a test DC for LDAP discovery', 'EDR telemetry for PowerShell and registry'],
    steps: 8,
  },
};
