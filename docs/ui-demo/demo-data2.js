// Extended sample data for the deeper page modules (loaded after demo-data.js). Deterministic; fictional.
const pk = (arr, i) => arr[i % arr.length];

// ---- Live runs: add history so the list, filters and paging have substance
D.RUNS_HIST = Array.from({ length: 10 }, (_, i) => {
  const sc = D.SCENARIOS[(i * 3 + 1) % D.SCENARIOS.length];
  const status = ['Passed', 'Passed', 'Failed', 'Passed', 'Passed', 'Passed', 'Failed', 'Passed', 'Passed', 'Passed'][i];
  const day = ['Yesterday', 'Yesterday', 'Yesterday', '23 Oct', '23 Oct', '22 Oct', '22 Oct', '21 Oct', '21 Oct', '20 Oct'][i];
  return { id: 'RUN-' + (5515 - i), name: sc.name, target: pk(['FS-SHARE-03', 'Finance Workstations (2)', 'Domain Controllers (2)', 'Linux Web Tier (2)', 'SQL-PAY-02', 'AWS prod (3 accounts)'], i * 2 + 1), status, progress: 100, step: status === 'Failed' ? 'Detection missed on step ' + (3 + (i % 3)) : 'Completed', started: `${day} ${String(8 + ((i * 7) % 11)).padStart(2, '0')}:${String((i * 17) % 60).padStart(2, '0')}`, dur: `${8 + ((i * 5) % 31)}m ${String((i * 13) % 60).padStart(2, '0')}s`, _sc: sc.id };
});
D.RUNS.push(...D.RUNS_HIST);

// ---- Kubernetes
D.CLUSTERS = [
  { id: 'prod-aks-east', provider: 'Azure AKS', version: '1.29.4', nodes: 3, pods: 148, posture: 78, status: 'Healthy', runs: 14 },
  { id: 'prod-eks-west', provider: 'AWS EKS', version: '1.30.1', nodes: 5, pods: 212, posture: 71, status: 'Healthy', runs: 9 },
  { id: 'staging-eks', provider: 'AWS EKS', version: '1.28.9', nodes: 3, pods: 64, posture: 58, status: 'Degraded', runs: 6 },
  { id: 'lab-kind', provider: 'kind (local)', version: '1.29.0', nodes: 1, pods: 22, posture: 44, status: 'Healthy', runs: 21 },
];
D.K8S.push(
  { id: 'K8S-025', name: 'Exposed Kubelet API Probe', cluster: 'prod-eks-west', ns: 'kube-system', status: 'Active', techniques: 3, mins: 10, last: 'PASS' },
  { id: 'K8S-027', name: 'Secrets Read via Over-permissive Role', cluster: 'prod-aks-east', ns: 'payments', status: 'Active', techniques: 4, mins: 18, last: 'FAIL' },
  { id: 'K8S-030', name: 'HostPath Mount Escape', cluster: 'staging-eks', ns: 'default', status: 'Draft', techniques: 3, mins: 14, last: 'NEVER' },
  { id: 'K8S-033', name: 'Admission Controller Bypass', cluster: 'lab-kind', ns: 'default', status: 'Active', techniques: 2, mins: 9, last: 'WARN' });
D.K8S_STEPS = ['Enumerate service accounts and bound roles', 'Attempt privileged pod creation in target namespace', 'Mount host filesystem / read node credentials', 'Query API server with stolen token', 'Verify audit-log and runtime alerts fired', 'Clean up created objects'];

// ---- Scheduled assessments: extra rows + week strip
D.SCHEDULES.push(
  { id: 'SA-212', name: 'Weekly Cloud Posture', scope: 'AWS prod (3 accounts)', cron: '0 3 * * 3', next: 'Wed 29 Oct, 03:00', last: 'WARN 79%', state: 'Active' },
  { id: 'SA-215', name: 'Email Gateway Regression', scope: 'Mail gateways (2)', cron: '15 6 * * 1-5', next: 'Mon 27 Oct, 06:15', last: 'PASS 96%', state: 'Active' });
D.WEEK = [['Sat 25', [['23:30', 'Ransomware Canary']]], ['Sun 26', [['23:30', 'Ransomware Canary']]], ['Mon 27', [['02:00', 'Endpoint Regression'], ['06:15', 'Email Gateway'], ['23:30', 'Ransomware Canary']]], ['Tue 28', [['06:15', 'Email Gateway'], ['23:30', 'Ransomware Canary']]], ['Wed 29', [['03:00', 'Cloud Posture'], ['06:15', 'Email Gateway'], ['23:30', 'Ransomware Canary']]], ['Thu 30', [['06:15', 'Email Gateway'], ['23:30', 'Ransomware Canary']]], ['Fri 31', [['06:15', 'Email Gateway'], ['23:30', 'Ransomware Canary']]]];

// ---- Initiatives / campaigns
D.INITIATIVES.forEach((x, i) => { x.desc = ['Remove excessive ACLs and retire vulnerable ADCS templates across the forest.', 'Validate ransomware detection and containment on tier-0 and file-tier hosts.', 'Raise email gateway detection of credential phishing and QR lures above 95%.', 'Review and reduce standing IAM privilege in AWS production accounts.'][i]; x.ms = [[['Scope agreed', 100], ['Baseline validation', 100], ['Fix ACLs', 70], ['Retire ESC1 template', 40], ['Re-validate', 0]], [['Scope agreed', 100], ['Baseline validation', 100], ['Containment playbook tuned', 35], ['Re-validate', 0]], [['Baseline', 100], ['Rule tuning', 100], ['QR-code lure coverage', 75], ['Re-validate', 40]], [['Inventory roles', 60], ['Remove stale keys', 10], ['Re-validate', 0]]][i]; });
D.CAMPAIGNS.forEach((c, i) => { c.phases = [[['Recon validation', 94], ['Identity chain', 88], ['Endpoint & persistence', 61], ['Lateral movement', null], ['Exfiltration', null]], [['Recon validation', 96], ['Kerberos attacks', 91], ['ADCS abuse', 83], ['Reporting', 100]], [['Inventory', null], ['Exposure checks', null], ['IAM chain', null]]][i]; });

// ---- Factory
D.FACTORY.builds.push(
  { id: 'b-4198', what: 'Threat intel ingest — CISA KEV', when: '22 Oct 10:05', by: 'factory-bot', result: 'ok' },
  { id: 'b-4195', what: 'ADCS ESC Template Audit v1', when: '21 Oct 16:22', by: 'analyst.r', result: 'ok' },
  { id: 'b-4190', what: 'Variant generator — WMI set', when: '21 Oct 09:48', by: 'factory-bot', result: 'err' },
  { id: 'b-4188', what: 'Linux persistence pack v2', when: '20 Oct 14:30', by: 'factory-bot', result: 'ok' },
  { id: 'b-4183', what: 'Signature gate sweep', when: '20 Oct 08:00', by: 'system', result: 'warn' },
  { id: 'b-4179', what: 'Cloud S3 exposure v2', when: '19 Oct 17:12', by: 'analyst.r', result: 'ok' });
D.UNSIGNED = [['SC-0377', 'Akira Kill Chain — Ransomware Emulation', 'Draft · edited 2 h ago'], ['SC-0274', 'Email Gateway Credential Phish Simulation', 'Draft · edited yesterday']];

// ---- Technique coverage (28 rows)
D.TECH_ROWS.push(...[
  ['T1190', 'Exploit Public-Facing Application', 'Initial Access', 67, 4, 'PASS'], ['T1078', 'Valid Accounts', 'Initial Access', 58, 5, 'WARN'], ['T1204.002', 'Malicious File', 'Execution', 81, 6, 'PASS'],
  ['T1053.005', 'Scheduled Task', 'Persistence', 72, 8, 'PASS'], ['T1543.003', 'Windows Service', 'Persistence', 53, 4, 'WARN'], ['T1055', 'Process Injection', 'Defense Evasion', 47, 5, 'FAIL'],
  ['T1003.001', 'LSASS Memory', 'Credential Access', 76, 7, 'PASS'], ['T1110', 'Brute Force', 'Credential Access', 84, 4, 'PASS'], ['T1018', 'Remote System Discovery', 'Discovery', 69, 3, 'PASS'],
  ['T1482', 'Domain Trust Discovery', 'Discovery', 39, 2, 'FAIL'], ['T1550.002', 'Pass the Hash', 'Lateral Movement', 55, 3, 'WARN'], ['T1570', 'Lateral Tool Transfer', 'Lateral Movement', 62, 3, 'PASS'],
  ['T1560', 'Archive Collected Data', 'Collection', 44, 2, 'WARN'], ['T1071.001', 'Web Protocols (C2)', 'Command & Control', 71, 6, 'PASS'], ['T1105', 'Ingress Tool Transfer', 'Command & Control', 79, 5, 'PASS'],
  ['T1567', 'Exfil to Web Service', 'Exfiltration', 33, 3, 'FAIL'], ['T1490', 'Inhibit System Recovery', 'Impact', 46, 3, 'WARN'], ['T1489', 'Service Stop', 'Impact', 58, 2, 'PASS']
].map(([id, name, tac, cov, tests, last]) => ({ id, name, tac, cov, tests, last })));

// ---- IOCs (24)
D.IOCS.push(...[
  ['203.0.113.77', 'IPv4', 'OTX · Akira feed', 84, 'Block', '2 d'], ['mail-secure-login[.]com', 'Domain', 'Phish sim SC-0274', 97, 'Block', '1 h'], ['b71d0a…44c9e1', 'SHA-256', 'MISP community', 71, 'Alert', '4 d'],
  ['http://185.220.101.44/dl/update.ps1', 'URL', 'CISA AA21-148A', 90, 'Block', '3 h'], ['svc_update.exe', 'Filename', 'Internal run RUN-5521', 93, 'Alert', '5 h'], ['198.51.100.23', 'IPv4', 'AlienVault OTX', 62, 'Monitor', '11 d'],
  ['cdn-sync-update[.]org', 'Domain', 'CISA KEV ingest', 80, 'Block', '2 d'], ['HKLM\\SYSTEM\\CurrentControlSet\\Services\\wsvc', 'Registry', 'Scenario SC-0355', 98, 'Alert', '5 h'],
  ['it-helpdesk@acme-bank-support[.]net', 'Email', 'Phish sim SC-0274', 96, 'Block', '1 h'], ['44f2c8…19ab07', 'SHA-256', 'Internal run RUN-5516', 74, 'Alert', '2 d'], ['192.0.2.150', 'IPv4', 'OTX · APT29 feed', 87, 'Block', '6 d'],
  ['payroll_update.xlsm', 'Filename', 'Phish sim SC-0274', 91, 'Block', '1 d'], ['login-acme-bank[.]top', 'Domain', 'MISP community', 69, 'Monitor', '9 d'], ['10.20.4.250', 'IPv4', 'Internal sinkhole', 58, 'Monitor', '12 d'],
  ['http://update-cdn-sync[.]net/gate.php', 'URL', 'CISA AA21-148A', 89, 'Block', '1 d'], ['e91a77…c20d45', 'SHA-256', 'AV validation run', 77, 'Alert', '3 d'], ['HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command', 'Registry', 'Scenario SC-0391', 95, 'Alert', '2 d']
].map(([value, type, source, conf, action, seen]) => ({ value, type, source, conf, action, seen })));
D.IOCS.forEach((x, i) => { x.first = ['3 Oct', '9 Oct', '14 Oct', '18 Oct', '20 Oct', '22 Oct'][i % 6]; x.sightings = 1 + ((i * 7) % 19); x.tags = [pk(['apt29', 'akira', 'phishing', 'c2', 'persistence', 'ransomware'], i), pk(['finance', 'identity', 'endpoint', 'email'], i + 1)]; });

// ---- Exposure (14)
D.EXPOSURE.push(...[
  ['api-gw-prod-02', 'Internet-facing', '443', 2, 0, 'Digital', 'API'], ['sftp-partner-01', 'Internet-facing', '22', 1, 0, 'Network', 'SFTP'], ['jump-host-eu', 'Internet-facing', '3389', 3, 1, 'Infra', 'RDP'],
  ['DC-PRI-01', 'Internal (tier 0)', '88, 389, 445', 3, 1, 'Identity', 'AD'], ['FS-SHARE-03', 'Internal', '445', 2, 0, 'Infra', 'SMB'], ['k8s-ingress-east', 'Cloud', '80, 443', 2, 0, 'Platform', 'K8s'],
  ['aws-iam-role-ci', 'Cloud', '—', 2, 1, 'Cloud', 'IAM'], ['hr-portal-int', 'Internal', '443', 1, 0, 'HR IT', 'Web']
].map(([asset, type, ports, vulns, crit, owner, tag]) => ({ asset, type, ports, vulns, crit, owner, tag })));
D.CVES = [['CVE-2024-3400', 'PAN-OS GlobalProtect command injection', 10.0, 'critical'], ['CVE-2023-4966', 'Citrix NetScaler session leak', 9.4, 'critical'], ['CVE-2024-21762', 'FortiOS out-of-bounds write', 9.6, 'critical'], ['CVE-2023-34362', 'MOVEit Transfer SQL injection', 9.8, 'critical'], ['CVE-2023-23397', 'Outlook NTLM leak', 9.1, 'high'], ['CVE-2022-26134', 'Confluence OGNL injection', 8.8, 'high'], ['CVE-2021-34527', 'PrintNightmare', 8.8, 'high'], ['CVE-2020-1472', 'Zerologon', 8.1, 'high'], ['CVE-2024-0012', 'Weak TLS configuration', 5.9, 'medium'], ['CVE-2023-48795', 'SSH Terrapin', 5.9, 'medium']];

// ---- Verification (16)
D.VERIFY.push(...[
  ['EDR · LSASS access via comsvcs', 'AV / NGAV sweep', 'Detected', 'Alert', 'Alert in 6 s'], ['SIEM · Pass-the-hash (4624 type 9)', 'Lateral SMB Baseline', 'Partial', 'Alert', 'Logged, no alert'], ['EDR · Scheduled task creation', 'Linux Persistence', 'Detected', 'Alert', 'Alert in 3 s'],
  ['Email · Malicious attachment (ISO)', 'Email Credential Phish', 'Detected', 'Block', 'Quarantined'], ['DLP · Cloud upload of PII', 'Data exfil baseline', 'Missed', 'Block', 'Allowed'], ['SIEM · Kerberoasting volume spike', 'ACL Privilege Audit', 'Detected', 'Alert', 'Alert in 22 s'],
  ['EDR · Process hollowing', 'APT29 Phase 7', 'Partial', 'Alert', 'Telemetry only'], ['WAF · SQLi on /login', 'WAF mastery', 'Detected', 'Block', 'Blocked'], ['SIEM · DCSync (4662)', 'ADCS ESC Audit', 'Missed', 'Alert', 'No alert']
].map(([detection, scenario, result, expected, seen], i) => ({ id: 'V-' + (881 - i * 3), detection, scenario, result, expected, seen, checked: `${20 - (i % 4)} Oct ${String(9 + i).padStart(2, '0')}:${String((i * 11) % 60).padStart(2, '0')}` })));
D.VERIFY.forEach((v, i) => { v.src = v.detection.split(' · ')[0]; v.rule = ['Rule 4214 — Registry persistence', 'Rule 1180 — Encoded PowerShell', 'Rule 2207 — Kerberos anomaly', 'Rule 3302 — ADCS request spike', 'Rule 1042 — Office child process'][i % 5]; v.ttd = v.result === 'Missed' ? '—' : (3 + i * 4) + ' s'; });

// ---- Audit (24)
D.AUDIT.push(...Array.from({ length: 16 }, (_, i) => [`${22 - Math.floor(i / 4)} Oct ${String(8 + ((i * 5) % 12)).padStart(2, '0')}:${String((i * 13) % 60).padStart(2, '0')}:${String((i * 29) % 60).padStart(2, '0')}`, pk(['admin', 'analyst.r', 'soc.lead', 'system', 'compliance'], i), pk(['run.start', 'scenario.edit', 'agent.approve', 'report.generate', 'ioc.import', 'user.invite', 'integration.test', 'finding.assign'], i * 3), pk(['RUN-55' + (10 + i), 'SC-04' + (10 + i), 'AG-10' + (40 + i), 'RPT-019' + (i % 9), 'ioc batch ' + (i + 1), 'role Operator', 'Splunk HEC', 'F-22' + (10 + i)], i * 3), pk(['ok', 'ok', 'ok', 'warn', 'ok', 'err'], i)]));

// ---- AD coverage (14, with category / explanation / fix)
D.AD.forEach((a, i) => { a.cat = ['Kerberos', 'Kerberos', 'Delegation', 'ACLs', 'Hygiene', 'ADCS', 'Tiering'][i]; a.why = ['Service accounts with SPNs can be requested by any user and cracked offline.', 'Accounts without pre-auth leak crackable hashes to anonymous requests.', 'Hosts trusted for delegation can impersonate any user to any service.', 'Over-permissive ACEs on protected objects allow silent privilege escalation.', 'Local admin passwords that are unmanaged enable fast lateral movement.', 'Misconfigured certificate templates allow certificate-based domain takeover.', 'Admin logons outside tier 0 expose privileged credentials on workstations.'][i]; a.fix = ['Move to gMSA or set 25+ character passwords; remove unused SPNs.', 'Require Kerberos pre-authentication on all accounts.', 'Switch to constrained / resource-based delegation; protect admins.', 'Remove GenericAll for helpdesk groups and reset AdminSDHolder.', 'Deploy Windows LAPS to remaining hosts.', 'Disable ENROLLEE_SUPPLIES_SUBJECT; require manager approval.', 'Enforce logon restrictions via authentication policy silos.'][i]; });
D.AD.push(...[
  ['Trust relationships without SID filtering', 'Found 1', 'high', 'T1482', 'Open', 'Trusts', 'Cross-forest trusts without SID filtering enable SID-history abuse.', 'Enable SID filtering / quarantine on external trusts.'],
  ['GPO write access for non-admins', 'Found 3', 'high', 'T1484.001', 'Open', 'GPO', 'Write access to a GPO lets an attacker push code to every linked host.', 'Remove edit rights; audit GPO delegation monthly.'],
  ['Domain functional level < 2016', 'Level 2012 R2', 'medium', 'T1078', 'Open', 'Hygiene', 'Old functional levels block modern protections such as Protected Users.', 'Raise functional level after DC upgrade.'],
  ['Stale privileged accounts (90+ days)', 'Found 6', 'medium', 'T1078.002', 'In progress', 'Hygiene', 'Dormant privileged accounts are easy, quiet footholds.', 'Disable or remove after owner confirmation.'],
  ['SMB signing not required on DCs', 'All DCs compliant', 'info', 'T1557', 'Pass', 'Hygiene', 'Unsigned SMB enables relay attacks.', '—'],
  ['Krbtgt password age', '412 days', 'medium', 'T1558.001', 'Open', 'Kerberos', 'An old krbtgt password extends the life of forged golden tickets.', 'Rotate twice, 10 hours apart.'],
  ['Print Spooler running on DCs', 'Found 2', 'high', 'T1068', 'Open', 'Hygiene', 'Spooler on DCs has repeatedly been abused for remote code execution.', 'Disable the Print Spooler service on domain controllers.']
].map(([check, result, sev2, mapped, status, cat, why, fix]) => ({ check, result, sev: sev2, mapped, status, cat, why, fix })));

// ---- Agents: 8 more
D.AGENTS.push(...[
  ['AG-1601', 'WS-HR-0311', 'Windows 11 23H2', 'Finance Workstations', 'Online', '1.9.2', '3 min', 'Low', '10.20.7.31'], ['AG-1602', 'WS-HR-0318', 'Windows 10 22H2', 'Finance Workstations', 'Online', '1.9.1', '8 min', 'Medium', '10.20.7.38'],
  ['AG-1650', 'lnx-app-03', 'RHEL 9', 'Linux Web Tier', 'Online', '1.9.2', 'now', 'Low', '10.30.3.3'], ['AG-1651', 'lnx-app-04', 'RHEL 9', 'Linux Web Tier', 'Degraded', '1.9.2', '2 min', 'Medium', '10.30.3.4'],
  ['AG-1700', 'MAC-DES-301', 'macOS 14.6', 'Executive Laptops', 'Online', '1.9.2', '5 min', 'Low', '10.20.9.101'], ['AG-1710', 'SQL-PAY-03', 'Windows Server 2022', 'Payments DB', 'Online', '1.9.2', 'now', 'High', '10.40.1.53'],
  ['AG-1720', 'DC-BRN-01', 'Windows Server 2022', 'Domain Controllers', 'Online', '1.9.2', 'now', 'High', '10.11.1.11'], ['AG-1730', 'FS-SHARE-04', 'Windows Server 2022', 'File Servers', 'Offline', '1.8.9', '2 d', 'Medium', '10.10.6.24']
].map(([id, host, os, group, status, version, lastSeen, risk, ip]) => ({ id, host, os, group, status, version, lastSeen, risk, ip })));
D.AGENT_GROUPS = [['All agents', D.AGENTS.length], ...['Finance Workstations', 'Domain Controllers', 'File Servers', 'Linux Web Tier', 'Executive Laptops', 'Payments DB'].map(g => [g, D.AGENTS.filter(a => a.group === g).length])];

// ---- Email
D.EMAIL.campaigns = [
  { id: 'EC-18', name: 'Q4 finance awareness', tpl: 'Invoice overdue — credential harvest', group: 'Finance (420)', sent: 420, delivered: 414, opened: 201, clicked: 53, reported: 96, date: '21 Oct', status: 'Completed' },
  { id: 'EC-17', name: 'Vendor invoice drill', tpl: 'Payroll update — attachment', group: 'Procurement (180)', sent: 180, delivered: 176, opened: 88, clicked: 19, reported: 41, date: '14 Oct', status: 'Completed' },
  { id: 'EC-19', name: 'MFA re-enrolment QR lure', tpl: 'MFA re-enrol request (QR)', group: 'Executives (18)', sent: 18, delivered: 18, opened: 11, clicked: 5, reported: 3, date: '23 Oct', status: 'Completed' },
  { id: 'EC-20', name: 'Helpdesk password reset', tpl: 'Password expiry notice', group: 'All staff (2,140)', sent: 1260, delivered: 1244, opened: 540, clicked: 118, reported: 232, date: 'Today', status: 'Running' },
  { id: 'EC-21', name: 'Shared document lure', tpl: 'Shared document — cloud', group: 'Marketing (64)', sent: 0, delivered: 0, opened: 0, clicked: 0, reported: 0, date: '28 Oct', status: 'Scheduled' }];
D.EMAIL.templates = [
  { name: 'Invoice overdue — credential harvest', vector: 'Link', used: 14, click: '18%', status: 'Active', from: 'accounts@billing-portal.example', subject: 'Action required: invoice #88213 is overdue', body: 'Our records show invoice #88213 remains unpaid. To avoid service interruption, review the invoice and confirm payment details using the secure link below.' },
  { name: 'Payroll update — attachment', vector: 'Attachment', used: 9, click: '11%', status: 'Active', from: 'hr-payroll@acme-bank-hr.example', subject: 'Updated payroll calendar for Q4', body: 'Please find the updated payroll calendar attached. Open the spreadsheet and enable editing to view your pay period.' },
  { name: 'MFA re-enrol request (QR)', vector: 'QR code', used: 4, click: '27%', status: 'Draft', from: 'it-security@acme-bank-it.example', subject: 'Re-enrol your authenticator before Friday', body: 'We are migrating authenticators. Scan the QR code below with your phone camera to complete re-enrolment.' },
  { name: 'Password expiry notice', vector: 'Link', used: 6, click: '15%', status: 'Active', from: 'helpdesk@acme-bank-support.example', subject: 'Your password expires in 24 hours', body: 'Your network password will expire tomorrow. Select Keep my password to avoid being locked out.' },
  { name: 'Shared document — cloud', vector: 'Link', used: 3, click: '22%', status: 'Active', from: 'no-reply@docs-share.example', subject: 'A document was shared with you', body: 'A colleague shared "Q4 Budget Draft" with you. Open it to review and comment.' }];

// ---- Threats
D.THREATS.forEach((t, i) => { t.factors = [['Sector targeting', [95, 62, 28, 88][i]], ['Exposure match', [88, 91, 40, 79][i]], ['Validated gaps', [70, 78, 35, 84][i]], ['Recent activity', [92, 85, 45, 96][i]]]; t.techs = [['T1566', 'T1059.001', 'T1547.001', 'T1087', 'T1482', 'T1071.001'], ['T1486', 'T1490', 'T1021.002', 'T1078', 'T1567'], ['T1204', 'T1105', 'T1041'], ['T1566', 'T1078', 'T1556', 'T1621']][i]; t.scen = [['SC-0355', 'APT29 Kill Chain — Cozy Bear (Phase 7)'], ['SC-0377', 'Akira Kill Chain — Ransomware Emulation'], ['SC-0362', 'APT36 Kill Chain (Three-Tier)'], ['SC-0274', 'Email Gateway Credential Phish Simulation']][i]; });

// ---- Exercises
D.EXERCISES.forEach((e, i) => { e.agenda = [['09:00', 'Briefing and objectives'], ['09:30', 'Injects: initial encryption alerts'], ['10:30', 'Containment decisions'], ['11:30', 'Recovery and comms'], ['12:15', 'Hot wash']]; e.people = [['SOC lead', 'Incident commander'], ['Identity lead', 'Responder'], ['Comms lead', 'Observer'], ['CISO', 'Executive sponsor']]; e.score = [null, 72, 81, null][i]; });

// ---- ART library, sessions, tokens, role permissions
D.ART = [['Scheduled task via schtasks', 'T1053.005', 'Windows', true], ['Registry Run key persistence', 'T1547.001', 'Windows', true], ['LaunchAgent persistence', 'T1543.001', 'macOS', true], ['Cron job persistence', 'T1053.003', 'Linux', false], ['LSASS dump via comsvcs', 'T1003.001', 'Windows', true], ['Kerberoast with Rubeus', 'T1558.003', 'Windows', true], ['WMI event subscription', 'T1546.003', 'Windows', true], ['PowerShell download cradle', 'T1059.001', 'Windows', true], ['Bash history clearing', 'T1070.003', 'Linux', true], ['Disable Defender via registry', 'T1562.001', 'Windows', false], ['DNS tunnelling probe', 'T1071.004', 'Cross-platform', true], ['Archive and stage data', 'T1560.001', 'Cross-platform', true], ['Shadow copy deletion', 'T1490', 'Windows', false], ['Systemd service persistence', 'T1543.002', 'Linux', true]].map(([name, tech, plat, on]) => ({ name, tech, plat, on }));
D.SESSIONS = [['Windows · Chrome 129', '10.20.1.10', 'This session', true], ['macOS · Safari 17', '10.20.9.101', '2 days ago', false], ['Windows · Edge 130', '10.20.1.14', '6 days ago', false]];
D.TOKENS = [['CI pipeline reporter', 'bas_••••a41f', 'Read', '12 Oct', 'Never'], ['Splunk export', 'bas_••••9c02', 'Read', '3 Sep', '30 Nov 2026']];
D.PERMS = { Admin: ['Run scenarios', 'Manage agents', 'Manage users', 'Edit integrations', 'View reports', 'Approve remediation', 'Change settings'], Analyst: ['Run scenarios', 'Manage agents', 'View reports', 'Approve remediation'], Viewer: ['View reports'] };
D.USERS.push({ name: 'Platform Eng', email: 'platform@acme-bank.demo', role: 'Analyst', last: '3 d', mfa: true }, { name: 'CISO Office', email: 'ciso@acme-bank.demo', role: 'Viewer', last: '1 d', mfa: true });
D.INTEGRATION_LOGS = [['14:20', 'Sync OK — 128 events pulled'], ['13:20', 'Sync OK — 97 events pulled'], ['12:20', 'Sync OK — 110 events pulled'], ['11:20', 'Warning — rate limited, retried in 30 s'], ['10:20', 'Sync OK — 84 events pulled']];

// Variant detail generator: first `pass` variants pass, spread failures through the rest
D.variantList = v => Array.from({ length: v.count }, (_, i) => ({ id: `${v.family}-v${String(i + 1).padStart(2, '0')}`, desc: pk(['encoded command', 'renamed binary', 'alternate API', 'staged payload', 'living-off-the-land', 'sleep-obfuscated', 'parent-PID spoof'], i * 3 + v.count), ok: ((i * 7 + 3) % v.count) < v.pass }));
