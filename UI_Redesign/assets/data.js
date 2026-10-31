/* =============================================================================
   Sample dataset shared by every page, so the numbers agree across screens.
   Illustrative only — "Contoso Bank" is fictional. Technique IDs/names are real
   MITRE ATT&CK (Enterprise); outcomes are invented for the mock-up.
   Outcome codes: P = prevented, D = detected only, M = missed, U = not tested.
   ========================================================================== */
window.AUD = {
  org: { name: 'Contoso Bank', short: 'CB', env: 'Production · 3 sites' },
  period: { label: 'Last 30 days', compare: 'vs 30 days ago', asOf: '31 Oct 2026, 09:40 IST' },

  weeks: ['10 Aug', '17 Aug', '24 Aug', '31 Aug', '7 Sep', '14 Sep', '21 Sep', '28 Sep', '5 Oct', '12 Oct', '19 Oct', '26 Oct'],

  posture: {
    score: 72, ago: 66, target: 80,
    history: [60, 61, 62, 62, 63, 64, 65, 66, 67, 69, 70, 72],
    simulations: 1284, endpoints: 214, lastRun: '2 h ago', projected: 81,
    /* Proposed, explainable composite (higher is always better) */
    components: [
      { name: 'Prevention rate', value: 78, weight: 45 },
      { name: 'Detection rate', value: 64, weight: 30 },
      { name: 'ATT&CK coverage', value: 76, weight: 15 },
      { name: 'Attack-path resilience', value: 58, weight: 10 }
    ]
  },

  trend: {
    prevention: [69, 70, 71, 71, 72, 73, 73, 74, 75, 76, 77, 78],
    detection: [47, 49, 50, 52, 51, 53, 54, 55, 59, 61, 63, 64],
    events: [{ i: 8, label: 'Splunk detection pack v3' }]
  },

  kpis: [
    { id: 'prev', label: 'Prevention rate', value: 78, unit: '%', delta: 4, dUnit: ' pts', good: 'up', ctx: 'of 1,284 simulations blocked', spark: [69, 70, 71, 71, 72, 73, 73, 74, 75, 76, 77, 78] },
    { id: 'det', label: 'Detection rate', value: 64, unit: '%', delta: 9, dUnit: ' pts', good: 'up', ctx: 'alerted in SIEM / EDR', spark: [47, 49, 50, 52, 51, 53, 54, 55, 59, 61, 63, 64] },
    { id: 'mttd', label: 'Mean time to detect', value: '4m 12s', unit: '', delta: -65, dText: '−1m 05s', good: 'down', ctx: 'median 2m 40s', spark: [430, 415, 400, 388, 372, 360, 349, 317, 300, 285, 268, 252] },
    { id: 'cov', label: 'ATT&CK coverage', value: 76, unit: '%', delta: 6, dUnit: ' pts', good: 'up', ctx: '80 of 105 techniques in profile', spark: [58, 60, 61, 63, 64, 66, 68, 70, 71, 73, 75, 76] },
    { id: 'crit', label: 'Open critical findings', value: 12, unit: '', delta: -5, dUnit: '', good: 'down', ctx: '3 past SLA', spark: [22, 21, 21, 19, 20, 18, 18, 17, 15, 14, 13, 12] },
    { id: 'fleet', label: 'Endpoints validated', value: 96, unit: '%', delta: 2, dUnit: ' pts', good: 'up', ctx: '206 of 214 in last 30 days', spark: [88, 89, 90, 91, 92, 93, 94, 94, 95, 95, 96, 96] }
  ],

  /* Kill-chain resilience (simulation-level share, %): prevented / detected only / missed */
  tactics: [
    { id: 'TA0001', name: 'Initial access', short: 'Initial access', p: 90, d: 6, m: 4, sims: 96 },
    { id: 'TA0002', name: 'Execution', short: 'Execution', p: 88, d: 6, m: 6, sims: 164 },
    { id: 'TA0003', name: 'Persistence', short: 'Persistence', p: 84, d: 8, m: 8, sims: 142 },
    { id: 'TA0004', name: 'Privilege escalation', short: 'Priv. escalation', p: 81, d: 7, m: 12, sims: 88 },
    { id: 'TA0005', name: 'Defense evasion', short: 'Defense evasion', p: 76, d: 9, m: 15, sims: 176 },
    { id: 'TA0006', name: 'Credential access', short: 'Credential access', p: 58, d: 12, m: 30, sims: 104 },
    { id: 'TA0007', name: 'Discovery', short: 'Discovery', p: 70, d: 18, m: 12, sims: 132 },
    { id: 'TA0008', name: 'Lateral movement', short: 'Lateral movement', p: 49, d: 16, m: 35, sims: 72 },
    { id: 'TA0009', name: 'Collection', short: 'Collection', p: 83, d: 7, m: 10, sims: 84 },
    { id: 'TA0011', name: 'Command and control', short: 'Command & control', p: 86, d: 6, m: 8, sims: 98 },
    { id: 'TA0010', name: 'Exfiltration', short: 'Exfiltration', p: 71, d: 9, m: 20, sims: 64 },
    { id: 'TA0040', name: 'Impact', short: 'Impact', p: 92, d: 4, m: 4, sims: 64 }
  ],

  /* ATT&CK matrix: [techniqueId, name, outcome] — worst outcome across in-scope endpoints */
  matrix: [
    { name: 'Initial access', short: 'Initial access', tech: [['T1189', 'Drive-by Compromise', 'P'], ['T1190', 'Exploit Public-Facing Application', 'P'], ['T1133', 'External Remote Services', 'D'], ['T1200', 'Hardware Additions', 'U'], ['T1566', 'Phishing', 'P'], ['T1091', 'Replication Through Removable Media', 'P'], ['T1195', 'Supply Chain Compromise', 'U'], ['T1199', 'Trusted Relationship', 'U'], ['T1078', 'Valid Accounts', 'D']] },
    { name: 'Execution', short: 'Execution', tech: [['T1059', 'Command and Scripting Interpreter', 'D'], ['T1203', 'Exploitation for Client Execution', 'P'], ['T1559', 'Inter-Process Communication', 'P'], ['T1106', 'Native API', 'M'], ['T1053', 'Scheduled Task/Job', 'P'], ['T1129', 'Shared Modules', 'U'], ['T1072', 'Software Deployment Tools', 'U'], ['T1569', 'System Services', 'P'], ['T1204', 'User Execution', 'P'], ['T1047', 'Windows Management Instrumentation', 'D']] },
    { name: 'Persistence', short: 'Persist.', tech: [['T1098', 'Account Manipulation', 'D'], ['T1197', 'BITS Jobs', 'P'], ['T1547', 'Boot or Logon Autostart Execution', 'P'], ['T1037', 'Boot or Logon Initialization Scripts', 'U'], ['T1136', 'Create Account', 'P'], ['T1543', 'Create or Modify System Process', 'P'], ['T1546', 'Event Triggered Execution', 'M'], ['T1574', 'Hijack Execution Flow', 'D'], ['T1505', 'Server Software Component', 'U'], ['T1137', 'Office Application Startup', 'P']] },
    { name: 'Privilege escalation', short: 'Priv. esc.', tech: [['T1548', 'Abuse Elevation Control Mechanism', 'P'], ['T1134', 'Access Token Manipulation', 'M'], ['T1068', 'Exploitation for Privilege Escalation', 'P'], ['T1055', 'Process Injection', 'D'], ['T1484', 'Domain or Tenant Policy Modification', 'U'], ['T1611', 'Escape to Host', 'U']] },
    { name: 'Defense evasion', short: 'Def. evasion', tech: [['T1140', 'Deobfuscate/Decode Files or Information', 'P'], ['T1562', 'Impair Defenses', 'M'], ['T1070', 'Indicator Removal', 'D'], ['T1036', 'Masquerading', 'P'], ['T1112', 'Modify Registry', 'P'], ['T1027', 'Obfuscated Files or Information', 'P'], ['T1218', 'System Binary Proxy Execution', 'D'], ['T1553', 'Subvert Trust Controls', 'U'], ['T1497', 'Virtualization/Sandbox Evasion', 'U'], ['T1620', 'Reflective Code Loading', 'M'], ['T1564', 'Hide Artifacts', 'P'], ['T1222', 'File and Directory Permissions Modification', 'P']] },
    { name: 'Credential access', short: 'Cred. access', tech: [['T1110', 'Brute Force', 'P'], ['T1555', 'Credentials from Password Stores', 'M'], ['T1003', 'OS Credential Dumping', 'M'], ['T1558', 'Steal or Forge Kerberos Tickets', 'M'], ['T1552', 'Unsecured Credentials', 'D'], ['T1056', 'Input Capture', 'U'], ['T1557', 'Adversary-in-the-Middle', 'U'], ['T1539', 'Steal Web Session Cookie', 'D']] },
    { name: 'Discovery', short: 'Discovery', tech: [['T1087', 'Account Discovery', 'D'], ['T1482', 'Domain Trust Discovery', 'M'], ['T1083', 'File and Directory Discovery', 'D'], ['T1046', 'Network Service Discovery', 'P'], ['T1135', 'Network Share Discovery', 'D'], ['T1069', 'Permission Groups Discovery', 'D'], ['T1057', 'Process Discovery', 'U'], ['T1012', 'Query Registry', 'U'], ['T1018', 'Remote System Discovery', 'D'], ['T1082', 'System Information Discovery', 'M'], ['T1016', 'System Network Configuration Discovery', 'U'], ['T1033', 'System Owner/User Discovery', 'D']] },
    { name: 'Lateral movement', short: 'Lateral movement', tech: [['T1210', 'Exploitation of Remote Services', 'P'], ['T1570', 'Lateral Tool Transfer', 'M'], ['T1021', 'Remote Services', 'M'], ['T1550', 'Use Alternate Authentication Material', 'M'], ['T1563', 'Remote Service Session Hijacking', 'U'], ['T1080', 'Taint Shared Content', 'D']] },
    { name: 'Collection', short: 'Collect.', tech: [['T1560', 'Archive Collected Data', 'P'], ['T1119', 'Automated Collection', 'D'], ['T1115', 'Clipboard Data', 'U'], ['T1005', 'Data from Local System', 'P'], ['T1039', 'Data from Network Shared Drive', 'D'], ['T1074', 'Data Staged', 'M'], ['T1114', 'Email Collection', 'U'], ['T1113', 'Screen Capture', 'P']] },
    { name: 'Command and control', short: 'C2', tech: [['T1071', 'Application Layer Protocol', 'P'], ['T1132', 'Data Encoding', 'P'], ['T1001', 'Data Obfuscation', 'U'], ['T1568', 'Dynamic Resolution', 'P'], ['T1573', 'Encrypted Channel', 'D'], ['T1105', 'Ingress Tool Transfer', 'P'], ['T1090', 'Proxy', 'D'], ['T1219', 'Remote Access Software', 'M'], ['T1572', 'Protocol Tunneling', 'P']] },
    { name: 'Exfiltration', short: 'Exfil.', tech: [['T1020', 'Automated Exfiltration', 'U'], ['T1030', 'Data Transfer Size Limits', 'U'], ['T1048', 'Exfiltration Over Alternative Protocol', 'P'], ['T1041', 'Exfiltration Over C2 Channel', 'P'], ['T1567', 'Exfiltration Over Web Service', 'M'], ['T1052', 'Exfiltration Over Physical Medium', 'U'], ['T1029', 'Scheduled Transfer', 'D']] },
    { name: 'Impact', short: 'Impact', tech: [['T1485', 'Data Destruction', 'P'], ['T1486', 'Data Encrypted for Impact', 'P'], ['T1490', 'Inhibit System Recovery', 'M'], ['T1489', 'Service Stop', 'P'], ['T1491', 'Defacement', 'U'], ['T1529', 'System Shutdown/Reboot', 'U'], ['T1531', 'Account Access Removal', 'P'], ['T1496', 'Resource Hijacking', 'D']] }
  ],

  /* Module scores — every Audspect module gets its own 0–100 score (higher is better).
     The overall posture score is the weighted average of the weighted modules (weights sum to 100). */
  moduleGroups: [
    ['surface', 'Attack surface', 'Where attacks get in'],
    ['technique', 'Attack techniques', 'What an attacker does once inside'],
    ['defence', 'Detection & exposure', 'Whether you see it, and how far it can go'],
    ['governance', 'Governance lenses', 'Shown for context; not weighted in the posture score']
  ],
  modules: [
    { id: 'endpoint', name: 'Endpoint security', icon: 'monitor', group: 'surface', score: 86, delta: 5, p: 90, d: 79, weight: 15, last: '2 h ago', sims: 1012, spark: [76, 77, 78, 78, 79, 80, 81, 82, 83, 84, 85, 86],
      desc: 'Malware, scripts, persistence and privilege escalation executed on endpoints by the agent.',
      tests: [['T1059.001', 'PowerShell execution', 'D'], ['T1003.001', 'LSASS memory dumping', 'M'], ['T1547.001', 'Registry run keys', 'P'], ['T1055', 'Process injection', 'D'], ['T1562.001', 'Disable or modify tools', 'M'], ['T1218.011', 'Rundll32 proxy execution', 'P'], ['T1053.005', 'Scheduled task', 'P'], ['T1027', 'Obfuscated files', 'P']] },
    { id: 'email', name: 'Email security', icon: 'mail', group: 'surface', score: 81, delta: 1, p: 84, d: 76, weight: 8, last: '2 days ago', sims: 140, spark: [78, 78, 79, 79, 80, 80, 80, 81, 80, 80, 81, 81],
      desc: 'Malicious attachments, links and impersonation sent through the email gateway to test mailboxes.',
      tests: [['T1566.001', 'Macro attachment', 'P'], ['T1566.002', 'Spearphishing link', 'D'], ['T1027.006', 'HTML smuggling', 'M'], ['T1553.005', 'ISO / LNK container', 'P'], ['T1566.001', 'Password-protected archive', 'D'], ['T1534', 'Internal spearphishing', 'P']] },
    { id: 'webgw', name: 'Web gateway', icon: 'globe', group: 'surface', score: 76, delta: 2, p: 79, d: 71, weight: 6, last: '5 days ago', sims: 96, spark: [70, 71, 71, 72, 72, 73, 74, 74, 75, 75, 76, 76],
      desc: 'Downloads, risky categories and command-and-control over HTTP(S) through the proxy.',
      tests: [['T1071.001', 'C2 over web protocols', 'P'], ['T1105', 'Ingress tool transfer', 'P'], ['T1567.002', 'Upload to cloud storage', 'M'], ['T1090.004', 'Domain fronting', 'D'], ['T1189', 'Drive-by download', 'P'], ['T1102', 'Web-service C2', 'D']] },
    { id: 'waf', name: 'Web application firewall', icon: 'shield', group: 'surface', score: 88, delta: 1, p: 91, d: 84, weight: 6, last: '6 days ago', sims: 86, spark: [85, 85, 86, 86, 86, 87, 87, 87, 88, 88, 88, 88],
      desc: 'OWASP Top 10 payloads replayed against four internet-facing applications.',
      tests: [['A03', 'SQL injection', 'P'], ['A03', 'Cross-site scripting', 'P'], ['A01', 'Path traversal', 'P'], ['A10', 'Server-side request forgery', 'D'], ['A03', 'OS command injection', 'P'], ['A06', 'Log4Shell (CVE-2021-44228)', 'P']] },
    { id: 'cloud', name: 'Cloud security', icon: 'cloud', group: 'surface', state: 'none', weight: 0, mapped: 16,
      desc: 'Cloud control-plane and workload techniques. No cloud assessment has run yet, so the score is unknown, not zero.' },
    { id: 'k8s', name: 'Kubernetes', icon: 'box', group: 'surface', state: 'addon', weight: 0,
      desc: 'Cluster hardening, access configuration and isolation checks, run in a lab cluster. Available as a licensed add-on.' },
    { id: 'network', name: 'Network & segmentation', icon: 'network', group: 'technique', score: 64, delta: 2, p: 61, d: 69, weight: 10, last: '2 h ago', sims: 148, spark: [58, 58, 59, 60, 60, 61, 61, 62, 62, 63, 63, 64],
      desc: 'Lateral movement, discovery and zone-to-zone reachability between the DMZ, branches and core banking.',
      tests: [['T1021.002', 'SMB / admin shares', 'M'], ['T1021.001', 'Remote Desktop', 'D'], ['T1046', 'Network service discovery', 'P'], ['T1570', 'Lateral tool transfer', 'M'], ['T1572', 'Protocol tunnelling', 'P'], ['Zone test', 'DMZ → core banking reachability', 'P']] },
    { id: 'identity', name: 'AD & identity', icon: 'key', group: 'technique', score: 68, delta: 3, p: 66, d: 71, weight: 10, last: '3 days ago', sims: 92, spark: [61, 62, 62, 63, 63, 64, 65, 65, 66, 67, 67, 68],
      desc: 'Credential theft and abuse of Active Directory: Kerberos, replication and group policy.',
      tests: [['T1558.003', 'Kerberoasting', 'M'], ['T1003.006', 'DCSync', 'M'], ['T1110.003', 'Password spraying', 'P'], ['T1087.002', 'Domain account discovery', 'D'], ['T1484.001', 'Group policy modification', 'P'], ['T1550.002', 'Pass the hash', 'M']] },
    { id: 'dlp', name: 'Data exfiltration', icon: 'database', group: 'technique', score: 54, delta: -3, p: 52, d: 57, weight: 7, last: '4 days ago', sims: 64, spark: [58, 58, 57, 57, 57, 56, 56, 56, 55, 55, 54, 54],
      desc: 'Moving synthetic customer data out through web, DNS, email and removable media.',
      tests: [['T1567.002', 'Exfiltration to cloud storage', 'M'], ['T1048.003', 'Unencrypted protocol (FTP)', 'D'], ['T1041', 'Over the C2 channel', 'P'], ['T1052.001', 'USB device', 'P'], ['T1020', 'Automated exfiltration', 'M'], ['T1048', 'DNS tunnelling', 'D']] },
    { id: 'ransom', name: 'Ransomware readiness', icon: 'lock', group: 'technique', score: 70, delta: 4, p: 68, d: 73, weight: 10, last: 'Yesterday', sims: 96, spark: [62, 63, 63, 64, 65, 65, 66, 67, 68, 68, 69, 70],
      desc: 'Pre-encryption behaviour on core banking servers. Nothing is ever encrypted.',
      tests: [['T1490', 'Inhibit system recovery', 'M'], ['T1486', 'Data encrypted for impact (simulated)', 'P'], ['T1489', 'Service stop', 'P'], ['T1562.001', 'Disable security tools', 'M'], ['T1083', 'File and directory discovery', 'D'], ['T1070.004', 'File deletion', 'D']] },
    { id: 'evasion', name: 'Payload variant resistance', icon: 'bug', group: 'technique', score: 74, delta: 0, p: 74, d: 70, weight: 5, last: '6 days ago', sims: 210, spark: [74, 74, 73, 74, 74, 74, 73, 74, 74, 74, 74, 74],
      desc: 'How consistently endpoint protection blocks re-packaged variants of the same benign test payloads.',
      tests: [['Family A', 'Variant family A', 'P'], ['Family B', 'Variant family B', 'P'], ['Family C', 'Variant family C', 'M'], ['Family D', 'Variant family D', 'M'], ['Family E', 'Variant family E', 'D'], ['Family F', 'Variant family F', 'D']] },
    { id: 'detect', name: 'Detection & response', icon: 'radar', group: 'defence', score: 64, delta: 9, p: null, d: 64, weight: 12, last: '3 days ago', sims: 1284, link: '12-detection.html', spark: [47, 49, 50, 52, 51, 53, 54, 55, 59, 61, 63, 64],
      desc: 'Whether simulations raise the right alert in your SIEM and EDR, and how fast.' },
    { id: 'paths', name: 'Attack-path resilience', icon: 'route', group: 'defence', score: 58, delta: 6, weight: 6, last: 'Yesterday', link: '13-attack-paths.html', spark: [48, 49, 50, 51, 52, 52, 53, 54, 55, 56, 57, 58],
      desc: 'How hard it is to chain techniques from an endpoint to crown-jewel systems.' },
    { id: 'exposure', name: 'Exposure & KEV', icon: 'alert', group: 'defence', score: 78, delta: 2, weight: 5, last: 'Today', link: '14-threat-intel.html#kev', spark: [73, 73, 74, 74, 75, 75, 76, 76, 77, 77, 78, 78],
      desc: 'Known-exploited vulnerabilities and exposed services that make techniques reachable.' },
    { id: 'threat', name: 'Threat readiness', icon: 'target', group: 'governance', score: 71, delta: 3, weight: 0, last: 'Yesterday', link: '14-threat-intel.html', spark: [64, 65, 65, 66, 67, 67, 68, 68, 69, 70, 70, 71],
      desc: 'Share of the techniques used by groups in your threat profile that your controls prevent.' },
    { id: 'compliance', name: 'Compliance readiness', icon: 'scale', group: 'governance', score: 78, delta: 4, weight: 0, last: '2 h ago', link: '06-compliance.html', spark: [70, 71, 72, 73, 73, 74, 75, 76, 76, 77, 77, 78],
      desc: 'Average readiness across the seven frameworks in scope.' }
  ],

  /* Posture by control domain — shape of GET /api/controlhealth/summary (10 categories, already built, unused today) */
  domains: [
    { id: 'endpoint-protection', name: 'Endpoint protection', prevention: 83, detection: 74, validated: 41, mapped: 48, delta: 5 },
    { id: 'application-control', name: 'Application control', prevention: 88, detection: 71, validated: 12, mapped: 14, delta: 2 },
    { id: 'email-security', name: 'Email security', prevention: 79, detection: 66, validated: 9, mapped: 12, delta: 1 },
    { id: 'detection-response', name: 'Detection & response', prevention: null, na: 'Detect-only', detection: 64, validated: 52, mapped: 64, delta: 9 },
    { id: 'identity-access', name: 'Identity & access', prevention: 62, detection: 55, validated: 14, mapped: 22, delta: 3 },
    { id: 'privileged-access', name: 'Privileged access', prevention: 61, detection: 57, validated: 11, mapped: 18, delta: 4 },
    { id: 'network-security', name: 'Network security', prevention: 58, detection: 51, validated: 17, mapped: 26, delta: 2 },
    { id: 'backup-recovery', name: 'Backup & recovery', prevention: 55, detection: 60, validated: 4, mapped: 8, delta: 1 },
    { id: 'data-protection', name: 'Data protection', prevention: 46, detection: 39, validated: 6, mapped: 14, delta: -3 },
    { id: 'cloud-security', name: 'Cloud security', prevention: null, detection: null, validated: 0, mapped: 16, delta: null, none: true }
  ],

  /* Threat-actor readiness (share of each actor's emulated TTPs) */
  actors: [
    { name: 'RansomEXX', aka: 'Ransomware', why: 'Linked to the 2024 C-Edge outage at Indian co-operative banks', ttps: 22, p: 57, d: 63, last: 'Yesterday' },
    { name: 'Lazarus Group', aka: 'DPRK-nexus', why: 'Linked to the 2018 Cosmos Bank heist', ttps: 31, p: 68, d: 74, last: '3 days ago' },
    { name: 'FIN7', aka: 'Financially motivated', why: 'Targets payment and finance environments', ttps: 24, p: 70, d: 58, last: '6 days ago' },
    { name: 'APT41', aka: 'China-nexus', why: 'Active against Indian organisations', ttps: 27, p: 74, d: 70, last: '5 days ago' },
    { name: 'LockBit 3.0', aka: 'RaaS', why: 'Prolific ransomware affiliate programme', ttps: 26, p: 77, d: 72, last: '2 days ago' },
    { name: 'Transparent Tribe', aka: 'APT36', why: 'Long-running campaigns against Indian entities', ttps: 18, p: 83, d: 78, last: '4 days ago' }
  ],

  /* Compliance readiness — controls whose mapped techniques were validated and passed */
  frameworks: [
    { id: 'rbi', short: 'RBI CSF', name: 'RBI Cyber Security Framework for Banks', regulator: 'Reserve Bank of India', pass: 42, partial: 5, untested: 1, total: 52, delta: 4, spark: [70, 71, 73, 74, 74, 75, 77, 81] },
    { id: 'sebi', short: 'SEBI CSCRF', name: 'SEBI Cybersecurity & Cyber Resilience Framework', pass: 35, partial: 7, total: 46, delta: 6, spark: [64, 65, 66, 68, 70, 71, 72, 76] },
    { id: 'certin', short: 'CERT-In', name: 'CERT-In Directions (April 2022)', pass: 15, partial: 1, total: 17, delta: 2, spark: [82, 82, 84, 84, 86, 86, 86, 88] },
    { id: 'irdai', short: 'IRDAI', name: 'IRDAI Information & Cyber Security Guidelines', pass: 33, partial: 8, total: 45, delta: 3, spark: [66, 67, 68, 69, 70, 70, 71, 73] },
    { id: 'pci', short: 'PCI DSS 4.0', name: 'PCI DSS v4.0', pass: 27, partial: 7, total: 39, delta: 5, spark: [60, 61, 62, 63, 64, 64, 67, 69] },
    { id: 'iso', short: 'ISO 27001', name: 'ISO/IEC 27001:2022 (Annex A)', pass: 31, partial: 4, total: 37, delta: 1, spark: [80, 81, 81, 82, 82, 83, 83, 84] },
    { id: 'nist', short: 'NIST CSF 2.0', name: 'NIST Cybersecurity Framework 2.0', pass: 38, partial: 6, total: 49, delta: 4, spark: [70, 71, 72, 73, 74, 75, 75, 78] }
  ],

  /* "Fix these first" — ranked by projected posture uplift */
  actions: [
    { title: 'Block credential theft from LSASS', detail: 'Enable LSA protection (RunAsPPL) and the Defender ASR rule “Block credential stealing from LSASS”.', tech: ['T1003.001'], scope: '14 endpoints', uplift: 3.8, effort: 'Low', owner: 'Endpoint team', sev: 'critical', finding: 'F-1042' },
    { title: 'Stop admin-share lateral movement', detail: 'Restrict SMB / ADMIN$ between workstations and roll out LAPS for local admin passwords.', tech: ['T1021.002', 'T1570'], scope: '22 endpoints', uplift: 2.9, effort: 'Medium', owner: 'Infrastructure', sev: 'critical', finding: 'F-1038' },
    { title: 'Protect shadow copies from ransomware', detail: 'Block and alert on shadow-copy deletion (vssadmin, wmic shadowcopy) on core-banking servers.', tech: ['T1490'], scope: '9 servers', uplift: 2.1, effort: 'Low', owner: 'Server team', sev: 'critical', finding: 'F-1035' },
    { title: 'Detect encoded PowerShell', detail: 'Turn on Script Block Logging (event 4104), forward it to Splunk and enable the matching detection.', tech: ['T1059.001'], scope: 'SIEM', uplift: 1.4, effort: 'Low', owner: 'SOC', sev: 'high', finding: 'F-1031' },
    { title: 'Block uploads to unsanctioned cloud storage', detail: 'Add a proxy + DLP policy for web-service exfiltration.', tech: ['T1567.002'], scope: 'Proxy / DLP', uplift: 1.1, effort: 'Medium', owner: 'Network team', sev: 'high', finding: 'F-1027' }
  ],

  fleet: { total: 214, online: 194, attention: 4, offline: 13, quarantined: 3, validated30d: 206, os: { Windows: 168, Linux: 39, macOS: 7 } },

  /* Operations view (SOC / BAS operator) */
  ops: {
    live: { id: 'A-3321', name: 'Ransomware readiness', scope: 'Core banking · 24 endpoints', progress: 64, done: 118, total: 184, eta: '≈ 12 min', started: '09:22 IST' },
    feed: [
      { t: '09:39:58', host: 'CBS-APP-01', tech: 'T1490', name: 'Inhibit System Recovery', o: 'M' },
      { t: '09:39:41', host: 'CBS-APP-02', tech: 'T1486', name: 'Data Encrypted for Impact', o: 'P' },
      { t: '09:39:20', host: 'CBS-DB-01', tech: 'T1489', name: 'Service Stop', o: 'P' },
      { t: '09:38:57', host: 'CBS-APP-01', tech: 'T1059.001', name: 'PowerShell', o: 'D' },
      { t: '09:38:31', host: 'CBS-APP-03', tech: 'T1562.001', name: 'Disable or Modify Tools', o: 'M' },
      { t: '09:38:02', host: 'CBS-DB-02', tech: 'T1070.004', name: 'File Deletion', o: 'D' }
    ],
    connectors: [
      { name: 'Splunk Enterprise Security', kind: 'SIEM', status: 'good', label: 'Healthy', last: 'Last event 28 s ago' },
      { name: 'Microsoft Defender for Endpoint', kind: 'EDR', status: 'good', label: 'Healthy', last: 'Last verdict 1 min ago' },
      { name: 'ServiceNow', kind: 'ITSM', status: 'good', label: 'Healthy', last: '12 tickets synced today' },
      { name: 'MISP', kind: 'Threat intel', status: 'warning', label: 'Stale', last: 'Last sync 3 days ago — import the next offline bundle' }
    ],
    content: [
      { name: 'Threat library', v: '2026.10.2', when: 'Imported 12 Oct · offline bundle · signature verified' },
      { name: 'MITRE ATT&CK', v: 'v17', when: 'Bundled with release' },
      { name: 'CISA KEV catalogue', v: '1,384 CVEs', when: 'Updated 3 days ago' },
      { name: 'Agent build', v: '3.0.2', when: '4 endpoints behind' }
    ],
    upcoming: [
      { name: 'Board scorecard (PDF, signed)', when: 'Sat 1 Nov · 08:00', scope: 'Emailed to CISO and CRO' },
      { name: 'Monthly full kill chain', when: 'Mon 3 Nov · 02:00', scope: 'All endpoints · 214' },
      { name: 'Weekly BFSI threat pack', when: 'Fri 7 Nov · 01:00', scope: 'All branches · 198 endpoints' }
    ]
  },

  assessments: [
    { id: 'A-3318', name: 'Weekly BFSI threat pack', type: 'Scheduled', scope: 'All branches · 198 endpoints', status: 'Completed', when: '2 h ago', by: 'Schedule', p: 241, d: 37, m: 34, delta: 2, dur: '1h 12m' },
    { id: 'A-3321', name: 'Ransomware readiness', type: 'On demand', scope: 'Core banking · 24 endpoints', status: 'Running', progress: 64, when: 'Started 18 min ago', by: 'R. Iyer', dur: '—' },
    { id: 'A-3309', name: 'Lazarus Group emulation', type: 'Threat actor', scope: 'Treasury & SWIFT zone · 12 endpoints', status: 'Completed', when: 'Yesterday', by: 'Purple team', p: 58, d: 21, m: 16, delta: 5, dur: '46m' },
    { id: 'A-3297', name: 'Detection validation — Splunk ES', type: 'Detection', scope: 'SIEM · 64 detections', status: 'Completed', when: '3 days ago', by: 'SOC', p: 0, d: 47, m: 17, delta: 7, dur: '31m' },
    { id: 'A-3290', name: 'Re-test: LSASS hardening', type: 'Re-test', scope: 'FIN-WS-023, FIN-WS-031', status: 'Partial', when: '4 days ago', by: 'A. Khan', p: 1, d: 0, m: 1, note: '1 agent offline', dur: '4m' },
    { id: 'A-3330', name: 'Monthly full kill chain', type: 'Scheduled', scope: 'All endpoints · 214', status: 'Scheduled', when: 'Mon 3 Nov, 02:00', by: 'Schedule', dur: '—' }
  ],

  paths: [
    { target: 'DC01', kind: 'Domain controller', risk: 'critical', steps: 3, hosts: 14,
      chain: [{ n: 'FIN-WS-023', k: 'Finance workstation' }, { t: 'T1003.001', l: 'LSASS dump' }, { n: 'Domain-admin hash', k: 'Credential' }, { t: 'T1550.002', l: 'Pass the hash' }, { n: 'FILESRV-02', k: 'File server' }, { t: 'T1021.002', l: 'SMB admin share' }, { n: 'DC01', k: 'Domain controller', jewel: true }] },
    { target: 'CBS-DB-01', kind: 'Core-banking database', risk: 'serious', steps: 4, hosts: 6 },
    { target: 'SWIFT-GW-01', kind: 'SWIFT gateway', risk: 'serious', steps: 5, hosts: 2 }
  ],
  pathStats: { total: 22, resilience: 58 },
  chokePoints: [
    { name: 'Domain-admin credentials cached on finance workstations', breaks: 16, fix: 'Fix 1 (LSASS protection) plus tiered admin accounts' },
    { name: 'FILESRV-02 admin share reachable from workstations', breaks: 9, fix: 'Fix 2 (restrict SMB between tiers)' }
  ],

  findings: [
    { id: 'F-1042', sev: 'critical', title: 'LSASS memory dumping not prevented', tech: 'T1003.001', tactic: 'Credential access', prevented: false, detected: false, assets: 14, first: '12 Oct', sla: 'Due in 5 days', slaState: 'ok', owner: 'Endpoint team', status: 'In progress', ticket: 'SEC-2291', uplift: 3.8 },
    { id: 'F-1038', sev: 'critical', title: 'Lateral movement over SMB admin shares', tech: 'T1021.002', tactic: 'Lateral movement', prevented: false, detected: true, assets: 22, first: '9 Oct', sla: 'Due in 2 days', slaState: 'warn', owner: 'Infrastructure', status: 'Open', ticket: 'SEC-2287', uplift: 2.9 },
    { id: 'F-1035', sev: 'critical', title: 'Shadow copies deleted before encryption', tech: 'T1490', tactic: 'Impact', prevented: false, detected: false, assets: 9, first: '5 Oct', sla: 'Overdue 1 day', slaState: 'breach', owner: 'Server team', status: 'Open', ticket: 'SEC-2279', uplift: 2.1 },
    { id: 'F-1031', sev: 'high', title: 'Encoded PowerShell not detected in SIEM', tech: 'T1059.001', tactic: 'Execution', prevented: false, detected: false, assets: 31, first: '2 Oct', sla: 'Due in 6 days', slaState: 'ok', owner: 'SOC', status: 'In progress', ticket: 'SEC-2270', uplift: 1.4 },
    { id: 'F-1027', sev: 'high', title: 'Exfiltration to cloud storage not blocked', tech: 'T1567.002', tactic: 'Exfiltration', prevented: false, detected: true, assets: 6, first: '30 Sep', sla: 'Due in 9 days', slaState: 'ok', owner: 'Network team', status: 'Open', ticket: '', uplift: 1.1 },
    { id: 'F-1024', sev: 'high', title: 'Kerberoasting not detected', tech: 'T1558.003', tactic: 'Credential access', prevented: false, detected: false, assets: 1, assetLabel: 'Domain', first: '28 Sep', sla: 'Due in 12 days', slaState: 'ok', owner: 'Identity team', status: 'Open', ticket: '', uplift: 0.9 },
    { id: 'F-1019', sev: 'medium', title: 'Security event log clearing not alerted', tech: 'T1070.001', tactic: 'Defense evasion', prevented: false, detected: false, assets: 41, first: '24 Sep', sla: 'Due in 18 days', slaState: 'ok', owner: 'SOC', status: 'Open', ticket: '', uplift: 0.6 },
    { id: 'F-1016', sev: 'medium', title: 'Scheduled-task persistence detected late (22 min)', tech: 'T1053.005', tactic: 'Persistence', prevented: false, detected: true, assets: 17, first: '21 Sep', sla: 'Due in 21 days', slaState: 'ok', owner: 'SOC', status: 'In progress', ticket: 'SEC-2244', uplift: 0.4 },
    { id: 'F-1011', sev: 'medium', title: 'Remote-access software allowed outbound', tech: 'T1219', tactic: 'Command and control', prevented: false, detected: true, assets: 8, first: '18 Sep', sla: 'Due in 25 days', slaState: 'ok', owner: 'Network team', status: 'Open', ticket: '', uplift: 0.3 },
    { id: 'F-1003', sev: 'low', title: 'Domain trust discovery not detected', tech: 'T1482', tactic: 'Discovery', prevented: false, detected: false, assets: 1, assetLabel: 'Domain', first: '15 Sep', sla: 'Due in 40 days', slaState: 'ok', owner: 'SOC', status: 'Open', ticket: '', uplift: 0.2 },
    { id: 'F-0994', sev: 'high', title: 'Token impersonation not prevented', tech: 'T1134.001', tactic: 'Privilege escalation', prevented: true, detected: true, assets: 11, first: '3 Sep', sla: 'Closed 27 Oct', slaState: 'done', owner: 'Endpoint team', status: 'Verified fixed', ticket: 'SEC-2201', uplift: 0 }
  ],
  findingTotals: { critical: 12, high: 31, medium: 58, low: 44, breached: 3, mttr: '9.4 days', verified30d: 27 },

  endpoints: [
    { host: 'FIN-WS-023', os: 'Windows 11 23H2', group: 'Mumbai HQ · Finance', ip: '10.20.4.23', ver: '3.0.2', status: 'Online', seen: 'Just now', tested: '2 h ago', score: 54, tags: ['Finance', 'On attack path'] },
    { host: 'CBS-APP-01', os: 'RHEL 9.4', group: 'DC Navi Mumbai · Core banking', ip: '10.10.1.11', ver: '3.0.2', status: 'Running', seen: 'Just now', tested: 'Running now', score: 71, tags: ['Crown jewel'] },
    { host: 'CBS-DB-01', os: 'RHEL 9.4', group: 'DC Navi Mumbai · Core banking', ip: '10.10.1.21', ver: '3.0.2', status: 'Online', seen: '1 min ago', tested: '2 h ago', score: 79, tags: ['Crown jewel'] },
    { host: 'SWIFT-GW-01', os: 'Windows Server 2022', group: 'DC Navi Mumbai · SWIFT zone', ip: '10.10.9.5', ver: '3.0.2', status: 'Online', seen: 'Just now', tested: 'Yesterday', score: 83, tags: ['Crown jewel', 'SWIFT CSP'] },
    { host: 'DC01', os: 'Windows Server 2022', group: 'DC Navi Mumbai · Identity', ip: '10.10.0.10', ver: '3.0.2', status: 'Online', seen: 'Just now', tested: '2 h ago', score: 77, tags: ['Crown jewel'] },
    { host: 'FILESRV-02', os: 'Windows Server 2019', group: 'Mumbai HQ · Shared services', ip: '10.20.0.42', ver: '3.0.1', status: 'Online', seen: '2 min ago', tested: '2 h ago', score: 62, tags: ['On attack path'] },
    { host: 'FIN-WS-031', os: 'Windows 11 23H2', group: 'Mumbai HQ · Finance', ip: '10.20.4.31', ver: '3.0.2', status: 'Offline', seen: '3 days ago', tested: '4 days ago', score: 58, tags: ['Finance'] },
    { host: 'BR-PUNE-WS-112', os: 'Windows 10 22H2', group: 'Pune branch', ip: '10.40.2.112', ver: '2.9.4', status: 'Update', seen: '5 min ago', tested: '2 h ago', score: 66, tags: ['Branch'] },
    { host: 'BR-BLR-WS-087', os: 'Windows 11 23H2', group: 'Bengaluru branch', ip: '10.50.3.87', ver: '3.0.2', status: 'Quarantined', seen: '1 h ago', tested: 'Yesterday', score: 41, tags: ['Branch'] },
    { host: 'WEB-DMZ-03', os: 'Ubuntu 22.04 LTS', group: 'DC Navi Mumbai · DMZ', ip: '172.16.5.3', ver: '3.0.2', status: 'Online', seen: 'Just now', tested: '2 h ago', score: 81, tags: ['Internet-facing'] },
    { host: 'HR-WS-009', os: 'Windows 11 23H2', group: 'Mumbai HQ · HR', ip: '10.20.6.9', ver: '3.0.2', status: 'Online', seen: '4 min ago', tested: '2 h ago', score: 74, tags: [] },
    { host: 'DEV-MAC-014', os: 'macOS 14.6', group: 'Mumbai HQ · Engineering', ip: '10.20.8.14', ver: '3.0.2', status: 'Online', seen: '10 min ago', tested: '6 days ago', score: 88, tags: [] }
  ],

  /* Threat library — reusable scenarios */
  scenarios: [
    { id: 'SC-220', name: 'RansomEXX emulation', cat: 'Threat group', tactics: ['Impact', 'Defense evasion', 'Discovery'], tech: 22, os: ['Windows'], source: 'Audspect', updated: '12 Oct', runs: 48, safe: true },
    { id: 'SC-218', name: 'Lazarus Group — financial sector', cat: 'Threat group', tactics: ['Initial access', 'Credential access', 'Exfiltration'], tech: 31, os: ['Windows', 'Linux'], source: 'Audspect', updated: '12 Oct', runs: 16, safe: true },
    { id: 'SC-205', name: 'Ransomware readiness pack', cat: 'Scenario pack', tactics: ['Impact', 'Discovery', 'Credential access'], tech: 38, os: ['Windows'], source: 'Audspect', updated: '12 Oct', runs: 64, safe: true },
    { id: 'SC-181', name: 'Credential access sweep', cat: 'Technique set', tactics: ['Credential access'], tech: 14, os: ['Windows'], source: 'MITRE ATT&CK', updated: '28 Sep', runs: 54, safe: true },
    { id: 'SC-164', name: 'BFSI phishing & delivery', cat: 'Scenario pack', tactics: ['Initial access', 'Execution'], tech: 12, os: ['Windows'], source: 'Audspect', updated: '28 Sep', runs: 42, safe: true },
    { id: 'SC-150', name: 'Lateral movement essentials', cat: 'Technique set', tactics: ['Lateral movement', 'Discovery'], tech: 10, os: ['Windows'], source: 'MITRE ATT&CK', updated: '14 Sep', runs: 38, safe: true },
    { id: 'SC-142', name: 'Defense evasion catalogue', cat: 'Technique set', tactics: ['Defense evasion'], tech: 18, os: ['Windows'], source: 'MITRE ATT&CK', updated: '14 Sep', runs: 29, safe: true },
    { id: 'SC-120', name: 'Exfiltration channels', cat: 'Technique set', tactics: ['Exfiltration', 'Command and control'], tech: 9, os: ['Windows', 'Linux'], source: 'Audspect', updated: '5 Sep', runs: 31, safe: true },
    { id: 'SC-095', name: 'Data-destruction drill (safe)', cat: 'Scenario', tactics: ['Impact'], tech: 6, os: ['Windows'], source: 'Audspect', updated: '5 Sep', runs: 24, safe: true, note: 'Simulated only — never destroys data' },
    { id: 'SC-061', name: 'Custom: SWIFT zone checks', cat: 'Custom', tactics: ['Lateral movement', 'Collection'], tech: 7, os: ['Windows'], source: 'Contoso Bank', updated: '2 Oct', runs: 5, safe: true }
  ],
  libraryStats: { scenarios: 318, techniques: 92, actors: 13, custom: 6 },

  /* Purple-team exercises */
  exercises: [
    { id: 'PT-18', name: 'SOC detection drill — ransomware', when: 'In progress', red: 'Audspect automation', blue: 'SOC shift A', steps: 12, done: 7, detected: 5, mttd: '6m 20s' },
    { id: 'PT-17', name: 'Lazarus tabletop + live fire', when: '28 Oct', red: 'Purple team', blue: 'SOC + IR', steps: 16, done: 16, detected: 12, mttd: '8m 05s' },
    { id: 'PT-15', name: 'Insider exfiltration', when: '14 Oct', red: 'Red team', blue: 'SOC shift B', steps: 9, done: 9, detected: 5, mttd: '14m 40s' }
  ],
  exerciseSteps: [
    { t: '09:22', tech: 'T1566.001', name: 'Phishing attachment delivered', o: 'D', mttd: '2m 10s', who: 'SOC shift A' },
    { t: '09:31', tech: 'T1059.001', name: 'Script execution', o: 'D', mttd: '3m 05s', who: 'SOC shift A' },
    { t: '09:44', tech: 'T1003.001', name: 'Credential access attempt', o: 'M', mttd: '—', who: '—' },
    { t: '09:58', tech: 'T1021.002', name: 'Lateral movement', o: 'D', mttd: '5m 30s', who: 'SOC shift A' },
    { t: '10:12', tech: 'T1486', name: 'Encryption behaviour (simulated)', o: 'M', mttd: '—', who: '—' }
  ],

  /* Detection validation — expected vs fired, by source */
  detectionSources: [
    { name: 'Splunk Enterprise Security', kind: 'SIEM', expected: 184, fired: 118, missing: 66, mttd: '4m 40s', health: 'good' },
    { name: 'Microsoft Defender for Endpoint', kind: 'EDR', expected: 142, fired: 121, missing: 21, mttd: '2m 10s', health: 'good' },
    { name: 'Microsoft Sentinel', kind: 'SIEM', expected: 96, fired: 54, missing: 42, mttd: '7m 30s', health: 'warning' },
    { name: 'Network IDS', kind: 'Network', expected: 64, fired: 38, missing: 26, mttd: '3m 15s', health: 'good' }
  ],
  detectionRules: [
    { tech: 'T1003.001', name: 'LSASS access', rule: 'Credential dumping via LSASS', source: 'Splunk ES', status: 'Missing', note: 'No rule matched the test telemetry' },
    { tech: 'T1059.001', name: 'Encoded PowerShell', rule: 'Suspicious encoded command', source: 'Splunk ES', status: 'Fired late', note: 'Alerted after 11 min; tune the threshold' },
    { tech: 'T1021.002', name: 'SMB lateral movement', rule: 'Admin share access', source: 'Defender', status: 'Fired', note: 'Alert in 3m 40s' },
    { tech: 'T1486', name: 'Mass file change', rule: 'Ransomware canary', source: 'Defender', status: 'Fired', note: 'Alert in 1m 05s' },
    { tech: 'T1490', name: 'Shadow-copy deletion', rule: 'Volume shadow tampering', source: 'Sentinel', status: 'Missing', note: 'Rule disabled in content pack' },
    { tech: 'T1070.001', name: 'Event-log clearing', rule: 'Security log cleared', source: 'Sentinel', status: 'Fired', note: 'Alert in 6m 20s' }
  ],

  /* Threat intel — IOCs and KEV */
  iocs: [
    { type: 'Hash', value: 'a1b2c3…9f0e', kind: 'SHA-256', actor: 'RansomEXX', added: '12 Oct', source: 'MISP', hits: 0 },
    { type: 'Domain', value: 'update-svc.example', kind: 'C2', actor: 'Lazarus Group', added: '11 Oct', source: 'OpenCTI', hits: 2 },
    { type: 'IP', value: '203.0.113.44', kind: 'C2', actor: 'FIN7', added: '9 Oct', source: 'OTX', hits: 0 },
    { type: 'Hash', value: 'd4e5f6…1a2b', kind: 'SHA-256', actor: 'LockBit 3.0', added: '7 Oct', source: 'MISP', hits: 1 },
    { type: 'Domain', value: 'cdn-assets.example', kind: 'Phishing', actor: 'APT41', added: '5 Oct', source: 'CERT-In', hits: 0 }
  ],
  iocStats: { total: 1842, matchedInSim: 38, feeds: 4, stale: 1 },
  kev: [
    { cve: 'CVE-2024-3400', product: 'Perimeter gateway', ransomware: true, assets: 2, status: 'Patched', sim: 'Prevented' },
    { cve: 'CVE-2023-34362', product: 'File-transfer app', ransomware: true, assets: 1, status: 'Mitigated', sim: 'Prevented' },
    { cve: 'CVE-2021-44228', product: 'Java logging (Log4j)', ransomware: false, assets: 4, status: 'Patched', sim: 'Prevented' },
    { cve: 'CVE-2023-23397', product: 'Mail client', ransomware: false, assets: 11, status: 'Open', sim: 'Detected only' },
    { cve: 'CVE-2022-30190', product: 'Office (Follina)', ransomware: false, assets: 6, status: 'Open', sim: 'Missed' }
  ],
  testNext: [
    { tech: 'T1558.003', name: 'Kerberoasting', why: 'Used by 3 groups in your profile · never tested', priority: 'High', kev: false },
    { tech: 'T1197', name: 'BITS jobs', why: 'KEV-linked tooling · last tested 90+ days', priority: 'High', kev: true },
    { tech: 'T1546.015', name: 'COM hijacking', why: 'Gap in persistence coverage', priority: 'Medium', kev: false },
    { tech: 'T1609', name: 'Container admin command', why: 'New in your environment', priority: 'Medium', kev: false }
  ],

  /* Remediation */
  initiatives: [
    { id: 'IN-04', name: 'Credential-theft hardening', owner: 'Endpoint team', findings: 6, done: 2, due: '15 Nov', uplift: 6.4, status: 'On track' },
    { id: 'IN-03', name: 'Network segmentation (tier 0)', owner: 'Infrastructure', findings: 9, done: 3, due: '30 Nov', uplift: 5.1, status: 'At risk' },
    { id: 'IN-02', name: 'Ransomware resilience', owner: 'Server team', findings: 5, done: 4, due: '10 Nov', uplift: 3.8, status: 'On track' },
    { id: 'IN-01', name: 'SIEM detection coverage', owner: 'SOC', findings: 12, done: 7, due: '22 Nov', uplift: 4.4, status: 'On track' }
  ],
  slaBySeverity: [
    { sev: 'Critical', target: '7 days', onTime: 9, late: 3, rate: 75 },
    { sev: 'High', target: '14 days', onTime: 24, late: 4, rate: 86 },
    { sev: 'Medium', target: '30 days', onTime: 46, late: 6, rate: 88 },
    { sev: 'Low', target: '90 days', onTime: 40, late: 2, rate: 95 }
  ],
  slaTrend: [78, 79, 80, 82, 81, 83, 85, 87],

  /* Integrations */
  integrations: [
    { name: 'Splunk Enterprise Security', kind: 'SIEM', status: 'good', detail: 'Last event 28 s ago · 184 detections mapped', since: 'Connected May 2026' },
    { name: 'Microsoft Defender for Endpoint', kind: 'EDR / EPP', status: 'good', detail: 'Last verdict 1 min ago · response actions enabled', since: 'Connected May 2026' },
    { name: 'Microsoft Sentinel', kind: 'SIEM', status: 'warning', detail: '42 expected detections not firing — review content pack', since: 'Connected Jul 2026' },
    { name: 'ServiceNow', kind: 'ITSM', status: 'good', detail: '12 tickets synced today', since: 'Connected Jun 2026' },
    { name: 'MISP', kind: 'Threat intel', status: 'warning', detail: 'Last sync 3 days ago — import the next offline bundle', since: 'Connected May 2026' },
    { name: 'OpenCTI', kind: 'Threat intel', status: 'good', detail: 'Synced 2 h ago', since: 'Connected Aug 2026' },
    { name: 'TAXII — CERT-In feed', kind: 'Threat intel', status: 'good', detail: 'Polled this morning', since: 'Connected Apr 2026' },
    { name: 'Caldera', kind: 'Engine', status: 'good', detail: 'Adversary engine healthy', since: 'Bundled' },
    { name: 'CrowdStrike Falcon', kind: 'EDR / EPP', status: 'off', detail: 'Available — not configured', since: '' },
    { name: 'Jira', kind: 'ITSM', status: 'off', detail: 'Available — not configured', since: '' }
  ],

  /* Users (settings) */
  users: [
    { name: 'Priya Nair', email: 'ciso@contoso.example', role: 'Admin', mfa: true, last: 'Just now' },
    { name: 'Rahul Iyer', email: 'r.iyer@contoso.example', role: 'Analyst', mfa: true, last: '10 min ago' },
    { name: 'Aisha Khan', email: 'a.khan@contoso.example', role: 'Analyst', mfa: true, last: '2 h ago' },
    { name: 'SOC shift (shared)', email: 'soc@contoso.example', role: 'Viewer', mfa: true, last: 'Yesterday' },
    { name: 'Internal audit', email: 'audit@contoso.example', role: 'Auditor', mfa: false, last: '3 days ago' }
  ],
  auditLog: [
    { t: 'Today 09:40', who: 'Schedule', action: 'Assessment completed', detail: 'Weekly BFSI threat pack (A-3318)' },
    { t: 'Today 08:00', who: 'Schedule', action: 'Report delivered', detail: 'Board scorecard → CISO, CRO' },
    { t: 'Today 07:12', who: 'r.iyer', action: 'Finding status changed', detail: 'F-1042 → In progress' },
    { t: 'Yesterday 18:30', who: 'a.khan', action: 'Assessment started', detail: 'Lazarus Group emulation (A-3309)' },
    { t: 'Yesterday 11:05', who: 'ciso', action: 'Role changed', detail: 'audit@contoso.example → Auditor' }
  ],

  rbiControls: [
    { id: 'RBI-CSF-04', name: 'Preventing execution of unauthorised software', tech: ['T1204', 'T1059', 'T1218'], status: 'Pass', tests: 128, last: '2 h ago' },
    { id: 'RBI-CSF-07', name: 'User access control / management', tech: ['T1078', 'T1134', 'T1548'], status: 'Partial', tests: 64, last: '2 h ago' },
    { id: 'RBI-CSF-09', name: 'Advanced real-time threat defence and management', tech: ['T1003', 'T1055', 'T1562'], status: 'Fail', tests: 96, last: '2 h ago' },
    { id: 'RBI-CSF-11', name: 'Anti-phishing', tech: ['T1566'], status: 'Pass', tests: 42, last: 'Yesterday' },
    { id: 'RBI-CSF-12', name: 'Data leak prevention strategy', tech: ['T1567', 'T1048', 'T1041'], status: 'Partial', tests: 38, last: '2 h ago' },
    { id: 'RBI-CSF-13', name: 'Maintenance, monitoring and analysis of audit logs', tech: ['T1070', 'T1562.002'], status: 'Partial', tests: 51, last: '3 days ago' },
    { id: 'RBI-CSF-15', name: 'Network management and security', tech: ['T1021', 'T1570', 'T1046'], status: 'Fail', tests: 72, last: '2 h ago' },
    { id: 'RBI-CSF-17', name: 'Removable media', tech: ['T1091', 'T1052'], status: 'Not tested', tests: 0, last: '—' },
    { id: 'RBI-CSF-19', name: 'Backup and recovery', tech: ['T1490', 'T1485'], status: 'Fail', tests: 24, last: 'Yesterday' },
    { id: 'RBI-CSF-21', name: 'Incident response and management', tech: ['MTTD ≤ 15 min'], status: 'Pass', tests: 1284, last: '2 h ago' }
  ]
};
