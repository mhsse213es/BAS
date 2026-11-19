// Scenario catalogue aligned with the real console: 12 real categories, Built-in / Custom / Threat intel sources,
// and availability states. Mutates D.SCENARIOS in place (other modules already captured it).
(() => {
D.CATEGORIES = [
  ['all', 'All Scenarios', 'layers', 119], ['antivirus', 'Antivirus', 'shield', 30], ['network', 'Network', 'globe', 3], ['email', 'Email', 'mail', 1],
  ['dlp', 'DLP', 'lock', 15], ['phishing', 'Phishing', 'flag', 44], ['killchain', 'Kill Chain', 'path', 9], ['ransomware', 'Ransomware', 'alert', 14],
  ['cloud', 'Cloud', 'cloud', 2], ['adbas', 'AD BAS', 'key', 9], ['dbsim', 'DB Simulation', 'db', 11], ['frameworks', 'Simulation Frameworks', 'box', 25], ['templates', 'Adversary Templates', 'user', 7]];
const remap = { 'SC-0412': 'adbas', 'SC-0398': 'adbas', 'SC-0377': 'ransomware', 'SC-0391': 'antivirus', 'SC-0355': 'killchain', 'SC-0362': 'killchain', 'SC-0340': 'frameworks', 'SC-0318': 'frameworks', 'SC-0305': 'dlp', 'SC-0291': 'cloud', 'SC-0274': 'email', 'SC-0260': 'network' };
const rename = { 'SC-0318': 'Caldera Lateral Movement Scenario', 'SC-0305': 'DLP Exfiltration Validation — SMTP Channel', 'SC-0291': 'Cloud VM Attack — Azure/AWS Instance Metadata Token Theft', 'SC-0260': 'Windows Host Firewall Exposure Posture (Lateral Management Ports)' };
D.SCENARIOS.forEach(s => { s.cat = remap[s.id] || s.cat; if (rename[s.id]) s.name = rename[s.id]; s.source = 'Built-in'; s.avail = 'ok'; });
D.SCENARIOS.find(s => s.id === 'SC-0355').source = 'Threat intel';
let n = 500;
const mk = (cat, name, os, tactic, techs, mins, desc, o = {}) => D.SCENARIOS.push({ id: 'SC-' + (n++).toString().padStart(4, '0'), name, desc, source: o.source || 'Built-in', os, product: o.product || 'Endpoint / EDR', tactic, tier: o.tier || ['Core', 'Advanced'], status: 'Active', techniques: techs.length, mins, sig: 'Signed v1', cat, tech: techs, tacticTag: tactic, avail: o.avail || 'ok' });
mk('antivirus', 'AV/NGAV Assessment', 'Windows', 'Defense Evasion', ['T1562.001', 'T1027', 'T1059.001'], 30, 'Validates signature, behavioural and cloud-lookup protection of the installed AV/NGAV.');
mk('antivirus', 'Endpoint Mastery 03 — Memory-Based Attacks', 'Windows', 'Execution', ['T1055', 'T1620'], 25, 'Reflective loading and process injection against memory protections.');
mk('antivirus', 'Endpoint Mastery 06 — Defense Evasion & LOLBin Execution', 'Windows', 'Defense Evasion', ['T1218.011', 'T1218.005'], 22, 'Living-off-the-land binaries used to evade application control.');
mk('network', 'Network Egress Control Validation', 'Linux', 'Command and Control', ['T1071.001', 'T1095'], 18, 'Tests outbound filtering for non-standard ports and protocols.', { product: 'Network' });
mk('network', 'Sink-Verified HTTPS Beaconing', 'Windows', 'Command and Control', ['T1071.001', 'T1573'], 15, 'Beacon-style HTTPS traffic to a verified sink.', { product: 'Network' });
mk('dlp', 'DLP Exfiltration Validation — Cloud Storage Channels', 'Windows', 'Exfiltration', ['T1567.002'], 20, 'Synthetic regulated data pushed to cloud-storage channels.', { product: 'Data Security' });
mk('dlp', 'DLP Exfiltration Validation — DNS Tunneling Channel', 'Linux', 'Exfiltration', ['T1048.003', 'T1071.004'], 20, 'Encoded payloads over DNS queries.', { product: 'Data Security' });
mk('dlp', 'DLP Exfiltration Validation — Generative-AI Channels', 'Windows', 'Exfiltration', ['T1567'], 16, 'Sensitive strings posted to public generative-AI endpoints.', { product: 'Data Security' });
const ph = [['Credential-harvest landing page (link click)', 'ok'], ['Malicious attachment — macro document', 'ok'], ['QR-code lure', 'ok'], ['MFA fatigue prompt bombing', 'identity'], ['OAuth consent phishing', 'identity'], ['Reply-chain hijack', 'cat'], ['Executive impersonation (BEC)', 'cat'], ['Voice phishing callback (vishing)', 'cat'], ['Experimental — AI-generated lure', 'exp']];
ph.forEach(([nm, a]) => mk('phishing', 'Phishing — ' + nm, 'Cross-Platform', 'Initial Access', ['T1566.001', 'T1566.002'], 12, 'Phishing simulation for user and mail-control validation.', { product: 'Email', avail: a }));
mk('killchain', 'FIN7 Kill Chain — BFSI Financial Sector Targeting', 'Windows', 'Initial Access', ['T1566', 'T1059.001', 'T1547.001', 'T1003'], 55, 'Campaign-grade emulation of FIN7 tradecraft.', { source: 'Threat intel', tier: ['Advanced', 'Enterprise'] });
mk('killchain', 'Volt Typhoon — Living-off-the-Land Kill Chain', 'Windows', 'Discovery', ['T1087', 'T1018', 'T1047', 'T1021.002'], 50, 'Living-off-the-land intrusion pattern with minimal tooling.', { source: 'Threat intel', tier: ['Advanced', 'Enterprise'] });
mk('killchain', 'Scattered Spider Kill Chain — Social Engineering + Insider Escalation', 'Cross-Platform', 'Initial Access', ['T1566', 'T1078', 'T1621'], 60, 'Help-desk social engineering through to privileged access.', { source: 'Threat intel', tier: ['Advanced', 'Enterprise'] });
mk('ransomware', 'LockBit Kill Chain — Ransomware Emulation (Phase 7)', 'Windows', 'Impact', ['T1486', 'T1490', 'T1489', 'T1562'], 45, 'Safe encryption and recovery-inhibition emulation.', { source: 'Threat intel', tier: ['Advanced', 'Enterprise'] });
mk('ransomware', 'BlackCat/ALPHV Kill Chain — Ransomware Emulation', 'Windows', 'Impact', ['T1486', 'T1490'], 45, 'ALPHV-style staging, encryption and extortion prep.', { source: 'Threat intel' });
mk('ransomware', 'Linux Ransomware Drill — LVM Snapshot and File-Encryption Validation', 'Linux', 'Impact', ['T1486', 'T1490'], 35, 'Snapshot protection and encryption-behaviour checks on Linux.');
mk('cloud', 'Entra ID / M365 Hybrid Identity Attack — Token Theft and Session Theft', 'Cloud', 'Credential Access', ['T1528', 'T1539', 'T1556.007'], 40, 'Hybrid identity bridge exposure and token abuse.', { product: 'Identity & Access', avail: 'identity' });
mk('adbas', 'DCSync Replication-Rights Exposure Audit', 'Windows', 'Credential Access', ['T1003.006'], 15, 'Reports which principals hold replication rights.', { product: 'Identity & Access' });
mk('adbas', 'Kerberoasting & Active Directory Credential Theft Drill', 'Windows', 'Credential Access', ['T1558.003', 'T1558.004'], 25, 'SPN enumeration and ticket requests against a lab domain.', { product: 'Identity & Access' });
[['01', 'Authentication Policy Check'], ['02', 'Excessive Grants Against Policy'], ['03', 'Unauthorized Table Access Attempt'], ['04', 'Audit Coverage Check']].forEach(([i, nm]) => mk('dbsim', `Database Security Simulation DB-${i} — ${nm}`, 'Cross-Platform', 'Collection', ['T1213'], 12, 'Safe database control validation against PostgreSQL and MySQL.', { product: 'Application Security' }));
mk('frameworks', 'Atomic Red Team — Full Windows Sweep', 'Windows', 'Execution', ['T1059.001', 'T1053.005', 'T1547.001'], 90, 'Runs the full Atomic Red Team Windows library.', { tier: ['Enterprise'] });
mk('frameworks', 'Atomic Red Team — Selective Linux Capabilities', 'Linux', 'Persistence', ['T1053.003', 'T1098.004'], 40, 'Selected Linux atomics by capability.');
mk('templates', 'Adversary Template — APT29 (Cozy Bear)', 'Windows', 'Initial Access', ['T1566', 'T1078'], 30, 'Reusable adversary template; compose into your own scenarios.', { source: 'Custom' });
mk('templates', 'Adversary Template — Akira', 'Windows', 'Impact', ['T1486', 'T1490'], 30, 'Reusable adversary template for ransomware crews.', { source: 'Custom' });
})();
