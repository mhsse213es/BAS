// Dummy-data overrides, group a: { 'GET /api/path': value | (url) => value }
// Fictional data for a bank / insurer security team. Shapes follow the real loaders in src/features.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const DAY = 1440;

// ── identity / tamper ───────────────────────────────────────────────────────
const ME = { username: 'asha.nair', role: 'admin', isActive: true, createdAt: iso(300 * DAY), lastLogin: iso(95), authSource: 'local' };
const TAMPER = [
  { id: 'tp-1', path: 'C:\\Program Files\\Audspect\\agent\\agent-config.signed.json', eventType: 'modified', hostname: 'WS-FIN-0143', createdAt: iso(42), acknowledged: false },
  { id: 'tp-2', path: '/opt/audspect/agent/bin/audspect-agent', eventType: 'replaced', hostname: 'lnx-web-08', createdAt: iso(17), acknowledged: false },
];

// ── agent groups (ids are referenced by campaigns and scheduled assessments) ─
const GROUPS = [
  { id: 1, name: 'Finance Workstations', parentId: null, agentCount: 2, totalAgentCount: 3, children: [
    { id: 7, name: 'HR Workstations', parentId: 1, agentCount: 1, totalAgentCount: 1, children: [] },
  ] },
  { id: 2, name: 'Domain Controllers', parentId: null, agentCount: 3, totalAgentCount: 3, children: [] },
  { id: 3, name: 'File Servers', parentId: null, agentCount: 1, totalAgentCount: 1, children: [] },
  { id: 4, name: 'Linux Web Tier', parentId: null, agentCount: 2, totalAgentCount: 2, children: [] },
  { id: 5, name: 'Payments DB', parentId: null, agentCount: 1, totalAgentCount: 1, children: [] },
  { id: 6, name: 'Executive Laptops', parentId: null, agentCount: 2, totalAgentCount: 2, children: [] },
];

// ── campaigns ───────────────────────────────────────────────────────────────
function campaign(id, name, scenarioName, over, summary, runs, skips) {
  return {
    id, name, scenarioName, description: '', mode: 'posture', targetType: 'group', targetGroupId: 1, createdBy: 'asha.nair',
    createdAt: iso(100), updatedAt: iso(60), startedAt: iso(100), scenarioIds: [], steps: [], targets: [],
    ...over, summary, runs, skips: skips || [],
  };
}
const CAMPAIGNS = [
  campaign('camp-2026-1041', 'Q4 ransomware readiness', 'Ransomware: Shadow Copy Deletion', { targetType: 'all', startedAt: iso(2 * DAY + 90), createdBy: 'asha.nair' },
    { status: 'running', paused: true, prevented: 21, detected: 9, missed: 6, dispatched: 9, targets: 12, skipped: 1, progress: 75 },
    [
      { status: 'completed', agentId: 'a-1', preventionScore: 83, runId: 'run-1' }, { status: 'completed', agentId: 'a-2', preventionScore: 71, runId: 'run-2' },
      { status: 'running', agentId: 'a-3', preventionScore: 0, runId: 'run-3', paused: true }, { status: 'completed', agentId: 'a-5', preventionScore: 64, runId: 'run-4' },
      { status: 'completed', agentId: 'a-6', preventionScore: 88, runId: 'run-5' }, { status: 'failed', agentId: 'a-7', preventionScore: 0, runId: 'run-6' },
    ], [{ agentId: 'a-9', reason: 'offline for more than 24 hours' }]),
  campaign('camp-2026-1038', 'Domain controller hardening check', 'DCSync Replication Abuse', { targetGroupId: 2, startedAt: iso(4 * DAY), createdBy: 'rohan.kulkarni', mode: 'telemetry' },
    { status: 'completed', paused: false, prevented: 14, detected: 4, missed: 3, dispatched: 3, targets: 3, skipped: 0, progress: 100 },
    [{ status: 'completed', agentId: 'a-3', preventionScore: 74, runId: 'run-7' }, { status: 'completed', agentId: 'a-4', preventionScore: 69, runId: 'run-8' }, { status: 'completed', agentId: 'a-12', preventionScore: 81, runId: 'run-9' }]),
  campaign('camp-2026-1035', 'Branch office endpoint sweep', 'Persistence via Run Key', { targetGroupId: 1, startedAt: iso(6 * DAY), createdBy: 'asha.nair' },
    { status: 'partial', paused: false, prevented: 11, detected: 2, missed: 5, dispatched: 3, targets: 3, skipped: 0, progress: 100 },
    [{ status: 'completed', agentId: 'a-1', preventionScore: 58, runId: 'run-10' }, { status: 'completed', agentId: 'a-2', preventionScore: 62, runId: 'run-11' }, { status: 'failed', agentId: 'a-11', preventionScore: 0, runId: 'run-12' }]),
  campaign('camp-2026-1029', 'Payments DB lateral movement', 'Kerberoasting', { targetGroupId: 5, startedAt: iso(9 * DAY), createdBy: 'rohan.kulkarni' },
    { status: 'completed', paused: false, prevented: 6, detected: 1, missed: 1, dispatched: 1, targets: 1, skipped: 0, progress: 100 },
    [{ status: 'completed', agentId: 'a-8', preventionScore: 75, runId: 'run-13' }]),
  campaign('camp-2026-1024', 'Executive laptop phishing follow-through', 'Office Child Process Execution', { targetGroupId: 6, startedAt: iso(12 * DAY), createdBy: 'meera.iyer' },
    { status: 'stopped', paused: false, prevented: 3, detected: 0, missed: 2, dispatched: 1, targets: 2, skipped: 1, progress: 50 },
    [{ status: 'completed', agentId: 'a-9', preventionScore: 60, runId: 'run-14' }], [{ agentId: 'a-10', reason: 'stopped by operator before dispatch' }]),
  campaign('camp-2026-1017', 'Linux web tier exfiltration drill', 'DNS Tunnelling Exfiltration', { targetGroupId: 4, startedAt: iso(15 * DAY), createdBy: 'asha.nair', mode: 'telemetry' },
    { status: 'failed', paused: false, prevented: 0, detected: 0, missed: 0, dispatched: 2, targets: 2, skipped: 0, progress: 100 },
    [{ status: 'failed', agentId: 'a-6', preventionScore: 0, runId: 'run-15' }, { status: 'failed', agentId: 'a-7', preventionScore: 0, runId: 'run-16' }]),
];

// ── compliance ──────────────────────────────────────────────────────────────
function fw(frameworkId, frameworkName, shortName, regulator, totalControls, testableControls, testedControls, passingControls) {
  return {
    frameworkId, frameworkName, shortName, regulator, enrolledAgentCount: 12, totalControls, testableControls, testedControls, passingControls,
    failingControls: testedControls - passingControls, untestedControls: testableControls - testedControls,
    compliancePct: Math.round((passingControls / testedControls) * 1000) / 10, coveragePct: Math.round((testedControls / testableControls) * 1000) / 10,
  };
}
const COMPLIANCE = [
  fw('sebi-cscrf', 'SEBI Cybersecurity and Cyber Resilience Framework', 'SEBI CSCRF', 'SEBI', 96, 58, 46, 34),
  fw('rbi-csf', 'RBI Cyber Security Framework for Banks', 'RBI CSF', 'RBI', 118, 72, 61, 49),
  fw('irdai-iscg', 'IRDAI Information and Cyber Security Guidelines', 'IRDAI', 'IRDAI', 84, 50, 36, 22),
  fw('cert-in', 'CERT-In Directions (28 April 2022)', 'CERT-In', 'CERT-In', 24, 14, 12, 10),
  fw('iso-27001', 'ISO/IEC 27001:2022 Annex A', 'ISO 27001', 'ISO', 93, 61, 52, 41),
  fw('nist-csf', 'NIST Cybersecurity Framework 2.0', 'NIST CSF', 'NIST', 106, 68, 57, 43),
];

// ── ITSM / endpoint posture / threat intel ──────────────────────────────────
const TICKETING = { openTickets: 12, resolvedTickets: 29, pendingRevalidation: 5, byProvider: [{ provider: 'ServiceNow', count: 31 }, { provider: 'Jira', count: 15 }] };
const POSTURE = {
  totalAgents: 12, onlineAgents: 11, offlineAgents: 1, activeAgents: 11, restrictedAgents: 1, quarantinedAgents: 0, retiredAgents: 1,
  untrustedBinaryCount: 1, currentlyIsolated: 1,
};
const TI_SUMMARY = {
  topActors: [
    { actorName: 'FIN7', tier: 'Critical', score: 91 }, { actorName: 'APT29', tier: 'High', score: 84 },
    { actorName: 'Scattered Spider', tier: 'High', score: 79 }, { actorName: 'LockBit 3.0', tier: 'Medium', score: 63 },
  ],
};
const TI_TECH = (n, tactics) => Array.from({ length: n }, (_, i) => ({ techniqueId: `T${1000 + i * 17}`, tactic: tactics[i % tactics.length] }));
const PACKS = {
  kev: { packName: 'CISA KEV Exploited Techniques', description: 'Techniques linked to CVEs on the CISA Known Exploited Vulnerabilities catalogue that are relevant to the enrolled fleet.', techniqueCount: 27, totalKevCves: 143, ransomwareCount: 9, tactics: ['Initial Access', 'Execution', 'Privilege Escalation', 'Defense Evasion', 'Lateral Movement'] },
  ransomware: { packName: 'Ransomware Operator Playbook', description: 'Pre-encryption behaviours common across current ransomware affiliates: discovery, credential theft, backup inhibition.', techniqueCount: 19, totalKevCves: 38, ransomwareCount: 19, tactics: ['Discovery', 'Credential Access', 'Impact', 'Defense Evasion'] },
  apt: { packName: 'Targeted Financial-Sector Intrusion', description: 'Techniques attributed to groups that target banks and insurers, ordered by relevance to the fleet.', techniqueCount: 23, totalKevCves: 51, ransomwareCount: 4, tactics: ['Initial Access', 'Persistence', 'Credential Access', 'Collection', 'Exfiltration'] },
};
function suggestPack(u) {
  const type = u.searchParams.get('type') || 'kev';
  const p = PACKS[type] || PACKS.kev;
  return {
    hasData: true, packName: p.packName, description: p.description, techniqueCount: p.techniqueCount, totalKevCves: p.totalKevCves,
    ransomwareCount: p.ransomwareCount, techniques: TI_TECH(p.techniqueCount, p.tactics), suggestedName: `${p.packName} (Oct 2026)`,
    suggestedId: `ti-${type}-2026-10`, suggestedScenario: { id: `ti-${type}-2026-10`, name: `${p.packName} (Oct 2026)`, steps: [] },
  };
}
const READINESS = {
  total: 7,
  trends: [
    { actorName: 'FIN7', latestPrevention: 58, direction: 'down', preventionDelta: -6.5, dataPoints: 5 },
    { actorName: 'Scattered Spider', latestPrevention: 49, direction: 'down', preventionDelta: -3.2, dataPoints: 4 },
    { actorName: 'APT29', latestPrevention: 72, direction: 'up', preventionDelta: 8.1, dataPoints: 5 },
    { actorName: 'LockBit 3.0', latestPrevention: 81, direction: 'up', preventionDelta: 4.7, dataPoints: 5 },
    { actorName: 'Lazarus Group', latestPrevention: 66, direction: 'up', preventionDelta: 2.4, dataPoints: 3 },
    { actorName: 'APT41', latestPrevention: 69, direction: 'flat', preventionDelta: 0, dataPoints: 3 },
    { actorName: 'Cl0p', latestPrevention: 77, direction: 'flat', preventionDelta: 0, dataPoints: 2 },
  ],
};

// ── run report.json (run-1 .. run-6) ────────────────────────────────────────
const KC = {
  cred: [
    ['execution', 'T1059', 'Command and Scripting Interpreter', 'Launched encoded PowerShell', 'prevented', 'Blocked by AMSI / script policy'],
    ['credential-access', 'T1003', 'OS Credential Dumping', 'Opened handle to LSASS memory', 'detected', 'EDR alert raised, process not terminated', 'high', 12000],
    ['credential-access', 'T1558', 'Steal or Forge Kerberos Tickets', 'Requested service tickets for SPNs', 'missed', ''],
    ['lateral-movement', 'T1021', 'Remote Services', 'Attempted SMB admin share logon', 'prevented', 'Blocked by host firewall rule'],
  ],
  ransom: [
    ['discovery', 'T1083', 'File and Directory Discovery', 'Enumerated user document folders', 'detected', 'Behavioural alert on mass enumeration', 'medium', 31000],
    ['defense-evasion', 'T1562', 'Impair Defenses', 'Attempted to disable real-time protection', 'prevented', 'Tamper protection held'],
    ['impact', 'T1490', 'Inhibit System Recovery', 'Deleted volume shadow copies', 'missed', ''],
    ['impact', 'T1486', 'Data Encrypted for Impact', 'Encrypted canary files', 'detected', 'Canary file alert', 'high', 8000],
  ],
  persist: [
    ['persistence', 'T1547', 'Boot or Logon Autostart Execution', 'Wrote HKCU Run key value', 'detected', 'Registry modification alert', 'medium', 22000],
    ['persistence', 'T1053', 'Scheduled Task/Job', 'Registered a logon scheduled task', 'missed', ''],
    ['defense-evasion', 'T1112', 'Modify Registry', 'Changed Run key permissions', 'prevented', 'Blocked by application control'],
  ],
};
function report(kind, i) {
  const kc = KC[kind].map(([phase, techniqueId, technique, action, outcome, detail, confidence, latencyMs]) => ({ phase, techniqueId, technique, action, outcome, detail, confidence, latencyMs }));
  const prevented = kc.filter((s) => s.outcome === 'prevented').length;
  const detected = kc.filter((s) => s.outcome === 'detected').length;
  const total = kc.length;
  const detRate = Math.round((detected / (total - prevented || 1)) * 100);
  return {
    killChain: kc,
    alertsTotal: 14 + i * 3, alertsHighFidelity: 3 + (i % 3), noiseScore: 38 + i * 6,
    attackSurfaceAge: 11 + i * 4, oldestFindingID: `finding-${i + 3}`, oldestFindingName: kc[kc.length - 1].technique, oldestFindingSeverity: 'High',
    attackSurfaceSLAStatus: i % 3 === 0 ? 'over-sla' : 'within-sla',
    perfCpuBefore: 2.4, perfCpuAfter: 3.1, perfRamBefore: 5.1, perfRamAfter: 5.2, perfDiskBefore: 61.2, perfDiskAfter: 61.3,
    envRestoration: { impactLevel: 'clean', statusLabel: 'Successful', impactLabel: 'No Persistent Changes', cleanupRate: 100, stepsLeaked: 0, stepsCleaned: total, stepsRescued: 0, execSummary: 'All simulation-induced changes were reverted successfully.', leakedItems: [] },
    summary: { detectionRate: detRate, undetectedRate: 100 - detRate, logged: 0, loggedRate: 0, mttdMs: 17000 },
    detectionTechniques: kc.filter((s) => s.outcome !== 'missed').map((s) => ({ techniqueId: s.techniqueId, verdict: s.outcome, confidence: s.confidence, timeToDetectMs: s.latencyMs })).concat(kc.filter((s) => s.outcome === 'missed').map((s) => ({ techniqueId: s.techniqueId, verdict: 'undetected' }))),
    detectionSources: [{ product: 'Microsoft Defender for Endpoint', detections: detected, minMttdMs: 8000, avgMttdMs: 17000 }],
    detectionValidation: {
      hasData: true, expected: total, verified: total - prevented, detected, coverage: Math.round((detected / total) * 100),
      rows: kc.map((s) => ({ techniqueId: s.techniqueId, status: s.outcome === 'missed' ? 'NotDetected' : s.outcome === 'detected' ? 'Detected' : 'NotApplicable', provider: s.outcome === 'detected' ? 'Defender' : '', domain: 'endpoint' })),
    },
    topFindings: kc.filter((s) => s.outcome === 'missed').map((s) => ({
      severity: 'High', techniqueId: s.techniqueId, techniqueName: s.technique, tactic: s.phase,
      details: `${s.action} completed without a prevention or detection response on the tested endpoint.`,
      remediation: `Add a detection rule for ${s.technique} and review the endpoint policy that should have blocked it.`,
    })),
    recommendations: [
      'Enable LSASS protection (RunAsPPL) on all Windows servers in the Domain Controllers group.',
      'Alert on volume shadow copy deletion from non-backup processes and route it to the SOC queue.',
      'Restrict creation of logon scheduled tasks to approved administrative accounts.',
    ],
  };
}
const REPORTS = {};
['cred', 'cred', 'ransom', 'ransom', 'persist', 'persist'].forEach((kind, i) => { REPORTS[`GET /api/scenarios/runs/run-${i + 1}/report.json`] = report(kind, i); });

// ── ATT&CK coverage ─────────────────────────────────────────────────────────
const TACTICS = [
  ['Initial Access', [['T1566', 'Phishing'], ['T1190', 'Exploit Public-Facing Application'], ['T1078', 'Valid Accounts'], ['T1133', 'External Remote Services']]],
  ['Execution', [['T1059', 'Command and Scripting Interpreter'], ['T1047', 'Windows Management Instrumentation'], ['T1204', 'User Execution'], ['T1053', 'Scheduled Task/Job']]],
  ['Persistence', [['T1547', 'Boot or Logon Autostart Execution'], ['T1543', 'Create or Modify System Process'], ['T1136', 'Create Account'], ['T1505', 'Server Software Component']]],
  ['Privilege Escalation', [['T1068', 'Exploitation for Privilege Escalation'], ['T1055', 'Process Injection'], ['T1134', 'Access Token Manipulation'], ['T1548', 'Abuse Elevation Control Mechanism']]],
  ['Defense Evasion', [['T1562', 'Impair Defenses'], ['T1070', 'Indicator Removal'], ['T1027', 'Obfuscated Files or Information'], ['T1218', 'System Binary Proxy Execution'], ['T1112', 'Modify Registry']]],
  ['Credential Access', [['T1003', 'OS Credential Dumping'], ['T1558', 'Steal or Forge Kerberos Tickets'], ['T1110', 'Brute Force'], ['T1555', 'Credentials from Password Stores']]],
  ['Discovery', [['T1082', 'System Information Discovery'], ['T1087', 'Account Discovery'], ['T1018', 'Remote System Discovery'], ['T1083', 'File and Directory Discovery']]],
  ['Lateral Movement', [['T1021', 'Remote Services'], ['T1550', 'Use Alternate Authentication Material'], ['T1570', 'Lateral Tool Transfer']]],
  ['Collection', [['T1005', 'Data from Local System'], ['T1560', 'Archive Collected Data'], ['T1114', 'Email Collection']]],
  ['Command and Control', [['T1071', 'Application Layer Protocol'], ['T1572', 'Protocol Tunneling'], ['T1105', 'Ingress Tool Transfer']]],
  ['Exfiltration', [['T1041', 'Exfiltration Over C2 Channel'], ['T1048', 'Exfiltration Over Alternative Protocol'], ['T1567', 'Exfiltration Over Web Service']]],
  ['Impact', [['T1486', 'Data Encrypted for Impact'], ['T1490', 'Inhibit System Recovery'], ['T1489', 'Service Stop']]],
];
const ATTACK_MATRIX = { tactics: TACTICS.map(([name, techs]) => ({ name, techniques: techs.map(([id, n]) => ({ id, name: n })) })) };
const FLAT = TACTICS.flatMap(([tactic, techs]) => techs.map(([id, name]) => ({ id, name, tactic })));
// Deterministic verdict per technique: 0 prevented, 1 detectedOnly, 2 missed (roughly 60 / 25 / 15 percent).
const verdictOf = (i) => { const m = (i * 7 + 3) % 20; return m < 12 ? 'prevented' : m < 17 ? 'detectedOnly' : 'missed'; };
const TECH_ROWS = FLAT.map((t, i) => ({ ...t, bestVerdict: verdictOf(i), runCount: 1 + ((i * 5) % 7) }));
const UNIFIED = FLAT.map((t, i) => {
  const basCount = 1 + (i % 3), artCount = i % 4 === 0 ? 0 : 1 + (i % 2), emuCount = i % 5 === 0 ? 1 : 0, atomicCount = 1 + (i % 6);
  return { techniqueId: t.id, name: t.name, tactic: t.tactic, basCount, artCount, emuCount, atomicCount, totalVariants: basCount + artCount + emuCount + atomicCount };
});
function coverageAnalytics() {
  const cnt = (v, rows) => rows.filter((r) => r.bestVerdict === v).length;
  const prevented = cnt('prevented', TECH_ROWS), detectedOnly = cnt('detectedOnly', TECH_ROWS), missed = cnt('missed', TECH_ROWS);
  const attempted = TECH_ROWS.length;
  // privilege tiers partition the same totals
  const split = (total, parts) => { const out = []; let left = total; parts.forEach((p, k) => { const v = k === parts.length - 1 ? left : Math.round(total * p); out.push(v); left -= v; }); return out; };
  const att = split(attempted, [0.5, 0.3, 0.2]), prev = split(prevented, [0.55, 0.28, 0.17]), mis = split(missed, [0.2, 0.4, 0.4]);
  const tiers = ['user', 'admin', 'system'].map((tier, k) => ({ tier, attempted: att[k], prevented: prev[k], missed: mis[k], preventionRate: Math.round((prev[k] / att[k]) * 100) }));
  return {
    runsAnalyzed: 16,
    summary: { attempted, prevented, detectedOnly, missed, preventionRate: Math.round((prevented / attempted) * 100), detectionCoverage: Math.round(((prevented + detectedOnly) / attempted) * 100) },
    byTactic: TACTICS.map(([tactic]) => { const rows = TECH_ROWS.filter((r) => r.tactic === tactic); return { tactic, prevented: cnt('prevented', rows), detectedOnly: cnt('detectedOnly', rows), missed: cnt('missed', rows) }; }),
    byTechnique: TECH_ROWS.map((r) => ({ techniqueId: r.id, name: r.name, runCount: r.runCount, bestVerdict: r.bestVerdict })),
    privilegeCoverage: {
      byTier: tiers,
      gapTechs: [
        { techniqueId: 'T1068', name: 'Exploitation for Privilege Escalation', tiers: ['admin', 'system'] },
        { techniqueId: 'T1543', name: 'Create or Modify System Process', tiers: ['system'] },
        { techniqueId: 'T1134', name: 'Access Token Manipulation', tiers: ['admin', 'system'] },
      ],
    },
  };
}
const EXPOSURE = [
  { title: 'FIN7 phishing-to-ransomware chain targeting finance staff', lastSeenAt: iso(2 * DAY), techniques: [{ hasExecutableContent: true }, { hasExecutableContent: true }, { hasExecutableContent: false }],
    content: [
      { contentId: 'sc-office-child-process', relationshipKind: 'direct', validation: 'validated', isExecutable: true, lifecycle: 'active', runCount: 4, lastRunAt: iso(3 * DAY) },
      { contentId: 'art-T1059.001-3', relationshipKind: 'variant', validation: 'unvalidated', isExecutable: true, lifecycle: 'active', runCount: 0, lastRunAt: null },
    ] },
  { title: 'APT29 credential theft against identity infrastructure', lastSeenAt: iso(5 * DAY), techniques: [{ hasExecutableContent: true }, { hasExecutableContent: true }],
    content: [{ contentId: 'sc-dcsync-replication', relationshipKind: 'direct', validation: 'validated', isExecutable: true, lifecycle: 'active', runCount: 6, lastRunAt: iso(4 * DAY) }] },
  { title: 'Scattered Spider help-desk social engineering', lastSeenAt: iso(8 * DAY), techniques: [{ hasExecutableContent: false }, { hasExecutableContent: false }], content: [] },
  { title: 'LockBit 3.0 affiliate pre-encryption activity', lastSeenAt: iso(11 * DAY), techniques: [{ hasExecutableContent: true }, { hasExecutableContent: true }, { hasExecutableContent: true }],
    content: [{ contentId: 'sc-shadow-copy-deletion', relationshipKind: 'direct', validation: 'validated', isExecutable: true, lifecycle: 'active', runCount: 9, lastRunAt: iso(DAY) }] },
];
const ACTORS = ['APT29', 'APT41', 'Cl0p', 'FIN7', 'Lazarus Group', 'LockBit 3.0', 'Scattered Spider'];
function covMatrix(u) {
  const actor = u.searchParams.get('actor') || '';
  const seed = actor ? [...actor].reduce((a, c) => a + c.charCodeAt(0), 0) : 0;
  const pick = actor ? FLAT.filter((_, i) => (i + seed) % 3 !== 0) : FLAT;
  return pick.slice(0, 24).map((t, i) => ({
    techniqueId: t.id, simulationExists: (i + seed) % 5 !== 0, detectionProfileExists: (i + seed) % 3 !== 1,
    purpleExerciseExists: (i + seed) % 4 === 0, complianceMappingExists: (i + seed) % 2 === 0, responsePlaybookExists: (i + seed) % 7 === 0 ? null : (i + seed) % 3 === 0,
  }));
}

// ── attack path / exposure ──────────────────────────────────────────────────
const REL = { smb: 41, winrm: 18, rdp: 12, 'admin-to': 9, 'has-session': 14, 'member-of': 27, credential: 6 };
const AP_SUMMARY = {
  collected: true,
  agentMeta: [{ agentId: 'a-3', hostname: 'DC-PRI-01', collectedAt: iso(5 * 60), edgeCount: Object.values(REL).reduce((a, b) => a + b, 0) }],
  summary: {
    attackPathScore: 58, band: 'Medium',
    scoreDrivers: [
      { label: 'Domain Admin reachable from a workstation', deficit: 14.5 }, { label: 'Local administrator reuse across hosts', deficit: 9.0 },
      { label: 'Flat network between server segments', deficit: 6.5 }, { label: 'Credential exposure on file servers', deficit: 0 },
    ],
    avgBlastRadius: 3.4, maxBlastRadius: 9, maxBlastEntry: 'WS-FIN-0142', lateralMovementBand: 'High',
    domainCompromise: true, domainCompromiseStatus: 'reachable', shortestDomainAdminDifficulty: 'Medium',
    shortestDomainAdminPath: [
      { from: 'WS-FIN-0142', to: 'FS-LEG-01', kind: 'smb' }, { from: 'FS-LEG-01', to: 'svc-backup', kind: 'has-session' },
      { from: 'svc-backup', to: 'DC-PRI-01', kind: 'admin-to' }, { from: 'DC-PRI-01', to: 'Domain Admins', kind: 'member-of' },
    ],
    confidence: { level: 'Medium', based: ['Host reachability probes', 'Local administrator enumeration', 'Active session listing'], missing: [] },
    relationshipCounts: REL,
    crownJewels: [
      { node: 'lnx-db-02', tag: 'Payments ledger', reachable: true, entryHosts: 4, minHops: 3 },
      { node: 'CA-ISS-01', tag: 'Issuing CA', reachable: true, entryHosts: 2, minHops: 4 },
      { node: 'DC-PRI-01', tag: 'Identity', reachable: true, entryHosts: 6, minHops: 2 },
    ],
    chokePoints: [
      { label: 'FS-LEG-01', onPaths: 14, coverage: 0.61 }, { label: 'svc-backup', onPaths: 11, coverage: 0.48 }, { label: 'DC-SEC-02', onPaths: 6, coverage: 0.26 },
    ],
    segmentationViolations: [
      { from: 'WS-FIN-0143', fromSegment: 'Finance LAN', kind: 'smb', to: 'FS-LEG-01', toSegment: 'Server LAN' },
      { from: 'lnx-web-07', fromSegment: 'DMZ', kind: 'rdp', to: 'lnx-db-02', toSegment: 'Payments' },
    ],
    hosts: 12, users: 38, groups: 21, edges: Object.values(REL).reduce((a, b) => a + b, 0),
  },
  coverage: { targetsRequested: 12, targetsRepresented: 11, completeness: 'Limited', sharpHoundRequested: false, sharpHoundAvailable: false },
};
const AP_CORR = {
  gaps: [
    { priority: 'Critical', edge: { from: 'FS-LEG-01', to: 'svc-backup', kind: 'has-session' }, reason: 'Backup service account session on a file server with no credential-theft detection.', remediation: 'Move the backup service to a gMSA and enable LSASS protection on FS-LEG-01.' },
    { priority: 'High', edge: { from: 'WS-FIN-0143', to: 'FS-LEG-01', kind: 'smb' }, reason: 'Finance workstation can reach the legal file server over SMB.', remediation: 'Restrict SMB between the Finance LAN and the Server LAN to approved shares.' },
    { priority: 'Medium', edge: { from: 'lnx-web-07', to: 'lnx-db-02', kind: 'rdp' }, reason: 'DMZ web host reaches the payments database on a management port.', remediation: 'Allow only the application port from the DMZ and require a bastion for administration.' },
  ],
};
const asset = (hostKey, label, managed, crownJewel, exposureScore, attackPathScore, detectionCoverageScore, openFindingsCount, kevExposed) =>
  ({ asset: { hostKey, label, managed, crownJewel }, exposureScore, attackPathScore, detectionCoverageScore, openFindingsCount, kevExposed });
const ASSETS = [
  asset('ws-fin-0142', 'WS-FIN-0142', true, '', 54, 48, 71, 6, true), asset('ws-fin-0143', 'WS-FIN-0143', true, '', 61, 55, 69, 4, false),
  asset('dc-pri-01', 'DC-PRI-01', true, 'Identity', 47, 42, 83, 3, false), asset('dc-sec-02', 'DC-SEC-02', true, 'Identity', 52, 46, 80, 2, false),
  asset('fs-leg-01', 'FS-LEG-01', true, '', 38, 33, 58, 9, true), asset('lnx-web-07', 'lnx-web-07', true, '', 66, 62, 74, 3, false),
  asset('lnx-web-08', 'lnx-web-08', true, '', 63, 60, 72, 4, false), asset('lnx-db-02', 'lnx-db-02', true, 'Payments ledger', 44, 40, 77, 5, true),
  asset('mac-des-221', 'MAC-DES-221', true, '', 78, 75, 86, 1, false), asset('ca-iss-01', 'CA-ISS-01', true, 'Issuing CA', 57, 51, 88, 2, false),
  asset('10.20.2.60', 'NAS-ARCH-01', false, '', 35, 30, 20, 0, true), asset('10.20.8.14', 'PRN-FLR3-04', false, '', 49, 45, 15, 0, false),
];

// ── IOC registry ────────────────────────────────────────────────────────────
const ioc = (n, type, value, source, origin, status, sightingCount, firstMin, lastMin, extra) => ({ id: `ioc-${n}`, type, value, source, origin, status, sightingCount, firstSeen: iso(firstMin), lastSeen: iso(lastMin), suppressed: false, ...extra });
const IOCS = [
  ioc(1, 'domain', 'update-check.cdn-sync.example.net', 'ART', 'run', 'active', 14, 9 * DAY, 90),
  ioc(2, 'ip', '203.0.113.47', 'ART', 'run', 'active', 11, 12 * DAY, 3 * 60),
  ioc(3, 'ip', '198.51.100.23', 'OTX', 'import', 'active', 6, 20 * DAY, 2 * DAY),
  ioc(4, 'file_hash', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'ART', 'run', 'active', 8, 7 * DAY, 5 * 60),
  ioc(5, 'file_hash', '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 'MISP', 'import', 'active', 3, 30 * DAY, 6 * DAY),
  ioc(6, 'domain', 'login-portal.secure-mail.example.net', 'OTX', 'import', 'active', 5, 16 * DAY, DAY),
  ioc(7, 'url', 'http://203.0.113.47/stage2/payload.bin', 'ART', 'run', 'active', 7, 6 * DAY, 11 * 60),
  ioc(8, 'process', 'rundll32.exe comsvcs.dll MiniDump', 'Detection', 'detection', 'active', 12, 10 * DAY, 4 * 60),
  ioc(9, 'command_line', 'vssadmin.exe delete shadows /all /quiet', 'Detection', 'detection', 'active', 9, 8 * DAY, 2 * 60),
  ioc(10, 'registry_key', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdater', 'ART', 'run', 'active', 5, 5 * DAY, 8 * 60),
  ioc(11, 'mutex', 'Global\\SyncMgr_8c41e', 'MISP', 'import', 'active', 2, 25 * DAY, 9 * DAY),
  ioc(12, 'domain', 'cdn-assets.files-share.example.net', 'OTX', 'import', 'retired', 4, 40 * DAY, 18 * DAY),
  ioc(13, 'ip', '198.51.100.88', 'ART', 'run', 'active', 3, 4 * DAY, 20 * 60),
  ioc(14, 'file_hash', '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752', 'ART', 'run', 'active', 4, 3 * DAY, 13 * 60),
  ioc(15, 'user_agent', 'Mozilla/5.0 (compatible; SyncAgent/2.1)', 'Detection', 'detection', 'active', 6, 14 * DAY, 3 * DAY),
  ioc(16, 'domain', 'internal-vpn-help.example.net', 'OTX', 'import', 'active', 1, 2 * DAY, 2 * DAY, { suppressed: true, suppressionReason: 'Used in an authorised phishing exercise' }),
];
const IOC_ANALYTICS = {
  mostDetected: [{ value: 'vssadmin.exe delete shadows /all /quiet', sightingCount: 9 }, { value: 'rundll32.exe comsvcs.dll MiniDump', sightingCount: 12 }],
  highestBypassRate: [{ value: 'http://203.0.113.47/stage2/payload.bin', sightingCount: 5 }],
  frequentlyReused: [{ value: 'update-check.cdn-sync.example.net', sightingCount: 14 }],
  longestSurviving: [{ value: 'Global\\SyncMgr_8c41e', sightingCount: 2 }],
};

// ── initiatives ─────────────────────────────────────────────────────────────
const init = (n, Name, State, CreatedBy, CreatedAt, Description) => ({ ID: `init-${n}`, Name, State, CreatedBy, CreatedAt, Description });
const INITS = [
  init(1, 'Q4 ransomware resilience', 'active', 'asha.nair', iso(18 * DAY), 'Close the prevention and recovery gaps found in the Q3 ransomware drills across finance and file servers.'),
  init(2, 'Domain controller hardening', 'active', 'rohan.kulkarni', iso(26 * DAY), 'Apply LSASS protection, tiered administration and replication monitoring to all domain controllers.'),
  init(3, 'Payments segmentation review', 'active', 'meera.iyer', iso(33 * DAY), 'Validate that only approved application ports reach the payments database tier.'),
  init(4, 'Executive laptop baseline', 'closed', 'asha.nair', iso(61 * DAY), 'Baseline EDR policy and disk encryption on executive laptops.'),
  init(5, 'Legacy file share clean-up', 'archived', 'rohan.kulkarni', iso(120 * DAY), 'Retire unused legal-department shares and re-test access paths.'),
];
const job = (n, type, state, createdMin, doneMin) => ({ id: `job-${String(n).padStart(4, '0')}-a1b2c3`, type, state, createdAt: iso(createdMin), completedAt: doneMin == null ? null : iso(doneMin) });
const INIT_DETAIL = {
  'init-1': [job(1, 'revalidation', 'completed', 14 * DAY, 14 * DAY - 40), job(2, 'revalidation', 'completed', 10 * DAY, 10 * DAY - 55), job(3, 'remediation_check', 'running', 3 * DAY, null), job(4, 'revalidation', 'partial', 6 * DAY, 6 * DAY - 70), job(5, 'remediation_check', 'requested', 90, null)],
  'init-2': [job(6, 'revalidation', 'completed', 20 * DAY, 20 * DAY - 30), job(7, 'revalidation', 'completed', 12 * DAY, 12 * DAY - 35), job(8, 'revalidation', 'failed', 5 * DAY, 5 * DAY - 15), job(9, 'remediation_check', 'completed', 2 * DAY, 2 * DAY - 25)],
  'init-3': [job(10, 'revalidation', 'completed', 25 * DAY, 25 * DAY - 45), job(11, 'remediation_check', 'running', DAY, null)],
  'init-4': [job(12, 'revalidation', 'completed', 50 * DAY, 50 * DAY - 20), job(13, 'revalidation', 'completed', 44 * DAY, 44 * DAY - 22)],
  'init-5': [],
};
function progressOf(jobs) {
  const c = (s) => jobs.filter((j) => j.state === s).length;
  const Total = jobs.length;
  const done = c('completed');
  return { Total, Completed: done, Running: c('running'), Requested: c('requested'), Partial: c('partial'), Failed: c('failed'), Cancelled: c('cancelled'), PercentComplete: Total ? Math.round((done / Total) * 100) : 0 };
}
const INIT_DETAILS = {};
INITS.forEach((it) => { INIT_DETAILS[`GET /api/initiatives/${it.ID}`] = { initiative: it, progress: progressOf(INIT_DETAIL[it.ID]), jobs: INIT_DETAIL[it.ID] }; });

// ── scheduled assessments (jobs.Schedule, PascalCase) ───────────────────────
const sched = (n, Mode, Enabled, rec, GroupIDs, AgentIDs, scenarioId, LastOccurrenceAt) => ({
  ID: `sched-${n}`, Mode, Enabled, Timezone: 'Asia/Kolkata', GroupIDs, AgentIDs, Payload: { scenarioId }, LastOccurrenceAt, ...rec,
});
const SCHEDULES = [
  sched(1, 'posture', true, { RecurrenceType: 'weekly', DayOfWeek: 1, TimeOfDay: '02:00' }, [1, 7], [], 'sc-1', iso(5 * DAY - 120)),
  sched(2, 'posture', true, { RecurrenceType: 'weekly', DayOfWeek: 3, TimeOfDay: '03:30' }, [2], [], 'sc-4', iso(DAY * 2 + 10)),
  sched(3, 'telemetry', true, { RecurrenceType: 'daily', TimeOfDay: '23:00' }, [], ['a-8', 'a-6'], 'sc-6', iso(10 * 60)),
  sched(4, 'posture', true, { RecurrenceType: 'monthly', DayOfMonth: 1, TimeOfDay: '01:00' }, [3, 5], [], 'sc-2', iso(25 * DAY)),
  sched(5, 'telemetry', false, { RecurrenceType: 'weekly', DayOfWeek: 5, TimeOfDay: '22:00' }, [4], [], 'sc-3', iso(19 * DAY)),
  sched(6, 'posture', true, { RecurrenceType: 'once', RunAt: new Date(NOW + 3 * DAY * 60_000).toISOString() }, [6], [], 'sc-8', null),
  sched(7, 'posture', true, { RecurrenceType: 'once', RunAt: iso(9 * DAY) }, [2], [], 'sc-4', iso(9 * DAY)),
];

export const DEMO = {
  'GET /api/me': ME,
  'GET /api/tamper-events': TAMPER,
  'GET /api/agent-groups': GROUPS,
  'GET /api/campaigns': CAMPAIGNS,
  'GET /api/compliance/scores': COMPLIANCE,
  'GET /api/ticketing/summary': TICKETING,
  'GET /api/analytics/endpoint-posture': POSTURE,
  'GET /api/analytics/threat-intel-summary': TI_SUMMARY,
  'GET /api/ti/suggest-pack': suggestPack,
  'GET /api/ti/readiness/history': READINESS,
  ...REPORTS,
  'GET /api/attack/matrix': ATTACK_MATRIX,
  'GET /api/techniques/unified': UNIFIED,
  'GET /api/coverage/analytics': () => coverageAnalytics(),
  'GET /api/threats/exposure': EXPOSURE,
  'GET /api/coverage/actors': { actors: ACTORS },
  'GET /api/coverage/matrix': covMatrix,
  'GET /api/attackpath/summary': AP_SUMMARY,
  'GET /api/attackpath/correlation': AP_CORR,
  'GET /api/exposure/assets': ASSETS,
  'GET /api/initiatives': (u) => { const s = u.searchParams.get('state'); return { initiatives: s ? INITS.filter((i) => i.State === s) : INITS }; },
  ...INIT_DETAILS,
  'GET /api/analytics/iocs': IOC_ANALYTICS,
  'GET /api/iocs': IOCS,
  'GET /api/scheduled-assessments': { schedules: SCHEDULES },
};
for (const c of CAMPAIGNS) DEMO[`GET /api/campaigns/${c.id}`] = c;
