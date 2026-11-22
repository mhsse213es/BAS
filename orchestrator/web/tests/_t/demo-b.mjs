// Dummy-data overrides, group b: { 'GET /api/path': value | (url) => value }
// Fictional data for a bank / insurer security team, dates around 2026-10-20..2026-10-26.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const H = 60, D = 1440;

// ── Email gateway ───────────────────────────────────────────────────────────
const emailCoverage = {
  summary: '17 of 20 gateway test areas covered; 3 areas excluded for this deployment.',
  areas: [
    ['EG-001', 'Malicious attachment detonation', 'covered'], ['EG-002', 'Credential-phishing URL rewriting', 'covered'],
    ['EG-003', 'Business email compromise heuristics', 'covered'], ['EG-004', 'Sender spoofing (SPF/DKIM/DMARC)', 'covered'],
    ['EG-005', 'Display-name impersonation', 'covered'], ['EG-006', 'Macro-enabled documents', 'covered'],
    ['EG-007', 'Archive nesting and password-protected archives', 'covered'], ['EG-008', 'HTML smuggling', 'covered'],
    ['EG-009', 'QR-code lures', 'excluded', 'Image-based QR inspection is not licensed on this gateway tier.'],
    ['EG-010', 'Lookalike domain detection', 'covered'], ['EG-011', 'Reply-chain hijack', 'covered'],
    ['EG-012', 'Data-loss keywords in outbound mail', 'excluded', 'Outbound DLP is handled by the separate DLP programme.'],
    ['EG-013', 'Quarantine release workflow', 'covered'], ['EG-014', 'User-reported phishing triage', 'covered'],
    ['EG-015', 'Calendar-invite abuse', 'covered'], ['EG-016', 'Open-redirect link chains', 'covered'],
    ['EG-017', 'Encrypted-message inspection', 'excluded', 'Tenant uses S/MIME end to end; content cannot be inspected by design.'],
    ['EG-018', 'Ransomware stand-in payloads', 'covered'], ['EG-019', 'File-type spoofing', 'covered'],
    ['EG-020', 'Blocked-extension policy', 'covered'],
  ].map(([areaId, areaName, status, exclusionReason]) => ({ areaId, areaName, status, ...(exclusionReason ? { exclusionReason } : {}) })),
};
const dim = (s, f, i, nt = 0) => ({ outcomes: { confirmedSuccess: s, confirmedFailure: f, inconclusive: i, notTested: nt, notApplicable: 0 } });
const lat = (n, mean, median) => ({ sufficient: true, sampleCount: n, minimumSampleSize: 5, meanSeconds: mean, medianSeconds: median });
const emailMetrics = {
  lab: {
    runsConsidered: 38,
    prevention: dim(31, 5, 2),
    detection: { ...dim(27, 8, 3), latency: lat(27, 48, 41) },
    response: { ...dim(22, 10, 6), latency: lat(22, 312, 275) },
  },
  customer: {
    runsConsidered: 14,
    prevention: dim(10, 3, 1),
    detection: { ...dim(8, 4, 2), latency: lat(8, 96, 82) },
    response: { ...dim(5, 5, 4), latency: { sufficient: false, sampleCount: 3, minimumSampleSize: 5 } },
  },
};
const emailCampaigns = [
  { id: 'ecmp-0412', templateId: 'bec-supplier-fraud', status: 'completed', createdAt: iso(5 * D + 120), completedAt: iso(5 * D + 60) },
  { id: 'ecmp-0415', templateId: 'credential-phishing-url-chain', status: 'running', createdAt: iso(95), completedAt: null },
  { id: 'ecmp-0409', templateId: 'credential-phishing-url-chain', status: 'partial', createdAt: iso(3 * D + 200), completedAt: iso(3 * D + 140) },
  { id: 'ecmp-0403', templateId: 'bec-supplier-fraud', status: 'completed', createdAt: iso(8 * D), completedAt: iso(8 * D - 55) },
  { id: 'ecmp-0398', templateId: 'bec-supplier-fraud', status: 'failed', createdAt: iso(10 * D + 30), completedAt: iso(10 * D) },
];
const verdictObj = (v) => ({ verdict: v });
const egRun = (id, scenarioId, status, env, minAgo, result, error) => ({
  id, scenarioId, status, environment: env, startedAt: iso(minAgo), ...(error ? { error } : {}),
  ...(result ? { result: { prevention: verdictObj(result[0]), detectionVerdict: verdictObj(result[1]), responseVerdict: verdictObj(result[2]) } } : {}),
});
const emailRuns = [
  egRun('erun-2201', 'EG-002.credential-phishing-url-rewriting.known-bad', 'running', 'customer', 14),
  egRun('erun-2200', 'EG-006.macro-enabled-documents.known-bad', 'completed', 'customer', 3 * H, ['confirmed-success', 'confirmed-success', 'inconclusive']),
  egRun('erun-2199', 'EG-004.sender-spoofing.known-bad', 'completed', 'lab', 7 * H, ['confirmed-failure', 'confirmed-success', 'confirmed-success']),
  egRun('erun-2198', 'EG-019.file-type-spoofing.known-bad', 'completed', 'customer', 1 * D + 2 * H, ['confirmed-success', 'confirmed-success', 'confirmed-success']),
  egRun('erun-2197', 'EG-008.html-smuggling.known-bad', 'partial', 'customer', 1 * D + 6 * H, ['confirmed-failure', 'inconclusive', 'not-tested']),
  egRun('erun-2196', 'EG-018.ransomware-stand-in.known-bad', 'completed', 'lab', 2 * D, ['confirmed-success', 'confirmed-success', 'confirmed-success']),
  egRun('erun-2195', 'EG-005.display-name-impersonation.known-bad', 'completed', 'customer', 2 * D + 5 * H, ['confirmed-success', 'confirmed-failure', 'not-tested']),
  egRun('erun-2194', 'EG-020.blocked-extension-policy.known-good', 'completed', 'lab', 3 * D, ['confirmed-success', 'not-applicable', 'not-applicable']),
  egRun('erun-2193', 'EG-007.archive-nesting.known-bad', 'failed', 'customer', 3 * D + 4 * H, null, 'Mailbox probe timed out waiting for delivery'),
  egRun('erun-2192', 'EG-010.lookalike-domain.known-bad', 'completed', 'customer', 4 * D, ['confirmed-success', 'confirmed-success', 'confirmed-failure']),
  egRun('erun-2191', 'EG-003.bec-heuristics.known-bad', 'completed', 'customer', 5 * D, ['confirmed-failure', 'confirmed-failure', 'inconclusive']),
  egRun('erun-2190', 'EG-001.malicious-attachment.known-good', 'pending', 'lab', 6),
];

// ── Exercises ───────────────────────────────────────────────────────────────
const oaev = (id, name, category, severity, techs, injects, upd) => ({
  OpenAEVScenarioID: id, Name: name, Category: category, Severity: severity, TechniqueIDs: techs, InjectsCount: injects, SourceUpdatedAt: upd,
});
const oaevScenarios = [
  oaev('oaev-sc-101', 'Ransomware precursor: credential theft to file encryption', 'Ransomware', 'critical', ['T1003', 'T1021', 'T1486', 'T1490'], 9, '2026-10-21'),
  oaev('oaev-sc-102', 'Business email compromise: payment redirection', 'Phishing', 'high', ['T1566', 'T1534', 'T1114'], 6, '2026-10-19'),
  oaev('oaev-sc-103', 'Insider data staging and exfiltration', 'Insider threat', 'high', ['T1074', 'T1048', 'T1567'], 7, '2026-10-18'),
  oaev('oaev-sc-104', 'Domain controller compromise via Kerberos abuse', 'Active Directory', 'critical', ['T1558', 'T1003', 'T1207'], 8, '2026-10-22'),
  oaev('oaev-sc-105', 'Web shell on internet-facing application tier', 'Initial access', 'medium', ['T1190', 'T1505', 'T1059'], 5, '2026-10-15'),
  oaev('oaev-sc-106', 'Cloud storage misconfiguration discovery', 'Cloud', 'medium', ['T1530', 'T1580'], 4, '2026-10-12'),
];
const oaevExercises = [
  oaev('oaev-ex-201', 'Tabletop: customer portal outage with extortion note', 'Crisis management', 'high', ['T1498', 'T1657'], 11, '2026-10-20'),
  oaev('oaev-ex-202', 'Purple team: lateral movement across finance VLAN', 'Purple team', 'high', ['T1021', 'T1570', 'T1047'], 8, '2026-10-17'),
  oaev('oaev-ex-203', 'Quarterly phishing resilience drill', 'Awareness', 'low', ['T1566', 'T1204'], 5, '2026-10-09'),
];
const plan = (id, name, steps, minAgo) => ({ id, name, steps: Array.from({ length: steps }, (_, i) => ({ id: `${id}-s${i + 1}` })), created_at: iso(minAgo).slice(0, 10) });
const exPlans = [
  plan('plan-11', 'Ransomware readiness: finance workstations', 9, 6 * D),
  plan('plan-12', 'Domain controller attack path rehearsal', 8, 5 * D),
  plan('plan-13', 'Insider exfiltration drill: payments data', 7, 4 * D),
  plan('plan-14', 'BEC response walkthrough', 6, 2 * D),
];
const exExec = (id, plan_id, name, status, done, total, minAgo) => ({ id, plan_id, name, status, steps_done: done, steps_total: total, started_at: iso(minAgo).slice(0, 16).replace('T', ' '), created_at: iso(minAgo + 5) });
const exExecs = [
  exExec('exec-310', 'plan-12', 'Domain controller attack path rehearsal', 'running', 5, 8, 42),
  exExec('exec-309', 'plan-11', 'Ransomware readiness: finance workstations', 'paused', 4, 9, 3 * H),
  exExec('exec-308', 'plan-14', 'BEC response walkthrough', 'completed', 6, 6, 1 * D + 3 * H),
  exExec('exec-307', 'plan-13', 'Insider exfiltration drill: payments data', 'completed', 7, 7, 3 * D),
  exExec('exec-306', 'plan-11', 'Ransomware readiness: finance workstations', 'aborted', 2, 9, 5 * D),
  exExec('exec-305', 'plan-12', 'Domain controller attack path rehearsal', 'completed', 8, 8, 6 * D),
];

// ── Factory health ──────────────────────────────────────────────────────────
const trend = (vals) => vals.map((value, i) => ({ date: iso((vals.length - i) * D).slice(0, 10), value }));
const factoryHealth = {
  threatsProcessed: { state: 'ok', value: 412 },
  publishedContent: { state: 'ok', value: 96 },
  medianThreatToContentTcv: { state: 'ok', value: 207360 },
  staticValidationPassRate: { state: 'ok', value: 0.76 },
  duplicateGenerationRate: { state: 'no_data', reason: 'Not enough published items in the last 30 days to compute a rate.' },
  sourceToTechniqueCoverage: { state: 'ok', value: 0.83 },
  pipeline: {
    ingestion: {
      sources: [
        { displayName: 'MITRE ATT&CK', lastSuccessAt: iso(6 * H), failuresInWindow: 0 },
        { displayName: 'CISA KEV', lastSuccessAt: iso(95), failuresInWindow: 0 },
        { displayName: 'AlienVault OTX', lastSuccessAt: iso(2 * D + 4 * H), failuresInWindow: 3, lastDiagnostic: 'HTTP 429 rate limited by upstream' },
        { displayName: 'MISP (internal)', lastSuccessAt: iso(40), failuresInWindow: 0 },
        { displayName: 'OpenCTI', lastSuccessAt: null, failuresInWindow: 1, lastDiagnostic: 'connector not configured' },
      ],
      unresolvedCandidates: 7,
    },
    funnel: { candidate: 148, validated: 112, published: 96, rejected: 36 },
    dataQuality: { staleSources: ['AlienVault OTX'], staleValidations: 2 },
  },
  trends: {
    threatsProcessedByDay: trend([38, 44, 41, 52, 47, 63, 58, 49, 71, 66, 60, 74, 69, 82]),
    tcvByDay: trend([3.1, 2.9, 3.4, 2.8, 2.6, 2.7, 2.5, 2.4, 2.6, 2.3, 2.4, 2.2, 2.4, 2.4]),
  },
};

// ── Recommendations ─────────────────────────────────────────────────────────
const rec = (techniqueId, name, tactic, score, tier, coverageState, kev, epss, actors, env, reasons) => ({
  techniqueId, name, tactic, score, tier, coverageState, kev, epssPercentile: epss, threatActors: actors, environmentRisk: env, reasons,
});
const recTechniques = [
  rec('T1003', 'OS Credential Dumping', 'Credential Access', 94, 'Critical', 'never-tested', true, 97, 14, 'High', ['Used by 14 tracked groups', 'Domain controllers in scope']),
  rec('T1486', 'Data Encrypted for Impact', 'Impact', 91, 'Critical', 'stale', true, 95, 11, 'High', ['Active ransomware campaigns in the sector', 'Last validated 74 days ago']),
  rec('T1558', 'Steal or Forge Kerberos Tickets', 'Credential Access', 86, 'Critical', 'never-tested', false, 88, 7, 'High', ['Kerberoastable service accounts reported by AD checks']),
  rec('T1190', 'Exploit Public-Facing Application', 'Initial Access', 82, 'High', 'stale', true, 99, 9, 'Medium', ['Three internet-facing web servers', 'KEV-listed CVE affects the web tier']),
  rec('T1566', 'Phishing', 'Initial Access', 78, 'High', 'recent', false, 92, 16, 'Medium', ['Most reported initial access vector']),
  rec('T1021', 'Remote Services', 'Lateral Movement', 74, 'High', 'stale', false, 81, 12, 'High', ['Flat network between finance workstations and file servers']),
  rec('T1490', 'Inhibit System Recovery', 'Impact', 71, 'High', 'never-tested', false, 76, 8, 'Medium', ['Backup servers reachable from user VLANs']),
  rec('T1059', 'Command and Scripting Interpreter', 'Execution', 64, 'Medium', 'recent', false, 70, 18, 'Low', ['Script block logging enabled']),
  rec('T1547', 'Boot or Logon Autostart Execution', 'Persistence', 58, 'Medium', 'stale', false, 64, 10, 'Low', ['Last validated 51 days ago']),
  rec('T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration', 55, 'Medium', 'never-tested', false, 58, 6, 'Medium', ['DNS egress not restricted on Linux web tier']),
  rec('T1112', 'Modify Registry', 'Defense Evasion', 41, 'Low', 'recent', false, 49, 9, 'Low', ['Covered by recent endpoint scenarios']),
  rec('T1070', 'Indicator Removal', 'Defense Evasion', 36, 'Low', 'recent', false, 44, 7, 'Low', ['Covered by recent endpoint scenarios']),
];
const recommendations = (u) => {
  const lim = parseInt(u.searchParams.get('limit') || '20', 10);
  return {
    techniques: recTechniques.slice(0, lim),
    suggestedScenario: { artTechniques: recTechniques.slice(0, 5).map((t) => t.techniqueId) },
  };
};

// ── Remediation ─────────────────────────────────────────────────────────────
const rem = (severity, techniqueId, techniqueName, findingCount, agentCount, controlClasses, missed, detectedOnly, mitigations, detection, targets) => ({
  severity, techniqueId, techniqueName, findingCount, agentCount, controlClasses, missed, detectedOnly, mitigations, detection, recommendedTargets: targets,
});
const remediations = [
  rem('Critical', 'T1003', 'OS Credential Dumping', 6, 4, ['EDR', 'OS hardening'], 5, 1, [
    { name: 'Credential Access Protection', description: 'Enable LSASS protection (RunAsPPL) and Credential Guard on all domain-joined Windows hosts.' },
    { name: 'Privileged Account Management', description: 'Remove local administrator rights from standard finance workstation users.' },
    { name: 'Active Directory Configuration', description: 'Restrict replication permissions to domain controllers only.' },
  ], 'Monitor access to LSASS and attempts to read SAM, SECURITY and NTDS.dit from unexpected processes.', ['WS-FIN-0142', 'WS-FIN-0143', 'DC-SEC-02', 'FS-LEG-01']),
  rem('Critical', 'T1486', 'Data Encrypted for Impact', 4, 3, ['EDR', 'Backup'], 3, 1, [
    { name: 'Data Backup', description: 'Keep offline, immutable copies of file server data and test restores quarterly.' },
    { name: 'Behavior Prevention on Endpoint', description: 'Turn on ransomware protection and controlled folder access for user profile paths.' },
  ], 'Alert on mass file renames with new extensions and rapid entropy increase in user directories.', ['WS-FIN-0142', 'FS-LEG-01', 'MAC-DES-221']),
  rem('High', 'T1021', 'Remote Services', 5, 5, ['Network', 'Identity'], 4, 1, [
    { name: 'Network Segmentation', description: 'Block SMB and RDP between user VLANs; allow only from jump hosts.' },
    { name: 'Multi-factor Authentication', description: 'Require MFA for all remote service logons to servers.' },
  ], 'Alert on interactive logons from workstation to server tiers outside change windows.', ['WS-FIN-0143', 'WS-HR-0031', 'FS-LEG-01', 'lnx-db-02', 'DC-PRI-01']),
  rem('High', 'T1490', 'Inhibit System Recovery', 3, 2, ['EDR'], 2, 1, [
    { name: 'Operating System Configuration', description: 'Restrict vssadmin, wbadmin and bcdedit to the backup operator group.' },
  ], 'Alert on shadow copy deletion and boot configuration changes.', ['WS-FIN-0142', 'FS-LEG-01']),
  rem('High', 'T1190', 'Exploit Public-Facing Application', 3, 2, ['WAF', 'Patching'], 3, 0, [
    { name: 'Update Software', description: 'Patch the web tier to the vendor fixed release for the KEV-listed CVE.' },
    { name: 'Application Isolation and Sandboxing', description: 'Run the web service as a non-privileged user in a restricted container.' },
  ], 'Alert on web server processes spawning shells or writing executable content.', ['lnx-web-07', 'lnx-web-08']),
  rem('Medium', 'T1547', 'Boot or Logon Autostart Execution', 4, 4, ['EDR'], 2, 2, [
    { name: 'Restrict Registry Permissions', description: 'Limit write access to Run and RunOnce keys for standard users.' },
  ], 'Monitor creation of Run key values and startup folder entries.', ['WS-FIN-0142', 'WS-FIN-0143', 'WS-HR-0031', 'MAC-DES-222']),
  rem('Medium', 'T1048', 'Exfiltration Over Alternative Protocol', 2, 2, ['Network', 'DLP'], 1, 1, [
    { name: 'Filter Network Traffic', description: 'Force DNS through the internal resolver and block direct outbound DNS and ICMP tunnels.' },
  ], 'Alert on high volume or high-entropy DNS queries from servers.', ['lnx-web-07', 'lnx-db-02']),
  rem('Low', 'T1070', 'Indicator Removal', 1, 1, ['SIEM'], 0, 1, [
    { name: 'Remote Data Storage', description: 'Forward Windows security logs to the central SIEM so local clearing is visible.' },
  ], 'Alert on event log clearing (Event ID 1102 and 104).', ['DC-SEC-02']),
];

// ── Reports history ─────────────────────────────────────────────────────────
const rpt = (reportType, scopeLabel, format, generatedBy, minAgo, status = 'completed', n) => ({
  reportType, scopeLabel, format, generatedBy, generatedAt: iso(minAgo), status, downloadPath: `/api/reports/download/rpt-${n}`,
});
const reports = [
  rpt('posture', 'WS-FIN-0142 (latest run)', 'pdf', 'asha.nair', 35, 'completed', 1041),
  rpt('compliance', 'DC-PRI-01 · RBI Cyber Security Framework', 'html', 'asha.nair', 4 * H, 'completed', 1040),
  rpt('audit', 'FS-LEG-01', '', 'rohan.mehta', 1 * D + 2 * H, 'completed', 1039),
  rpt('posture', 'lnx-db-02 (latest run)', 'csv', 'rohan.mehta', 1 * D + 5 * H, 'completed', 1038),
  rpt('compliance', 'WS-FIN-0143 · ISO/IEC 27001', 'csv', 'priya.iyer', 2 * D, 'failed', 1037),
  rpt('posture', 'MAC-DES-221 (latest run)', 'pdf', 'priya.iyer', 3 * D, 'completed', 1036),
  rpt('audit', 'DC-SEC-02', '', 'asha.nair', 4 * D, 'completed', 1035),
  rpt('compliance', 'lnx-web-07 · NIST CSF', 'html', 'rohan.mehta', 5 * D, 'completed', 1034),
];

// ── SLA report ──────────────────────────────────────────────────────────────
const sevRows = [
  { severity: 'Critical', onTime: 11, late: 3, currentlyOpen: 2 },
  { severity: 'High', onTime: 27, late: 8, currentlyOpen: 5 },
  { severity: 'Medium', onTime: 34, late: 6, currentlyOpen: 7 },
  { severity: 'Low', onTime: 14, late: 1, currentlyOpen: 4 },
].map((s) => ({ ...s, complianceRate: Math.round((s.onTime / (s.onTime + s.late)) * 1000) / 10 }));
const sum = (k) => sevRows.reduce((a, r) => a + r[k], 0);
const slaOnTime = sum('onTime'), slaLate = sum('late'), slaOpen = sum('currentlyOpen');
const monthRows = [['2026-05', 14, 11], ['2026-06', 16, 13], ['2026-07', 18, 14], ['2026-08', 20, 17], ['2026-09', 22, 19], ['2026-10', 16, 14]]
  .map(([month, resolved, onTime]) => ({ month, resolved, onTime, complianceRate: Math.round((onTime / resolved) * 1000) / 10 }));
const slaReport = {
  overall: {
    totalEpisodes: slaOnTime + slaLate + slaOpen, onTime: slaOnTime, late: slaLate, currentlyOpen: slaOpen,
    complianceRate: Math.round((slaOnTime / (slaOnTime + slaLate)) * 1000) / 10,
  },
  bySeverity: sevRows,
  monthlyTrend: monthRows,
  recentlyResolved: [
    ['a-1', 'CHK-LSASS-PROTECT', 'Critical', 80, true], ['a-3', 'CHK-DCSYNC-PERMS', 'Critical', 1 * D + 60, true],
    ['a-8', 'CHK-DB-EGRESS-DNS', 'High', 1 * D + 6 * H, false], ['a-5', 'CHK-SMB-SIGNING', 'High', 2 * D, true],
    ['a-6', 'CHK-WEB-SHELL-WRITE', 'High', 2 * D + 5 * H, true], ['a-11', 'CHK-RUNKEY-ACL', 'Medium', 3 * D, true],
    ['a-9', 'CHK-GATEKEEPER-POLICY', 'Medium', 3 * D + 3 * H, false], ['a-2', 'CHK-VSS-RESTRICT', 'High', 4 * D, true],
    ['a-12', 'CHK-CA-TEMPLATE-ACL', 'Critical', 5 * D, false], ['a-7', 'CHK-NGINX-VERSION-BANNER', 'Low', 6 * D, true],
  ].map(([agentId, checkId, severity, m, onTime]) => ({ agentId, checkId, severity, resolvedAt: iso(m), onTime })),
};

// ── Threat prioritization ───────────────────────────────────────────────────
const actorDefs = [
  ['APT29', 'Critical', 91, 'up', 4, 5, 22, 'G0016'],
  ['FIN7', 'Critical', 87, 'up', 2, 4, 18, 'G0046'],
  ['Lazarus Group', 'High', 78, 'stable', 0, 6, 25, 'G0032'],
  ['Scattered Spider', 'High', 74, 'up', 3, 3, 14, 'G1015'],
  ['APT41', 'High', 69, 'down', -2, 5, 21, 'G0096'],
  ['LockBit', 'Medium', 58, 'stable', 0, 3, 16, 'S1129'],
  ['Kimsuky', 'Medium', 52, 'down', -1, 4, 17, 'G0094'],
  ['Transparent Tribe', 'Low', 39, 'new', 0, 2, 12, 'G0134'],
];
const tpActors = actorDefs.map(([actorName, tier, score, trendDir, trendDelta, coverageGapCount, techniqueCount]) => ({
  actorName, tier, score, trend: trendDir, trendDelta, coverageGapCount, techniqueCount,
}));
const TECH_NAMES = {
  T1003: 'OS Credential Dumping', T1486: 'Data Encrypted for Impact', T1558: 'Steal or Forge Kerberos Tickets', T1190: 'Exploit Public-Facing Application',
  T1566: 'Phishing', T1021: 'Remote Services', T1490: 'Inhibit System Recovery', T1059: 'Command and Scripting Interpreter',
  T1547: 'Boot or Logon Autostart Execution', T1048: 'Exfiltration Over Alternative Protocol',
};
const tpDetail = (name, mitreId, techIds, uncovered, factors, history, srcs) => {
  const base = actorDefs.find((a) => a[0] === name);
  return {
    actorName: name, canonicalGroupId: mitreId, score: base[2], tier: base[1], techniqueCount: base[6], coverageGapCount: uncovered.length,
    techniqueSource: 'mitre', techniqueIds: techIds, uncoveredTechniques: uncovered,
    factors: factors.map(([n, explanation, rawScore, available = true]) => ({ name: n, explanation, rawScore, available })),
    techniqueCoverage: techIds.map((id, i) => ({
      techniqueId: id, techniqueName: TECH_NAMES[id], hasSimulation: !uncovered.includes(id), hasDetection: i % 3 !== 2, hasCompliance: i % 2 === 0,
      preventionVerdict: uncovered.includes(id) ? '' : ['Prevented', 'Allowed', 'Prevented', 'Partial'][i % 4],
      detectionVerdict: uncovered.includes(id) ? '' : ['Detected', 'Detected', 'Missed', 'Detected'][i % 4],
    })),
    sources: srcs,
    techniqueEvidence: techIds.slice(0, 3).map((id, i) => ({ techniqueId: id, via: i === 1 ? 'Software' : '', viaName: i === 1 ? 'Cobalt Strike' : '', confidence: 90 - i * 8, startTime: iso((40 + i * 30) * D) })),
    history: history.map((s, i) => ({ recordedAt: iso((history.length - 1 - i) * 7 * D), score: s })),
  };
};
const srcRow = (source, name, aliases, sectors, regions, confidence, techniqueCount, lastSeenDays) => ({
  source, name, aliases, sectors, regions, confidence, techniqueCount, lastSeen: iso(lastSeenDays * D),
});
const std = (sim, det, sector, recent) => [
  ['Technique coverage gap', 'Share of this actor\'s techniques with no validated prevention or detection.', sim],
  ['Detection effectiveness', 'Share of simulated techniques that raised a detection.', det],
  ['Sector targeting', 'How often this actor targets financial services and insurance.', sector],
  ['Recent activity', 'Observed campaign activity in the last 90 days.', recent],
  ['Exploit availability', 'Known exploited vulnerabilities used by this actor.', 0, false],
];
const tpDetails = {
  'APT29': tpDetail('APT29', 'G0016', ['T1566', 'T1003', 'T1558', 'T1021', 'T1059', 'T1547'], ['T1558', 'T1021', 'T1547', 'T1003', 'T1566'],
    std(77, 62, 88, 94), [78, 81, 84, 86, 91],
    [srcRow('mitre', 'APT29', ['Cozy Bear', 'The Dukes', 'Midnight Blizzard'], ['Government', 'Technology'], ['Europe', 'North America'], 'High', 22, 11),
      srcRow('misp', 'APT29', ['Cozy Bear'], ['Financial'], [], 'Medium', 17, 4)]),
  'FIN7': tpDetail('FIN7', 'G0046', ['T1566', 'T1059', 'T1021', 'T1486'], ['T1021', 'T1486', 'T1059', 'T1566'],
    std(72, 58, 95, 81), [80, 82, 84, 87],
    [srcRow('mitre', 'FIN7', ['Carbon Spider', 'Sangria Tempest'], ['Retail', 'Financial', 'Hospitality'], ['Global'], 'High', 18, 19),
      srcRow('otx', 'FIN7', [], ['Financial'], ['North America'], 'Medium', 12, 2)]),
  'Lazarus Group': tpDetail('Lazarus Group', 'G0032', ['T1190', 'T1048', 'T1486', 'T1059', 'T1003'], ['T1048', 'T1003', 'T1486', 'T1190', 'T1059'],
    std(66, 55, 90, 70), [77, 78, 77, 78, 78],
    [srcRow('mitre', 'Lazarus Group', ['Hidden Cobra', 'Diamond Sleet'], ['Financial', 'Cryptocurrency', 'Defence'], ['Asia', 'North America'], 'High', 25, 9)]),
};
const tpDetailRoutes = Object.fromEntries(Object.entries(tpDetails).map(([n, d]) => [`GET /api/threat-priority/actors/${encodeURIComponent(n)}`, d]));

// ── Kubernetes scenarios ────────────────────────────────────────────────────
const k8sRuns = [
  { id: 'k8s-run-0147', action: 'pod-create-unprivileged', cluster: 'prod-eks-eu1', namespace: 'bas-sandbox', requester: 'asha.nair', state: 'PLANNED', detail: 'Plan: create pod bas-probe-7f2 (non-root, no host mounts) in bas-sandbox.\nNothing has been written to the cluster.' },
  { id: 'k8s-run-0146', action: 'sa-token-probe', cluster: 'prod-eks-eu1', namespace: 'bas-sandbox', requester: 'rohan.mehta', state: 'APPROVED', detail: 'Plan: request a short-lived token for service account bas-probe and discard it.\nApproved by asha.nair.' },
  { id: 'k8s-run-0145', action: 'configmap-patch-labelled', cluster: 'stg-aks-01', namespace: 'bas-sandbox', requester: 'priya.iyer', state: 'CLEANED', detail: 'Patched labelled ConfigMap bas-probe-cfg key probe=on.\nReverted and verified: object matches original.' },
  { id: 'k8s-run-0144', action: 'synthetic-secret-read', cluster: 'stg-aks-01', namespace: 'bas-sandbox', requester: 'priya.iyer', state: 'CLEANED', detail: 'Read synthetic secret bas-canary as probe identity.\nAccess logged by the audit pipeline within 14s.' },
  { id: 'k8s-run-0143', action: 'sa-token-probe', cluster: 'prod-eks-eu1', namespace: 'bas-sandbox', requester: 'rohan.mehta', state: 'DISCARDED_NOT_REVOKED', detail: 'Token minted and discarded.\nThe API server does not support revocation; the token expires at its TTL.' },
  { id: 'k8s-run-0142', action: 'pod-create-unprivileged', cluster: 'prod-eks-eu1', namespace: 'payments', requester: 'rohan.mehta', state: 'REFUSED', detail: 'Refused: namespace payments is not on the cluster allow-list.' },
  { id: 'k8s-run-0141', action: 'configmap-patch-labelled', cluster: 'stg-aks-01', namespace: 'bas-sandbox', requester: 'asha.nair', state: 'CLEANUP_FAILED', detail: 'Patch applied, restore step timed out.\nCheck ConfigMap bas-probe-cfg in stg-aks-01 manually.' },
];

// ── Verification ────────────────────────────────────────────────────────────
const vfItems = (runN) => {
  const rows = [
    ['T1003', 'Splunk Enterprise Security', 'siem', 'Detected', 'high', 'priya.iyer', 2, 'Approved'],
    ['T1021', 'Palo Alto NGFW', 'network', 'NotDetected', 'high', 'rohan.mehta', 1, 'Approved'],
    ['T1566', 'Proofpoint Email Gateway', 'email', 'Pending', 'medium', null, 0, 'Pending'],
    ['T1048', 'Zscaler Web Gateway', 'network', 'NeedsReview', 'medium', 'priya.iyer', 3, 'NeedsReview'],
    ['T1490', 'CrowdStrike Falcon', 'endpoint', 'Detected', 'high', 'asha.nair', 1, 'Approved'],
    ['T1558', 'Microsoft Defender for Identity', 'identity', 'Pending', 'low', null, 0, 'Pending'],
    ['T1190', 'Imperva WAF', 'web', 'NotApplicable', 'low', 'rohan.mehta', 0, 'Approved'],
  ];
  return rows.map(([techniqueId, provider, domain, status, confidence, verifiedBy, evidenceCount, workflowState], i) => ({
    expectationId: `exp-${runN}-${i + 1}`, verificationId: verifiedBy ? `ver-${runN}-${i + 1}` : '', techniqueId, provider, providerDisplay: provider,
    domain, status, confidence, verifiedBy, evidenceCount, workflowState,
  }));
};
const vfRoutes = {};
for (let n = 1; n <= 16; n++) vfRoutes[`GET /api/scenarios/runs/run-${n}/verifications`] = (u) => {
  const d = u.searchParams.get('domain');
  const items = vfItems(n).filter((i) => !d || i.domain === d);
  return { items };
};

// ── AD coverage ─────────────────────────────────────────────────────────────
const cap = (primitiveId, name, techniqueId, family, content, composed, exec, det, risk, extra = {}) => ({
  primitiveId, name, techniqueId, family, contentAvailability: content, scenarioComposed: composed,
  executionValidation: exec, detectionValidation: det, riskClass: risk,
  prerequisites: { domainJoined: true, privileges: extra.privileges || ['domain user'] },
  expectedPostconditions: extra.post || [],
  evidenceRequirements: extra.evidence || ['Command line and process tree', 'Domain controller security log events'],
  telemetrySources: extra.telemetry || ['Windows Security 4769', 'Sysmon 1'],
  cleanup: extra.cleanup || ['No persistent change is made'],
  limitations: extra.limitations || ['Modeled against a lab domain only; no production domain has been exercised.'],
  outstanding: extra.outstanding || [],
  contentSource: extra.source || 'Atomic Red Team', contentReason: extra.reason || '',
});
const adCaps = [
  cap('ad.kerberoast', 'Kerberoasting', 'T1558.003', 'Credential access', 'scenario-composable', true, 'execution_completed', 'telemetry_observed', 'non_destructive', { post: [{ kind: 'ticket-request', target: 'service-account' }] }),
  cap('ad.asreproast', 'AS-REP roasting', 'T1558.004', 'Credential access', 'scenario-composable', true, 'execution_completed', 'simulated_evidence_only', 'non_destructive'),
  cap('ad.dcsync', 'DCSync replication request', 'T1003.006', 'Credential access', 'scenario-composable', true, 'postcondition_verified', 'telemetry_observed', 'potentially_destructive', { privileges: ['Replicating Directory Changes'], outstanding: ['Validate detection against a production-like domain controller'] }),
  cap('ad.ntds-copy', 'NTDS.dit shadow copy extraction', 'T1003.003', 'Credential access', 'reusable-unmapped', false, 'not_executed', 'not_validated', 'potentially_destructive', { source: 'Caldera', reason: 'Ability exists but is not mapped to a scenario step.' }),
  cap('ad.passwordspray', 'Password spraying', 'T1110.003', 'Credential access', 'scenario-composable', true, 'execution_attempted', 'not_validated', 'potentially_destructive', { limitations: ['Honours the lockout threshold of the target domain; spray count is capped.'] }),
  cap('ad.golden-ticket', 'Golden ticket forging', 'T1558.001', 'Persistence', 'model-only', false, 'not_executed', 'not_validated', 'destructive', { source: '', reason: 'No executable content is attached; modeled for reporting only.', outstanding: ['Author a safe krbtgt-free simulation'] }),
  cap('ad.adminsdholder', 'AdminSDHolder ACL modification', 'T1098', 'Persistence', 'missing-executable-content', false, 'not_executed', 'not_validated', 'destructive', { source: '', reason: 'Not found in the attached ART or Caldera stores.' }),
  cap('ad.gpo-abuse', 'Malicious GPO link', 'T1484.001', 'Privilege escalation', 'reusable-unmapped', false, 'not_executed', 'not_validated', 'potentially_destructive', { source: 'Atomic Red Team' }),
  cap('ad.certtemplate', 'Vulnerable certificate template enrolment', 'T1649', 'Privilege escalation', 'scenario-composable', true, 'not_executed', 'not_validated', 'potentially_destructive', { telemetry: ['CA audit events 4886', '4887'] }),
  cap('ad.bloodhound', 'AD object and ACL enumeration', 'T1087.002', 'Discovery', 'scenario-composable', true, 'execution_completed', 'telemetry_observed', 'non_destructive', { telemetry: ['LDAP query volume', 'Sysmon 3'] }),
  cap('ad.trust-enum', 'Domain trust enumeration', 'T1482', 'Discovery', 'scenario-composable', true, 'execution_completed', 'simulated_evidence_only', 'non_destructive'),
  cap('ad.pth', 'Pass-the-hash logon', 'T1550.002', 'Lateral movement', 'scenario-composable', true, 'execution_attempted', 'not_validated', 'potentially_destructive'),
  cap('ad.dcom-exec', 'DCOM remote execution', 'T1021.003', 'Lateral movement', 'reusable-unmapped', false, 'not_executed', 'not_validated', 'potentially_destructive', { source: 'Caldera' }),
  cap('ad.unconstrained', 'Unconstrained delegation abuse', 'T1558', 'Lateral movement', 'model-only', false, 'not_executed', 'not_validated', 'potentially_destructive', { reason: 'No executable content is attached; modeled for reporting only.', source: '' }),
];
const cnt = (f) => adCaps.filter(f).length;
const adCoverage = {
  capabilityStates: adCaps,
  capabilityStateSummary: {
    total: adCaps.length, modeled: adCaps.length, scenarioComposed: cnt((c) => c.scenarioComposed),
    executed: cnt((c) => c.executionValidation === 'execution_completed' || c.executionValidation === 'postcondition_verified'),
    detectionValidated: cnt((c) => c.detectionValidation === 'telemetry_observed'),
  },
  contentSummary: { reusableUnmapped: cnt((c) => c.contentAvailability === 'reusable-unmapped') },
};
const adInventory = { artStoreLoaded: true, calderaStoreLoaded: true, artTechniques: 312, note: '' };

// ── Compliance frameworks ───────────────────────────────────────────────────
const frameworks = [
  { id: 'rbi-csf', name: 'RBI Cyber Security Framework', version: '2016' },
  { id: 'sebi-cscrf', name: 'SEBI Cybersecurity and Cyber Resilience Framework', version: '2024' },
  { id: 'irdai', name: 'IRDAI Information and Cyber Security Guidelines', version: '2023' },
  { id: 'cert-in', name: 'CERT-In Directions', version: '2022' },
  { id: 'iso27001', name: 'ISO/IEC 27001 Annex A', version: '2022' },
  { id: 'nist-csf', name: 'NIST Cybersecurity Framework', version: '2.0' },
];

export const DEMO = {
  'GET /api/emailgw/coverage': emailCoverage,
  'GET /api/emailgw/metrics': emailMetrics,
  'GET /api/emailgw-campaigns': emailCampaigns,
  'GET /api/emailgw-runs': emailRuns,
  'GET /api/openaev/scenarios': (u) => (u.searchParams.get('type') === 'exercise' ? oaevExercises : oaevScenarios),
  'GET /api/exercises/plans': exPlans,
  'GET /api/exercises/executions': exExecs,
  'GET /api/analytics/factory-health': factoryHealth,
  'GET /api/recommend/simulations': recommendations,
  'GET /api/remediations': remediations,
  'GET /api/reports': reports,
  'GET /api/sla/report': slaReport,
  'GET /api/threat-priority/actors': tpActors,
  ...tpDetailRoutes,
  'GET /api/me/permissions': {
    permissions: ['verification:view', 'verification:verify', 'verification:review', 'verification:evidence:upload', 'scenarios:run', 'findings:view', 'reports:generate', 'compliance:view'],
  },
  ...vfRoutes,
  'GET /api/k8s-scenarios/runs': k8sRuns,
  'GET /api/ad/coverage': adCoverage,
  'GET /api/ad/content-inventory': adInventory,
  'GET /api/compliance/frameworks': frameworks,
};
