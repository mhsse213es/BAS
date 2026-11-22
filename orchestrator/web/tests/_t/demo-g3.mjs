// Dummy-data overrides, page group 3: { 'GET /api/path': value | (url) => value }
// Findings: the real response shape (status open|triaged|remediated|risk_accepted, capitalised severity).
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (hoursAgo) => new Date(NOW - hoursAgo * 3_600_000).toISOString();

const TECH = [
  ['T1003', 'OS Credential Dumping', 'Credential Access', 'EDR'], ['T1547', 'Boot or Logon Autostart Execution', 'Persistence', 'EDR'],
  ['T1021', 'Remote Services', 'Lateral Movement', 'Network'], ['T1059', 'Command and Scripting Interpreter', 'Execution', 'EDR'],
  ['T1490', 'Inhibit System Recovery', 'Impact', 'EDR'], ['T1558', 'Steal or Forge Kerberos Tickets', 'Credential Access', 'Identity'],
  ['T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration', 'DLP'], ['T1566', 'Phishing', 'Initial Access', 'Email'],
];
const SEV = ['Critical', 'High', 'High', 'Medium', 'Medium', 'Medium', 'Low', 'High'];
const STATUS = ['open', 'open', 'open', 'triaged', 'open', 'remediated', 'risk_accepted', 'open', 'remediated', 'open', 'triaged'];

const findings = Array.from({ length: 26 }, (_, i) => {
  const [techniqueId, techniqueName, tactic, controlClass] = TECH[i % TECH.length];
  const status = STATUS[i % STATUS.length];
  const first = 8 + i * 61;
  return {
    id: `finding-${i + 1}`, techniqueId, techniqueName, tactic, controlClass, severity: SEV[(i * 3) % SEV.length], status,
    agentId: `a-${(i % 12) + 1}`, firstSeen: iso(first), lastSeen: iso(Math.max(1, first - 30)),
    resolvedAt: status === 'remediated' ? iso(Math.max(1, first - 60)) : null,
    occurrenceCount: 1 + (i % 5), reopenedCount: i % 7 === 3 ? 1 : 0,
    exposureState: i % 5 === 1 ? 'detected_only' : 'exposed', sourceType: 'simulation', enrichment: {},
  };
});

// Compliance report (GET /api/compliance/report?agentId=&framework=): real shape, derived counts.
const CTRL = [
  ['AC-01', 'Access control policy enforced on privileged accounts', 'Access Control', 'pass', 6, 6, ['T1078', 'T1003']],
  ['AC-04', 'Credential dumping prevented on endpoints', 'Access Control', 'fail', 5, 2, ['T1003', 'T1558']],
  ['LG-02', 'Security logs forwarded to central SIEM', 'Logging & Monitoring', 'pass', 4, 4, ['T1070']],
  ['LG-05', 'Alerting on log clearing and tampering', 'Logging & Monitoring', 'partial', 4, 3, ['T1070', 'T1562']],
  ['NW-03', 'Egress filtering blocks tunnelling protocols', 'Network Security', 'fail', 3, 1, ['T1048', 'T1071']],
  ['NW-07', 'Lateral movement over SMB and RDP restricted', 'Network Security', 'pass', 5, 5, ['T1021']],
  ['EP-01', 'Endpoint protection blocks ransomware behaviour', 'Endpoint Protection', 'pass', 7, 7, ['T1486', 'T1490']],
  ['EP-04', 'Persistence mechanisms are monitored', 'Endpoint Protection', 'partial', 4, 3, ['T1547']],
  ['DP-02', 'Data loss prevention on removable media', 'Data Protection', 'untested', 0, 0, []],
  ['GV-01', 'Security awareness programme documented', 'Governance', 'manual', 0, 0, []],
  ['GV-02', 'Incident response plan reviewed yearly', 'Governance', 'manual', 0, 0, []],
];
const controls = CTRL.map(([id, name, domain, status, tested, passed, techs]) => ({
  id, name, domain, status, tested, passed, failed: tested - passed,
  evidence: techs.map((t, i) => ({ techniqueId: t, result: status === 'fail' && i === 0 ? 'bypassed' : 'blocked', details: `${t} simulated on the agent; ${status === 'fail' && i === 0 ? 'the technique executed without a prevention event' : 'blocked by the endpoint control'}.` })),
}));
const domainNames = [...new Set(CTRL.map((c) => c[2]))];
const domains = domainNames.map((name) => {
  const cs = controls.filter((c) => c.domain === name);
  const n = (st) => cs.filter((c) => c.status === st).length;
  const tested = n('pass') + n('fail') + n('partial');
  return { name, passing: n('pass'), failing: n('fail'), partial: n('partial'), untested: n('untested') + n('manual'), compliancePct: tested ? Math.round((n('pass') / tested) * 1000) / 10 : 0 };
});
const cn = (st) => controls.filter((c) => c.status === st).length;
const complianceReport = (u) => ({
  framework: { id: u.searchParams.get('framework') || 'rbi', name: 'RBI Cyber Security Framework', version: '2016' },
  agentId: u.searchParams.get('agentId') || 'a-1', generatedAt: iso(2), scenarioName: 'Credential Dumping via LSASS (aggregated)',
  narrative: 'Most tested controls hold. Credential dumping and DNS tunnelling are the two gaps that keep the score below target; both have an open remediation.',
  summary: { compliancePct: Math.round((cn('pass') / (cn('pass') + cn('fail') + cn('partial'))) * 1000) / 10, coveragePct: 73, totalControls: controls.length, passing: cn('pass'), failing: cn('fail'), partial: cn('partial'), untested: cn('untested'), manual: cn('manual') },
  domains, controls,
});

// GET /api/findings/{id}: the list row plus enrichment, products and the variant breakdown.
const detailRoutes = {};
findings.forEach((f, i) => {
  detailRoutes[`GET /api/findings/${f.id}`] = {
    ...f, productSnapshot: ['CrowdStrike Falcon', 'Microsoft Defender'], dataSources: ['Process: Process Access', 'Command: Command Execution'], sourceType: 'simulation',
    enrichment: { description: `${f.techniqueName} is a ${f.tactic.toLowerCase()} technique. The simulated variant executed on ${f.agentId} and the expected ${f.controlClass} control did not prevent it.`, url: `https://attack.mitre.org/techniques/${f.techniqueId}/` },
    variantBreakdown: { total: 4, prevented: i % 3 === 0 ? 4 : 2, detectedOnly: i % 3 === 0 ? 0 : 1, missed: i % 3 === 0 ? 0 : 1, results: [
      { outcome: 'prevented', details: 'Blocked by the endpoint control before execution.' },
      { outcome: i % 3 === 0 ? 'prevented' : 'detected_only', details: 'Alert raised, process allowed to continue.' },
    ] },
  };
});

export const DEMO = {
  ...detailRoutes,
  'GET /api/findings': () => findings,
  'GET /api/compliance/report': complianceReport,
};
