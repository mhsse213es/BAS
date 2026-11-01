// Dummy-data overrides, page group 18: Findings (real response shapes of GET /api/findings and GET /api/findings/{id}).
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const H = 60, D = 1440;

const ROWS = [
  ['T1547.001', 'Registry Run Keys / Startup Folder', 'Persistence', 'Critical', 'Endpoint', 'open', 'missed', 'ws-fin-0142', 2 * H, 0],
  ['T1558.003', 'Kerberoasting', 'Credential Access', 'Critical', 'Identity', 'triaged', 'missed', 'dc-pri-01', 1 * D, 0],
  ['T1649', 'Steal or Forge Authentication Certificates', 'Credential Access', 'Critical', 'Identity', 'open', 'missed', 'ca-iss-01', 3 * D, 1],
  ['T1053.003', 'Cron', 'Execution', 'High', 'Endpoint', 'open', 'detected_only', 'lnx-web-07', 5 * D, 0],
  ['T1059.001', 'PowerShell', 'Execution', 'High', 'Endpoint', 'open', 'missed', 'ws-fin-0177', 9 * D, 0],
  ['T1021.002', 'SMB/Windows Admin Shares', 'Lateral Movement', 'High', 'Network', 'open', 'detected_only', 'fs-share-03', 12 * D, 0],
  ['T1048.003', 'Exfiltration Over Unencrypted Protocol', 'Exfiltration', 'High', 'Network', 'triaged', 'missed', 'dmz-mail-01', 16 * D, 0],
  ['T1071.004', 'DNS', 'Command and Control', 'Medium', 'DNS', 'open', 'missed', 'eng-ws-02', 20 * D, 0],
  ['T1218', 'System Binary Proxy Execution', 'Defense Evasion', 'Medium', 'Endpoint', 'risk_accepted', 'missed', 'ws-fin-0177', 24 * D, 0],
  ['T1070', 'Indicator Removal', 'Defense Evasion', 'Medium', 'Endpoint', 'open', 'missed', 'sql-pay-02', 33 * D, 0],
  ['T1530', 'Data from Cloud Storage', 'Collection', 'Medium', 'Cloud', 'open', 'missed', 'cloud-gw-01', 41 * D, 0],
  ['T1105', 'Ingress Tool Transfer', 'Command and Control', 'Low', 'Network', 'remediated', 'missed', 'hr-mac-01', 18 * D, 0],
  ['T1082', 'System Information Discovery', 'Discovery', 'Low', 'Endpoint', 'remediated', 'detected_only', 'eng-lnx-02', 6 * D, 0],
  ['T1033', 'System Owner/User Discovery', 'Discovery', 'Low', 'Endpoint', 'open', 'detected_only', 'ws-fin-0142', 95 * D, 0],
];

const findings = () => ROWS.map((r, i) => {
  const [techniqueId, techniqueName, tactic, severity, controlClass, status, exposureState, agentId, ageMin, reopenedCount] = r;
  const done = status === 'remediated';
  return {
    id: `fnd-${String(i + 1).padStart(4, '0')}-9c1e4b7a`, agentId, techniqueId, controlClass, techniqueName, tactic, severity, exposureState, status,
    sourceType: 'scenario_run', occurrenceCount: 2 + (i % 4), reopenedCount, lastCampaignId: null,
    firstSeen: iso(ageMin), lastSeen: iso(Math.max(10, ageMin / 4)), lastRunId: `run-${100 + i}`,
    ...(done ? { resolvedAt: iso(Math.max(30, ageMin / 3)), resolvedReason: 'auto-healed' } : {}),
  };
});

const detail = (i) => () => ({
  ...findings()[i],
  enrichment: {
    description: 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.',
    url: 'https://attack.mitre.org/techniques/T1547/001/',
    mitigations: [
      { name: 'Execution Prevention', description: 'Block execution of code from user-writable autostart locations with application control.' },
      { name: 'Restrict Registry Permissions', description: 'Limit write access to HKCU and HKLM Run keys for standard users.' },
    ],
    detection: 'Monitor Registry creation and modification events for keys that launch programs at logon.',
  },
  productSnapshot: ['Microsoft Defender for Endpoint'],
  dataSources: ['Windows Registry: Windows Registry Key Modification', 'Process: Process Creation'],
  variantBreakdown: i === 0 ? { total: 5, prevented: 3, detectedOnly: 1, missed: 1, results: [
    { name: 'v1', outcome: 'prevented', details: 'reg add HKCU Run key blocked by ASR rule' },
    { name: 'v2', outcome: 'detected_only', details: 'Startup folder shortcut created; alert raised, not blocked' },
    { name: 'v3', outcome: 'missed', details: 'RunOnce value written with no telemetry' },
  ] } : undefined,
});

export const DEMO = {
  'GET /api/findings': findings,
  'GET /api/findings/fnd-0001-9c1e4b7a': detail(0),
  'GET /api/findings/fnd-0002-9c1e4b7a': detail(1),
  'GET /api/findings/fnd-0003-9c1e4b7a': detail(2),
};
