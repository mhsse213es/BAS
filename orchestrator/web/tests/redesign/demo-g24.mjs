// Dummy-data overrides, page group 24: Exposure Explorer (per-asset table, host charts, detail drawer).
// Response shapes follow GET /api/exposure/assets (AssetSummary rows) and GET /api/exposure/assets/{hostKey}.
const row = (key, label, managed, cj, exp, ap, det, f, kev, extra) => ({
  asset: { hostKey: key, label, managed, crownJewel: cj, ...extra },
  exposureScore: exp, attackPathScore: ap, detectionCoverageScore: det, openFindingsCount: f, kevExposed: kev,
});
const ASSETS = [
  row('dc-01', 'DC-01', true, 'AD', 32, 0, 40, 5, true, { os: 'Windows Server 2022', ip: '10.20.1.10', criticalityTier: 'Tier 0' }),
  row('eng-ws-01', 'ENG-WS-01', true, '', 50, 30, 40, 9, false, { os: 'Windows 11', ip: '10.20.4.21' }),
  row('fin-ws-01', 'FIN-WS-01', true, '', 59, 60, 40, 5, true, { os: 'Windows 11', ip: '10.20.5.14' }),
  row('dc-02', 'DC-02', true, '', 41, 30, 40, 8, false, { os: 'Windows Server 2019', ip: '10.20.1.11' }),
  row('eng-lnx-01', 'ENG-LNX-01', true, '', 54, 45, 40, 5, false, { os: 'Ubuntu 22.04', ip: '10.20.4.40' }),
  row('fin-ws-02', 'FIN-WS-02', true, '', 54, 45, 40, 12, true, { os: 'Windows 11', ip: '10.20.5.15' }),
  row('hr-mac-01', 'HR-MAC-01', true, '', 54, 45, 40, 10, false, { os: 'macOS 14', ip: '10.20.6.9' }),
  row('dmz-web-01', 'DMZ-WEB-01', true, '', 33, 0, 40, 0, true, { os: 'Ubuntu 22.04', ip: '172.16.0.20', internetFacing: true }),
  row('eng-lnx-02', 'ENG-LNX-02', true, '', 45, 15, 40, 13, false, { os: 'Ubuntu 22.04', ip: '10.20.4.41' }),
  row('eng-ws-02', 'ENG-WS-02', true, '', 50, 30, 40, 14, true, { os: 'Windows 11', ip: '10.20.4.22' }),
  row('fin-srv-01', 'FIN-SRV-01', true, 'ERP', 38, 10, 40, 0, false, { os: 'Windows Server 2022', ip: '10.20.5.5', criticalityTier: 'Tier 1' }),
  row('lab-lnx-01', 'LAB-LNX-01', true, '', 52, 30, 40, 6, false, { os: 'Debian 12', ip: '10.30.0.12' }),
  row('lab-win-01', 'LAB-WIN-01', true, '', 47, 15, 40, 6, false, { os: 'Windows 10', ip: '10.30.0.13' }),
  row('dmz-mail-01', 'DMZ-MAIL-01', false, '', 42, 30, 40, 11, true, { ip: '172.16.0.25', internetFacing: true }),
];

const detail = (a) => ({
  asset: a.asset,
  scores: {
    exposureScore: a.exposureScore, attackPathScore: a.attackPathScore, detectionCoverageScore: a.detectionCoverageScore, vulnerabilityScore: 61, criticalityRisk: 55,
    exposureMeasurable: true, attackPathMeasurable: true, detectionMeasurable: true, vulnerabilityMeasurable: true,
  },
  attackPath: { reachable: true, onShortestDaPath: false, distanceToNearestCrownJewel: 2, isChokePoint: false },
  detection: { edges: [], covered: 3, partial: 1, gap: 2, unknown: 0 },
  vulnerabilities: [
    { cveId: 'CVE-2021-34527', cvss: 8.8, kev: true, epssScore: 0.97, techniqueId: 'T1068', severity: 8.8 },
    { cveId: 'CVE-2020-1472', cvss: 10, kev: true, epssScore: 0.94, techniqueId: 'T1210', severity: 10 },
    { cveId: 'CVE-2023-23397', cvss: 9.8, kev: false, epssScore: 0.62, techniqueId: 'T1187', severity: 9.8 },
  ],
  findings: {
    collected: a.asset.managed, openCount: a.openFindingsCount, criticalCount: Math.min(2, a.openFindingsCount),
    findings: [
      { id: 'f1', techniqueId: 'T1003.001', techniqueName: 'LSASS Memory', tactic: 'Credential Access', severity: 'Critical', exposureState: 'missed' },
      { id: 'f2', techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools', tactic: 'Defense Evasion', severity: 'High', exposureState: 'detected_only' },
    ].slice(0, Math.min(2, a.openFindingsCount)),
  },
  threatIntel: [{ groupName: 'APT29', techniqueIds: ['T1003.001'] }, { groupName: 'FIN7', techniqueIds: ['T1562.001'] }],
  recommendations: [
    { edge: { from: 'FIN-WS-01', to: a.asset.label, kind: 'smb' }, priority: 'High', reason: 'No detection on this lateral-movement edge' },
  ],
});

export const DEMO = {
  'GET /api/exposure/assets': ASSETS,
  ...Object.fromEntries(ASSETS.map((a) => [`GET /api/exposure/assets/${encodeURIComponent(a.asset.hostKey)}`, detail(a)])),
};
