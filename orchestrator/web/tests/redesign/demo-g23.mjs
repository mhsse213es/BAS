// Dummy-data overrides, page group 23: Attack Paths, matching the design demo's sample values.
// Response shape follows GET /api/attackpath/summary and /api/attackpath/correlation.
const NOW = new Date('2026-10-25T12:30:00Z').getTime();
const iso = (hAgo) => new Date(NOW - hAgo * 3_600_000).toISOString();

const REL = { smb: 14, winrm: 6, rdp: 7, 'admin-to': 9, 'has-session': 8, 'member-of': 0, credential: 14 };

const summary = () => ({
  collected: true,
  agentMeta: [{ agentId: 'a-9', hostname: 'FIN-SRV-01', collectedAt: iso(19), edgeCount: 58 }],
  summary: {
    attackPathScore: 1, band: 'Critical',
    scoreDrivers: [
      { label: 'Lateral movement reach', deficit: 39.6 },
      { label: 'Domain compromise reachable', deficit: 39.6 },
      { label: 'Graph scope', deficit: 19.8 },
    ],
    avgBlastRadius: 13.0, maxBlastRadius: 13, maxBlastEntry: 'DC-01', lateralMovementBand: 'Critical',
    domainCompromise: true, domainCompromiseStatus: 'reachable', shortestDomainAdminDifficulty: 'Low',
    shortestDomainAdminPath: [
      { from: 'ENG-WS-01', to: 'FS-HR-01', kind: 'smb' }, { from: 'FS-HR-01', to: 'svc-backup', kind: 'has-session' }, { from: 'svc-backup', to: 'DC-01', kind: 'admin-to' },
    ],
    confidence: { level: 'Medium', based: ['Host reachability probes', 'Local administrator enumeration', 'Active session listing'], missing: ['Active Directory relationships'] },
    relationshipCounts: REL,
    crownJewels: [{ node: 'FIN-SRV-01', tag: 'ERP', reachable: true, entryHosts: 5, minHops: 2 }],
    chokePoints: [{ label: 'FS-HR-01', onPaths: 9, coverage: 0.64 }, { label: 'svc-backup', onPaths: 6, coverage: 0.42 }],
    segmentationViolations: [],
    hosts: 14, users: 7, groups: 1, edges: 58,
  },
  coverage: { targetsRequested: 14, targetsRepresented: 14, completeness: 'Limited', sharpHoundRequested: false, sharpHoundAvailable: false },
});

export const DEMO = {
  'GET /api/attackpath/summary': summary,
};
