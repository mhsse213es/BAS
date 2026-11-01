// Dummy-data overrides, page group 29: Agents.
// Response shapes follow GET /api/agents (cursor page: items[], next_cursor, has_more, totals{online,degraded,offline,retired}),
// where "degraded" is a lifecycle state (restricted / quarantined / revoked) on a reachable agent, not a status value.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

// [hostname, osVersion, ip, group, groupId, status, state, minutesSinceUpdate, sims, ws, transport]
const ROWS = [
  ['WS-FIN-0142', 'Windows 11 23H2', '10.20.4.42', 'Finance Workstations', 2, 'idle', 'active', 2, 6, true, 'mtls'],
  ['WS-FIN-0143', 'Windows 11 23H2', '10.20.4.43', 'Finance Workstations', 2, 'scanning', 'active', 1, 4, true, 'mtls'],
  ['DC-PRI-01', 'Windows Server 2022', '10.20.1.10', 'Domain Controllers', 3, 'idle', 'active', 3, 5, true, 'mtls'],
  ['DC-SEC-02', 'Windows Server 2022', '10.20.1.11', 'Domain Controllers', 3, 'idle', 'active', 4, 3, true, 'mtls'],
  ['FS-LEG-01', 'Windows Server 2019', '10.20.2.21', 'File Servers', 4, 'idle', 'active', 6, 2, false, 'mtls'],
  ['lnx-web-07', 'Ubuntu 22.04', '10.30.8.7', 'Linux Web Tier', 5, 'idle', 'restricted', 5, 1, true, 'mtls'],
  ['lnx-web-08', 'Ubuntu 22.04', '10.30.8.8', 'Linux Web Tier', 5, 'offline', 'active', 2900, 0, false, 'mtls'],
  ['lnx-db-02', 'Rocky Linux 9.3', '10.30.9.2', 'Payments DB', 6, 'idle', 'active', 7, 2, true, 'legacy'],
  ['MAC-DES-221', 'macOS 14.6', '10.40.2.221', 'Executive Laptops', 7, 'offline', 'active', 1800, 0, false, 'mtls'],
  ['MAC-DES-222', 'macOS 14.6', '10.40.2.222', 'Executive Laptops', 7, 'idle', 'active', 9, 1, true, 'mtls'],
  ['WS-HR-0031', 'Windows 10 22H2', '10.20.6.31', 'Finance Workstations', 2, 'idle', 'quarantined', 12, 0, true, 'mtls'],
  ['CA-ISS-01', 'Windows Server 2022', '10.20.1.30', 'Domain Controllers', 3, 'idle', 'active', 8, 1, true, 'mtls'],
  ['WS-OLD-0007', 'Windows 10 21H2', '10.20.9.7', null, null, 'offline', 'uninstalled', 20000, 3, false, 'mtls'],
  ['jump-01', 'Debian 12', '10.30.1.5', null, null, 'idle', 'active', 3, 0, true, 'mtls'],
];

const agents = () => ROWS.map((r, i) => ({
  agentId: `a1b2c3d4e5f6${String(i + 1).padStart(4, '0')}`, hostname: r[0], osVersion: r[1], ipAddress: r[2], username: 'svc-bas',
  groupName: r[3], groupId: r[4], status: r[5], state: r[6], wsConnected: r[9], transport: r[10], envLabel: 'Production',
  hasReport: true, binaryTrusted: r[6] !== 'quarantined', enrolledAt: iso(60 * 24 * (20 + i)), lastUpdate: iso(r[7]), sims: r[8],
}));

const bucket = (a) => (a.state === 'retired' || a.state === 'uninstalled' ? 'retired' : a.status === 'offline' ? 'offline' : a.state !== 'active' ? 'degraded' : 'online');

const GROUPS = [
  { id: 2, name: 'Finance Workstations', totalAgentCount: 3, agentCount: 3, children: [] },
  { id: 3, name: 'Domain Controllers', totalAgentCount: 3, agentCount: 3, children: [] },
  { id: 4, name: 'File Servers', totalAgentCount: 1, agentCount: 1, children: [] },
  { id: 8, name: 'Linux', totalAgentCount: 3, agentCount: 0, children: [
    { id: 5, name: 'Linux Web Tier', totalAgentCount: 2, agentCount: 2, children: [] },
    { id: 6, name: 'Payments DB', totalAgentCount: 1, agentCount: 1, children: [] },
  ] },
  { id: 7, name: 'Executive Laptops', totalAgentCount: 2, agentCount: 2, children: [] },
];

export const DEMO = {
  'GET /api/agents': (u) => {
    let a = agents();
    const totals = { online: 0, degraded: 0, offline: 0, retired: 0 };
    a.forEach((x) => { totals[bucket(x)]++; });
    if (!u.searchParams.has('limit')) return a;
    const b = u.searchParams.get('bucket');
    const q = (u.searchParams.get('q') || '').toLowerCase();
    if (b) a = a.filter((x) => bucket(x) === b);
    else a = a.filter((x) => bucket(x) !== 'retired');
    if (q) a = a.filter((x) => (x.hostname + x.agentId + x.ipAddress + (x.groupName || '')).toLowerCase().includes(q));
    return { items: a, next_cursor: '', has_more: false, totals };
  },
  'GET /api/agent-groups': GROUPS,
  'GET /api/agents/legacy-migration-status': {
    daysClean: 22, daysRequired: 30, eligible: false, unattributedRequests: null,
    blockingAgents: [{ agentId: 'a1b2c3d4e5f60008', hostname: 'lnx-db-02', lastSeen: iso(7) }],
  },
};
