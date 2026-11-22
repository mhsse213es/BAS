// Dummy-data overrides, page group 5: { 'GET /api/path': value | (url) => value }
const HOSTS = ['WS-FIN-0142', 'WS-FIN-0143', 'DC-PRI-01', 'DC-SEC-02', 'FS-LEG-01', 'lnx-web-07', 'lnx-web-08', 'lnx-db-02', 'MAC-DES-221', 'MAC-DES-222', 'WS-HR-0031', 'CA-ISS-01'];
const SCORE = [74, 81, 58, 63, 41, 88, 92, 77, 0, 69, 83, 52];
const TREND = ['Declining', 'Stable', 'Declining', 'Improving', 'Declining', 'Stable', 'Improving', 'Stable', null, 'Stable', 'Improving', 'Declining'];
const ISSUE = ['Credential Protection', 'Endpoint Hardening', 'Credential Protection', 'Network Segmentation', 'Backup Protection', 'Logging and Audit', 'Endpoint Hardening', 'Access Control', '', 'Endpoint Hardening', 'Email Security', 'Credential Protection'];

export const DEMO = {
  'GET /api/agents/risk-summary': {
    agents: HOSTS.map((h, i) => ({
      agentId: `a-${i + 1}`, hostname: h, healthScore: SCORE[i], measurable: SCORE[i] > 0,
      criticalityRisk: [3, 2, 5, 5, 4, 2, 1, 4, 0, 1, 2, 5][i], trend: TREND[i], topDeficitCategory: ISSUE[i], openFindingsCount: [6, 3, 9, 7, 11, 2, 1, 4, 0, 5, 2, 8][i],
    })),
  },
};
