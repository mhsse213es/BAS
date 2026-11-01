// Dummy-data overrides, page group 30: Integrations.
// Shapes follow GET /api/ticketing/configs (lastTestOk / lastTestAt / lastTestError), GET /api/actions/configs
// (no test result) and GET /api/taxii/connectors.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const ITSM = [
  { id: 'tk-1', name: 'ServiceNow production', provider: 'servicenow', enabled: true, autoCreate: 'critical_high', autoUpdate: true, autoClose: true, settings: {}, lastTestOk: true, lastTestAt: iso(2), lastTestError: '' },
  { id: 'tk-2', name: 'Jira SEC project', provider: 'jira', enabled: true, autoCreate: 'critical', autoUpdate: true, autoClose: false, settings: {}, lastTestOk: false, lastTestAt: iso(180), lastTestError: 'HTTP 401: invalid API token' },
  { id: 'tk-3', name: 'SOC webhook', provider: 'webhook', enabled: true, autoCreate: 'off', autoUpdate: false, autoClose: false, settings: {}, lastTestOk: null, lastTestAt: null, lastTestError: '' },
  { id: 'tk-4', name: 'ServiceNow sandbox', provider: 'servicenow', enabled: false, autoCreate: 'off', autoUpdate: false, autoClose: false, settings: {}, lastTestOk: true, lastTestAt: iso(60 * 24 * 9), lastTestError: '' },
];
const EPP = [
  { id: 'ep-1', name: 'Prod CrowdStrike', provider: 'crowdstrike', enabled: true, tenantId: '', baseUrl: 'https://api.crowdstrike.com', killProcessScriptName: '' },
  { id: 'ep-2', name: 'Defender tenant', provider: 'microsoft_defender', enabled: false, tenantId: '3f2a9c10-77be-4a1e-9d52-0c1b2e4f6a88', baseUrl: '', killProcessScriptName: 'Audspect-KillProcess.ps1' },
];
const TAXII = [
  { id: 'tx-1', name: 'FS-ISAC production', serverUrl: 'https://taxii.fsisac.example/taxii2/', enabled: true, lastPollStatus: 'ok', lastPollAt: iso(60), lastPollSummary: { processed: 212, skipped: 4, malformed: 0 } },
  { id: 'tx-2', name: 'Internal MISP', serverUrl: 'https://misp.internal/taxii2/', enabled: true, lastPollStatus: 'error', lastPollAt: iso(60 * 24 * 3), lastError: 'connection refused' },
  { id: 'tx-3', name: 'CISA AIS', serverUrl: 'https://taxii.cisa.example/taxii2/', enabled: false },
];

export const DEMO = {
  'GET /api/ticketing/configs': ITSM,
  'GET /api/actions/configs': EPP,
  'GET /api/taxii/connectors': TAXII,
  'GET /api/ticketing/revalidation': { pendingRevalidation: 0 },
};
