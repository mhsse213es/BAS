// Dummy-data overrides, page group 19: IOC Registry (real response shapes of /api/iocs and /api/analytics/iocs).
// Rows carry the registry's real lifecycle statuses and origins so the status pills, source bars and
// both donuts have something to compute from; the type/status/origin/source query params filter like the API.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();
const DAY = 1440;

const ioc = (n, type, value, source, origin, status, sightingCount, firstMin, lastMin, extra) => ({
  id: `ioc-${n}`, type, value, source, origin, status, sightingCount, firstSeen: iso(firstMin), lastSeen: iso(lastMin), suppressed: false, suppressionReason: '', ...extra,
});
const ROWS = [
  ioc(1, 'ip', '198.51.100.23', 'detection_alert', 'generated', 'detected', 6, 20 * DAY, 2 * DAY),
  ioc(2, 'ip', '203.0.113.47', 'scenario', 'built-in', 'observed', 11, 12 * DAY, 3 * 60),
  ioc(3, 'domain', 'update-check.cdn-sync.example.net', 'scenario', 'built-in', 'detected', 14, 9 * DAY, 90),
  ioc(4, 'file_hash', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'detection_alert', 'generated', 'missed', 8, 7 * DAY, 5 * 60),
  ioc(5, 'file_hash', '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 'threat_feed', 'misp', 'assigned', 3, 30 * DAY, 6 * DAY),
  ioc(6, 'url', 'http://203.0.113.47/stage2/payload.bin', 'variant', 'generated', 'executed', 7, 6 * DAY, 11 * 60),
  ioc(7, 'process', 'rundll32.exe comsvcs.dll MiniDump', 'detection_alert', 'generated', 'detected', 12, 10 * DAY, 4 * 60),
  ioc(8, 'command_line', 'vssadmin.exe delete shadows /all /quiet', 'detection_alert', 'generated', 'missed', 9, 8 * DAY, 2 * 60),
  ioc(9, 'registry_key', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', 'scenario', 'built-in', 'observed', 3, 5 * DAY, 8 * 60),
  ioc(10, 'mutex', 'Global\\SyncMgr_8c41e', 'threat_feed', 'opencti', 'draft', 2, 25 * DAY, 9 * DAY),
  ioc(11, 'domain', 'cdn-assets.files-share.example.net', 'threat_feed', 'threat-feed', 'expired', 4, 40 * DAY, 18 * DAY),
  ioc(12, 'user_agent', 'Mozilla/5.0 (compatible; SyncAgent/2.1)', 'manual', 'customer', 'draft', 1, 14 * DAY, 3 * DAY),
  ioc(13, 'domain', 'internal-vpn-help.example.net', 'manual', 'customer', 'archived', 1, 2 * DAY, 2 * DAY, { suppressed: true, suppressionReason: 'Used in an authorised phishing exercise' }),
];

const top = (list) => list.map(([value, sightingCount]) => ({ value, sightingCount }));
const analytics = () => ({
  mostDetected: top([['198.51.100.23', 6], ['update-check.cdn-sync.example.net', 5], ['rundll32.exe comsvcs.dll MiniDump', 4]]),
  highestBypassRate: [],
  frequentlyReused: top([['update-check.cdn-sync.example.net', 14], ['rundll32.exe comsvcs.dll MiniDump', 12], ['203.0.113.47', 11]]),
  longestSurviving: top([['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', 3], ['Global\\SyncMgr_8c41e', 2]]),
});

export const DEMO = {
  'GET /api/iocs': (u) => {
    const q = u.searchParams;
    const type = q.get('type'), source = q.get('source'), origin = q.get('origin'), status = q.get('status'), value = (q.get('value') || '').toLowerCase();
    return ROWS.filter((r) => (!type || r.type === type) && (!source || r.source === source) && (!origin || r.origin === origin) && (!status || r.status === status) && (!value || r.value.toLowerCase().includes(value)));
  },
  'GET /api/analytics/iocs': analytics,
};
