// Dummy-data overrides, page group 12 (Campaigns page redesign). Real response shapes, sample values.
//   GET /api/campaigns        -> [campaign] (summary: status, paused, targets, dispatched, skipped, progress, prevented, detected, missed)
//   GET /api/campaigns/{id}   -> campaign with runs and skips
//   GET /api/findings         -> findings; lastCampaignId ties a finding to the campaign that last found it
// demo-a.mjs already holds six campaigns (one paused, one stopped, one failed); this adds a live one with a
// very long name, and an empty one with nothing dispatched, so the progress line, wrapping and the Empty chip show up.
import { DEMO as demoA } from './demo-a.mjs';
import { DEMO as demoG3 } from './demo-g3.mjs';

const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (minAgo) => new Date(NOW - minAgo * 60_000).toISOString();

const base = { description: '', mode: 'posture', targetType: 'group', createdAt: iso(100), updatedAt: iso(60), scenarioIds: [], steps: [], targets: [] };
const LIVE = {
  ...base, id: 'camp-2026-1044', name: 'Quarterly purple-team exercise across all regional offices and the data centre estate', scenarioName: 'Active Directory Kill Chain',
  targetGroupId: 2, startedAt: iso(95), createdBy: 'meera.iyer',
  summary: { status: 'running', paused: false, prevented: 4, detected: 2, missed: 1, dispatched: 4, targets: 10, skipped: 0, progress: 40 },
  runs: [
    { status: 'completed', agentId: 'a-1', preventionScore: 72, runId: 'run-1' }, { status: 'completed', agentId: 'a-2', preventionScore: 65, runId: 'run-2' },
    { status: 'running', agentId: 'a-3', preventionScore: 0, runId: 'run-3' }, { status: 'running', agentId: 'a-4', preventionScore: 0, runId: 'run-4' },
  ],
  skips: [],
};
const EMPTY = {
  ...base, id: 'camp-2026-1012', name: 'New hire laptop baseline', scenarioName: 'Persistence via Run Key', targetGroupId: 6, startedAt: iso(20 * 1440), createdBy: 'rohan.kulkarni',
  summary: { status: 'empty', paused: false, prevented: 0, detected: 0, missed: 0, dispatched: 0, targets: 0, skipped: 0, progress: 0 },
  runs: [], skips: [],
};

const all = () => [LIVE, ...demoA['GET /api/campaigns'], EMPTY];
const routes = {};
[LIVE, EMPTY].forEach((c) => { routes[`GET /api/campaigns/${c.id}`] = c; });

export const DEMO = {
  ...routes,
  'GET /api/campaigns': () => all(),
  // A few findings carry the campaign that last found them, so the drawer's related row and the
  // recommended-next-steps list have something to show.
  'GET /api/findings': () => demoG3['GET /api/findings']().map((f, i) => (i < 5
    ? { ...f, status: 'open', lastCampaignId: 'camp-2026-1038', reopenedCount: i === 1 ? 1 : 0 }
    : f)),
};
