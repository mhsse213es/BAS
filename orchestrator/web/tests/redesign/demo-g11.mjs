// Dummy-data overrides, page group 11 (Initiatives page redesign). Real response shapes, sample values.
//   GET /api/initiatives        -> { initiatives: [...] } (Initiative: PascalCase, no json tags)
//   GET /api/initiatives/{id}   -> { initiative, progress, jobs } (jobs use camelCase tags)
// demo-a.mjs already holds five initiatives; this adds a sixth with a cancelled job and a very long
// description, and a seventh with no jobs, so the card strip, the empty state and the wrapping show up.
import { DEMO as demoA } from './demo-a.mjs';

const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const DAY = 86_400_000;
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();

const init = (n, Name, State, CreatedBy, CreatedAt, Description) => ({ ID: `init-${n}`, Name, State, CreatedBy, CreatedAt, Description });
const EXTRA = [
  init(6, 'Cloud storage exposure review', 'active', 'meera.iyer', iso(9 * DAY), 'Check that no storage bucket is readable without authentication and that every bucket has an owner tag, then re-test after each fix. Findings feed the quarterly cloud posture review.'),
  init(7, 'Branch network refresh', 'active', 'rohan.kulkarni', iso(2 * DAY), ''),
];
const job = (n, type, state, createdMs, doneMs) => ({ id: `job-${String(n).padStart(4, '0')}-d4e5f6`, type, state, createdAt: iso(createdMs), completedAt: doneMs == null ? null : iso(doneMs) });
const JOBS = {
  'init-6': [job(21, 'revalidation', 'completed', 8 * DAY, 8 * DAY - 2_400_000), job(22, 'revalidation', 'completed', 6 * DAY, 6 * DAY - 3_000_000), job(23, 'remediation_check', 'cancelled', 4 * DAY, 4 * DAY - 600_000), job(24, 'revalidation', 'running', DAY, null)],
  'init-7': [],
};
const progressOf = (jobs) => {
  const c = (s) => jobs.filter((j) => j.state === s).length;
  const Total = jobs.length;
  return { Total, Completed: c('completed'), Running: c('running'), Requested: c('requested'), Partial: c('partial'), Failed: c('failed'), Cancelled: c('cancelled'), PercentComplete: Total ? Math.round((c('completed') / Total) * 100) : 0 };
};

const routes = {};
EXTRA.forEach((it) => { routes[`GET /api/initiatives/${it.ID}`] = { initiative: it, progress: progressOf(JOBS[it.ID]), jobs: JOBS[it.ID] }; });

export const DEMO = {
  ...routes,
  // The state filter is applied the way the server does it; demo-a's five stay first.
  'GET /api/initiatives': (u) => {
    const s = u.searchParams.get('state');
    const all = demoA['GET /api/initiatives'](new URL(u.origin + u.pathname)).initiatives.concat(EXTRA);
    return { initiatives: s ? all.filter((i) => i.State === s) : all };
  },
};
