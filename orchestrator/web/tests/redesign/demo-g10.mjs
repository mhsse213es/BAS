// Dummy-data overrides, page group 10 (Scheduled Assessments page redesign). Real response shapes, sample values.
//   GET /api/scheduled-assessments -> jobs.Schedule rows (PascalCase), now with LastSpawnedJobID, CreatedBy,
//                                     CreatedAt and ConcurrencyLimit so the drawer has something to show.
//   GET /api/jobs/{id}             -> { job, targets, progress } for the job each schedule last spawned
//                                     (jobs.Job / jobs.JobTarget have no JSON tags, so PascalCase).
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const MIN = 60_000;
const DAY = 1440;
const iso = (minAgo) => new Date(NOW - minAgo * MIN).toISOString();
const ahead = (minAhead) => new Date(NOW + minAhead * MIN).toISOString();

const s = (n, o) => ({
  ID: `sched-${n}`, Type: 'scheduled_assessment', Enabled: true, Timezone: 'Asia/Kolkata', GroupIDs: [], AgentIDs: [],
  CreatedBy: 'asha.nair', CreatedAt: iso(40 * DAY), ConcurrencyLimit: 0, InitiativeID: '', ...o,
});
const SCHEDULES = [
  s(1, { Mode: 'posture', RecurrenceType: 'weekly', DayOfWeek: 1, TimeOfDay: '02:00', GroupIDs: [1, 7], Payload: { scenarioId: 'kc-001' }, LastOccurrenceAt: iso(5 * DAY - 120), LastSpawnedJobID: 'job-s1', ConcurrencyLimit: 4 }),
  s(2, { Mode: 'posture', RecurrenceType: 'weekly', DayOfWeek: 3, TimeOfDay: '03:30', GroupIDs: [2], Payload: { scenarioId: 'ad-002' }, LastOccurrenceAt: iso(DAY * 2 + 10), LastSpawnedJobID: 'job-s2' }),
  s(3, { Mode: 'telemetry', RecurrenceType: 'daily', TimeOfDay: '23:00', AgentIDs: ['a-8', 'a-6'], Payload: { scenarioId: 'dlp-001' }, LastOccurrenceAt: iso(10 * 60), LastSpawnedJobID: 'job-s3', Reason: 'Approved recurring detection validation, CR-4471', ApprovedBy: 'rohan.k', Timezone: 'UTC' }),
  s(4, { Mode: 'posture', RecurrenceType: 'monthly', DayOfMonth: 1, TimeOfDay: '01:00', GroupIDs: [3, 5], Payload: { scenarioId: 'rw-001' }, LastOccurrenceAt: iso(25 * DAY), LastSpawnedJobID: 'job-s4', EndDate: ahead(200 * DAY) }),
  s(5, { Mode: 'telemetry', Enabled: false, RecurrenceType: 'weekly', DayOfWeek: 5, TimeOfDay: '22:00', GroupIDs: [4], Payload: { scenarioId: 'kc-005' }, LastOccurrenceAt: iso(19 * DAY), LastSpawnedJobID: 'job-s5', Reason: 'Quarterly purple-team window', ApprovedBy: 'rohan.k' }),
  s(6, { Mode: 'posture', RecurrenceType: 'once', RunAt: ahead(3 * DAY), GroupIDs: [6], Payload: { scenarioId: 'em-002' }, LastOccurrenceAt: null, LastSpawnedJobID: '' }),
  s(7, { Mode: 'posture', RecurrenceType: 'once', RunAt: iso(9 * DAY), GroupIDs: [2], Payload: { scenarioId: 'ad-002' }, LastOccurrenceAt: iso(9 * DAY), LastSpawnedJobID: 'job-s7' }),
  s(8, { Mode: 'posture', RecurrenceType: 'weekly', DayOfWeek: 2, TimeOfDay: '06:15', GroupIDs: [1], Payload: { scenarioId: 'cu-001' }, LastOccurrenceAt: iso(6 * DAY), LastSpawnedJobID: 'job-s8' }),
];

const T = (job, agent, State, mins, Error) => ({ ID: `${job}-${agent}`, JobID: job, AgentID: agent, State, Error: Error || '', CreatedAt: iso(mins + 6), CompletedAt: State === 'completed' || State === 'failed' ? iso(mins) : null });
const JOBS = {
  'job-s1': ['completed', [T('job-s1', 'a-1', 'completed', 5 * DAY - 130), T('job-s1', 'a-2', 'completed', 5 * DAY - 131), T('job-s1', 'a-3', 'completed', 5 * DAY - 133), T('job-s1', 'a-11', 'completed', 5 * DAY - 134)]],
  'job-s2': ['partial', [T('job-s2', 'a-3', 'completed', DAY * 2), T('job-s2', 'a-4', 'failed', DAY * 2, 'agent offline during dispatch'), T('job-s2', 'a-12', 'completed', DAY * 2)]],
  'job-s3': ['completed', [T('job-s3', 'a-8', 'completed', 10 * 60 + 2), T('job-s3', 'a-6', 'completed', 10 * 60 + 3)]],
  'job-s4': ['completed', [T('job-s4', 'a-5', 'completed', 25 * DAY), T('job-s4', 'a-9', 'completed', 25 * DAY), T('job-s4', 'a-10', 'completed', 25 * DAY)]],
  'job-s5': ['failed', [T('job-s5', 'a-4', 'failed', 19 * DAY, 'scenario blocked by execution policy')]],
  'job-s7': ['completed', [T('job-s7', 'a-3', 'completed', 9 * DAY), T('job-s7', 'a-4', 'completed', 9 * DAY)]],
  'job-s8': ['running', [T('job-s8', 'a-1', 'dispatched', 0), T('job-s8', 'a-2', 'pending', 0)]],
};

const routes = {};
Object.keys(JOBS).forEach((id) => {
  const [State, targets] = JOBS[id];
  routes[`GET /api/jobs/${id}`] = {
    job: { ID: id, Type: 'scheduled_assessment', State, CreatedAt: iso(60), CompletedAt: State === 'running' ? null : iso(30), ConcurrencyLimit: 0, InitiativeID: '' },
    targets,
    progress: { Total: targets.length, Completed: targets.filter((t) => t.State === 'completed').length },
  };
});

export const DEMO = {
  'GET /api/scheduled-assessments': { schedules: SCHEDULES },
  ...routes,
};
