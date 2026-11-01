// Dummy-data overrides, page group 26: Exercises (OpenAEV scenarios / exercises, plans, executions).
// Shapes follow GET /api/openaev/scenarios?type=, /api/exercises/plans and /api/exercises/executions.
const sc = (n, name, category, severity, techs, injects) => ({
  OpenAEVScenarioID: 'oaev-sc-' + n, Name: name, Category: category, Severity: severity,
  TechniqueIDs: Array.from({ length: techs }, (_, i) => 'T1' + (100 + n * 7 + i)), InjectsCount: injects, SourceUpdatedAt: '2026-10-15T17:30:00Z',
});
const scenarios = [
  sc(1, 'Cloud Credential Theft', 'Credential Access', 'high', 4, 9),
  sc(2, 'Insider Data Staging', 'Collection', 'medium', 4, 7),
  sc(3, 'Lateral Movement via SMB', 'Lateral Movement', 'medium', 4, 6),
  sc(4, 'Phishing to Domain Admin', 'Initial Access', 'high', 4, 10),
  sc(5, 'Ransomware Precursors', 'Impact', 'critical', 4, 5),
  sc(6, 'Web Shell Persistence', 'Persistence', 'high', 4, 11),
];
const plan = (id, name, steps, created) => ({ id, name, steps: Array.from({ length: steps }, (_, i) => ({ id: 's' + i })), created_at: created });
const plans = [
  plan('pl-1', 'Ransomware Tabletop + Technical', 2, '2026-09-25T09:00:00Z'),
  plan('pl-2', 'Phishing Response Drill', 2, '2026-09-25T09:10:00Z'),
  plan('pl-3', 'Data Exfiltration Exercise', 2, '2026-09-25T09:20:00Z'),
];
const execs = [
  { id: 'exec-308', plan_id: 'pl-3', name: 'Data Exfiltration Exercise #2', status: 'completed', steps_done: 2, steps_total: 2, started_at: '2026-10-21T10:00:00Z' },
  { id: 'exec-309', plan_id: 'pl-2', name: 'Phishing Response Drill #3', status: 'completed', steps_done: 2, steps_total: 2, started_at: '2026-10-12T10:00:00Z' },
  { id: 'exec-310', plan_id: 'pl-1', name: 'Ransomware Tabletop + Technical #1', status: 'running', steps_done: 1, steps_total: 2, started_at: '2026-10-25T10:00:00Z' },
];

export const DEMO = {
  'GET /api/openaev/scenarios': (u) => (u.searchParams.get('type') === 'exercise' ? [] : scenarios),
  'GET /api/exercises/plans': plans,
  'GET /api/exercises/executions': execs,
};
