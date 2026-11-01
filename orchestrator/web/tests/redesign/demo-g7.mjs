// Dummy-data overrides, page group 7 (Scenarios page redesign). Real response shapes, sample values.
//   GET /api/scenarios       -> scenario.Scenario rows: steps carry techniqueId/framework/executor/timeoutSec, some scenarios
//                               carry artTechniques, one is a sweep, one a posture check, a few are drafts or unregistered
//   GET /api/scenarios/runs  -> the g1 runs, re-pointed at catalogue scenario ids so the drawer's History tab has rows
//                               (also honours ?scenarioId= like the real handler)
import { DEMO as demoC } from './demo-c.mjs';
import { DEMO as demoG1 } from './demo-g1.mjs';

const TECH = {
  'rw-001': ['T1490', 'T1489', 'T1562.001'], 'rw-002': ['T1486', 'T1486'], 'kc-001': ['T1003.001', 'T1003.001', 'T1003.003'], 'kc-002': ['T1555.003', 'T1555.003'],
  'kc-003': ['T1021.002', 'T1543.003', 'T1569.002', 'T1070'], 'kc-004': ['T1047', 'T1047'], 'kc-005': ['T1547.001', 'T1053.005', 'T1070'], 'kc-006': ['T1053.003', 'T1543.002', 'T1070'],
  'dlp-001': ['T1132', 'T1048.003', 'T1048.003'], 'dlp-002': ['T1074', 'T1567.002'], 'ad-001': ['T1018', 'T1003.006'], 'ad-002': ['T1558.003', 'T1558.003'],
  'em-001': ['T1566.001', 'T1204.002', 'T1059.001'], 'em-002': ['T1082', 'T1562.001', 'T1562.001'], 'cu-001': ['T1120', 'T1087.001', 'T1531'],
};

const base = demoC['GET /api/scenarios'];
const scenarios = base.map((s, i) => {
  const t = TECH[s.id];
  const steps = s.steps.map((st, k) => ({
    name: st.name, techniqueId: t ? t[k % t.length] : '', framework: 'native', executor: s.supportedOs[0] === 'linux' ? 'sh' : 'powershell',
    timeoutSec: 30 + ((i + k) % 4) * 15, testIndex: 0,
  }));
  const o = { ...s, steps };
  if (s.id === 'dlp-002') o.artTechniques = ['T1567.002', 'T1048'];
  if (s.id === 'em-002') o.registry = { latestVersion: 4, latestLifecycle: 'DRAFT', latestVersionId: 'ver-4', executableVersion: 3, executableTrust: 'VENDOR_SIGNED' };
  if (s.id === 'cu-001') o.registry = { latestVersion: 1, latestLifecycle: 'DRAFT', latestVersionId: 'ver-1', executableVersion: 0, executableTrust: '' };
  if (s.id === 'kc-006') o.registry = null;
  return o;
});
// A posture check and a full Atomic Red Team sweep, to show how the cards word scenarios with no explicit technique list.
scenarios.push(
  { id: 'pc-001', name: 'Windows Security Baseline Posture Check', productLine: 'common', description: 'Read-only registry and policy checks for firewall, BitLocker, SMB signing and Defender state.', tags: ['posture'], mitrePhases: ['Defense Evasion'], supportedOs: ['windows'], author: 'Audspect Content Team', source: 'builtin', executable: false, localCheck: true, steps: [], registry: { latestVersion: 2, latestLifecycle: 'PUBLISHED_VENDOR', latestVersionId: 'ver-2', executableVersion: 2, executableTrust: 'VENDOR_SIGNED' } },
  { id: 'art-win-full', name: 'Atomic Red Team: Full Windows Sweep', productLine: 'common', description: 'Runs every Windows technique in the bundled Atomic Red Team index, one atomic at a time.', tags: ['art', 'sweep'], mitrePhases: ['Execution', 'Persistence', 'Defense Evasion'], supportedOs: ['windows'], author: 'Audspect Content Team', source: 'builtin', executable: true, artAllWindows: true, steps: [], registry: { latestVersion: 1, latestLifecycle: 'PUBLISHED_VENDOR', latestVersionId: 'ver-1', executableVersion: 1, executableTrust: 'VENDOR_SIGNED' } },
);

const ids = scenarios.filter((s) => s.steps.length).map((s) => s.id);
const g1runs = demoG1['GET /api/scenarios/runs'];
const runsFor = () => g1runs().map((r, n) => (/^sc-\d+$/.test(r.scenarioId) ? { ...r, scenarioId: ids[(n * 3) % 6], name: scenarios.find((s) => s.id === ids[(n * 3) % 6]).name } : r));

export const DEMO = {
  'GET /api/phishing-runs': [],
  'GET /api/scenarios': scenarios,
  'GET /api/scenarios/runs': (u) => {
    const all = runsFor();
    const id = u.searchParams.get('scenarioId');
    return id ? all.filter((r) => r.scenarioId === id) : all;
  },
};
