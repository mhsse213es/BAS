// Dummy-data overrides, page group 14: Coverage (real response shapes of GET /api/coverage/analytics
// and GET /api/threats/exposure). byTechnique carries the tactic and the per-run outcome counts.
import { DEMO as A } from './demo-a.mjs';

const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const iso = (daysAgo) => new Date(NOW - daysAgo * 86_400_000).toISOString();

const analytics = () => {
  const d = A['GET /api/coverage/analytics']();
  const tacticOf = {};
  (A['GET /api/techniques/unified'] || []).forEach((u) => { tacticOf[u.techniqueId] = u.tactic; });
  d.byTechnique = d.byTechnique.map((t, i) => {
    const runCount = t.runCount;
    const prevented = t.bestVerdict === 'prevented' ? runCount : t.bestVerdict === 'detectedOnly' ? Math.floor(runCount / 3) : 0;
    const detectedOnly = t.bestVerdict === 'detectedOnly' ? runCount - prevented : t.bestVerdict === 'missed' ? i % 2 : 0;
    return { ...t, tactic: tacticOf[t.techniqueId] || '', prevented, detectedOnly, missed: runCount - prevented - detectedOnly };
  });
  d.byTactic = d.byTactic.map((t) => ({ ...t, attempted: t.prevented + t.detectedOnly + t.missed }));
  return d;
};

const threat = (title, daysAgo, flags, content = []) => ({ title, lastSeenAt: iso(daysAgo), techniques: flags.map((hasExecutableContent) => ({ hasExecutableContent })), content });
const exposure = () => [
  ...A['GET /api/threats/exposure'],
  threat('Qakbot resurgence via malspam', 11, [false, false, false, false]),
  threat('Sandworm wiper activity', 17, [false, false]),
  threat('APT29 spearphishing wave against government', 21, [true, false, false, false, false]),
  threat('Lazarus crypto-theft toolkit', 24, [true, true, false, false]),
  threat('Akira ransomware targets VPN appliances', 24, [false, false, false]),
  threat('APT41 supply-chain intrusion', 4, [false, false, false]),
];

export const DEMO = {
  'GET /api/coverage/analytics': analytics,
  'GET /api/threats/exposure': exposure,
};
