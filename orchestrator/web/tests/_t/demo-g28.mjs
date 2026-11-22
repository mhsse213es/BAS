// Dummy-data overrides, page group 28: Threat Prioritization (ten actors, as in the design demo).
// Response shapes follow GET /api/threat-priority/actors and GET /api/threat-priority/actors/{name}.
const D = 1440;
const iso = (min) => new Date(Date.now() - min * 60000).toISOString();

// [actorName, tier, score, trend, trendDelta, coverageGapCount, techniqueCount, MITRE group]
const defs = [
  ['LockBit', 'High', 43, 'down', -23, 1, 12, 'S1129'],
  ['Akira', 'Medium', 37, 'down', -1, 5, 11, 'S1194'],
  ['APT29', 'Medium', 35, 'down', -31, 65, 121, 'G0016'],
  ['APT41', 'Medium', 32, 'down', -28, 38, 85, 'G0096'],
  ['APT28', 'Medium', 30, 'down', -36, 53, 92, 'G0007'],
  ['Sandworm', 'Medium', 29, 'down', -47, 3, 12, 'G0034'],
  ['Lazarus Group', 'Medium', 23, 'down', -31, 55, 78, 'G0032'],
  ['FIN7', 'Medium', 21, 'down', -22, 21, 37, 'G0046'],
  ['Scattered Spider', 'Low', 16, 'down', -57, 24, 30, 'G1015'],
  ['APT36', 'Low', 11, 'down', -75, 4, 4, 'G0134'],
];
const actors = defs.map(([actorName, tier, score, trend, trendDelta, coverageGapCount, techniqueCount]) => ({
  actorName, tier, score, trend, trendDelta, coverageGapCount, techniqueCount,
}));

const NAMES = { T1003: 'OS Credential Dumping', T1486: 'Data Encrypted for Impact', T1566: 'Phishing', T1021: 'Remote Services', T1059: 'Command and Scripting Interpreter' };
const detail = ([actorName, tier, score, trend, trendDelta, gap, total, gid]) => {
  const ids = Object.keys(NAMES);
  const unc = ids.slice(0, Math.min(gap, 3));
  return {
    actorName, tier, score, trend, trendDelta, coverageGapCount: gap, techniqueCount: total, canonicalGroupId: gid, techniqueSource: 'mitre',
    techniqueIds: ids, uncoveredTechniques: unc,
    factors: [
      { name: 'Technique coverage gap', explanation: 'Share of this actor\'s techniques with no validated prevention or detection.', rawScore: Math.min(100, Math.round(gap / total * 100)), available: true },
      { name: 'Detection effectiveness', explanation: 'Share of simulated techniques that raised a detection.', rawScore: 55, available: true },
      { name: 'Exploit availability', explanation: 'Known exploited vulnerabilities used by this actor.', rawScore: 0, available: false },
    ],
    techniqueCoverage: ids.map((id, i) => ({
      techniqueId: id, techniqueName: NAMES[id], hasSimulation: !unc.includes(id), hasDetection: i % 3 !== 2, hasCompliance: i % 2 === 0,
      preventionVerdict: unc.includes(id) ? '' : ['Prevented', 'Allowed', 'Partial'][i % 3], detectionVerdict: unc.includes(id) ? '' : ['Detected', 'Missed', 'Detected'][i % 3],
    })),
    sources: [{ source: 'mitre', name: actorName, aliases: [], sectors: ['Financial'], regions: [], confidence: 'High', techniqueCount: total, lastSeen: iso(12 * D) }],
    techniqueEvidence: ids.slice(0, 2).map((id, i) => ({ techniqueId: id, via: i ? 'Software' : '', viaName: i ? 'Cobalt Strike' : '', confidence: 90 - i * 8, startTime: iso((40 + i * 30) * D) })),
    history: [score - trendDelta, score].map((s, i) => ({ recordedAt: iso((1 - i) * 7 * D), score: s })),
  };
};

export const DEMO = { 'GET /api/threat-priority/actors': actors };
for (const d of defs) DEMO[`GET /api/threat-priority/actors/${encodeURIComponent(d[0])}`] = detail(d);
