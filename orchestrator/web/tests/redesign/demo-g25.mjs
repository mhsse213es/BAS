// Dummy-data overrides, page group 25: Recommendations ("What to simulate next").
// Response shape follows GET /api/recommend/simulations (techniques[], suggestedScenario, hasData).
const t = (techniqueId, name, tactic, score, tier, coverageState, kev, epss, actors, env, reasons) => ({
  techniqueId, name, tactic, score, tier, coverageState, kev, epssPercentile: epss, threatActors: actors, environmentRisk: env, reasons,
  actorPriority: 40, threatPriority: 45, coverageGap: coverageState === 'never-tested' ? 100 : coverageState === 'stale' ? 60 : 10,
});

const recommendations = () => {
  const techniques = [
    t('T1021.002', 'SMB/Windows Admin Shares', 'lateral-movement', 72, 'Critical', 'never-tested', true, 94, 15, 100, ['Traverses an edge on a domain-compromise or crown-jewel path', 'Previously failed — remediate before re-testing']),
    t('T1021.001', 'Remote Desktop Protocol', 'lateral-movement', 66, 'High', 'stale', false, 88, 15, 100, ['Traverses an edge on a domain-compromise or crown-jewel path in your environment']),
    t('T1041', 'Exfiltration Over C2 Channel', 'exfiltration', 58, 'High', 'never-tested', false, 0, 9, 0, ['Previously failed — remediate before re-testing']),
    t('T1053.005', 'Scheduled Task', 'persistence', 49, 'Medium', 'stale', false, 71, 15, 0, ['Attributed to 15 ATT&CK groups', 'Overdue for testing']),
    t('T1003.001', 'LSASS Memory', 'credential-access', 47, 'Medium', 'recent', true, 97, 12, 40, ['Actively exploited (KEV)']),
    t('T1059.001', 'PowerShell', 'execution', 41, 'Medium', 'recent', false, 80, 18, 0, []),
    t('T1486', 'Data Encrypted for Impact', 'impact', 38, 'Medium', 'never-tested', false, 52, 7, 0, ['Never tested']),
    t('T1566.001', 'Spearphishing Attachment', 'initial-access', 33, 'Medium', 'stale', false, 0, 11, 0, []),
    t('T1070.004', 'File Deletion', 'defense-evasion', 22, 'Low', 'recent', false, 0, 3, 0, []),
    t('T1082', 'System Information Discovery', 'discovery', 14, 'Low', 'recent', false, 0, 2, 0, []),
  ];
  return {
    hasData: true,
    techniques,
    suggestedScenario: { name: 'Recommended simulation', description: 'Top-ranked techniques', artTechniques: techniques.slice(0, 5).map((x) => x.techniqueId) },
  };
};

export const DEMO = {
  'GET /api/recommend/simulations': recommendations,
};
