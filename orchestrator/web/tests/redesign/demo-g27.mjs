// Dummy-data overrides, page group 27: Technique Coverage.
// Response shapes follow GET /api/coverage/actors and GET /api/coverage/matrix.
const ACTORS = ['APT28', 'APT29', 'APT38', 'APT41', 'Akira', 'FIN7', 'Kimsuky', 'LockBit', 'Lazarus Group', 'Scattered Spider', 'Sandworm', 'Wizard Spider'];
const IDS = ['T1003.001', 'T1021.001', 'T1021.002', 'T1041', 'T1053.005', 'T1059.001', 'T1070.004', 'T1082', 'T1486', 'T1566.001', 'T1105', 'T1547.001', 'T1055', 'T1027', 'T1078'];
const row = (id, i) => ({
  techniqueId: id,
  simulationExists: i % 4 !== 3,
  detectionProfileExists: i % 3 !== 0,
  purpleExerciseExists: i % 5 === 0,
  complianceMappingExists: i % 2 === 0,
  responsePlaybookExists: i % 6 === 5 ? null : i % 3 === 1,
});
const matrix = (u) => (u && u.searchParams && u.searchParams.get('actor') ? IDS.slice(0, 8) : IDS).map(row);

export const DEMO = {
  'GET /api/coverage/actors': () => ({ actors: ACTORS }),
  'GET /api/coverage/matrix': matrix,
};
