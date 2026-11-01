// Dummy-data overrides, page group 15: Variants (real response shape of GET /api/variants/coverage).
const rows = [
  ['T1059.001', 'execution', 56, 51, 4, 1, 'Remote System Discovery was not prevented'],
  ['T1547.001', 'persistence', 56, 56, 0, 0, ''],
  ['T1218.011', 'defense-evasion', 48, 40, 8, 0, 'Data Encrypted for Impact was not prevented'],
  ['T1003.001', 'credential-access', 56, 33, 20, 3, 'Registry Run Keys was not prevented'],
  ['T1490', 'impact', 40, 12, 28, 0, 'Data from Local System was not prevented'],
];

export const DEMO = {
  'GET /api/variants/coverage': () => rows.map(([techniqueId, tactic, totalTested, prevented, allowed, errored, firstBypass]) =>
    ({ techniqueId, tactic, totalTested, prevented, allowed, errored, firstBypass })),
};
