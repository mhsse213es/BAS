// Dummy-data overrides, page group 22: Verification (the expectation queue per run).
// Response shape follows GET /api/scenarios/runs/{id}/verifications: { items: [ { expectationId, verificationId,
// techniqueId, provider, providerDisplay, domain, status, confidence, verifiedBy, evidenceCount, workflowState } ] }.
// Enough rows (18) to exercise the pager, the filters, every status and every domain.
const ROWS = [
  ['T1003.001', 'Splunk Enterprise Security', 'siem', 'Detected', 'high', 'priya.iyer', 2, 'Approved'],
  ['T1021.002', 'Palo Alto NGFW', 'network', 'NotDetected', 'high', 'rohan.mehta', 1, 'Approved'],
  ['T1566.001', 'Proofpoint Email Gateway', 'email', 'Pending', 'medium', null, 0, 'Pending'],
  ['T1048', 'Zscaler Web Gateway', 'network', 'NeedsReview', 'medium', 'priya.iyer', 3, 'NeedsReview'],
  ['T1490', 'CrowdStrike Falcon', 'cloud', 'Detected', 'high', 'asha.nair', 1, 'Approved'],
  ['T1558.003', 'Microsoft Defender for Identity', 'identity', 'Pending', 'low', null, 0, 'Pending'],
  ['T1190', 'Imperva WAF', 'network', 'NotApplicable', 'low', 'rohan.mehta', 0, 'Approved'],
  ['T1078', 'Okta System Log', 'identity', 'Detected', 'high', 'asha.nair', 2, 'Approved'],
  ['T1530', 'AWS GuardDuty', 'cloud', 'NotDetected', 'medium', 'priya.iyer', 0, 'Approved'],
  ['T1567.002', 'Symantec DLP', 'dlp', 'NotDetected', 'high', 'rohan.mehta', 1, 'Rejected'],
  ['T1041', 'Forcepoint DLP', 'dlp', 'Detected', 'medium', 'asha.nair', 0, 'Approved'],
  ['T1059.001', 'Elastic Security', 'siem', 'Detected', 'high', 'priya.iyer', 4, 'Approved'],
  ['T1136.003', 'Azure AD Audit Log', 'cloud', 'Pending', 'medium', null, 0, 'Pending'],
  ['T1110.003', 'Okta ThreatInsight', 'identity', 'NeedsReview', 'low', 'asha.nair', 1, 'NeedsReview'],
  ['T1071.004', 'Cisco Umbrella', 'network', 'Detected', 'high', 'rohan.mehta', 2, 'Approved'],
  ['T1027', 'Microsoft Sentinel', 'siem', 'Pending', 'medium', null, 0, 'Pending'],
  ['T1552.001', 'GCP Security Command Center', 'cloud', 'Detected', 'low', 'priya.iyer', 0, 'Approved'],
  ['T1114.003', 'Mimecast', 'email', 'NotDetected', 'high', 'asha.nair', 1, 'Approved'],
];

const items = (runN) => ROWS.map(([techniqueId, provider, domain, status, confidence, verifiedBy, evidenceCount, workflowState], i) => ({
  expectationId: `exp-${runN}-${i + 1}`, verificationId: verifiedBy ? `ver-${runN}-${i + 1}` : '', techniqueId, provider, providerDisplay: provider,
  domain, status, confidence, verifiedBy, evidenceCount, workflowState,
}));

export const DEMO = {};
for (let n = 1; n <= 16; n++) {
  DEMO[`GET /api/scenarios/runs/run-${n}/verifications`] = () => ({ items: items(n) });
}
