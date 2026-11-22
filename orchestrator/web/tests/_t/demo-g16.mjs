// Dummy-data overrides, page group 16: AD Coverage (real response shape of GET /api/ad/coverage).
const CAPS = [
  ['SPN Enumeration', 'spn-enumerate', 'T1558.003', 'Kerberoasting', 'scenario-composable', true, false],
  ['Kerberoasting TGS-REP Request', 'kerberoast-tgs-request', 'T1558.003', 'Kerberoasting', 'scenario-composable', true, true],
  ['ForceChangePassword ACL Abuse', 'acl-forcechangepassword-abuse', '', 'ACL', 'model-only', false, true],
  ['GenericAll ACL Takeover', 'acl-genericall-takeover', '', 'ACL', 'model-only', false, true],
  ['ACL Privilege Exposure Audit', 'acl-privilege-exposure-check', 'T1069', 'ACL', 'scenario-composable', true, false],
  ['Configure Resource-Based Constrained Delegation', 'rbcd-configure', '', 'RBCD', 'model-only', false, true],
  ['DCSync Directory Replication', 'dcsync', 'T1003.006', 'DCSync', 'reusable-unmapped', false, true],
  ['DCSync Replication-Right Exposure Check', 'dcsync-replication-right-exposure-check', '', 'DCSync', 'scenario-composable', true, false],
  ['ADCS ESC1: Enrollee-Supplied Subject', 'adcs-esc1', 'T1649', 'ADCS', 'model-only', false, true],
  ['ADCS ESC Template Exposure Audit', 'adcs-esc-exposure-check', 'T1649', 'ADCS', 'scenario-composable', true, false],
  ['Unconstrained Delegation TGT Capture', 'kerberos-unconstrained-delegation', 'T1558', 'Delegation', 'model-only', false, true],
  ['Trust / SID-History Exposure Audit', 'trust-sid-history-exposure-check', 'T1134.005', 'Trust', 'scenario-composable', true, false],
  ['GPO Abuse: Policy Push to Linked Scope', 'gpo-abuse-linked-scope', 'T1484.001', 'GPO', 'model-only', false, true],
  ['GPO Writable-Linked Exposure Audit', 'gpo-abuse-exposure-check', 'T1484.001', 'GPO', 'scenario-composable', true, false],
];

const coverage = () => {
  const caps = CAPS.map(([name, primitiveId, techniqueId, family, contentAvailability, scenarioComposed, risky]) => ({
    primitiveId, name, techniqueId, family, modeled: true, contentAvailability, scenarioComposed,
    executionValidation: 'not_executed', detectionValidation: 'not_validated',
    riskClass: risky ? 'potentially_destructive' : 'non_destructive',
    prerequisites: { domainJoined: true, capabilities: [{ kind: 'domain-user' }] },
    evidenceRequirements: ['Directory object state before and after'],
    limitations: ['Not executed against a real domain'],
    outstanding: scenarioComposed ? [] : ['Compose into a scenario'],
  }));
  return {
    capabilityStates: caps,
    capabilityStateSummary: {
      total: caps.length, modeled: caps.length, scenarioComposed: caps.filter((c) => c.scenarioComposed).length,
      executed: 0, detectionValidated: 0,
    },
    contentSummary: { reusableUnmapped: caps.filter((c) => c.contentAvailability === 'reusable-unmapped').length },
  };
};

export const DEMO = { 'GET /api/ad/coverage': coverage };
