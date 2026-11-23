// Dummy-data overrides, page group 20 (Remediation page redesign). Real response shape of
// GET /api/remediations (one row per technique to fix), sample values, now with findingIds so the
// Ticket buttons have something to push and with enough rows (9) to fill three card rows.
const rem = (severity, techniqueId, techniqueName, controlClasses, missed, detectedOnly, mitigations, detection, targets) => ({
  severity, techniqueId, techniqueName, findingCount: missed + detectedOnly, agentCount: targets.length, controlClasses, missed, detectedOnly,
  mitigations, detection, recommendedTargets: targets,
  findingIds: Array.from({ length: missed + detectedOnly }, (_, i) => `f-${techniqueId}-${i + 1}`),
});

const remediations = () => [
  rem('Critical', 'T1486', 'Data Encrypted for Impact', ['AV', 'EDR', 'Identity'], 6, 0, [
    { name: 'Data Backup', description: 'Keep offline, immutable copies of file server data and test restores quarterly.' },
    { name: 'Behavior Prevention on Endpoint', description: 'Turn on ransomware protection and controlled folder access for user profile paths.' },
  ], 'Alert on mass file renames with new extensions and rapid entropy increase in user directories.', ['WS-FIN-0142', 'FS-LEG-01', 'MAC-DES-221', 'WS-FIN-0143', 'lnx-db-02', 'WS-HR-0031']),
  rem('Critical', 'T1003.001', 'LSASS Memory', ['Identity', 'Network', 'Email', 'AV'], 5, 0, [
    { name: 'Credential Access Protection', description: 'Enable LSASS protection (RunAsPPL) and Credential Guard on all domain-joined Windows hosts.' },
    { name: 'Privileged Account Management', description: 'Remove local administrator rights from standard finance workstation users.' },
  ], 'Monitor access to LSASS from unexpected processes.', ['WS-FIN-0142', 'WS-FIN-0143', 'DC-SEC-02', 'FS-LEG-01', 'WS-HR-0031']),
  rem('Critical', 'T1190', 'Exploit Public-Facing Application', ['Identity', 'Network', 'AV'], 4, 0, [
    { name: 'Update Software', description: 'Patch the web tier to the vendor fixed release for the KEV-listed CVE.' },
    { name: 'Application Isolation and Sandboxing', description: 'Run the web service as a non-privileged user in a restricted container.' },
  ], 'Alert on web server processes spawning shells or writing executable content.', ['lnx-web-07', 'lnx-web-08', 'lnx-db-02', 'CA-ISS-01']),
  rem('High', 'T1562.001', 'Disable or Modify Tools', ['Network', 'AV', 'Identity'], 5, 0, [
    { name: 'Restrict Registry Permissions', description: 'Limit write access to security tooling configuration keys to administrators.' },
  ], 'Alert on security service stop and tamper events.', ['WS-FIN-0142', 'WS-FIN-0143', 'DC-PRI-01', 'FS-LEG-01', 'WS-HR-0031']),
  rem('High', 'T1055', 'Process Injection', ['Email', 'EDR'], 3, 1, [
    { name: 'Behavior Prevention on Endpoint', description: 'Block cross-process memory writes from untrusted parents.' },
  ], '', ['WS-FIN-0142', 'WS-FIN-0143', 'MAC-DES-222', 'WS-HR-0031']),
  rem('High', 'T1490', 'Inhibit System Recovery', ['AV', 'Network', 'Email'], 3, 0, [
    { name: 'Operating System Configuration', description: 'Restrict vssadmin, wbadmin and bcdedit to the backup operator group.' },
  ], 'Alert on shadow copy deletion and boot configuration changes.', ['WS-FIN-0142', 'FS-LEG-01', 'DC-SEC-02']),
  rem('High', 'T1548.002', 'Bypass User Account Control', ['EDR', 'AV'], 2, 1, [], '', ['WS-FIN-0143', 'WS-HR-0031', 'WS-FIN-0142']),
  rem('Medium', 'T1070.001', 'Clear Windows Event Logs', ['EDR', 'Identity', 'Email', 'AV'], 6, 1, [
    { name: 'Remote Data Storage', description: 'Forward Windows security logs to the central SIEM so local clearing is visible.' },
  ], 'Alert on event log clearing (Event ID 1102 and 104).', ['DC-SEC-02', 'DC-PRI-01', 'WS-FIN-0142', 'WS-FIN-0143', 'FS-LEG-01', 'CA-ISS-01', 'WS-HR-0031']),
  rem('Medium', 'T1005', 'Data from Local System', ['EDR', 'Email', 'Identity', 'Network'], 5, 1, [
    { name: 'Data Loss Prevention', description: 'Block bulk reads of document folders by untrusted processes.' },
  ], '', ['WS-FIN-0142', 'WS-FIN-0143', 'MAC-DES-221', 'WS-HR-0031', 'FS-LEG-01', 'lnx-web-07']),
];

export const DEMO = {
  'GET /api/remediations': remediations,
};
