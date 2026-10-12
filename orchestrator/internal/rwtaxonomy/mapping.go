package rwtaxonomy

import "regexp"

// techniqueIDPattern matches a syntactically valid MITRE ATT&CK technique
// ID: Txxxx or Txxxx.yyy.
var techniqueIDPattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// TechniqueDomain maps every MITRE technique ID referenced by the 8
// ransomware scenarios/drills in scenarios/ to its one primary domain in
// THIS ransomware-specific context. A technique mapped here under one
// domain is not a claim that it belongs exclusively to that domain across
// every ATT&CK context -- only that, as used in Audspect's ransomware
// corpus today, this is its primary classification.
var TechniqueDomain = map[string]Domain{
	// OS Credential Dumping: SAM
	"T1003.002": DomainCredentialAccess,
	// Remote Services: RDP
	"T1021.001": DomainLateralMovement,
	// Remote Services: SMB/Windows Admin Shares
	"T1021.002": DomainLateralMovement,
	// Indicator Removal: Clear Windows Event Logs. Ambiguous case,
	// documented per the spec: this could reasonably sit under Defense
	// Evasion (MITRE's own tactic for it) instead. Chosen as Post-Incident
	// Assurance because that domain's own description ("evidence
	// preservation, root-cause findings, regression testing") is precisely
	// about whether evidence survives an attacker's attempt to erase it,
	// while Defense Evasion's description here is specifically about
	// security-tool tampering and agent health, not log/forensic-trail
	// destruction.
	"T1070.001": DomainPostIncidentAssurance,
	// File and Directory Discovery (BFSI sensitive-file recon ahead of staging)
	"T1083": DomainDataDiscoveryAndStaging,
	// Account Discovery: Domain Account
	"T1087.002": DomainPreparationAndPersistence,
	// Network Share Discovery (ahead of SMB-based lateral movement)
	"T1135": DomainLateralMovement,
	// Data Encrypted for Impact
	"T1486": DomainEncryptionAndDestruction,
	// Service Stop (backup service stop attempt, em-07 Stage 5A)
	"T1489": DomainRecoveryInhibition,
	// Inhibit System Recovery
	"T1490": DomainRecoveryInhibition,
	// Security Software Discovery
	"T1518.001": DomainPreparationAndPersistence,
	// Create or Modify System Process: Windows Service
	"T1543.003": DomainPreparationAndPersistence,
	// Archive Collected Data via Utility
	"T1560.001": DomainDataDiscoveryAndStaging,
	// Impair Defenses: Disable or Modify Tools
	"T1562.001": DomainDefenseEvasion,
	// Exfiltration to Cloud Storage
	"T1567.002": DomainExfiltration,
}

// DomainFor returns techniqueID's mapped domain and true, or ("", false)
// if techniqueID has no entry.
func DomainFor(techniqueID string) (Domain, bool) {
	d, ok := TechniqueDomain[techniqueID]
	return d, ok
}
