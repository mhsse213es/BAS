// Package rwtaxonomy classifies MITRE ATT&CK techniques used by Audspect's
// ransomware scenarios into the 12 ransomware-specific capability domains
// from ransomware.txt (lines 171-183). It answers one question only: which
// part of the ransomware kill chain does a technique represent. It never
// answers how controls responded to that technique -- that is
// internal/rwevidence's job, an orthogonal axis. See
// docs/superpowers/specs/2026-10-12-ransomware-domain-taxonomy-design.md.
package rwtaxonomy

// Domain is one of the 12 ransomware-specific capability domains. It is a
// dedicated type, never aliased to models.Tactic (MITRE's 14 generic
// Enterprise tactics) or rwevidence.Capability (the control-efficacy axis)
// -- those answer different questions at a different granularity.
type Domain string

const (
	DomainInitialAccess             Domain = "initial_access"
	DomainPreparationAndPersistence Domain = "preparation_and_persistence"
	DomainCredentialAccess          Domain = "credential_access"
	DomainLateralMovement           Domain = "lateral_movement"
	DomainDefenseEvasion            Domain = "defense_evasion"
	DomainDataDiscoveryAndStaging   Domain = "data_discovery_and_staging"
	DomainExfiltration              Domain = "exfiltration"
	DomainEncryptionAndDestruction  Domain = "encryption_and_destruction"
	DomainRecoveryInhibition        Domain = "recovery_inhibition"
	DomainContainmentAndResponse    Domain = "containment_and_response"
	DomainRecoveryAndResilience     Domain = "recovery_and_resilience"
	DomainPostIncidentAssurance     Domain = "post_incident_assurance"
)

// AllDomains is the closed, ordered set of valid domains -- the single
// source of truth other code (including this package's own tests) checks
// membership against. Order matches ransomware.txt's own table.
var AllDomains = []Domain{
	DomainInitialAccess, DomainPreparationAndPersistence, DomainCredentialAccess,
	DomainLateralMovement, DomainDefenseEvasion, DomainDataDiscoveryAndStaging,
	DomainExfiltration, DomainEncryptionAndDestruction, DomainRecoveryInhibition,
	DomainContainmentAndResponse, DomainRecoveryAndResilience, DomainPostIncidentAssurance,
}

// Valid reports whether d is one of AllDomains.
func (d Domain) Valid() bool {
	for _, v := range AllDomains {
		if d == v {
			return true
		}
	}
	return false
}
