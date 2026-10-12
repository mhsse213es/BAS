# Ransomware Domain Taxonomy (`internal/rwtaxonomy`) — Design

Sub-project #8 of the ransomware-mastery master roadmap.

## A. Problem statement

`ransomware.txt` (lines 169-184) asks for a richer classification of ransomware
tradecraft than the informal 8-phase skeleton Audspect's scenario authors
already use (Initial Access → Discovery → Credential Access → Defense Evasion
→ Lateral Movement → Encryption → Recovery Inhibition → Cleanup). That skeleton
is content-authoring guidance only — the one place it reaches code,
`scenario.Scenario.MITREPhases []string`, has zero consumers anywhere in the
Go codebase today. The source text is explicit that the 12-domain taxonomy is
**additive**, not a replacement: "Keep your existing eight phases for
compatibility with current scenarios, but introduce a more detailed capability
taxonomy underneath them." It also gives the taxonomy's own worked example —
distinguishing T1486 (Data Encrypted for Impact) from T1490 (Inhibit System
Recovery) — which are exactly the two techniques `internal/rwevidence`
already evaluates as separate capabilities.

This taxonomy answers one question only: **which part of the ransomware
kill chain does a given MITRE technique represent?** It is deliberately kept
separate from two other, already-answered questions:

- **Efficacy** ("how did controls respond to this technique?") is
  `rwevidence`'s 5 capabilities (Prevention/Detection/Containment/Recovery/
  DataProtection) — an orthogonal axis. A single technique gets exactly one
  domain tag from this taxonomy, but can independently carry up to 5
  capability verdicts from `rwevidence`.
- **Customer-facing reporting** ("where is the organization strong, weak, or
  untested across the lifecycle?") is explicitly **out of scope** for this
  pass. Building a domain-level readiness view means deciding how to
  represent partial coverage, untested domains, and evidence quality without
  misleading a customer — that is its own design, made later, once this
  classification foundation exists to design against.

This pass therefore delivers **only** a closed 12-domain enum and a validated
technique→domain mapping. Nothing in the codebase calls this package after
this pass ships; no HTTP, no persistence, no scoring, no reporting change.

## B. Core types

New package: `internal/rwtaxonomy`. Pure Go, two files.

### `domain.go`

```go
package rwtaxonomy

// Domain is one of the 12 ransomware-specific capability domains from
// ransomware.txt (lines 171-183) — a classification of WHICH PART of the
// ransomware kill chain a technique represents. It is a dedicated type,
// never aliased to models.Tactic (MITRE's 14 generic Enterprise tactics)
// or rwevidence.Capability (the orthogonal control-efficacy axis) --
// those answer different questions at a different granularity.
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
```

### `mapping.go`

```go
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
	"T1003.002": DomainCredentialAccess,          // OS Credential Dumping: SAM
	"T1021.001": DomainLateralMovement,           // Remote Services: RDP
	"T1021.002": DomainLateralMovement,           // Remote Services: SMB/Windows Admin Shares
	"T1070.001": DomainPostIncidentAssurance,     // Indicator Removal: Clear Windows Event Logs -- see rationale below
	"T1083":     DomainDataDiscoveryAndStaging,   // File and Directory Discovery (BFSI sensitive-file recon ahead of staging)
	"T1087.002": DomainPreparationAndPersistence, // Account Discovery: Domain Account
	"T1135":     DomainLateralMovement,           // Network Share Discovery (ahead of SMB-based lateral movement)
	"T1486":     DomainEncryptionAndDestruction,  // Data Encrypted for Impact
	"T1489":     DomainRecoveryInhibition,        // Service Stop (backup service stop attempt, em-07 Stage 5A)
	"T1490":     DomainRecoveryInhibition,        // Inhibit System Recovery
	"T1518.001": DomainPreparationAndPersistence, // Security Software Discovery
	"T1543.003": DomainPreparationAndPersistence, // Create or Modify System Process: Windows Service
	"T1560.001": DomainDataDiscoveryAndStaging,   // Archive Collected Data via Utility
	"T1562.001": DomainDefenseEvasion,            // Impair Defenses: Disable or Modify Tools
	"T1567.002": DomainExfiltration,              // Exfiltration to Cloud Storage
}

// DomainFor returns techniqueID's mapped domain and true, or ("", false)
// if techniqueID has no entry.
func DomainFor(techniqueID string) (Domain, bool) {
	d, ok := TechniqueDomain[techniqueID]
	return d, ok
}
```

**Documented ambiguous case (acceptance criterion 4):** T1070.001 (Clear
Windows Event Logs) could reasonably sit under Defense Evasion (MITRE's own
tactic for it, and the domain whose description mentions tamper protection)
or Post-Incident Assurance (whose description is explicitly "evidence
preservation, root-cause findings, regression testing"). This mapping
chooses **Post-Incident Assurance**: Defense Evasion's domain description in
ransomware.txt is specifically about security-*tool* tampering and
security-agent health, not log/forensic-trail destruction, while
Post-Incident Assurance's description is precisely about whether evidence
survives an attacker's attempt to erase it. If a later pass finds this
doesn't match how the taxonomy is used in practice, it's a one-line change
to `TechniqueDomain`, caught immediately by the fail-closed test below
(moving a key never breaks a test — it would only break if the target
domain name were misspelled, which the `Valid()` check catches).

**Coverage note:** three of the twelve domains (Initial Access, Containment
and Response, Recovery and Resilience) have no entry in `TechniqueDomain`
today. This is expected, not a gap in the taxonomy: Initial Access is
deliberately absent from this attacker-technique corpus (existing scenario
convention: the actually-exploited software, e.g. Cl0p's MOVEit/GoAnywhere
vulnerabilities, is rarely present on a generic endpoint, so no executable
step represents it); Containment and Response and Recovery and Resilience
describe the **defender's** response rather than anything an attacker
*technique* does, so no technique-to-domain entry would ever populate them —
they are exercised through `rwevidence`'s Containment/Recovery capability
verdicts, not through this mapping. `AllDomains` still lists all 12; nothing
about this mapping shrinks the enum.

## C. Fail-closed validation (acceptance criterion 3)

`mapping_corpus_test.go` in the same package, modeled directly on
`internal/rwdetect/profiles_test.go`'s already-established pattern (same
`repoScenariosDir` helper shape, same `ransomwareScenarioFiles` 8-entry list,
same `scenario.ParseYAML` + `step.TechniqueID` extraction):

1. **`TestTechniqueDomain_AllValuesAreValidDomains`** — every value in
   `TechniqueDomain` passes `.Valid()`. Fails closed against a typo'd domain
   constant.
2. **`TestTechniqueDomain_AllKeysAreWellFormedTechniqueIDs`** — every key in
   `TechniqueDomain` matches `techniqueIDPattern`. Fails closed against an
   invalid technique identifier (acceptance criterion 3's third clause).
3. **`TestTechniqueDomain_MatchesRealCorpus`** — parses all 8 real scenario
   YAMLs fresh at test time (never a hardcoded count), collects every
   distinct `step.TechniqueID` actually present, and asserts a two-way
   match against `TechniqueDomain`'s keys: every technique the real corpus
   uses has a mapping (fails if a scenario introduces an unmapped
   technique — acceptance criterion 3's first clause), and every mapped
   technique is still used by the real corpus (fails if a mapping goes
   stale after a scenario is edited/retired).
4. **`TestAllDomains_HasExactlyTwelveEntriesInRoadmapOrder`** — a direct,
   literal check that `AllDomains` is the 12 domains from ransomware.txt in
   the source document's own order, guarding the one piece of this package
   that is a transcription from prose rather than something re-derivable
   from code.

## D. Explicitly deferred (not this pass)

- Any HTTP endpoint, DB table, or scoring/reporting integration that reads
  `TechniqueDomain` or `Domain`.
- A domain-level readiness view for customers (coverage, partial-evidence,
  untested-domain semantics) — a separate design decision, deliberately
  made after this foundation exists, not before.
- Expanding `TechniqueDomain` beyond the ransomware scenario corpus to the
  full MITRE ATT&CK catalog — this taxonomy is ransomware-specific by
  design (per ransomware.txt's own framing), not a general-purpose
  technique classifier.
- Revisiting `scenario.Scenario.MITREPhases` (the informal 8-phase field) —
  it remains exactly as inert as it is today; this pass does not touch it.
