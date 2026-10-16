// Package avcatalog is a vendor-neutral, I/O-free, versioned AV/NGAV
// test-vector catalog that resolves into internal/avval's evidence contract.
// It depends on avval; avval never depends on it. It imports stdlib only --
// no PowerShell/shell execution, no agent dispatch, no vendor SDK. Real
// execution against a controlled endpoint is a separate, deferred package
// (av.txt §5, "Scenario adapters").
//
// This catalog covers av.txt §2 groups A, B, C, D, E, G and H (file-based,
// script/fileless, behavioral, configuration/security-control weaknesses,
// network-delivered, credential/persistence, and
// false-positive/operational-resilience threats). Group D is modeled here
// ONLY for the three scenario families (av.txt §3) that require an actual
// test execution to demonstrate the weakness -- exclusion weakness,
// security tampering, and degraded (cloud-lookup-unavailable) protection
// -- under FamilyConfigurationWeakness. The REST of group D (stale
// signatures, policy drift, conflicting policies, endpoint health) remains
// a direct snapshot-vs-baseline comparison (internal/avval's
// ConfigurationSnapshot/EvaluateConfigurationSnapshot/
// EvaluateConfigurationDrift), not an attack execution, so it still has no
// Vector shape of its own. Group F (ransomware and destructive-impact
// precursors) is NOT modeled here either: av.txt §8 step 5 explicitly says
// to integrate with the existing ransomware mastery (internal/rwevidence,
// which already builds on internal/controlval) rather than duplicate it.
// That bridge is real, not just planned: GET
// /api/av/ransomware-precursor-coverage (internal/api/av_ransomware_bridge.go)
// reports, per rwevidence-modeled technique, which real, already-dispatched
// scenarios exercise it, and points callers at the existing
// /api/scenarios/runs/{runId}/rw-score endpoint for findings -- this
// catalog adds no Vector and internal/avefficacy adds no evaluator for
// group F, because that would duplicate the real pipeline rather than use
// it.
package avcatalog

import "github.com/audspect/bas/internal/avval"

// AttackFamily is one of the vector-bearing av.txt §2 groups this catalog
// covers.
type AttackFamily string

const (
	FamilyFileBasedThreat         AttackFamily = "file_based_threat"         // §2.A
	FamilyScriptFileless          AttackFamily = "script_fileless"           // §2.B
	FamilyBehavioralExploit       AttackFamily = "behavioral_exploit"        // §2.C
	FamilyConfigurationWeakness   AttackFamily = "configuration_weakness"    // §2.D (execution-based subset only)
	FamilyNetworkDelivered        AttackFamily = "network_delivered"         // §2.E
	FamilyCredentialPersistence   AttackFamily = "credential_persistence"    // §2.G
	FamilyFalsePositiveResilience AttackFamily = "false_positive_resilience" // §2.H
)

// Severity is the catalog entry's declared risk level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Platform is one applicable OS/endpoint-role target. av.txt §2 (closing
// paragraph): "Each vector must explicitly state its applicable operating
// systems and product capabilities rather than pretending every AV/NGAV
// supports every technique."
type Platform string

const (
	PlatformWindowsWorkstation Platform = "windows_workstation"
	PlatformWindowsServer      Platform = "windows_server"
	PlatformLinuxServer        Platform = "linux_server"
	PlatformMacOS              Platform = "macos"
)

// RequiredCapability names the product capability class a vector needs to
// be meaningful at all -- a signature-only AV engine cannot be faulted for
// missing a vector that requires behavioral/NGAV analysis.
type RequiredCapability string

const (
	CapabilitySignatureAV    RequiredCapability = "signature_av"
	CapabilityBehavioralNGAV RequiredCapability = "behavioral_ngav"
	CapabilityEDRResponse    RequiredCapability = "edr_response"
	CapabilityNetworkControl RequiredCapability = "network_control"
)

// ExecutionTemplate describes one test artifact/behavior without executing
// it -- avcatalog's equivalent of wafcatalog.RequestTemplate, adapted for
// endpoint execution rather than an HTTP request.
type ExecutionTemplate struct {
	Executor     string // e.g. "powershell", "cmd", "binary"
	Command      string
	ArtifactPath string // where a test file/artifact is placed, if any
	Description  string
	// CleanupCommand is an actual executable command, in the same Executor,
	// that reverses this leg's artifact/change -- distinct from Vector's own
	// CleanupRequirement, which is human-readable prose describing what
	// cleanup must verify. Empty means no adapter-executable cleanup command
	// exists for this leg (e.g. nothing persists); never fabricated.
	CleanupCommand string
}

// StandardsMapping ties a vector to external references. ATTACKTechniques is
// required (av.txt §3: "map techniques to the current MITRE ATT&CK
// Enterprise taxonomy"); CWEIDs is optional, for file-format/exploit-specific
// vectors where it adds useful context.
type StandardsMapping struct {
	ATTACKTechniques []string
	CWEIDs           []string
}

// Vector is one versioned catalog entry. Primary is the vector's main test
// execution; for most vectors this is the malicious artifact/behavior,
// evaluated under ClaimPrevention. For the pure operational-resilience
// vectors in FamilyFalsePositiveResilience (av.txt §2.H), Primary is itself
// the legitimate business workload, evaluated under ClaimFalsePositive --
// PrimaryClaim records which. Counterpart is the OTHER leg (nil only when
// NoCounterpartReason explains why none exists -- never a silent omission).
type Vector struct {
	ID                   string
	Version              int
	Family               AttackFamily
	Name                 string
	Severity             Severity
	Platforms            []Platform
	RequiredCapabilities []RequiredCapability
	Preconditions        string
	PrimaryClaim         avval.ClaimType // avval.ClaimPrevention for most vectors; avval.ClaimFalsePositive for FamilyFalsePositiveResilience
	Primary              ExecutionTemplate
	Counterpart          *ExecutionTemplate
	NoCounterpartReason  string
	CleanupRequirement   string
	Limitations          string
	Standards            StandardsMapping
	Provenance           string
}
