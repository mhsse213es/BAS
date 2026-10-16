// Package avcatalog is a vendor-neutral, I/O-free, versioned AV/NGAV
// test-vector catalog that resolves into internal/avval's evidence contract.
// It depends on avval; avval never depends on it. It imports stdlib only --
// no PowerShell/shell execution, no agent dispatch, no vendor SDK. Real
// execution against a controlled endpoint is a separate, deferred package
// (av.txt §5, "Scenario adapters").
//
// This catalog deliberately covers av.txt §2 groups A, B, C, E, G and H
// (file-based, script/fileless, behavioral, network-delivered,
// credential/persistence, and false-positive/operational-resilience
// threats). Group D (configuration and policy weaknesses) is NOT modeled as
// catalog vectors here: it is a direct snapshot-vs-baseline comparison
// (internal/avval's ConfigurationSnapshot/EvaluateConfigurationSnapshot/
// EvaluateConfigurationDrift), not an attack execution with Observation-based
// evidence, so it has no Vector shape to seed. Group F (ransomware and
// destructive-impact precursors) is NOT modeled here either: av.txt §8 step 5
// explicitly says to integrate with the existing ransomware mastery
// (internal/rwevidence, which already builds on internal/controlval) rather
// than duplicate it; a future AV enterprise scenario covering group F should
// dispatch into rwevidence directly.
package avcatalog

import "github.com/audspect/bas/internal/avval"

// AttackFamily is one of the six vector-bearing av.txt §2 groups this
// catalog covers.
type AttackFamily string

const (
	FamilyFileBasedThreat         AttackFamily = "file_based_threat"         // §2.A
	FamilyScriptFileless          AttackFamily = "script_fileless"           // §2.B
	FamilyBehavioralExploit       AttackFamily = "behavioral_exploit"        // §2.C
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
