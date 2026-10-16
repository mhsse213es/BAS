// Package avefficacy correlates avcatalog vectors' collected evidence with
// internal/avval's independent result dimensions, bundling every dimension
// per vector (av.txt §4: "Use independent result dimensions. Do not collapse
// everything into a single pass/fail field") and applying a non-offsetting
// rule across a scenario's vectors: a confirmed critical protection failure
// on any one vector can never be hidden by strong results elsewhere. It
// depends on avval and avcatalog; neither depends on it. Fixture-backed
// only in this phase -- EvidenceSourceLiveExecution is declared for forward
// compatibility but not yet producible; real execution against a controlled
// endpoint, through the existing agent-dispatch path, is the next phase.
package avefficacy

import (
	"time"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// EvidenceSource distinguishes fixture-validated evidence from a real
// endpoint execution. EvidenceSourceLiveExecution is not yet producible by
// this package -- declared for the enum's forward compatibility, mirroring
// wafassessment's own EvidenceSource discipline.
type EvidenceSource string

const (
	EvidenceSourceFixture       EvidenceSource = "fixture"
	EvidenceSourceLiveExecution EvidenceSource = "live_execution"
)

// DetectionLatencyState is av.txt §1's "alert delivery latency" dimension:
// a SEPARATE, purely descriptive signal from Finding/Response/Telemetry --
// an SLA breach never forces a scenario-level failure on its own, since the
// control did detect, only slowly. It is never evaluated when no SLA was
// declared or the detection timestamp cannot be established.
type DetectionLatencyState string

const (
	LatencyWithinSLA    DetectionLatencyState = "within_sla"
	LatencySLABreached  DetectionLatencyState = "sla_breached"
	LatencyNotEvaluated DetectionLatencyState = "not_evaluated"
)

// ConfigurationCheck pairs a snapshot with either a compliance baseline or
// a centrally-managed policy to compare against -- av.txt names "weak or
// conflicting policies" and "policy drift" as distinct weaknesses. When
// Managed is set, EvaluateVector checks drift (snapshot vs. the policy that
// should be in force); otherwise it checks baseline compliance (snapshot
// vs. the required-secure baseline). Nil on VectorFixture means
// configuration is not applicable to that vector's test (most
// malicious/benign execution vectors have no configuration angle).
type ConfigurationCheck struct {
	Snapshot avval.ConfigurationSnapshot
	Baseline avval.ConfigurationBaseline
	Managed  *avval.ConfigurationSnapshot
}

// VectorFixture is one contributing vector's collected evidence.
// PreventionEvidence doubles as the Telemetry-completeness input: telemetry
// describes how completely the SAME collection pipeline worked for this
// test, never a separately-sourced signal (av.txt §4: "no alert found" is a
// pipeline question, not a different test). ResponseEvidence empty means
// nothing required a response for this vector (most prevention-only
// vectors). TestExecutedAt/DetectionSLA zero means latency is not
// evaluated.
type VectorFixture struct {
	PreventionEvidence []avval.CollectionResult
	ResponseEvidence   []avval.CollectionResult
	Configuration      *ConfigurationCheck
	TestExecutedAt     time.Time
	DetectionSLA       time.Duration
}

// VectorOutcome bundles every independent dimension's result for one
// contributing vector, never collapsed into a single field. A reader never
// needs to re-run anything to see WHY a vector failed: each dimension
// carries its own reason.
type VectorOutcome struct {
	VectorID string
	Severity avcatalog.Severity

	Finding           avval.FindingClassification
	FindingConfidence avval.Confidence
	FindingReason     string

	Response           avval.ResponseOutcome
	ResponseConfidence avval.Confidence
	ResponseReason     string

	Telemetry       avval.TelemetryState
	TelemetryReason string

	Configuration       avval.ConfigurationState // "" when not applicable to this vector
	ConfigurationReason string

	DetectionLatency       DetectionLatencyState
	DetectionLatencyReason string

	EvidenceSource EvidenceSource
}
