package avefficacy

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/avcatalog"
	"github.com/audspect/bas/internal/avval"
)

// EvaluateVector grades one vector's fixture against every independent
// dimension avval exposes, via avval's own real evaluators -- this package
// never derives a verdict itself, only bundles what avval already derived.
func EvaluateVector(vector avcatalog.Vector, policyBasis string, fixture VectorFixture) (VectorOutcome, error) {
	legs := vector.Expectations(policyBasis)
	key := avval.CorrelationKey{TestExecutionID: vector.ID, Target: vector.ID}

	claimResult := avval.EvaluateClaim(legs[0].Expectation, fixture.PreventionEvidence, key)

	telemetryState, telemetryReason := avval.EvaluateTelemetryCompleteness(fixture.PreventionEvidence)

	var responseOutcome avval.ResponseOutcome
	var responseConfidence avval.Confidence
	var responseReason string
	if len(fixture.ResponseEvidence) == 0 {
		responseOutcome = avval.ResponseNotApplicable
		responseConfidence = avval.ConfidenceHigh
		responseReason = "no response evidence was collected for this vector; nothing required a response"
	} else {
		responseOutcome, responseConfidence, responseReason = avval.EvaluateResponse(fixture.ResponseEvidence, key)
	}

	var configState avval.ConfigurationState
	var configReason string
	switch {
	case fixture.Configuration == nil:
		configState, configReason = "", "configuration was not evaluated for this vector"
	case fixture.Configuration.Managed != nil:
		configState, configReason = avval.EvaluateConfigurationDrift(fixture.Configuration.Snapshot, *fixture.Configuration.Managed)
	default:
		configState, configReason = avval.EvaluateConfigurationSnapshot(fixture.Configuration.Snapshot, fixture.Configuration.Baseline)
	}

	latencyState, latencyReason := evaluateDetectionLatency(claimResult.View, fixture.TestExecutedAt, fixture.DetectionSLA)

	return VectorOutcome{
		VectorID: vector.ID, Severity: vector.Severity,
		Finding: claimResult.Finding, FindingConfidence: claimResult.Confidence, FindingReason: claimResult.Reason,
		Response: responseOutcome, ResponseConfidence: responseConfidence, ResponseReason: responseReason,
		Telemetry: telemetryState, TelemetryReason: telemetryReason,
		Configuration: configState, ConfigurationReason: configReason,
		DetectionLatency: latencyState, DetectionLatencyReason: latencyReason,
	}, nil
}

// evaluateDetectionLatency compares the earliest agreeing Detected
// observation's timestamp against testExecutedAt+sla. It is deliberately
// conservative: any ambiguity (no SLA declared, detection did not resolve to
// an agreeing Detected outcome, no timestamped observation found, or a
// timestamp that precedes execution) resolves to LatencyNotEvaluated, never
// a fabricated breach.
func evaluateDetectionLatency(view avval.CorrelatedView, testExecutedAt time.Time, sla time.Duration) (DetectionLatencyState, string) {
	if testExecutedAt.IsZero() || sla <= 0 {
		return LatencyNotEvaluated, "no detection SLA was declared for this vector"
	}
	if view.DetectionAx.State != avval.AxisAgree || view.DetectionAx.Detection != avval.DetectionDetected {
		return LatencyNotEvaluated, "detection did not resolve to a confirmed Detected outcome; latency cannot be measured"
	}
	var earliest time.Time
	for _, o := range view.Raw {
		if o.Detection != avval.DetectionDetected || o.ObservedAt.IsZero() {
			continue
		}
		if earliest.IsZero() || o.ObservedAt.Before(earliest) {
			earliest = o.ObservedAt
		}
	}
	if earliest.IsZero() {
		return LatencyNotEvaluated, "no timestamped detection observation was found"
	}
	latency := earliest.Sub(testExecutedAt)
	if latency < 0 {
		return LatencyNotEvaluated, "detection timestamp precedes the test execution timestamp; latency cannot be measured"
	}
	if latency <= sla {
		return LatencyWithinSLA, fmt.Sprintf("detection observed %s after execution, within the %s SLA", latency, sla)
	}
	return LatencySLABreached, fmt.Sprintf("detection observed %s after execution, exceeding the %s SLA", latency, sla)
}
