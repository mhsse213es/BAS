package emailgwefficacy

import (
	"encoding/json"
	"fmt"
	"time"
)

// This file closes part of area G's own documented gap (coverage.go:
// "Detection/IR/resilience... IR workflow orchestration beyond this
// evidence layer remains unbuilt") -- email.txt §6 P2's own ask to
// "correlate gateway and Microsoft 365 Defender evidence with SIEM
// and ticketing telemetry", mirroring webgwefficacy.SIEMEvidence/
// SIEMEvidenceProvider/CorrelateWithSIEM's own pattern independently
// (never imported, per this package's locked zero-cross-import
// architecture) -- adapted to EfficacyResult's own DetectionVerdict
// field rather than webgwefficacy's single Detection field, and to
// this package's own EmailGWVerdict vocabulary.

// SIEMEvidence is one normalized SIEM telemetry record independently
// corroborating (or failing to corroborate) that an EmailGW/Defender
// detection actually reached the SOC's own detection surface -- a
// second, separately-sourced signal, never derived from
// DetectionEvidence itself.
type SIEMEvidence struct {
	Message   MessageRef      `json:"-"`
	EventType string          `json:"eventType,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Source    EvidenceSource  `json:"source"`
	RawEvent  json.RawMessage `json:"rawEvent,omitempty"`
}

// SIEMEvidenceProvider supplies SIEM evidence for a message and time
// window. Mirrors the *shape* of a real vendor SIEM connector (call a
// real product, normalize, return typed evidence) without importing
// internal/detectverify -- same reasoning as webgwefficacy's own
// SIEMEvidenceProvider.
type SIEMEvidenceProvider interface {
	SIEMEvidenceFor(msg MessageRef, window TimeWindow) ([]SIEMEvidence, error)
}

// FixtureSIEMProvider wraps an in-memory slice of hand-built
// SIEMEvidence values -- no real SIEM API call happens in this phase.
type FixtureSIEMProvider struct {
	events []SIEMEvidence
}

func NewFixtureSIEMProvider(events []SIEMEvidence) *FixtureSIEMProvider {
	return &FixtureSIEMProvider{events: events}
}

func (p *FixtureSIEMProvider) SIEMEvidenceFor(msg MessageRef, window TimeWindow) ([]SIEMEvidence, error) {
	var out []SIEMEvidence
	for _, e := range p.events {
		if e.Message != msg {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// CorrelateWithSIEM strengthens or weakens an already-computed
// EfficacyResult's DetectionVerdict using independent SIEM telemetry.
// Microsoft 365 Defender's own alert is never treated as sufficient
// proof that it actually reached the SOC's detection surface: if
// Defender itself never showed detection (DetectionVerdict !=
// ConfirmedSuccess), there is nothing to corroborate and the result
// is returned unchanged; if it did, a missing SIEM record downgrades
// DetectionVerdict to Inconclusive (never ConfirmedFailure -- absence
// of SIEM evidence is not proof the alert was lost, only that it is
// uncorroborated), and a matching record keeps DetectionVerdict at
// ConfirmedSuccess with an annotated Reason plus the corroborating
// evidence attached to the result.
func CorrelateWithSIEM(result EfficacyResult, siem SIEMEvidenceProvider, window TimeWindow) EfficacyResult {
	if result.DetectionVerdict.Verdict != VerdictConfirmedSuccess {
		return result
	}
	records, err := siem.SIEMEvidenceFor(result.Expectation.Ref(), window)
	if err != nil {
		result.DetectionVerdict = VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("SIEM evidence collection failed: %v", err)}
		return result
	}
	if len(records) == 0 {
		result.DetectionVerdict = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "Defender's own evidence shows detection, but no independent SIEM record corroborates it reaching the SOC's detection surface",
		}
		return result
	}
	result.SIEMEvidence = records
	result.DetectionVerdict = VerdictDetail{Verdict: VerdictConfirmedSuccess, Reason: "corroborated by independent SIEM telemetry"}
	return result
}
