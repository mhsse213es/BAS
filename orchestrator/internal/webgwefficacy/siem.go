package webgwefficacy

import (
	"encoding/json"
	"fmt"
	"time"
)

// SIEMEvidence is one normalized SIEM telemetry record independently
// corroborating (or failing to corroborate) a gateway event -- a
// second, separately-sourced signal, never derived from
// GatewayEvidence itself.
type SIEMEvidence struct {
	RequestURL string          `json:"requestUrl"`
	User       string          `json:"user,omitempty"`
	EventType  string          `json:"eventType"`
	Timestamp  time.Time       `json:"timestamp"`
	Source     EvidenceSource  `json:"source"`
	RawEvent   json.RawMessage `json:"rawEvent,omitempty"`
}

// SIEMEvidenceProvider supplies SIEM evidence for a request shape and
// time window. Mirrors the *shape* of a real vendor connector (call
// a real product, normalize, return typed evidence) without
// importing internal/detectverify -- see the master spec's locked
// decision against type-level cross-package dependencies here.
type SIEMEvidenceProvider interface {
	SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error)
}

// FixtureSIEMProvider wraps an in-memory slice of hand-built
// SIEMEvidence values -- no real SIEM API call happens in this
// phase.
type FixtureSIEMProvider struct {
	events []SIEMEvidence
}

func NewFixtureSIEMProvider(events []SIEMEvidence) *FixtureSIEMProvider {
	return &FixtureSIEMProvider{events: events}
}

func (p *FixtureSIEMProvider) SIEMEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]SIEMEvidence, error) {
	var out []SIEMEvidence
	for _, e := range p.events {
		if !matchesRequest(e.RequestURL, e.User, req) {
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
// EfficacyResult's Detection verdict using independent SIEM
// telemetry. A gateway's own log is never treated as sufficient
// proof that an alert reached the SOC's detection surface: if the
// gateway itself never showed detection (Detection != Pass), there is
// nothing to corroborate and the result is returned unchanged; if it
// did, a missing SIEM record downgrades Detection to Inconclusive
// (never Fail -- absence of SIEM evidence is not proof the alert was
// lost, only that it is uncorroborated), and a matching record keeps
// Detection at Pass with an annotated Reason.
func CorrelateWithSIEM(result EfficacyResult, siem SIEMEvidenceProvider, window TimeWindow) EfficacyResult {
	if result.Detection.Verdict != VerdictPass {
		return result
	}
	req := HTTPRequestRef{URL: result.Expectation.RequestURL, User: result.Expectation.User}
	records, err := siem.SIEMEvidenceFor(req, window)
	if err != nil {
		result.Detection = VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("SIEM evidence collection failed: %v", err)}
		return result
	}
	if len(records) == 0 {
		result.Detection = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "gateway evidence shows detection, but no independent SIEM record corroborates it reaching the SOC's detection surface",
		}
		return result
	}
	result.SIEMEvidence = records
	result.Detection = VerdictDetail{Verdict: VerdictPass, Reason: "corroborated by independent SIEM telemetry"}
	return result
}
