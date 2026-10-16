package emailgwefficacy

import (
	"fmt"
	"time"
)

// This file is the other half of email.txt §6 P2's "correlate...
// with SIEM and ticketing telemetry" ask (siemcorrelation.go is the
// SIEM half). Genuinely new in this domain -- webgwefficacy has no
// ticketing-correlation precedent to mirror -- but follows the exact
// same structural discipline CorrelateWithSIEM establishes: an
// already-confirmed verdict dimension is never treated as sufficient
// proof of a SEPARATE claim (here: that the incident was actually
// escalated into the organization's own ITSM/ticketing system, not
// merely remediated). Deliberately strengthens/weakens
// ResponseVerdict, not DetectionVerdict: escalation is a response/IR-
// workflow concern (email.txt §1.G names "escalation" alongside
// "automated remediation... containment"), distinct from whether the
// threat was detected at all.
type TicketEvidence struct {
	Message         MessageRef     `json:"-"`
	IncidentCreated bool           `json:"incidentCreated"`
	System          string         `json:"system,omitempty"` // e.g. "ServiceNow", "Jira"
	Severity        string         `json:"severity,omitempty"`
	Timestamp       time.Time      `json:"timestamp"`
	Source          EvidenceSource `json:"source"`
}

// TicketEvidenceProvider supplies incident-ticketing evidence for a
// message and time window. Mirrors the *shape* of a real ITSM
// connector (call a real product, normalize, return typed evidence)
// without importing internal/ticketing -- same cross-package
// discipline as every other evidence provider in this package.
type TicketEvidenceProvider interface {
	TicketEvidenceFor(msg MessageRef, window TimeWindow) ([]TicketEvidence, error)
}

// FixtureTicketProvider wraps an in-memory slice of hand-built
// TicketEvidence values -- no real ITSM API call happens in this
// phase.
type FixtureTicketProvider struct {
	events []TicketEvidence
}

func NewFixtureTicketProvider(events []TicketEvidence) *FixtureTicketProvider {
	return &FixtureTicketProvider{events: events}
}

func (p *FixtureTicketProvider) TicketEvidenceFor(msg MessageRef, window TimeWindow) ([]TicketEvidence, error) {
	var out []TicketEvidence
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

// CorrelateWithTicketing strengthens or weakens an already-computed
// EfficacyResult's ResponseVerdict using independent ITSM/ticketing
// telemetry. A completed remediation action (ResponseVerdict ==
// ConfirmedSuccess) is never treated as proof the incident was also
// properly escalated into the organization's own incident-management
// process: if remediation was not confirmed, there is nothing to
// corroborate and the result is returned unchanged; if it was, a
// missing or IncidentCreated=false ticket record downgrades
// ResponseVerdict to Inconclusive (never ConfirmedFailure -- absence
// of a ticket is not proof escalation failed, only that it is
// uncorroborated), and a matching IncidentCreated=true record keeps
// ResponseVerdict at ConfirmedSuccess with an annotated Reason plus
// the corroborating evidence attached to the result.
func CorrelateWithTicketing(result EfficacyResult, ticketing TicketEvidenceProvider, window TimeWindow) EfficacyResult {
	if result.ResponseVerdict.Verdict != VerdictConfirmedSuccess {
		return result
	}
	records, err := ticketing.TicketEvidenceFor(result.Expectation.Ref(), window)
	if err != nil {
		result.ResponseVerdict = VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("ticketing evidence collection failed: %v", err)}
		return result
	}
	if len(records) == 0 {
		result.ResponseVerdict = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "remediation was confirmed, but no independent ticketing record corroborates the incident was actually escalated",
		}
		return result
	}
	latest := latestByTimestamp(records, func(e TicketEvidence) time.Time { return e.Timestamp })
	if !latest.IncidentCreated {
		result.ResponseVerdict = VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "remediation was confirmed, but the most recent ticketing record shows no incident was created",
		}
		return result
	}
	result.TicketEvidence = records
	result.ResponseVerdict = VerdictDetail{Verdict: VerdictConfirmedSuccess, Reason: "corroborated by independent ticketing/ITSM telemetry"}
	return result
}
