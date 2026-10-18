package phishbridge

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// ReportTicketExpectation declares what should happen after a target
// reports a simulated phishing message: whether SOC triage is
// expected to create a ticket for it. Keyed on ExecutionID/TargetID --
// exercise's own real identity for a report event -- deliberately
// never a MessageRef. PH-DET-002's own investigated resolution found
// no lossless execution-to-MessageRef mapping exists in exercise's
// types, and a real SOC ticket for a self-report is keyed to the
// report action itself (reporter/timestamp), not the original
// campaign message's delivery identity -- so this is a genuinely new,
// separate type family, not a stretch of
// emailgwefficacy.CorrelateWithTicketing's own MessageRef-keyed
// TicketEvidenceProvider.
type ReportTicketExpectation struct {
	ExecutionID           string
	TargetID              string
	ExpectedTicketCreated bool
}

// ReportTicketEvidence is one normalized record of whether a ticket
// was actually created in response to a specific report event.
type ReportTicketEvidence struct {
	ExecutionID   string
	TargetID      string
	TicketCreated bool
	TicketRef     string
	Timestamp     time.Time
}

// ReportTicketEvidenceProvider supplies ticketing evidence for one
// execution/target's report event and time window. A returned error
// means collection failed -- distinct from a successful search that
// found nothing (nil error, empty slice).
type ReportTicketEvidenceProvider interface {
	ReportTicketEvidenceFor(executionID, targetID string, window emailgwefficacy.TimeWindow) ([]ReportTicketEvidence, error)
}

// FixtureReportTicketProvider wraps an in-memory slice of hand-built
// ReportTicketEvidence values -- no real ITSM (ServiceNow/Jira)
// connector is called in this phase; that remains a separate, not-yet-
// built adapter, the same maturity gap PH-IR-004's own fixture-only
// CorrelateWithTicketing already carries.
type FixtureReportTicketProvider struct {
	events []ReportTicketEvidence
}

func NewFixtureReportTicketProvider(events []ReportTicketEvidence) *FixtureReportTicketProvider {
	return &FixtureReportTicketProvider{events: events}
}

func (p *FixtureReportTicketProvider) ReportTicketEvidenceFor(executionID, targetID string, window emailgwefficacy.TimeWindow) ([]ReportTicketEvidence, error) {
	var out []ReportTicketEvidence
	for _, e := range p.events {
		if e.ExecutionID != executionID || e.TargetID != targetID {
			continue
		}
		if e.Timestamp.Before(window.Start) || e.Timestamp.After(window.End) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyReportTicketExpectation checks exp against ticketing evidence.
// Returns emailgwefficacy.VerdictDetail directly -- this check is
// single-dimensional (was a ticket created), the same simple success/
// failure/inconclusive vocabulary InboxRuleExpectation's own Verify
// function already uses, reused here rather than inventing a third
// parallel verdict taxonomy for what is structurally the same kind of
// check. A collection error or an empty result both yield
// Inconclusive, never an assumed verdict -- absence of evidence is
// not proof a ticket was or wasn't created.
func VerifyReportTicketExpectation(exp ReportTicketExpectation, provider ReportTicketEvidenceProvider, window emailgwefficacy.TimeWindow) emailgwefficacy.VerdictDetail {
	records, err := provider.ReportTicketEvidenceFor(exp.ExecutionID, exp.TargetID, window)
	if err != nil {
		return emailgwefficacy.VerdictDetail{
			Verdict: emailgwefficacy.VerdictInconclusive,
			Reason:  fmt.Sprintf("report-ticket evidence collection failed: %v", err),
		}
	}
	if len(records) == 0 {
		return emailgwefficacy.VerdictDetail{
			Verdict: emailgwefficacy.VerdictInconclusive,
			Reason:  "no ticketing evidence found for this report event in the window; absence of evidence is not proof of either outcome",
		}
	}
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	if latest.TicketCreated == exp.ExpectedTicketCreated {
		return emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess}
	}
	return emailgwefficacy.VerdictDetail{
		Verdict: emailgwefficacy.VerdictConfirmedFailure,
		Reason: fmt.Sprintf("ticket created=%t did not match expected=%t for execution %q target %q",
			latest.TicketCreated, exp.ExpectedTicketCreated, exp.ExecutionID, exp.TargetID),
	}
}

// ReportedPhishingTicketExpectation builds PH-DET-002's own scenario:
// a target reports a simulated phishing message
// (exercise/tracker.HandleReport's own real "phishing_reported"
// event, already read by FromExerciseInteractionEvidence for
// PH-ID-001), which SOC triage should turn into a ticket.
// ticketed=true is the known-good case; ticketed=false is the
// known-bad case (the report was logged but never triaged).
func ReportedPhishingTicketExpectation(ticketed bool) ReportTicketExpectation {
	return ReportTicketExpectation{
		ExecutionID:           "exec-lab-phishing-report-001",
		TargetID:              "target-lab-001",
		ExpectedTicketCreated: ticketed,
	}
}
