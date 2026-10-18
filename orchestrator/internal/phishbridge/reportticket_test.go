package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHDET002_EndToEnd_KnownGood_ReportCreatesTicket(t *testing.T) {
	exp := ReportedPhishingTicketExpectation(true)
	provider := NewFixtureReportTicketProvider([]ReportTicketEvidence{{
		ExecutionID: exp.ExecutionID, TargetID: exp.TargetID,
		TicketCreated: true, TicketRef: "TICKET-1001", Timestamp: time.Now(),
	}})

	verdict := VerifyReportTicketExpectation(exp, provider, scenarioWindow())
	obs := FromSingleDimensionResponseVerdict(verdict, "exercise-reportticket")
	outcome := phishval.Evaluate("run-ph-det-002", "known-good", catalogExpectation(t, "PH-DET-002"), obs)

	if outcome.Response.Verdict != phishval.VerdictPass {
		t.Errorf("Response.Verdict = %q (%s), want %q", outcome.Response.Verdict, outcome.Response.Reason, phishval.VerdictPass)
	}
}

func TestPHDET002_EndToEnd_KnownBad_ReportNeverTicketed(t *testing.T) {
	exp := ReportedPhishingTicketExpectation(true)
	provider := NewFixtureReportTicketProvider([]ReportTicketEvidence{{
		ExecutionID: exp.ExecutionID, TargetID: exp.TargetID,
		TicketCreated: false, Timestamp: time.Now(),
	}})

	verdict := VerifyReportTicketExpectation(exp, provider, scenarioWindow())
	obs := FromSingleDimensionResponseVerdict(verdict, "exercise-reportticket")
	outcome := phishval.Evaluate("run-ph-det-002", "known-bad", catalogExpectation(t, "PH-DET-002"), obs)

	if outcome.Response.Verdict != phishval.VerdictFail {
		t.Errorf("Response.Verdict = %q, want %q", outcome.Response.Verdict, phishval.VerdictFail)
	}
}

func TestPHDET002_NoTicketingEvidence_NotTested_NeverFabricatesEitherOutcome(t *testing.T) {
	exp := ReportedPhishingTicketExpectation(true)
	provider := NewFixtureReportTicketProvider(nil)

	verdict := VerifyReportTicketExpectation(exp, provider, scenarioWindow())
	obs := FromSingleDimensionResponseVerdict(verdict, "exercise-reportticket")
	outcome := phishval.Evaluate("run-ph-det-002", "no-evidence", catalogExpectation(t, "PH-DET-002"), obs)

	if outcome.Response.Verdict != phishval.VerdictNotTested {
		t.Errorf("Response.Verdict = %q, want %q (an inconclusive single-dimensional check must never fabricate Remediated or Failed)", outcome.Response.Verdict, phishval.VerdictNotTested)
	}
}

func TestVerifyReportTicketExpectation_WrongTargetIgnored(t *testing.T) {
	exp := ReportedPhishingTicketExpectation(true)
	provider := NewFixtureReportTicketProvider([]ReportTicketEvidence{{
		ExecutionID: exp.ExecutionID, TargetID: "a-different-target",
		TicketCreated: true, Timestamp: time.Now(),
	}})

	verdict := VerifyReportTicketExpectation(exp, provider, scenarioWindow())
	if verdict.Verdict != emailgwefficacy.VerdictInconclusive {
		t.Errorf("verdict = %+v, want Inconclusive (evidence for a different target must not be matched)", verdict)
	}
}
