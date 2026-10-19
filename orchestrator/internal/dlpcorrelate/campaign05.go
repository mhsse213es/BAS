package dlpcorrelate

import (
	"fmt"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/reporting"
)

// Campaign05DetectionToResponse is dlp.txt §3C's Campaign 05. Stages 5 and 6
// (assignment, acknowledgment/response time) are permanently StageNotTested:
// ticketing.TicketRef carries no assignee and no ack timestamp, so they
// cannot be evaluated until internal/ticketing gains those features.
var Campaign05DetectionToResponse = CorrelationChain{
	ID:   "DLPCORRELATE-CAMPAIGN-05",
	Name: "Detection-to-response validation",
	Stages: []StageDefinition{
		{Label: "controlled policy violation enforced as expected", Dimension: "DLP-ENF"},
		{Label: "event reaches DLP console", Dimension: "DLP-TEL"},
		{Label: "SIEM ingestion verified", Dimension: "DLP-TEL"},
		{Label: "incident creation confirmed", Dimension: "DLP-RESP"},
		{Label: "incident assignment confirmed", Dimension: "DLP-RESP"},
		{Label: "acknowledgment and response measured", Dimension: "DLP-RESP"},
	},
}

// Campaign05Evidence carries already-computed verification results. Ticket
// evidence is primitive so this package never imports internal/ticketing.
type Campaign05Evidence struct {
	EnforcementComparison reporting.ComparisonResult
	EnforcementReason     string
	ConsoleComparison     reporting.ComparisonResult
	ConsoleReason         string
	SIEMVerdict           string
	TicketAttempted       bool
	TicketID              string
}

// verificationStageOutcome is Campaign 05's own translation of a comparison
// result. Unlike enforcementOutcome, Match continues the chain: a successful
// block must still be followed by detection and response verification.
func verificationStageOutcome(c reporting.ComparisonResult) StageOutcome {
	switch c {
	case reporting.Match:
		return StageContinues
	case reporting.Mismatch:
		return StageFailed
	default:
		return StageInconclusive
	}
}

func siemStageOutcome(verdict string) StageOutcome {
	switch verdict {
	case detectverify.VerdictDetected:
		return StageContinues
	default:
		return StageInconclusive
	}
}

func ticketStageOutcome(attempted bool, ticketID string) (StageOutcome, string) {
	switch {
	case !attempted:
		return StageInconclusive, "no incident creation attempt observed"
	case ticketID == "":
		return StageFailed, "incident creation attempted but no ticket ID returned"
	default:
		return StageContinues, fmt.Sprintf("incident created as %s", ticketID)
	}
}

// EvaluateCampaign05 translates ev into a chain result. It never builds stage
// 5 or 6 itself; EvaluateCorrelationChain skip-fills them as StageNotTested.
func EvaluateCampaign05(ev Campaign05Evidence) (ChainResult, error) {
	chain := Campaign05DetectionToResponse
	var reached []StageResult

	stage1 := StageResult{
		StageOrder: 1,
		Label:      chain.Stages[0].Label,
		Dimension:  "DLP-ENF",
		Outcome:    verificationStageOutcome(ev.EnforcementComparison),
		Reason:     ev.EnforcementReason,
	}
	reached = append(reached, stage1)
	if stage1.Outcome.stops() {
		return EvaluateCorrelationChain(chain, reached)
	}

	stage2 := StageResult{
		StageOrder: 2,
		Label:      chain.Stages[1].Label,
		Dimension:  "DLP-TEL",
		Outcome:    verificationStageOutcome(ev.ConsoleComparison),
		Reason:     ev.ConsoleReason,
	}
	reached = append(reached, stage2)
	if stage2.Outcome.stops() {
		return EvaluateCorrelationChain(chain, reached)
	}

	stage3 := StageResult{
		StageOrder: 3,
		Label:      chain.Stages[2].Label,
		Dimension:  "DLP-TEL",
		Outcome:    siemStageOutcome(ev.SIEMVerdict),
		Reason:     fmt.Sprintf("SIEM verdict %q", ev.SIEMVerdict),
	}
	reached = append(reached, stage3)
	if stage3.Outcome.stops() {
		return EvaluateCorrelationChain(chain, reached)
	}

	ticketOutcome, ticketReason := ticketStageOutcome(ev.TicketAttempted, ev.TicketID)
	stage4 := StageResult{
		StageOrder: 4,
		Label:      chain.Stages[3].Label,
		Dimension:  "DLP-RESP",
		Outcome:    ticketOutcome,
		Reason:     ticketReason,
	}
	reached = append(reached, stage4)
	return EvaluateCorrelationChain(chain, reached)
}
